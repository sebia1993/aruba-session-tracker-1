"""Strict, bounded and read-only SSH collection.

The concrete factory probes unknown hosts before approval, while already-known
hosts rely on Netmiko's strict authenticated connection for host-key checking.
This gives the GUI a chance to display a new fingerprint without adding a
second handshake to every connection after trust has been established.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import inspect
import msvcrt
import os
import re
import socket
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

import paramiko
from netmiko.aruba.aruba_os import ArubaOsSSH
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from netmiko.session_log import SessionLog
from paramiko.hostkeys import HostKeyEntry, InvalidHostKey

from aruba_session_tracker.models import Credentials, DeviceTarget, ErrorCode
from aruba_session_tracker.parsers.common import ParseError, reject_command_errors
from aruba_session_tracker.paths import (
    DirectoryIdentity,
    UnsafeManagedPath,
    ensure_managed_directory,
    reject_link_or_reparse,
    reject_managed_file_link,
    verify_managed_directory,
)

MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_LINES = 50_000
POLL_DEADLINE_SECONDS = 300.0
KNOWN_HOSTS_LOCK_TIMEOUT_SECONDS = 10.0
MAX_KNOWN_HOSTS_BYTES = 1024 * 1024

_KNOWN_HOSTS_LOCKS_GUARD = threading.Lock()
_KNOWN_HOSTS_LOCKS: dict[str, threading.Lock] = {}

_GLOBAL_USER_RE = re.compile(
    r'^show global-user-table list ip "(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"$'
)
_DATAPATH_RE = re.compile(
    r"^show datapath session table (?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$"
)


class CancellationToken:
    """Thread-safe cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._callbacks_lock = threading.RLock()
        self._callbacks: dict[int, Callable[[], None]] = {}
        self._next_callback_id = 0

    def cancel(self) -> None:
        with self._callbacks_lock:
            if self._event.is_set():
                return
            self._event.set()
            callbacks = tuple(self._callbacks.values())
        for callback in callbacks:
            with suppress(Exception):
                callback()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds; return true when cancellation won."""
        return self._event.wait(timeout)

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise CollectorError(ErrorCode.CANCELLED, "작업이 취소되었습니다.")

    @contextmanager
    def abort_on_cancel(self, callback: Callable[[], None]) -> Iterator[None]:
        """Run a non-blocking abort callback when cancellation wins.

        Registration is race-safe with :meth:`cancel`: a callback registered
        after cancellation runs immediately, while a callback registered just
        before cancellation is included in the cancellation snapshot.
        """

        with self._callbacks_lock:
            if self._event.is_set():
                callback_id: int | None = None
                run_now = True
            else:
                self._next_callback_id += 1
                callback_id = self._next_callback_id
                self._callbacks[callback_id] = callback
                run_now = False
        if run_now:
            with suppress(Exception):
                callback()
        try:
            yield
        finally:
            if callback_id is not None:
                with self._callbacks_lock:
                    self._callbacks.pop(callback_id, None)


@dataclass(frozen=True, slots=True)
class PollDeadline:
    """One monotonic wall-clock budget shared by every operation in a poll."""

    expires_at: float
    clock: Callable[[], float] = field(default=time.monotonic, repr=False, compare=False)

    @classmethod
    def after(
        cls,
        seconds: float = POLL_DEADLINE_SECONDS,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> PollDeadline:
        if seconds <= 0:
            raise ValueError("poll deadline must be positive")
        return cls(clock() + seconds, clock)

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - self.clock())

    def bounded_timeout(self, configured_timeout: float) -> float:
        self.raise_if_expired()
        return max(0.001, min(configured_timeout, self.remaining_seconds))

    def raise_if_expired(self) -> None:
        if self.remaining_seconds <= 0:
            raise CollectorError(
                ErrorCode.POLL_DEADLINE_EXCEEDED,
                "전체 조회 제한 시간이 초과되었습니다.",
                retryable_network=True,
            )


def _deadline_elapsed_before_stop(deadline: PollDeadline, stop: threading.Event) -> bool:
    """Wait until the monotonic deadline, tolerating early OS timer wakeups."""

    while True:
        remaining = deadline.remaining_seconds
        if remaining <= 0:
            return True
        if stop.wait(remaining):
            return False


@dataclass(frozen=True, slots=True)
class HostKeyInfo:
    algorithm: str
    sha256_fingerprint: str


HostKeyApproval = (
    Callable[[DeviceTarget, HostKeyInfo], bool]
    | Callable[[DeviceTarget, HostKeyInfo, PollDeadline], bool]
)


class CollectorError(RuntimeError):
    """Sanitized collection failure with explicit failover eligibility."""

    def __init__(self, code: ErrorCode, message: str, *, retryable_network: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable_network = retryable_network


@dataclass(slots=True)
class _ApprovalResult:
    answer: bool = False
    error: BaseException | None = None


def run_bounded_approval(
    approval: Callable[..., bool],
    first_argument: object,
    second_argument: object,
    *,
    cancel_token: CancellationToken,
    deadline: PollDeadline,
) -> bool:
    """Run an operator approval without letting it exceed a poll boundary.

    Legacy two-argument callbacks remain supported.  New callbacks may accept
    the shared :class:`PollDeadline` as a third positional argument so a UI can
    dismiss its own pending prompt.  Signature binding happens before the call,
    therefore a ``TypeError`` raised *inside* the callback is never mistaken for
    a legacy callback signature.

    A callback that ignores cancellation or the deadline may leave its daemon
    helper alive temporarily, but its late answer is never consumed by the poll.
    """

    arguments = (first_argument, second_argument)
    try:
        signature = inspect.signature(approval)
    except (TypeError, ValueError) as exc:
        raise TypeError("approval callback signature cannot be inspected") from exc
    try:
        signature.bind(*arguments, deadline)
    except TypeError:
        # Validate the legacy signature separately.  Do not catch any error
        # raised later by the callback itself.
        signature.bind(*arguments)
        deadline_aware = False
    else:
        deadline_aware = True

    cancel_token.raise_if_cancelled()
    deadline.raise_if_expired()
    completed = threading.Event()
    result = _ApprovalResult()

    def invoke() -> None:
        try:
            if deadline_aware:
                result.answer = bool(approval(*arguments, deadline))
            else:
                result.answer = bool(approval(*arguments))
        except BaseException as exc:  # Re-raised on the polling thread below.
            result.error = exc
        finally:
            completed.set()

    threading.Thread(
        target=invoke,
        name="aruba-approval-callback",
        daemon=True,
    ).start()
    while True:
        cancel_token.raise_if_cancelled()
        deadline.raise_if_expired()
        wait_seconds = min(0.05, deadline.remaining_seconds)
        if completed.wait(wait_seconds):
            break

    # Cancellation/deadline always wins a race with a callback completion.
    cancel_token.raise_if_cancelled()
    deadline.raise_if_expired()
    if result.error is not None:
        raise result.error
    return result.answer


class CommandConnection(Protocol):
    def send_command(self, command: str, *, read_timeout: float) -> str: ...

    def close(self) -> None: ...


class SSHConnectionFactory(Protocol):
    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: HostKeyApproval | None,
        cancel_token: CancellationToken,
        deadline: PollDeadline,
    ) -> AbstractContextManager[CommandConnection]: ...


@dataclass(frozen=True, slots=True)
class CommandOutput:
    command: str
    output: str


@dataclass(frozen=True, slots=True)
class CommandBatch:
    target: DeviceTarget
    outputs: tuple[CommandOutput, ...]

    def output_for(self, command: str) -> str:
        for item in self.outputs:
            if item.command == command:
                return item.output
        raise KeyError(command)


class SSHCollector:
    """Execute a small command allowlist with hard output and cancellation bounds."""

    def __init__(
        self,
        factory: SSHConnectionFactory,
        *,
        command_timeout: float = 30.0,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
        max_output_lines: int = MAX_OUTPUT_LINES,
    ) -> None:
        self._factory = factory
        self._command_timeout = command_timeout
        self._max_output_bytes = max_output_bytes
        self._max_output_lines = max_output_lines

    def collect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        commands: Iterable[str],
        *,
        host_key_approval: HostKeyApproval | None = None,
        cancel_token: CancellationToken | None = None,
        deadline: PollDeadline | None = None,
    ) -> CommandBatch:
        token = cancel_token or CancellationToken()
        poll_deadline = deadline or PollDeadline.after()
        requested = tuple(commands)
        if not requested:
            raise ValueError("실행할 명령이 없습니다.")
        for command in requested:
            _validate_command(command)

        token.raise_if_cancelled()
        poll_deadline.raise_if_expired()
        outputs: list[CommandOutput] = []
        try:
            manager = self._factory.connect(
                target,
                credentials,
                host_key_approval=host_key_approval,
                cancel_token=token,
                deadline=poll_deadline,
            )
            connection = manager.__enter__()
            abort = getattr(manager, "abort", None)
            abort_callback = abort if callable(abort) else connection.close
            with token.abort_on_cancel(abort_callback):
                try:
                    for command in requested:
                        token.raise_if_cancelled()
                        read_timeout = poll_deadline.bounded_timeout(self._command_timeout)
                        bounded_sender = getattr(connection, "send_command_bounded", None)
                        if callable(bounded_sender):
                            output = bounded_sender(
                                command,
                                read_timeout=read_timeout,
                                max_output_bytes=self._max_output_bytes,
                                max_output_lines=self._max_output_lines,
                            )
                        else:
                            output = connection.send_command(command, read_timeout=read_timeout)
                        token.raise_if_cancelled()
                        poll_deadline.raise_if_expired()
                        _check_output_limits(
                            output,
                            max_bytes=self._max_output_bytes,
                            max_lines=self._max_output_lines,
                        )
                        if command == "no paging":
                            try:
                                reject_command_errors(output)
                            except ParseError as exc:
                                if exc.code is ErrorCode.COMMAND_REJECTED:
                                    raise CollectorError(
                                        ErrorCode.COMMAND_REJECTED,
                                        "장비가 세션 페이징 해제 명령의 실행 권한을 거부했습니다.",
                                    ) from exc
                                raise CollectorError(
                                    ErrorCode.COMMAND_VARIANT_UNVERIFIED,
                                    "장비가 세션 페이징 해제 명령을 거부했습니다.",
                                ) from exc
                        outputs.append(CommandOutput(command=command, output=output))
                except BaseException as exc:
                    with suppress(Exception):
                        manager.__exit__(type(exc), exc, exc.__traceback__)
                    raise
                else:
                    # Keep the abort callback registered during graceful SSH
                    # teardown so cancellation can wake a blocked disconnect.
                    manager.__exit__(None, None, None)
                    token.raise_if_cancelled()
                    poll_deadline.raise_if_expired()
        except CollectorError as exc:
            if token.is_cancelled and exc.retryable_network:
                token.raise_if_cancelled()
            if exc.retryable_network:
                try:
                    poll_deadline.raise_if_expired()
                except CollectorError as deadline_exc:
                    raise deadline_exc from exc
            raise
        except (NetmikoAuthenticationException, paramiko.AuthenticationException) as exc:
            raise CollectorError(ErrorCode.AUTH_FAILED, "SSH 인증에 실패했습니다.") from exc
        except (NetmikoTimeoutException, ReadTimeout, TimeoutError) as exc:
            token.raise_if_cancelled()
            try:
                poll_deadline.raise_if_expired()
            except CollectorError as deadline_exc:
                raise deadline_exc from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 연결 또는 명령 시간이 초과되었습니다.",
                retryable_network=True,
            ) from exc
        except (OSError, paramiko.SSHException) as exc:
            token.raise_if_cancelled()
            try:
                poll_deadline.raise_if_expired()
            except CollectorError as deadline_exc:
                raise deadline_exc from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 네트워크 연결에 실패했습니다.",
                retryable_network=True,
            ) from exc
        return CommandBatch(target=target, outputs=tuple(outputs))


class _NetmikoConnectionManager(AbstractContextManager[CommandConnection]):
    def __init__(
        self,
        connection: Any,
        *,
        deadline: PollDeadline | None = None,
        bounded_session_log: _BoundedSessionLog | None = None,
    ) -> None:
        self._connection: Any | None = connection
        self._closing_connection: Any | None = None
        self._lock = threading.Lock()
        self._bounded_session_log = bounded_session_log
        self._deadline = deadline
        self._deadline_stop = threading.Event()
        self._deadline_thread: threading.Thread | None = None
        if deadline is not None:
            try:
                deadline.raise_if_expired()
            except CollectorError:
                _abort_netmiko_connection(connection)
                self._connection = None
                raise
            deadline_thread = threading.Thread(
                target=self._watch_deadline,
                name="aruba-ssh-deadline-watchdog",
                daemon=True,
            )
            self._deadline_thread = deadline_thread
            deadline_thread.start()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            self.close()
        except Exception:
            if exc_type is None:
                raise

    def send_command(self, command: str, *, read_timeout: float) -> str:
        with self._lock:
            connection = self._connection
        if connection is None:
            raise CollectorError(ErrorCode.MM_UNREACHABLE, "SSH 연결이 이미 종료되었습니다.")
        result = connection.send_command(
            command,
            read_timeout=read_timeout,
            strip_prompt=False,
            strip_command=False,
        )
        return str(result)

    def send_command_bounded(
        self,
        command: str,
        *,
        read_timeout: float,
        max_output_bytes: int,
        max_output_lines: int,
    ) -> str:
        """Use Netmiko normally while rejecting oversized channel reads immediately."""

        session_log = self._bounded_session_log
        if session_log is None:
            result = self.send_command(command, read_timeout=read_timeout)
            _check_output_limits(
                result,
                max_bytes=max_output_bytes,
                max_lines=max_output_lines,
            )
            return result
        session_log.begin_command(
            max_bytes=max_output_bytes,
            max_lines=max_output_lines,
        )
        try:
            return self.send_command(command, read_timeout=read_timeout)
        except CollectorError as exc:
            if exc.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED:
                self.abort()
            raise
        finally:
            session_log.end_command()

    def close(self) -> None:
        with self._lock:
            connection = self._connection or self._closing_connection
            self._connection = None
            self._closing_connection = None
        if connection is None:
            self._stop_deadline_watchdog()
            return
        try:
            # Netmiko's graceful CLI logout can block independently of its
            # configured read timeout. A read-only collector does not require
            # a logout command, so close the owned channel/transport directly.
            _abort_netmiko_connection(connection, cleanup=True)
        finally:
            self._stop_deadline_watchdog()

    def abort(self) -> None:
        """Force-close the active transport without waiting for CLI logout."""

        with self._lock:
            connection = self._connection or self._closing_connection
            self._connection = None
            if connection is not None:
                self._closing_connection = connection
        if connection is not None:
            _abort_netmiko_connection(connection)

    def _watch_deadline(self) -> None:
        deadline = self._deadline
        if deadline is None:
            return
        if not _deadline_elapsed_before_stop(deadline, self._deadline_stop):
            return
        self.abort()

    def _stop_deadline_watchdog(self) -> None:
        self._deadline_stop.set()
        deadline_thread = self._deadline_thread
        if deadline_thread is not None and deadline_thread is not threading.current_thread():
            deadline_thread.join(timeout=1.0)
        self._deadline_thread = None


class _BoundedSessionLog(SessionLog):  # type: ignore[misc]
    """Discard session data while bounding setup, enable and command receives."""

    def __init__(self) -> None:
        super().__init__()
        self._guard_lock = threading.Lock()
        # Netmiko writes banner, prompt-discovery and enable traffic before the
        # first audited command.  Keep the hard safety cap armed from object
        # creation so a malformed peer cannot stream unbounded setup output.
        self._active = True
        self._max_bytes = MAX_OUTPUT_BYTES
        self._max_lines = MAX_OUTPUT_LINES
        self._bytes = 0
        self._line_breaks = 0
        self._has_data = False
        self._ends_with_break = False
        self._previous_was_cr = False

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def flush(self) -> None:
        return None

    def begin_command(self, *, max_bytes: int, max_lines: int) -> None:
        with self._guard_lock:
            self._active = True
            self._max_bytes = max_bytes
            self._max_lines = max_lines
            self._bytes = 0
            self._line_breaks = 0
            self._has_data = False
            self._ends_with_break = False
            self._previous_was_cr = False

    def end_command(self) -> None:
        with self._guard_lock:
            self._active = False

    def write(self, data: str) -> None:
        if not data:
            return
        with self._guard_lock:
            if not self._active:
                return
            self._bytes += len(data.encode("utf-8", errors="replace"))
            if self._bytes > self._max_bytes:
                raise CollectorError(
                    ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                    "명령 출력 크기 한도를 초과했습니다.",
                )
            for character in data:
                self._has_data = True
                if character == "\r":
                    self._line_breaks += 1
                    self._ends_with_break = True
                    self._previous_was_cr = True
                elif character == "\n":
                    if not self._previous_was_cr:
                        self._line_breaks += 1
                    self._ends_with_break = True
                    self._previous_was_cr = False
                else:
                    self._ends_with_break = False
                    self._previous_was_cr = False
            line_count = self._line_breaks + int(self._has_data and not self._ends_with_break)
            if line_count > self._max_lines:
                raise CollectorError(
                    ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                    "명령 출력 행 수 한도를 초과했습니다.",
                )


class _SocketDeadlineGuard:
    """Close a factory-owned TCP socket when connector setup exceeds the poll deadline."""

    def __init__(self, sock: socket.socket, deadline: PollDeadline) -> None:
        self._socket = sock
        self._deadline = deadline
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._watch,
            name="aruba-ssh-connect-watchdog",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=1.0)

    def close_socket(self) -> None:
        with suppress(OSError):
            self._socket.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            self._socket.close()

    def _watch(self) -> None:
        if _deadline_elapsed_before_stop(self._deadline, self._stop):
            self.close_socket()


def _abort_netmiko_connection(connection: Any, *, cleanup: bool = False) -> None:
    """Best-effort close of Netmiko/Paramiko transports used to wake blocked reads."""

    remote_channel = getattr(connection, "remote_conn", None)
    remote_client = getattr(connection, "remote_conn_pre", None)
    transport = getattr(remote_channel, "transport", None)
    if transport is None and remote_client is not None:
        transport = getattr(remote_client, "_transport", None)
    if transport is None and remote_client is not None:
        get_transport = getattr(remote_client, "get_transport", None)
        if callable(get_transport):
            with suppress(Exception):
                transport = get_transport()

    # Wake the blocking Paramiko read before invoking any higher-level cleanup.
    # Channel.close() is user-extensible and has been observed to block forever;
    # calling it first would disable the deadline watchdog itself.  A factory-
    # owned production connection always exposes the underlying transport socket.
    raw_sockets: list[Any] = []
    for candidate in (
        getattr(connection, "sock", None),
        getattr(transport, "sock", None),
    ):
        if candidate is not None and all(candidate is not item for item in raw_sockets):
            raw_sockets.append(candidate)
    for raw_socket in raw_sockets:
        shutdown = getattr(raw_socket, "shutdown", None)
        if callable(shutdown):
            with suppress(Exception):
                shutdown(socket.SHUT_RDWR)
        close = getattr(raw_socket, "close", None)
        if callable(close):
            with suppress(Exception):
                close()

    if raw_sockets and not cleanup:
        return

    # Injected test/custom connectors may not expose a socket.  Prefer the
    # transport/client cleanup path, but deliberately never call Channel.close()
    # from the watchdog because that method can block before reaching transport.
    resources: list[Any] = []
    for resource in (transport, remote_client):
        if resource is not None and all(resource is not item for item in resources):
            resources.append(resource)
    for resource in resources:
        close = getattr(resource, "close", None)
        if callable(close):
            with suppress(Exception):
                close()


KeyProbe = Callable[[DeviceTarget, float], paramiko.PKey]
NetmikoConnector = Callable[..., Any]


class _ReadOnlyArubaOsSSH(ArubaOsSSH):  # type: ignore[misc]
    """Aruba driver without implicit enable or paging commands.

    The stock Netmiko Aruba session preparation sends ``enable`` and
    ``no paging`` during object construction.  This application must keep its
    actual CLI surface explicit, so it only establishes and records the base
    prompt here.  Optional enable and session-scoped paging are performed by
    the audited code paths below.
    """

    def __init__(
        self,
        *args: Any,
        host_keys_snapshot: paramiko.HostKeys | None = None,
        **kwargs: Any,
    ) -> None:
        # BaseConnection connects during __init__, so the immutable-by-convention
        # trust snapshot must be available before the parent constructor runs.
        self._host_keys_snapshot = host_keys_snapshot
        super().__init__(*args, **kwargs)

    def _build_ssh_client(self) -> paramiko.SSHClient:
        snapshot = self._host_keys_snapshot
        if snapshot is None:
            return super()._build_ssh_client()

        remote_conn_pre = paramiko.SSHClient()
        if self.system_host_keys:
            remote_conn_pre.load_system_host_keys()
        destination = remote_conn_pre.get_host_keys()
        for hostname in snapshot:
            entries = snapshot.lookup(hostname)
            if entries is None:
                continue
            for key_type in entries:
                destination.add(hostname, key_type, entries[key_type])
        remote_conn_pre.set_missing_host_key_policy(self.key_policy)
        return remote_conn_pre

    def session_preparation(self) -> None:
        self.ansi_escape_codes = True
        self._test_channel_read(pattern=r"[>#]")
        self.set_base_prompt()


def _connect_read_only_aruba(**kwargs: Any) -> Any:
    kwargs.pop("device_type", None)
    return _ReadOnlyArubaOsSSH(**kwargs)


class StrictNetmikoFactory:
    """Netmiko connection factory with callback-gated strict known_hosts."""

    def __init__(
        self,
        known_hosts_path: Path,
        *,
        connect_timeout: float = 10.0,
        key_probe: KeyProbe | None = None,
        connector: NetmikoConnector | None = None,
    ) -> None:
        self._known_hosts_path = Path(os.path.abspath(known_hosts_path))
        self._connect_timeout = connect_timeout
        self._key_probe = key_probe or _probe_server_key
        self._connector = connector or _connect_read_only_aruba
        self._connector_uses_owned_socket = connector is None
        self._connector_enforces_strict_host_keys = connector is None
        self._host_keys_lock = _known_hosts_thread_lock(self._known_hosts_path)
        try:
            parent, self._known_hosts_parent_identity = ensure_managed_directory(
                self._known_hosts_path.parent
            )
            self._known_hosts_path = parent / self._known_hosts_path.name
            reject_managed_file_link(self._known_hosts_path)
        except UnsafeManagedPath as exc:
            raise CollectorError(
                ErrorCode.HOST_KEY_UNKNOWN,
                "known_hosts 관리 경로를 안전하게 사용할 수 없습니다.",
            ) from exc

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: HostKeyApproval | None,
        cancel_token: CancellationToken,
        deadline: PollDeadline | None = None,
    ) -> AbstractContextManager[CommandConnection]:
        poll_deadline = deadline or PollDeadline.after()
        cancel_token.raise_if_cancelled()
        poll_deadline.raise_if_expired()
        host_keys_snapshot = (
            self._known_host_keys_snapshot(target, cancel_token, poll_deadline)
            if self._connector_enforces_strict_host_keys
            else None
        )
        if host_keys_snapshot is None:
            verified_host_keys = self._probe_and_verify(
                target,
                host_key_approval,
                cancel_token,
                poll_deadline,
            )
            if self._connector_enforces_strict_host_keys:
                host_keys_snapshot = verified_host_keys
        cancel_token.raise_if_cancelled()
        poll_deadline.raise_if_expired()

        if self._connector_enforces_strict_host_keys and host_keys_snapshot is None:
            raise CollectorError(
                ErrorCode.HOST_KEY_UNKNOWN,
                "SSH 호스트 키 신뢰 정보를 안전하게 준비하지 못했습니다.",
            )

        try:
            connection_timeout = poll_deadline.bounded_timeout(self._connect_timeout)
            bounded_session_log = _BoundedSessionLog()
            connector_kwargs: dict[str, Any] = {
                "device_type": "aruba_os",
                "host": target.host,
                "port": target.port,
                "username": credentials.username,
                "password": credentials.password,
                "secret": credentials.enable_secret,
                "timeout": connection_timeout,
                "conn_timeout": connection_timeout,
                "auth_timeout": connection_timeout,
                "banner_timeout": connection_timeout,
                "ssh_strict": True,
                "system_host_keys": False,
                "alt_host_keys": True,
                "alt_key_file": str(self._known_hosts_path),
                "session_log": bounded_session_log,
            }
            if self._connector_enforces_strict_host_keys:
                connector_kwargs["host_keys_snapshot"] = host_keys_snapshot
            connector_socket: socket.socket | None = None
            connector_guard: _SocketDeadlineGuard | None = None
            if self._connector_uses_owned_socket:
                connector_socket = socket.create_connection(
                    (target.host, target.port),
                    timeout=connection_timeout,
                )
                connector_socket.settimeout(connection_timeout)
                connector_guard = _SocketDeadlineGuard(connector_socket, poll_deadline)
                connector_kwargs["sock"] = connector_socket
            try:
                if connector_guard is None:
                    connection = self._connector(**connector_kwargs)
                else:
                    with cancel_token.abort_on_cancel(connector_guard.close_socket):
                        connection = self._connector(**connector_kwargs)
            except BaseException:
                if connector_guard is not None:
                    connector_guard.close_socket()
                elif connector_socket is not None:
                    with suppress(OSError):
                        connector_socket.close()
                raise
            finally:
                if connector_guard is not None:
                    connector_guard.stop()
        except (NetmikoAuthenticationException, paramiko.AuthenticationException) as exc:
            raise CollectorError(ErrorCode.AUTH_FAILED, "SSH 인증에 실패했습니다.") from exc
        except paramiko.BadHostKeyException as exc:
            raise CollectorError(
                ErrorCode.HOST_KEY_CHANGED,
                "SSH 호스트 키가 변경되었습니다.",
            ) from exc
        except NetmikoTimeoutException as exc:
            if _is_strict_host_key_rejection(exc):
                raise CollectorError(
                    ErrorCode.HOST_KEY_CHANGED,
                    "SSH 호스트 키 검증에 실패했습니다.",
                ) from exc
            cancel_token.raise_if_cancelled()
            try:
                poll_deadline.raise_if_expired()
            except CollectorError as deadline_exc:
                raise deadline_exc from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 연결 시간이 초과되었거나 장비에 연결할 수 없습니다.",
                retryable_network=True,
            ) from exc
        except (TimeoutError, OSError) as exc:
            cancel_token.raise_if_cancelled()
            try:
                poll_deadline.raise_if_expired()
            except CollectorError as deadline_exc:
                raise deadline_exc from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 연결 시간이 초과되었거나 장비에 연결할 수 없습니다.",
                retryable_network=True,
            ) from exc
        except ValueError as exc:
            raise CollectorError(
                ErrorCode.PROMPT_PARSE_FAILED,
                "SSH 장비 프롬프트를 안전하게 확인하지 못했습니다.",
            ) from exc
        except paramiko.SSHException as exc:
            # A strict-policy rejection is never eligible for MM failover.
            if _is_strict_host_key_rejection(exc):
                raise CollectorError(
                    ErrorCode.HOST_KEY_CHANGED,
                    "SSH 호스트 키 검증에 실패했습니다.",
                ) from exc
            cancel_token.raise_if_cancelled()
            try:
                poll_deadline.raise_if_expired()
            except CollectorError as deadline_exc:
                raise deadline_exc from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 세션 수립에 실패했습니다.",
                retryable_network=True,
            ) from exc

        manager = _NetmikoConnectionManager(
            connection,
            deadline=poll_deadline,
            bounded_session_log=bounded_session_log,
        )
        if cancel_token.is_cancelled:
            with suppress(Exception):
                manager.close()
            cancel_token.raise_if_cancelled()

        if credentials.enable_secret:
            try:
                with cancel_token.abort_on_cancel(manager.abort):
                    cancel_token.raise_if_cancelled()
                    poll_deadline.raise_if_expired()
                    connection.enable()
                    cancel_token.raise_if_cancelled()
                    poll_deadline.raise_if_expired()
            except CollectorError:
                with suppress(Exception):
                    manager.close()
                raise
            except (NetmikoAuthenticationException, ValueError) as exc:
                with suppress(Exception):
                    manager.close()
                raise CollectorError(
                    ErrorCode.AUTH_FAILED,
                    "SSH Enable 인증에 실패했습니다.",
                ) from exc
            except (NetmikoTimeoutException, TimeoutError, OSError, paramiko.SSHException) as exc:
                if cancel_token.is_cancelled:
                    with suppress(Exception):
                        manager.close()
                    cancel_token.raise_if_cancelled()
                try:
                    poll_deadline.raise_if_expired()
                except CollectorError as deadline_exc:
                    with suppress(Exception):
                        manager.close()
                    raise deadline_exc from exc
                with suppress(Exception):
                    manager.close()
                raise CollectorError(
                    ErrorCode.MM_UNREACHABLE,
                    "SSH Enable 전환 중 연결이 중단되었습니다.",
                    retryable_network=True,
                ) from exc
            if cancel_token.is_cancelled:
                with suppress(Exception):
                    manager.close()
                cancel_token.raise_if_cancelled()
        return manager

    def _known_host_keys_snapshot(
        self,
        target: DeviceTarget,
        cancel_token: CancellationToken,
        deadline: PollDeadline,
    ) -> paramiko.HostKeys | None:
        host_token = _known_hosts_token(target)
        with self._locked_host_keys(cancel_token, deadline) as host_keys:
            if host_keys.lookup(host_token) is None:
                return None
            return host_keys

    def _probe_and_verify(
        self,
        target: DeviceTarget,
        host_key_approval: HostKeyApproval | None,
        cancel_token: CancellationToken,
        deadline: PollDeadline,
    ) -> paramiko.HostKeys:
        try:
            offered_key = self._key_probe(
                target,
                deadline.bounded_timeout(self._connect_timeout),
            )
        except CollectorError as exc:
            if exc.retryable_network:
                cancel_token.raise_if_cancelled()
                try:
                    deadline.raise_if_expired()
                except CollectorError as deadline_exc:
                    raise deadline_exc from exc
            raise
        except (TimeoutError, OSError, paramiko.SSHException) as exc:
            cancel_token.raise_if_cancelled()
            try:
                deadline.raise_if_expired()
            except CollectorError as deadline_exc:
                raise deadline_exc from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 호스트 키 확인 연결에 실패했습니다.",
                retryable_network=True,
            ) from exc
        cancel_token.raise_if_cancelled()
        deadline.raise_if_expired()
        return self._verify_or_approve(
            target,
            offered_key,
            host_key_approval,
            cancel_token,
            deadline,
        )

    def _verify_or_approve(
        self,
        target: DeviceTarget,
        offered_key: paramiko.PKey,
        approval: HostKeyApproval | None,
        cancel_token: CancellationToken,
        deadline: PollDeadline,
    ) -> paramiko.HostKeys:
        host_token = _known_hosts_token(target)
        cancel_token.raise_if_cancelled()
        with self._locked_host_keys(cancel_token, deadline) as host_keys:
            if _known_key_matches(host_keys, host_token, offered_key):
                return host_keys

        info = HostKeyInfo(
            algorithm=offered_key.get_name(),
            sha256_fingerprint=_sha256_fingerprint(offered_key),
        )
        approved = approval is not None and run_bounded_approval(
            approval,
            target,
            info,
            cancel_token=cancel_token,
            deadline=deadline,
        )
        cancel_token.raise_if_cancelled()
        deadline.raise_if_expired()
        if not approved:
            raise CollectorError(
                ErrorCode.HOST_KEY_UNKNOWN,
                "승인되지 않은 SSH 호스트 키입니다.",
            )

        # Approval must not hold either the process-local or cross-process lock.
        # Reload after approval so another process cannot be overwritten.
        with self._locked_host_keys(cancel_token, deadline) as host_keys:
            if _known_key_matches(host_keys, host_token, offered_key):
                return host_keys
            cancel_token.raise_if_cancelled()
            deadline.raise_if_expired()
            host_keys.add(host_token, offered_key.get_name(), offered_key)
            try:
                self._save_host_keys(host_keys)
            except OSError as exc:
                raise CollectorError(
                    ErrorCode.HOST_KEY_UNKNOWN,
                    "승인한 SSH 호스트 키를 known_hosts에 저장할 수 없습니다.",
                ) from exc
        cancel_token.raise_if_cancelled()
        deadline.raise_if_expired()
        return host_keys

    @contextmanager
    def _locked_host_keys(
        self,
        cancel_token: CancellationToken,
        deadline: PollDeadline,
    ) -> Iterator[paramiko.HostKeys]:
        try:
            with (
                _known_hosts_process_lock(
                    self._host_keys_lock,
                    cancel_token,
                    deadline,
                ),
                _known_hosts_file_lock(
                    self._known_hosts_path,
                    cancel_token,
                    deadline=deadline,
                    parent_identity=self._known_hosts_parent_identity,
                ),
            ):
                cancel_token.raise_if_cancelled()
                deadline.raise_if_expired()
                self._assert_known_hosts_path()
                try:
                    host_keys = self._load_host_keys()
                except (
                    OSError,
                    UnicodeError,
                    paramiko.SSHException,
                    InvalidHostKey,
                    binascii.Error,
                ) as exc:
                    raise CollectorError(
                        ErrorCode.HOST_KEY_CHANGED,
                        "known_hosts 파일을 안전하게 읽을 수 없습니다.",
                    ) from exc
                yield host_keys
        except CollectorError:
            raise
        except (OSError, UnsafeManagedPath) as exc:
            raise CollectorError(
                ErrorCode.HOST_KEY_UNKNOWN,
                "known_hosts 잠금을 안전하게 사용할 수 없습니다.",
            ) from exc

    def _save_host_keys(self, host_keys: paramiko.HostKeys) -> None:
        parent = self._known_hosts_path.parent
        self._assert_known_hosts_path()
        file_descriptor, temporary_name = tempfile.mkstemp(prefix="known_hosts.", dir=parent)
        os.close(file_descriptor)
        temporary_path = Path(temporary_name)
        try:
            host_keys.save(str(temporary_path))
            with temporary_path.open("r+b") as stream:
                os.fsync(stream.fileno())
            self._assert_known_hosts_path()
            os.replace(temporary_path, self._known_hosts_path)
            self._assert_known_hosts_path()
        finally:
            temporary_path.unlink(missing_ok=True)

    def _load_host_keys(self) -> paramiko.HostKeys:
        host_keys = paramiko.HostKeys()
        if not os.path.lexists(self._known_hosts_path):
            return host_keys
        before = reject_link_or_reparse(self._known_hosts_path)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("known_hosts is not a regular file")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self._known_hosts_path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or int(opened.st_dev) != int(before.st_dev)
                or int(opened.st_ino) != int(before.st_ino)
            ):
                raise OSError("known_hosts changed while opening")
            data = stream.read(MAX_KNOWN_HOSTS_BYTES + 1)
        if len(data) > MAX_KNOWN_HOSTS_BYTES:
            raise OSError("known_hosts exceeds the size limit")
        for line_number, raw_line in enumerate(data.decode("utf-8").splitlines(), 1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            entry = HostKeyEntry.from_line(line, line_number)
            if entry is None:
                continue
            for hostname in entry.hostnames:
                host_keys.add(hostname, entry.key.get_name(), entry.key)
        return host_keys

    def _assert_known_hosts_path(self) -> None:
        try:
            verify_managed_directory(
                self._known_hosts_path.parent,
                self._known_hosts_parent_identity,
            )
            reject_managed_file_link(self._known_hosts_path)
        except UnsafeManagedPath as exc:
            raise CollectorError(
                ErrorCode.HOST_KEY_UNKNOWN,
                "known_hosts 관리 경로가 실행 중 변경되었습니다.",
            ) from exc


def _known_hosts_thread_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(os.path.abspath(path))
    with _KNOWN_HOSTS_LOCKS_GUARD:
        return _KNOWN_HOSTS_LOCKS.setdefault(key, threading.Lock())


@contextmanager
def _known_hosts_process_lock(
    lock: threading.Lock,
    cancel_token: CancellationToken,
    deadline: PollDeadline,
) -> Iterator[None]:
    """Acquire one process-local trust lock within the shared poll budget."""

    acquired = False
    try:
        while not acquired:
            cancel_token.raise_if_cancelled()
            deadline.raise_if_expired()
            acquired = lock.acquire(timeout=min(0.05, deadline.remaining_seconds))
        # A cancellation or deadline that races with acquisition must win
        # before known_hosts is read or mutated.
        cancel_token.raise_if_cancelled()
        deadline.raise_if_expired()
        yield
    finally:
        if acquired:
            lock.release()


@contextmanager
def _known_hosts_file_lock(
    known_hosts_path: Path,
    cancel_token: CancellationToken,
    *,
    timeout: float = KNOWN_HOSTS_LOCK_TIMEOUT_SECONDS,
    deadline: PollDeadline | None = None,
    parent_identity: DirectoryIdentity | None = None,
) -> Iterator[None]:
    cancel_token.raise_if_cancelled()
    if deadline is not None:
        deadline.raise_if_expired()
    parent = known_hosts_path.parent
    if parent_identity is None:
        parent, parent_identity = ensure_managed_directory(parent)
        known_hosts_path = parent / known_hosts_path.name
    else:
        verify_managed_directory(parent, parent_identity)
    lock_path = known_hosts_path.with_name(f"{known_hosts_path.name}.lock")
    reject_managed_file_link(lock_path)
    lock_expires_at = time.monotonic() + timeout
    with lock_path.open("a+b") as stream:
        verify_managed_directory(parent, parent_identity)
        lock_info = reject_link_or_reparse(lock_path)
        opened = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(opened.st_dev) != int(lock_info.st_dev)
            or int(opened.st_ino) != int(lock_info.st_ino)
        ):
            raise UnsafeManagedPath("known_hosts 잠금 파일이 여는 동안 변경되었습니다.")
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        acquired = False
        try:
            while not acquired:
                cancel_token.raise_if_cancelled()
                if deadline is not None:
                    deadline.raise_if_expired()
                stream.seek(0)
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                except OSError as exc:
                    remaining = lock_expires_at - time.monotonic()
                    if remaining <= 0:
                        cancel_token.raise_if_cancelled()
                        if deadline is not None:
                            deadline.raise_if_expired()
                        raise CollectorError(
                            ErrorCode.HOST_KEY_UNKNOWN,
                            "known_hosts 잠금 시간이 초과되었습니다.",
                        ) from exc
                    wait_seconds = min(0.05, remaining)
                    if deadline is not None:
                        wait_seconds = min(wait_seconds, deadline.remaining_seconds)
                    cancel_token.wait(wait_seconds)
            # A cancellation or deadline that races with acquisition must win
            # before known_hosts is read or mutated.
            cancel_token.raise_if_cancelled()
            if deadline is not None:
                deadline.raise_if_expired()
            yield
        finally:
            if acquired:
                stream.seek(0)
                with suppress(OSError):
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def _known_key_matches(
    host_keys: paramiko.HostKeys,
    host_token: str,
    offered_key: paramiko.PKey,
) -> bool:
    known = host_keys.lookup(host_token)
    if known is None:
        return False
    expected = known.get(offered_key.get_name())
    if expected is not None and expected == offered_key:
        return True
    raise CollectorError(ErrorCode.HOST_KEY_CHANGED, "SSH 호스트 키가 변경되었습니다.")


def _is_strict_host_key_rejection(exc: BaseException) -> bool:
    pending = [exc]
    visited: set[int] = set()
    while pending:
        candidate = pending.pop()
        identity = id(candidate)
        if identity in visited:
            continue
        visited.add(identity)
        if isinstance(candidate, paramiko.BadHostKeyException):
            return True
        if isinstance(candidate, paramiko.SSHException):
            message = str(candidate).casefold()
            if "not found in known_hosts" in message:
                return True
        for linked in (candidate.__cause__, candidate.__context__):
            if linked is not None:
                pending.append(linked)
    return False


def _known_hosts_token(target: DeviceTarget) -> str:
    return target.host if target.port == 22 else f"[{target.host}]:{target.port}"


def _sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _probe_server_key(target: DeviceTarget, timeout: float) -> paramiko.PKey:
    sock = socket.create_connection((target.host, target.port), timeout=timeout)
    transport: paramiko.Transport | None = None
    try:
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        if transport is not None:
            transport.close()
        else:
            sock.close()


def _validate_command(command: str) -> None:
    if (
        command == "no paging"
        or _GLOBAL_USER_RE.fullmatch(command)
        or _DATAPATH_RE.fullmatch(command)
    ):
        return
    raise CollectorError(ErrorCode.COMMAND_REJECTED, "허용되지 않은 SSH 명령입니다.")


def _check_output_limits(output: str, *, max_bytes: int, max_lines: int) -> None:
    if len(output.encode("utf-8", errors="replace")) > max_bytes:
        raise CollectorError(ErrorCode.OUTPUT_LIMIT_EXCEEDED, "명령 출력 크기 한도를 초과했습니다.")
    # splitlines() handles CRLF and a final line without allocating another encoded copy.
    if len(output.splitlines()) > max_lines:
        raise CollectorError(
            ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            "명령 출력 행 수 한도를 초과했습니다.",
        )
