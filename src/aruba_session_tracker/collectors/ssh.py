"""Strict, bounded and read-only SSH collection.

The concrete factory performs a Paramiko host-key handshake first and then lets
Netmiko establish the authenticated CLI session with strict known-host checking.
This two-step design gives the GUI a chance to display an unknown fingerprint
without ever weakening the authenticated connection's host-key policy.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import socket
import tempfile
import threading
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager, suppress
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol, Self

import paramiko
from netmiko.aruba.aruba_os import ArubaOsSSH
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.hostkeys import InvalidHostKey

from aruba_session_tracker.models import Credentials, DeviceTarget, ErrorCode
from aruba_session_tracker.parsers.common import ParseError, reject_command_errors

MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_LINES = 50_000

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

    def cancel(self) -> None:
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds; return true when cancellation won."""
        return self._event.wait(timeout)

    def raise_if_cancelled(self) -> None:
        if self.is_cancelled:
            raise CollectorError(ErrorCode.CANCELLED, "작업이 취소되었습니다.")


@dataclass(frozen=True, slots=True)
class HostKeyInfo:
    algorithm: str
    sha256_fingerprint: str


HostKeyApproval = Callable[[DeviceTarget, HostKeyInfo], bool]


class CollectorError(RuntimeError):
    """Sanitized collection failure with explicit failover eligibility."""

    def __init__(self, code: ErrorCode, message: str, *, retryable_network: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable_network = retryable_network


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
    ) -> CommandBatch:
        token = cancel_token or CancellationToken()
        requested = tuple(commands)
        if not requested:
            raise ValueError("실행할 명령이 없습니다.")
        for command in requested:
            _validate_command(command)

        token.raise_if_cancelled()
        outputs: list[CommandOutput] = []
        try:
            manager = self._factory.connect(
                target,
                credentials,
                host_key_approval=host_key_approval,
                cancel_token=token,
            )
            with manager as connection:
                for command in requested:
                    token.raise_if_cancelled()
                    output = connection.send_command(command, read_timeout=self._command_timeout)
                    token.raise_if_cancelled()
                    _check_output_limits(
                        output,
                        max_bytes=self._max_output_bytes,
                        max_lines=self._max_output_lines,
                    )
                    if command == "no paging":
                        try:
                            reject_command_errors(output)
                        except ParseError as exc:
                            raise CollectorError(
                                ErrorCode.COMMAND_VARIANT_UNVERIFIED,
                                "장비가 세션 페이징 해제 명령을 거부했습니다.",
                            ) from exc
                    outputs.append(CommandOutput(command=command, output=output))
        except CollectorError:
            raise
        except (NetmikoAuthenticationException, paramiko.AuthenticationException) as exc:
            raise CollectorError(ErrorCode.AUTH_FAILED, "SSH 인증에 실패했습니다.") from exc
        except (NetmikoTimeoutException, TimeoutError) as exc:
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 연결 또는 명령 시간이 초과되었습니다.",
                retryable_network=True,
            ) from exc
        except (OSError, paramiko.SSHException) as exc:
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 네트워크 연결에 실패했습니다.",
                retryable_network=True,
            ) from exc
        return CommandBatch(target=target, outputs=tuple(outputs))


class _NetmikoConnectionManager(AbstractContextManager[CommandConnection]):
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def send_command(self, command: str, *, read_timeout: float) -> str:
        result = self._connection.send_command(
            command,
            read_timeout=read_timeout,
            strip_prompt=False,
            strip_command=False,
        )
        return str(result)

    def close(self) -> None:
        self._connection.disconnect()


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
        self._known_hosts_path = Path(known_hosts_path)
        self._connect_timeout = connect_timeout
        self._key_probe = key_probe or _probe_server_key
        self._connector = connector or _connect_read_only_aruba
        self._host_keys_lock = threading.Lock()

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: HostKeyApproval | None,
        cancel_token: CancellationToken,
    ) -> AbstractContextManager[CommandConnection]:
        cancel_token.raise_if_cancelled()
        try:
            offered_key = self._key_probe(target, self._connect_timeout)
        except CollectorError:
            raise
        except (TimeoutError, OSError, paramiko.SSHException) as exc:
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 호스트 키 확인 연결에 실패했습니다.",
                retryable_network=True,
            ) from exc
        cancel_token.raise_if_cancelled()
        self._verify_or_approve(target, offered_key, host_key_approval)

        try:
            connection = self._connector(
                device_type="aruba_os",
                host=target.host,
                port=target.port,
                username=credentials.username,
                password=credentials.password,
                secret=credentials.enable_secret,
                timeout=self._connect_timeout,
                conn_timeout=self._connect_timeout,
                auth_timeout=self._connect_timeout,
                banner_timeout=self._connect_timeout,
                ssh_strict=True,
                system_host_keys=False,
                alt_host_keys=True,
                alt_key_file=str(self._known_hosts_path),
            )
        except (NetmikoAuthenticationException, paramiko.AuthenticationException) as exc:
            raise CollectorError(ErrorCode.AUTH_FAILED, "SSH 인증에 실패했습니다.") from exc
        except paramiko.BadHostKeyException as exc:
            raise CollectorError(
                ErrorCode.HOST_KEY_CHANGED,
                "SSH 호스트 키가 변경되었습니다.",
            ) from exc
        except (NetmikoTimeoutException, TimeoutError, OSError) as exc:
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
            if "host key" in str(exc).lower():
                raise CollectorError(
                    ErrorCode.HOST_KEY_CHANGED,
                    "SSH 호스트 키 검증에 실패했습니다.",
                ) from exc
            raise CollectorError(
                ErrorCode.MM_UNREACHABLE,
                "SSH 세션 수립에 실패했습니다.",
                retryable_network=True,
            ) from exc

        if credentials.enable_secret:
            try:
                connection.enable()
            except (NetmikoAuthenticationException, ValueError) as exc:
                with suppress(Exception):
                    connection.disconnect()
                raise CollectorError(
                    ErrorCode.AUTH_FAILED,
                    "SSH Enable 인증에 실패했습니다.",
                ) from exc
            except (NetmikoTimeoutException, TimeoutError, OSError) as exc:
                with suppress(Exception):
                    connection.disconnect()
                raise CollectorError(
                    ErrorCode.MM_UNREACHABLE,
                    "SSH Enable 전환 중 연결이 중단되었습니다.",
                    retryable_network=True,
                ) from exc
        return _NetmikoConnectionManager(connection)

    def _verify_or_approve(
        self,
        target: DeviceTarget,
        offered_key: paramiko.PKey,
        approval: HostKeyApproval | None,
    ) -> None:
        host_token = _known_hosts_token(target)
        with self._host_keys_lock:
            host_keys = paramiko.HostKeys()
            if self._known_hosts_path.exists():
                try:
                    host_keys.load(str(self._known_hosts_path))
                except (OSError, paramiko.SSHException, InvalidHostKey, binascii.Error) as exc:
                    raise CollectorError(
                        ErrorCode.HOST_KEY_CHANGED,
                        "known_hosts 파일을 안전하게 읽을 수 없습니다.",
                    ) from exc

            known = host_keys.lookup(host_token)
            if known is not None:
                expected = known.get(offered_key.get_name())
                if expected is not None and expected == offered_key:
                    return
                raise CollectorError(ErrorCode.HOST_KEY_CHANGED, "SSH 호스트 키가 변경되었습니다.")

            info = HostKeyInfo(
                algorithm=offered_key.get_name(),
                sha256_fingerprint=_sha256_fingerprint(offered_key),
            )
            if approval is None or not approval(target, info):
                raise CollectorError(
                    ErrorCode.HOST_KEY_UNKNOWN,
                    "승인되지 않은 SSH 호스트 키입니다.",
                )
            host_keys.add(host_token, offered_key.get_name(), offered_key)
            try:
                self._save_host_keys(host_keys)
            except OSError as exc:
                # A local trust-store failure is not a network error and must
                # never make MM standby failover eligible.
                raise CollectorError(
                    ErrorCode.HOST_KEY_UNKNOWN,
                    "승인한 SSH 호스트 키를 known_hosts에 저장할 수 없습니다.",
                ) from exc

    def _save_host_keys(self, host_keys: paramiko.HostKeys) -> None:
        parent = self._known_hosts_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(prefix="known_hosts.", dir=parent)
        os.close(file_descriptor)
        temporary_path = Path(temporary_name)
        try:
            host_keys.save(str(temporary_path))
            os.replace(temporary_path, self._known_hosts_path)
        finally:
            temporary_path.unlink(missing_ok=True)


def _known_hosts_token(target: DeviceTarget) -> str:
    return target.host if target.port == 22 else f"[{target.host}]:{target.port}"


def _sha256_fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _probe_server_key(target: DeviceTarget, timeout: float) -> paramiko.PKey:
    sock = socket.create_connection((target.host, target.port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        transport.close()


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
