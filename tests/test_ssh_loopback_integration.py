"""Loopback-only integration coverage for the real Paramiko/Netmiko boundary."""

from __future__ import annotations

import base64
import ctypes
import gc
import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import AbstractContextManager, suppress
from ctypes import wintypes
from pathlib import Path
from types import TracebackType
from typing import Self

import paramiko
import pytest

import aruba_session_tracker.collectors.ssh as ssh_module
from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    PollDeadline,
    SSHCollector,
    StrictNetmikoFactory,
)
from aruba_session_tracker.main import _loopback_runtime_smoke
from aruba_session_tracker.models import Credentials, DeviceTarget, ErrorCode

_LOOPBACK = "127.0.0.1"
_PROMPT = "fixture-mm#"
_RESOURCE_REPEAT_ENV = "ARUBA_SSH_LOOPBACK_REPEATS"
_RESOURCE_RESULT_PREFIX = "ARUBA_SSH_LOOPBACK_RESOURCE_RESULT="


class _PasswordServer(paramiko.ServerInterface):  # type: ignore[misc]
    def __init__(self, owner: _LoopbackSshServer) -> None:
        self._owner = owner
        self.shell_requested = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        accepted = username == self._owner.username and password == self._owner.password
        with self._owner.lock:
            self._owner.auth_results.append(accepted)
        return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        del username
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        del chanid
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        del channel, term, width, height, pixelwidth, pixelheight, modes
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        del channel
        self.shell_requested.set()
        return True


class _LoopbackSshServer(AbstractContextManager["_LoopbackSshServer"]):
    """Small bounded SSH fixture that never binds outside 127.0.0.1."""

    def __init__(self) -> None:
        self.username = "fixture-operator"
        self.password = self.username[::-1]
        self.host_key = paramiko.RSAKey.generate(1024)
        self.command_outputs = {
            "no paging": "",
            "show datapath session table 192.0.2.20": "fixture-session-row",
        }
        self.auth_results: list[bool] = []
        self.commands: list[str] = []
        self.accepted_connections = 0
        self.failures: list[BaseException] = []
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((_LOOPBACK, 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port = int(self._listener.getsockname()[1])
        self._threads: list[threading.Thread] = []
        self._transports: set[paramiko.Transport] = set()
        self._accept_thread = threading.Thread(
            target=self._accept_connections,
            name=f"loopback-ssh-accept-{self.port}",
            daemon=True,
        )

    def __enter__(self) -> Self:
        self._accept_thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        self._stop.set()
        with suppress(OSError):
            self._listener.close()
        with self.lock:
            active = tuple(self._transports)
        for transport in active:
            transport.close()
        self._accept_thread.join(timeout=3)
        deadline = time.monotonic() + 5
        for worker in tuple(self._threads):
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        leaked = [worker.name for worker in self._threads if worker.is_alive()]
        if self._accept_thread.is_alive() or leaked:
            raise AssertionError(f"loopback SSH fixture leaked threads: {leaked}")
        if self.failures:
            raise AssertionError(f"loopback SSH fixture failed: {self.failures!r}")

    def _accept_connections(self) -> None:
        while not self._stop.is_set():
            try:
                client, peer = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    self.failures.append(RuntimeError("loopback listener failed"))
                return
            if peer[0] != _LOOPBACK:
                client.close()
                self.failures.append(RuntimeError("non-loopback SSH client rejected"))
                continue
            self.accepted_connections += 1
            worker = threading.Thread(
                target=self._handle_client,
                args=(client,),
                name=f"loopback-ssh-client-{len(self._threads) + 1}",
                daemon=True,
            )
            self._threads.append(worker)
            worker.start()

    def _handle_client(self, client: socket.socket) -> None:
        transport: paramiko.Transport | None = None
        channel: paramiko.Channel | None = None
        try:
            client.settimeout(3)
            transport = paramiko.Transport(client)
            with self.lock:
                self._transports.add(transport)
            transport.add_server_key(self.host_key)
            server = _PasswordServer(self)
            transport.start_server(server=server)
            channel = transport.accept(timeout=2)
            if channel is None:
                return  # The host-key-only probe intentionally stops before authentication.
            if not server.shell_requested.wait(timeout=2):
                raise TimeoutError("SSH shell request was not received")
            channel.settimeout(0.2)
            channel.sendall(_PROMPT.encode("ascii"))
            self._serve_shell(channel)
        except (EOFError, OSError, paramiko.SSHException):
            if not self._stop.is_set() and transport is not None and transport.is_active():
                self.failures.append(RuntimeError("active loopback SSH transport failed"))
        except BaseException as exc:  # pragma: no cover - asserted by fixture cleanup
            self.failures.append(exc)
        finally:
            if channel is not None:
                with suppress(Exception):
                    channel.close()
            if transport is not None:
                with suppress(Exception):
                    transport.close()
                with self.lock:
                    self._transports.discard(transport)
            with suppress(OSError):
                client.close()

    def _serve_shell(self, channel: paramiko.Channel) -> None:
        buffer = bytearray()
        while not self._stop.is_set() and not channel.closed:
            try:
                data = channel.recv(4096)
            except TimeoutError:
                continue
            if not data:
                return
            buffer.extend(data)
            while True:
                terminators = [index for value in (10, 13) if (index := buffer.find(value)) >= 0]
                if not terminators:
                    break
                index = min(terminators)
                command = bytes(buffer[:index]).decode("utf-8", errors="strict").strip()
                del buffer[: index + 1]
                while buffer and buffer[0] in (10, 13):
                    del buffer[0]
                if not command:
                    channel.sendall(_PROMPT.encode("ascii"))
                    continue
                with self.lock:
                    self.commands.append(command)
                if command == "exit":
                    return
                output = self.command_outputs.get(command, "% Invalid input")
                response = f"{command}\r\n"
                if output:
                    response += f"{output}\r\n"
                response += _PROMPT
                channel.sendall(response.encode("utf-8"))


def _collector(server: _LoopbackSshServer, known_hosts: Path) -> SSHCollector:
    factory = StrictNetmikoFactory(known_hosts, connect_timeout=3.0)
    return SSHCollector(factory, command_timeout=3.0)


def _configure_runtime_outputs(server: _LoopbackSshServer) -> str:
    fixtures = Path(__file__).parent / "fixtures"
    source = (
        (fixtures / "global_user_one.txt")
        .read_text(encoding="utf-8")
        .replace(
            "198.51.100.11",
            "127.0.0.1    ",
        )
    )
    destination = (
        (fixtures / "global_user_empty.txt")
        .read_text(encoding="utf-8")
        .replace(
            "192.0.2.99",
            "203.0.113.20",
        )
    )
    datapath = (fixtures / "datapath_sessions.txt").read_text(encoding="utf-8")
    server.command_outputs.update(
        {
            'show global-user-table list ip "192.0.2.10"': source,
            'show global-user-table list ip "203.0.113.20"': destination,
            "show datapath session table 192.0.2.10": datapath,
        }
    )
    digest = hashlib.sha256(server.host_key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _windows_handle_count() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    handle_count = wintypes.DWORD()
    process = kernel32.GetCurrentProcess()
    if not kernel32.GetProcessHandleCount(process, ctypes.byref(handle_count)):
        raise OSError(ctypes.get_last_error(), "GetProcessHandleCount failed")
    return int(handle_count.value)


def _live_worker_names() -> tuple[str, ...]:
    current = threading.current_thread()
    return tuple(
        thread.name
        for thread in threading.enumerate()
        if thread is not current and thread.is_alive()
    )


def _settled_resource_snapshot(*, timeout: float = 10.0) -> dict[str, object]:
    """Wait for Paramiko, Netmiko and fixture workers to finish before sampling."""

    deadline = time.monotonic() + timeout
    previous_handles: int | None = None
    stable_samples = 0
    while time.monotonic() < deadline:
        gc.collect()
        worker_names = _live_worker_names()
        handles = _windows_handle_count()
        if not worker_names and handles == previous_handles:
            stable_samples += 1
            if stable_samples >= 3:
                return {
                    "handles": handles,
                    "threads": len(threading.enumerate()),
                    "workers": list(worker_names),
                }
        else:
            stable_samples = 0
        previous_handles = handles
        time.sleep(0.05)
    raise RuntimeError(f"loopback SSH workers did not settle: {_live_worker_names()!r}")


def _run_repeated_loopback_connections(root: Path, repeats: int) -> dict[str, object]:
    if os.name != "nt":
        raise RuntimeError("Windows process resource counters are required")
    if not 100 <= repeats <= 500:
        raise ValueError("loopback SSH repeats must be between 100 and 500")

    credentials: Credentials
    target: DeviceTarget

    # Warm cryptography, Paramiko and Netmiko once before the baseline so the
    # comparison measures repeated-session cleanup rather than lazy imports.
    with _LoopbackSshServer() as warmup_server:
        credentials = Credentials(warmup_server.username, warmup_server.password)
        target = DeviceTarget("loopback-warmup", _LOOPBACK, warmup_server.port)
        _collector(warmup_server, root / "warmup" / "known_hosts").collect(
            target,
            credentials,
            ("no paging",),
            host_key_approval=lambda _target, _info: True,
            deadline=PollDeadline.after(10),
        )

    baseline = _settled_resource_snapshot()
    approvals: list[str] = []
    accepted_connections = 0
    authenticated_sessions = 0
    collected_commands = 0

    with _LoopbackSshServer() as server:
        credentials = Credentials(server.username, server.password)
        target = DeviceTarget("loopback-resource", _LOOPBACK, server.port)
        collector = _collector(server, root / "repeated" / "known_hosts")
        command = "show datapath session table 192.0.2.20"
        for _iteration in range(repeats):
            batch = collector.collect(
                target,
                credentials,
                ("no paging", command),
                host_key_approval=lambda _target, info: (
                    approvals.append(info.sha256_fingerprint) or True
                ),
                deadline=PollDeadline.after(10),
            )
            if "fixture-session-row" not in batch.output_for(command):
                raise AssertionError("loopback command output was incomplete")

        accepted_connections = server.accepted_connections
        authenticated_sessions = server.auth_results.count(True)
        collected_commands = server.commands.count(command)

    final = _settled_resource_snapshot()
    return {
        "repeats": repeats,
        "accepted_connections": accepted_connections,
        "authenticated_sessions": authenticated_sessions,
        "collected_commands": collected_commands,
        "approvals": len(approvals),
        "baseline": baseline,
        "final": final,
    }


def _resource_worker_main(arguments: list[str]) -> int:
    if len(arguments) != 3 or arguments[0] != "--resource-cleanup-worker":
        return 2
    root = Path(arguments[1])
    root.mkdir(parents=True, exist_ok=True)
    result = _run_repeated_loopback_connections(root, int(arguments[2]))
    print(_RESOURCE_RESULT_PREFIX + json.dumps(result, sort_keys=True))
    return 0


@pytest.mark.integration
def test_loopback_paramiko_server_approves_host_key_and_collects_command(
    tmp_path: Path,
) -> None:
    with _LoopbackSshServer() as server:
        target = DeviceTarget("loopback-fixture", _LOOPBACK, server.port)
        credentials = Credentials(server.username, server.password)
        approvals: list[str] = []
        collector = _collector(server, tmp_path / "known_hosts")

        batch = collector.collect(
            target,
            credentials,
            ("no paging", "show datapath session table 192.0.2.20"),
            host_key_approval=lambda _target, info: (
                approvals.append(info.sha256_fingerprint) or True
            ),
            deadline=PollDeadline.after(10),
        )

        assert len(approvals) == 1
        assert approvals[0].startswith("SHA256:")
        assert "fixture-session-row" in batch.output_for("show datapath session table 192.0.2.20")
        assert "no paging" in server.commands
        assert "show datapath session table 192.0.2.20" in server.commands
        assert True in server.auth_results
        assert server.accepted_connections == 2

        collector.collect(
            target,
            credentials,
            ("no paging",),
            host_key_approval=lambda _target, _info: pytest.fail("known host requested approval"),
            deadline=PollDeadline.after(10),
        )

        # First trust uses one probe plus one authenticated connection. Once the
        # target token is known, the actual strict connection is sufficient.
        assert server.accepted_connections == 3
        assert server.auth_results.count(True) == 2


@pytest.mark.integration
def test_loopback_known_host_key_change_is_blocked_without_a_probe(tmp_path: Path) -> None:
    with _LoopbackSshServer() as server:
        target = DeviceTarget("loopback-fixture", _LOOPBACK, server.port)
        credentials = Credentials(server.username, server.password)
        known_hosts = tmp_path / "known_hosts"
        wrong_key = paramiko.RSAKey.generate(1024)
        host_keys = paramiko.HostKeys()
        host_keys.add(f"[{target.host}]:{target.port}", wrong_key.get_name(), wrong_key)
        host_keys.save(str(known_hosts))

        with pytest.raises(CollectorError) as caught:
            _collector(server, known_hosts).collect(
                target,
                credentials,
                ("no paging",),
                host_key_approval=lambda _target, _info: pytest.fail(
                    "known host requested approval"
                ),
                deadline=PollDeadline.after(10),
            )

        assert caught.value.code is ErrorCode.HOST_KEY_CHANGED
        assert caught.value.retryable_network is False
        assert server.accepted_connections == 1
        assert server.auth_results == []


@pytest.mark.integration
def test_loopback_connection_uses_locked_host_key_snapshot_after_file_replacement(
    tmp_path: Path,
) -> None:
    with _LoopbackSshServer() as server:
        target = DeviceTarget("loopback-fixture", _LOOPBACK, server.port)
        credentials = Credentials(server.username, server.password)
        known_hosts = tmp_path / "known_hosts"
        originally_trusted_key = paramiko.RSAKey.generate(1024)
        host_token = f"[{target.host}]:{target.port}"
        host_keys = paramiko.HostKeys()
        host_keys.add(host_token, originally_trusted_key.get_name(), originally_trusted_key)
        host_keys.save(str(known_hosts))

        factory = StrictNetmikoFactory(known_hosts, connect_timeout=3.0)
        production_connector = ssh_module._connect_read_only_aruba

        def replace_file_then_connect(**kwargs: object) -> object:
            replacement = paramiko.HostKeys()
            replacement.add(host_token, server.host_key.get_name(), server.host_key)
            replacement.save(str(known_hosts))
            return production_connector(**kwargs)

        # Keep the production strict/single-socket flags while injecting the
        # replacement at the exact boundary between safe loading and connect.
        factory._connector = replace_file_then_connect
        collector = SSHCollector(factory, command_timeout=3.0)

        with pytest.raises(CollectorError) as caught:
            collector.collect(
                target,
                credentials,
                ("no paging",),
                host_key_approval=lambda _target, _info: pytest.fail(
                    "known host requested approval"
                ),
                deadline=PollDeadline.after(10),
            )

        assert caught.value.code is ErrorCode.HOST_KEY_CHANGED
        assert caught.value.retryable_network is False
        assert paramiko.HostKeys(str(known_hosts)).check(host_token, server.host_key) is True
        assert server.accepted_connections == 1
        assert server.auth_results == []


@pytest.mark.integration
def test_loopback_paramiko_server_maps_password_rejection_to_fatal_auth_failure(
    tmp_path: Path,
) -> None:
    with _LoopbackSshServer() as server:
        target = DeviceTarget("loopback-fixture", _LOOPBACK, server.port)
        credentials = Credentials(server.username, f"{server.password}-wrong")

        with pytest.raises(CollectorError) as caught:
            _collector(server, tmp_path / "known_hosts").collect(
                target,
                credentials,
                ("no paging",),
                host_key_approval=lambda _target, _info: True,
                deadline=PollDeadline.after(10),
                cancel_token=CancellationToken(),
            )

        assert caught.value.code is ErrorCode.AUTH_FAILED
        assert caught.value.retryable_network is False
        assert False in server.auth_results


@pytest.mark.integration
@pytest.mark.parametrize("mode", ("success", "auth-failure"))
def test_loopback_runtime_smoke_covers_full_success_and_auth_failure(mode: str) -> None:
    with _LoopbackSshServer() as server:
        fingerprint = _configure_runtime_outputs(server)

        result = _loopback_runtime_smoke(server.port, fingerprint, mode)

        assert result == 0
        if mode == "success":
            assert 'show global-user-table list ip "192.0.2.10"' in server.commands
            assert 'show global-user-table list ip "203.0.113.20"' in server.commands
            assert "show datapath session table 192.0.2.10" in server.commands
            assert True in server.auth_results
        else:
            assert False in server.auth_results


@pytest.mark.integration
@pytest.mark.windows
def test_repeated_loopback_ssh_connections_release_threads_and_handles(tmp_path: Path) -> None:
    """Repeat the real local SSH boundary without retaining client resources."""

    if os.name != "nt":
        pytest.skip("Windows process resource counters are required")
    repeats = int(os.environ.get(_RESOURCE_REPEAT_ENV, "100"))
    if not 100 <= repeats <= 500:
        raise ValueError(f"{_RESOURCE_REPEAT_ENV} must be between 100 and 500")

    repository = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(repository / "src") + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--resource-cleanup-worker",
            str(tmp_path / "worker"),
            str(repeats),
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=min(480, max(180, repeats * 2)),
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    result_lines = tuple(
        line.removeprefix(_RESOURCE_RESULT_PREFIX)
        for line in completed.stdout.splitlines()
        if line.startswith(_RESOURCE_RESULT_PREFIX)
    )
    assert len(result_lines) == 1, completed.stdout[-4000:]
    result = json.loads(result_lines[0])
    baseline = result["baseline"]
    final = result["final"]

    assert result["repeats"] == repeats
    # Initial trust has one probe and one authenticated session. Every repeated
    # known-host collection after that has only the strict authenticated session.
    assert result["accepted_connections"] == repeats + 1
    assert result["authenticated_sessions"] == repeats
    assert result["collected_commands"] == repeats
    assert result["approvals"] == 1
    assert final["workers"] == []
    assert int(final["handles"]) - int(baseline["handles"]) <= 5, result
    assert int(final["threads"]) - int(baseline["threads"]) <= 1, result


if __name__ == "__main__":  # pragma: no cover - exercised by the subprocess test
    raise SystemExit(_resource_worker_main(sys.argv[1:]))
