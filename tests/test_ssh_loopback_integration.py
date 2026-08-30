"""Loopback-only integration coverage for the real Paramiko/Netmiko boundary."""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
import time
from contextlib import AbstractContextManager, suppress
from pathlib import Path
from types import TracebackType
from typing import Self

import paramiko
import pytest

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


@pytest.mark.integration
def test_loopback_paramiko_server_approves_host_key_and_collects_command(
    tmp_path: Path,
) -> None:
    with _LoopbackSshServer() as server:
        target = DeviceTarget("loopback-fixture", _LOOPBACK, server.port)
        credentials = Credentials(server.username, server.password)
        approvals: list[str] = []

        batch = _collector(server, tmp_path / "known_hosts").collect(
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
