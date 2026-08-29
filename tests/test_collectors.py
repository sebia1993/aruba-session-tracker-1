from __future__ import annotations

import os
from contextlib import AbstractContextManager
from pathlib import Path
from threading import Barrier, Event, Thread
from types import TracebackType
from typing import Self

import paramiko
import pytest
from netmiko.exceptions import NetmikoAuthenticationException

import aruba_session_tracker.collectors.ssh as ssh_module
from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    CommandConnection,
    HostKeyInfo,
    PollDeadline,
    SSHCollector,
    StrictNetmikoFactory,
)
from aruba_session_tracker.collectors.ssh import (
    _known_hosts_file_lock,
    _NetmikoConnectionManager,
)
from aruba_session_tracker.models import Credentials, DeviceTarget, ErrorCode


class FakeConnection(AbstractContextManager[CommandConnection]):
    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        self.commands: list[str] = []
        self.closed = False

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
        self.commands.append(command)
        return self.outputs[command]

    def close(self) -> None:
        self.closed = True


class FakeFactory:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection
        self.connect_count = 0

    def connect(self, *args: object, **kwargs: object) -> FakeConnection:
        self.connect_count += 1
        return self.connection


TARGET = DeviceTarget("MM", "192.0.2.10")
CREDENTIALS = Credentials("operator", "secret")


def test_collector_allows_only_filtered_read_commands() -> None:
    connection = FakeConnection({"no paging": "", "show datapath session table 192.0.2.20": "ok"})
    factory = FakeFactory(connection)
    batch = SSHCollector(factory).collect(
        TARGET,
        CREDENTIALS,
        ("no paging", "show datapath session table 192.0.2.20"),
    )
    assert [item.command for item in batch.outputs] == [
        "no paging",
        "show datapath session table 192.0.2.20",
    ]

    with pytest.raises(CollectorError) as caught:
        SSHCollector(factory).collect(TARGET, CREDENTIALS, ("show datapath session table",))
    assert caught.value.code is ErrorCode.COMMAND_REJECTED
    assert factory.connect_count == 1


def test_collector_checks_cancellation_and_output_limits() -> None:
    token = CancellationToken()
    token.cancel()
    factory = FakeFactory(FakeConnection({"no paging": ""}))
    with pytest.raises(CollectorError) as caught:
        SSHCollector(factory).collect(TARGET, CREDENTIALS, ("no paging",), cancel_token=token)
    assert caught.value.code is ErrorCode.CANCELLED
    assert factory.connect_count == 0

    oversized = FakeFactory(FakeConnection({"no paging": "x" * 11}))
    with pytest.raises(CollectorError) as caught:
        SSHCollector(oversized, max_output_bytes=10).collect(TARGET, CREDENTIALS, ("no paging",))
    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED

    rejected_paging = FakeFactory(FakeConnection({"no paging": "% Invalid input"}))
    with pytest.raises(CollectorError) as caught:
        SSHCollector(rejected_paging).collect(TARGET, CREDENTIALS, ("no paging",))
    assert caught.value.code is ErrorCode.COMMAND_VARIANT_UNVERIFIED

    too_many_lines = FakeFactory(FakeConnection({"no paging": "1\n2\n3"}))
    with pytest.raises(CollectorError) as caught:
        SSHCollector(too_many_lines, max_output_lines=2).collect(
            TARGET, CREDENTIALS, ("no paging",)
        )
    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_cancellation_wins_over_timeout_and_cleanup_failure() -> None:
    token = CancellationToken()

    class CancelThenTimeout(FakeConnection):
        def send_command(self, command: str, *, read_timeout: float) -> str:
            del command, read_timeout
            token.cancel()
            raise TimeoutError("fixture timeout")

        def close(self) -> None:
            self.closed = True
            raise OSError("fixture cleanup failure")

    connection = CancelThenTimeout({"no paging": ""})
    with pytest.raises(CollectorError) as caught:
        SSHCollector(FakeFactory(connection)).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
            cancel_token=token,
        )

    assert caught.value.code is ErrorCode.CANCELLED
    assert connection.closed is True


def test_expired_poll_deadline_fails_before_opening_connection() -> None:
    connection = FakeConnection({"no paging": ""})
    factory = FakeFactory(connection)

    with pytest.raises(CollectorError) as caught:
        SSHCollector(factory).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
            deadline=PollDeadline(1.0, lambda: 1.0),
        )

    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert caught.value.retryable_network is True
    assert factory.connect_count == 0


def test_command_timeout_at_poll_deadline_uses_deadline_error_code() -> None:
    now = [0.0]

    class DeadlineTimeout(FakeConnection):
        def send_command(self, command: str, *, read_timeout: float) -> str:
            del command, read_timeout
            now[0] = 5.0
            raise TimeoutError("fixture command timeout")

    with pytest.raises(CollectorError) as caught:
        SSHCollector(FakeFactory(DeadlineTimeout({"no paging": ""}))).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
            deadline=PollDeadline(5.0, lambda: now[0]),
        )

    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert caught.value.retryable_network is True


def test_cancellation_callback_is_idempotent() -> None:
    token = CancellationToken()
    callback_calls = 0

    def callback() -> None:
        nonlocal callback_calls
        callback_calls += 1

    with token.abort_on_cancel(callback):
        token.cancel()
        token.cancel()

    assert callback_calls == 1


def test_cancellation_callback_aborts_a_blocked_netmiko_transport() -> None:
    entered = Event()
    channel_closed = Event()

    class BlockingNetmiko:
        remote_conn = None
        remote_conn_pre = None

        def __init__(self) -> None:
            self.remote_conn = self

        def send_command(self, *_args: object, **_kwargs: object) -> str:
            entered.set()
            assert channel_closed.wait(timeout=5)
            raise OSError("fixture transport aborted")

        def close(self) -> None:
            channel_closed.set()

        def disconnect(self) -> None:
            channel_closed.set()

    connection = BlockingNetmiko()
    manager = _NetmikoConnectionManager(connection)

    class ManagerFactory:
        def connect(self, *_args: object, **_kwargs: object) -> _NetmikoConnectionManager:
            return manager

    token = CancellationToken()
    failures: list[CollectorError] = []

    def collect() -> None:
        try:
            SSHCollector(ManagerFactory()).collect(
                TARGET,
                CREDENTIALS,
                ("no paging",),
                cancel_token=token,
            )
        except CollectorError as exc:
            failures.append(exc)

    worker = Thread(target=collect)
    worker.start()
    assert entered.wait(timeout=5)
    token.cancel()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert channel_closed.is_set()
    assert [failure.code for failure in failures] == [ErrorCode.CANCELLED]


def test_cancellation_callback_remains_active_during_ssh_teardown() -> None:
    disconnect_started = Event()
    channel_closed = Event()

    class BlockingDisconnect:
        remote_conn = None
        remote_conn_pre = None

        def __init__(self) -> None:
            self.remote_conn = self

        def send_command(self, *_args: object, **_kwargs: object) -> str:
            return ""

        def disconnect(self) -> None:
            disconnect_started.set()
            assert channel_closed.wait(timeout=5)

        def close(self) -> None:
            channel_closed.set()

    manager = _NetmikoConnectionManager(BlockingDisconnect())

    class ManagerFactory:
        def connect(self, *_args: object, **_kwargs: object) -> _NetmikoConnectionManager:
            return manager

    token = CancellationToken()
    failures: list[CollectorError] = []

    def collect() -> None:
        try:
            SSHCollector(ManagerFactory()).collect(
                TARGET,
                CREDENTIALS,
                ("no paging",),
                cancel_token=token,
            )
        except CollectorError as exc:
            failures.append(exc)

    worker = Thread(target=collect)
    worker.start()
    assert disconnect_started.wait(timeout=5)
    token.cancel()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert channel_closed.is_set()
    assert [failure.code for failure in failures] == [ErrorCode.CANCELLED]


def test_cancellation_does_not_hide_an_authentication_failure() -> None:
    token = CancellationToken()

    class CancelThenAuthenticationFailure:
        def connect(self, *args: object, **kwargs: object) -> FakeConnection:
            del args, kwargs
            token.cancel()
            raise CollectorError(ErrorCode.AUTH_FAILED, "authentication failed")

    with pytest.raises(CollectorError) as caught:
        SSHCollector(CancelThenAuthenticationFailure()).collect(  # type: ignore[arg-type]
            TARGET,
            CREDENTIALS,
            ("no paging",),
            cancel_token=token,
        )

    assert caught.value.code is ErrorCode.AUTH_FAILED


def test_primary_collector_error_is_not_masked_by_cleanup_failure() -> None:
    class RejectThenFailCleanup(FakeConnection):
        def close(self) -> None:
            self.closed = True
            raise OSError("fixture cleanup failure")

    connection = RejectThenFailCleanup({"no paging": "% Invalid input"})
    with pytest.raises(CollectorError) as caught:
        SSHCollector(FakeFactory(connection)).collect(TARGET, CREDENTIALS, ("no paging",))

    assert caught.value.code is ErrorCode.COMMAND_VARIANT_UNVERIFIED
    assert connection.closed is True


class FakeNetmiko:
    def __init__(self) -> None:
        self.enable_called = False

    def send_command(self, command: str, **kwargs: object) -> str:
        return ""

    def enable(self) -> None:
        self.enable_called = True

    def disconnect(self) -> None:
        return None


def test_factory_cancellation_does_not_hide_connector_authentication_failure(
    tmp_path: Path,
) -> None:
    key = paramiko.RSAKey.generate(1024)
    token = CancellationToken()

    def fail_authentication(**_kwargs: object) -> FakeNetmiko:
        token.cancel()
        raise NetmikoAuthenticationException("fixture authentication failure")

    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=fail_authentication,
    )

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=token,
        )

    assert caught.value.code is ErrorCode.AUTH_FAILED


def test_probe_closes_socket_when_transport_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ProbeSocket:
        closed = False

        def close(self) -> None:
            self.closed = True

    probe_socket = ProbeSocket()
    monkeypatch.setattr(
        ssh_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: probe_socket,
    )

    def fail_transport(_socket: object) -> object:
        raise OSError("fixture transport construction failure")

    monkeypatch.setattr(ssh_module.paramiko, "Transport", fail_transport)

    with pytest.raises(OSError, match="transport construction"):
        ssh_module._probe_server_key(TARGET, timeout=1.0)

    assert probe_socket.closed is True


def test_unknown_host_key_requires_callback_and_changed_key_fails_closed(tmp_path: Path) -> None:
    first_key = paramiko.RSAKey.generate(1024)
    second_key = paramiko.RSAKey.generate(1024)
    offered = [first_key]
    connector_calls: list[dict[str, object]] = []

    def probe(target: DeviceTarget, timeout: float) -> paramiko.PKey:
        return offered[0]

    def connector(**kwargs: object) -> FakeNetmiko:
        connector_calls.append(kwargs)
        return FakeNetmiko()

    known_hosts = tmp_path / "known_hosts"
    factory = StrictNetmikoFactory(known_hosts, key_probe=probe, connector=connector)

    def approve_first_key(_target: DeviceTarget, info: HostKeyInfo) -> bool:
        approvals.append(info.sha256_fingerprint)
        return True

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=None,
            cancel_token=CancellationToken(),
        )
    assert caught.value.code is ErrorCode.HOST_KEY_UNKNOWN
    assert not known_hosts.exists()

    approvals: list[str] = []
    with factory.connect(
        TARGET,
        CREDENTIALS,
        host_key_approval=approve_first_key,
        cancel_token=CancellationToken(),
    ):
        pass
    assert approvals[0].startswith("SHA256:")
    assert known_hosts.exists()
    assert connector_calls[-1]["ssh_strict"] is True
    assert connector_calls[-1]["alt_key_file"] == str(known_hosts)

    # A known matching key no longer asks for approval.
    with factory.connect(
        TARGET,
        CREDENTIALS,
        host_key_approval=lambda *_args: pytest.fail("known key prompted again"),
        cancel_token=CancellationToken(),
    ):
        pass

    offered[0] = second_key
    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
        )
    assert caught.value.code is ErrorCode.HOST_KEY_CHANGED
    assert caught.value.retryable_network is False


def test_known_hosts_parent_identity_change_fails_closed(tmp_path: Path) -> None:
    parent = tmp_path / "trust"
    parent.mkdir()
    known_hosts = parent / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    connector_called = False

    def connector(**_kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: key,
        connector=connector,
    )
    original = tmp_path / "trust-original"
    os.replace(parent, original)
    parent.mkdir()

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
        )

    assert caught.value.code is ErrorCode.HOST_KEY_UNKNOWN
    assert connector_called is False
    assert not known_hosts.exists()


def test_known_hosts_read_is_bounded_before_trust_evaluation(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_bytes(b"#" * (ssh_module.MAX_KNOWN_HOSTS_BYTES + 1))
    connector_called = False

    def connector(**_kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: paramiko.RSAKey.generate(1024),
        connector=connector,
    )

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
        )

    assert caught.value.code is ErrorCode.HOST_KEY_CHANGED
    assert connector_called is False


def test_known_hosts_write_failure_is_not_network_failover_eligible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = paramiko.RSAKey.generate(1024)
    connector_called = False

    def connector(**kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=connector,
    )

    def fail_save(_keys: paramiko.HostKeys) -> None:
        raise OSError("fixture write failure")

    monkeypatch.setattr(factory, "_save_host_keys", fail_save)
    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
        )
    assert caught.value.code is ErrorCode.HOST_KEY_UNKNOWN
    assert caught.value.retryable_network is False
    assert connector_called is False


def test_optional_enable_secret_enters_enable_mode(tmp_path: Path) -> None:
    key = paramiko.RSAKey.generate(1024)
    connection = FakeNetmiko()
    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=lambda **_kwargs: connection,
    )
    with factory.connect(
        TARGET,
        Credentials("operator", "secret", "enable-secret"),
        host_key_approval=lambda *_args: True,
        cancel_token=CancellationToken(),
    ):
        pass
    assert connection.enable_called is True


def test_connector_prompt_failure_is_sanitized_and_not_retryable(tmp_path: Path) -> None:
    key = paramiko.RSAKey.generate(1024)

    def fail_connector(**_kwargs: object) -> FakeNetmiko:
        raise ValueError("raw prompt with device identity")

    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=fail_connector,
    )
    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
        )

    assert caught.value.code is ErrorCode.PROMPT_PARSE_FAILED
    assert caught.value.retryable_network is False
    assert "device identity" not in str(caught.value)


def test_host_key_approval_cancellation_never_saves_or_connects(tmp_path: Path) -> None:
    key = paramiko.RSAKey.generate(1024)
    token = CancellationToken()
    connector_called = False

    def connector(**_kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    def cancel_during_approval(_target: DeviceTarget, _info: HostKeyInfo) -> bool:
        token.cancel()
        return False

    known_hosts = tmp_path / "known_hosts"
    factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: key,
        connector=connector,
    )
    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=cancel_during_approval,
            cancel_token=token,
        )

    assert caught.value.code is ErrorCode.CANCELLED
    assert not known_hosts.exists()
    assert connector_called is False


def test_factories_for_same_path_do_not_hold_trust_lock_during_approval(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    first_target = DeviceTarget("MM-1", "192.0.2.10")
    second_target = DeviceTarget("MM-2", "192.0.2.11")
    targets = (first_target, second_target)
    keys = {
        first_target.host: paramiko.RSAKey.generate(1024),
        second_target.host: paramiko.RSAKey.generate(1024),
    }
    approval_barrier = Barrier(2)
    failures: list[BaseException] = []

    def approval(_target: DeviceTarget, _info: HostKeyInfo) -> bool:
        approval_barrier.wait(timeout=5)
        return True

    def connect(target: DeviceTarget) -> None:
        factory = StrictNetmikoFactory(
            known_hosts,
            key_probe=lambda device, _timeout: keys[device.host],
            connector=lambda **_kwargs: FakeNetmiko(),
        )
        try:
            with factory.connect(
                target,
                CREDENTIALS,
                host_key_approval=approval,
                cancel_token=CancellationToken(),
            ):
                pass
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    workers = [Thread(target=connect, args=(target,)) for target in targets]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)

    assert all(not worker.is_alive() for worker in workers)
    assert failures == []
    saved = paramiko.HostKeys(str(known_hosts))
    assert saved.lookup(first_target.host) is not None
    assert saved.lookup(second_target.host) is not None


def test_known_hosts_cross_process_lock_fails_closed_at_bound(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    with (
        _known_hosts_file_lock(known_hosts, CancellationToken()),
        pytest.raises(CollectorError) as caught,
        _known_hosts_file_lock(
            known_hosts,
            CancellationToken(),
            timeout=0.0,
        ),
    ):
        pytest.fail("an already-held known_hosts lock was acquired")

    assert caught.value.code is ErrorCode.HOST_KEY_UNKNOWN
    assert caught.value.retryable_network is False


def test_connection_manager_close_is_idempotent_and_cleanup_error_is_sanitized(
    tmp_path: Path,
) -> None:
    key = paramiko.RSAKey.generate(1024)

    class FailingDisconnect(FakeNetmiko):
        def __init__(self) -> None:
            super().__init__()
            self.disconnect_calls = 0

        def disconnect(self) -> None:
            self.disconnect_calls += 1
            raise OSError("sensitive cleanup detail")

    connection = FailingDisconnect()
    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=lambda **_kwargs: connection,
    )
    manager = factory.connect(
        TARGET,
        CREDENTIALS,
        host_key_approval=lambda *_args: True,
        cancel_token=CancellationToken(),
    )

    with pytest.raises(CollectorError) as caught:
        manager.close()  # type: ignore[attr-defined]
    manager.close()  # type: ignore[attr-defined]

    assert caught.value.code is ErrorCode.MM_UNREACHABLE
    assert "sensitive" not in str(caught.value)
    assert connection.disconnect_calls == 1
