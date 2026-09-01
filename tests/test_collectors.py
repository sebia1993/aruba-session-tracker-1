from __future__ import annotations

import os
import threading
import time
from contextlib import AbstractContextManager
from pathlib import Path
from threading import Barrier, Event, Thread
from types import TracebackType
from typing import Self

import paramiko
import pytest
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)

import aruba_session_tracker.collectors.ssh as ssh_module
from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    CollectorPhase,
    CommandBatch,
    CommandConnection,
    HostKeyInfo,
    MonitoringSSHConnectionFactory,
    PollDeadline,
    SSHCollector,
    StrictNetmikoFactory,
    run_bounded_approval,
)
from aruba_session_tracker.collectors.ssh import (
    _abort_netmiko_connection,
    _BoundedSessionLog,
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


class _ReusableConnection(FakeConnection):
    def __init__(self, outputs: dict[str, str]) -> None:
        super().__init__(outputs)
        self.alive = True
        self.close_count = 0
        self.fail_next: dict[str, BaseException] = {}

    def send_command(self, command: str, *, read_timeout: float) -> str:
        del read_timeout
        self.commands.append(command)
        failure = self.fail_next.pop(command, None)
        if failure is not None:
            self.alive = False
            raise failure
        return self.outputs[command]

    def is_alive(self) -> bool:
        return self.alive and not self.closed

    def close(self) -> None:
        self.close_count += 1
        self.alive = False
        self.closed = True


class _ReusableFactory:
    def __init__(self) -> None:
        self.connections: list[_ReusableConnection] = []
        self.reuse_tokens: dict[tuple[str, int], bytes] = {}

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        **kwargs: object,
    ) -> _ReusableConnection:
        del credentials, kwargs
        connection = _ReusableConnection(
            {
                "no paging": "",
                "show datapath session table 192.0.2.20": "ok",
            }
        )
        self.connections.append(connection)
        self.reuse_tokens.setdefault((target.host, target.port), b"trusted-key-one")
        return connection

    def connection_reuse_token(
        self,
        target: DeviceTarget,
        **kwargs: object,
    ) -> bytes:
        del kwargs
        return self.reuse_tokens[(target.host, target.port)]


TARGET = DeviceTarget("MM", "192.0.2.10")
CREDENTIALS = Credentials("operator", "secret")


def _collect_datapath(
    factory: MonitoringSSHConnectionFactory,
    *,
    target: DeviceTarget = TARGET,
) -> CommandBatch:
    return SSHCollector(factory).collect(
        target,
        CREDENTIALS,
        ("no paging", "show datapath session table 192.0.2.20"),
    )


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


def test_monitor_factory_reuses_endpoint_until_explicit_close() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)

    first = _collect_datapath(pool)
    second = _collect_datapath(pool)

    assert first.outputs == second.outputs
    assert len(base_factory.connections) == 1
    connection = base_factory.connections[0]
    assert connection.commands == [
        "no paging",
        "show datapath session table 192.0.2.20",
        "no paging",
        "show datapath session table 192.0.2.20",
    ]
    assert connection.closed is False

    pool.close()

    assert connection.closed is True
    assert pool._credentials is None


def test_monitor_factory_reconnects_once_for_dead_reused_paging_transport() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    _collect_datapath(pool)
    first = base_factory.connections[0]
    first.fail_next["no paging"] = OSError("fixture dead transport")

    batch = _collect_datapath(pool)

    assert batch.output_for("show datapath session table 192.0.2.20") == "ok"
    assert len(base_factory.connections) == 2
    assert first.closed is True
    assert base_factory.connections[1].commands == [
        "no paging",
        "show datapath session table 192.0.2.20",
    ]
    pool.close()


def test_monitor_factory_never_retries_authentication_or_data_command_failure() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    _collect_datapath(pool)
    first = base_factory.connections[0]
    first.fail_next["no paging"] = paramiko.AuthenticationException("fixture auth")

    with pytest.raises(CollectorError) as auth_error:
        _collect_datapath(pool)

    assert auth_error.value.code is ErrorCode.AUTH_FAILED
    assert auth_error.value.phase is CollectorPhase.LOGIN
    assert len(base_factory.connections) == 1

    _collect_datapath(pool)
    second = base_factory.connections[1]
    second.fail_next["show datapath session table 192.0.2.20"] = OSError(
        "fixture data transport failure"
    )

    with pytest.raises(CollectorError) as data_error:
        _collect_datapath(pool)

    assert data_error.value.code is ErrorCode.MM_UNREACHABLE
    assert data_error.value.retryable_network is True
    assert len(base_factory.connections) == 2
    pool.close()


def test_monitor_factory_reconnects_before_reuse_when_local_host_token_changes() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    _collect_datapath(pool)
    first = base_factory.connections[0]
    base_factory.reuse_tokens[(TARGET.host, TARGET.port)] = b"trusted-key-two"

    _collect_datapath(pool)

    assert first.closed is True
    assert len(base_factory.connections) == 2
    pool.close()


def test_monitor_factory_never_retries_a_host_key_read_failure() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    _collect_datapath(pool)
    first = base_factory.connections[0]

    def fail_host_key_read(target: DeviceTarget, **kwargs: object) -> bytes:
        del target, kwargs
        raise CollectorError(ErrorCode.HOST_KEY_CHANGED, "sanitized host key failure")

    base_factory.connection_reuse_token = fail_host_key_read  # type: ignore[method-assign]
    with pytest.raises(CollectorError) as caught:
        _collect_datapath(pool)

    assert caught.value.code is ErrorCode.HOST_KEY_CHANGED
    assert len(base_factory.connections) == 1
    assert first.closed is True
    pool.close()


def test_monitor_factory_bounds_endpoints_and_rejects_changed_credentials() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    for index in range(6):
        _collect_datapath(pool, target=DeviceTarget(f"device-{index}", f"192.0.2.{index + 1}"))

    with pytest.raises(CollectorError) as limit_error:
        _collect_datapath(pool, target=DeviceTarget("device-7", "192.0.2.7"))
    assert limit_error.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED

    with pytest.raises(CollectorError) as credential_error:
        SSHCollector(pool).collect(
            TARGET,
            Credentials("operator", "changed"),
            ("no paging",),
        )
    assert credential_error.value.code is ErrorCode.AUTH_FAILED
    assert credential_error.value.phase is CollectorPhase.LOGIN
    assert "changed" not in str(credential_error.value)
    pool.close()


def test_monitor_factory_serializes_leases_for_the_same_endpoint() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    first_entered = Event()
    release_first = Event()
    second_entered = Event()

    def first_lease() -> None:
        with pool.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=None,
            cancel_token=CancellationToken(),
            deadline=PollDeadline.after(5),
        ):
            first_entered.set()
            assert release_first.wait(timeout=5)

    def second_lease() -> None:
        assert first_entered.wait(timeout=5)
        with pool.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=None,
            cancel_token=CancellationToken(),
            deadline=PollDeadline.after(5),
        ):
            second_entered.set()

    first_worker = Thread(target=first_lease)
    second_worker = Thread(target=second_lease)
    first_worker.start()
    second_worker.start()
    assert first_entered.wait(timeout=5)
    assert not second_entered.wait(timeout=0.05)
    release_first.set()
    first_worker.join(timeout=5)
    second_worker.join(timeout=5)

    assert not first_worker.is_alive()
    assert not second_worker.is_alive()
    assert second_entered.is_set()
    assert len(base_factory.connections) == 1
    pool.close()


@pytest.mark.parametrize(
    ("paging_result", "max_output_bytes", "expected_code"),
    [
        ("% Invalid input", 1024, ErrorCode.COMMAND_VARIANT_UNVERIFIED),
        ("x" * 11, 10, ErrorCode.OUTPUT_LIMIT_EXCEEDED),
    ],
)
def test_monitor_factory_does_not_reconnect_for_paging_command_or_output_failure(
    paging_result: str,
    max_output_bytes: int,
    expected_code: ErrorCode,
) -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    _collect_datapath(pool)
    base_factory.connections[0].outputs["no paging"] = paging_result

    with pytest.raises(CollectorError) as caught:
        SSHCollector(pool, max_output_bytes=max_output_bytes).collect(
            TARGET,
            CREDENTIALS,
            ("no paging", "show datapath session table 192.0.2.20"),
        )

    assert caught.value.code is expected_code
    assert len(base_factory.connections) == 1
    pool.close()


def test_monitor_factory_cancel_and_deadline_never_trigger_reconnect() -> None:
    base_factory = _ReusableFactory()
    pool = MonitoringSSHConnectionFactory(base_factory, CREDENTIALS)
    _collect_datapath(pool)
    first = base_factory.connections[0]
    token = CancellationToken()

    def cancel_then_timeout(command: str, *, read_timeout: float) -> str:
        del command, read_timeout
        first.alive = False
        token.cancel()
        raise TimeoutError("fixture cancelled transport")

    first.send_command = cancel_then_timeout  # type: ignore[method-assign]
    with pytest.raises(CollectorError) as cancelled:
        SSHCollector(pool).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
            cancel_token=token,
        )

    assert cancelled.value.code is ErrorCode.CANCELLED
    assert len(base_factory.connections) == 1

    _collect_datapath(pool)
    second = base_factory.connections[1]
    now = [0.0]

    def expire_then_timeout(command: str, *, read_timeout: float) -> str:
        del command, read_timeout
        second.alive = False
        now[0] = 1.0
        raise TimeoutError("fixture expired transport")

    second.send_command = expire_then_timeout  # type: ignore[method-assign]
    with pytest.raises(CollectorError) as expired:
        SSHCollector(pool).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
            deadline=PollDeadline(1.0, lambda: now[0]),
        )

    assert expired.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert len(base_factory.connections) == 2
    pool.close()


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


def test_paging_validation_preserves_explicit_command_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection({"no paging": "authorization fixture"})

    def reject_as_unauthorized(_output: str) -> None:
        raise ssh_module.ParseError(
            "fixture authorization rejection",
            code=ErrorCode.COMMAND_REJECTED,
        )

    monkeypatch.setattr(ssh_module, "reject_command_errors", reject_as_unauthorized)

    with pytest.raises(CollectorError) as caught:
        SSHCollector(FakeFactory(connection)).collect(TARGET, CREDENTIALS, ("no paging",))

    assert caught.value.code is ErrorCode.COMMAND_REJECTED
    assert caught.value.retryable_network is False
    assert connection.closed is True


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


def test_netmiko_read_timeout_is_sanitized_as_retryable_network_failure() -> None:
    class PromptReadTimeout(FakeConnection):
        def send_command(self, command: str, *, read_timeout: float) -> str:
            del command, read_timeout
            raise ReadTimeout("raw prompt and command output")

    with pytest.raises(CollectorError) as caught:
        SSHCollector(FakeFactory(PromptReadTimeout({}))).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
        )

    assert caught.value.code is ErrorCode.MM_UNREACHABLE
    assert caught.value.retryable_network is True
    assert "raw prompt" not in str(caught.value)


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
            self.remote_conn_pre = self

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


def test_ssh_teardown_bypasses_unbounded_graceful_disconnect() -> None:
    channel_closed = Event()

    class BlockingDisconnect:
        remote_conn = None
        remote_conn_pre = None

        def __init__(self) -> None:
            self.remote_conn = self
            self.remote_conn_pre = self

        def send_command(self, *_args: object, **_kwargs: object) -> str:
            return ""

        def disconnect(self) -> None:
            raise AssertionError("collector teardown must not call an unbounded CLI logout")

        def close(self) -> None:
            channel_closed.set()

    manager = _NetmikoConnectionManager(BlockingDisconnect())

    class ManagerFactory:
        def connect(self, *_args: object, **_kwargs: object) -> _NetmikoConnectionManager:
            return manager

    SSHCollector(ManagerFactory()).collect(
        TARGET,
        CREDENTIALS,
        ("no paging",),
    )

    assert channel_closed.is_set()


def test_deadline_watchdog_aborts_blocked_command() -> None:
    operation_started = Event()
    transport_closed = Event()

    class BlockingNetmiko:
        remote_conn = None
        remote_conn_pre = None

        def __init__(self) -> None:
            self.remote_conn = self
            self.remote_conn_pre = self

        def send_command(self, *_args: object, **_kwargs: object) -> str:
            operation_started.set()
            assert transport_closed.wait(timeout=2)
            raise OSError("fixture watchdog abort")

        def disconnect(self) -> None:
            raise AssertionError("collector teardown must not call graceful disconnect")

        def close(self) -> None:
            transport_closed.set()

    deadline = PollDeadline.after(0.1)
    manager = _NetmikoConnectionManager(
        BlockingNetmiko(),
        deadline=deadline,
    )

    class ManagerFactory:
        def connect(self, *_args: object, **_kwargs: object) -> _NetmikoConnectionManager:
            return manager

    with pytest.raises(CollectorError) as caught:
        SSHCollector(ManagerFactory()).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
            deadline=deadline,
        )

    assert operation_started.is_set()
    assert transport_closed.is_set()
    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert manager._deadline_thread is None


def test_deadline_watchdog_never_calls_blocking_channel_close() -> None:
    transport_closed = Event()
    channel_close_called = Event()

    class BlockingChannel:
        def close(self) -> None:
            channel_close_called.set()
            Event().wait()

    class Transport:
        def close(self) -> None:
            transport_closed.set()

    class Connection:
        def __init__(self) -> None:
            self.remote_conn = BlockingChannel()
            self.remote_conn_pre = self
            self.transport = Transport()

        def get_transport(self) -> object:
            return self.transport

    connection = Connection()

    worker = threading.Thread(target=_abort_netmiko_connection, args=(connection,), daemon=True)
    worker.start()
    worker.join(timeout=0.5)

    assert not worker.is_alive()
    assert transport_closed.is_set()
    assert not channel_close_called.is_set()


def test_netmiko_session_log_rejects_oversized_output_during_receive() -> None:
    session_log = _BoundedSessionLog()
    transport_closed = Event()

    class StreamingNetmiko:
        remote_conn = None
        remote_conn_pre = None

        def __init__(self) -> None:
            self.remote_conn = self
            self.remote_conn_pre = self

        def send_command(self, *_args: object, **_kwargs: object) -> str:
            session_log.write("12345")
            session_log.write("67890")
            session_log.write("X")
            raise AssertionError("receive limit should abort before a full result is built")

        def disconnect(self) -> None:
            return None

        def close(self) -> None:
            transport_closed.set()

    manager = _NetmikoConnectionManager(
        StreamingNetmiko(),
        bounded_session_log=session_log,
    )

    class ManagerFactory:
        def connect(self, *_args: object, **_kwargs: object) -> _NetmikoConnectionManager:
            return manager

    with pytest.raises(CollectorError) as caught:
        SSHCollector(ManagerFactory(), max_output_bytes=10).collect(
            TARGET,
            CREDENTIALS,
            ("no paging",),
        )

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert transport_closed.is_set()


def test_netmiko_session_log_bounds_setup_before_first_command() -> None:
    session_log = _BoundedSessionLog()

    with pytest.raises(CollectorError) as caught:
        session_log.write("X" * (ssh_module.MAX_OUTPUT_BYTES + 1))

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_cancellation_does_not_hide_an_authentication_failure() -> None:
    token = CancellationToken()

    class CancelThenAuthenticationFailure:
        def connect(self, *args: object, **kwargs: object) -> FakeConnection:
            del args, kwargs
            token.cancel()
            raise CollectorError(
                ErrorCode.AUTH_FAILED,
                "authentication failed",
                phase=CollectorPhase.LOGIN,
            )

    with pytest.raises(CollectorError) as caught:
        SSHCollector(CancelThenAuthenticationFailure()).collect(  # type: ignore[arg-type]
            TARGET,
            CREDENTIALS,
            ("no paging",),
            cancel_token=token,
        )

    assert caught.value.code is ErrorCode.AUTH_FAILED
    assert caught.value.phase is CollectorPhase.LOGIN


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
    assert caught.value.phase is CollectorPhase.LOGIN


def test_factory_marks_enable_authentication_phase(tmp_path: Path) -> None:
    key = paramiko.RSAKey.generate(1024)

    class RejectEnable(FakeNetmiko):
        def enable(self) -> None:
            raise NetmikoAuthenticationException("fixture enable authentication failure")

    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=lambda **_kwargs: RejectEnable(),
    )

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            Credentials("operator", "secret", "enable-secret"),
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
        )

    assert caught.value.code is ErrorCode.AUTH_FAILED
    assert caught.value.phase is CollectorPhase.ENABLE


def test_factory_deadline_watchdog_aborts_blocked_enable(tmp_path: Path) -> None:
    key = paramiko.RSAKey.generate(1024)
    enable_started = Event()
    transport_closed = Event()
    now = [0.0]

    class BlockingEnableNetmiko(FakeNetmiko):
        remote_conn = None
        remote_conn_pre = None

        def __init__(self) -> None:
            super().__init__()
            self.remote_conn = self
            self.remote_conn_pre = self

        def enable(self) -> None:
            enable_started.set()
            now[0] = 1.0
            assert transport_closed.wait(timeout=2)

        def close(self) -> None:
            transport_closed.set()

    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
        connector=lambda **_kwargs: BlockingEnableNetmiko(),
    )

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            Credentials("operator", "secret", "enable-secret"),
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
            deadline=PollDeadline(0.1, lambda: now[0]),
        )

    assert enable_started.is_set()
    assert transport_closed.is_set()
    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED


def test_deadline_watchdog_rechecks_an_early_timer_wakeup() -> None:
    now = [0.0]

    class EarlyWakeStop:
        def __init__(self) -> None:
            self.wait_calls = 0

        def wait(self, timeout: float) -> bool:
            self.wait_calls += 1
            if self.wait_calls == 1:
                now[0] += timeout / 2
            else:
                now[0] += timeout + 0.01
            return False

    stop = EarlyWakeStop()

    assert ssh_module._deadline_elapsed_before_stop(  # type: ignore[arg-type]
        PollDeadline(0.1, lambda: now[0]),
        stop,
    )
    assert stop.wait_calls == 2


def test_factory_deadline_watchdog_closes_owned_socket_during_blocked_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key = paramiko.RSAKey.generate(1024)
    connector_started = Event()
    socket_closed = Event()
    now = [0.0]

    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            return None

        def shutdown(self, _how: int) -> None:
            socket_closed.set()

        def close(self) -> None:
            socket_closed.set()

    fake_socket = FakeSocket()
    monkeypatch.setattr(
        ssh_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: fake_socket,
    )
    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
    )

    def blocked_connector(**kwargs: object) -> object:
        connector_started.set()
        now[0] = 1.0
        assert kwargs["sock"] is fake_socket
        assert socket_closed.wait(timeout=2)
        raise OSError("fixture connector released by owned socket close")

    # Preserve the production owned-socket path while substituting a connector
    # that cannot return until that socket is force-closed.
    factory._connector = blocked_connector

    with pytest.raises(CollectorError) as caught:
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: True,
            cancel_token=CancellationToken(),
            deadline=PollDeadline(0.1, lambda: now[0]),
        )

    assert connector_started.is_set()
    assert socket_closed.is_set()
    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert not any(
        thread.name == "aruba-ssh-connect-watchdog" and thread.is_alive()
        for thread in threading.enumerate()
    )


def test_factory_cancellation_closes_owned_socket_during_blocked_connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key = paramiko.RSAKey.generate(1024)
    connector_started = Event()
    socket_closed = Event()
    token = CancellationToken()
    failures: list[CollectorError] = []

    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            return None

        def shutdown(self, _how: int) -> None:
            socket_closed.set()

        def close(self) -> None:
            socket_closed.set()

    fake_socket = FakeSocket()
    monkeypatch.setattr(
        ssh_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: fake_socket,
    )
    factory = StrictNetmikoFactory(
        tmp_path / "known_hosts",
        key_probe=lambda *_args: key,
    )

    def blocked_connector(**_kwargs: object) -> object:
        connector_started.set()
        assert socket_closed.wait(timeout=2)
        raise OSError("fixture connector released by cancellation")

    factory._connector = blocked_connector

    def connect() -> None:
        try:
            factory.connect(
                TARGET,
                CREDENTIALS,
                host_key_approval=lambda *_args: True,
                cancel_token=token,
                deadline=PollDeadline.after(5),
            )
        except CollectorError as exc:
            failures.append(exc)

    worker = Thread(target=connect)
    worker.start()
    assert connector_started.wait(timeout=1)
    token.cancel()
    worker.join(timeout=1)

    assert not worker.is_alive()
    assert socket_closed.is_set()
    assert [failure.code for failure in failures] == [ErrorCode.CANCELLED]
    assert not any(
        thread.name == "aruba-ssh-connect-watchdog" and thread.is_alive()
        for thread in threading.enumerate()
    )


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


def test_default_connector_skips_probe_for_safely_loaded_known_host(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    key = paramiko.RSAKey.generate(1024)
    known_hosts = tmp_path / "known_hosts"
    host_keys = paramiko.HostKeys()
    host_keys.add(TARGET.host, key.get_name(), key)
    host_keys.save(str(known_hosts))
    connector_calls: list[dict[str, object]] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        def settimeout(self, _timeout: float) -> None:
            return None

        def shutdown(self, _how: int) -> None:
            self.closed = True

        def close(self) -> None:
            self.closed = True

    fake_socket = FakeSocket()
    monkeypatch.setattr(
        ssh_module.socket,
        "create_connection",
        lambda *_args, **_kwargs: fake_socket,
    )
    factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: pytest.fail("known host was probed"),
    )

    def connector(**kwargs: object) -> FakeNetmiko:
        connector_calls.append(kwargs)
        connection = FakeNetmiko()
        connection.sock = kwargs["sock"]
        return connection

    factory._connector = connector
    with factory.connect(
        TARGET,
        CREDENTIALS,
        host_key_approval=lambda *_args: pytest.fail("known host requested approval"),
        cancel_token=CancellationToken(),
    ):
        pass

    assert len(connector_calls) == 1
    assert connector_calls[0]["ssh_strict"] is True
    assert connector_calls[0]["system_host_keys"] is False
    assert connector_calls[0]["alt_host_keys"] is True
    assert connector_calls[0]["alt_key_file"] == str(known_hosts)
    snapshot = connector_calls[0]["host_keys_snapshot"]
    assert isinstance(snapshot, paramiko.HostKeys)
    assert snapshot.check(TARGET.host, key) is True
    assert connector_calls[0]["sock"] is fake_socket
    assert fake_socket.closed is True


def test_default_connector_distinguishes_wrapped_host_key_rejections_from_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    trusted_key = paramiko.RSAKey.generate(1024)
    changed_key = paramiko.RSAKey.generate(1024)
    known_hosts = tmp_path / "known_hosts"
    host_keys = paramiko.HostKeys()
    host_keys.add(TARGET.host, trusted_key.get_name(), trusted_key)
    host_keys.save(str(known_hosts))
    sockets: list[object] = []

    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            return None

        def shutdown(self, _how: int) -> None:
            return None

        def close(self) -> None:
            return None

    def create_socket(*_args: object, **_kwargs: object) -> FakeSocket:
        current = FakeSocket()
        sockets.append(current)
        return current

    monkeypatch.setattr(ssh_module.socket, "create_connection", create_socket)

    strict_failures = (
        paramiko.BadHostKeyException(TARGET.host, changed_key, trusted_key),
        paramiko.SSHException(f"Server {TARGET.host!r} not found in known_hosts"),
    )
    for strict_failure in strict_failures:
        factory = StrictNetmikoFactory(
            known_hosts,
            key_probe=lambda *_args: pytest.fail("known host was probed"),
        )

        def reject_host_key(
            *,
            failure: paramiko.SSHException = strict_failure,
            **_kwargs: object,
        ) -> FakeNetmiko:
            try:
                raise failure
            except paramiko.SSHException as exc:
                raise NetmikoTimeoutException("wrapped strict connection failure") from exc

        factory._connector = reject_host_key
        with pytest.raises(CollectorError) as caught:
            factory.connect(
                TARGET,
                CREDENTIALS,
                host_key_approval=lambda *_args: pytest.fail("known host requested approval"),
                cancel_token=CancellationToken(),
            )
        assert caught.value.code is ErrorCode.HOST_KEY_CHANGED
        assert caught.value.retryable_network is False

    timeout_factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: pytest.fail("known host was probed"),
    )

    def timeout_connector(**_kwargs: object) -> FakeNetmiko:
        raise NetmikoTimeoutException("fixture host key lookup timed out")

    timeout_factory._connector = timeout_connector
    with pytest.raises(CollectorError) as caught:
        timeout_factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: pytest.fail("known host requested approval"),
            cancel_token=CancellationToken(),
        )

    assert caught.value.code is ErrorCode.MM_UNREACHABLE
    assert caught.value.retryable_network is True

    negotiation_factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: pytest.fail("known host was probed"),
    )

    def incompatible_host_key_algorithm(**_kwargs: object) -> FakeNetmiko:
        raise paramiko.IncompatiblePeer("Incompatible ssh peer (no acceptable host key)")

    negotiation_factory._connector = incompatible_host_key_algorithm
    with pytest.raises(CollectorError) as caught:
        negotiation_factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=lambda *_args: pytest.fail("known host requested approval"),
            cancel_token=CancellationToken(),
        )

    assert caught.value.code is ErrorCode.MM_UNREACHABLE
    assert caught.value.retryable_network is True
    assert len(sockets) == 4


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


def test_host_key_approval_deadline_never_saves_or_connects_after_late_yes(
    tmp_path: Path,
) -> None:
    key = paramiko.RSAKey.generate(1024)
    release_approval = Event()
    approval_finished = Event()
    connector_called = False

    def connector(**_kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    def blocking_approval(
        _target: DeviceTarget,
        _info: HostKeyInfo,
        _deadline: PollDeadline,
    ) -> bool:
        release_approval.wait(timeout=3)
        approval_finished.set()
        return True

    known_hosts = tmp_path / "known_hosts"
    factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: key,
        connector=connector,
    )
    started_at = time.monotonic()
    try:
        with pytest.raises(CollectorError) as caught:
            factory.connect(
                TARGET,
                CREDENTIALS,
                host_key_approval=blocking_approval,
                cancel_token=CancellationToken(),
                deadline=PollDeadline.after(0.05),
            )
        elapsed = time.monotonic() - started_at
        assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
        assert elapsed < 0.5
        assert not known_hosts.exists()
        assert connector_called is False
    finally:
        release_approval.set()
        assert approval_finished.wait(timeout=3)

    # The daemon callback's late approval cannot resume the completed poll.
    assert not known_hosts.exists()
    assert connector_called is False


def test_bounded_approval_supports_legacy_and_deadline_aware_callbacks() -> None:
    token = CancellationToken()
    deadline = PollDeadline.after(1)
    received_deadlines: list[PollDeadline] = []

    def legacy(first: object, second: object) -> bool:
        return (first, second) == ("first", "second")

    def deadline_aware(first: object, second: object, current: PollDeadline) -> bool:
        received_deadlines.append(current)
        return (first, second) == ("first", "second")

    assert run_bounded_approval(
        legacy,
        "first",
        "second",
        cancel_token=token,
        deadline=deadline,
    )
    assert run_bounded_approval(
        deadline_aware,
        "first",
        "second",
        cancel_token=token,
        deadline=deadline,
    )
    assert received_deadlines == [deadline]


def test_bounded_approval_does_not_reinterpret_callback_type_error() -> None:
    def broken_callback(_first: object, _second: object) -> bool:
        raise TypeError("callback body failed")

    with pytest.raises(TypeError, match="callback body failed"):
        run_bounded_approval(
            broken_callback,
            "first",
            "second",
            cancel_token=CancellationToken(),
            deadline=PollDeadline.after(1),
        )


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


def test_known_hosts_process_lock_respects_poll_deadline_without_side_effects(
    tmp_path: Path,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    connector_called = False
    approval_called = False

    def connector(**_kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    def approval(_target: DeviceTarget, _info: HostKeyInfo) -> bool:
        nonlocal approval_called
        approval_called = True
        return True

    lock_owner = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: key,
        connector=connector,
    )
    contender = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: key,
        connector=connector,
    )
    assert lock_owner._host_keys_lock is contender._host_keys_lock

    started_at = time.monotonic()
    with lock_owner._host_keys_lock, pytest.raises(CollectorError) as caught:
        contender.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=approval,
            cancel_token=CancellationToken(),
            deadline=PollDeadline.after(0.05),
        )
    elapsed = time.monotonic() - started_at

    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert elapsed < 0.5
    assert not known_hosts.exists()
    assert approval_called is False
    assert connector_called is False


def test_known_hosts_process_lock_respects_cancellation_without_side_effects(
    tmp_path: Path,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    token = CancellationToken()
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

    def cancel_soon() -> None:
        time.sleep(0.05)
        token.cancel()

    canceller = Thread(target=cancel_soon)
    started_at = time.monotonic()
    with factory._host_keys_lock:
        canceller.start()
        with pytest.raises(CollectorError) as caught:
            factory.connect(
                TARGET,
                CREDENTIALS,
                host_key_approval=lambda *_args: True,
                cancel_token=token,
                deadline=PollDeadline.after(1),
            )
    elapsed = time.monotonic() - started_at
    canceller.join(timeout=1)

    assert not canceller.is_alive()
    assert caught.value.code is ErrorCode.CANCELLED
    assert elapsed < 0.5
    assert not known_hosts.exists()
    assert connector_called is False


def test_known_hosts_file_lock_respects_poll_deadline_without_side_effects(
    tmp_path: Path,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(1024)
    connector_called = False
    approval_called = False

    def connector(**_kwargs: object) -> FakeNetmiko:
        nonlocal connector_called
        connector_called = True
        return FakeNetmiko()

    def approval(_target: DeviceTarget, _info: HostKeyInfo) -> bool:
        nonlocal approval_called
        approval_called = True
        return True

    factory = StrictNetmikoFactory(
        known_hosts,
        key_probe=lambda *_args: key,
        connector=connector,
    )
    started_at = time.monotonic()
    with (
        _known_hosts_file_lock(
            known_hosts,
            CancellationToken(),
            deadline=PollDeadline.after(1),
        ),
        pytest.raises(CollectorError) as caught,
    ):
        factory.connect(
            TARGET,
            CREDENTIALS,
            host_key_approval=approval,
            cancel_token=CancellationToken(),
            deadline=PollDeadline.after(0.05),
        )
    elapsed = time.monotonic() - started_at

    assert caught.value.code is ErrorCode.POLL_DEADLINE_EXCEEDED
    assert elapsed < 0.5
    assert not known_hosts.exists()
    assert approval_called is False
    assert connector_called is False


def test_known_hosts_file_lock_respects_cancellation(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    token = CancellationToken()

    def cancel_soon() -> None:
        time.sleep(0.05)
        token.cancel()

    canceller = Thread(target=cancel_soon)
    started_at = time.monotonic()
    with _known_hosts_file_lock(known_hosts, CancellationToken()):
        canceller.start()
        with (
            pytest.raises(CollectorError) as caught,
            _known_hosts_file_lock(
                known_hosts,
                token,
                deadline=PollDeadline.after(1),
            ),
        ):
            pytest.fail("an already-held known_hosts lock was acquired")
    elapsed = time.monotonic() - started_at
    canceller.join(timeout=1)

    assert not canceller.is_alive()
    assert caught.value.code is ErrorCode.CANCELLED
    assert elapsed < 0.5
    assert not known_hosts.exists()


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


def test_connection_manager_close_is_idempotent_and_skips_unbounded_disconnect(
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

    manager.close()  # type: ignore[attr-defined]
    manager.close()  # type: ignore[attr-defined]

    assert connection.disconnect_calls == 0
