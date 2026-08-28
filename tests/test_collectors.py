from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from types import TracebackType
from typing import Self

import paramiko
import pytest

from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    CommandConnection,
    HostKeyInfo,
    SSHCollector,
    StrictNetmikoFactory,
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


class FakeNetmiko:
    def __init__(self) -> None:
        self.enable_called = False

    def send_command(self, command: str, **kwargs: object) -> str:
        return ""

    def enable(self) -> None:
        self.enable_called = True

    def disconnect(self) -> None:
        return None


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
