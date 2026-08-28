from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Self

from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    CommandConnection,
)
from aruba_session_tracker.commands import (
    NO_PAGING_COMMAND,
    build_datapath_session_command,
    build_global_user_command,
)
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.services import (
    LifecycleEventType,
    MonitorEngine,
    QueryOutcome,
    TrackerService,
)

GLOBAL_HEADER = "IP              MAC                Name              Current switch    Role"
DATAPATH_HEADER = """Datapath Session Table Entries
Source IP Destination IP Prot SPort DPort Cnt Prio ToS Age Destination TAge
Packets Bytes Flags CPU ID
"""
DATAPATH_EMPTY = DATAPATH_HEADER + "Entries: 0\n"


def _global_output(client_ip: str, switch: str | None) -> str:
    if switch is None:
        return f"{GLOBAL_HEADER}\n{'-' * len(GLOBAL_HEADER)}\nTotal entries = 0\n"
    row = _global_row(client_ip, switch)
    return f"{GLOBAL_HEADER}\n{'-' * len(GLOBAL_HEADER)}\n{row}\nTotal entries = 1\n"


def _global_row(client_ip: str, switch: str) -> str:
    starts = {
        label: GLOBAL_HEADER.index(label)
        for label in ("IP", "MAC", "Name", "Current switch", "Role")
    }
    row = [" "] * (len(GLOBAL_HEADER) + 16)
    for label, value in (
        ("IP", client_ip),
        ("MAC", "00:11:22:33:44:55"),
        ("Name", "fixture"),
        ("Current switch", switch),
        ("Role", "authenticated"),
    ):
        start = starts[label]
        row[start : start + len(value)] = value
    return "".join(row).rstrip()


def _ambiguous_global_output(client_ip: str) -> str:
    rows = "\n".join((_global_row(client_ip, "192.0.2.101"), _global_row(client_ip, "192.0.2.102")))
    return f"{GLOBAL_HEADER}\n{'-' * len(GLOBAL_HEADER)}\n{rows}\nTotal entries = 2\n"


def _datapath_output(
    source: str = "198.51.100.10",
    destination: str = "203.0.113.20",
    *,
    packets: int = 5,
    flags: str = "SY",
) -> str:
    return DATAPATH_HEADER + (
        f"{source} {destination} 6 12345 443 0/0 0 0 10 0 0 {packets} 100 {flags} 0\nEntries: 1\n"
    )


class FakeConnection(AbstractContextManager[CommandConnection]):
    def __init__(self, outputs: dict[str, str]) -> None:
        self._outputs = outputs

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    def send_command(self, command: str, *, read_timeout: float) -> str:
        return self._outputs.get(command, "")

    def close(self) -> None:
        return None


class FakeFactory:
    def __init__(self, outputs: dict[str, dict[str, str]]) -> None:
        self.outputs = outputs
        self.errors: dict[str, CollectorError] = {}
        self.calls: list[str] = []
        self.commands_by_device: dict[str, list[str]] = {}

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: object,
        cancel_token: CancellationToken,
    ) -> FakeConnection:
        self.calls.append(target.name)
        if target.name in self.errors:
            raise self.errors[target.name]
        base = FakeConnection(self.outputs[target.name])
        original = base.send_command

        def recording(command: str, *, read_timeout: float) -> str:
            self.commands_by_device.setdefault(target.name, []).append(command)
            return original(command, read_timeout=read_timeout)

        base.send_command = recording  # type: ignore[method-assign]
        return base


def _config() -> AppConfig:
    return AppConfig(
        mm_primary=DeviceTarget("MM-Primary", "192.0.2.10"),
        mm_standby=DeviceTarget("MM-Standby", "192.0.2.11"),
        managed_devices=(
            DeviceTarget("MD-1", "192.0.2.101"),
            DeviceTarget("MD-2", "192.0.2.102"),
            DeviceTarget("MD-3", "192.0.2.103"),
            DeviceTarget("MD-4", "192.0.2.104"),
        ),
        session_interval_seconds=5,
        location_interval_seconds=30,
        close_after_misses=3,
    )


REQUEST = QueryRequest("198.51.100.10", "203.0.113.20", 12345, 443)
CREDENTIALS = Credentials("operator", "secret")


def _mm_outputs(source_switch: str | None, destination_switch: str | None) -> dict[str, str]:
    return {
        NO_PAGING_COMMAND: "",
        build_global_user_command(REQUEST.source_ip): _global_output(
            REQUEST.source_ip, source_switch
        ),
        build_global_user_command(REQUEST.destination_ip): _global_output(
            REQUEST.destination_ip, destination_switch
        ),
    }


def test_primary_network_failure_uses_standby_but_auth_failure_does_not() -> None:
    config = _config()
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", None),
        "MM-Standby": _mm_outputs("192.0.2.101", None),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)
    factory.errors["MM-Primary"] = CollectorError(
        ErrorCode.MM_UNREACHABLE, "timeout", retryable_network=True
    )
    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)
    assert outcome.used_mm == "MM-Standby"
    assert len(outcome.observations) == 1
    assert factory.calls[:2] == ["MM-Primary", "MM-Standby"]

    auth_factory = FakeFactory(outputs)
    auth_factory.errors["MM-Primary"] = CollectorError(ErrorCode.AUTH_FAILED, "auth")
    outcome = TrackerService(config, auth_factory).query_once(REQUEST, CREDENTIALS)
    assert outcome.observations == ()
    assert [event.code for event in outcome.diagnostics] == [ErrorCode.AUTH_FAILED]
    assert auth_factory.calls == ["MM-Primary"]


def test_destination_md_is_queried_only_after_source_md_has_no_match() -> None:
    config = _config()
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.destination_ip): _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)
    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)
    assert len(outcome.observations) == 1
    assert outcome.controllers == ("MD-1", "MD-2")
    assert factory.calls == ["MM-Primary", "MD-1", "MD-2"]
    assert all(
        command != "show datapath session table"
        for commands in factory.commands_by_device.values()
        for command in commands
    )


def test_md_authentication_failure_stops_before_other_candidates() -> None:
    config = _config()
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {NO_PAGING_COMMAND: ""},
        "MD-2": {NO_PAGING_COMMAND: ""},
    }
    factory = FakeFactory(outputs)
    factory.errors["MD-1"] = CollectorError(ErrorCode.AUTH_FAILED, "auth")

    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)

    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary", "MD-1"]
    assert ErrorCode.AUTH_FAILED in {event.code for event in outcome.diagnostics}


def test_full_scan_requires_explicit_approval_and_queries_all_enabled_mds() -> None:
    config = _config()
    outputs: dict[str, dict[str, str]] = {"MM-Primary": _mm_outputs(None, None)}
    for device in config.managed_devices:
        outputs[device.name] = {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
        }

    denied_factory = FakeFactory(outputs)
    denied = TrackerService(config, denied_factory).query_once(
        REQUEST, CREDENTIALS, full_scan_approval=lambda *_args: False
    )
    assert denied.authoritative is False
    assert denied_factory.calls == ["MM-Primary"]
    assert ErrorCode.CLIENT_NOT_FOUND_ON_MM in {item.code for item in denied.diagnostics}

    approved_factory = FakeFactory(outputs)
    approved = TrackerService(config, approved_factory).query_once(
        REQUEST, CREDENTIALS, full_scan_approval=lambda *_args: True
    )
    assert approved.controllers == ("MD-1", "MD-2", "MD-3", "MD-4")
    assert approved_factory.calls == [
        "MM-Primary",
        "MD-1",
        "MD-2",
        "MD-3",
        "MD-4",
    ]
    assert approved.authoritative is True


def test_rejected_filtered_command_never_falls_back_to_unfiltered_table() -> None:
    config = _config()
    filtered = build_datapath_session_command(REQUEST.source_ip)
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", None),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            filtered: "% Invalid input detected",
        },
    }
    factory = FakeFactory(outputs)
    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)
    assert outcome.authoritative is False
    assert ErrorCode.COMMAND_VARIANT_UNVERIFIED in {item.code for item in outcome.diagnostics}
    assert factory.commands_by_device["MD-1"] == [NO_PAGING_COMMAND, filtered]


def test_ambiguous_mm_location_never_grants_full_scan_eligibility() -> None:
    config = _config()
    mm = _mm_outputs(None, None)
    mm[build_global_user_command(REQUEST.source_ip)] = _ambiguous_global_output(REQUEST.source_ip)
    factory = FakeFactory({"MM-Primary": mm})
    approval_calls = 0

    def approve(*_args: object) -> bool:
        nonlocal approval_calls
        approval_calls += 1
        return True

    outcome = TrackerService(config, factory).query_once(
        REQUEST,
        CREDENTIALS,
        full_scan_approval=approve,
    )
    assert outcome.authoritative is False
    assert approval_calls == 0
    assert factory.calls == ["MM-Primary"]
    assert ErrorCode.CURRENT_SWITCH_AMBIGUOUS in {item.code for item in outcome.diagnostics}


def test_unmapped_destination_makes_negative_source_result_non_authoritative() -> None:
    config = _config()
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.250"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
        },
    }
    factory = FakeFactory(outputs)

    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)

    assert outcome.observations == ()
    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary", "MD-1"]
    assert ErrorCode.CURRENT_SWITCH_UNMAPPED in {item.code for item in outcome.diagnostics}


def _observation(*, packets: int = 1, controller: str = "192.0.2.101") -> SessionObservation:
    return SessionObservation(
        controller_name="MD",
        controller_host=controller,
        protocol=6,
        source_ip=REQUEST.source_ip,
        destination_ip=REQUEST.destination_ip,
        source_port=12345,
        destination_port=443,
        counter="0/0",
        packets=packets,
        bytes_count=packets * 100,
        flags="SY",
    )


class StubService:
    def __init__(self, outcomes: list[QueryOutcome]) -> None:
        self.config = _config()
        self.outcomes = outcomes
        self.refresh_calls: list[bool] = []

    def query_once(self, *args: object, **kwargs: object) -> QueryOutcome:
        self.refresh_calls.append(bool(kwargs["refresh_locations"]))
        return self.outcomes.pop(0)


def test_monitor_refreshes_mm_on_second_miss_and_closes_on_third() -> None:
    observed = QueryOutcome(
        observations=(_observation(),), used_mm="MM-Primary", authoritative=True
    )
    miss = QueryOutcome(used_mm="MM-Primary", authoritative=True)
    service = StubService([observed, miss, miss, miss, miss])
    ticks = iter((0.0, 5.0, 10.0, 15.0, 20.0))
    wall = datetime(2026, 8, 28, tzinfo=UTC)
    wall_ticks = iter(wall + timedelta(seconds=i) for i in range(10))
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(ticks),
        wall_clock=lambda: next(wall_ticks),
    )

    started = monitor.poll_once()
    original_instance = started.active_sessions[0].instance_id
    assert started.events[0].event_type is LifecycleEventType.STARTED

    first_miss = monitor.poll_once()
    assert first_miss.consecutive_misses == 1
    assert first_miss.events[-1].event_type is LifecycleEventType.MISSED

    second_miss = monitor.poll_once()
    assert second_miss.refreshed_location is True
    assert second_miss.consecutive_misses == 2
    assert service.refresh_calls == [True, False, False, True]

    closed = monitor.poll_once()
    assert closed.consecutive_misses == 3
    assert closed.events[-1].event_type is LifecycleEventType.CLOSED
    assert closed.active_sessions == ()

    # A reappearing identical 5-tuple starts a distinct lifecycle instance.
    service.outcomes.append(observed)
    reopened = monitor.poll_once()
    assert reopened.events[0].event_type is LifecycleEventType.STARTED
    assert reopened.active_sessions[0].instance_id != original_instance


def test_non_authoritative_poll_never_advances_miss_or_closes() -> None:
    observed = QueryOutcome(
        observations=(_observation(),), used_mm="MM-Primary", authoritative=True
    )
    uncertain = QueryOutcome(used_mm="MM-Primary", authoritative=False)
    service = StubService([observed, uncertain])
    ticks = iter((0.0, 5.0))
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(ticks),
    )
    monitor.poll_once()
    result = monitor.poll_once()
    assert result.consecutive_misses == 0
    assert result.events == ()
    assert len(result.active_sessions) == 1


def test_second_miss_of_one_flow_refreshes_mm_while_another_flow_remains() -> None:
    first = _observation(packets=1)
    second = replace(_observation(packets=1), source_port=23456)
    both = QueryOutcome(observations=(first, second), used_mm="MM-Primary", authoritative=True)
    only_first = QueryOutcome(observations=(first,), used_mm="MM-Primary", authoritative=True)
    service = StubService([both, only_first, only_first, both])
    ticks = iter((0.0, 5.0, 10.0))
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(ticks),
    )

    monitor.poll_once()
    first_miss = monitor.poll_once()
    assert sorted(item.miss_count for item in first_miss.active_sessions) == [0, 1]

    refreshed = monitor.poll_once()
    assert refreshed.refreshed_location is True
    assert all(item.miss_count == 0 for item in refreshed.active_sessions)
    assert service.refresh_calls == [True, False, False, True]


def test_failed_second_miss_refresh_retains_positive_first_pass_evidence() -> None:
    first = _observation(packets=1)
    second = replace(_observation(packets=1), source_port=23456)
    first_updated = replace(first, packets=2)
    first_latest = replace(first, packets=3)
    both = QueryOutcome(observations=(first, second), used_mm="MM-Primary", authoritative=True)
    only_first = QueryOutcome(
        observations=(first_updated,), used_mm="MM-Primary", authoritative=True
    )
    first_before_failed_refresh = QueryOutcome(
        observations=(first_latest,), used_mm="MM-Primary", authoritative=True
    )
    refresh_failed = QueryOutcome(authoritative=False)
    service = StubService([both, only_first, first_before_failed_refresh, refresh_failed])
    ticks = iter((0.0, 5.0, 10.0))
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(ticks),
    )

    monitor.poll_once()
    monitor.poll_once()
    result = monitor.poll_once()

    assert result.authoritative is False
    assert result.observations == (first_latest,)
    assert sorted(item.miss_count for item in result.active_sessions) == [0, 1]
    assert any(
        event.event_type is LifecycleEventType.OBSERVED and event.observation.packets == 3
        for event in result.events
    )
