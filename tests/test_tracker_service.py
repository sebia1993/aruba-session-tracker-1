from __future__ import annotations

import os
import time
from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path
from threading import Event, Thread
from types import TracebackType
from typing import Self

import pytest

import aruba_session_tracker.services.monitoring as monitoring_module
from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    CommandConnection,
    PollDeadline,
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
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.services import (
    MAX_POLL_OBSERVATIONS,
    MAX_POLL_RAW_BYTES,
    LifecycleEventType,
    LocationSnapshot,
    MonitorDaemonError,
    MonitorEngine,
    PollBudget,
    QueryOutcome,
    RawSnapshot,
    TrackerService,
)

GLOBAL_HEADER = "IP              MAC                Name              Current switch    Role"
GLOBAL_SEPARATOR = "-" * len(GLOBAL_HEADER)
FIXTURES = Path(__file__).parent / "fixtures"
DATAPATH_HEADER = """Datapath Session Table Entries
Source IP Destination IP Prot SPort DPort Cnt Prio ToS Age Destination TAge
Packets Bytes Flags CPU ID
"""
DATAPATH_EMPTY = DATAPATH_HEADER + "Entries: 0\n"


def _global_output(client_ip: str, switch: str | None) -> str:
    if switch is None:
        return f"{GLOBAL_HEADER}\n{GLOBAL_SEPARATOR}\nTotal entries = 0\n"
    row = _global_row(client_ip, switch)
    return f"{GLOBAL_HEADER}\n{GLOBAL_SEPARATOR}\n{row}\nTotal entries = 1\n"


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
    return f"{GLOBAL_HEADER}\n{GLOBAL_SEPARATOR}\n{rows}\nTotal entries = 2\n"


def _datapath_output(
    source: str = "198.51.100.10",
    destination: str = "203.0.113.20",
    *,
    source_port: int = 12345,
    destination_port: int = 443,
    packets: int = 5,
    flags: str = "SY",
) -> str:
    return DATAPATH_HEADER + (
        f"{source} {destination} 6 {source_port} {destination_port} "
        f"0/0 0 0 10 0 0 {packets} 100 {flags} 0\nEntries: 1\n"
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
        deadline: object,
    ) -> FakeConnection:
        del credentials, host_key_approval, cancel_token, deadline
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
    primary_failure = outcome.diagnostics[0]
    assert primary_failure.transient is True
    assert primary_failure.recovered is True
    assert outcome.authoritative is True

    auth_factory = FakeFactory(outputs)
    auth_factory.errors["MM-Primary"] = CollectorError(ErrorCode.AUTH_FAILED, "auth")
    outcome = TrackerService(config, auth_factory).query_once(REQUEST, CREDENTIALS)
    assert outcome.observations == ()
    assert [event.code for event in outcome.diagnostics] == [ErrorCode.AUTH_FAILED]
    assert auth_factory.calls == ["MM-Primary"]


def test_expired_poll_deadline_does_not_attempt_mm_failover() -> None:
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", None),
        "MM-Standby": _mm_outputs("192.0.2.101", None),
    }
    factory = FakeFactory(outputs)

    outcome = TrackerService(_config(), factory).query_once(
        REQUEST,
        CREDENTIALS,
        deadline=PollDeadline(1.0, lambda: 1.0),
    )

    assert outcome.authoritative is False
    assert factory.calls == []
    assert [item.code for item in outcome.diagnostics] == [ErrorCode.POLL_DEADLINE_EXCEEDED]
    assert outcome.diagnostics[0].transient is True


def test_destination_md_is_queried_when_source_md_has_no_match() -> None:
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
    assert outcome.raw_snapshots[-2].observation_keys == ()
    assert outcome.raw_snapshots[-1].observation_keys == (outcome.observations[0].session_key,)
    assert all(
        command != "show datapath session table"
        for commands in factory.commands_by_device.values()
        for command in commands
    )


def test_source_only_query_uses_only_the_entered_ip_for_mm_and_md() -> None:
    request = QueryRequest(REQUEST.source_ip, "", REQUEST.source_port, REQUEST.destination_port)
    source_lookup = build_global_user_command(REQUEST.source_ip)
    source_filter = build_datapath_session_command(REQUEST.source_ip)
    factory = FakeFactory(
        {
            "MM-Primary": {
                NO_PAGING_COMMAND: "",
                source_lookup: _global_output(REQUEST.source_ip, "192.0.2.101"),
            },
            "MD-1": {
                NO_PAGING_COMMAND: "",
                source_filter: _datapath_output(),
            },
        }
    )

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert outcome.source_location is not None
    assert outcome.destination_location is None
    assert factory.calls == ["MM-Primary", "MD-1"]
    assert factory.commands_by_device["MM-Primary"] == [NO_PAGING_COMMAND, source_lookup]
    assert factory.commands_by_device["MD-1"] == [NO_PAGING_COMMAND, source_filter]


def test_source_only_query_accepts_centered_aos8_global_user_output() -> None:
    source_ip = "198.51.100.10"
    request = QueryRequest(source_ip, "")
    source_lookup = build_global_user_command(source_ip)
    source_filter = build_datapath_session_command(source_ip)
    factory = FakeFactory(
        {
            "MM-Primary": {
                NO_PAGING_COMMAND: "",
                source_lookup: (FIXTURES / "global_user_aos8_centered.txt").read_text(
                    encoding="utf-8"
                ),
            },
            "MD-1": {
                NO_PAGING_COMMAND: "",
                source_filter: _datapath_output(source=source_ip),
            },
        }
    )

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert outcome.source_location is not None
    assert outcome.source_location.current_switch == "192.0.2.101"
    assert outcome.destination_location is None
    assert all(event.stage != "MM_PARSE" for event in outcome.diagnostics)
    assert factory.commands_by_device["MM-Primary"] == [NO_PAGING_COMMAND, source_lookup]
    assert factory.commands_by_device["MD-1"] == [NO_PAGING_COMMAND, source_filter]


def test_two_ip_query_accepts_centered_aos8_global_user_outputs() -> None:
    source_ip = "198.51.100.10"
    destination_ip = "198.51.100.20"
    request = QueryRequest(source_ip, destination_ip)
    source_lookup = build_global_user_command(source_ip)
    destination_lookup = build_global_user_command(destination_ip)
    source_filter = build_datapath_session_command(source_ip)
    destination_filter = build_datapath_session_command(destination_ip)
    source_output = (FIXTURES / "global_user_aos8_centered.txt").read_text(encoding="utf-8")
    destination_output = source_output.replace(source_ip, destination_ip).replace(
        "192.0.2.101", "192.0.2.102"
    )
    factory = FakeFactory(
        {
            "MM-Primary": {
                NO_PAGING_COMMAND: "",
                source_lookup: source_output,
                destination_lookup: destination_output,
            },
            "MD-1": {
                NO_PAGING_COMMAND: "",
                source_filter: _datapath_output(
                    source=source_ip,
                    destination=destination_ip,
                ),
            },
            "MD-2": {
                NO_PAGING_COMMAND: "",
                destination_filter: DATAPATH_EMPTY,
            },
        }
    )

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert outcome.source_location is not None
    assert outcome.source_location.current_switch == "192.0.2.101"
    assert outcome.destination_location is not None
    assert outcome.destination_location.current_switch == "192.0.2.102"
    assert all(event.stage != "MM_PARSE" for event in outcome.diagnostics)
    assert factory.calls == ["MM-Primary", "MD-1", "MD-2"]


def test_malformed_centered_destination_stops_before_any_md_query() -> None:
    source_ip = "198.51.100.10"
    destination_ip = "198.51.100.20"
    request = QueryRequest(source_ip, destination_ip)
    source_lookup = build_global_user_command(source_ip)
    destination_lookup = build_global_user_command(destination_ip)
    source_output = (FIXTURES / "global_user_aos8_centered.txt").read_text(encoding="utf-8")
    destination_output = source_output.replace(source_ip, "not-an-ip")
    factory = FakeFactory(
        {
            "MM-Primary": {
                NO_PAGING_COMMAND: "",
                source_lookup: source_output,
                destination_lookup: destination_output,
            }
        }
    )

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert outcome.observations == ()
    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary"]
    assert factory.commands_by_device["MM-Primary"] == [
        NO_PAGING_COMMAND,
        source_lookup,
        destination_lookup,
    ]
    parse_event = next(event for event in outcome.diagnostics if event.stage == "MM_PARSE")
    assert parse_event.code is ErrorCode.PARSE_PARTIAL
    assert "Global user row IP is missing or is not an IPv4 address" in parse_event.message


def test_destination_only_query_uses_only_the_entered_ip_for_mm_and_md() -> None:
    request = QueryRequest("", REQUEST.destination_ip)
    destination_lookup = build_global_user_command(REQUEST.destination_ip)
    destination_filter = build_datapath_session_command(REQUEST.destination_ip)
    factory = FakeFactory(
        {
            "MM-Primary": {
                NO_PAGING_COMMAND: "",
                destination_lookup: _global_output(REQUEST.destination_ip, "192.0.2.102"),
            },
            "MD-2": {
                NO_PAGING_COMMAND: "",
                destination_filter: _datapath_output(),
            },
        }
    )

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert outcome.source_location is None
    assert outcome.destination_location is not None
    assert factory.calls == ["MM-Primary", "MD-2"]
    assert factory.commands_by_device["MM-Primary"] == [NO_PAGING_COMMAND, destination_lookup]
    assert factory.commands_by_device["MD-2"] == [NO_PAGING_COMMAND, destination_filter]


def test_md_status_prompt_completes_output_without_entry_count() -> None:
    request = QueryRequest("", REQUEST.destination_ip)
    destination_lookup = build_global_user_command(REQUEST.destination_ip)
    destination_filter = build_datapath_session_command(REQUEST.destination_ip)
    datapath_output = _datapath_output().replace(
        "Entries: 1",
        "(MD-2)^*[mynode]#",
    )
    factory = FakeFactory(
        {
            "MM-Primary": {
                NO_PAGING_COMMAND: "",
                destination_lookup: _global_output(REQUEST.destination_ip, "192.0.2.102"),
            },
            "MD-2": {
                NO_PAGING_COMMAND: "",
                destination_filter: datapath_output,
            },
        }
    )

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert all(event.stage != "MD_PARSE" for event in outcome.diagnostics)


def test_distinct_source_and_destination_mds_are_both_queried() -> None:
    request = QueryRequest(REQUEST.source_ip, REQUEST.destination_ip)
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.destination_ip): _datapath_output(
                source_port=23456
            ),
        },
    }
    factory = FakeFactory(outputs)

    outcome = TrackerService(_config(), factory).query_once(request, CREDENTIALS)

    assert len(outcome.observations) == 2
    assert outcome.authoritative is True
    assert factory.calls == ["MM-Primary", "MD-1", "MD-2"]


def test_same_source_and_destination_md_is_queried_once() -> None:
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.101"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)

    outcome = TrackerService(_config(), factory).query_once(REQUEST, CREDENTIALS)

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert factory.calls == ["MM-Primary", "MD-1"]


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


def test_md_host_key_failure_stops_before_other_candidates() -> None:
    config = _config()
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {NO_PAGING_COMMAND: ""},
        "MD-2": {NO_PAGING_COMMAND: ""},
    }
    factory = FakeFactory(outputs)
    factory.errors["MD-1"] = CollectorError(ErrorCode.HOST_KEY_CHANGED, "changed")

    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)

    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary", "MD-1"]
    assert ErrorCode.HOST_KEY_CHANGED in {event.code for event in outcome.diagnostics}


def test_md_command_permission_failure_stops_before_other_candidates() -> None:
    config = _config()
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {NO_PAGING_COMMAND: ""},
        "MD-2": {NO_PAGING_COMMAND: ""},
    }
    factory = FakeFactory(outputs)
    factory.errors["MD-1"] = CollectorError(ErrorCode.COMMAND_REJECTED, "permission")

    outcome = TrackerService(config, factory).query_once(REQUEST, CREDENTIALS)

    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary", "MD-1"]
    assert ErrorCode.COMMAND_REJECTED in {event.code for event in outcome.diagnostics}


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


def test_destination_only_full_scan_never_builds_an_unfiltered_md_command() -> None:
    request = QueryRequest("", REQUEST.destination_ip)
    destination_lookup = build_global_user_command(REQUEST.destination_ip)
    destination_filter = build_datapath_session_command(REQUEST.destination_ip)
    config = _config()
    outputs: dict[str, dict[str, str]] = {
        "MM-Primary": {
            NO_PAGING_COMMAND: "",
            destination_lookup: _global_output(REQUEST.destination_ip, None),
        }
    }
    for device in config.managed_devices:
        outputs[device.name] = {
            NO_PAGING_COMMAND: "",
            destination_filter: (_datapath_output() if device.name == "MD-2" else DATAPATH_EMPTY),
        }
    factory = FakeFactory(outputs)

    outcome = TrackerService(config, factory).query_once(
        request,
        CREDENTIALS,
        full_scan_approval=lambda *_args: True,
    )

    assert len(outcome.observations) == 1
    assert outcome.authoritative is True
    assert outcome.full_scan_eligible is True
    assert outcome.controllers == ("MD-1", "MD-2", "MD-3", "MD-4")
    for device in config.managed_devices:
        assert factory.commands_by_device[device.name] == [NO_PAGING_COMMAND, destination_filter]
    assert all(
        command != "show datapath session table"
        for commands in factory.commands_by_device.values()
        for command in commands
    )


def test_full_scan_approval_cancellation_takes_precedence_over_denial() -> None:
    config = _config()
    token = CancellationToken()
    factory = FakeFactory({"MM-Primary": _mm_outputs(None, None)})

    def cancel_approval(*_args: object) -> bool:
        token.cancel()
        return False

    outcome = TrackerService(config, factory).query_once(
        REQUEST,
        CREDENTIALS,
        full_scan_approval=cancel_approval,
        cancel_token=token,
    )

    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary"]
    assert [event.code for event in outcome.diagnostics][-1] is ErrorCode.CANCELLED


def test_full_scan_approval_deadline_prevents_late_scan() -> None:
    config = _config()
    outputs: dict[str, dict[str, str]] = {"MM-Primary": _mm_outputs(None, None)}
    for device in config.managed_devices:
        outputs[device.name] = {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
        }
    factory = FakeFactory(outputs)
    release_approval = Event()
    approval_finished = Event()

    def blocking_approval(
        _request: QueryRequest,
        _devices: tuple[DeviceTarget, ...],
        _deadline: PollDeadline,
    ) -> bool:
        release_approval.wait(timeout=3)
        approval_finished.set()
        return True

    started_at = time.monotonic()
    try:
        outcome = TrackerService(config, factory).query_once(
            REQUEST,
            CREDENTIALS,
            full_scan_approval=blocking_approval,
            deadline=PollDeadline.after(0.05),
        )
        elapsed = time.monotonic() - started_at
        assert elapsed < 0.5
        assert factory.calls == ["MM-Primary"]
        assert outcome.authoritative is False
        assert [event.code for event in outcome.diagnostics][-1] is (
            ErrorCode.POLL_DEADLINE_EXCEEDED
        )
    finally:
        release_approval.set()
        assert approval_finished.wait(timeout=3)

    # A late yes is discarded, so no managed-device query can start afterward.
    assert factory.calls == ["MM-Primary"]


def test_destination_only_monitor_reuses_cached_location_without_an_mm_query() -> None:
    request = QueryRequest("", REQUEST.destination_ip)
    destination_lookup = build_global_user_command(request.destination_ip)
    destination_filter = build_datapath_session_command(request.destination_ip)
    outputs = {
        "MM-Primary": {
            NO_PAGING_COMMAND: "",
            destination_lookup: _global_output(request.destination_ip, "192.0.2.102"),
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            destination_filter: _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)
    now = [0.0]
    monitor = MonitorEngine(
        TrackerService(_config(), factory),
        request,
        CREDENTIALS,
        monotonic_clock=lambda: now[0],
    )

    first = monitor.poll_once()
    now[0] = 5.0
    second = monitor.poll_once()

    assert len(first.observations) == 1
    assert first.refreshed_location is True
    assert first.outcome.source_location is None
    assert first.outcome.destination_location is not None
    assert len(second.observations) == 1
    assert second.refreshed_location is False
    assert second.outcome.source_location is None
    assert second.outcome.destination_location == first.outcome.destination_location
    assert factory.calls == ["MM-Primary", "MD-2", "MD-2"]
    assert factory.commands_by_device == {
        "MM-Primary": [NO_PAGING_COMMAND, destination_lookup],
        "MD-2": [
            NO_PAGING_COMMAND,
            destination_filter,
            NO_PAGING_COMMAND,
            destination_filter,
        ],
    }


def test_monitor_full_scan_reuses_only_the_md_that_matched_until_mm_refresh() -> None:
    config = _config()
    outputs: dict[str, dict[str, str]] = {"MM-Primary": _mm_outputs(None, None)}
    for device in config.managed_devices:
        outputs[device.name] = {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): (
                _datapath_output() if device.name == "MD-2" else DATAPATH_EMPTY
            ),
        }
    factory = FakeFactory(outputs)
    approvals = 0

    def approve(*_args: object) -> bool:
        nonlocal approvals
        approvals += 1
        return True

    ticks = count(0.0, 5.0)
    monitor = MonitorEngine(
        TrackerService(config, factory),
        REQUEST,
        CREDENTIALS,
        full_scan_approval=approve,
        monotonic_clock=lambda: next(ticks),
    )

    first = monitor.poll_once()
    calls_after_first = tuple(factory.calls)
    second = monitor.poll_once()

    assert len(first.observations) == 1
    assert len(second.observations) == 1
    assert approvals == 1
    assert calls_after_first == ("MM-Primary", "MD-1", "MD-2", "MD-3", "MD-4")
    assert factory.calls[len(calls_after_first) :] == ["MD-2"]


def test_destination_only_monitor_full_scan_reuses_the_filtered_matching_md() -> None:
    request = QueryRequest("", REQUEST.destination_ip)
    destination_lookup = build_global_user_command(request.destination_ip)
    destination_filter = build_datapath_session_command(request.destination_ip)
    config = _config()
    outputs: dict[str, dict[str, str]] = {
        "MM-Primary": {
            NO_PAGING_COMMAND: "",
            destination_lookup: _global_output(request.destination_ip, None),
        }
    }
    for device in config.managed_devices:
        outputs[device.name] = {
            NO_PAGING_COMMAND: "",
            destination_filter: (_datapath_output() if device.name == "MD-2" else DATAPATH_EMPTY),
        }
    factory = FakeFactory(outputs)
    approvals = 0

    def approve(*_args: object) -> bool:
        nonlocal approvals
        approvals += 1
        return True

    now = [0.0]
    monitor = MonitorEngine(
        TrackerService(config, factory),
        request,
        CREDENTIALS,
        full_scan_approval=approve,
        monotonic_clock=lambda: now[0],
    )

    first = monitor.poll_once()
    calls_after_first = tuple(factory.calls)
    now[0] = 5.0
    second = monitor.poll_once()

    assert len(first.observations) == 1
    assert first.authoritative is True
    assert first.outcome.full_scan_eligible is True
    assert len(second.observations) == 1
    assert second.authoritative is True
    assert second.refreshed_location is False
    assert approvals == 1
    assert calls_after_first == ("MM-Primary", "MD-1", "MD-2", "MD-3", "MD-4")
    assert factory.calls[len(calls_after_first) :] == ["MD-2"]
    assert factory.commands_by_device["MM-Primary"] == [NO_PAGING_COMMAND, destination_lookup]
    for device in config.managed_devices:
        expected = [NO_PAGING_COMMAND, destination_filter]
        if device.name == "MD-2":
            expected *= 2
        assert factory.commands_by_device[device.name] == expected
    assert all(
        not command.startswith("show datapath session table") or command == destination_filter
        for commands in factory.commands_by_device.values()
        for command in commands
    )


def test_monitor_empty_full_scan_is_not_repeated_before_the_next_mm_refresh() -> None:
    config = _config()
    outputs: dict[str, dict[str, str]] = {"MM-Primary": _mm_outputs(None, None)}
    for device in config.managed_devices:
        outputs[device.name] = {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
        }
    factory = FakeFactory(outputs)
    approvals = 0

    def approve(*_args: object) -> bool:
        nonlocal approvals
        approvals += 1
        return True

    ticks = count(0.0, 5.0)
    monitor = MonitorEngine(
        TrackerService(config, factory),
        REQUEST,
        CREDENTIALS,
        full_scan_approval=approve,
        monotonic_clock=lambda: next(ticks),
    )

    monitor.poll_once()
    calls_after_first = tuple(factory.calls)
    deferred = monitor.poll_once()

    assert approvals == 1
    assert tuple(factory.calls) == calls_after_first
    assert deferred.authoritative is False
    assert ErrorCode.CLIENT_NOT_FOUND_ON_MM in {event.code for event in deferred.diagnostics}


def test_monitor_keeps_querying_the_md_of_each_active_split_flow() -> None:
    split_request = QueryRequest(REQUEST.source_ip, REQUEST.destination_ip)
    source_command = build_datapath_session_command(split_request.source_ip)
    destination_command = build_datapath_session_command(split_request.destination_ip)
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            source_command: _datapath_output(source_port=12345),
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            destination_command: _datapath_output(source_port=23456),
        },
    }
    factory = FakeFactory(outputs)
    monotonic_now = [0.0]
    wall_start = datetime(2026, 8, 30, tzinfo=UTC)
    wall_ticks = count()
    monitor = MonitorEngine(
        TrackerService(replace(_config(), close_after_misses=2), factory),
        split_request,
        CREDENTIALS,
        monotonic_clock=lambda: monotonic_now[0],
        wall_clock=lambda: wall_start + timedelta(seconds=next(wall_ticks)),
    )

    first = monitor.poll_once()
    assert len(first.observations) == 2
    split_flow = next(
        item for item in first.active_sessions if item.observation.source_port == 23456
    )
    first_seen = split_flow.last_seen
    calls_after_first = len(factory.calls)

    later_results = []
    for poll_number in range(1, 4):
        monotonic_now[0] = float(poll_number * 5)
        later_results.append(monitor.poll_once())

    assert factory.calls[:calls_after_first] == ["MM-Primary", "MD-1", "MD-2"]
    assert factory.calls[calls_after_first:] == ["MD-1", "MD-2"] * 3
    assert all(len(result.observations) == 2 for result in later_results)
    assert all(
        not {
            LifecycleEventType.MISSED,
            LifecycleEventType.CLOSED,
        }.intersection(event.event_type for event in result.events)
        for result in later_results
    )
    final_split_flow = next(
        item for item in later_results[-1].active_sessions if item.observation.source_port == 23456
    )
    assert final_split_flow.instance_id == split_flow.instance_id
    assert final_split_flow.miss_count == 0
    assert final_split_flow.last_seen > first_seen


def test_repeated_full_scans_rotate_the_first_managed_device() -> None:
    outputs = {
        "MM-Primary": _mm_outputs(None, None),
        "MM-Standby": _mm_outputs(None, None),
        **{
            f"MD-{index}": {
                NO_PAGING_COMMAND: "",
                build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
            }
            for index in range(1, 5)
        },
    }
    factory = FakeFactory(outputs)
    service = TrackerService(_config(), factory)

    service.query_once(REQUEST, CREDENTIALS, full_scan_approval=lambda *_args: True)
    first_calls = tuple(factory.calls)
    factory.calls.clear()
    service.query_once(REQUEST, CREDENTIALS, full_scan_approval=lambda *_args: True)
    second_calls = tuple(factory.calls)

    assert first_calls == ("MM-Primary", "MD-1", "MD-2", "MD-3", "MD-4")
    assert second_calls == ("MM-Primary", "MD-2", "MD-3", "MD-4", "MD-1")


def test_repeated_fallback_full_scans_also_rotate_the_first_managed_device() -> None:
    outputs = {
        f"MD-{index}": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
        }
        for index in range(1, 5)
    }
    factory = FakeFactory(outputs)
    service = TrackerService(_config(), factory)
    fallback = _config().managed_devices
    location_snapshot = LocationSnapshot(
        source=None,
        destination=None,
        used_mm="MM-Primary",
        full_scan_eligible=True,
    )

    service.query_once(
        REQUEST,
        CREDENTIALS,
        location_snapshot=location_snapshot,
        refresh_locations=False,
        fallback_devices=fallback,
    )
    first_calls = tuple(factory.calls)
    factory.calls.clear()
    service.query_once(
        REQUEST,
        CREDENTIALS,
        location_snapshot=location_snapshot,
        refresh_locations=False,
        fallback_devices=fallback,
    )
    second_calls = tuple(factory.calls)

    assert first_calls == ("MD-1", "MD-2", "MD-3", "MD-4")
    assert second_calls == ("MD-2", "MD-3", "MD-4", "MD-1")


def test_fallback_scan_also_queries_an_active_controller_missing_from_its_cache() -> None:
    config = _config()
    outputs = {
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(source_port=23456),
        },
    }
    factory = FakeFactory(outputs)
    service = TrackerService(config, factory)

    outcome = service.query_once(
        QueryRequest(REQUEST.source_ip, REQUEST.destination_ip),
        CREDENTIALS,
        location_snapshot=LocationSnapshot(
            source=None,
            destination=None,
            used_mm="MM-Primary",
            full_scan_eligible=True,
        ),
        refresh_locations=False,
        fallback_devices=(config.managed_devices[0],),
        required_controller_hosts=(config.managed_devices[1].host,),
    )

    assert outcome.authoritative is True
    assert len(outcome.observations) == 2
    assert factory.calls == ["MD-1", "MD-2"]


def test_destination_only_fallback_and_required_controller_use_entered_filter() -> None:
    request = QueryRequest("", REQUEST.destination_ip)
    destination_filter = build_datapath_session_command(REQUEST.destination_ip)
    config = _config()
    outputs = {
        "MD-1": {
            NO_PAGING_COMMAND: "",
            destination_filter: _datapath_output(),
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            destination_filter: _datapath_output(source_port=23456),
        },
    }
    factory = FakeFactory(outputs)

    outcome = TrackerService(config, factory).query_once(
        request,
        CREDENTIALS,
        location_snapshot=LocationSnapshot(
            source=None,
            destination=None,
            used_mm="MM-Primary",
            full_scan_eligible=True,
        ),
        refresh_locations=False,
        fallback_devices=(config.managed_devices[0],),
        required_controller_hosts=(config.managed_devices[1].host,),
    )

    assert outcome.authoritative is True
    assert len(outcome.observations) == 2
    assert factory.calls == ["MD-1", "MD-2"]
    assert factory.commands_by_device == {
        "MD-1": [NO_PAGING_COMMAND, destination_filter],
        "MD-2": [NO_PAGING_COMMAND, destination_filter],
    }


def test_tracker_preserves_same_flow_from_two_direct_managed_devices() -> None:
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.destination_ip): _datapath_output(),
        },
    }

    outcome = TrackerService(_config(), FakeFactory(outputs)).query_once(REQUEST, CREDENTIALS)

    assert outcome.authoritative is True
    assert [item.controller_host for item in outcome.observations] == [
        "192.0.2.101",
        "192.0.2.102",
    ]
    assert len({_flow_key_without_controller(item) for item in outcome.observations}) == 1
    raw_links = {
        snapshot.device_name: snapshot.observation_keys
        for snapshot in outcome.raw_snapshots
        if snapshot.command.startswith("show datapath session table")
    }
    assert raw_links == {
        "MD-1": (outcome.observations[0].session_key,),
        "MD-2": (outcome.observations[1].session_key,),
    }


def test_direct_multi_md_query_fairly_slices_deadline_and_reaches_later_device() -> None:
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

    class DirectDeadlineFactory(FakeFactory):
        def __init__(self) -> None:
            super().__init__(outputs)
            self.md_deadlines: list[float] = []

        def connect(
            self,
            target: DeviceTarget,
            credentials: Credentials,
            *,
            host_key_approval: object,
            cancel_token: CancellationToken,
            deadline: object,
        ) -> FakeConnection:
            if target.name.startswith("MD-"):
                assert isinstance(deadline, PollDeadline)
                self.md_deadlines.append(deadline.expires_at)
                if target.name == "MD-1":
                    self.calls.append(target.name)
                    raise CollectorError(
                        ErrorCode.POLL_DEADLINE_EXCEEDED,
                        "fixture direct-device slice expired",
                        retryable_network=True,
                    )
            return super().connect(
                target,
                credentials,
                host_key_approval=host_key_approval,
                cancel_token=cancel_token,
                deadline=deadline,
            )

    factory = DirectDeadlineFactory()

    outcome = TrackerService(_config(), factory).query_once(
        REQUEST,
        CREDENTIALS,
        deadline=PollDeadline(100.0, lambda: 0.0),
    )

    assert factory.calls == ["MM-Primary", "MD-1", "MD-2"]
    assert factory.md_deadlines == pytest.approx([50.0, 100.0])
    assert len(outcome.observations) == 1
    assert outcome.authoritative is False


def test_full_scan_deadline_slice_failure_does_not_starve_later_devices() -> None:
    outputs = {
        "MM-Primary": _mm_outputs(None, None),
        "MM-Standby": _mm_outputs(None, None),
        **{
            f"MD-{index}": {
                NO_PAGING_COMMAND: "",
                build_datapath_session_command(REQUEST.source_ip): DATAPATH_EMPTY,
            }
            for index in range(1, 5)
        },
    }

    class DeadlineFactory(FakeFactory):
        def __init__(self) -> None:
            super().__init__(outputs)
            self.md_deadlines: list[float] = []

        def connect(
            self,
            target: DeviceTarget,
            credentials: Credentials,
            *,
            host_key_approval: object,
            cancel_token: CancellationToken,
            deadline: object,
        ) -> FakeConnection:
            if target.name.startswith("MD-"):
                assert isinstance(deadline, PollDeadline)
                self.md_deadlines.append(deadline.expires_at)
                if target.name == "MD-1":
                    self.calls.append(target.name)
                    raise CollectorError(
                        ErrorCode.POLL_DEADLINE_EXCEEDED,
                        "fixture device slice expired",
                        retryable_network=True,
                    )
            return super().connect(
                target,
                credentials,
                host_key_approval=host_key_approval,
                cancel_token=cancel_token,
                deadline=deadline,
            )

    factory = DeadlineFactory()
    outcome = TrackerService(_config(), factory).query_once(
        REQUEST,
        CREDENTIALS,
        full_scan_approval=lambda *_args: True,
        deadline=PollDeadline(100.0, lambda: 0.0),
    )

    assert factory.calls == ["MM-Primary", "MD-1", "MD-2", "MD-3", "MD-4"]
    assert factory.md_deadlines == pytest.approx([25.0, 100.0 / 3.0, 50.0, 100.0])
    assert outcome.authoritative is False


def test_query_raw_budget_exhaustion_is_non_authoritative() -> None:
    factory = FakeFactory({"MM-Primary": _mm_outputs("192.0.2.101", None)})

    outcome = TrackerService(_config(), factory).query_once(
        REQUEST,
        CREDENTIALS,
        poll_budget=PollBudget(max_raw_bytes=1),
    )

    assert outcome.authoritative is False
    assert ErrorCode.OUTPUT_LIMIT_EXCEEDED in {event.code for event in outcome.diagnostics}


@pytest.mark.parametrize(
    "kwargs, expected_exception",
    [
        ({"max_raw_bytes": MAX_POLL_RAW_BYTES + 1}, ValueError),
        ({"max_observations": MAX_POLL_OBSERVATIONS + 1}, ValueError),
        ({"max_observations": True}, TypeError),
        ({"raw_bytes": -1}, ValueError),
        ({"observations": 20_001}, ValueError),
    ],
)
def test_poll_budget_rejects_unsafe_initial_state(
    kwargs: dict[str, object],
    expected_exception: type[Exception],
) -> None:
    with pytest.raises(expected_exception):
        PollBudget(**kwargs)  # type: ignore[arg-type]


def test_poll_budget_rejects_non_integer_consumption() -> None:
    budget = PollBudget()

    with pytest.raises(TypeError):
        budget.consume_observations(1.5)  # type: ignore[arg-type]


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


def test_parsed_permission_rejection_stops_before_later_managed_device() -> None:
    filtered_source = build_datapath_session_command(REQUEST.source_ip)
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", "192.0.2.102"),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            filtered_source: "Permission denied",
        },
        "MD-2": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.destination_ip): _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)

    outcome = TrackerService(_config(), factory).query_once(REQUEST, CREDENTIALS)

    assert outcome.authoritative is False
    assert factory.calls == ["MM-Primary", "MD-1"]
    assert ErrorCode.COMMAND_REJECTED in {event.code for event in outcome.diagnostics}


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


def _flow_key_without_controller(observation: SessionObservation) -> tuple[object, ...]:
    return (
        observation.protocol,
        observation.source_ip,
        observation.destination_ip,
        observation.source_port,
        observation.destination_port,
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
    ticks = count(0.0, 5.0)
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
    ticks = count(0.0, 5.0)
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


def test_both_mm_transient_outage_recovers_without_false_miss_or_close() -> None:
    config = replace(_config(), location_interval_seconds=10)
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", None),
        "MM-Standby": _mm_outputs("192.0.2.101", None),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)
    now = [0.0]
    monitor = MonitorEngine(
        TrackerService(config, factory),
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: now[0],
    )

    started = monitor.poll_once()
    assert started.events[0].event_type is LifecycleEventType.STARTED

    factory.errors["MM-Primary"] = CollectorError(
        ErrorCode.MM_UNREACHABLE, "fixture primary timeout", retryable_network=True
    )
    factory.errors["MM-Standby"] = CollectorError(
        ErrorCode.MM_UNREACHABLE, "fixture standby timeout", retryable_network=True
    )
    now[0] = 11.0
    unavailable = monitor.poll_once()

    assert unavailable.authoritative is False
    assert unavailable.retry_after_seconds == 5
    assert unavailable.consecutive_misses == 0
    assert len(unavailable.active_sessions) == 1
    assert not {
        LifecycleEventType.MISSED,
        LifecycleEventType.CLOSED,
    }.intersection(event.event_type for event in unavailable.events)

    factory.errors.clear()
    now[0] = 22.0
    recovered = monitor.poll_once()

    assert recovered.authoritative is True
    assert recovered.retry_after_seconds == 0
    assert recovered.consecutive_transient_failures == 0
    assert recovered.consecutive_misses == 0
    assert len(recovered.active_sessions) == 1
    assert not {
        LifecycleEventType.MISSED,
        LifecycleEventType.CLOSED,
    }.intersection(event.event_type for event in recovered.events)


def test_transient_md_outage_recovers_without_false_miss_or_close() -> None:
    outputs = {
        "MM-Primary": _mm_outputs("192.0.2.101", None),
        "MM-Standby": _mm_outputs("192.0.2.101", None),
        "MD-1": {
            NO_PAGING_COMMAND: "",
            build_datapath_session_command(REQUEST.source_ip): _datapath_output(),
        },
    }
    factory = FakeFactory(outputs)
    now = [0.0]
    monitor = MonitorEngine(
        TrackerService(_config(), factory),
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: now[0],
    )

    monitor.poll_once()
    factory.errors["MD-1"] = CollectorError(
        ErrorCode.MD_UNREACHABLE, "fixture MD timeout", retryable_network=True
    )
    now[0] = 1.0
    unavailable = monitor.poll_once()

    assert unavailable.authoritative is False
    assert unavailable.retry_after_seconds == 5
    assert unavailable.consecutive_misses == 0
    assert len(unavailable.active_sessions) == 1
    assert not {
        LifecycleEventType.MISSED,
        LifecycleEventType.CLOSED,
    }.intersection(event.event_type for event in unavailable.events)

    factory.errors.clear()
    now[0] = 2.0
    recovered = monitor.poll_once()

    assert recovered.authoritative is True
    assert recovered.retry_after_seconds == 0
    assert recovered.consecutive_transient_failures == 0
    assert recovered.consecutive_misses == 0
    assert len(recovered.active_sessions) == 1
    assert not {
        LifecycleEventType.MISSED,
        LifecycleEventType.CLOSED,
    }.intersection(event.event_type for event in recovered.events)


def test_monitor_transient_failure_backoff_is_deterministic_and_resets() -> None:
    transient = QueryOutcome(
        diagnostics=(
            DiagnosticEvent(
                stage="MM_QUERY",
                code=ErrorCode.MM_UNREACHABLE,
                message="fixture transient",
                transient=True,
            ),
        ),
        authoritative=False,
    )
    recovered = QueryOutcome(used_mm="MM-Primary", authoritative=True)
    service = StubService([transient] * 7 + [recovered])
    ticks = count(0.0, 1.0)
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(ticks),
    )

    delays = [monitor.poll_once().retry_after_seconds for _ in range(7)]
    final = monitor.poll_once()

    assert delays == [5, 10, 20, 40, 80, 160, 300]
    assert final.retry_after_seconds == 0
    assert final.consecutive_transient_failures == 0


def test_successful_location_refresh_timestamp_is_taken_after_query_completion() -> None:
    observed = QueryOutcome(used_mm="MM-Primary", authoritative=True)
    service = StubService([observed, observed])
    ticks = iter((0.0, 45.0, 50.0))
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(ticks),
    )

    monitor.poll_once()
    monitor.poll_once()

    assert service.refresh_calls == [True, False]


def test_second_miss_of_one_flow_refreshes_mm_while_another_flow_remains() -> None:
    first = _observation(packets=1)
    second = replace(_observation(packets=1), source_port=23456)
    both = QueryOutcome(
        observations=(first, second),
        used_mm="MM-Primary",
        raw_snapshots=(
            RawSnapshot(
                "MD",
                "show datapath session table 198.51.100.10",
                "refreshed snapshot",
                observation_keys=(first.session_key, second.session_key),
            ),
        ),
        authoritative=True,
    )
    only_first = QueryOutcome(
        observations=(first,),
        used_mm="MM-Primary",
        raw_snapshots=(
            RawSnapshot(
                "MD",
                "show datapath session table 198.51.100.10",
                "first-pass snapshot",
                observation_keys=(first.session_key,),
            ),
        ),
        authoritative=True,
    )
    service = StubService([both, only_first, only_first, both])
    ticks = count(0.0, 5.0)
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
    assert tuple(snapshot.output for snapshot in refreshed.raw_snapshots) == (
        "first-pass snapshot",
        "refreshed snapshot",
    )
    assert refreshed.raw_snapshots[0].observation_keys == ()
    assert refreshed.raw_snapshots[1].observation_keys == (
        first.session_key,
        second.session_key,
    )


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
    ticks = count(0.0, 5.0)
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
    assert result.active_sessions[0].observation.packets == 3
    assert not any(event.event_type is LifecycleEventType.OBSERVED for event in result.events)


def test_monitor_defers_controller_change_across_authoritative_overlap() -> None:
    first = _observation(controller="192.0.2.101")
    second = replace(
        first,
        controller_name="MD-2",
        controller_host="192.0.2.102",
    )

    class RecordingService(StubService):
        def __init__(self) -> None:
            super().__init__(
                [
                    QueryOutcome(observations=(first,), authoritative=True),
                    QueryOutcome(observations=(second, first), authoritative=True),
                    QueryOutcome(observations=(second,), authoritative=True),
                ]
            )
            self.required_hosts: list[tuple[str, ...]] = []

        def query_once(self, *args: object, **kwargs: object) -> QueryOutcome:
            self.required_hosts.append(tuple(kwargs["required_controller_hosts"]))
            return super().query_once(*args, **kwargs)

    service = RecordingService()
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    started = monitor.poll_once()
    overlap = monitor.poll_once()
    moved = monitor.poll_once()

    assert len(overlap.observations) == 2
    assert len(overlap.active_sessions) == 1
    assert overlap.active_sessions[0].instance_id == started.active_sessions[0].instance_id
    assert overlap.events == ()
    assert ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS in {
        item.code for item in overlap.diagnostics
    }
    assert service.required_hosts[:2] == [(), ("192.0.2.101",)]
    assert set(service.required_hosts[2]) == {"192.0.2.101", "192.0.2.102"}
    assert [item.event_type for item in moved.events] == [LifecycleEventType.CONTROLLER_CHANGED]
    assert moved.events[0].previous_observation == first
    assert moved.events[0].observation == second
    assert moved.active_sessions[0].instance_id == started.active_sessions[0].instance_id


def test_monitor_initial_overlap_resolves_without_false_controller_change() -> None:
    first = _observation(controller="192.0.2.101")
    second = replace(
        first,
        controller_name="MD-2",
        controller_host="192.0.2.102",
    )

    class RecordingService(StubService):
        def __init__(self) -> None:
            super().__init__(
                [
                    QueryOutcome(observations=(second, first), authoritative=True),
                    QueryOutcome(observations=(second,), authoritative=True),
                ]
            )
            self.required_hosts: list[tuple[str, ...]] = []

        def query_once(self, *args: object, **kwargs: object) -> QueryOutcome:
            self.required_hosts.append(tuple(kwargs["required_controller_hosts"]))
            return super().query_once(*args, **kwargs)

    service = RecordingService()
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    overlap = monitor.poll_once()
    resolved = monitor.poll_once()

    assert [item.event_type for item in overlap.events] == [LifecycleEventType.STARTED]
    assert resolved.events == ()
    assert resolved.active_sessions[0].instance_id == overlap.active_sessions[0].instance_id
    assert set(service.required_hosts[1]) == {"192.0.2.101", "192.0.2.102"}


def test_non_authoritative_positive_poll_retains_controller_scope_and_defers_change() -> None:
    first = _observation(controller="192.0.2.101")
    second = replace(
        first,
        controller_name="MD-2",
        controller_host="192.0.2.102",
    )

    class RecordingService(StubService):
        def __init__(self) -> None:
            super().__init__(
                [
                    QueryOutcome(observations=(first,), authoritative=True),
                    QueryOutcome(observations=(second,), authoritative=False),
                    QueryOutcome(observations=(second,), authoritative=True),
                ]
            )
            self.required_hosts: list[tuple[str, ...]] = []

        def query_once(self, *args: object, **kwargs: object) -> QueryOutcome:
            self.required_hosts.append(tuple(kwargs["required_controller_hosts"]))
            return super().query_once(*args, **kwargs)

    service = RecordingService()
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    monitor.poll_once()
    partial = monitor.poll_once()
    resolved = monitor.poll_once()

    assert partial.authoritative is False
    assert partial.events == ()
    assert partial.consecutive_misses == 0
    assert set(service.required_hosts[2]) == {"192.0.2.101", "192.0.2.102"}
    assert [item.event_type for item in resolved.events] == [LifecycleEventType.CONTROLLER_CHANGED]


def test_merge_outcomes_supersedes_every_first_pass_controller_for_refreshed_flow() -> None:
    first = _observation(controller="192.0.2.101")
    second = replace(
        first,
        controller_name="MD-2",
        controller_host="192.0.2.102",
    )
    refreshed_second = replace(second, packets=2)
    merged = monitoring_module._merge_outcomes(
        QueryOutcome(
            observations=(first, second),
            raw_snapshots=(
                RawSnapshot(
                    "MD-1",
                    "show datapath session table 198.51.100.10",
                    "first-pass",
                    observation_keys=(first.session_key,),
                ),
                RawSnapshot(
                    "MD-2",
                    "show datapath session table 198.51.100.10",
                    "first-pass-overlap",
                    observation_keys=(second.session_key,),
                ),
            ),
            authoritative=True,
        ),
        QueryOutcome(
            observations=(refreshed_second,),
            raw_snapshots=(
                RawSnapshot(
                    "MD-2",
                    "show datapath session table 198.51.100.10",
                    "refreshed-pass",
                    observation_keys=(refreshed_second.session_key,),
                ),
            ),
            authoritative=True,
        ),
    )

    assert merged.observations == (refreshed_second,)
    assert [snapshot.observation_keys for snapshot in merged.raw_snapshots] == [
        (),
        (),
        (refreshed_second.session_key,),
    ]


def test_merge_outcomes_preserves_all_controllers_within_refreshed_pass() -> None:
    first = _observation(controller="192.0.2.101")
    refreshed_first = replace(first, packets=2)
    refreshed_second = replace(
        first,
        controller_name="MD-2",
        controller_host="192.0.2.102",
        packets=3,
    )
    merged = monitoring_module._merge_outcomes(
        QueryOutcome(
            observations=(first,),
            raw_snapshots=(
                RawSnapshot(
                    "MD-1",
                    "show datapath session table 198.51.100.10",
                    "first-pass",
                    observation_keys=(first.session_key,),
                ),
            ),
            authoritative=True,
        ),
        QueryOutcome(
            observations=(refreshed_first, refreshed_second),
            raw_snapshots=(
                RawSnapshot(
                    "MD-1",
                    "show datapath session table 198.51.100.10",
                    "refreshed-first-controller",
                    observation_keys=(refreshed_first.session_key,),
                ),
                RawSnapshot(
                    "MD-2",
                    "show datapath session table 198.51.100.10",
                    "refreshed-second-controller",
                    observation_keys=(refreshed_second.session_key,),
                ),
            ),
            authoritative=True,
        ),
    )

    assert merged.observations == (refreshed_first, refreshed_second)
    assert [snapshot.observation_keys for snapshot in merged.raw_snapshots] == [
        (),
        (refreshed_first.session_key,),
        (refreshed_second.session_key,),
    ]


def test_discarded_prepared_poll_does_not_advance_monitor_state() -> None:
    observed = QueryOutcome(
        observations=(_observation(),), used_mm="MM-Primary", authoritative=True
    )
    service = StubService([observed, observed])
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    prepared = monitor._prepare_for_persistence()
    monitor._discard_prepared(prepared)
    committed = monitor.poll_once()

    assert committed.events[0].event_type is LifecycleEventType.STARTED
    assert service.refresh_calls == [True, True]


def test_monitor_rejects_overlapping_prepared_polls() -> None:
    started = Event()
    release = Event()
    observed = QueryOutcome(
        observations=(_observation(),), used_mm="MM-Primary", authoritative=True
    )

    class BlockingService:
        config = _config()

        def query_once(self, *args: object, **kwargs: object) -> QueryOutcome:
            del args, kwargs
            started.set()
            assert release.wait(timeout=5)
            return observed

    monitor = MonitorEngine(
        BlockingService(),  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
    )
    prepared_results: list[object] = []

    def prepare() -> None:
        prepared_results.append(monitor._prepare_for_persistence())

    worker = Thread(target=prepare)
    worker.start()
    assert started.wait(timeout=5)

    with pytest.raises(RuntimeError, match="이미 진행"):
        monitor._prepare_for_persistence()

    release.set()
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert len(prepared_results) == 1
    monitor._discard_prepared(prepared_results[0])  # type: ignore[arg-type]


def test_monitor_callback_observes_committed_result_and_thread_can_restart() -> None:
    observed = QueryOutcome(
        observations=(_observation(),), used_mm="MM-Primary", authoritative=True
    )
    service = StubService([observed, QueryOutcome(used_mm="MM-Primary", authoritative=True)])
    callback_seen = Event()
    holder: list[MonitorEngine] = []

    def callback(event: object) -> None:
        monitor = holder[0]
        assert monitor.last_result is not None
        assert event in monitor.last_result.events
        callback_seen.set()

    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        callbacks=callback,  # type: ignore[arg-type]
    )
    holder.append(monitor)

    for _ in range(2):
        callback_seen.clear()
        monitor.start()
        assert callback_seen.wait(timeout=5)
        monitor.stop(timeout=5)
        assert monitor.is_running is False


def test_monitor_callback_failure_does_not_reclassify_committed_poll() -> None:
    observed = QueryOutcome(
        observations=(_observation(),), used_mm="MM-Primary", authoritative=True
    )
    service = StubService([observed])
    callback_events: list[object] = []

    def failing_callback(event: object) -> None:
        callback_events.append(event)
        raise RuntimeError("fixture callback failure")

    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        callbacks=failing_callback,  # type: ignore[arg-type]
    )

    result = monitor.poll_once()

    assert callback_events == list(result.events)
    assert monitor.last_result is result
    assert monitor._prepared_generation is None


def test_monitor_events_focus_on_state_transitions_not_routine_counter_growth() -> None:
    first = _observation(packets=10)
    growing = replace(first, packets=11, bytes_count=1001)
    reset = replace(first, packets=1, bytes_count=10)
    missing = QueryOutcome(used_mm="MM-Primary", authoritative=True)
    service = StubService(
        [
            QueryOutcome(observations=(first,), used_mm="MM-Primary", authoritative=True),
            QueryOutcome(observations=(growing,), used_mm="MM-Primary", authoritative=True),
            missing,
            QueryOutcome(observations=(reset,), used_mm="MM-Primary", authoritative=True),
        ]
    )
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    started = monitor.poll_once()
    routine = monitor.poll_once()
    missed = monitor.poll_once()
    recovered = monitor.poll_once()

    assert [event.event_type for event in started.events] == [LifecycleEventType.STARTED]
    assert routine.events == ()
    assert [event.event_type for event in missed.events] == [LifecycleEventType.MISSED]
    assert [event.event_type for event in recovered.events] == [
        LifecycleEventType.OBSERVED,
        LifecycleEventType.COUNTERS_CHANGED,
    ]
    assert routine.observations == (growing,)
    assert recovered.observations == (reset,)


def test_one_recovered_observation_can_emit_four_lifecycle_events() -> None:
    first = _observation(packets=10)
    changed = replace(
        first,
        controller_name="MD-02",
        controller_host="198.51.100.22",
        flags="D",
        packets=1,
        bytes_count=10,
    )
    service = StubService(
        [
            QueryOutcome(observations=(first,), authoritative=True),
            QueryOutcome(authoritative=True),
            QueryOutcome(observations=(changed,), authoritative=True),
        ]
    )
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    monitor.poll_once()
    monitor.poll_once()
    recovered = monitor.poll_once()

    assert [event.event_type for event in recovered.events] == [
        LifecycleEventType.OBSERVED,
        LifecycleEventType.CONTROLLER_CHANGED,
        LifecycleEventType.FLAGS_CHANGED,
        LifecycleEventType.COUNTERS_CHANGED,
    ]


def test_monitor_capacity_overflow_recovers_to_current_positive_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(monitoring_module, "MAX_POLL_OBSERVATIONS", 2)
    first = replace(_observation(), source_port=10001)
    second = replace(_observation(), source_port=10002)
    third = replace(_observation(), source_port=10003)
    fourth = replace(_observation(), source_port=10004)
    initial = QueryOutcome(observations=(first, second), authoritative=True)
    churn = QueryOutcome(observations=(third, fourth), authoritative=True)
    service = StubService([initial, churn, churn])
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    monitor.poll_once()
    overflowed = monitor.poll_once()
    healed = monitor.poll_once()

    assert overflowed.authoritative is False
    assert {item.flow_key for item in overflowed.active_sessions} == {
        monitoring_module._flow_key(third),
        monitoring_module._flow_key(fourth),
    }
    assert not {
        LifecycleEventType.MISSED,
        LifecycleEventType.CLOSED,
    }.intersection(event.event_type for event in overflowed.events)
    assert healed.authoritative is True
    assert len(healed.active_sessions) == 2


def test_monitor_location_invalidation_forces_refresh() -> None:
    observed = QueryOutcome(observations=(_observation(),), authoritative=True)
    service = StubService([observed, observed])
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    monitor.poll_once()
    monitor.invalidate_location()
    monitor.poll_once()

    assert service.refresh_calls == [True, True]


def test_monitor_location_invalidation_during_poll_cannot_recommit_stale_location() -> None:
    observed = QueryOutcome(observations=(_observation(),), used_mm="MM-Primary")
    service = StubService([observed, observed])
    monitor = MonitorEngine(service, REQUEST, CREDENTIALS)  # type: ignore[arg-type]

    prepared = monitor._prepare_for_persistence()
    monitor.invalidate_location()
    monitor._commit_prepared(prepared)
    monitor.poll_once()

    assert monitor._location_snapshot is not None
    assert service.refresh_calls == [True, True]


def test_monitor_daemon_exposes_unexpected_failure() -> None:
    service = StubService([])
    failure_seen = Event()
    failures: list[Exception] = []

    def failure_callback(exc: Exception) -> None:
        failures.append(exc)
        failure_seen.set()

    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        failure_callback=failure_callback,
    )
    monitor.start()

    assert failure_seen.wait(timeout=5)
    monitor.stop(timeout=1)
    assert isinstance(monitor.last_error, MonitorDaemonError)
    assert monitor.last_error.exception_type == "IndexError"
    assert monitor.last_error.__traceback__ is None
    assert len(failures) == 1
    assert failures[0] is monitor.last_error
    assert "fixture" not in repr(failures[0])
    assert monitor.is_running is False


def test_monitor_daemon_does_not_retain_failure_message_or_traceback_secret() -> None:
    canary = "MONITOR_SECRET_CANARY_7f4a"
    failure_seen = Event()

    class SecretFailureService:
        config = _config()

        def query_once(self, *_args: object, **_kwargs: object) -> QueryOutcome:
            runtime_secret = canary
            raise RuntimeError(runtime_secret)

    monitor = MonitorEngine(
        SecretFailureService(),  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        failure_callback=lambda _failure: failure_seen.set(),
    )
    monitor.start()

    assert failure_seen.wait(timeout=5)
    monitor.stop(timeout=1)
    assert monitor.last_error is not None
    assert monitor.last_error.exception_type == "RuntimeError"
    assert monitor.last_error.__traceback__ is None
    assert canary not in repr(monitor.last_error)


@pytest.mark.soak
def test_monitor_accelerated_soak_keeps_bounded_ownership() -> None:
    iterations_text = os.environ.get("ARUBA_SOAK_POLLS", "2000")
    assert iterations_text.isascii() and iterations_text.isdecimal()
    iterations = int(iterations_text)
    assert 1 <= iterations <= 20_000

    class FreshSoakService:
        def __init__(self) -> None:
            self.config = _config()
            self.polls = 0

        def query_once(self, *args: object, **kwargs: object) -> QueryOutcome:
            del args, kwargs
            self.polls += 1
            observation = _observation(packets=self.polls)
            return QueryOutcome(
                observations=(observation,),
                used_mm="MM-Primary",
                raw_snapshots=(
                    RawSnapshot(
                        "MD",
                        build_datapath_session_command(REQUEST.source_ip),
                        f"poll={self.polls}",
                        observation_keys=(observation.session_key,),
                    ),
                ),
                authoritative=True,
            )

    service = FreshSoakService()
    monotonic_ticks = count(0.0, 1.0)
    wall_ticks = count()
    wall_start = datetime(2026, 8, 28, tzinfo=UTC)
    monitor = MonitorEngine(
        service,  # type: ignore[arg-type]
        REQUEST,
        CREDENTIALS,
        monotonic_clock=lambda: next(monotonic_ticks),
        wall_clock=lambda: wall_start + timedelta(seconds=next(wall_ticks)),
    )

    first_instance: str | None = None
    previous_outcome: QueryOutcome | None = None
    for poll_number in range(1, iterations + 1):
        result = monitor.poll_once()
        assert len(result.active_sessions) == 1
        assert result.outcome is not previous_outcome
        assert result.raw_snapshots[0].output == f"poll={poll_number}"
        assert result.retry_after_seconds == 0
        if first_instance is None:
            first_instance = result.active_sessions[0].instance_id
        else:
            assert result.active_sessions[0].instance_id == first_instance
        previous_outcome = result.outcome

    assert service.polls == iterations
    assert monitor.is_running is False
    assert monitor.last_result is not None
    assert monitor.last_result.consecutive_misses == 0
    assert monitor._thread is None
    assert monitor._cancel_token is None
    assert monitor._prepared_generation is None
    assert len(monitor._active) == 1
