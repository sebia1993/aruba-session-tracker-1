"""Pure session-observation aggregation for optional analysis views."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Address

from aruba_session_tracker.models import SessionObservation

from .catalog import protocol_label


@dataclass(frozen=True, slots=True)
class SessionFlow:
    """Controller-independent identity of one observed network flow."""

    protocol: int
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int

    @classmethod
    def from_observation(cls, observation: SessionObservation) -> SessionFlow:
        return cls(
            protocol=observation.protocol,
            source_ip=observation.source_ip,
            source_port=observation.source_port,
            destination_ip=observation.destination_ip,
            destination_port=observation.destination_port,
        )

    @property
    def key(self) -> str:
        """Return an unambiguous stable key without controller identity."""

        return "|".join(
            (
                str(self.protocol),
                self.source_ip,
                self.destination_ip,
                str(self.source_port),
                str(self.destination_port),
            )
        )


@dataclass(frozen=True, slots=True)
class CounterTrend:
    """First and last stored values with their arithmetic difference."""

    first_value: int | None
    last_value: int | None
    delta: int | None


@dataclass(frozen=True, slots=True)
class SessionTrend:
    """Observed endpoints and counters for one controller-independent flow."""

    flow: SessionFlow
    observation_count: int
    first_observed_at: datetime
    last_observed_at: datetime
    first_controller_name: str
    last_controller_name: str
    packets: CounterTrend
    bytes_count: CounterTrend
    denied_observation_count: int

    @property
    def was_denied(self) -> bool:
        return self.denied_observation_count > 0

    @property
    def controller_changed(self) -> bool:
        return self.first_controller_name != self.last_controller_name


@dataclass(frozen=True, slots=True)
class ProtocolCount:
    protocol: int
    label: str
    observation_count: int
    stored_session_count: int
    logical_flow_count: int


@dataclass(frozen=True, slots=True)
class DestinationCount:
    destination_ip: str
    observation_count: int
    stored_session_count: int
    logical_flow_count: int


@dataclass(frozen=True, slots=True)
class CurrentCounterTotals:
    """Totals from the last observation of every controller-independent flow."""

    packets_total: int
    bytes_total: int
    packets_value_count: int
    bytes_value_count: int
    logical_flow_count: int

    @property
    def packets_missing_count(self) -> int:
        return self.logical_flow_count - self.packets_value_count

    @property
    def bytes_missing_count(self) -> int:
        return self.logical_flow_count - self.bytes_value_count


@dataclass(frozen=True, slots=True)
class SessionAnalysisSummary:
    observation_count: int
    stored_session_count: int
    logical_flow_count: int
    denied_observation_count: int
    denied_stored_session_count: int
    denied_flow_count: int
    protocol_counts: tuple[ProtocolCount, ...]
    destination_counts: tuple[DestinationCount, ...]
    current_totals: CurrentCounterTotals
    flow_trends: tuple[SessionTrend, ...]


def analyze_observations(
    observations: Iterable[SessionObservation],
) -> SessionAnalysisSummary:
    """Return a deterministic immutable summary without changing input rows.

    ``stored_session_count`` follows :attr:`SessionObservation.session_key` and
    therefore includes the controller. ``logical_flow_count`` and trends use
    the protocol and four-tuple independently of the reporting controller so a
    controller move can be compared. Deltas are only ``last - first``;
    negative values are retained and no reset, wrap, loss, or other cause is
    inferred.
    """

    indexed_rows: list[tuple[int, SessionObservation]] = []
    for index, observation in enumerate(observations):
        if not isinstance(observation, SessionObservation):
            raise TypeError("All observations must be SessionObservation values.")
        indexed_rows.append((index, observation))

    grouped: dict[SessionFlow, list[tuple[int, SessionObservation]]] = defaultdict(list)
    for indexed_row in indexed_rows:
        grouped[SessionFlow.from_observation(indexed_row[1])].append(indexed_row)

    trends = tuple(
        _trend(flow, rows)
        for flow, rows in sorted(grouped.items(), key=lambda item: _flow_sort_key(item[0]))
    )

    protocol_observations: dict[int, int] = defaultdict(int)
    destination_observations: dict[str, int] = defaultdict(int)
    denied_observation_count = 0
    stored_sessions: set[str] = set()
    denied_stored_sessions: set[str] = set()
    protocol_stored_sessions: dict[int, set[str]] = defaultdict(set)
    destination_stored_sessions: dict[str, set[str]] = defaultdict(set)
    for _, observation in indexed_rows:
        protocol_observations[observation.protocol] += 1
        destination_observations[observation.destination_ip] += 1
        denied_observation_count += int("D" in observation.flags)
        stored_sessions.add(observation.session_key)
        protocol_stored_sessions[observation.protocol].add(observation.session_key)
        destination_stored_sessions[observation.destination_ip].add(observation.session_key)
        if "D" in observation.flags:
            denied_stored_sessions.add(observation.session_key)

    protocol_sessions: dict[int, int] = defaultdict(int)
    destination_sessions: dict[str, int] = defaultdict(int)
    for trend in trends:
        protocol_sessions[trend.flow.protocol] += 1
        destination_sessions[trend.flow.destination_ip] += 1

    protocol_counts = tuple(
        ProtocolCount(
            protocol=protocol,
            label=protocol_label(protocol),
            observation_count=count,
            stored_session_count=len(protocol_stored_sessions[protocol]),
            logical_flow_count=protocol_sessions[protocol],
        )
        for protocol, count in sorted(
            protocol_observations.items(), key=lambda item: (-item[1], item[0])
        )
    )
    destination_counts = tuple(
        DestinationCount(
            destination_ip=destination_ip,
            observation_count=count,
            stored_session_count=len(destination_stored_sessions[destination_ip]),
            logical_flow_count=destination_sessions[destination_ip],
        )
        for destination_ip, count in sorted(
            destination_observations.items(),
            key=lambda item: (-item[1], int(IPv4Address(item[0]))),
        )
    )

    packets = tuple(trend.packets.last_value for trend in trends)
    bytes_values = tuple(trend.bytes_count.last_value for trend in trends)
    current_totals = CurrentCounterTotals(
        packets_total=sum(value for value in packets if value is not None),
        bytes_total=sum(value for value in bytes_values if value is not None),
        packets_value_count=sum(value is not None for value in packets),
        bytes_value_count=sum(value is not None for value in bytes_values),
        logical_flow_count=len(trends),
    )

    return SessionAnalysisSummary(
        observation_count=len(indexed_rows),
        stored_session_count=len(stored_sessions),
        logical_flow_count=len(trends),
        denied_observation_count=denied_observation_count,
        denied_stored_session_count=len(denied_stored_sessions),
        denied_flow_count=sum(trend.was_denied for trend in trends),
        protocol_counts=protocol_counts,
        destination_counts=destination_counts,
        current_totals=current_totals,
        flow_trends=trends,
    )


def _trend(
    flow: SessionFlow,
    rows: list[tuple[int, SessionObservation]],
) -> SessionTrend:
    ordered = sorted(rows, key=lambda item: (_datetime_sort_key(item[1].observed_at), item[0]))
    first = ordered[0][1]
    last = ordered[-1][1]
    return SessionTrend(
        flow=flow,
        observation_count=len(ordered),
        first_observed_at=first.observed_at,
        last_observed_at=last.observed_at,
        first_controller_name=first.controller_name,
        last_controller_name=last.controller_name,
        packets=_counter_trend(first.packets, last.packets),
        bytes_count=_counter_trend(first.bytes_count, last.bytes_count),
        denied_observation_count=sum("D" in observation.flags for _, observation in ordered),
    )


def _counter_trend(first: int | None, last: int | None) -> CounterTrend:
    delta = None if first is None or last is None else last - first
    return CounterTrend(first_value=first, last_value=last, delta=delta)


def _datetime_sort_key(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _flow_sort_key(flow: SessionFlow) -> tuple[int, int, int, int, int]:
    return (
        flow.protocol,
        int(IPv4Address(flow.source_ip)),
        flow.source_port,
        int(IPv4Address(flow.destination_ip)),
        flow.destination_port,
    )
