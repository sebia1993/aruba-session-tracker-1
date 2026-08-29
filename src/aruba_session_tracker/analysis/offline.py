"""Deterministic aggregation for one parsed offline session snapshot.

Offline rows do not contain a trustworthy observation time or controller
identity.  This module therefore summarizes only values present in the single
snapshot and deliberately exposes no trend or lifecycle model.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address

from aruba_session_tracker.offline import OfflineSessionRecord

from .catalog import protocol_label


@dataclass(frozen=True, slots=True, repr=False)
class OfflineSnapshotProtocolCount:
    """Row and unique-flow counts for one protocol in the snapshot."""

    protocol: int
    label: str
    row_count: int
    unique_flow_count: int


@dataclass(frozen=True, slots=True, repr=False)
class OfflineSnapshotDestinationCount:
    """Row and unique-flow counts for one destination in the snapshot."""

    destination_ip: str
    row_count: int
    unique_flow_count: int


@dataclass(frozen=True, slots=True, repr=False)
class OfflineSnapshotCounterTotals:
    """Arithmetic packet and byte totals across every stored snapshot row."""

    packets_total: int
    bytes_total: int


@dataclass(frozen=True, slots=True, repr=False)
class OfflineSnapshotSummary:
    """Immutable facts available from exactly one offline snapshot."""

    row_count: int
    unique_session_key_count: int
    denied_row_count: int
    protocol_counts: tuple[OfflineSnapshotProtocolCount, ...]
    destination_counts: tuple[OfflineSnapshotDestinationCount, ...]
    counter_totals: OfflineSnapshotCounterTotals


def analyze_offline_snapshot(
    records: Iterable[OfflineSessionRecord],
) -> OfflineSnapshotSummary:
    """Summarize one offline snapshot without inventing time or controller data.

    ``unique_session_key_count`` and each ``unique_flow_count`` use the
    controller-free :attr:`OfflineSessionRecord.session_key`. Packet and byte
    totals include every supplied row. A ``D`` in the stored flags marks only
    that row as denied; no creation, closure, movement, or trend is inferred.
    """

    rows: list[OfflineSessionRecord] = []
    for record in records:
        if not isinstance(record, OfflineSessionRecord):
            raise TypeError("All records must be OfflineSessionRecord values.")
        rows.append(record)

    session_keys: set[str] = set()
    protocol_rows: dict[int, int] = defaultdict(int)
    protocol_flows: dict[int, set[str]] = defaultdict(set)
    destination_rows: dict[str, int] = defaultdict(int)
    destination_flows: dict[str, set[str]] = defaultdict(set)
    denied_row_count = 0
    packets_total = 0
    bytes_total = 0

    for record in rows:
        session_key = record.session_key
        session_keys.add(session_key)
        protocol_rows[record.protocol] += 1
        protocol_flows[record.protocol].add(session_key)
        destination_rows[record.destination_ip] += 1
        destination_flows[record.destination_ip].add(session_key)
        denied_row_count += int("D" in record.flags)
        packets_total += record.packets
        bytes_total += record.bytes_count

    protocol_counts = tuple(
        OfflineSnapshotProtocolCount(
            protocol=protocol,
            label=protocol_label(protocol),
            row_count=row_count,
            unique_flow_count=len(protocol_flows[protocol]),
        )
        for protocol, row_count in sorted(
            protocol_rows.items(), key=lambda item: (-item[1], item[0])
        )
    )
    destination_counts = tuple(
        OfflineSnapshotDestinationCount(
            destination_ip=destination_ip,
            row_count=row_count,
            unique_flow_count=len(destination_flows[destination_ip]),
        )
        for destination_ip, row_count in sorted(
            destination_rows.items(),
            key=lambda item: (-item[1], int(IPv4Address(item[0]))),
        )
    )

    return OfflineSnapshotSummary(
        row_count=len(rows),
        unique_session_key_count=len(session_keys),
        denied_row_count=denied_row_count,
        protocol_counts=protocol_counts,
        destination_counts=destination_counts,
        counter_totals=OfflineSnapshotCounterTotals(
            packets_total=packets_total,
            bytes_total=bytes_total,
        ),
    )
