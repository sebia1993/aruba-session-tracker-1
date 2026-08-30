from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from aruba_session_tracker.analysis import (
    OfflineSnapshotSummary,
    analyze_offline_snapshot,
)
from aruba_session_tracker.offline import OfflineSessionRecord


def _record(**overrides: object) -> OfflineSessionRecord:
    values: dict[str, object] = {
        "source_ip": "192.0.2.10",
        "destination_ip": "203.0.113.20",
        "protocol": 6,
        "source_port": 50_000,
        "destination_port": 443,
        "counter": "1/2/3",
        "priority": 0,
        "tos": 0,
        "age": 10,
        "destination": "local",
        "tunnel_age": 0,
        "packets": 12,
        "bytes_count": 1_200,
        "session_index": "1",
        "source_route_table_index": "0",
        "source_class_index": "0",
        "source_route_receive": "0",
        "mobility_tunnel": "0",
        "source_route_mobility_version": "0",
        "user_index": "1",
        "user_version": "1",
        "acl_version": "1",
        "next_hop_list_index": "0",
        "next_hop_index": "0",
        "next_hop_list_next_hop_version": "0",
        "internal_flag": "-",
        "session_flag2": "-",
        "dpi_packets": "0",
        "uplink_vlan": "0",
        "application_id": "0",
        "webcc_reputation": "0",
        "webcc_id": "0",
        "threat": "0",
        "country": "--",
        "flags": "FC",
        "dpi_table_index": "0",
        "webcc_url": "-",
        "cpu_id": 0,
    }
    values.update(overrides)
    return OfflineSessionRecord(**values)  # type: ignore[arg-type]


def test_offline_snapshot_aggregates_only_stored_snapshot_facts() -> None:
    duplicate_flow = _record(packets=8, bytes_count=800, flags="D")
    rows = (
        _record(),
        duplicate_flow,
        _record(
            protocol=17,
            source_port=53_000,
            destination_ip="203.0.113.10",
            destination_port=53,
            packets=5,
            bytes_count=500,
            flags="FD",
        ),
        _record(
            protocol=17,
            source_port=53_001,
            destination_ip="203.0.113.10",
            destination_port=53,
            packets=4,
            bytes_count=400,
        ),
        _record(
            protocol=253,
            source_port=1,
            destination_ip="198.51.100.3",
            destination_port=2,
            packets=1,
            bytes_count=100,
        ),
    )

    summary = analyze_offline_snapshot(row for row in rows)

    assert summary.row_count == 5
    assert summary.unique_session_key_count == 4
    assert summary.denied_row_count == 2
    assert [
        (item.label, item.row_count, item.unique_flow_count) for item in summary.protocol_counts
    ] == [
        ("TCP (6)", 2, 1),
        ("UDP (17)", 2, 2),
        ("Protocol 253", 1, 1),
    ]
    assert [
        (item.destination_ip, item.row_count, item.unique_flow_count)
        for item in summary.destination_counts
    ] == [
        ("203.0.113.10", 2, 2),
        ("203.0.113.20", 2, 1),
        ("198.51.100.3", 1, 1),
    ]
    assert summary.counter_totals.packets_total == 30
    assert summary.counter_totals.bytes_total == 3_000


def test_offline_snapshot_summary_is_deterministic_for_input_order() -> None:
    rows = (
        _record(destination_ip="203.0.113.2", source_port=50_002),
        _record(destination_ip="203.0.113.1", source_port=50_001),
        _record(protocol=17, destination_ip="203.0.113.3", source_port=53_000),
    )

    assert analyze_offline_snapshot(rows) == analyze_offline_snapshot(reversed(rows))


def test_offline_snapshot_empty_summary_and_models_are_immutable() -> None:
    summary = analyze_offline_snapshot(())

    assert isinstance(summary, OfflineSnapshotSummary)
    assert summary.row_count == 0
    assert summary.unique_session_key_count == 0
    assert summary.denied_row_count == 0
    assert summary.protocol_counts == ()
    assert summary.destination_counts == ()
    assert summary.counter_totals.packets_total == 0
    assert summary.counter_totals.bytes_total == 0
    with pytest.raises(FrozenInstanceError):
        summary.row_count = 1  # type: ignore[misc]


def test_offline_snapshot_has_no_live_or_lifecycle_inferences() -> None:
    summary = analyze_offline_snapshot((_record(),))

    assert "203.0.113.20" not in repr(summary)
    for unsupported_name in (
        "observed_at",
        "controller_host",
        "controller_changed",
        "trends",
        "created_count",
        "closed_count",
    ):
        assert not hasattr(summary, unsupported_name)


def test_offline_snapshot_rejects_non_offline_records() -> None:
    with pytest.raises(TypeError, match="OfflineSessionRecord"):
        analyze_offline_snapshot((_record(), object()))  # type: ignore[arg-type]


def test_offline_snapshot_uses_record_session_key_for_unique_flows() -> None:
    first = _record()
    same_flow_different_opaque_fields = replace(
        first,
        counter="9/9/9",
        age=999,
        destination="tunnel",
        packets=999,
        bytes_count=9_999,
        cpu_id=7,
    )

    summary = analyze_offline_snapshot((first, same_flow_different_opaque_fields))

    assert summary.row_count == 2
    assert summary.unique_session_key_count == 1
    assert summary.protocol_counts[0].unique_flow_count == 1
    assert summary.destination_counts[0].unique_flow_count == 1
