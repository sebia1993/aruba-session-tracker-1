from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest

from aruba_session_tracker.analysis import (
    TosEncoding,
    analyze_observations,
    interpret_tos,
    protocol_label,
    service_definition,
    service_label,
)
from aruba_session_tracker.models import SessionObservation


def _observation(**overrides: object) -> SessionObservation:
    values: dict[str, object] = {
        "controller_name": "MD-01",
        "controller_host": "198.51.100.21",
        "protocol": 6,
        "source_ip": "192.0.2.101",
        "destination_ip": "203.0.113.50",
        "source_port": 50000,
        "destination_port": 443,
        "packets": 10,
        "bytes_count": 1_000,
        "flags": "FC",
        "observed_at": datetime(2026, 8, 29, 10, 0, tzinfo=UTC),
    }
    values.update(overrides)
    return SessionObservation(**values)  # type: ignore[arg-type]


def test_protocol_labels_are_static_and_keep_unknown_numbers() -> None:
    assert protocol_label(1) == "ICMP (1)"
    assert protocol_label(6) == "TCP (6)"
    assert protocol_label(17) == "UDP (17)"
    assert protocol_label(253) == "Protocol 253"
    with pytest.raises(TypeError):
        protocol_label(True)
    with pytest.raises(ValueError):
        protocol_label(256)


def test_service_lookup_is_protocol_aware_and_never_guesses() -> None:
    assert service_label(6, 443) == "HTTPS (443)"
    assert service_label(17, 53) == "DNS (53)"
    assert service_definition(17, 22) is None
    assert service_label(17, 22) == "22"
    assert service_label(1, 443) == "443"
    with pytest.raises(TypeError):
        service_label(6, False)
    with pytest.raises(ValueError):
        service_label(17, 65_536)


def test_raw_tos_does_not_claim_dscp_without_explicit_encoding() -> None:
    raw = interpret_tos(46)
    assert raw is not None
    assert raw.encoding is TosEncoding.RAW
    assert raw.raw_value == 46
    assert raw.dscp_value is None
    assert raw.dscp_label is None
    assert raw.ecn_value is None
    assert raw.ecn_label is None

    ds_field = interpret_tos(46, encoding=TosEncoding.IP_DS_FIELD)
    assert ds_field is not None
    assert ds_field.dscp_value == 11
    assert ds_field.dscp_label == "DSCP 11"
    assert ds_field.ecn_value == 2
    assert ds_field.ecn_label == "ECT(0)"

    codepoint = interpret_tos(46, encoding=TosEncoding.DSCP_CODEPOINT)
    assert codepoint is not None
    assert codepoint.dscp_value == 46
    assert codepoint.dscp_label == "EF"
    assert codepoint.ecn_value is None
    assert interpret_tos(None) is None


def test_tos_modes_have_strict_ranges_and_types() -> None:
    with pytest.raises(ValueError):
        interpret_tos(256)
    with pytest.raises(ValueError):
        interpret_tos(64, encoding=TosEncoding.DSCP_CODEPOINT)
    with pytest.raises(TypeError):
        interpret_tos(True)
    with pytest.raises(TypeError):
        interpret_tos(0, encoding="RAW")  # type: ignore[arg-type]


def test_analysis_aggregates_counts_current_totals_and_first_last_deltas() -> None:
    start = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)
    rows = (
        _observation(observed_at=start, packets=100, bytes_count=10_000),
        _observation(
            controller_name="MD-02",
            controller_host="198.51.100.22",
            observed_at=start + timedelta(seconds=10),
            packets=160,
            bytes_count=14_000,
            flags="D",
        ),
        _observation(
            protocol=17,
            source_port=53000,
            destination_ip="203.0.113.10",
            destination_port=53,
            observed_at=start + timedelta(seconds=5),
            packets=20,
            bytes_count=None,
            flags="D",
        ),
        _observation(
            protocol=17,
            source_port=53001,
            destination_ip="203.0.113.10",
            destination_port=53,
            observed_at=start + timedelta(seconds=8),
            packets=None,
            bytes_count=500,
        ),
    )

    summary = analyze_observations(row for row in rows)

    assert summary.observation_count == 4
    assert summary.stored_session_count == 4
    assert summary.logical_flow_count == 3
    assert summary.denied_observation_count == 2
    assert summary.denied_stored_session_count == 2
    assert summary.denied_flow_count == 2
    assert [
        (
            item.label,
            item.observation_count,
            item.stored_session_count,
            item.logical_flow_count,
        )
        for item in summary.protocol_counts
    ] == [
        ("TCP (6)", 2, 2, 1),
        ("UDP (17)", 2, 2, 2),
    ]
    assert [
        (
            item.destination_ip,
            item.observation_count,
            item.stored_session_count,
            item.logical_flow_count,
        )
        for item in summary.destination_counts
    ] == [
        ("203.0.113.10", 2, 2, 2),
        ("203.0.113.50", 2, 2, 1),
    ]
    assert summary.current_totals.packets_total == 180
    assert summary.current_totals.bytes_total == 14_500
    assert summary.current_totals.packets_value_count == 2
    assert summary.current_totals.bytes_value_count == 2
    assert summary.current_totals.packets_missing_count == 1
    assert summary.current_totals.bytes_missing_count == 1

    tcp = next(item for item in summary.flow_trends if item.flow.protocol == 6)
    assert tcp.observation_count == 2
    assert tcp.first_controller_name == "MD-01"
    assert tcp.last_controller_name == "MD-02"
    assert tcp.controller_changed
    assert tcp.packets.first_value == 100
    assert tcp.packets.last_value == 160
    assert tcp.packets.delta == 60
    assert tcp.bytes_count.delta == 4_000
    assert tcp.denied_observation_count == 1
    assert tcp.was_denied


def test_analysis_retains_negative_deltas_without_inferring_a_cause() -> None:
    start = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)
    summary = analyze_observations(
        (
            _observation(observed_at=start, packets=100, bytes_count=5_000),
            _observation(observed_at=start + timedelta(seconds=5), packets=20, bytes_count=2_000),
        )
    )
    trend = summary.flow_trends[0]
    assert trend.packets.delta == -80
    assert trend.bytes_count.delta == -3_000


def test_analysis_uses_edge_values_and_handles_empty_input() -> None:
    start = datetime(2026, 8, 29, 10, 0, tzinfo=UTC)
    summary = analyze_observations(
        (
            _observation(observed_at=start, packets=None, bytes_count=10),
            _observation(observed_at=start + timedelta(seconds=1), packets=20, bytes_count=None),
        )
    )
    trend = summary.flow_trends[0]
    assert trend.packets.first_value is None
    assert trend.packets.last_value == 20
    assert trend.packets.delta is None
    assert trend.bytes_count.first_value == 10
    assert trend.bytes_count.last_value is None
    assert trend.bytes_count.delta is None

    empty = analyze_observations(())
    assert empty.observation_count == 0
    assert empty.stored_session_count == 0
    assert empty.logical_flow_count == 0
    assert empty.protocol_counts == ()
    assert empty.destination_counts == ()
    assert empty.flow_trends == ()
    assert empty.current_totals.packets_total == 0
    assert empty.current_totals.bytes_total == 0


def test_analysis_models_are_immutable_and_reject_non_observations() -> None:
    observation = _observation()
    summary = analyze_observations((observation,))
    assert summary.flow_trends[0].flow.key == observation.session_key.split("|", 1)[1]
    with pytest.raises(FrozenInstanceError):
        summary.observation_count = 99  # type: ignore[misc]
    with pytest.raises(TypeError):
        analyze_observations((_observation(), object()))  # type: ignore[arg-type]
