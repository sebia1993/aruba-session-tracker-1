from __future__ import annotations

import pytest

from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    QueryRequest,
    SessionObservation,
)


def _observation(**overrides: object) -> SessionObservation:
    values: dict[str, object] = {
        "controller_name": "MD-01",
        "controller_host": "198.51.100.21",
        "protocol": 6,
        "source_ip": "192.0.2.101",
        "destination_ip": "203.0.113.50",
        "source_port": 50000,
        "destination_port": 443,
    }
    values.update(overrides)
    return SessionObservation(**values)  # type: ignore[arg-type]


def test_query_requires_ipv4_and_valid_ports() -> None:
    request = QueryRequest("192.0.2.101", "203.0.113.50", 0, 65535)
    assert request.source_ip == "192.0.2.101"
    with pytest.raises(ValueError):
        QueryRequest("2001:db8::1", "203.0.113.50")
    with pytest.raises(ValueError):
        QueryRequest("192.0.2.1", "203.0.113.50", 65536)
    with pytest.raises(TypeError):
        QueryRequest("192.0.2.1", "203.0.113.50", True)


def test_bidirectional_matching_swaps_ports_together() -> None:
    request = QueryRequest("192.0.2.101", "203.0.113.50", 50000, 443, True)
    assert request.matches(_observation())
    assert request.matches(
        _observation(
            source_ip="203.0.113.50",
            destination_ip="192.0.2.101",
            source_port=443,
            destination_port=50000,
        )
    )
    assert not request.matches(
        _observation(
            source_ip="203.0.113.50",
            destination_ip="192.0.2.101",
            source_port=50000,
            destination_port=443,
        )
    )


def test_credentials_repr_never_exposes_secret() -> None:
    credentials = Credentials("operator", "super-secret", "enable-secret")
    rendered = repr(credentials)
    assert "super-secret" not in rendered
    assert "enable-secret" not in rendered


def test_config_round_trip_and_bounds() -> None:
    config = AppConfig(
        mm_primary=DeviceTarget("MM-1", "192.0.2.10"),
        mm_standby=DeviceTarget("MM-2", "192.0.2.11"),
        managed_devices=(DeviceTarget("MD-1", "198.51.100.21"),),
    )
    assert AppConfig.from_dict(config.to_dict()) == config
    with pytest.raises(ValueError):
        AppConfig(
            mm_primary=config.mm_primary,
            mm_standby=config.mm_standby,
            managed_devices=config.managed_devices,
            session_interval_seconds=1,
        )
    with pytest.raises(TypeError):
        DeviceTarget("MD", "198.51.100.21", port=True)


def test_session_key_excludes_flags() -> None:
    first = _observation(flags="FC")
    second = _observation(flags="D")
    assert first.session_key == second.session_key
