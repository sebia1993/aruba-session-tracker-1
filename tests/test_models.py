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


def test_query_accepts_either_ip_but_rejects_an_empty_filter() -> None:
    source_only = QueryRequest(" 192.0.2.101 ", "")
    destination_only = QueryRequest("", " 203.0.113.50 ")

    assert source_only.source_ip == "192.0.2.101"
    assert source_only.destination_ip == ""
    assert source_only.client_ips == ("192.0.2.101",)
    assert source_only.filter_ip == "192.0.2.101"
    assert destination_only.source_ip == ""
    assert destination_only.destination_ip == "203.0.113.50"
    assert destination_only.client_ips == ("203.0.113.50",)
    assert destination_only.filter_ip == "203.0.113.50"

    with pytest.raises(TypeError, match="출발지 IP"):
        QueryRequest(None, "203.0.113.50")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="목적지 IP"):
        QueryRequest("192.0.2.101", None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="하나 이상"):
        QueryRequest(" ", "")


def test_single_ip_matching_respects_direction_and_swapped_ports() -> None:
    source_only = QueryRequest("192.0.2.101", "", 50000, 443, True)
    destination_only = QueryRequest("", "203.0.113.50", 50000, 443, True)

    assert source_only.matches(_observation())
    assert source_only.matches(
        _observation(
            source_ip="203.0.113.50",
            destination_ip="192.0.2.101",
            source_port=443,
            destination_port=50000,
        )
    )
    assert not source_only.matches(_observation(destination_port=8443))
    assert destination_only.matches(_observation())
    assert destination_only.matches(
        _observation(
            source_ip="203.0.113.50",
            destination_ip="192.0.2.101",
            source_port=443,
            destination_port=50000,
        )
    )
    assert not destination_only.matches(_observation(destination_ip="198.51.100.5"))

    one_way = QueryRequest("192.0.2.101", "", bidirectional=False)
    assert one_way.matches(_observation())
    assert not one_way.matches(
        _observation(
            source_ip="203.0.113.50",
            destination_ip="192.0.2.101",
        )
    )


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


def test_config_rejects_enabled_mm_with_the_same_ssh_endpoint() -> None:
    with pytest.raises(ValueError, match="서로 다른 SSH endpoint"):
        AppConfig(
            mm_primary=DeviceTarget("MM-1", "192.0.2.10", port=22),
            mm_standby=DeviceTarget("MM-2", "192.0.2.10", port=22),
            managed_devices=(DeviceTarget("MD-1", "198.51.100.21"),),
        )


def test_config_allows_enabled_mm_on_the_same_host_with_distinct_ports() -> None:
    config = AppConfig(
        mm_primary=DeviceTarget("MM-1", "192.0.2.10", port=22),
        mm_standby=DeviceTarget("MM-2", "192.0.2.10", port=2222),
        managed_devices=(DeviceTarget("MD-1", "198.51.100.21"),),
    )

    assert config.mm_primary.host == config.mm_standby.host


@pytest.mark.parametrize("disabled_role", ["primary", "standby"])
def test_config_ignores_disabled_mm_endpoint_collision(disabled_role: str) -> None:
    primary_enabled = disabled_role != "primary"
    standby_enabled = disabled_role != "standby"

    config = AppConfig(
        mm_primary=DeviceTarget("MM-1", "192.0.2.10", enabled=primary_enabled),
        mm_standby=DeviceTarget("MM-2", "192.0.2.10", enabled=standby_enabled),
        managed_devices=(DeviceTarget("MD-1", "198.51.100.21"),),
    )

    assert config.mm_primary.enabled is primary_enabled
    assert config.mm_standby.enabled is standby_enabled
    assert AppConfig.from_dict(config.to_dict()) == config


def test_config_rejects_enabled_md_host_collision_even_when_ports_differ() -> None:
    with pytest.raises(ValueError, match="SSH 포트와 관계없이 중복"):
        AppConfig(
            mm_primary=DeviceTarget("MM-1", "192.0.2.10"),
            mm_standby=DeviceTarget("MM-2", "192.0.2.11"),
            managed_devices=(
                DeviceTarget("MD-1", "198.51.100.21", port=22),
                DeviceTarget("MD-2", "198.51.100.21", port=2222),
            ),
        )


def test_config_rejects_enabled_md_normalized_name_collision() -> None:
    with pytest.raises(ValueError, match="정규화된 이름은 중복"):
        AppConfig(
            mm_primary=DeviceTarget("MM-1", "192.0.2.10"),
            mm_standby=DeviceTarget("MM-2", "192.0.2.11"),
            managed_devices=(
                DeviceTarget(" MD-1. ", "198.51.100.21"),
                DeviceTarget("md-1", "198.51.100.22"),
            ),
        )


@pytest.mark.parametrize(
    "managed_devices",
    [
        (
            DeviceTarget("md-1.example.test", "198.51.100.21"),
            DeviceTarget("MD-1.other.test", "198.51.100.22"),
        ),
        (
            DeviceTarget("MD-1", "198.51.100.21"),
            DeviceTarget("md-1.example.test", "198.51.100.22"),
        ),
        (
            DeviceTarget("198.51.100.22", "198.51.100.21"),
            DeviceTarget("MD-2", "198.51.100.22"),
        ),
    ],
    ids=("short-name", "full-name-to-short-name", "name-to-host"),
)
def test_config_rejects_other_enabled_md_mapping_token_collisions(
    managed_devices: tuple[DeviceTarget, ...],
) -> None:
    with pytest.raises(ValueError, match="Current switch 매핑 토큰은 중복"):
        AppConfig(
            mm_primary=DeviceTarget("MM-1", "192.0.2.10"),
            mm_standby=DeviceTarget("MM-2", "192.0.2.11"),
            managed_devices=managed_devices,
        )


def test_config_ignores_disabled_md_mapping_collisions() -> None:
    config = AppConfig(
        mm_primary=DeviceTarget("MM-1", "192.0.2.10"),
        mm_standby=DeviceTarget("MM-2", "192.0.2.11"),
        managed_devices=(
            DeviceTarget("MD-1.example.test", "198.51.100.21"),
            DeviceTarget("md-1.other.test", "198.51.100.21", port=2222, enabled=False),
            DeviceTarget("198.51.100.21", "198.51.100.22", enabled=False),
        ),
    )

    assert tuple(device.name for device in config.managed_devices if device.enabled) == (
        "MD-1.example.test",
    )
    assert AppConfig.from_dict(config.to_dict()) == config


def test_session_key_excludes_flags() -> None:
    first = _observation(flags="FC")
    second = _observation(flags="D")
    assert first.session_key == second.session_key
