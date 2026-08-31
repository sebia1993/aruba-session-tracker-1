from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Any


class ErrorCode(StrEnum):
    AUTH_FAILED = "AUTH_FAILED"
    COMMAND_REJECTED = "COMMAND_REJECTED"
    COMMAND_VARIANT_UNVERIFIED = "COMMAND_VARIANT_UNVERIFIED"
    CLIENT_NOT_FOUND_ON_MM = "CLIENT_NOT_FOUND_ON_MM"
    CURRENT_SWITCH_AMBIGUOUS = "CURRENT_SWITCH_AMBIGUOUS"
    CURRENT_SWITCH_UNMAPPED = "CURRENT_SWITCH_UNMAPPED"
    DB_WRITE_FAILED = "DB_WRITE_FAILED"
    DUPLICATE_FLOW_ACROSS_CONTROLLERS = "DUPLICATE_FLOW_ACROSS_CONTROLLERS"
    EXPORT_FAILED = "EXPORT_FAILED"
    HOST_KEY_CHANGED = "HOST_KEY_CHANGED"
    HOST_KEY_UNKNOWN = "HOST_KEY_UNKNOWN"
    MD_UNREACHABLE = "MD_UNREACHABLE"
    MM_UNREACHABLE = "MM_UNREACHABLE"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    POLL_DEADLINE_EXCEEDED = "POLL_DEADLINE_EXCEEDED"
    PARSE_PARTIAL = "PARSE_PARTIAL"
    PROMPT_PARSE_FAILED = "PROMPT_PARSE_FAILED"
    SESSION_NOT_FOUND = "SESSION_NOT_FOUND"
    STORAGE_LOW_SPACE = "STORAGE_LOW_SPACE"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class DeviceTarget:
    name: str
    host: str
    port: int = 22
    enabled: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not isinstance(self.host, str):
            raise TypeError("장비 이름과 주소는 문자열이어야 합니다.")
        if type(self.port) is not int:  # bool is intentionally rejected.
            raise TypeError("SSH 포트는 정수여야 합니다.")
        if type(self.enabled) is not bool:
            raise TypeError("장비 사용 여부는 boolean이어야 합니다.")
        if not self.name.strip():
            raise ValueError("장비 이름은 비어 있을 수 없습니다.")
        normalized = str(IPv4Address(self.host))
        object.__setattr__(self, "host", normalized)
        if not 1 <= self.port <= 65535:
            raise ValueError("SSH 포트는 1~65535 범위여야 합니다.")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> DeviceTarget:
        return cls(
            name=_strict_string(value["name"], "name"),
            host=_strict_string(value["host"], "host"),
            port=_strict_integer(value.get("port", 22), "port"),
            enabled=_strict_boolean(value.get("enabled", True), "enabled"),
        )

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "host": self.host, "port": self.port, "enabled": self.enabled}


@dataclass(frozen=True, slots=True, repr=False)
class Credentials:
    username: str
    password: str
    enable_secret: str = ""

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) for value in (self.username, self.password, self.enable_secret)
        ):
            raise TypeError("자격증명 값은 문자열이어야 합니다.")
        if not self.username.strip():
            raise ValueError("사용자 이름을 입력하십시오.")
        if not self.password:
            raise ValueError("암호를 입력하십시오.")


@dataclass(frozen=True, slots=True)
class AppConfig:
    mm_primary: DeviceTarget
    mm_standby: DeviceTarget
    managed_devices: tuple[DeviceTarget, ...]
    session_interval_seconds: int = 5
    location_interval_seconds: int = 30
    close_after_misses: int = 3

    def __post_init__(self) -> None:
        for label, value in (
            ("session_interval_seconds", self.session_interval_seconds),
            ("location_interval_seconds", self.location_interval_seconds),
            ("close_after_misses", self.close_after_misses),
        ):
            if type(value) is not int:
                raise TypeError(f"{label}은 정수여야 합니다.")
        if not self.mm_primary.enabled and not self.mm_standby.enabled:
            raise ValueError("활성 MM을 한 대 이상 등록하십시오.")
        enabled = tuple(device for device in self.managed_devices if device.enabled)
        if not enabled:
            raise ValueError("활성 MD를 한 대 이상 등록하십시오.")
        _validate_enabled_topology(self.mm_primary, self.mm_standby, enabled)
        if not 3 <= self.session_interval_seconds <= 300:
            raise ValueError("세션 조회 주기는 3~300초 범위여야 합니다.")
        if not 10 <= self.location_interval_seconds <= 3600:
            raise ValueError("MM 위치 조회 주기는 10~3600초 범위여야 합니다.")
        if not 2 <= self.close_after_misses <= 10:
            raise ValueError("종료 판정 MISS 횟수는 2~10 범위여야 합니다.")

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AppConfig:
        devices_value = value.get("managed_devices")
        if not isinstance(devices_value, list):
            raise ValueError("managed_devices는 배열이어야 합니다.")
        return cls(
            mm_primary=DeviceTarget.from_dict(_dict(value["mm_primary"])),
            mm_standby=DeviceTarget.from_dict(_dict(value["mm_standby"])),
            managed_devices=tuple(DeviceTarget.from_dict(_dict(item)) for item in devices_value),
            session_interval_seconds=_strict_integer(
                value.get("session_interval_seconds", 5),
                "session_interval_seconds",
            ),
            location_interval_seconds=_strict_integer(
                value.get("location_interval_seconds", 30),
                "location_interval_seconds",
            ),
            close_after_misses=_strict_integer(
                value.get("close_after_misses", 3),
                "close_after_misses",
            ),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "mm_primary": self.mm_primary.to_dict(),
            "mm_standby": self.mm_standby.to_dict(),
            "managed_devices": [device.to_dict() for device in self.managed_devices],
            "session_interval_seconds": self.session_interval_seconds,
            "location_interval_seconds": self.location_interval_seconds,
            "close_after_misses": self.close_after_misses,
        }


@dataclass(frozen=True, slots=True)
class QueryRequest:
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    bidirectional: bool = True

    def __post_init__(self) -> None:
        if type(self.bidirectional) is not bool:
            raise TypeError("bidirectional은 boolean이어야 합니다.")
        for label, value in (
            ("출발지 IP", self.source_ip),
            ("목적지 IP", self.destination_ip),
        ):
            if type(value) is not str:
                raise TypeError(f"{label}는 문자열이어야 합니다.")
        source_ip = self.source_ip.strip()
        destination_ip = self.destination_ip.strip()
        if not source_ip and not destination_ip:
            raise ValueError("출발지 IP 또는 목적지 IP 중 하나 이상을 입력하십시오.")
        object.__setattr__(
            self,
            "source_ip",
            str(IPv4Address(source_ip)) if source_ip else "",
        )
        object.__setattr__(
            self,
            "destination_ip",
            str(IPv4Address(destination_ip)) if destination_ip else "",
        )
        for label, port in (("SPort", self.source_port), ("DPort", self.destination_port)):
            if port is not None and type(port) is not int:
                raise TypeError(f"{label}는 정수여야 합니다.")
            if port is not None and not 0 <= port <= 65535:
                raise ValueError(f"{label}는 0~65535 범위여야 합니다.")

    @property
    def client_ips(self) -> tuple[str, ...]:
        """Return the entered client addresses once each, preserving UI order."""

        return tuple(dict.fromkeys(ip for ip in (self.source_ip, self.destination_ip) if ip))

    @property
    def filter_ip(self) -> str:
        """Return a validated address that is always safe for a filtered MD query."""

        return self.client_ips[0]

    def matches(self, observation: SessionObservation) -> bool:
        direct = self._matches_direction(observation, reverse=False)
        return direct or (self.bidirectional and self._matches_direction(observation, reverse=True))

    def _matches_direction(self, observation: SessionObservation, *, reverse: bool) -> bool:
        source_ip = self.destination_ip if reverse else self.source_ip
        destination_ip = self.source_ip if reverse else self.destination_ip
        source_port = self.destination_port if reverse else self.source_port
        destination_port = self.source_port if reverse else self.destination_port
        return (
            (not source_ip or observation.source_ip == source_ip)
            and (not destination_ip or observation.destination_ip == destination_ip)
            and (source_port is None or observation.source_port == source_port)
            and (destination_port is None or observation.destination_port == destination_port)
        )


@dataclass(frozen=True, slots=True)
class ControllerLocation:
    client_ip: str
    current_switch: str
    mm_name: str
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class SessionObservation:
    controller_name: str
    controller_host: str
    protocol: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    counter: str = ""
    priority: int | None = None
    tos: int | None = None
    age: int | None = None
    destination: str = ""
    tunnel_age: int | None = None
    packets: int | None = None
    bytes_count: int | None = None
    flags: str = ""
    cpu_id: int | None = None
    raw_line: str = ""
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        object.__setattr__(self, "controller_host", str(IPv4Address(self.controller_host)))
        object.__setattr__(self, "source_ip", str(IPv4Address(self.source_ip)))
        object.__setattr__(self, "destination_ip", str(IPv4Address(self.destination_ip)))

    @property
    def session_key(self) -> str:
        return "|".join(
            (
                self.controller_host,
                str(self.protocol),
                self.source_ip,
                self.destination_ip,
                str(self.source_port),
                str(self.destination_port),
            )
        )


@dataclass(frozen=True, slots=True)
class DiagnosticEvent:
    stage: str
    code: ErrorCode | None
    message: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    transient: bool = False
    recovered: bool = False


def _dict(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("장비 설정은 객체여야 합니다.")
    return value


def _strict_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label}은 문자열이어야 합니다.")
    return value


def _strict_integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{label}은 정수여야 합니다.")
    return value


def _strict_boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label}은 boolean이어야 합니다.")
    return value


def _validate_enabled_topology(
    mm_primary: DeviceTarget,
    mm_standby: DeviceTarget,
    managed_devices: tuple[DeviceTarget, ...],
) -> None:
    if (
        mm_primary.enabled
        and mm_standby.enabled
        and (mm_primary.host, mm_primary.port) == (mm_standby.host, mm_standby.port)
    ):
        raise ValueError("활성 Primary MM과 Standby MM은 서로 다른 SSH endpoint여야 합니다.")

    hosts: set[str] = set()
    normalized_names: set[str] = set()
    mapping_tokens: set[str] = set()
    for device in managed_devices:
        if device.host in hosts:
            raise ValueError("활성 MD의 주소는 SSH 포트와 관계없이 중복될 수 없습니다.")

        normalized_name = _normalize_switch_token(device.name)
        if normalized_name in normalized_names:
            raise ValueError("활성 MD의 정규화된 이름은 중복될 수 없습니다.")

        device_tokens = {
            token
            for token in (
                normalized_name,
                _normalize_switch_token(device.host),
                _normalize_switch_token(device.name.split(".", 1)[0]),
            )
            if token
        }
        if mapping_tokens.intersection(device_tokens):
            raise ValueError("활성 MD의 Current switch 매핑 토큰은 중복될 수 없습니다.")

        hosts.add(device.host)
        normalized_names.add(normalized_name)
        mapping_tokens.update(device_tokens)


def _normalize_switch_token(value: str) -> str:
    """Match the normalization used by current-switch routing."""

    return value.strip().rstrip(".").casefold()
