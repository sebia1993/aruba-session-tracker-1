"""Immutable records produced by the offline tech-support parser."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


@dataclass(frozen=True, slots=True)
class OfflineParseLimits:
    """Hard resource bounds for one in-memory offline parse."""

    max_text_bytes: int = 32 * 1024 * 1024
    max_lines: int = 250_000
    max_line_characters: int = 64 * 1024
    max_sessions: int = 20_000
    max_enrichment_records: int = 50_000

    def __post_init__(self) -> None:
        for name, value in (
            ("max_text_bytes", self.max_text_bytes),
            ("max_lines", self.max_lines),
            ("max_line_characters", self.max_line_characters),
            ("max_sessions", self.max_sessions),
            ("max_enrichment_records", self.max_enrichment_records),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer.")
            if value < 1:
                raise ValueError(f"{name} must be positive.")


@dataclass(frozen=True, slots=True, repr=False)
class OfflineCommandBlock:
    """One unambiguous command block held only in process memory."""

    command: str
    lines: tuple[str, ...]
    terminated_by_command: bool


@dataclass(frozen=True, slots=True, repr=False)
class OfflineSessionRecord:
    """One validated IPv4 row from ``show datapath session internal``.

    Internal datapath counters are hexadecimal in this command. The numeric
    fields below contain their decoded values while the less stable diagnostic
    columns remain opaque, bounded strings. No controller address is fabricated.
    """

    source_ip: str
    destination_ip: str
    protocol: int
    source_port: int
    destination_port: int
    counter: str
    priority: int
    tos: int
    age: int
    destination: str
    tunnel_age: int
    packets: int
    bytes_count: int
    session_index: str
    source_route_table_index: str
    source_class_index: str
    source_route_receive: str
    mobility_tunnel: str
    source_route_mobility_version: str
    user_index: str
    user_version: str
    acl_version: str
    next_hop_list_index: str
    next_hop_index: str
    next_hop_list_next_hop_version: str
    internal_flag: str
    session_flag2: str
    dpi_packets: str
    uplink_vlan: str
    application_id: str
    webcc_reputation: str
    webcc_id: str
    threat: str
    country: str
    flags: str
    dpi_table_index: str
    webcc_url: str
    cpu_id: int

    @property
    def session_key(self) -> str:
        """Return an offline-only key that deliberately has no controller part."""

        return "|".join(
            (
                str(self.protocol),
                self.source_ip,
                self.destination_ip,
                str(self.source_port),
                str(self.destination_port),
            )
        )


class OfflineEnrichmentStatus(StrEnum):
    """Whether an optional label source was safely usable."""

    NOT_PRESENT = "NOT_PRESENT"
    VALIDATED = "VALIDATED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True, slots=True, repr=False)
class OfflineUserRecord:
    """One validated user-table row kept only for local correlation.

    Every field can contain network or operator data, so the generated repr is
    disabled for the complete record rather than relying on callers to redact
    individual values.
    """

    ip_address: str
    mac_address: str
    name: str
    role: str


@dataclass(frozen=True, slots=True, repr=False)
class OfflineStationRecord:
    """One validated station-table row kept only for local correlation."""

    mac_address: str
    name: str
    role: str


@dataclass(frozen=True, slots=True, repr=False)
class OfflineEnrichment:
    """Validated relationship records plus backward-compatible membership."""

    user_ips: frozenset[str] = frozenset()
    user_macs: frozenset[str] = frozenset()
    station_macs: frozenset[str] = frozenset()
    user_table_status: OfflineEnrichmentStatus = OfflineEnrichmentStatus.NOT_PRESENT
    station_table_status: OfflineEnrichmentStatus = OfflineEnrichmentStatus.NOT_PRESENT
    user_records: tuple[OfflineUserRecord, ...] = ()
    station_records: tuple[OfflineStationRecord, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class OfflineTechSupportResult:
    """Complete immutable result of one local-only text parse."""

    sessions: tuple[OfflineSessionRecord, ...]
    enrichment: OfflineEnrichment
