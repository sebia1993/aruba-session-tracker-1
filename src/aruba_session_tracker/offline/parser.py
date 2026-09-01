"""Strict, local-only Aruba tech-support command block parsing.

This module intentionally does not read files, call the network, write output,
or turn offline rows into live ``SessionObservation`` objects. It accepts only
an exact, fixed-width schema and fails closed when the required block is
ambiguous or incomplete.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from ipaddress import IPv4Address

from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.parsers.common import ParseError, reject_command_errors

from .models import (
    OfflineCommandBlock,
    OfflineEnrichment,
    OfflineEnrichmentStatus,
    OfflineParseLimits,
    OfflineSessionRecord,
    OfflineStationRecord,
    OfflineTechSupportResult,
    OfflineUserRecord,
)

DATAPATH_INTERNAL_COMMAND = "show datapath session internal"
USER_TABLE_VERBOSE_COMMAND = "show user-table verbose"
STATION_TABLE_COMMAND = "show station-table"

_SUPPORTED_COMMANDS = frozenset(
    (DATAPATH_INTERNAL_COMMAND, USER_TABLE_VERBOSE_COMMAND, STATION_TABLE_COMMAND)
)
_COMMAND_WITH_PROMPT_RE = re.compile(
    r"^(?:"
    r"(?:\([^()\r\n]{1,64}\)\s*(?:(?:\^\*?|\*)\s*)?)?"
    r"(?:\[[^\[\]\r\n]{1,64}\]\s*)?"
    r"|[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\s*"
    r")[#>]\s*"
    r"(show [A-Za-z0-9][A-Za-z0-9 _./:|,?=-]{0,240})$",
    re.IGNORECASE,
)
_BARE_COMMAND_RE = re.compile(
    r"^(show [A-Za-z0-9][A-Za-z0-9 _./:|,?=-]{0,240})$",
    re.IGNORECASE,
)
_DASH_RUN_RE = re.compile(r"-+")
_LINE_BREAK_RE = re.compile(r"\r\n|\r|\n")
_UNSUPPORTED_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_COUNT_RE = re.compile(r"^(?:Total\s+)?Entries\s*[:=]\s*([0-9]+)\s*$", re.IGNORECASE)
_USER_COUNT_RE = re.compile(
    r"^User Entries\s*:\s*([0-9]+)(?:/[0-9]+)?\s*$",
    re.IGNORECASE,
)
_STATION_COUNT_RE = re.compile(r"^Station Entries\s*:\s*([0-9]+)\s*$", re.IGNORECASE)
_FINAL_PROMPT_RE = re.compile(
    r"^(?:"
    r"(?:\([^()\r\n]{1,64}\)\s*(?:(?:\^\*?|\*)\s*)?)?"
    r"(?:\[[^\[\]\r\n]{1,64}\]\s*)?"
    r"|[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\s*"
    r")[#>]\s*$"
)
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SAFE_FIELD_RE = re.compile(r"^[^<>\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*$")
_UNSPECIFIED_IPV4 = str(IPv4Address(0))

_INTERNAL_HEADERS = (
    "Source IP or MAC",
    "Destination IP",
    "Prot",
    "SPort",
    "DPort",
    "Cntr",
    "Prio",
    "ToS",
    "Age",
    "Destination",
    "TAge",
    "Packets",
    "Bytes",
    "SIDX",
    "SRTI",
    "SRCI",
    "SRTRCV",
    "MI_TUN",
    "SRTMIV",
    "UsrIdx",
    "UsrVer",
    "AclVer",
    "NhlIdx",
    "NhIdx",
    "NhlNhVer",
    "Int-Flag",
    "Sess-Flag2",
    "PktsDpi",
    "UplinkVlan",
    "AppID",
    "WebCCRep",
    "WebCCID",
    "Threat",
    "Country",
    "Flags",
    "DpiTIdx",
    "WebCCURL",
    "CPU ID",
)


def extract_exact_command_block(
    text: str,
    command: str,
    *,
    limits: OfflineParseLimits | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> OfflineCommandBlock:
    """Extract exactly one supported echoed command and its output lines."""

    _validate_cancellation_callback(is_cancelled)
    selected_limits = limits or OfflineParseLimits()
    lines = _validated_lines(text, selected_limits, is_cancelled=is_cancelled)
    if command not in _SUPPORTED_COMMANDS:
        raise ValueError("Unsupported offline command.")
    block = _find_exact_command_block(lines, command, is_cancelled=is_cancelled)
    if block is None:
        raise ParseError("Required offline command block was not found.")
    return block


def parse_offline_tech_support(
    text: str,
    *,
    limits: OfflineParseLimits | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> OfflineTechSupportResult:
    """Parse the required session block and safe optional enrichment records."""

    _validate_cancellation_callback(is_cancelled)
    selected_limits = limits or OfflineParseLimits()
    lines = _validated_lines(text, selected_limits, is_cancelled=is_cancelled)
    datapath_block = _find_exact_command_block(
        lines,
        DATAPATH_INTERNAL_COMMAND,
        is_cancelled=is_cancelled,
    )
    if datapath_block is None:
        raise ParseError("Required offline command block was not found.")
    sessions = _parse_internal_block(
        datapath_block,
        selected_limits,
        is_cancelled=is_cancelled,
    )

    user_records: tuple[OfflineUserRecord, ...] = ()
    user_status = OfflineEnrichmentStatus.NOT_PRESENT
    try:
        user_block = _find_exact_command_block(
            lines,
            USER_TABLE_VERBOSE_COMMAND,
            is_cancelled=is_cancelled,
        )
        if user_block is not None:
            user_records = _parse_user_enrichment(
                user_block,
                selected_limits,
                is_cancelled=is_cancelled,
            )
            user_status = OfflineEnrichmentStatus.VALIDATED
    except ParseError as exc:
        if exc.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED:
            raise
        user_status = OfflineEnrichmentStatus.UNAVAILABLE

    station_records: tuple[OfflineStationRecord, ...] = ()
    station_status = OfflineEnrichmentStatus.NOT_PRESENT
    try:
        station_block = _find_exact_command_block(
            lines,
            STATION_TABLE_COMMAND,
            is_cancelled=is_cancelled,
        )
        if station_block is not None:
            station_records = _parse_station_enrichment(
                station_block,
                selected_limits,
                is_cancelled=is_cancelled,
            )
            station_status = OfflineEnrichmentStatus.VALIDATED
    except ParseError as exc:
        if exc.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED:
            raise
        station_status = OfflineEnrichmentStatus.UNAVAILABLE

    return OfflineTechSupportResult(
        sessions=sessions,
        enrichment=OfflineEnrichment(
            user_ips=frozenset(
                record.ip_address
                for record in user_records
                if record.ip_address != _UNSPECIFIED_IPV4
            ),
            user_macs=frozenset(record.mac_address for record in user_records),
            station_macs=frozenset(record.mac_address for record in station_records),
            user_records=user_records,
            station_records=station_records,
            user_table_status=user_status,
            station_table_status=station_status,
        ),
    )


def _validated_lines(
    text: str,
    limits: OfflineParseLimits,
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[str, ...]:
    _raise_if_cancelled(is_cancelled)
    if not isinstance(text, str):
        raise TypeError("Offline input must be text.")
    if len(text) > limits.max_text_bytes:
        raise ParseError(
            "Offline input exceeds the configured size limit.",
            code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
    byte_count = _utf8_length(text)
    _raise_if_cancelled(is_cancelled)
    if byte_count is None:
        raise ParseError("Offline input contains unsupported text encoding.")
    if byte_count > limits.max_text_bytes:
        raise ParseError(
            "Offline input exceeds the configured size limit.",
            code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
    line_count = text.count("\n") + text.count("\r") - text.count("\r\n") + 1
    if line_count > limits.max_lines:
        raise ParseError(
            "Offline input exceeds the configured line limit.",
            code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
    if _UNSUPPORTED_CONTROL_RE.search(text) is not None:
        raise ParseError("Offline input contains unsupported control characters.")
    _raise_if_cancelled(is_cancelled)
    lines = tuple(_LINE_BREAK_RE.split(text))
    for index, line in enumerate(lines):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        if len(line) > limits.max_line_characters:
            raise ParseError(
                "Offline input contains an overlong line.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
    _raise_if_cancelled(is_cancelled)
    return lines


def _find_exact_command_block(
    lines: Sequence[str],
    command: str,
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> OfflineCommandBlock | None:
    target_indexes: list[int] = []
    for index, line in enumerate(lines):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        if (_echoed_show_command(line) or "").casefold() == command.casefold():
            target_indexes.append(index)
    if not target_indexes:
        return None
    if len(target_indexes) != 1:
        raise ParseError("Required offline command block is duplicated.")
    start = target_indexes[0]
    end = len(lines)
    terminated = False
    for index in range(start + 1, len(lines)):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        if _echoed_show_command(lines[index]) is not None:
            end = index
            terminated = True
            break
    return OfflineCommandBlock(
        command=command,
        lines=tuple(lines[start + 1 : end]),
        terminated_by_command=terminated,
    )


def _echoed_show_command(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or len(stripped) > 256 or not stripped.isascii():
        return None
    match = _BARE_COMMAND_RE.fullmatch(stripped) or _COMMAND_WITH_PROMPT_RE.fullmatch(stripped)
    return match.group(1) if match is not None else None


def _parse_internal_block(
    block: OfflineCommandBlock,
    limits: OfflineParseLimits,
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[OfflineSessionRecord, ...]:
    output = "\n".join(block.lines)
    reject_command_errors(output)
    layout = _find_exact_layout(
        block.lines,
        _INTERNAL_HEADERS,
        is_cancelled=is_cancelled,
    )
    if layout is None:
        raise ParseError("Offline datapath header is missing, incomplete, or unsupported.")
    _, separator_index, columns = layout

    rows: list[OfflineSessionRecord] = []
    declared_count: int | None = None
    completed_by_prompt = False
    for index, line in enumerate(block.lines[separator_index + 1 :]):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        stripped = line.strip()
        if not stripped:
            continue
        if declared_count is not None:
            if _COUNT_RE.fullmatch(stripped) is not None:
                raise ParseError("Offline datapath completion marker is duplicated.")
            if not completed_by_prompt and _FINAL_PROMPT_RE.fullmatch(stripped) is not None:
                completed_by_prompt = True
                continue
            raise ParseError("Offline datapath block contains data after completion.")
        if completed_by_prompt:
            raise ParseError("Offline datapath block contains data after completion.")
        count_match = _COUNT_RE.fullmatch(stripped)
        if count_match is not None:
            declared_count = _bounded_count(count_match.group(1), limits.max_sessions)
            continue
        if _FINAL_PROMPT_RE.fullmatch(stripped) is not None:
            completed_by_prompt = True
            continue
        if set(stripped) == {"-"}:
            continue
        if len(rows) >= limits.max_sessions:
            raise ParseError(
                "Offline datapath session limit exceeded.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        rows.append(_parse_internal_row(line, columns))

    if declared_count is not None and declared_count != len(rows):
        raise ParseError("Offline datapath row count does not match its completion marker.")
    if declared_count is None and not completed_by_prompt:
        raise ParseError("Offline datapath block has no trusted completion marker.")
    return tuple(rows)


def _parse_internal_row(line: str, columns: tuple[tuple[int, int], ...]) -> OfflineSessionRecord:
    fields = _fixed_fields(line, columns)
    if not all(_SAFE_FIELD_RE.fullmatch(field) is not None for field in fields):
        raise ParseError("Offline datapath row contains unsupported text.")
    if _MAC_RE.fullmatch(fields[0]) is not None:
        raise ParseError("Offline datapath row uses an unsupported endpoint type.")
    source_ip = _normalized_ipv4(fields[0])
    destination_ip = _normalized_ipv4(fields[1])
    if source_ip is None or destination_ip is None:
        raise ParseError("Offline datapath row is malformed.")
    numeric_values = _parse_numeric_fields(fields)
    if numeric_values is None:
        raise ParseError("Offline datapath row is malformed.")
    (
        protocol,
        source_port,
        destination_port,
        priority,
        tos,
        age,
        tunnel_age,
        packets,
        bytes_count,
        cpu_id,
    ) = numeric_values
    if not re.fullmatch(r"[0-9]+(?:/[0-9]+)+", fields[5]):
        raise ParseError("Offline datapath row is malformed.")
    if not fields[9]:
        raise ParseError("Offline datapath row is malformed.")
    return OfflineSessionRecord(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        counter=fields[5],
        priority=priority,
        tos=tos,
        age=age,
        destination=fields[9],
        tunnel_age=tunnel_age,
        packets=packets,
        bytes_count=bytes_count,
        session_index=fields[13],
        source_route_table_index=fields[14],
        source_class_index=fields[15],
        source_route_receive=fields[16],
        mobility_tunnel=fields[17],
        source_route_mobility_version=fields[18],
        user_index=fields[19],
        user_version=fields[20],
        acl_version=fields[21],
        next_hop_list_index=fields[22],
        next_hop_index=fields[23],
        next_hop_list_next_hop_version=fields[24],
        internal_flag=fields[25],
        session_flag2=fields[26],
        dpi_packets=fields[27],
        uplink_vlan=fields[28],
        application_id=fields[29],
        webcc_reputation=fields[30],
        webcc_id=fields[31],
        threat=fields[32],
        country=fields[33],
        flags=fields[34],
        dpi_table_index=fields[35],
        webcc_url=fields[36],
        cpu_id=cpu_id,
    )


def _parse_user_enrichment(
    block: OfflineCommandBlock,
    limits: OfflineParseLimits,
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[OfflineUserRecord, ...]:
    reject_command_errors("\n".join(block.lines))
    layout = _find_prefix_layout(
        block.lines,
        ("IP", "MAC", "Name", "Role"),
        is_cancelled=is_cancelled,
    )
    if layout is None:
        raise ParseError("Optional user enrichment table is unavailable.")
    _, separator_index, columns = layout
    records: list[OfflineUserRecord] = []
    declared_count: int | None = None
    for index, line in enumerate(block.lines[separator_index + 1 :]):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        stripped = line.strip()
        if not stripped:
            continue
        count_match = _USER_COUNT_RE.fullmatch(stripped)
        if count_match is not None:
            if declared_count is not None:
                raise ParseError("Optional user enrichment table is unavailable.")
            declared_count = _bounded_count(
                count_match.group(1),
                limits.max_enrichment_records,
            )
            continue
        if declared_count is not None:
            raise ParseError("Optional user enrichment table is unavailable.")
        if len(records) >= limits.max_enrichment_records:
            raise ParseError(
                "Offline enrichment record limit exceeded.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        fields = _fixed_fields(line, columns)
        if not all(_SAFE_FIELD_RE.fullmatch(field) is not None for field in fields):
            raise ParseError("Optional user enrichment table is unavailable.")
        ip_address = _normalized_ipv4(fields[0])
        if ip_address is None:
            raise ParseError("Optional user enrichment table is unavailable.")
        mac = fields[1].lower()
        if _MAC_RE.fullmatch(mac) is None:
            raise ParseError("Optional user enrichment table is unavailable.")
        records.append(
            OfflineUserRecord(
                ip_address=ip_address,
                mac_address=mac,
                name=fields[2],
                role=fields[3],
            )
        )
    if declared_count is not None and declared_count != len(records):
        raise ParseError("Optional user enrichment table is unavailable.")
    if declared_count is None and not block.terminated_by_command:
        raise ParseError("Optional user enrichment table is unavailable.")
    return tuple(records)


def _parse_station_enrichment(
    block: OfflineCommandBlock,
    limits: OfflineParseLimits,
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[OfflineStationRecord, ...]:
    reject_command_errors("\n".join(block.lines))
    layout = _find_prefix_layout(
        block.lines,
        ("MAC", "Name", "Role"),
        is_cancelled=is_cancelled,
    )
    if layout is None:
        raise ParseError("Optional station enrichment table is unavailable.")
    _, separator_index, columns = layout
    records: list[OfflineStationRecord] = []
    declared_count: int | None = None
    for index, line in enumerate(block.lines[separator_index + 1 :]):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        stripped = line.strip()
        if not stripped:
            continue
        count_match = _STATION_COUNT_RE.fullmatch(stripped)
        if count_match is not None:
            if declared_count is not None:
                raise ParseError("Optional station enrichment table is unavailable.")
            declared_count = _bounded_count(
                count_match.group(1),
                limits.max_enrichment_records,
            )
            continue
        if declared_count is not None:
            raise ParseError("Optional station enrichment table is unavailable.")
        if len(records) >= limits.max_enrichment_records:
            raise ParseError(
                "Offline enrichment record limit exceeded.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        fields = _fixed_fields(line, columns)
        if not all(_SAFE_FIELD_RE.fullmatch(field) is not None for field in fields):
            raise ParseError("Optional station enrichment table is unavailable.")
        mac = fields[0].lower()
        if _MAC_RE.fullmatch(mac) is None:
            raise ParseError("Optional station enrichment table is unavailable.")
        records.append(
            OfflineStationRecord(
                mac_address=mac,
                name=fields[1],
                role=fields[2],
            )
        )
    if declared_count is not None and declared_count != len(records):
        raise ParseError("Optional station enrichment table is unavailable.")
    if declared_count is None and not block.terminated_by_command:
        raise ParseError("Optional station enrichment table is unavailable.")
    return tuple(records)


def _find_exact_layout(
    lines: Sequence[str],
    expected_headers: tuple[str, ...],
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[int, int, tuple[tuple[int, int], ...]] | None:
    matches: list[tuple[int, int, tuple[tuple[int, int], ...]]] = []
    for index in range(len(lines) - 1):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        columns = _separator_columns(lines[index + 1])
        if columns is None or len(columns) != len(expected_headers):
            continue
        headers = tuple(_slice_column(lines[index], column) for column in columns)
        if headers == expected_headers:
            matches.append((index, index + 1, columns))
    if len(matches) != 1:
        return None
    return matches[0]


def _find_prefix_layout(
    lines: Sequence[str],
    expected_prefix: tuple[str, ...],
    *,
    is_cancelled: Callable[[], bool] | None = None,
) -> tuple[int, int, tuple[tuple[int, int], ...]] | None:
    matches: list[tuple[int, int, tuple[tuple[int, int], ...]]] = []
    for index in range(len(lines) - 1):
        if index % 256 == 0:
            _raise_if_cancelled(is_cancelled)
        columns = _separator_columns(lines[index + 1])
        if columns is None or len(columns) < len(expected_prefix):
            continue
        headers = tuple(_slice_column(lines[index], column) for column in columns)
        if headers[: len(expected_prefix)] == expected_prefix:
            matches.append((index, index + 1, columns))
    if len(matches) != 1:
        return None
    return matches[0]


def _separator_columns(line: str) -> tuple[tuple[int, int], ...] | None:
    if not line or re.fullmatch(r"[ -]+", line) is None:
        return None
    runs = tuple((match.start(), match.end()) for match in _DASH_RUN_RE.finditer(line))
    if not runs or any(end - start < 3 for start, end in runs):
        return None
    return runs


def _fixed_fields(line: str, columns: tuple[tuple[int, int], ...]) -> tuple[str, ...]:
    if not columns:
        return ()
    last_start, last_end = columns[-1]
    if len(line) <= last_start:
        raise ParseError("Offline fixed-width row is incomplete.")
    if len(line) > last_end and line[last_end:].strip():
        raise ParseError("Offline fixed-width row exceeds its validated schema.")
    return tuple(_slice_column(line, column) for column in columns)


def _slice_column(line: str, column: tuple[int, int]) -> str:
    start, end = column
    return line[start:end].strip()


def _decimal(value: str, minimum: int, maximum: int) -> int:
    if not value.isascii() or not value.isdecimal():
        raise ValueError("invalid decimal")
    parsed = int(value, 10)
    if not minimum <= parsed <= maximum:
        raise ValueError("decimal out of range")
    return parsed


def _hexadecimal(value: str) -> int:
    digits = value[2:] if value.lower().startswith("0x") else value
    if not digits or not digits.isascii() or re.fullmatch(r"[0-9A-Fa-f]+", digits) is None:
        raise ValueError("invalid hexadecimal")
    parsed = int(digits, 16)
    if not 0 <= parsed <= 2**64 - 1:
        raise ValueError("hexadecimal out of range")
    return parsed


def _parse_numeric_fields(
    fields: tuple[str, ...],
) -> tuple[int, int, int, int, int, int, int, int, int, int] | None:
    try:
        return (
            _decimal(fields[2], 0, 255),
            _decimal(fields[3], 0, 65535),
            _decimal(fields[4], 0, 65535),
            _decimal(fields[6], 0, 2**31 - 1),
            _decimal(fields[7], 0, 255),
            _decimal(fields[8], 0, 2**63 - 1),
            _hexadecimal(fields[10]),
            _hexadecimal(fields[11]),
            _hexadecimal(fields[12]),
            _decimal(fields[37], 0, 2**31 - 1),
        )
    except ValueError:
        return None


def _bounded_count(value: str, maximum: int) -> int:
    """Parse an ASCII count without constructing an attacker-sized integer."""

    normalized = value.lstrip("0") or "0"
    maximum_text = str(maximum)
    if len(normalized) > len(maximum_text) or (
        len(normalized) == len(maximum_text) and normalized > maximum_text
    ):
        raise ParseError(
            "Offline row count exceeds the configured limit.",
            code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
    return int(normalized, 10)


def _utf8_length(value: str) -> int | None:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _normalized_ipv4(value: str) -> str | None:
    try:
        return str(IPv4Address(value))
    except ValueError:
        return None


def _raise_if_cancelled(is_cancelled: Callable[[], bool] | None) -> None:
    if is_cancelled is not None and is_cancelled():
        raise ParseError("Offline analysis was cancelled.", code=ErrorCode.CANCELLED)


def _validate_cancellation_callback(is_cancelled: Callable[[], bool] | None) -> None:
    if is_cancelled is not None and not callable(is_cancelled):
        raise TypeError("is_cancelled must be callable.")
