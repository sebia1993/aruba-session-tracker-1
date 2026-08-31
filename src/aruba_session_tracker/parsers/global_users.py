"""Parser for filtered ``show global-user-table list ip`` output."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from ipaddress import IPv4Address

from aruba_session_tracker.models import ErrorCode

from .common import ParseError, reject_command_errors


class GlobalUserStatus(StrEnum):
    NOT_FOUND = "NOT_FOUND"
    FOUND = "FOUND"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class GlobalUserEntry:
    """Sanitized-in-repr context from one matching global-user row.

    These values are useful to later, local-only analysis, but they can contain
    operator or network data.  Keeping every field out of the generated repr
    prevents an exception or debug representation from copying those values
    into a diagnostic log by accident.
    """

    client_ip: str = field(repr=False)
    mac_address: str = field(repr=False)
    user_name: str = field(repr=False)
    current_switch: str = field(repr=False)
    role: str = field(repr=False)
    auth_method: str = field(repr=False)
    ap_name: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class GlobalUserLookup:
    client_ip: str
    current_switches: tuple[str, ...]
    status: GlobalUserStatus
    row_count: int
    entries: tuple[GlobalUserEntry, ...] = field(default=(), repr=False)

    @property
    def current_switch(self) -> str | None:
        return self.current_switches[0] if self.status is GlobalUserStatus.FOUND else None


_TOTAL_RE = re.compile(r"(?im)^\s*Total\s+entries\s*=\s*([0-9]+)\s*$")
_MAX_GLOBAL_USER_ROWS = 20_000
_HEADER_REQUIRED = ("IP", "MAC", "Name", "Current switch", "Role")
_HEADER_OPTIONAL = ("Auth", "AP name")
_HEADER_AFTER_AP = ("Roaming", "Essid", "Bssid", "Phy", "Profile", "Type", "User Type")
_AP_END = "__AP_END__"
_MAX_COLUMN_SPANS = len(_HEADER_REQUIRED) + len(_HEADER_OPTIONAL) + len(_HEADER_AFTER_AP)
_COLUMN_SEPARATOR_RE = re.compile(r"-+")
_HEADER_CONTINUATION_RE = re.compile(
    r"\s*Roaming\s+Essid\s+Bssid\s+Phy\s+Profile\s+Type\s+User\s+Type\s*\Z"
)
_MAC_RE = re.compile(
    r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|"
    r"(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}"
)


def parse_global_user_table(output: str, *, client_ip: str) -> GlobalUserLookup:
    """Return zero, one, or multiple unique Current switch values.

    The parser uses the table's fixed-width separator geometry so centered
    header labels and blank user-name fields do not shift the Current switch
    column.  A declared row count that cannot be accounted for is treated as
    truncation rather than as NOT_FOUND.
    """

    reject_command_errors(output)
    normalized_client = str(IPv4Address(client_ip))
    lines = output.splitlines()
    header_index = _find_header(lines)
    total_match = _TOTAL_RE.search(output)
    if header_index is None or total_match is None:
        raise ParseError("Global user table is incomplete or unrecognized.")

    declared_total = _bounded_total(total_match.group(1))
    separator_index, starts = _table_geometry(lines, header_index)

    parsed_rows = 0
    switches: list[str] = []
    entries: list[GlobalUserEntry] = []
    for line in lines[separator_index + 1 :]:
        if _TOTAL_RE.match(line):
            break
        if not line.strip() or _is_separator(line):
            continue
        entry = _parse_entry(line, starts)
        parsed_rows += 1
        if entry.client_ip != normalized_client:
            continue
        entries.append(entry)
        if entry.current_switch not in switches:
            switches.append(entry.current_switch)

    if parsed_rows != declared_total:
        raise ParseError(
            "Global user table row count mismatch "
            f"({parsed_rows} parsed, {declared_total} declared)."
        )
    status = (
        GlobalUserStatus.NOT_FOUND
        if not switches
        else GlobalUserStatus.FOUND
        if len(switches) == 1
        else GlobalUserStatus.AMBIGUOUS
    )
    return GlobalUserLookup(
        client_ip=normalized_client,
        current_switches=tuple(switches),
        status=status,
        row_count=parsed_rows,
        entries=tuple(entries),
    )


def _find_header(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if all(label in line for label in _HEADER_REQUIRED):
            return index
    return None


def _table_geometry(lines: list[str], header_index: int) -> tuple[int, dict[str, int]]:
    header = lines[header_index]
    continuation_allowed = not any(label in header for label in _HEADER_AFTER_AP)
    saw_continuation = False
    for index in range(header_index + 1, len(lines)):
        line = lines[index]
        if _TOTAL_RE.match(line):
            break
        if not line.strip():
            continue
        spans = _separator_spans(line)
        if spans:
            return index, _header_starts(header, spans)
        if continuation_allowed and not saw_continuation and _is_known_header_continuation(line):
            saw_continuation = True
            continue
        raise ParseError("Global user table has an unrecognized header continuation.")
    raise ParseError("Global user table is missing validated column separators.")


def _header_starts(header: str, spans: tuple[tuple[int, int], ...]) -> dict[str, int]:
    if len(spans) == 1:
        return _legacy_header_starts(header, spans[0])

    starts: dict[str, int] = {}
    previous = -1
    optional_presence = {label: label in header for label in _HEADER_OPTIONAL}
    if len(set(optional_presence.values())) != 1:
        raise ParseError("Global user table has incomplete optional column geometry.")
    labels = (*_HEADER_REQUIRED, *(_HEADER_OPTIONAL if all(optional_presence.values()) else ()))
    if len(spans) < len(labels):
        raise ParseError("Global user table has incomplete column separator geometry.")

    for index, label in enumerate(labels):
        start = header.find(label, previous + 1)
        if start < 0:
            if label in _HEADER_OPTIONAL:
                raise ParseError("Global user table has conflicting optional column geometry.")
            raise ParseError(f"Global user table is missing the {label!r} column.")
        column_start = spans[index][0]
        column_end = spans[index][1]
        if start < column_start or start + len(label) > column_end:
            if label in _HEADER_OPTIONAL:
                raise ParseError("Global user table has conflicting optional column geometry.")
            raise ParseError("Global user table has conflicting column geometry.")
        starts[label] = column_start
        previous = start

    if "AP name" in starts and len(spans) > len(labels):
        starts[_AP_END] = spans[len(labels)][0]
    return starts


def _legacy_header_starts(header: str, span: tuple[int, int]) -> dict[str, int]:
    """Keep the old continuous-rule format only when its header is left aligned."""

    if span[0] != 0 or span[1] < len(header.rstrip()) or not header.startswith("IP"):
        raise ParseError("Global user table has unverified continuous separator geometry.")

    starts: dict[str, int] = {}
    previous = -1
    previous_label: str | None = None
    optional_presence = {label: label in header for label in _HEADER_OPTIONAL}
    if len(set(optional_presence.values())) != 1:
        raise ParseError("Global user table has incomplete optional column geometry.")
    labels = (*_HEADER_REQUIRED, *(_HEADER_OPTIONAL if all(optional_presence.values()) else ()))
    for label in labels:
        start = header.find(label, previous + 1)
        if start < 0:
            if label in _HEADER_OPTIONAL:
                raise ParseError("Global user table has conflicting optional column geometry.")
            raise ParseError(f"Global user table is missing the {label!r} column.")
        if previous_label is not None and start <= previous + len(previous_label):
            raise ParseError("Global user table has overlapping column geometry.")
        starts[label] = start
        previous = start
        previous_label = label

    if "AP name" in starts:
        trailing_starts = tuple(
            start for label in _HEADER_AFTER_AP if (start := header.find(label, previous + 1)) >= 0
        )
        if trailing_starts:
            starts[_AP_END] = min(trailing_starts)
    return starts


def _separator_spans(line: str) -> tuple[tuple[int, int], ...]:
    if not _is_separator(line):
        return ()
    spans: list[tuple[int, int]] = []
    for match in _COLUMN_SEPARATOR_RE.finditer(line):
        if len(spans) >= _MAX_COLUMN_SPANS:
            raise ParseError("Global user table has too many column separators.")
        spans.append((match.start(), match.end()))
    return tuple(spans)


def _is_known_header_continuation(line: str) -> bool:
    return _HEADER_CONTINUATION_RE.fullmatch(line) is not None


def _parse_entry(line: str, starts: dict[str, int]) -> GlobalUserEntry:
    ip_text = _column_text(line, starts, "IP", "MAC")
    mac_text = _column_text(line, starts, "MAC", "Name")
    user_name = _column_text(line, starts, "Name", "Current switch")
    switch_text = _column_text(line, starts, "Current switch", "Role")
    role = _column_text(line, starts, "Role", "Auth" if "Auth" in starts else None)
    auth_method = _column_text(line, starts, "Auth", "AP name") if "Auth" in starts else ""
    ap_name = (
        _column_text(line, starts, "AP name", _AP_END if _AP_END in starts else None)
        if "AP name" in starts
        else ""
    )

    normalized_ip = _normalized_ipv4(ip_text)
    if normalized_ip is None:
        raise ParseError("Global user row IP is missing or is not an IPv4 address.")
    if not _MAC_RE.fullmatch(mac_text):
        raise ParseError("Global user row MAC is missing or malformed.")
    normalized_switch = _normalized_ipv4(switch_text)
    if normalized_switch is None:
        raise ParseError("Current switch is missing or is not an IPv4 address.")

    return GlobalUserEntry(
        client_ip=normalized_ip,
        mac_address=mac_text.replace("-", ":").lower(),
        user_name=user_name,
        current_switch=normalized_switch,
        role=role,
        auth_method=auth_method,
        ap_name=ap_name,
    )


def _column_text(
    line: str,
    starts: dict[str, int],
    label: str,
    next_label: str | None,
) -> str:
    start = starts[label]
    end = starts[next_label] if next_label is not None else len(line)
    return line[start:end].strip()


def _normalized_ipv4(value: str) -> str | None:
    try:
        return str(IPv4Address(value))
    except ValueError:
        return None


def _bounded_total(value: str) -> int:
    normalized = value.lstrip("0") or "0"
    maximum_text = str(_MAX_GLOBAL_USER_ROWS)
    if len(normalized) > len(maximum_text) or (
        len(normalized) == len(maximum_text) and normalized > maximum_text
    ):
        raise ParseError(
            "Global user table exceeds the supported row limit.",
            code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
    return int(normalized, 10)


def _is_separator(line: str) -> bool:
    has_dash = False
    for character in line:
        if character == "-":
            has_dash = True
        elif character not in " \t":
            return False
    return has_dash
