"""Parser for filtered ``show global-user-table list ip`` output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address

from .common import ParseError, reject_command_errors


class GlobalUserStatus(StrEnum):
    NOT_FOUND = "NOT_FOUND"
    FOUND = "FOUND"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class GlobalUserLookup:
    client_ip: str
    current_switches: tuple[str, ...]
    status: GlobalUserStatus
    row_count: int

    @property
    def current_switch(self) -> str | None:
        return self.current_switches[0] if self.status is GlobalUserStatus.FOUND else None


_TOTAL_RE = re.compile(r"(?im)^\s*Total\s+entries\s*=\s*(\d+)\s*$")
_HEADER_REQUIRED = ("IP", "MAC", "Name", "Current switch", "Role")


def parse_global_user_table(output: str, *, client_ip: str) -> GlobalUserLookup:
    """Return zero, one, or multiple unique Current switch values.

    The parser uses the table's fixed-width header geometry so blank user-name
    fields do not shift the Current switch column.  A declared row count that
    cannot be accounted for is treated as truncation rather than as NOT_FOUND.
    """

    reject_command_errors(output)
    normalized_client = str(IPv4Address(client_ip))
    lines = output.splitlines()
    header_index = _find_header(lines)
    total_match = _TOTAL_RE.search(output)
    if header_index is None or total_match is None:
        raise ParseError("Global user table is incomplete or unrecognized.")

    declared_total = int(total_match.group(1))
    starts = _header_starts(lines[header_index])
    ip_start = starts["IP"]
    current_start = starts["Current switch"]
    role_start = starts["Role"]

    parsed_rows = 0
    switches: list[str] = []
    for line in lines[header_index + 1 :]:
        if _TOTAL_RE.match(line):
            break
        if not line.strip() or _is_separator(line):
            continue
        ip_text = line[ip_start : starts["MAC"]].strip()
        try:
            row_ip = str(IPv4Address(ip_text))
        except ValueError:
            continue
        parsed_rows += 1
        if row_ip != normalized_client:
            continue
        switch_text = line[current_start:role_start].strip()
        try:
            normalized_switch = str(IPv4Address(switch_text))
        except ValueError as exc:
            raise ParseError("Current switch is missing or is not an IPv4 address.") from exc
        if normalized_switch not in switches:
            switches.append(normalized_switch)

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
    )


def _find_header(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if all(label in line for label in _HEADER_REQUIRED):
            return index
    return None


def _header_starts(header: str) -> dict[str, int]:
    starts: dict[str, int] = {}
    previous = -1
    for label in _HEADER_REQUIRED:
        start = header.find(label, previous + 1)
        if start < 0:
            raise ParseError(f"Global user table is missing the {label!r} column.")
        starts[label] = start
        previous = start
    return starts


def _is_separator(line: str) -> bool:
    compact = line.replace(" ", "").replace("\t", "")
    return bool(compact) and set(compact) == {"-"}
