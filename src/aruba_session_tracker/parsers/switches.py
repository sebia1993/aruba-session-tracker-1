"""Parser for Mobility Conductor ``show switches`` managed-device rows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import IPv4Address

from .common import ParseError, reject_command_errors

_TOTAL_SWITCHES_RE = re.compile(r"(?im)^\s*Total\s+Switches\s*:\s*(\d+)\s*$")


@dataclass(frozen=True, slots=True)
class ManagedDeviceRow:
    ip_address: str
    name: str
    device_type: str
    status: str = ""
    model: str = ""
    version: str = ""


def parse_show_switches(output: str) -> tuple[ManagedDeviceRow, ...]:
    """Parse and return only MD rows from standard or debug table variants."""

    reject_command_errors(output)
    lines = output.splitlines()
    header_index = _find_switch_header(lines)
    total_match = _TOTAL_SWITCHES_RE.search(output)
    if header_index is None or total_match is None:
        raise ParseError("Switch table is incomplete or unrecognized.")

    header = lines[header_index]
    labels = _ordered_labels(header)
    starts = {label: header.index(label) for label in labels}
    rows: list[ManagedDeviceRow] = []
    parsed_switch_rows = 0
    for line in lines[header_index + 1 :]:
        if "Total Switches" in line:
            break
        if not line.strip() or _is_separator(line):
            continue
        values = _slice_row(line, labels, starts)
        ip_text = values["IP Address"]
        try:
            ip_address = str(IPv4Address(ip_text))
        except ValueError:
            continue
        parsed_switch_rows += 1
        device_type = values["Type"].strip()
        if device_type.upper() != "MD":
            continue
        name = values["Name"].strip()
        if not name:
            raise ParseError("Managed-device row has no name.")
        rows.append(
            ManagedDeviceRow(
                ip_address=ip_address,
                name=name,
                device_type=device_type,
                status=values.get("Status", "").strip(),
                model=values.get("Model", "").strip(),
                version=values.get("Version", "").strip(),
            )
        )
    declared_total = int(total_match.group(1))
    if parsed_switch_rows != declared_total:
        raise ParseError(
            "Switch table row count mismatch "
            f"({parsed_switch_rows} parsed, {declared_total} declared)."
        )
    return tuple(rows)


def _find_switch_header(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if "IP Address" in line and "Name" in line and "Type" in line:
            return index
    return None


def _ordered_labels(header: str) -> list[str]:
    candidates = (
        "IP Address",
        "MAC",
        "IPv6 Address",
        "Name",
        "Location",
        "Nodepath",
        "Type",
        "Model",
        "Version",
        "Status",
        "Configuration State",
        "Config Sync Time (sec)",
        "Config ID",
    )
    present = [(header.index(label), label) for label in candidates if label in header]
    labels = [label for _, label in sorted(present)]
    for required in ("IP Address", "Name", "Type"):
        if required not in labels:
            raise ParseError(f"Switch table is missing the {required!r} column.")
    return labels


def _slice_row(line: str, labels: list[str], starts: dict[str, int]) -> dict[str, str]:
    values: dict[str, str] = {}
    for index, label in enumerate(labels):
        start = starts[label]
        end = starts[labels[index + 1]] if index + 1 < len(labels) else len(line)
        values[label] = line[start:end].strip()
    return values


def _is_separator(line: str) -> bool:
    compact = line.replace(" ", "").replace("\t", "")
    return bool(compact) and set(compact) == {"-"}
