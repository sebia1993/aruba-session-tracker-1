"""Parser for filtered IPv4 ``show datapath session table`` output."""

from __future__ import annotations

import re
from ipaddress import IPv4Address

from aruba_session_tracker.models import ErrorCode, SessionObservation

from .common import ParseError, reject_command_errors

_COUNTER_RE = re.compile(r"^\d+(?:/\d+)+$")
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_ENTRY_COUNT_RE = re.compile(
    r"(?im)^[ \t]*(?:Total[ \t]+)?Entries[ \t]*[:=][ \t]*([0-9]+)[ \t]*\r?$"
)
_DATAPATH_TABLE_START_RE = re.compile(
    r"(?im)^[ \t]*Datapath[ \t]+Session[ \t]+Table[ \t]+Entries[ \t]*\r?$"
)
_DATAPATH_HEADER_RE = re.compile(
    r"^[ \t]*Source[ \t]+IP[ \t]+or[ \t]+MAC"
    r"[ \t]+Destination[ \t]+IP[ \t]+Prot[ \t]+SPort[ \t]+DPort"
    r"[ \t]+Cntr[ \t]+Prio[ \t]+ToS[ \t]+Age[ \t]+Destination"
    r"[ \t]+TAge[ \t]+Packets[ \t]+Bytes[ \t]+Flags[ \t]+CPU[ \t]+ID[ \t]*$"
)
_FINAL_PROMPT_RE = re.compile(
    r"^\s*(?:"
    r"(?:\([^\r\n()]{1,64}\)\s*(?:(?:\^\*?|\*)\s*)?)?"
    r"(?:\[[^\r\n\[\]]{1,64}\]\s*)?"
    r"|[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\s*"
    r")[#>]\s*$"
)
_UNSUPPORTED_COLUMNS = ("NhlIdx", "NhIdx", "NhlNhVer")
_MAX_DATAPATH_ROWS = 20_000


def parse_datapath_sessions(
    output: str,
    *,
    controller_name: str,
    controller_host: str,
    max_observations: int | None = None,
) -> tuple[SessionObservation, ...]:
    """Parse standard AOS 8 IPv4 session rows without column guessing."""

    reject_command_errors(output)
    try:
        normalized_controller_host = str(IPv4Address(controller_host))
    except ValueError as exc:
        raise ValueError("controller_host must be an IPv4 address.") from exc
    if not controller_name.strip():
        raise ValueError("controller_name must not be empty.")
    table_start = _DATAPATH_TABLE_START_RE.search(output)
    if table_start is None:
        raise ParseError("Datapath session table is incomplete or unrecognized.")
    effective_observation_limit = _observation_limit(max_observations)
    completion = _completion_boundary(
        output,
        effective_observation_limit,
        table_start=table_start,
    )
    region_end = completion[0] if completion is not None else len(output)
    data_lines = _validated_table_data_lines(output[table_start.end() : region_end])

    observations: list[SessionObservation] = []
    seen_session_keys: set[str] = set()
    for raw_line in data_lines:
        stripped = raw_line.strip()
        if not stripped:
            continue
        fields = stripped.split()
        if not fields:
            continue
        first_is_ipv4 = _is_ipv4(fields[0])
        if not first_is_ipv4:
            if _MAC_RE.fullmatch(fields[0]):
                raise ParseError(
                    "A MAC-address session row cannot be represented as an IPv4 session."
                )
            raise ParseError(
                "Datapath session table contains an unrecognized data line "
                "before its trusted completion marker."
            )
        if len(observations) >= effective_observation_limit:
            raise ParseError(
                "Datapath session observation limit exceeded.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        if len(fields) < 14:
            raise ParseError(f"Truncated datapath row ({len(fields)} fields).")
        if not _is_ipv4(fields[1]):
            raise ParseError("Datapath destination is not an IPv4 address.")
        observation = _parse_row(
            fields,
            raw_line=raw_line.rstrip(),
            controller_name=controller_name.strip(),
            controller_host=normalized_controller_host,
        )
        if observation.session_key in seen_session_keys:
            raise ParseError("Datapath session table contains a duplicate session key.")
        seen_session_keys.add(observation.session_key)
        observations.append(observation)
    if completion is None:
        raise ParseError("Datapath session table has no trusted completion marker.")
    declared_count = completion[1]
    if declared_count is not None and len(observations) != declared_count:
        raise ParseError(
            "Datapath session row count mismatch "
            f"({len(observations)} parsed, {declared_count} declared)."
        )
    return tuple(observations)


def _parse_row(
    fields: list[str],
    *,
    raw_line: str,
    controller_name: str,
    controller_host: str,
) -> SessionObservation:
    cpu_index = len(fields) - 1
    flags_index = cpu_index - 1 if not fields[cpu_index - 1].isdecimal() else None
    bytes_index = cpu_index - 2 if flags_index is not None else cpu_index - 1
    packets_index = bytes_index - 1
    tunnel_age_index = packets_index - 1
    destination_fields = fields[9:tunnel_age_index]
    if not destination_fields:
        raise ParseError("Datapath destination column is missing.")
    flags = fields[flags_index] if flags_index is not None else ""
    cpu_text = fields[cpu_index]
    if flags == "-":
        flags = ""
    if flags and any(character.isspace() for character in flags):
        raise ParseError("Datapath flags are malformed.")
    if not _COUNTER_RE.fullmatch(fields[5]):
        raise ParseError("Datapath counter column is malformed.")
    try:
        protocol = _bounded_decimal(fields[2], "protocol", 0, 255)
        source_port = _bounded_decimal(fields[3], "source port", 0, 65535)
        destination_port = _bounded_decimal(fields[4], "destination port", 0, 65535)
        priority = _bounded_decimal(fields[6], "priority", 0, 2**31 - 1)
        tos = _bounded_decimal(fields[7], "ToS", 0, 255)
        age = _bounded_decimal(fields[8], "age", 0, 2**63 - 1)
        tunnel_age = _mixed_nonnegative_int(fields[tunnel_age_index], "tunnel age")
        packets = _bounded_decimal(fields[packets_index], "packets", 0, 2**63 - 1)
        bytes_count = _bounded_decimal(fields[bytes_index], "bytes", 0, 2**63 - 1)
        cpu_id = _bounded_decimal(cpu_text, "CPU ID", 0, 2**31 - 1)
    except ValueError as exc:
        raise ParseError(str(exc)) from exc
    return SessionObservation(
        controller_name=controller_name,
        controller_host=controller_host,
        protocol=protocol,
        source_ip=str(IPv4Address(fields[0])),
        destination_ip=str(IPv4Address(fields[1])),
        source_port=source_port,
        destination_port=destination_port,
        counter=fields[5],
        priority=priority,
        tos=tos,
        age=age,
        destination=" ".join(destination_fields),
        tunnel_age=tunnel_age,
        packets=packets,
        bytes_count=bytes_count,
        flags=flags,
        cpu_id=cpu_id,
        raw_line=raw_line,
    )


def _validated_table_data_lines(region: str) -> tuple[str, ...]:
    lines = region.splitlines()
    header_indices = tuple(
        index for index, line in enumerate(lines) if _DATAPATH_HEADER_RE.fullmatch(line)
    )
    if len(header_indices) > 1:
        raise ParseError("Datapath session table header is duplicated.")
    if not header_indices:
        header_like_lines = tuple(line for line in lines if _looks_like_datapath_header(line))
        if any(
            unsupported in line
            for line in header_like_lines
            for unsupported in _UNSUPPORTED_COLUMNS
        ):
            raise ParseError("Datapath session table uses an unsupported next-hop column schema.")
        raise ParseError("Datapath session table is missing its required column header.")

    header_index = header_indices[0]
    in_flag_legend = False
    saw_flag_legend = False
    for line in lines[:header_index]:
        if not line.strip():
            in_flag_legend = False
            continue
        if _is_dash_separator(line) and not in_flag_legend:
            continue
        if not saw_flag_legend and _is_flag_legend_line(line, starts_legend=True):
            in_flag_legend = True
            saw_flag_legend = True
            continue
        if in_flag_legend and _is_flag_legend_line(line, starts_legend=False):
            continue
        raise ParseError("Datapath session table contains unrecognized data before its header.")

    separator_index: int | None = None
    for index in range(header_index + 1, len(lines)):
        if not lines[index].strip():
            continue
        if not _is_column_separator(lines[index]):
            raise ParseError("Datapath session table is missing its validated column separator.")
        separator_index = index
        break
    if separator_index is None:
        raise ParseError("Datapath session table is missing its validated column separator.")
    return tuple(lines[separator_index + 1 :])


def _looks_like_datapath_header(line: str) -> bool:
    normalized = " ".join(line.split())
    return normalized.startswith("Source IP or MAC ") and all(
        token in normalized for token in ("Destination IP", "Prot", "SPort", "DPort", "CPU ID")
    )


def _is_flag_legend_line(line: str, *, starts_legend: bool) -> bool:
    if not starts_legend and (not line or line[0] not in " \t"):
        return False
    text = line.strip()
    if starts_legend:
        if not text.startswith("Flags:"):
            return False
        text = text.removeprefix("Flags:").strip()
    elif text.startswith("Flags:"):
        return False
    if not text:
        return False
    for item in text.split(","):
        flag, separator, description = item.partition("-")
        normalized_flag = flag.strip()
        if (
            separator != "-"
            or len(normalized_flag) != 1
            or not normalized_flag.isascii()
            or not normalized_flag.isalpha()
            or not description.strip()
        ):
            return False
    return True


def _is_dash_separator(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and all(character in "- \t" for character in line)


def _is_column_separator(line: str) -> bool:
    groups = line.split()
    return len(groups) == 15 and all(len(group) >= 3 and set(group) == {"-"} for group in groups)


def _observation_limit(max_observations: int | None) -> int:
    if max_observations is None:
        return _MAX_DATAPATH_ROWS
    if type(max_observations) is not int:
        raise TypeError("max_observations must be an integer or None.")
    if max_observations < 0:
        raise ValueError("max_observations must not be negative.")
    return min(max_observations, _MAX_DATAPATH_ROWS)


def _completion_boundary(
    output: str,
    maximum: int,
    *,
    table_start: re.Match[str],
) -> tuple[int, int | None] | None:
    matches = tuple(_ENTRY_COUNT_RE.finditer(output))
    if len(matches) > 1:
        raise ParseError("Datapath session table completion marker is duplicated.")
    if matches:
        marker = matches[0]
        if marker.start() < table_start.end():
            raise ParseError("Datapath completion marker appears before the table rows.")
        before_marker = tuple(
            line.strip()
            for line in output[table_start.end() : marker.start()].splitlines()
            if line.strip()
        )
        if any(_FINAL_PROMPT_RE.fullmatch(line) is not None for line in before_marker):
            raise ParseError(
                "Datapath trusted prompt appears before the row-count completion marker."
            )
        trailing = tuple(
            line.strip() for line in output[marker.end() :].splitlines() if line.strip()
        )
        if trailing and not (
            len(trailing) == 1 and _FINAL_PROMPT_RE.fullmatch(trailing[0]) is not None
        ):
            raise ParseError("Datapath session table contains data after completion.")
        return marker.start(), _bounded_entry_count(marker.group(1), maximum)

    nonempty_lines = _nonempty_line_records(output)
    prompt_positions = tuple(
        index
        for index, (_, line) in enumerate(nonempty_lines)
        if _FINAL_PROMPT_RE.fullmatch(line.strip()) is not None
    )
    if len(prompt_positions) == 1 and prompt_positions[0] == len(nonempty_lines) - 1:
        prompt_start = nonempty_lines[prompt_positions[0]][0]
        if prompt_start >= table_start.end():
            return prompt_start, None
    return None


def _nonempty_line_records(output: str) -> tuple[tuple[int, str], ...]:
    records: list[tuple[int, str]] = []
    offset = 0
    for raw_line in output.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        if line.strip():
            records.append((offset, line))
        offset += len(raw_line)
    return tuple(records)


def _bounded_entry_count(value: str, maximum: int) -> int:
    normalized = value.lstrip("0") or "0"
    maximum_text = str(maximum)
    if len(normalized) > len(maximum_text) or (
        len(normalized) == len(maximum_text) and normalized > maximum_text
    ):
        raise ParseError(
            "Datapath session row count exceeds the supported limit.",
            code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        )
    return int(normalized, 10)


def _is_ipv4(value: str) -> bool:
    try:
        IPv4Address(value)
    except ValueError:
        return False
    return True


def _bounded_decimal(value: str, label: str, minimum: int, maximum: int) -> int:
    if not value.isascii() or not value.isdecimal():
        raise ValueError(f"Datapath {label} is not a decimal integer.")
    parsed = int(value, 10)
    if not minimum <= parsed <= maximum:
        raise ValueError(f"Datapath {label} is outside the supported range.")
    return parsed


def _mixed_nonnegative_int(value: str, label: str) -> int:
    is_hex = value.lower().startswith("0x") or any(char in "abcdefABCDEF" for char in value)
    base = 16 if is_hex else 10
    try:
        parsed = int(value, base)
    except ValueError as exc:
        raise ValueError(f"Datapath {label} is not a valid number.") from exc
    if parsed < 0:
        raise ValueError(f"Datapath {label} must not be negative.")
    return parsed
