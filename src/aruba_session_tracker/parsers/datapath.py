"""Parser for filtered IPv4 ``show datapath session table`` output."""

from __future__ import annotations

import re
from ipaddress import IPv4Address

from aruba_session_tracker.models import ErrorCode, SessionObservation

from .common import ParseError, reject_command_errors

_COUNTER_RE = re.compile(r"^\d+(?:/\d+)+$")
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_ENTRY_COUNT_RE = re.compile(r"(?im)^\s*(?:Total\s+)?Entries\s*[:=]\s*(\d+)\s*$")
_FINAL_PROMPT_RE = re.compile(
    r"^\s*(?:"
    r"(?:\([^\r\n()]{1,64}\)\s*(?:(?:\^\*?|\*)\s*)?)?"
    r"(?:\[[^\r\n\[\]]{1,64}\]\s*)?"
    r"|[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\s*"
    r")[#>]\s*$"
)
_UNSUPPORTED_COLUMNS = ("NhlIdx", "NhIdx", "NhlNhVer")


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
    header = _datapath_header(output)
    if header is None:
        raise ParseError("Datapath session table is incomplete or unrecognized.")
    if any(column in header for column in _UNSUPPORTED_COLUMNS):
        raise ParseError("Datapath session table uses an unsupported next-hop column schema.")

    observations: list[SessionObservation] = []
    seen_session_keys: set[str] = set()
    for raw_line in output.splitlines():
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
            continue
        if len(fields) < 14:
            raise ParseError(f"Truncated datapath row ({len(fields)} fields).")
        if not _is_ipv4(fields[1]):
            raise ParseError("Datapath destination is not an IPv4 address.")
        if max_observations is not None and len(observations) >= max_observations:
            raise ParseError(
                "Datapath session observation limit exceeded.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
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
    count_match = _ENTRY_COUNT_RE.search(output)
    if count_match is not None and len(observations) != int(count_match.group(1)):
        raise ParseError(
            "Datapath session row count mismatch "
            f"({len(observations)} parsed, {count_match.group(1)} declared)."
        )
    if count_match is None and not _has_final_prompt(output):
        raise ParseError("Datapath session table has no trusted completion marker.")
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


def _datapath_header(output: str) -> str | None:
    normalized = " ".join(output.split())
    if (
        "Datapath Session Table Entries" in normalized
        and "Source IP" in normalized
        and "Destination IP" in normalized
        and "Prot SPort DPort" in normalized
        and "Packets" in normalized
        and "Bytes" in normalized
        and "CPU ID" in normalized
    ):
        return normalized
    return None


def _has_final_prompt(output: str) -> bool:
    lines = [line for line in output.splitlines() if line.strip()]
    return bool(lines) and _FINAL_PROMPT_RE.fullmatch(lines[-1]) is not None


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
