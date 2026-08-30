"""Explicit, non-guessing interpretation of the Aruba ToS value."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class TosEncoding(StrEnum):
    """The meaning explicitly assigned to the stored ToS integer."""

    RAW = "RAW"
    IP_DS_FIELD = "IP_DS_FIELD"
    DSCP_CODEPOINT = "DSCP_CODEPOINT"


_DSCP_NAMES = {
    0: "CS0",
    8: "CS1",
    10: "AF11",
    12: "AF12",
    14: "AF13",
    16: "CS2",
    18: "AF21",
    20: "AF22",
    22: "AF23",
    24: "CS3",
    26: "AF31",
    28: "AF32",
    30: "AF33",
    32: "CS4",
    34: "AF41",
    36: "AF42",
    38: "AF43",
    40: "CS5",
    44: "VOICE-ADMIT",
    46: "EF",
    48: "CS6",
    56: "CS7",
}

DSCP_NAMES = MappingProxyType(_DSCP_NAMES)

_ECN_NAMES = {
    0: "Not-ECT",
    1: "ECT(1)",
    2: "ECT(0)",
    3: "CE",
}

ECN_NAMES = MappingProxyType(_ECN_NAMES)


@dataclass(frozen=True, slots=True)
class TosInterpretation:
    """A raw value plus only the fields justified by the selected encoding."""

    raw_value: int
    encoding: TosEncoding
    dscp_value: int | None = None
    dscp_label: str | None = None
    ecn_value: int | None = None
    ecn_label: str | None = None


def interpret_tos(
    value: int | None,
    *,
    encoding: TosEncoding = TosEncoding.RAW,
) -> TosInterpretation | None:
    """Interpret ``value`` only according to an explicit encoding.

    The default deliberately returns the raw ToS value with no DSCP claim.
    ``IP_DS_FIELD`` treats the integer as the full eight-bit DS field, while
    ``DSCP_CODEPOINT`` treats it as an already-decoded six-bit codepoint.
    """

    if not isinstance(encoding, TosEncoding):
        raise TypeError("encoding must be a TosEncoding value.")
    if value is None:
        return None
    if type(value) is not int:
        raise TypeError("ToS must be an integer or None.")

    if encoding is TosEncoding.DSCP_CODEPOINT:
        if not 0 <= value <= 63:
            raise ValueError("A DSCP codepoint must be in the 0..63 range.")
        return TosInterpretation(
            raw_value=value,
            encoding=encoding,
            dscp_value=value,
            dscp_label=_dscp_label(value),
        )

    if not 0 <= value <= 255:
        raise ValueError("A raw ToS or IP DS field must be in the 0..255 range.")
    if encoding is TosEncoding.RAW:
        return TosInterpretation(raw_value=value, encoding=encoding)

    dscp_value = value >> 2
    ecn_value = value & 0b11
    return TosInterpretation(
        raw_value=value,
        encoding=encoding,
        dscp_value=dscp_value,
        dscp_label=_dscp_label(dscp_value),
        ecn_value=ecn_value,
        ecn_label=ECN_NAMES[ecn_value],
    )


def _dscp_label(value: int) -> str:
    return DSCP_NAMES.get(value, f"DSCP {value}")
