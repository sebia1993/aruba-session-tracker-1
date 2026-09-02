"""Short, stable codes for sanitized operator-to-support handoff.

The registry in this module is intentionally explicit and append-only.  A
published code must never be reassigned to a different failure.  Unknown or
future inputs fall back to ``AS00`` without incorporating runtime values.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from aruba_session_tracker.models import ErrorCode

type DiagnosticKey = tuple[str, str]


class SupportCode(StrEnum):
    """Four-character codes that are safe to type outside the network."""

    AS00 = "AS00"

    AS01 = "AS01"
    AS02 = "AS02"
    AS03 = "AS03"
    AS04 = "AS04"
    AS05 = "AS05"
    AS06 = "AS06"
    AS07 = "AS07"
    AS08 = "AS08"
    AS09 = "AS09"
    AS10 = "AS10"
    AS11 = "AS11"
    AS12 = "AS12"
    AS13 = "AS13"
    AS14 = "AS14"
    AS15 = "AS15"
    AS16 = "AS16"
    AS17 = "AS17"

    AS20 = "AS20"
    AS21 = "AS21"
    AS22 = "AS22"
    AS23 = "AS23"
    AS24 = "AS24"
    AS25 = "AS25"
    AS26 = "AS26"
    AS27 = "AS27"
    AS28 = "AS28"
    AS29 = "AS29"
    AS30 = "AS30"
    AS31 = "AS31"
    AS32 = "AS32"
    AS33 = "AS33"
    AS34 = "AS34"
    AS35 = "AS35"
    AS36 = "AS36"
    AS37 = "AS37"
    AS38 = "AS38"
    AS39 = "AS39"
    AS40 = "AS40"
    AS41 = "AS41"

    AS60 = "AS60"
    AS61 = "AS61"

    AS70 = "AS70"
    AS71 = "AS71"
    AS72 = "AS72"
    AS73 = "AS73"
    AS74 = "AS74"
    AS75 = "AS75"
    AS76 = "AS76"
    AS77 = "AS77"
    AS78 = "AS78"
    AS79 = "AS79"
    AS80 = "AS80"
    AS81 = "AS81"
    AS82 = "AS82"
    AS83 = "AS83"
    AS84 = "AS84"
    AS85 = "AS85"
    AS86 = "AS86"
    AS87 = "AS87"
    AS88 = "AS88"
    AS89 = "AS89"


class UiFailureKey(StrEnum):
    """Stable keys for failures that do not originate as diagnostic events."""

    QUERY_AUTH_FAILED = "QUERY_AUTH_FAILED"
    QUERY_DB_WRITE_FAILED = "QUERY_DB_WRITE_FAILED"
    QUERY_STORAGE_LOW_SPACE = "QUERY_STORAGE_LOW_SPACE"
    QUERY_UNEXPECTED = "QUERY_UNEXPECTED"
    HISTORY_READ_FAILED = "HISTORY_READ_FAILED"
    EXPORT_CSV_FAILED = "EXPORT_CSV_FAILED"
    EXPORT_HTML_FAILED = "EXPORT_HTML_FAILED"
    DELETE_PREVIEW_FAILED = "DELETE_PREVIEW_FAILED"
    DELETE_COMMIT_FAILED = "DELETE_COMMIT_FAILED"
    DELETE_DISCARD_FAILED = "DELETE_DISCARD_FAILED"
    STARTUP_FAILED = "STARTUP_FAILED"
    MAIN_THREAD_FAILED = "MAIN_THREAD_FAILED"
    SHUTDOWN_INCOMPLETE = "SHUTDOWN_INCOMPLETE"
    WORKER_THREAD_FAILED = "WORKER_THREAD_FAILED"
    RUNTIME_CLEANUP_FAILED = "RUNTIME_CLEANUP_FAILED"
    CONFIG_READ_FAILED = "CONFIG_READ_FAILED"
    CONFIG_SAVE_FAILED = "CONFIG_SAVE_FAILED"
    QUERY_STORAGE_PATH_FAILED = "QUERY_STORAGE_PATH_FAILED"
    QUERY_STORAGE_BUSY = "QUERY_STORAGE_BUSY"
    QUERY_OUTPUT_LIMIT_EXCEEDED = "QUERY_OUTPUT_LIMIT_EXCEEDED"
    QUERY_PERSISTENCE_INDETERMINATE = "QUERY_PERSISTENCE_INDETERMINATE"


# AS01-AS19: MM.  Keep the tuples and their assigned values unchanged; append
# only when a new production stage/code pair is introduced.
_DIAGNOSTIC_SUPPORT_CODES: dict[DiagnosticKey, SupportCode] = {
    ("MM_LOGIN", ErrorCode.AUTH_FAILED.value): SupportCode.AS01,
    ("MM_QUERY", ErrorCode.AUTH_FAILED.value): SupportCode.AS01,
    ("MM_QUERY", ErrorCode.MM_UNREACHABLE.value): SupportCode.AS02,
    ("MM_QUERY", ErrorCode.HOST_KEY_UNKNOWN.value): SupportCode.AS03,
    ("MM_QUERY", ErrorCode.HOST_KEY_CHANGED.value): SupportCode.AS04,
    ("MM_QUERY", ErrorCode.POLL_DEADLINE_EXCEEDED.value): SupportCode.AS05,
    ("MM_QUERY", ErrorCode.CANCELLED.value): SupportCode.AS06,
    ("MM_QUERY", ErrorCode.PROMPT_PARSE_FAILED.value): SupportCode.AS07,
    ("MM_QUERY", ErrorCode.COMMAND_REJECTED.value): SupportCode.AS08,
    ("MM_QUERY", ErrorCode.COMMAND_VARIANT_UNVERIFIED.value): SupportCode.AS09,
    ("MM_QUERY", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS10,
    ("MM_COLLECT", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS11,
    ("MM_PARSE", ErrorCode.PARSE_PARTIAL.value): SupportCode.AS12,
    ("MM_PARSE", ErrorCode.COMMAND_VARIANT_UNVERIFIED.value): SupportCode.AS13,
    ("MM_PARSE", ErrorCode.COMMAND_REJECTED.value): SupportCode.AS14,
    ("MM_PARSE", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS15,
    ("MM_PARSE", ErrorCode.CURRENT_SWITCH_AMBIGUOUS.value): SupportCode.AS16,
    ("MM_ENABLE", ErrorCode.AUTH_FAILED.value): SupportCode.AS17,
    # AS20-AS59: MD.  MD_QUERY/AUTH_FAILED is the pre-v0.5.9 spelling of
    # MD_LOGIN/AUTH_FAILED and deliberately remains an AS20 alias.
    ("MD_LOGIN", ErrorCode.AUTH_FAILED.value): SupportCode.AS20,
    ("MD_QUERY", ErrorCode.AUTH_FAILED.value): SupportCode.AS20,
    ("MD_ENABLE", ErrorCode.AUTH_FAILED.value): SupportCode.AS21,
    ("MD_QUERY", ErrorCode.MD_UNREACHABLE.value): SupportCode.AS22,
    ("MD_QUERY", ErrorCode.HOST_KEY_UNKNOWN.value): SupportCode.AS23,
    ("MD_QUERY", ErrorCode.HOST_KEY_CHANGED.value): SupportCode.AS24,
    ("MD_QUERY", ErrorCode.POLL_DEADLINE_EXCEEDED.value): SupportCode.AS25,
    ("MD_QUERY", ErrorCode.CANCELLED.value): SupportCode.AS26,
    ("MD_QUERY", ErrorCode.PROMPT_PARSE_FAILED.value): SupportCode.AS27,
    ("MD_QUERY", ErrorCode.COMMAND_REJECTED.value): SupportCode.AS28,
    ("MD_QUERY", ErrorCode.COMMAND_VARIANT_UNVERIFIED.value): SupportCode.AS29,
    ("MD_QUERY", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS30,
    ("MD_COLLECT", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS31,
    ("MD_PARSE", ErrorCode.PARSE_PARTIAL.value): SupportCode.AS32,
    ("MD_PARSE", ErrorCode.COMMAND_VARIANT_UNVERIFIED.value): SupportCode.AS33,
    ("MD_PARSE", ErrorCode.COMMAND_REJECTED.value): SupportCode.AS34,
    ("MD_PARSE", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS35,
    ("MD_FILTER", ErrorCode.SESSION_NOT_FOUND.value): SupportCode.AS36,
    ("MD_ROUTE", ErrorCode.CURRENT_SWITCH_AMBIGUOUS.value): SupportCode.AS37,
    ("MD_ROUTE", ErrorCode.CURRENT_SWITCH_UNMAPPED.value): SupportCode.AS38,
    ("MD_SCAN", ErrorCode.CLIENT_NOT_FOUND_ON_MM.value): SupportCode.AS39,
    ("MD_SCAN", ErrorCode.CANCELLED.value): SupportCode.AS40,
    ("MD_SCAN", ErrorCode.POLL_DEADLINE_EXCEEDED.value): SupportCode.AS41,
    # AS60-AS69: monitoring lifecycle/reconciliation.
    ("MONITOR_STATE", ErrorCode.OUTPUT_LIMIT_EXCEEDED.value): SupportCode.AS60,
    (
        "MONITOR_STATE",
        ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS.value,
    ): SupportCode.AS61,
}

DIAGNOSTIC_SUPPORT_CODES: Final[Mapping[DiagnosticKey, SupportCode]] = MappingProxyType(
    _DIAGNOSTIC_SUPPORT_CODES
)


# AS70-AS89: application and local-storage boundaries.  These keys are kept
# separate from diagnostic stage/code pairs so callers must supply the failure
# boundary rather than guess one from an exception message.
_UI_FAILURE_SUPPORT_CODES: dict[UiFailureKey, SupportCode] = {
    UiFailureKey.QUERY_AUTH_FAILED: SupportCode.AS20,
    UiFailureKey.QUERY_DB_WRITE_FAILED: SupportCode.AS70,
    UiFailureKey.QUERY_STORAGE_LOW_SPACE: SupportCode.AS71,
    UiFailureKey.QUERY_UNEXPECTED: SupportCode.AS72,
    UiFailureKey.HISTORY_READ_FAILED: SupportCode.AS73,
    UiFailureKey.EXPORT_CSV_FAILED: SupportCode.AS74,
    UiFailureKey.EXPORT_HTML_FAILED: SupportCode.AS75,
    UiFailureKey.DELETE_PREVIEW_FAILED: SupportCode.AS76,
    UiFailureKey.DELETE_COMMIT_FAILED: SupportCode.AS77,
    UiFailureKey.DELETE_DISCARD_FAILED: SupportCode.AS78,
    UiFailureKey.STARTUP_FAILED: SupportCode.AS79,
    UiFailureKey.MAIN_THREAD_FAILED: SupportCode.AS80,
    UiFailureKey.SHUTDOWN_INCOMPLETE: SupportCode.AS81,
    UiFailureKey.WORKER_THREAD_FAILED: SupportCode.AS82,
    UiFailureKey.RUNTIME_CLEANUP_FAILED: SupportCode.AS83,
    UiFailureKey.CONFIG_READ_FAILED: SupportCode.AS84,
    UiFailureKey.CONFIG_SAVE_FAILED: SupportCode.AS85,
    UiFailureKey.QUERY_STORAGE_PATH_FAILED: SupportCode.AS86,
    UiFailureKey.QUERY_STORAGE_BUSY: SupportCode.AS87,
    UiFailureKey.QUERY_OUTPUT_LIMIT_EXCEEDED: SupportCode.AS88,
    UiFailureKey.QUERY_PERSISTENCE_INDETERMINATE: SupportCode.AS89,
}

UI_FAILURE_SUPPORT_CODES: Final[Mapping[UiFailureKey, SupportCode]] = MappingProxyType(
    _UI_FAILURE_SUPPORT_CODES
)

# AS90-AS99 must not be assigned without a future registry revision.
RESERVED_SUPPORT_CODES: Final = frozenset(f"AS{number:02d}" for number in range(90, 100))


def support_code_for(stage: str, code: ErrorCode | str | None) -> SupportCode:
    """Return the fixed diagnostic code, or AS00 for an unknown exact pair."""

    if not isinstance(stage, str):
        return SupportCode.AS00
    if isinstance(code, ErrorCode):
        code_text = code.value
    elif isinstance(code, str):
        code_text = code
    else:
        return SupportCode.AS00
    return DIAGNOSTIC_SUPPORT_CODES.get((stage, code_text), SupportCode.AS00)


def support_code_for_ui_failure(key: UiFailureKey | str | None) -> SupportCode:
    """Return the fixed code for an explicitly identified UI failure boundary."""

    if isinstance(key, UiFailureKey):
        normalized = key
    elif isinstance(key, str):
        try:
            normalized = UiFailureKey(key)
        except ValueError:
            return SupportCode.AS00
    else:
        return SupportCode.AS00
    return UI_FAILURE_SUPPORT_CODES.get(normalized, SupportCode.AS00)


def mappable_diagnostic_pairs() -> tuple[DiagnosticKey, ...]:
    """Return registry keys in their stable declaration order for storage reads."""

    return tuple(DIAGNOSTIC_SUPPORT_CODES)
