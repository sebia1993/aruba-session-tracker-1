"""Public AOS 8 parser API."""

from .common import ParseError
from .datapath import parse_datapath_sessions
from .flags import (
    FLAG_DEFINITIONS,
    FlagDefinition,
    FlagSeverity,
    InterpretedFlag,
    interpret_flags,
    overall_flag_severity,
)
from .global_users import (
    GlobalUserEntry,
    GlobalUserLookup,
    GlobalUserStatus,
    parse_global_user_table,
)
from .switches import ManagedDeviceRow, parse_show_switches

__all__ = [
    "FLAG_DEFINITIONS",
    "FlagDefinition",
    "FlagSeverity",
    "GlobalUserEntry",
    "GlobalUserLookup",
    "GlobalUserStatus",
    "InterpretedFlag",
    "ManagedDeviceRow",
    "ParseError",
    "interpret_flags",
    "overall_flag_severity",
    "parse_datapath_sessions",
    "parse_global_user_table",
    "parse_show_switches",
]
