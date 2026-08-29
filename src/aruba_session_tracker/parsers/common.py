"""Shared parser safeguards."""

from __future__ import annotations

import re

from aruba_session_tracker.models import ErrorCode


class ParseError(ValueError):
    """Raised when device output cannot be interpreted without guessing."""

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        self.code = code


_COMMAND_ERROR_PATTERNS = (
    re.compile(r"(?im)^\s*%?\s*invalid input\b"),
    re.compile(r"(?im)^\s*%?\s*unknown command\b"),
    re.compile(r"(?im)^\s*%?\s*incomplete command\b"),
    re.compile(r"(?im)^\s*%?\s*ambiguous command\b"),
    re.compile(r"(?im)^\s*%?\s*command not found\b"),
    re.compile(r"(?im)^\s*error:\s*(?:invalid|unknown|unsupported)\b"),
)


def reject_command_errors(output: str) -> None:
    """Reject recognizable CLI errors before any table parsing takes place."""

    if not isinstance(output, str):
        raise TypeError("CLI output must be text.")
    for pattern in _COMMAND_ERROR_PATTERNS:
        if pattern.search(output):
            raise ParseError("The device rejected or did not recognize the command.")
