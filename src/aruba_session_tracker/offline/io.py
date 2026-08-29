"""Bounded local-file input for offline tech-support analysis."""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from stat import S_ISREG

from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.parsers.common import ParseError

from .models import OfflineParseLimits, OfflineTechSupportResult
from .parser import parse_offline_tech_support

_READ_CHUNK_BYTES = 1024 * 1024


def parse_offline_tech_support_file(
    source: Path | str,
    *,
    limits: OfflineParseLimits | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> OfflineTechSupportResult:
    """Read and parse one explicitly selected local UTF-8 text file.

    The path and file contents are never included in errors. The reader stops
    after the configured byte limit and supports cooperative cancellation
    between bounded chunks.
    """

    if not isinstance(source, (Path, str)):
        raise TypeError("Offline source must be a filesystem path.")
    if is_cancelled is not None and not callable(is_cancelled):
        raise TypeError("is_cancelled must be callable or None.")
    selected_limits = limits or OfflineParseLimits()
    path = Path(source)
    read_result = _read_bounded_payload(path, selected_limits, is_cancelled)
    if read_result is None:
        raise ParseError("Offline input file could not be read.")
    payload, before, after = read_result

    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise ParseError("Offline input file changed while it was being read.")
    _raise_if_cancelled(is_cancelled)
    text = _decode_utf8(payload)
    if text is None:
        raise ParseError("Offline input file is not valid UTF-8 text.")
    return parse_offline_tech_support(text, limits=selected_limits)


def _read_bounded_payload(
    path: Path,
    limits: OfflineParseLimits,
    is_cancelled: Callable[[], bool] | None,
) -> tuple[bytes, os.stat_result, os.stat_result] | None:
    payload = bytearray()
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not S_ISREG(before.st_mode):
                raise ParseError("Offline input must be a regular file.")
            if before.st_size > limits.max_text_bytes:
                raise ParseError(
                    "Offline input exceeds the configured size limit.",
                    code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                )
            while True:
                _raise_if_cancelled(is_cancelled)
                chunk = stream.read(
                    min(
                        _READ_CHUNK_BYTES,
                        limits.max_text_bytes + 1 - len(payload),
                    )
                )
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > limits.max_text_bytes:
                    raise ParseError(
                        "Offline input exceeds the configured size limit.",
                        code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                    )
            after = os.fstat(stream.fileno())
    except ParseError:
        raise
    except (OSError, ValueError):
        return None
    return bytes(payload), before, after


def _decode_utf8(payload: bytes) -> str | None:
    try:
        return payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _raise_if_cancelled(is_cancelled: Callable[[], bool] | None) -> None:
    if is_cancelled is not None and is_cancelled():
        raise ParseError("Offline analysis was cancelled.", code=ErrorCode.CANCELLED)
