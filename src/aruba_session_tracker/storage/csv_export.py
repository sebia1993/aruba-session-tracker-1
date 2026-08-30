"""Excel-friendly CSV export with formula-injection protection."""

from __future__ import annotations

import csv
import hashlib
import os
import re
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

from aruba_session_tracker.storage.durable_io import replace_with_retry

_FORMULA_PREFIX = re.compile(r"^[\s\x00-\x1f]*[=+\-@]")


def guard_csv_cell(value: object) -> str:
    """Return text that Excel will not interpret as a formula."""

    if value is None:
        return ""
    text = str(value)
    if _FORMULA_PREFIX.match(text):
        return "'" + text
    return text


def write_csv_atomic(
    destination: Path | str,
    *,
    columns: Sequence[str],
    rows: Iterable[Mapping[str, object]],
) -> Path:
    """Write a UTF-8 BOM CSV via atomic same-directory replacement."""

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8-sig", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=list(columns), extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({column: guard_csv_cell(row.get(column)) for column in columns})
            stream.flush()
            os.fsync(stream.fileno())
        digest = hashlib.sha256()
        byte_size = 0
        with temporary_path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                byte_size += len(chunk)
        replace_with_retry(
            temporary_path,
            path,
            replace=os.replace,
            expected_sha256=digest.hexdigest(),
            expected_size=byte_size,
        )
    finally:
        temporary_path.unlink(missing_ok=True)
    return path
