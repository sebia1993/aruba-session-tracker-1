"""Crash one managed CSV export immediately after a durable phase write."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from aruba_session_tracker.storage import SessionStore

_EXIT_AFTER_PHASE = 91
_PHASES = {
    "PREPARED",
    "RENDERED",
    "INSTALLED",
    "DB_RECEIPT_COMMITTED",
    "DB_COMMITTED",
}


def main() -> int:
    if len(sys.argv) not in {7, 8}:
        return 2
    db_path, raw_root, exports_root, run_id, destination, target_phase = sys.argv[1:7]
    export_format = sys.argv[7] if len(sys.argv) == 8 else "csv"
    if target_phase not in _PHASES:
        return 2
    if export_format not in {"csv", "html"}:
        return 2

    store = SessionStore(db_path, raw_root, exports_root)
    store.initialize()
    original_write = store._write_manifest
    original_replace = store._replace_manifest

    def exit_after_write(operation_id: str, payload: dict[str, object]) -> Path:
        path = original_write(operation_id, payload)
        if payload.get("phase") == target_phase:
            os._exit(_EXIT_AFTER_PHASE)
        return path

    def exit_after_replace(path: Path, payload: dict[str, object]) -> None:
        if target_phase == "DB_RECEIPT_COMMITTED" and payload.get("phase") == "DB_COMMITTED":
            os._exit(_EXIT_AFTER_PHASE)
        original_replace(path, payload)
        if payload.get("phase") == target_phase:
            os._exit(_EXIT_AFTER_PHASE)

    store._write_manifest = exit_after_write  # type: ignore[method-assign]
    store._replace_manifest = exit_after_replace  # type: ignore[method-assign]
    if export_format == "csv":
        store.export_run_csv(run_id, Path(destination))
    else:
        store.export_run_html(run_id, Path(destination))
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
