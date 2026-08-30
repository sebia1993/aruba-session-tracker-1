from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from aruba_session_tracker.observability import CrashJournal, ExceptionHookManager
from aruba_session_tracker.paths import UnsafeManagedPath


def _journal_text(path: Path) -> str:
    candidates = [path, *(path.with_name(f"{path.name}.{index}") for index in range(1, 6))]
    return "".join(
        candidate.read_text(encoding="utf-8") for candidate in candidates if candidate.is_file()
    )


def test_crash_journal_is_bounded_and_accepts_only_sanitized_fields(tmp_path: Path) -> None:
    root = tmp_path / "app"
    journal = CrashJournal(
        root / "diagnostics" / "crash.jsonl",
        managed_root=root,
        max_bytes=1024,
        backups=2,
    )

    for _index in range(80):
        journal.record("UNHANDLED_EXCEPTION", "RuntimeError", stage="WORKER_THREAD")

    files = [path for path in journal.path.parent.iterdir() if path.name.startswith("crash.jsonl")]
    assert 1 <= len(files) <= 3
    assert all(path.stat().st_size <= 1024 for path in files)
    for line in _journal_text(journal.path).splitlines():
        document = json.loads(line)
        assert set(document) == {
            "event",
            "exception_type",
            "incident_id",
            "occurred_at_utc",
            "schema",
            "stage",
            "version",
        }


def test_global_hooks_never_record_exception_messages_and_restore_idempotently(
    tmp_path: Path,
) -> None:
    journal = CrashJournal(tmp_path / "diagnostics" / "crash.jsonl")
    manager = ExceptionHookManager(journal)
    original_sys = sys.excepthook
    original_threading = threading.excepthook
    original_unraisable = sys.unraisablehook
    secret = "password=canary 10.20.30.40 C:\\customer\\device.log"  # noqa: S105
    try:
        manager.install()
        manager.install()
        manager._handle_sys(RuntimeError, RuntimeError(secret), None)
    finally:
        manager.restore()
        manager.restore()

    text = _journal_text(journal.path)
    assert "RuntimeError" in text
    assert "password" not in text.casefold()
    assert "10.20.30.40" not in text
    assert "customer" not in text.casefold()
    assert sys.excepthook is original_sys
    assert threading.excepthook is original_threading
    assert sys.unraisablehook is original_unraisable


def test_running_marker_detects_only_previous_unclean_session(tmp_path: Path) -> None:
    path = tmp_path / "diagnostics" / "crash.jsonl"
    first = CrashJournal(path)
    assert first.start_session() is False

    second = CrashJournal(path)
    assert second.start_session() is True
    second.mark_clean_exit()
    second.mark_clean_exit()

    third = CrashJournal(path)
    assert third.start_session() is False
    assert "PREVIOUS_UNCLEAN_EXIT" in _journal_text(path)


def test_journal_file_link_cannot_redirect_crash_writes(tmp_path: Path) -> None:
    journal = CrashJournal(tmp_path / "app" / "diagnostics" / "crash.jsonl")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    try:
        journal.path.symlink_to(outside)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")

    journal.record("UNHANDLED_EXCEPTION", "RuntimeError")

    assert outside.read_text(encoding="utf-8") == "keep"


def test_journal_file_hardlink_cannot_redirect_crash_writes(tmp_path: Path) -> None:
    journal = CrashJournal(tmp_path / "app" / "diagnostics" / "crash.jsonl")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    try:
        os.link(outside, journal.path)
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error}")

    journal.record("UNHANDLED_EXCEPTION", "RuntimeError")

    assert outside.read_text(encoding="utf-8") == "keep"


def test_managed_root_identity_swap_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "app"
    journal = CrashJournal(
        root / "diagnostics" / "crash.jsonl",
        managed_root=root,
    )
    original = tmp_path / "app-original"
    os.replace(root, original)
    root.mkdir()

    journal.record("UNHANDLED_EXCEPTION", "RuntimeError")

    assert not (root / "diagnostics" / "crash.jsonl").exists()
    assert not (original / "diagnostics" / "crash.jsonl").exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction safety test")
def test_crash_journal_rejects_reparse_managed_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    junction = tmp_path / "app-junction"
    command = [
        os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
        "/d",
        "/c",
        "mklink",
        "/J",
        str(junction),
        str(outside),
    ]
    completed = subprocess.run(  # noqa: S603
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    try:
        with pytest.raises(UnsafeManagedPath, match="reparse point"):
            CrashJournal(
                junction / "diagnostics" / "crash.jsonl",
                managed_root=junction,
            )
        assert sentinel.read_text(encoding="utf-8") == "keep"
    finally:
        junction.rmdir()
