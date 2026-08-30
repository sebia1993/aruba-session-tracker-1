"""Bounded, privacy-preserving crash evidence for the Windows GUI process."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Any
from uuid import uuid4

from aruba_session_tracker import __version__
from aruba_session_tracker.paths import (
    DirectoryIdentity,
    UnsafeManagedPath,
    ensure_managed_directory,
    reject_link_or_reparse,
    reject_managed_file_link,
    verify_managed_directory,
)

_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.-]+")
_DEFAULT_MAX_BYTES = 1024 * 1024
_DEFAULT_BACKUPS = 2


def _safe_token(value: object, *, fallback: str = "UNKNOWN", limit: int = 80) -> str:
    text = _SAFE_TOKEN.sub("_", str(value))[:limit].strip("_.-")
    return text or fallback


class CrashJournal:
    """Append sanitized exception classes to a small rotating JSONL file.

    Exception messages, tracebacks, paths and arbitrary caller metadata are
    intentionally not accepted by this API.  The journal is local-only and is
    never uploaded or copied by the application.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        backups: int = _DEFAULT_BACKUPS,
        managed_root: Path | str | None = None,
    ) -> None:
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 16 * 1024 * 1024:
            raise ValueError("max_bytes must be between 1 KiB and 16 MiB")
        if type(backups) is not int or not 0 <= backups <= 5:
            raise ValueError("backups must be between 0 and 5")
        self.path = Path(os.path.abspath(Path(path)))
        self._max_bytes = max_bytes
        self._backups = backups
        self._lock = threading.RLock()
        self._managed_root: Path | None = None
        self._managed_root_identity: DirectoryIdentity | None = None
        if managed_root is not None:
            root, root_identity = ensure_managed_directory(managed_root)
            try:
                common = Path(os.path.commonpath((root, self.path)))
            except ValueError as error:
                raise UnsafeManagedPath("장애 기록 경로가 관리 루트 밖에 있습니다.") from error
            if common != root or self.path == root:
                raise UnsafeManagedPath("장애 기록 경로가 관리 루트 밖에 있습니다.")
            self._managed_root = root
            self._managed_root_identity = root_identity
            verify_managed_directory(root, root_identity)
        self._parent, self._parent_identity = ensure_managed_directory(self.path.parent)
        if self._managed_root is not None and self._managed_root_identity is not None:
            verify_managed_directory(self._managed_root, self._managed_root_identity)
        self.path = self._parent / self.path.name
        self._state_path = self.path.with_name(f"{self.path.name}.state")
        self._session_id: str | None = None
        self._clean_exit_written = False
        self._assert_paths()

    def start_session(self) -> bool:
        """Mark this process active and report whether the prior run was unclean."""

        with self._lock:
            if self._session_id is not None:
                return False
            previous_unclean = self._read_state_status() == "RUNNING"
            self._session_id = uuid4().hex[:16]
            self._write_state("RUNNING")
        if previous_unclean:
            self.record("PREVIOUS_UNCLEAN_EXIT", "ProcessInterrupted", stage="STARTUP")
        return previous_unclean

    def mark_clean_exit(self) -> None:
        """Persist one idempotent clean-exit marker for the current session."""

        with self._lock:
            if self._session_id is None or self._clean_exit_written:
                return
            self._write_state("CLEAN")
            self._clean_exit_written = True

    def record(self, event: str, exception_type: object, *, stage: str = "RUNTIME") -> str:
        """Record one bounded event and return its non-secret incident ID."""

        incident_id = uuid4().hex[:16]
        document = {
            "schema": 1,
            "occurred_at_utc": datetime.now(UTC).isoformat(),
            "incident_id": incident_id,
            "version": __version__,
            "event": _safe_token(event),
            "stage": _safe_token(stage),
            "exception_type": _safe_token(exception_type),
        }
        payload = (json.dumps(document, ensure_ascii=True, sort_keys=True) + "\n").encode("utf-8")
        try:
            with self._lock:
                self._assert_paths()
                self._rotate_if_needed(len(payload))
                descriptor = os.open(
                    self.path,
                    os.O_APPEND
                    | os.O_CREAT
                    | os.O_WRONLY
                    | getattr(os, "O_BINARY", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                with os.fdopen(descriptor, "ab") as stream:
                    before = reject_link_or_reparse(self.path)
                    opened = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or int(opened.st_dev) != int(before.st_dev)
                        or int(opened.st_ino) != int(before.st_ino)
                    ):
                        raise UnsafeManagedPath("장애 기록 파일이 여는 동안 변경되었습니다.")
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
        except (OSError, UnsafeManagedPath):
            # Crash reporting must never replace the original failure.
            return incident_id
        return incident_id

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        self._assert_paths()
        current_size = self.path.stat().st_size if self.path.exists() else 0
        if current_size + incoming_bytes <= self._max_bytes:
            return
        if self._backups == 0:
            self.path.unlink(missing_ok=True)
            return
        oldest = self.path.with_name(f"{self.path.name}.{self._backups}")
        oldest.unlink(missing_ok=True)
        for index in range(self._backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            destination = self.path.with_name(f"{self.path.name}.{index + 1}")
            if source.exists():
                os.replace(source, destination)
        if self.path.exists():
            os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))

    def _assert_paths(self) -> None:
        if self._managed_root is not None and self._managed_root_identity is not None:
            verify_managed_directory(self._managed_root, self._managed_root_identity)
        verify_managed_directory(self._parent, self._parent_identity)
        for path in (
            self.path,
            self._state_path,
            *(self.path.with_name(f"{self.path.name}.{index}") for index in range(1, 6)),
        ):
            reject_managed_file_link(path)

    def _read_state_status(self) -> str | None:
        self._assert_paths()
        if not self._state_path.exists():
            return None
        try:
            before = reject_link_or_reparse(self._state_path)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 4096:
                return None
            descriptor = os.open(
                self._state_path,
                os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or int(opened.st_dev) != int(before.st_dev)
                    or int(opened.st_ino) != int(before.st_ino)
                ):
                    raise UnsafeManagedPath("장애 기록 상태 파일이 여는 동안 변경되었습니다.")
                data = stream.read(4097)
            if len(data) > 4096:
                return None
            document = json.loads(data.decode("utf-8"))
        except (OSError, UnicodeError, ValueError, UnsafeManagedPath):
            return None
        status = document.get("status") if isinstance(document, dict) else None
        return status if status in {"RUNNING", "CLEAN"} else None

    def _write_state(self, status: str) -> None:
        if status not in {"RUNNING", "CLEAN"}:
            raise ValueError("invalid journal state")
        self._assert_paths()
        document = {
            "schema": 1,
            "status": status,
            "session_id": self._session_id,
            "version": __version__,
        }
        payload = (json.dumps(document, ensure_ascii=True, sort_keys=True) + "\n").encode("utf-8")
        temporary = self._state_path.with_name(f".{self._state_path.name}.{uuid4().hex}.tmp")
        reject_managed_file_link(temporary)
        try:
            descriptor = os.open(
                temporary,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_BINARY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self._assert_paths()
            os.replace(temporary, self._state_path)
            self._assert_paths()
        finally:
            temporary.unlink(missing_ok=True)


class ExceptionHookManager:
    """Install and later restore process-wide sanitized exception hooks."""

    def __init__(self, journal: CrashJournal) -> None:
        self._journal = journal
        self._installed = False
        self._original_sys: Any = None
        self._original_threading: Any = None
        self._original_unraisable: Any = None

    @property
    def installed(self) -> bool:
        return self._installed

    def install(self) -> None:
        if self._installed:
            return
        self._original_sys = sys.excepthook
        self._original_threading = threading.excepthook
        self._original_unraisable = sys.unraisablehook
        sys.excepthook = self._handle_sys
        threading.excepthook = self._handle_thread
        sys.unraisablehook = self._handle_unraisable
        self._installed = True

    def restore(self) -> None:
        if not self._installed:
            return
        sys.excepthook = self._original_sys
        threading.excepthook = self._original_threading
        sys.unraisablehook = self._original_unraisable
        self._installed = False

    def _handle_sys(
        self,
        exception_type: type[BaseException],
        _exception: BaseException,
        _traceback: TracebackType | None,
    ) -> None:
        self._journal.record("UNHANDLED_EXCEPTION", exception_type.__name__, stage="MAIN_THREAD")

    def _handle_thread(self, args: threading.ExceptHookArgs) -> None:
        self._journal.record(
            "UNHANDLED_THREAD_EXCEPTION",
            args.exc_type.__name__,
            stage="WORKER_THREAD",
        )

    def _handle_unraisable(self, args: Any) -> None:
        exception_type = type(args.exc_value).__name__ if args.exc_value is not None else "UNKNOWN"
        self._journal.record("UNRAISABLE_EXCEPTION", exception_type, stage="RUNTIME_CLEANUP")


__all__ = ["CrashJournal", "ExceptionHookManager"]
