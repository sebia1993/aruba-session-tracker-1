"""SQLite-backed session history and safe manual deletion workflow."""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO
from uuid import uuid4

from aruba_session_tracker.models import (
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.paths import (
    DirectoryIdentity,
    UnsafeManagedPath,
    ensure_managed_directory,
    reject_link_or_reparse,
    reject_managed_file_link,
    verify_managed_directory,
)
from aruba_session_tracker.storage.csv_export import write_csv_atomic
from aruba_session_tracker.storage.durable_io import replace_with_retry
from aruba_session_tracker.storage.html_report import (
    RunReportSnapshot,
    write_html_report_stream_atomic,
)
from aruba_session_tracker.storage.raw import (
    RawArtifact,
    RawOutputStore,
    UnsafeStoragePath,
    contained_path,
    safe_segment,
)

if TYPE_CHECKING:
    from aruba_session_tracker.services.monitoring import LifecycleEvent
    from aruba_session_tracker.services.tracker import QueryOutcome, RawSnapshot

_SCHEMA_VERSION = 2
_DELETE_PREVIEW_TTL_SECONDS = 300
_CSV_FETCH_BATCH = 1000
_HASH_CHUNK_SIZE = 1024 * 1024
_MANIFEST_VERSION = 1
_MAX_PENDING_DELETIONS = 16
_MAX_POLL_RAW_BYTES = 32 * 1024 * 1024
_MAX_POLL_OBSERVATIONS = 20_000
# One already-active observation can legitimately produce OBSERVED plus
# controller, flags and counter-change events in the same poll. Lifecycle rows
# therefore need their own bound; reusing the observation limit would make a
# valid saturated poll fail forever before prepared state can commit.
_MAX_POLL_LIFECYCLE_EVENTS = _MAX_POLL_OBSERVATIONS * 4
STORAGE_WARNING_FREE_BYTES = 5 * 1024**3
STORAGE_HARD_STOP_FREE_BYTES = 1024**3
_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_MANIFEST_TEMP_NAME = re.compile(r"\.(?P<operation_id>[0-9a-f]{32})\.json\.[0-9a-f]{32}\.tmp\Z")
_EVENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_IPV4_TEXT = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_CREDENTIAL_TEXT = re.compile(
    r"(?i)\b(username|user|password|passwd|secret|token)\s*[:=]\s*([^\s,;]+)"
)
_RAW_BUNDLE_MAGIC = b"ARUBA_SESSION_TRACKER_RAW_BUNDLE_V1\n"
_RAW_BUNDLE_CONTROLLER = "POLL_BUNDLE"
_RAW_BUNDLE_KIND = "poll-bundle"

CancelCheck = Callable[[], bool]
ProgressCallback = Callable[[str, int, int | None], None]

_CSV_COLUMNS = (
    "observed_at",
    "controller_name",
    "controller_host",
    "protocol",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "counter",
    "priority",
    "tos",
    "age",
    "destination",
    "tunnel_age",
    "packets",
    "bytes_count",
    "flags",
    "cpu_id",
    "session_key",
    "raw_relative_path",
    "raw_sha256",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    bidirectional INTEGER NOT NULL CHECK (bidirectional IN (0, 1)),
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    captured_at TEXT NOT NULL,
    kind TEXT NOT NULL,
    controller_name TEXT NOT NULL,
    relative_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0)
);

CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    raw_file_id INTEGER REFERENCES raw_files(id) ON DELETE SET NULL,
    observed_at TEXT NOT NULL,
    controller_name TEXT NOT NULL,
    controller_host TEXT NOT NULL,
    protocol INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_port INTEGER NOT NULL,
    counter TEXT NOT NULL,
    priority INTEGER,
    tos INTEGER,
    age INTEGER,
    destination TEXT NOT NULL,
    tunnel_age INTEGER,
    packets INTEGER,
    bytes_count INTEGER,
    flags TEXT NOT NULL,
    cpu_id INTEGER,
    session_key TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lifecycle_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL,
    session_key TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    controller_name TEXT NOT NULL,
    details_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS controller_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL,
    previous_controller TEXT,
    current_controller TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diagnostic_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT REFERENCES runs(id) ON DELETE CASCADE,
    occurred_at TEXT NOT NULL,
    stage TEXT NOT NULL,
    code TEXT,
    message TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    relative_path TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0)
);

CREATE TABLE IF NOT EXISTS external_export_commits (
    operation_id TEXT PRIMARY KEY CHECK (length(operation_id) = 32),
    target_key TEXT NOT NULL CHECK (length(target_key) = 64),
    run_id TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    byte_size INTEGER NOT NULL CHECK (byte_size >= 0)
);

CREATE INDEX IF NOT EXISTS ix_observations_run_time
    ON observations(run_id, observed_at);
CREATE INDEX IF NOT EXISTS ix_lifecycle_run_time
    ON lifecycle_events(run_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_controller_run_time
    ON controller_events(run_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_diagnostic_run_time
    ON diagnostic_events(run_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_observations_run_session_time
    ON observations(run_id, session_key, observed_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS ix_raw_files_run_time
    ON raw_files(run_id, captured_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS ix_exports_run_id
    ON exports(run_id, id);
"""


class StorageError(RuntimeError):
    """Local history could not be read or safely changed."""

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class StorageHealth:
    database_bytes: int
    wal_bytes: int
    raw_bytes: int
    raw_file_count: int
    export_bytes: int
    export_file_count: int
    free_bytes: int

    @property
    def total_managed_bytes(self) -> int:
        return self.database_bytes + self.wal_bytes + self.raw_bytes + self.export_bytes

    @property
    def total_file_count(self) -> int:
        return self.raw_file_count + self.export_file_count

    @property
    def warning(self) -> bool:
        return self.free_bytes < STORAGE_WARNING_FREE_BYTES

    @property
    def hard_stop(self) -> bool:
        return self.free_bytes < STORAGE_HARD_STOP_FREE_BYTES


@dataclass(frozen=True, slots=True)
class DeletePreview:
    preview_id: str
    confirmation_token: str
    run_ids: tuple[str, ...]
    database_rows: int
    raw_files: int
    export_files: int
    total_file_bytes: int
    expires_at: datetime
    summary: str


@dataclass(frozen=True, slots=True)
class DeletionResult:
    deleted_runs: int
    deleted_database_rows: int
    deleted_raw_files: int
    deleted_export_files: int


@dataclass(frozen=True, slots=True)
class _DeletionSnapshot:
    run_ids: tuple[str, ...]
    row_counts: tuple[tuple[str, int], ...]
    raw_files: tuple[_DeletionFile, ...]
    export_files: tuple[_DeletionFile, ...]
    total_file_bytes: int

    @property
    def database_rows(self) -> int:
        return sum(count for _, count in self.row_counts)


@dataclass(frozen=True, slots=True)
class _PendingDeletion:
    preview: DeletePreview
    snapshot: _DeletionSnapshot
    expires_monotonic: float
    target_run_id: str | None


@dataclass(frozen=True, slots=True)
class _StagedFile:
    source: Path
    destination: Path
    category: str
    relative_path: str
    sha256: str
    byte_size: int
    registered: bool
    device: int
    inode: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class _DeletionFile:
    relative_path: str
    sha256: str | None
    byte_size: int
    registered: bool
    device: int | None
    inode: int | None
    modified_ns: int | None


@dataclass(slots=True)
class _RunLease:
    path: Path
    stream: BinaryIO
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class _ManagedExportStage:
    operation_id: str
    path: Path
    lease: _RunLease
    manifest_path: Path


@dataclass(frozen=True, slots=True)
class _ExternalExportOwner:
    operation_id: str
    run_id: str
    destination: Path
    target_key: str
    token: str
    parent_device: int
    parent_inode: int
    path: Path


@dataclass(frozen=True, slots=True)
class _RawBundleSection:
    index: int
    sha256: str
    byte_size: int


@dataclass(frozen=True, slots=True)
class _PreparedRaw:
    artifact: RawArtifact
    staged_path: Path
    destination: Path
    captured_at: datetime
    kind: str
    controller_name: str
    observations: tuple[SessionObservation, ...]
    data: bytes
    bundle_sections: tuple[_RawBundleSection, ...] = ()


class SessionStore:
    """Facade for run history, raw capture, report export, and confirmed deletion."""

    def __init__(
        self,
        db_path: Path | str,
        raw_root: Path | str,
        exports_root: Path | str,
    ) -> None:
        self.db_path = Path(os.path.abspath(Path(db_path)))
        self.raw_root = Path(os.path.abspath(Path(raw_root)))
        self.exports_root = Path(os.path.abspath(Path(exports_root)))
        self._operations_root = self.db_path.parent / ".operations"
        self._manifests_root = self._operations_root / "manifests"
        self._leases_root = self._operations_root / "leases"
        self._export_owners_root = self._operations_root / "export-owners"
        self._raw = RawOutputStore(self.raw_root)
        self._initialized = False
        self._lock = threading.RLock()
        self._pending_deletions: dict[str, _PendingDeletion] = {}
        self._directory_identities: dict[Path, DirectoryIdentity] = {}
        self._run_leases: dict[str, _RunLease] = {}
        self._raw_unregistered_usage = (0, 0)
        self._export_unregistered_usage = (0, 0)
        self._pending_external_recoveries: dict[str, str] = {}

    def initialize(self) -> None:
        with self._lock:
            if self._initialized:
                return
            try:
                self._prepare_managed_layout()
                with self._connection(uninitialized=True, configure_wal=True) as connection:
                    _require_quick_check(connection)
                    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    if version not in {0, 1, _SCHEMA_VERSION}:
                        raise StorageError(
                            f"지원하지 않는 데이터베이스 스키마 버전입니다: {version}"
                        )
                    connection.execute("BEGIN IMMEDIATE")
                    _execute_schema(connection)
                    if version == 1:
                        columns = {
                            str(row[1])
                            for row in connection.execute(
                                "PRAGMA table_info(lifecycle_events)"
                            ).fetchall()
                        }
                        if "instance_id" not in columns:
                            connection.execute(
                                "ALTER TABLE lifecycle_events "
                                "ADD COLUMN instance_id TEXT NOT NULL DEFAULT ''"
                            )
                        connection.execute(
                            "UPDATE lifecycle_events "
                            "SET instance_id = 'legacy-' || id "
                            "WHERE instance_id = ''"
                        )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                    _validate_schema(connection)
                    _require_foreign_key_check(connection)

                self._recover_operations()
                self._recover_legacy_export_artifacts()
                self._interrupt_abandoned_runs()
                self._initialized = True
            except StorageError:
                raise
            except (OSError, sqlite3.Error, UnsafeManagedPath, UnsafeStoragePath) as error:
                raise StorageError(f"데이터베이스를 초기화할 수 없습니다: {error}") from error

    def close(self) -> None:
        """Release every locally owned run lease without masking earlier failures.

        A run whose database status remains ``RUNNING`` is intentionally left
        for the normal abandoned-run recovery on the next initialization.
        This method only guarantees that this process no longer owns an open
        file handle, which is also required before Windows temporary trees can
        be removed safely.
        """

        first_error: Exception | None = None
        with self._lock:
            leases = tuple(self._run_leases.values())
            self._run_leases.clear()
            for lease in leases:
                try:
                    _release_run_lease(lease, remove=True)
                except (OSError, StorageError, UnsafeManagedPath, UnsafeStoragePath) as error:
                    if first_error is None:
                        first_error = error
        if first_error is not None:
            raise StorageError(
                f"실행 잠금 파일을 모두 정리할 수 없습니다: {type(first_error).__name__}"
            ) from first_error

    def storage_health(self) -> StorageHealth:
        """Return a conservative snapshot of managed disk use and free capacity."""

        self._ensure_initialized()
        try:
            with self._lock:
                return self._storage_health_unlocked()
        except (OSError, sqlite3.Error, UnsafeManagedPath, UnsafeStoragePath) as error:
            raise StorageError(f"저장소 상태를 확인할 수 없습니다: {error}") from error

    def reconcile_storage_health(
        self,
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> StorageHealth:
        """Perform an explicit deep filesystem reconciliation and return health."""

        self._ensure_initialized()
        _check_cancelled(cancel_check)
        maintenance = self._acquire_maintenance_lease()
        if maintenance is None:
            raise StorageError("다른 저장소 유지보수 작업이 진행 중입니다.")
        try:
            for _attempt in range(2):
                registered_before = self._registered_storage_usage()
                filesystem_before = (
                    _directory_revision(self.raw_root),
                    _directory_revision(self.exports_root),
                )
                raw_actual = _storage_tree_stats(
                    self.raw_root,
                    cancel_check=cancel_check,
                    progress=progress,
                    phase="storage_reconcile_raw",
                )
                export_actual = _storage_tree_stats(
                    self.exports_root,
                    cancel_check=cancel_check,
                    progress=progress,
                    phase="storage_reconcile_exports",
                )
                registered_after = self._registered_storage_usage()
                filesystem_after = (
                    _directory_revision(self.raw_root),
                    _directory_revision(self.exports_root),
                )
                if registered_before != registered_after or filesystem_before != filesystem_after:
                    continue
                raw_unregistered = (
                    max(0, raw_actual[0] - registered_after[0][0]),
                    max(0, raw_actual[1] - registered_after[0][1]),
                )
                export_unregistered = (
                    max(0, export_actual[0] - registered_after[1][0]),
                    max(0, export_actual[1] - registered_after[1][1]),
                )
                with self._lock:
                    # Poll publication holds this same lock across its file and
                    # DB phases.  A final revision comparison prevents a file
                    # observed before its DB row from being cached as an orphan.
                    if (
                        self._registered_storage_usage() != registered_after
                        or (
                            _directory_revision(self.raw_root),
                            _directory_revision(self.exports_root),
                        )
                        != filesystem_after
                    ):
                        continue
                    self._raw_unregistered_usage = raw_unregistered
                    self._export_unregistered_usage = export_unregistered
                    return self._storage_health_unlocked()
            raise StorageError("저장소 대조 중 기록이 변경되었습니다. 잠시 후 다시 시도하십시오.")
        except (OSError, sqlite3.Error, UnsafeManagedPath, UnsafeStoragePath) as error:
            raise StorageError(f"저장소 상태를 대조할 수 없습니다: {error}") from error
        finally:
            _release_run_lease(maintenance, remove=True)

    @property
    def pending_external_recovery_count(self) -> int:
        """Number of safe external-export recoveries waiting for their target."""

        with self._lock:
            return len(self._pending_external_recoveries)

    def retry_pending_external_recoveries(self) -> int:
        """Retry deferred external recoveries without exposing their private paths."""

        self._ensure_initialized()
        with self._lock:
            previous = dict(self._pending_external_recoveries)
            self._pending_external_recoveries.clear()
        try:
            recovered = self._recover_operations()
        except BaseException:
            remaining = {
                operation_id: reason
                for operation_id, reason in previous.items()
                if os.path.lexists(self._manifests_root / f"{operation_id}.json")
            }
            with self._lock:
                self._pending_external_recoveries.update(remaining)
            raise
        if not recovered:
            with self._lock:
                self._pending_external_recoveries.update(previous)
        with self._lock:
            return len(self._pending_external_recoveries)

    def checkpoint_database(self) -> tuple[int, int, int]:
        """Request a non-blocking SQLite WAL checkpoint.

        The returned tuple is ``(busy, log_pages, checkpointed_pages)`` from
        SQLite's PASSIVE checkpoint and can be surfaced by a maintenance worker.
        """

        self._ensure_initialized()
        try:
            with self._lock, self._connection() as connection:
                row = connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
                if row is None or len(row) != 3:
                    raise StorageError("SQLite checkpoint 결과를 확인할 수 없습니다.")
                return int(row[0]), int(row[1]), int(row[2])
        except StorageError:
            raise
        except sqlite3.Error as error:
            raise StorageError(f"SQLite checkpoint를 실행할 수 없습니다: {error}") from error

    def backup_database(
        self,
        destination: Path | str,
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> Path:
        """Create a consistent user-requested SQLite backup via atomic replace."""

        self._ensure_initialized()
        _check_cancelled(cancel_check)
        path = Path(os.path.abspath(Path(destination)))
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            path = self._external_export_destination(path)
            _ensure_plain_directory(path.parent)
            path = self._external_export_destination(path)
            self._require_storage_capacity(
                path,
                required_extra_bytes=max(
                    _regular_file_size(self.db_path)
                    + _regular_file_size(Path(f"{self.db_path}-wal")),
                    1024 * 1024,
                ),
            )
            if os.path.lexists(temporary):  # pragma: no cover - UUID collision defense
                raise StorageError("데이터베이스 backup 임시 경로가 이미 존재합니다.")

            def report_backup(_status: int, remaining: int, total: int) -> None:
                _check_cancelled(cancel_check)
                _notify_progress(progress, "database_backup", total - remaining, total)

            with self._connection() as source, closing(sqlite3.connect(temporary)) as target:
                source.backup(target, pages=256, progress=report_backup, sleep=0.05)
                target.commit()
            _check_cancelled(cancel_check)
            with closing(sqlite3.connect(temporary)) as verification:
                _require_quick_check(verification)
                _require_foreign_key_check(verification)
            with temporary.open("r+b") as stream:
                os.fsync(stream.fileno())
            backup_sha, backup_size = _file_fingerprint(temporary)
            _replace_file(
                temporary,
                path,
                expected_sha256=backup_sha,
                expected_size=backup_size,
            )
            return path
        except StorageError:
            raise
        except (OSError, sqlite3.Error, UnsafeManagedPath, UnsafeStoragePath) as error:
            raise StorageError(f"데이터베이스 backup을 만들 수 없습니다: {error}") from error
        finally:
            if os.path.lexists(temporary):
                with suppress(OSError, UnsafeManagedPath, UnsafeStoragePath):
                    _unlink_regular(temporary, missing_ok=True)

    def ensure_query_capacity(self) -> None:
        """Fail before network I/O when the next query cannot be stored safely.

        Unlike :meth:`storage_health`, this intentionally performs only the
        inexpensive free-space and managed-path checks.  The UI calls it before
        every poll, while the full recursive usage snapshot remains rate-limited.
        """

        self._ensure_initialized()
        self._require_storage_capacity()

    def start_run(
        self,
        query: QueryRequest,
        *,
        run_id: str | None = None,
        started_at: datetime | None = None,
    ) -> str:
        self._ensure_initialized()
        self._require_storage_capacity()
        identifier = run_id or str(uuid4())
        safe_segment(identifier, "run_id")
        timestamp = _iso(started_at)
        lease: _RunLease | None = None
        try:
            with self._lock:
                self._assert_managed_layout()
                lease = self._acquire_run_lease(identifier)
                if lease is None:
                    raise StorageError("같은 실행 ID가 다른 프로세스에서 사용 중입니다.")
                with self._connection() as connection:
                    connection.execute(
                        """
                        INSERT INTO runs (
                            id, started_at, source_ip, destination_ip, source_port,
                            destination_port, bidirectional, status
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'RUNNING')
                        """,
                        (
                            identifier,
                            timestamp,
                            query.source_ip,
                            query.destination_ip,
                            query.source_port,
                            query.destination_port,
                            int(query.bidirectional),
                        ),
                    )
                self._run_leases[identifier] = lease
            return identifier
        except (sqlite3.Error, UnsafeStoragePath, UnsafeManagedPath) as error:
            if lease is not None:
                _release_run_lease(lease, remove=True)
            raise StorageError(f"조회 실행 기록을 시작할 수 없습니다: {error}") from error
        except StorageError:
            if lease is not None:
                _release_run_lease(lease, remove=True)
            raise

    def finish_run(
        self,
        run_id: str,
        *,
        status: str = "COMPLETED",
        ended_at: datetime | None = None,
    ) -> None:
        self._ensure_initialized()
        normalized_status = _event_name(status, "status")
        try:
            with self._lock:
                self._require_owned_running_run(run_id)
                self._assert_managed_layout()
                lease = self._run_leases[run_id]
                with self._connection() as connection:
                    cursor = connection.execute(
                        """
                        UPDATE runs SET ended_at = ?, status = ?
                        WHERE id = ? AND status = 'RUNNING'
                        """,
                        (_iso(ended_at), normalized_status, run_id),
                    )
                    if cursor.rowcount != 1:
                        row = connection.execute(
                            "SELECT status FROM runs WHERE id = ?", (run_id,)
                        ).fetchone()
                        if row is None:
                            raise StorageError("종료할 조회 실행 기록이 없습니다.")
                        if row["status"] != normalized_status:
                            raise StorageError("RUNNING 상태의 조회 실행만 종료할 수 있습니다.")
                try:
                    _release_run_lease(lease, remove=True)
                except (OSError, UnsafeStoragePath, UnsafeManagedPath) as error:
                    raise StorageError(
                        f"조회 실행 종료 후 잠금 파일을 정리할 수 없습니다: {error}"
                    ) from error
                if self._run_leases.get(run_id) is lease:
                    del self._run_leases[run_id]
        except sqlite3.Error as error:
            raise StorageError(f"조회 실행 종료를 기록할 수 없습니다: {error}") from error

    def record_query(
        self,
        run_id: str,
        observations: Iterable[SessionObservation],
        *,
        raw_text: str | None = None,
        controller_name: str | None = None,
        raw_kind: str = "session",
        captured_at: datetime | None = None,
    ) -> tuple[int, ...]:
        """Compatibility wrapper over the recoverable poll-batch writer."""

        from aruba_session_tracker.services.tracker import QueryOutcome, RawSnapshot

        values = tuple(observations)
        snapshots: tuple[RawSnapshot, ...] = ()
        if raw_text is not None:
            selected_controller = controller_name or _single_controller_name(values)
            observed_at = captured_at or datetime.now(UTC)
            command = (
                "show datapath session table"
                if raw_kind == "session"
                else "show global-user-table list ip"
            )
            snapshots = (
                RawSnapshot(
                    selected_controller,
                    command,
                    raw_text,
                    observed_at=observed_at,
                    observation_keys=tuple(item.session_key for item in values),
                ),
            )
        with self._lock:
            self._ensure_initialized()
            with self._connection() as connection:
                previous_id = int(
                    connection.execute(
                        "SELECT coalesce(max(id), 0) FROM observations WHERE run_id = ?",
                        (run_id,),
                    ).fetchone()[0]
                )
            self.record_poll_batch(
                run_id,
                QueryOutcome(observations=values, raw_snapshots=snapshots, authoritative=True),
                _raw_kind_overrides=(raw_kind,) if snapshots else (),
            )
            with self._connection() as connection:
                return tuple(
                    int(row[0])
                    for row in connection.execute(
                        """
                        SELECT id FROM observations
                        WHERE run_id = ? AND id > ?
                        ORDER BY id
                        """,
                        (run_id, previous_id),
                    )
                )

    def record_poll_batch(
        self,
        run_id: str,
        outcome: QueryOutcome,
        events: Sequence[LifecycleEvent] = (),
        *,
        _raw_kind_overrides: Sequence[str] = (),
    ) -> None:
        """Persist one complete query/poll as one recoverable SQLite transaction."""

        self._ensure_initialized()
        self._require_storage_capacity()
        safe_segment(run_id, "run_id")
        self._require_owned_running_run(run_id)
        self._validate_poll_batch_limits(outcome, events)
        operation_id = uuid4().hex
        stage_root = self.raw_root / f".raw-staging-{operation_id}"
        prepared: tuple[_PreparedRaw, ...] = ()
        manifest_path: Path | None = None
        installed: list[_PreparedRaw] = []
        operation_lease: _RunLease | None = None
        committed = False
        try:
            with self._lock:
                self._assert_managed_layout()
                operation_lease = self._acquire_operation_lease(operation_id)
                if operation_lease is None:  # pragma: no cover - UUID collision defense
                    raise StorageError("저장 작업 잠금을 획득할 수 없습니다.")
                prepared, remaining = self._prepare_poll_raw_files(
                    run_id,
                    outcome,
                    stage_root,
                    raw_kind_overrides=tuple(_raw_kind_overrides),
                )
                manifest_path = self._write_manifest(
                    operation_id,
                    {
                        "version": _MANIFEST_VERSION,
                        "kind": "raw_batch",
                        "operation_id": operation_id,
                        "run_id": run_id,
                        "stage_root": stage_root.name,
                        "files": [
                            {
                                "relative_path": item.artifact.relative_path,
                                "sha256": item.artifact.sha256,
                                "byte_size": item.artifact.byte_size,
                                "bundle_sections": [
                                    {
                                        "index": section.index,
                                        "sha256": section.sha256,
                                        "byte_size": section.byte_size,
                                    }
                                    for section in item.bundle_sections
                                ],
                            }
                            for item in prepared
                        ],
                    },
                )
                self._stage_prepared_raw(stage_root, prepared)
                for item in prepared:
                    item.destination.parent.mkdir(parents=True, exist_ok=True)
                    _reject_managed_chain(self.raw_root, item.destination.parent)
                    if os.path.lexists(item.destination):
                        raise StorageError("Raw 대상 파일이 이미 존재합니다.")
                    _verify_file_fingerprint(
                        item.staged_path,
                        item.artifact.sha256,
                        item.artifact.byte_size,
                    )
                    if item.bundle_sections:
                        _verify_raw_bundle_file(item.staged_path, item.bundle_sections)
                    _replace_file(
                        item.staged_path,
                        item.destination,
                        expected_sha256=item.artifact.sha256,
                        expected_size=item.artifact.byte_size,
                    )
                    installed.append(item)

                # Durable Raw file publication is manifest-protected and
                # complete before taking SQLite's writer lock.  The short
                # transaction below stores only references and poll rows.
                with self._connection() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._require_run(connection, run_id, require_running=True)
                    for item in prepared:
                        raw_file_id = _insert_raw_file(connection, run_id, item)
                        _insert_observations(connection, run_id, item.observations, raw_file_id)
                    _insert_observations(connection, run_id, remaining, None)
                    for diagnostic in outcome.diagnostics:
                        _insert_diagnostic(connection, run_id, diagnostic)
                    for event in events:
                        _insert_lifecycle_event(connection, run_id, event)
                committed = True
                self._remove_operation_artifacts(manifest_path, stage_root)
                _release_run_lease(operation_lease, remove=True)
                operation_lease = None
        except StorageError as error:
            cleanup_error = (
                None
                if committed
                else self._cleanup_failed_raw_batch(installed, stage_root, manifest_path)
            )
            if operation_lease is not None:
                _release_run_lease(operation_lease, remove=cleanup_error is None)
            if cleanup_error is not None:
                error.add_note(f"Raw batch 정리도 실패했습니다: {type(cleanup_error).__name__}")
            raise
        except (OSError, sqlite3.Error, UnsafeStoragePath, UnsafeManagedPath, ValueError) as error:
            cleanup_error = (
                None
                if committed
                else self._cleanup_failed_raw_batch(installed, stage_root, manifest_path)
            )
            if operation_lease is not None:
                _release_run_lease(operation_lease, remove=cleanup_error is None)
            wrapped = StorageError(f"조회 결과 batch를 기록할 수 없습니다: {error}")
            if cleanup_error is not None:
                wrapped.add_note(f"Raw batch 정리도 실패했습니다: {type(cleanup_error).__name__}")
            raise wrapped from error

    @staticmethod
    def _validate_poll_batch_limits(
        outcome: QueryOutcome,
        events: Sequence[LifecycleEvent],
    ) -> None:
        observation_count = len(outcome.observations)
        if observation_count > _MAX_POLL_OBSERVATIONS:
            raise StorageError(
                "한 번의 조회에서 저장할 수 있는 관측 수를 초과했습니다.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        if len(events) > _MAX_POLL_LIFECYCLE_EVENTS:
            raise StorageError(
                "한 번의 조회에서 저장할 수 있는 수명주기 이벤트 수를 초과했습니다.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        if len(outcome.raw_snapshots) > _MAX_POLL_OBSERVATIONS:
            raise StorageError(
                "한 번의 조회에서 저장할 수 있는 Raw 항목 수를 초과했습니다.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        raw_bytes = 0
        for snapshot in outcome.raw_snapshots:
            raw_bytes += len(snapshot.output.encode("utf-8", errors="replace"))
            if raw_bytes > _MAX_POLL_RAW_BYTES:
                raise StorageError(
                    "한 번의 조회에서 저장할 수 있는 Raw 출력 총량을 초과했습니다.",
                    code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                )

    def record_lifecycle(
        self,
        run_id: str,
        *,
        session_key: str,
        instance_id: str,
        event_type: str,
        controller_name: str,
        details: dict[str, object] | None = None,
        occurred_at: datetime | None = None,
    ) -> int:
        self._ensure_initialized()
        self._require_storage_capacity()
        self._require_owned_running_run(run_id)
        normalized_event = _event_name(event_type, "event_type")
        normalized_instance = _instance_id(instance_id)
        details_json = json.dumps(details or {}, ensure_ascii=False, sort_keys=True)
        try:
            with self._lock, self._connection() as connection:
                self._require_run(connection, run_id, require_running=True)
                cursor = connection.execute(
                    """
                    INSERT INTO lifecycle_events (
                        run_id, occurred_at, session_key, instance_id, event_type,
                        controller_name, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        _iso(occurred_at),
                        session_key,
                        normalized_instance,
                        normalized_event,
                        controller_name,
                        details_json,
                    ),
                )
                return _last_row_id(cursor)
        except sqlite3.Error as error:
            raise StorageError(f"세션 수명주기 이벤트를 기록할 수 없습니다: {error}") from error

    def record_controller_event(
        self,
        run_id: str,
        *,
        current_controller: str,
        previous_controller: str | None = None,
        reason: str = "LOCATION_REFRESH",
        occurred_at: datetime | None = None,
    ) -> int:
        self._ensure_initialized()
        self._require_storage_capacity()
        self._require_owned_running_run(run_id)
        try:
            with self._lock, self._connection() as connection:
                self._require_run(connection, run_id, require_running=True)
                cursor = connection.execute(
                    """
                    INSERT INTO controller_events (
                        run_id, occurred_at, previous_controller,
                        current_controller, reason
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        _iso(occurred_at),
                        previous_controller,
                        current_controller,
                        _sanitize_diagnostic(reason),
                    ),
                )
                return _last_row_id(cursor)
        except sqlite3.Error as error:
            raise StorageError(f"Controller 전환 이벤트를 기록할 수 없습니다: {error}") from error

    def record_diagnostic(self, event: DiagnosticEvent, *, run_id: str | None = None) -> int:
        self._ensure_initialized()
        self._require_storage_capacity()
        if run_id is not None:
            self._require_owned_running_run(run_id)
        try:
            with self._lock, self._connection() as connection:
                if run_id is not None:
                    self._require_run(connection, run_id, require_running=True)
                cursor = connection.execute(
                    """
                    INSERT INTO diagnostic_events (
                        run_id, occurred_at, stage, code, message
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        _iso(event.occurred_at),
                        _sanitize_diagnostic(event.stage),
                        event.code.value if event.code is not None else None,
                        _sanitize_diagnostic(event.message),
                    ),
                )
                return _last_row_id(cursor)
        except sqlite3.Error as error:
            raise StorageError(f"진단 이벤트를 기록할 수 없습니다: {error}") from error

    def list_runs(self, *, limit: int = 100) -> tuple[dict[str, object], ...]:
        self._ensure_initialized()
        if not 1 <= limit <= 1000:
            raise ValueError("limit는 1~1000 범위여야 합니다.")
        try:
            with self._lock, self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT r.*,
                           (SELECT count(*) FROM observations o WHERE o.run_id = r.id)
                               AS observation_count,
                           (SELECT count(*) FROM lifecycle_events l WHERE l.run_id = r.id)
                               AS lifecycle_count
                    FROM runs r
                    ORDER BY r.started_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                return tuple(dict(row) for row in rows)
        except sqlite3.Error as error:
            raise StorageError(f"조회 실행 목록을 읽을 수 없습니다: {error}") from error

    def export_run_csv(
        self,
        run_id: str,
        destination: Path | str | None = None,
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> Path:
        self._ensure_initialized()
        _check_cancelled(cancel_check)
        safe_segment(run_id, "run_id")
        path = (
            Path(destination)
            if destination is not None
            else self.exports_root / f"run-{run_id}.csv"
        )
        managed_destination, export_destination = self._resolve_export_destination(path)
        self._require_storage_capacity(
            export_destination,
            required_extra_bytes=self._estimate_export_bytes(run_id, html=False),
        )
        try:
            if managed_destination is None:
                stage = self._prepare_external_export(run_id, export_destination)
            else:
                stage = self._prepare_managed_export(run_id, managed_destination)
            try:
                self._verify_run_raw_integrity(
                    run_id,
                    cancel_check=cancel_check,
                    progress=progress,
                )
                with self._connection() as connection:
                    connection.execute("BEGIN")
                    self._require_run(connection, run_id)
                    _check_cancelled(cancel_check)
                    row_total = int(
                        connection.execute(
                            "SELECT count(*) FROM observations WHERE run_id = ?",
                            (run_id,),
                        ).fetchone()[0]
                    )
                    cursor = connection.execute(
                        """
                        SELECT o.observed_at, o.controller_name, o.controller_host,
                               o.protocol, o.source_ip, o.destination_ip, o.source_port,
                               o.destination_port, o.counter, o.priority, o.tos, o.age,
                               o.destination, o.tunnel_age, o.packets, o.bytes_count,
                               o.flags, o.cpu_id, o.session_key,
                               rf.relative_path AS raw_relative_path,
                               rf.sha256 AS raw_sha256
                        FROM observations o
                        LEFT JOIN raw_files rf ON rf.id = o.raw_file_id
                        WHERE o.run_id = ?
                        ORDER BY o.observed_at, o.id
                        """,
                        (run_id,),
                    )
                    write_csv_atomic(
                        stage.path,
                        columns=_CSV_COLUMNS,
                        rows=_iter_cursor_dicts(
                            cursor,
                            batch_size=_CSV_FETCH_BATCH,
                            cancel_check=cancel_check,
                            progress=progress,
                            phase="csv_rows",
                            total=row_total,
                        ),
                    )
            except BaseException as error:
                cleanup_error = (
                    self._discard_external_export_stage(stage)
                    if managed_destination is None
                    else self._discard_managed_export_stage(stage)
                )
                if cleanup_error is not None:
                    error.add_note(
                        f"내보내기 staging 정리도 실패했습니다: {type(cleanup_error).__name__}"
                    )
                raise
            if managed_destination is None:
                self._commit_external_export(run_id, export_destination, stage)
                return path
            self._commit_managed_export(run_id, managed_destination, stage)
            return managed_destination
        except StorageError:
            raise
        except (
            OSError,
            sqlite3.Error,
            UnsafeManagedPath,
            UnsafeStoragePath,
            ValueError,
        ) as error:
            raise StorageError(f"CSV를 내보낼 수 없습니다: {error}") from error

    def export_run_html(
        self,
        run_id: str,
        destination: Path | str | None = None,
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> Path:
        """Export one completed run as a standalone, offline HTML5 report."""

        self._ensure_initialized()
        _check_cancelled(cancel_check)
        safe_segment(run_id, "run_id")
        path = (
            Path(destination)
            if destination is not None
            else self.exports_root / f"run-{run_id}.html"
        )
        managed_destination, export_destination = self._resolve_export_destination(path)
        self._require_storage_capacity(
            export_destination,
            required_extra_bytes=self._estimate_export_bytes(run_id, html=True),
        )
        try:
            if managed_destination is None:
                stage = self._prepare_external_export(run_id, export_destination)
            else:
                stage = self._prepare_managed_export(run_id, managed_destination)
            try:
                self._verify_run_raw_integrity(
                    run_id,
                    cancel_check=cancel_check,
                    progress=progress,
                )
                with self._connection() as connection:
                    connection.execute("BEGIN")
                    run = connection.execute(
                        "SELECT * FROM runs WHERE id = ?", (run_id,)
                    ).fetchone()
                    if run is None:
                        raise StorageError("요청한 조회 실행 기록이 없습니다.")
                    if run["status"] == "RUNNING":
                        raise StorageError(
                            "RUNNING 상태의 실행은 중지 후 HTML 보고서를 만드십시오."
                        )
                    _check_cancelled(cancel_check)
                    observation_total = int(
                        connection.execute(
                            "SELECT count(*) FROM observations WHERE run_id = ?", (run_id,)
                        ).fetchone()[0]
                    )
                    unique_session_total = int(
                        connection.execute(
                            "SELECT count(DISTINCT session_key) FROM observations WHERE run_id = ?",
                            (run_id,),
                        ).fetchone()[0]
                    )
                    logical_session_total = int(
                        connection.execute(
                            """
                            SELECT count(*) FROM (
                                SELECT 1 FROM observations
                                WHERE run_id = ?
                                GROUP BY protocol, source_ip, destination_ip,
                                         source_port, destination_port
                            )
                            """,
                            (run_id,),
                        ).fetchone()[0]
                    )
                    latest = tuple(
                        dict(row)
                        for row in connection.execute(
                            """
                            WITH ranked AS (
                                SELECT o.*,
                                       row_number() OVER (
                                           PARTITION BY protocol, source_ip, destination_ip,
                                                        source_port, destination_port
                                           ORDER BY observed_at DESC, id DESC
                                       ) AS rank_in_flow
                                FROM observations o
                                WHERE run_id = ?
                            )
                            SELECT observed_at, controller_name, protocol,
                                   source_ip, destination_ip, source_port,
                                   destination_port, session_key
                            FROM ranked
                            WHERE rank_in_flow = 1
                            ORDER BY observed_at DESC, id DESC
                            LIMIT 50
                            """,
                            (run_id,),
                        )
                    )
                    lifecycle_events = self._latest_report_lifecycle_events(
                        connection,
                        run_id,
                        latest,
                        cancel_check=cancel_check,
                        progress=progress,
                    )
                    snapshot = RunReportSnapshot(
                        run=dict(run),
                        controllers=(),
                        mm_controllers=(),
                        md_controllers=(),
                        observations=latest,
                        observation_total=observation_total,
                        unique_session_total=unique_session_total,
                        lifecycle_events=lifecycle_events,
                        lifecycle_total=0,
                        lifecycle_counts=(),
                        controller_events=(),
                        controller_total=0,
                        diagnostics=(),
                        diagnostic_total=0,
                        raw_files=(),
                        raw_file_total=0,
                        raw_byte_total=0,
                    )
                    history = _iter_cursor_dicts(
                        connection.execute(
                            """
                            SELECT observed_at, controller_name, protocol,
                                   source_ip, destination_ip, source_port,
                                   destination_port, session_key
                            FROM observations
                            WHERE run_id = ?
                            ORDER BY observed_at, id
                            """,
                            (run_id,),
                        ),
                        batch_size=_CSV_FETCH_BATCH,
                        cancel_check=cancel_check,
                        progress=progress,
                        phase="html_history",
                        total=observation_total,
                    )
                    write_html_report_stream_atomic(
                        stage.path,
                        snapshot,
                        history,
                        logical_session_total=logical_session_total,
                    )
            except BaseException as error:
                cleanup_error = (
                    self._discard_external_export_stage(stage)
                    if managed_destination is None
                    else self._discard_managed_export_stage(stage)
                )
                if cleanup_error is not None:
                    error.add_note(
                        f"HTML staging 정리도 실패했습니다: {type(cleanup_error).__name__}"
                    )
                raise
            if managed_destination is None:
                self._commit_external_export(run_id, export_destination, stage)
                return path
            self._commit_managed_export(run_id, managed_destination, stage)
            return managed_destination
        except StorageError:
            raise
        except (
            OSError,
            sqlite3.Error,
            UnsafeManagedPath,
            UnsafeStoragePath,
            ValueError,
        ) as error:
            raise StorageError(f"HTML 보고서를 내보낼 수 없습니다: {error}") from error

    def preview_delete(
        self,
        run_id: str | None = None,
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> DeletePreview:
        """Create a five-minute, one-use deletion preview; this does not delete data."""

        self._ensure_initialized()
        _check_cancelled(cancel_check)
        with self._lock:
            self._sweep_expired_delete_previews_unlocked()
            if len(self._pending_deletions) >= _MAX_PENDING_DELETIONS:
                raise StorageError(
                    "동시에 유지할 수 있는 삭제 미리보기는 최대 16개입니다. "
                    "기존 미리보기를 취소하거나 만료 후 다시 시도하십시오."
                )
        try:
            snapshot = self._collect_deletion_snapshot(
                run_id,
                cancel_check=cancel_check,
                progress=progress,
            )
        except UnsafeStoragePath as error:
            raise StorageError(f"삭제 대상 경로가 안전하지 않습니다: {error}") from error
        preview_id = uuid4().hex
        confirmation_token = secrets.token_urlsafe(24)
        expires_at = datetime.now(UTC) + timedelta(seconds=_DELETE_PREVIEW_TTL_SECONDS)
        scope = "전체 기록" if run_id is None else f"실행 {run_id}"
        preview = DeletePreview(
            preview_id=preview_id,
            confirmation_token=confirmation_token,
            run_ids=snapshot.run_ids,
            database_rows=snapshot.database_rows,
            raw_files=len(snapshot.raw_files),
            export_files=len(snapshot.export_files),
            total_file_bytes=snapshot.total_file_bytes,
            expires_at=expires_at,
            summary=(
                f"{scope}: 실행 {len(snapshot.run_ids)}개, DB 행 "
                f"{snapshot.database_rows}개, Raw {len(snapshot.raw_files)}개, "
                f"내보내기 파일 {len(snapshot.export_files)}개를 삭제합니다."
            ),
        )
        with self._lock:
            self._sweep_expired_delete_previews_unlocked()
            if len(self._pending_deletions) >= _MAX_PENDING_DELETIONS:
                raise StorageError(
                    "동시에 유지할 수 있는 삭제 미리보기는 최대 16개입니다. "
                    "기존 미리보기를 취소하거나 만료 후 다시 시도하십시오."
                )
            self._pending_deletions[preview_id] = _PendingDeletion(
                preview=preview,
                snapshot=snapshot,
                expires_monotonic=time.monotonic() + _DELETE_PREVIEW_TTL_SECONDS,
                target_run_id=run_id,
            )
        return preview

    def discard_delete_preview(self, preview: DeletePreview) -> bool:
        """Discard one exact pending preview without deleting any data."""

        self._ensure_initialized()
        with self._lock:
            self._sweep_expired_delete_previews_unlocked()
            pending = self._pending_deletions.get(preview.preview_id)
            if pending is None or pending.preview != preview:
                return False
            self._pending_deletions.pop(preview.preview_id, None)
            return True

    def delete(
        self,
        preview: DeletePreview,
        *,
        confirmation_token: str,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> DeletionResult:
        """Delete exactly the unchanged items described by a valid preview."""

        self._ensure_initialized()
        _check_cancelled(cancel_check)
        with self._lock:
            now = time.monotonic()
            pending = self._pending_deletions.get(preview.preview_id)
            if pending is not None and now >= pending.expires_monotonic:
                self._pending_deletions.pop(preview.preview_id, None)
                self._sweep_expired_delete_previews_unlocked(now)
                raise StorageError("삭제 미리보기가 만료되었습니다. 다시 확인하십시오.")
            self._sweep_expired_delete_previews_unlocked(now)
            if pending is None or pending.preview != preview:
                raise StorageError("먼저 현재 삭제 대상을 미리 확인해야 합니다.")
            if not secrets.compare_digest(pending.preview.confirmation_token, confirmation_token):
                raise StorageError("삭제 확인 토큰이 일치하지 않습니다.")
            self._pending_deletions.pop(preview.preview_id, None)

        staged: list[_StagedFile] = []
        manifest_path: Path | None = None
        operation_lease = self._acquire_operation_lease(preview.preview_id)
        if operation_lease is None:
            raise StorageError("삭제 작업 잠금을 획득할 수 없습니다.")
        maintenance_lease = self._acquire_maintenance_lease()
        if maintenance_lease is None:
            _release_run_lease(operation_lease, remove=True)
            raise StorageError("다른 저장소 유지보수 작업이 진행 중입니다.")
        phase = "snapshot"
        try:
            current = self._collect_deletion_snapshot(
                pending.target_run_id,
                cancel_check=cancel_check,
                progress=progress,
                expected=pending.snapshot,
            )
            if current != pending.snapshot:
                raise StorageError("미리보기 이후 기록이 변경되었습니다. 다시 확인하십시오.")

            manifest_path = self._write_manifest(
                preview.preview_id,
                {
                    "version": _MANIFEST_VERSION,
                    "kind": "delete",
                    "operation_id": preview.preview_id,
                    "files": [
                        {
                            "category": category,
                            "relative_path": item.relative_path,
                            "sha256": item.sha256,
                            "byte_size": item.byte_size,
                            "registered": item.registered,
                        }
                        for category, items in (
                            ("raw", current.raw_files),
                            ("export", current.export_files),
                        )
                        for item in items
                    ],
                },
            )
            phase = "staging"
            _stage_files(
                self.raw_root,
                current.raw_files,
                preview.preview_id,
                "raw",
                staged,
                cancel_check=cancel_check,
                progress=progress,
            )
            _stage_files(
                self.exports_root,
                current.export_files,
                preview.preview_id,
                "export",
                staged,
                cancel_check=cancel_check,
                progress=progress,
            )
            self._require_no_new_deletion_files(
                pending.target_run_id,
                cancel_check=cancel_check,
                progress=progress,
            )

            phase = "database"
            _check_cancelled(cancel_check)
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._require_deletion_database_state(
                    connection,
                    pending.target_run_id,
                    current,
                )
                _verify_staged_file_identities(staged)
                if current.run_ids:
                    placeholders = ",".join("?" for _ in current.run_ids)
                    cursor = connection.execute(
                        f"DELETE FROM runs WHERE id IN ({placeholders})",  # noqa: S608
                        current.run_ids,
                    )
                    if cursor.rowcount != len(current.run_ids):
                        raise StorageError("삭제 대상 실행 기록이 미리보기와 다릅니다.")
        except (
            OSError,
            sqlite3.Error,
            StorageError,
            UnsafeStoragePath,
            UnsafeManagedPath,
        ) as error:
            restoration_error = _restore_staged_files(staged)
            if restoration_error is not None:
                error.add_note(
                    "삭제 취소 후 일부 파일 복원도 실패했습니다: "
                    f"{type(restoration_error).__name__}"
                )
                _release_run_lease(operation_lease, remove=False)
                _release_run_lease(maintenance_lease, remove=True)
            else:
                if manifest_path is not None:
                    _unlink_regular(manifest_path, missing_ok=True)
                _release_run_lease(operation_lease, remove=True)
                _release_run_lease(maintenance_lease, remove=True)
            if isinstance(error, StorageError):
                raise
            if isinstance(error, (UnsafeStoragePath, UnsafeManagedPath)):
                raise StorageError(f"삭제 대상 경로가 안전하지 않습니다: {error}") from error
            if phase == "staging":
                raise StorageError(
                    f"삭제 대상 파일을 안전하게 격리할 수 없습니다: {error}"
                ) from error
            raise StorageError(f"데이터베이스 기록을 삭제할 수 없습니다: {error}") from error

        try:
            _purge_staged_files(staged)
            if manifest_path is not None:
                _unlink_regular(manifest_path, missing_ok=False)
            _release_run_lease(operation_lease, remove=True)
            _release_run_lease(maintenance_lease, remove=True)
        except (OSError, StorageError, UnsafeStoragePath) as error:
            _release_run_lease(operation_lease, remove=False)
            _release_run_lease(maintenance_lease, remove=True)
            raise StorageError(
                "데이터베이스 삭제는 완료되었지만 격리된 파일을 마지막으로 제거하지 못했습니다."
            ) from error
        raw_orphans = tuple(
            item for item in staged if item.category == "raw" and not item.registered
        )
        export_orphans = tuple(
            item for item in staged if item.category == "export" and not item.registered
        )
        with self._lock:
            self._raw_unregistered_usage = (
                max(
                    0,
                    self._raw_unregistered_usage[0] - sum(item.byte_size for item in raw_orphans),
                ),
                max(0, self._raw_unregistered_usage[1] - len(raw_orphans)),
            )
            self._export_unregistered_usage = (
                max(
                    0,
                    self._export_unregistered_usage[0]
                    - sum(item.byte_size for item in export_orphans),
                ),
                max(0, self._export_unregistered_usage[1] - len(export_orphans)),
            )
        _remove_known_empty_run_directories(self.raw_root, current.run_ids)
        deleted_raw = sum(item.category == "raw" for item in staged)
        deleted_exports = sum(item.category == "export" for item in staged)
        return DeletionResult(
            deleted_runs=len(current.run_ids),
            deleted_database_rows=current.database_rows,
            deleted_raw_files=deleted_raw,
            deleted_export_files=deleted_exports,
        )

    def _sweep_expired_delete_previews_unlocked(self, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        expired = tuple(
            preview_id
            for preview_id, pending in self._pending_deletions.items()
            if current >= pending.expires_monotonic
        )
        for preview_id in expired:
            self._pending_deletions.pop(preview_id, None)
        return len(expired)

    def _prepare_managed_layout(self) -> None:
        db_parent = Path(os.path.abspath(self.db_path.parent))
        raw_root = Path(os.path.abspath(self.raw_root))
        exports_root = Path(os.path.abspath(self.exports_root))
        if _paths_overlap(raw_root, exports_root):
            raise StorageError("Raw와 내보내기 관리 루트는 서로 겹칠 수 없습니다.")
        if _paths_overlap(self._operations_root, raw_root) or _paths_overlap(
            self._operations_root, exports_root
        ):
            raise StorageError("내부 복구 경로는 Raw 또는 내보내기 루트와 겹칠 수 없습니다.")
        if _path_is_within(self.db_path, raw_root) or _path_is_within(self.db_path, exports_root):
            raise StorageError("데이터베이스 파일은 Raw 또는 내보내기 루트 안에 둘 수 없습니다.")

        self._directory_identities.clear()
        for directory in (
            db_parent,
            raw_root,
            exports_root,
            self._operations_root,
            self._manifests_root,
            self._leases_root,
            self._export_owners_root,
        ):
            absolute, identity = ensure_managed_directory(directory)
            self._directory_identities[absolute] = identity
        reject_managed_file_link(self.db_path)
        self._raw.initialize()
        self._assert_managed_layout()

    def _assert_managed_layout(self) -> None:
        for directory, identity in self._directory_identities.items():
            verify_managed_directory(directory, identity)
        reject_managed_file_link(self.db_path)
        self._raw.verify()

    def _storage_health_unlocked(self) -> StorageHealth:
        self._assert_managed_layout()
        with self._connection() as connection:
            raw_registered = connection.execute(
                "SELECT coalesce(sum(byte_size), 0), count(*) FROM raw_files"
            ).fetchone()
            export_registered = connection.execute(
                "SELECT coalesce(sum(byte_size), 0), count(*) FROM exports"
            ).fetchone()
        raw_registered_usage = (int(raw_registered[0]), int(raw_registered[1]))
        export_registered_usage = (int(export_registered[0]), int(export_registered[1]))
        raw_bytes = raw_registered_usage[0] + self._raw_unregistered_usage[0]
        raw_count = raw_registered_usage[1] + self._raw_unregistered_usage[1]
        export_bytes = export_registered_usage[0] + self._export_unregistered_usage[0]
        export_count = export_registered_usage[1] + self._export_unregistered_usage[1]
        free_bytes = _minimum_free_bytes((self.db_path.parent, self.raw_root, self.exports_root))
        return StorageHealth(
            database_bytes=_regular_file_size(self.db_path),
            wal_bytes=_regular_file_size(Path(f"{self.db_path}-wal")),
            raw_bytes=raw_bytes,
            raw_file_count=raw_count,
            export_bytes=export_bytes,
            export_file_count=export_count,
            free_bytes=free_bytes,
        )

    def _registered_storage_usage(
        self,
    ) -> tuple[tuple[int, int], tuple[int, int]]:
        self._assert_managed_layout()
        with self._connection() as connection:
            raw_registered = connection.execute(
                "SELECT coalesce(sum(byte_size), 0), count(*) FROM raw_files"
            ).fetchone()
            export_registered = connection.execute(
                "SELECT coalesce(sum(byte_size), 0), count(*) FROM exports"
            ).fetchone()
        return (
            (int(raw_registered[0]), int(raw_registered[1])),
            (int(export_registered[0]), int(export_registered[1])),
        )

    def _require_storage_capacity(
        self,
        destination: Path | None = None,
        *,
        required_extra_bytes: int = 0,
    ) -> None:
        if required_extra_bytes < 0:
            raise ValueError("추가 저장 공간 예상치는 음수일 수 없습니다.")
        try:
            with self._lock:
                self._assert_managed_layout()
                free_bytes = _minimum_free_bytes(
                    (self.db_path.parent, self.raw_root, self.exports_root)
                )
                if destination is not None:
                    free_bytes = min(
                        free_bytes,
                        _minimum_free_bytes((_nearest_existing_directory(destination.parent),)),
                    )
                if free_bytes - required_extra_bytes < STORAGE_HARD_STOP_FREE_BYTES:
                    raise StorageError(
                        "저장 공간이 1 GiB 미만이므로 새 기록을 안전하게 저장할 수 없습니다.",
                        code=ErrorCode.STORAGE_LOW_SPACE,
                    )
        except StorageError:
            raise
        except (OSError, UnsafeManagedPath, UnsafeStoragePath) as error:
            raise StorageError(f"저장소 여유 공간을 확인할 수 없습니다: {error}") from error

    def _estimate_export_bytes(self, run_id: str, *, html: bool) -> int:
        """Return a conservative preflight size without materializing report rows."""

        with self._lock, self._connection() as connection:
            self._require_run(connection, run_id)
            row_count = int(
                connection.execute(
                    "SELECT count(*) FROM observations WHERE run_id = ?",
                    (run_id,),
                ).fetchone()[0]
            )
        fixed_overhead = 256 * 1024 if html else 64 * 1024
        per_row = 1024 if html else 768
        return fixed_overhead + row_count * per_row

    def _acquire_run_lease(self, run_id: str) -> _RunLease | None:
        safe_segment(run_id, "run_id")
        return _acquire_file_lease(self._leases_root / f"run-{run_id}.lease")

    def _acquire_operation_lease(self, operation_id: str) -> _RunLease | None:
        _validate_operation_id(operation_id)
        return _acquire_file_lease(self._leases_root / f"operation-{operation_id}.lease")

    def _acquire_maintenance_lease(self) -> _RunLease | None:
        return _acquire_file_lease(self._leases_root / "storage-maintenance.lease")

    def _interrupt_abandoned_runs(self) -> None:
        acquired: list[tuple[str, _RunLease]] = []
        try:
            with self._connection(uninitialized=True) as connection:
                rows = connection.execute(
                    "SELECT id FROM runs WHERE status = 'RUNNING' ORDER BY id"
                ).fetchall()
                for row in rows:
                    run_id = str(row["id"])
                    lease = self._acquire_run_lease(run_id)
                    if lease is not None:
                        acquired.append((run_id, lease))
                if acquired:
                    connection.executemany(
                        """
                        UPDATE runs SET ended_at = ?, status = 'INTERRUPTED'
                        WHERE id = ? AND status = 'RUNNING'
                        """,
                        ((_iso(None), run_id) for run_id, _lease in acquired),
                    )
        finally:
            for _run_id, lease in acquired:
                _release_run_lease(lease, remove=True)

    def _write_manifest(self, operation_id: str, payload: dict[str, object]) -> Path:
        _validate_operation_id(operation_id)
        self._assert_managed_layout()
        path = self._manifests_root / f"{operation_id}.json"
        if os.path.lexists(path):
            raise StorageError("같은 저장 작업 manifest가 이미 존재합니다.")
        _write_json_atomic(path, payload)
        return path

    def _replace_manifest(self, path: Path, payload: dict[str, object]) -> None:
        operation_id = _manifest_text(payload, "operation_id")
        _validate_operation_id(operation_id)
        expected = self._manifests_root / f"{operation_id}.json"
        if path != expected or not os.path.lexists(path):
            raise StorageError("갱신할 저장 작업 manifest가 올바르지 않습니다.")
        self._assert_managed_layout()
        _write_json_atomic(path, payload)

    def _remove_operation_artifacts(self, manifest_path: Path | None, stage_root: Path) -> None:
        if os.path.lexists(stage_root):
            _remove_tree_strict(stage_root)
        if manifest_path is not None:
            _unlink_regular(manifest_path, missing_ok=True)

    def _prepare_poll_raw_files(
        self,
        run_id: str,
        outcome: QueryOutcome,
        stage_root: Path,
        *,
        raw_kind_overrides: tuple[str, ...] = (),
    ) -> tuple[tuple[_PreparedRaw, ...], tuple[SessionObservation, ...]]:
        remaining = {item.session_key: item for item in outcome.observations}
        snapshots = tuple(outcome.raw_snapshots)
        if raw_kind_overrides and len(raw_kind_overrides) != len(snapshots):
            raise ValueError("Raw kind override 수가 snapshot 수와 일치하지 않습니다.")
        if len(snapshots) > 1:
            bundled_observations: list[SessionObservation] = []
            section_observations: list[tuple[SessionObservation, ...]] = []
            for snapshot in snapshots:
                observations = _select_snapshot_observations(snapshot, remaining)
                section_observations.append(observations)
                bundled_observations.extend(observations)
            captured_at = min(snapshot.observed_at for snapshot in snapshots)
            data, sections = _raw_bundle_data(snapshots, tuple(section_observations))
            artifact = _raw_artifact_for_data(
                run_id,
                kind=_RAW_BUNDLE_KIND,
                controller_name=_RAW_BUNDLE_CONTROLLER,
                data=data,
                captured_at=captured_at,
            )
            relative = Path(artifact.relative_path)
            return (
                (
                    _PreparedRaw(
                        artifact=artifact,
                        staged_path=stage_root / relative,
                        destination=_managed_file_path(
                            self.raw_root,
                            artifact.relative_path,
                            allow_missing=True,
                        ),
                        captured_at=captured_at,
                        kind=_RAW_BUNDLE_KIND,
                        controller_name=_RAW_BUNDLE_CONTROLLER,
                        observations=tuple(bundled_observations),
                        data=data,
                        bundle_sections=sections,
                    ),
                ),
                tuple(remaining.values()),
            )

        prepared: list[_PreparedRaw] = []
        for index, snapshot in enumerate(snapshots):
            observations = _select_snapshot_observations(snapshot, remaining)
            raw_kind = (
                raw_kind_overrides[index]
                if raw_kind_overrides
                else "session"
                if "datapath" in snapshot.command
                else "mm-location"
            )
            artifact, data = _raw_artifact_for_batch(
                run_id,
                kind=raw_kind,
                controller_name=snapshot.device_name,
                content=snapshot.output,
                captured_at=snapshot.observed_at,
            )
            relative = Path(artifact.relative_path)
            prepared.append(
                _PreparedRaw(
                    artifact=artifact,
                    staged_path=stage_root / relative,
                    destination=_managed_file_path(
                        self.raw_root,
                        artifact.relative_path,
                        allow_missing=True,
                    ),
                    captured_at=snapshot.observed_at,
                    kind=raw_kind,
                    controller_name=snapshot.device_name,
                    observations=observations,
                    data=data,
                )
            )
        return tuple(prepared), tuple(remaining.values())

    def _stage_prepared_raw(
        self,
        stage_root: Path,
        prepared: tuple[_PreparedRaw, ...],
    ) -> None:
        if not prepared:
            return
        if os.path.lexists(stage_root):
            raise StorageError("Raw staging 경로가 이미 존재합니다.")
        stage_root.mkdir(parents=False, exist_ok=False)
        _reject_managed_chain(self.raw_root, stage_root)
        for item in prepared:
            item.staged_path.parent.mkdir(parents=True, exist_ok=True)
            _write_bytes_atomic(item.staged_path, item.data)

    def _cleanup_failed_raw_batch(
        self,
        installed: list[_PreparedRaw],
        stage_root: Path,
        manifest_path: Path | None,
    ) -> Exception | None:
        try:
            for item in reversed(installed):
                if os.path.lexists(item.destination):
                    _verify_file_fingerprint(
                        item.destination,
                        item.artifact.sha256,
                        item.artifact.byte_size,
                    )
                    item.destination.unlink()
            self._remove_operation_artifacts(manifest_path, stage_root)
            _remove_known_empty_run_directories(
                self.raw_root,
                tuple({Path(item.artifact.relative_path).parts[0] for item in installed}),
            )
        except Exception as error:  # manifest intentionally remains for startup recovery
            return error
        return None

    def _recover_operations(self) -> bool:
        maintenance = self._acquire_maintenance_lease()
        if maintenance is None:
            return False
        try:
            self._recover_operations_under_maintenance()
            return True
        finally:
            _release_run_lease(maintenance, remove=True)

    def _recover_operations_under_maintenance(self) -> None:
        self._assert_managed_layout()
        with os.scandir(self._manifests_root) as entries:
            manifest_paths: list[Path] = []
            temporary_paths: list[tuple[Path, str]] = []
            for entry in entries:
                path = Path(entry.path)
                reject_link_or_reparse(path)
                if entry.is_dir(follow_symlinks=False):
                    raise StorageError(
                        "manifest 디렉터리에 예상하지 못한 하위 디렉터리가 있습니다."
                    )
                if entry.name.endswith(".tmp"):
                    match = _MANIFEST_TEMP_NAME.fullmatch(entry.name)
                    if match is None:
                        raise StorageError("인식할 수 없는 manifest 임시 파일이 있습니다.")
                    temporary_paths.append((path, match.group("operation_id")))
                    continue
                if not entry.name.endswith(".json") or not _OPERATION_ID.fullmatch(
                    entry.name.removesuffix(".json")
                ):
                    raise StorageError("인식할 수 없는 저장 작업 manifest가 있습니다.")
                manifest_paths.append(path)

        for path, operation_id in sorted(temporary_paths):
            lease = self._acquire_operation_lease(operation_id)
            if lease is None:
                continue
            try:
                _unlink_regular(path, missing_ok=False)
            finally:
                _release_run_lease(lease, remove=not os.path.lexists(path))

        for path in sorted(manifest_paths):
            operation_id = path.stem
            lease = self._acquire_operation_lease(operation_id)
            if lease is None:
                continue
            try:
                payload = _read_manifest(path, operation_id)
                kind = payload.get("kind")
                if kind == "raw_batch":
                    self._recover_raw_batch_manifest(path, payload)
                elif kind == "delete":
                    self._recover_delete_manifest(path, payload)
                elif kind == "export":
                    self._recover_export_manifest(path, payload)
                elif kind == "external_export":
                    try:
                        self._recover_external_export_manifest(path, payload)
                    except OSError as error:
                        if not _external_recovery_target_unavailable(error):
                            raise
                        with self._lock:
                            self._pending_external_recoveries[operation_id] = type(error).__name__
                else:
                    raise StorageError("지원하지 않는 저장 작업 manifest 종류입니다.")
            finally:
                _release_run_lease(lease, remove=not os.path.lexists(path))

        self._recover_orphan_external_export_owners()
        self._recover_orphan_external_export_receipts()

    def _recover_raw_batch_manifest(self, path: Path, payload: dict[str, Any]) -> None:
        operation_id = _manifest_text(payload, "operation_id")
        run_id = _manifest_text(payload, "run_id")
        try:
            safe_segment(run_id, "run_id")
        except UnsafeStoragePath as error:
            raise StorageError("Raw batch 실행 ID가 올바르지 않습니다.") from error
        stage_name = _manifest_text(payload, "stage_root")
        if stage_name != f".raw-staging-{operation_id}":
            raise StorageError("Raw batch staging 경로가 manifest와 일치하지 않습니다.")
        stage_root = self.raw_root / stage_name
        files = _manifest_files(payload)
        try:
            for item in files:
                _validated_raw_relative(run_id, item["relative_path"])
        except UnsafeStoragePath as error:
            raise StorageError(
                "Raw batch 파일 경로가 manifest 실행 ID와 일치하지 않습니다."
            ) from error
        if len({item["relative_path"] for item in files}) != len(files):
            raise StorageError("Raw batch manifest에 중복 파일 경로가 있습니다.")
        with self._connection(uninitialized=True) as connection:
            states: list[bool] = []
            for item in files:
                row = connection.execute(
                    """
                    SELECT sha256, byte_size FROM raw_files
                    WHERE run_id = ? AND relative_path = ?
                    """,
                    (run_id, item["relative_path"]),
                ).fetchone()
                states.append(
                    row is not None
                    and str(row["sha256"]) == item["sha256"]
                    and int(row["byte_size"]) == item["byte_size"]
                )
            if any(states) and not all(states):
                raise StorageError(
                    "Raw batch의 DB 기록이 일부만 남아 있어 자동 복구할 수 없습니다."
                )
            committed = bool(files) and all(states)
            for item in files:
                relative = item["relative_path"]
                destination = _managed_file_path(self.raw_root, relative, allow_missing=True)
                staged = stage_root / Path(relative)
                if committed:
                    if os.path.lexists(destination):
                        _verify_file_fingerprint(destination, item["sha256"], item["byte_size"])
                        if item["bundle_sections"]:
                            _verify_raw_bundle_file(destination, item["bundle_sections"])
                    elif os.path.lexists(staged):
                        _verify_file_fingerprint(staged, item["sha256"], item["byte_size"])
                        if item["bundle_sections"]:
                            _verify_raw_bundle_file(staged, item["bundle_sections"])
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        _replace_file(
                            staged,
                            destination,
                            expected_sha256=item["sha256"],
                            expected_size=item["byte_size"],
                        )
                    else:
                        raise StorageError("DB가 참조하는 Raw 파일을 복구할 수 없습니다.")
                else:
                    for candidate in (destination, staged):
                        if os.path.lexists(candidate):
                            _verify_file_fingerprint(candidate, item["sha256"], item["byte_size"])
                            if item["bundle_sections"]:
                                _verify_raw_bundle_file(candidate, item["bundle_sections"])
                            candidate.unlink()
        self._remove_operation_artifacts(path, stage_root)

    def _recover_delete_manifest(self, path: Path, payload: dict[str, Any]) -> None:
        operation_id = _manifest_text(payload, "operation_id")
        files = _manifest_delete_files(payload)
        with self._connection(uninitialized=True) as connection:
            for item in files:
                root = self.raw_root if item["category"] == "raw" else self.exports_root
                stage_root = root / f".delete-staging-{operation_id}"
                canonical = _managed_file_path(root, item["relative_path"], allow_missing=True)
                staged = stage_root / Path(item["relative_path"])
                referenced = _database_references_file(
                    connection,
                    item["category"],
                    item["relative_path"],
                )
                should_restore = (item["registered"] and referenced) or not item["registered"]
                _reconcile_deleted_file(
                    canonical,
                    staged,
                    sha256=item["sha256"],
                    byte_size=item["byte_size"],
                    should_restore=should_restore,
                )
        for root in (self.raw_root, self.exports_root):
            stage_root = root / f".delete-staging-{operation_id}"
            if os.path.lexists(stage_root):
                _remove_tree_strict(stage_root)
        _unlink_regular(path, missing_ok=False)

    def _recover_export_manifest(self, path: Path, payload: dict[str, Any]) -> None:
        operation_id = _manifest_text(payload, "operation_id")
        run_id = _manifest_text(payload, "run_id")
        try:
            safe_segment(run_id, "run_id")
        except UnsafeStoragePath as error:
            raise StorageError("내보내기 manifest 실행 ID가 올바르지 않습니다.") from error
        relative = Path(*_safe_relative_parts(_manifest_text(payload, "relative_path"))).as_posix()
        staged_relative = _manifest_text(payload, "staged_relative")
        backup_relative = _manifest_text(payload, "backup_relative")
        expected_staged = _export_operation_relative(relative, operation_id, "staged")
        expected_backup = _export_operation_relative(relative, operation_id, "backup")
        if staged_relative != expected_staged:
            raise StorageError("내보내기 staging 경로가 작업 ID와 일치하지 않습니다.")
        if backup_relative != expected_backup:
            raise StorageError("내보내기 backup 경로가 작업 ID와 일치하지 않습니다.")
        destination = _managed_file_path(self.exports_root, relative, allow_missing=True)
        staged = _managed_file_path(self.exports_root, staged_relative, allow_missing=True)
        backup = _managed_file_path(self.exports_root, backup_relative, allow_missing=True)
        phase_value = payload.get("phase")
        if phase_value is not None and phase_value not in {
            "PREPARED",
            "RENDERED",
            "INSTALLED",
            "DB_COMMITTED",
        }:
            raise StorageError("내보내기 manifest 단계가 올바르지 않습니다.")
        if phase_value == "PREPARED":
            if os.path.lexists(backup):
                raise StorageError("PREPARED 내보내기에 예상하지 못한 backup 파일이 있습니다.")
            if os.path.lexists(staged):
                _unlink_regular(staged, missing_ok=False)
            _remove_export_temporary_files(staged)
            _unlink_regular(path, missing_ok=False)
            return
        new_sha, new_size = _manifest_fingerprint(payload, "sha256", "byte_size")
        previous_file = _manifest_optional_fingerprint(
            payload,
            "previous_file_sha256",
            "previous_file_byte_size",
        )
        previous_db = _manifest_optional_fingerprint(
            payload,
            "previous_db_sha256",
            "previous_db_byte_size",
        )
        with self._connection(uninitialized=True) as connection:
            row = connection.execute(
                "SELECT run_id, sha256, byte_size FROM exports WHERE relative_path = ?",
                (relative,),
            ).fetchone()
        db_is_new = (
            row is not None
            and str(row["run_id"]) == run_id
            and str(row["sha256"]) == new_sha
            and int(row["byte_size"]) == new_size
        )
        db_is_previous = (previous_db is None and row is None) or (
            row is not None
            and previous_db is not None
            and str(row["sha256"]) == previous_db[0]
            and int(row["byte_size"]) == previous_db[1]
        )
        if phase_value == "DB_COMMITTED" and not db_is_new:
            raise StorageError("DB_COMMITTED 내보내기의 DB 기록이 일치하지 않습니다.")
        if db_is_new:
            if os.path.lexists(staged):
                _verify_file_fingerprint(staged, new_sha, new_size)
            if os.path.lexists(backup):
                if previous_file is None:
                    raise StorageError("예상하지 못한 내보내기 backup 파일이 있습니다.")
                _verify_file_fingerprint(backup, *previous_file)
            if os.path.lexists(destination):
                _verify_file_fingerprint(destination, new_sha, new_size)
            elif os.path.lexists(staged):
                destination.parent.mkdir(parents=True, exist_ok=True)
                _replace_file(
                    staged,
                    destination,
                    expected_sha256=new_sha,
                    expected_size=new_size,
                )
            else:
                raise StorageError("등록된 내보내기 파일을 복구할 수 없습니다.")
        elif db_is_previous:
            if os.path.lexists(staged):
                _verify_file_fingerprint(staged, new_sha, new_size)
            if os.path.lexists(backup):
                if previous_file is None:
                    raise StorageError("예상하지 못한 내보내기 backup 파일이 있습니다.")
                _verify_file_fingerprint(backup, *previous_file)
            if previous_file is None:
                if os.path.lexists(destination):
                    _verify_file_fingerprint(destination, new_sha, new_size)
                    _unlink_regular(destination, missing_ok=False)
            else:
                if os.path.lexists(backup):
                    if os.path.lexists(destination):
                        _verify_file_fingerprint(destination, new_sha, new_size)
                        _unlink_regular(destination, missing_ok=False)
                    _replace_file(
                        backup,
                        destination,
                        expected_sha256=previous_file[0],
                        expected_size=previous_file[1],
                    )
                elif os.path.lexists(destination):
                    _verify_file_fingerprint(destination, *previous_file)
                else:
                    raise StorageError("이전 내보내기 파일을 복구할 수 없습니다.")
        else:
            raise StorageError("내보내기 DB 상태가 manifest와 달라 자동 복구할 수 없습니다.")
        for candidate in (staged, backup):
            if os.path.lexists(candidate):
                _unlink_regular(candidate, missing_ok=False)
        _remove_export_temporary_files(staged)
        _unlink_regular(path, missing_ok=False)

    def _recover_external_export_manifest(
        self,
        path: Path,
        payload: dict[str, Any],
    ) -> None:
        operation_id = _manifest_text(payload, "operation_id")
        owner = self._read_external_export_owner(operation_id, payload)
        destination = owner.destination
        staged = _external_export_operation_path(destination, operation_id, "staged")
        backup = _external_export_operation_path(destination, operation_id, "backup")
        phase = payload.get("phase")
        if phase not in {"PREPARED", "RENDERED", "INSTALLED", "DB_COMMITTED"}:
            raise StorageError("외부 내보내기 manifest 단계가 올바르지 않습니다.")
        with self._connection(uninitialized=True) as connection:
            receipt = connection.execute(
                """
                SELECT target_key, run_id, sha256, byte_size
                FROM external_export_commits WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()

        if phase == "PREPARED":
            if receipt is not None:
                raise StorageError("PREPARED 외부 내보내기에 commit receipt가 있습니다.")
            if os.path.lexists(backup):
                raise StorageError("PREPARED 외부 내보내기에 backup 파일이 있습니다.")
            if os.path.lexists(staged):
                _unlink_regular(staged, missing_ok=False)
            _remove_export_temporary_files(staged)
            _unlink_regular(path, missing_ok=False)
            _unlink_regular(owner.path, missing_ok=False)
            return

        new_sha, new_size = _manifest_fingerprint(payload, "sha256", "byte_size")
        previous_file = _manifest_optional_fingerprint(
            payload,
            "previous_file_sha256",
            "previous_file_byte_size",
        )
        database_committed = receipt is not None
        if receipt is not None and (
            str(receipt["target_key"]) != owner.target_key
            or str(receipt["run_id"]) != owner.run_id
            or str(receipt["sha256"]) != new_sha
            or int(receipt["byte_size"]) != new_size
        ):
            raise StorageError("외부 내보내기 commit receipt가 manifest와 다릅니다.")
        if database_committed and phase not in {"INSTALLED", "DB_COMMITTED"}:
            raise StorageError("외부 내보내기 commit receipt와 단계가 일치하지 않습니다.")
        if phase == "DB_COMMITTED" and not database_committed:
            raise StorageError("DB_COMMITTED 외부 내보내기에 commit receipt가 없습니다.")

        if database_committed:
            if not os.path.lexists(destination):
                raise StorageError("완료된 외부 내보내기 파일이 없습니다.")
            _verify_file_fingerprint(destination, new_sha, new_size)
            if os.path.lexists(staged):
                _verify_file_fingerprint(staged, new_sha, new_size)
                _unlink_regular(staged, missing_ok=False)
            if os.path.lexists(backup):
                if previous_file is None:
                    raise StorageError("예상하지 못한 외부 내보내기 backup 파일이 있습니다.")
                _verify_file_fingerprint(backup, *previous_file)
                _unlink_regular(backup, missing_ok=False)
        else:
            if os.path.lexists(staged):
                _verify_file_fingerprint(staged, new_sha, new_size)
            if os.path.lexists(backup):
                if previous_file is None:
                    raise StorageError("예상하지 못한 외부 내보내기 backup 파일이 있습니다.")
                _verify_file_fingerprint(backup, *previous_file)
                if os.path.lexists(destination):
                    _verify_file_fingerprint(destination, new_sha, new_size)
                    _unlink_regular(destination, missing_ok=False)
                _replace_file(
                    backup,
                    destination,
                    expected_sha256=previous_file[0],
                    expected_size=previous_file[1],
                )
            elif previous_file is None:
                if os.path.lexists(destination):
                    _verify_file_fingerprint(destination, new_sha, new_size)
                    _unlink_regular(destination, missing_ok=False)
            elif os.path.lexists(destination):
                _verify_file_fingerprint(destination, *previous_file)
            else:
                raise StorageError("이전 외부 내보내기 파일을 복구할 수 없습니다.")
            if os.path.lexists(staged):
                _unlink_regular(staged, missing_ok=False)

        _remove_export_temporary_files(staged)
        _unlink_regular(path, missing_ok=False)
        _unlink_regular(owner.path, missing_ok=False)
        if database_committed:
            with self._connection(uninitialized=True) as connection:
                deleted = connection.execute(
                    "DELETE FROM external_export_commits WHERE operation_id = ?",
                    (operation_id,),
                ).rowcount
                if deleted != 1:
                    raise StorageError("외부 내보내기 commit receipt를 정리하지 못했습니다.")

    def _recover_orphan_external_export_owners(self) -> None:
        with os.scandir(self._export_owners_root) as entries:
            owner_paths: list[Path] = []
            temporary_paths: list[tuple[Path, str]] = []
            for entry in entries:
                candidate = Path(entry.path)
                reject_link_or_reparse(candidate)
                if entry.is_dir(follow_symlinks=False):
                    raise StorageError("외부 내보내기 소유권 디렉터리에 하위 폴더가 있습니다.")
                if entry.name.endswith(".tmp"):
                    match = _MANIFEST_TEMP_NAME.fullmatch(entry.name)
                    if match is None:
                        raise StorageError("인식할 수 없는 소유권 증표 임시 파일이 있습니다.")
                    temporary_paths.append((candidate, match.group("operation_id")))
                    continue
                if not entry.name.endswith(".json") or not _OPERATION_ID.fullmatch(
                    entry.name.removesuffix(".json")
                ):
                    raise StorageError("인식할 수 없는 외부 내보내기 소유권 증표가 있습니다.")
                owner_paths.append(candidate)

        for candidate, operation_id in sorted(temporary_paths):
            lease = self._acquire_operation_lease(operation_id)
            if lease is None:
                continue
            try:
                _unlink_regular(candidate, missing_ok=False)
            finally:
                _release_run_lease(lease, remove=not os.path.lexists(candidate))

        for candidate in sorted(owner_paths):
            operation_id = candidate.stem
            manifest_path = self._manifests_root / f"{operation_id}.json"
            if os.path.lexists(manifest_path):
                continue
            lease = self._acquire_operation_lease(operation_id)
            if lease is None:
                continue
            try:
                if not os.path.lexists(manifest_path):
                    _unlink_regular(candidate, missing_ok=False)
            finally:
                _release_run_lease(lease, remove=not os.path.lexists(candidate))

    def _recover_orphan_external_export_receipts(self) -> None:
        with self._connection(uninitialized=True) as connection:
            operation_ids = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT operation_id FROM external_export_commits ORDER BY operation_id"
                )
            )
        for operation_id in operation_ids:
            _validate_operation_id(operation_id)
            manifest_path = self._manifests_root / f"{operation_id}.json"
            if os.path.lexists(manifest_path):
                continue
            lease = self._acquire_operation_lease(operation_id)
            if lease is None:
                continue
            try:
                if not os.path.lexists(manifest_path):
                    with self._connection(uninitialized=True) as connection:
                        connection.execute(
                            "DELETE FROM external_export_commits WHERE operation_id = ?",
                            (operation_id,),
                        )
            finally:
                _release_run_lease(lease, remove=not os.path.lexists(manifest_path))

    def _recover_legacy_export_artifacts(self) -> None:
        # v0.3.0 could leave these exact same-directory names after a hard exit.
        pattern = re.compile(r"^\.(?P<name>.+)\.(?P<nonce>[0-9a-f]{32})\.(?P<kind>backup|staged)$")
        candidates: dict[str, list[tuple[Path, str]]] = {}
        leases: dict[str, _RunLease] = {}
        busy_nonces: set[str] = set()
        try:
            for relative in _scan_regular_files(self.exports_root, include_internal=True):
                path = self.exports_root / Path(relative)
                match = pattern.fullmatch(path.name)
                if match is None:
                    continue
                nonce = match.group("nonce")
                if nonce in busy_nonces:
                    continue
                if nonce not in leases:
                    lease = self._acquire_operation_lease(nonce)
                    if lease is None:
                        busy_nonces.add(nonce)
                        continue
                    leases[nonce] = lease
                # A manifest always owns its staged/backup files. It may have
                # appeared after _recover_operations() scanned the directory.
                if os.path.lexists(self._manifests_root / f"{nonce}.json"):
                    continue
                destination = path.with_name(match.group("name"))
                destination_relative = destination.relative_to(self.exports_root).as_posix()
                candidates.setdefault(destination_relative, []).append((path, match.group("kind")))
            if not candidates:
                return
            with self._connection(uninitialized=True) as connection:
                for relative, artifacts in candidates.items():
                    destination = _managed_file_path(
                        self.exports_root, relative, allow_missing=True
                    )
                    row = connection.execute(
                        "SELECT sha256, byte_size FROM exports WHERE relative_path = ?",
                        (relative,),
                    ).fetchone()
                    if row is None:
                        raise StorageError("등록되지 않은 legacy 내보내기 잔여 파일이 있습니다.")
                    expected_sha, expected_size = str(row["sha256"]), int(row["byte_size"])
                    matching = [
                        artifact
                        for artifact, _kind in artifacts
                        if _fingerprint_matches(artifact, expected_sha, expected_size)
                    ]
                    if os.path.lexists(destination):
                        _verify_file_fingerprint(destination, expected_sha, expected_size)
                    elif len(matching) == 1:
                        _replace_file(
                            matching[0],
                            destination,
                            expected_sha256=expected_sha,
                            expected_size=expected_size,
                        )
                    else:
                        raise StorageError("legacy 내보내기 파일 상태가 모호합니다.")
                    for artifact, _kind in artifacts:
                        if os.path.lexists(artifact):
                            _unlink_regular(artifact, missing_ok=False)
        finally:
            for lease in leases.values():
                _release_run_lease(lease, remove=True)

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()
        try:
            self._assert_managed_layout()
        except (UnsafeManagedPath, UnsafeStoragePath) as error:
            raise StorageError(f"관리 저장 경로가 안전하지 않습니다: {error}") from error

    def _require_owned_running_run(self, run_id: str) -> None:
        if run_id not in self._run_leases:
            raise StorageError(
                "RUNNING 상태의 조회 실행은 해당 실행을 시작한 프로세스에서만 변경할 수 있습니다."
            )

    @contextmanager
    def _connection(
        self,
        *,
        uninitialized: bool = False,
        configure_wal: bool = False,
    ) -> Iterator[sqlite3.Connection]:
        if not uninitialized and not self._initialized:
            raise StorageError("데이터베이스가 초기화되지 않았습니다.")
        if self._directory_identities:
            self._assert_managed_layout()
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        if configure_wal:
            mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
            if mode != "wal":
                connection.close()
                raise StorageError("SQLite WAL journal mode를 활성화할 수 없습니다.")
        connection.execute("PRAGMA synchronous = FULL")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _require_run(
        connection: sqlite3.Connection,
        run_id: str,
        *,
        require_running: bool = False,
    ) -> None:
        row = connection.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise StorageError("요청한 조회 실행 기록이 없습니다.")
        if require_running and row["status"] != "RUNNING":
            raise StorageError("RUNNING 상태의 조회 실행에만 기록할 수 있습니다.")

    @staticmethod
    def _raise_missing_or_not_running(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> None:
        row = connection.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise StorageError("종료할 조회 실행 기록이 없습니다.")
        raise StorageError("RUNNING 상태의 조회 실행만 종료할 수 있습니다.")

    def _managed_export_destination(self, path: Path) -> Path | None:
        self._assert_managed_layout()
        exports_root = Path(os.path.abspath(self.exports_root))
        absolute = Path(os.path.abspath(path))
        if absolute == exports_root or not absolute.is_relative_to(exports_root):
            return None
        _reject_managed_chain(exports_root, absolute.parent)
        if os.path.lexists(absolute):
            _managed_file_path(
                exports_root,
                absolute.relative_to(exports_root).as_posix(),
                allow_missing=False,
            )
        return absolute

    def _resolve_export_destination(self, path: Path) -> tuple[Path | None, Path]:
        try:
            managed = self._managed_export_destination(path)
            resolved = self._external_export_destination(path) if managed is None else managed
            self._require_storage_capacity(resolved)
            return managed, resolved
        except StorageError:
            raise
        except (
            OSError,
            UnsafeManagedPath,
            UnsafeStoragePath,
            ValueError,
        ) as error:
            raise StorageError(f"내보내기 경로가 안전하지 않습니다: {error}") from error

    def _external_export_destination(self, path: Path) -> Path:
        """Return one external user path after rejecting application-managed storage."""

        self._assert_managed_layout()
        _validate_external_export_aliases(path)
        absolute = Path(os.path.abspath(path))
        _validate_external_export_aliases(absolute)
        protected_roots = (self.raw_root, self.exports_root, self._operations_root)
        protected_files = {
            self.db_path,
            Path(f"{self.db_path}-journal"),
            Path(f"{self.db_path}-shm"),
            Path(f"{self.db_path}-wal"),
        }
        if absolute in protected_files or any(
            _path_is_within(absolute, root) for root in protected_roots
        ):
            raise StorageError("외부 내보내기 경로가 프로그램 관리 저장소와 겹칩니다.")
        if not absolute.name:
            raise StorageError("외부 내보내기 파일 이름이 올바르지 않습니다.")
        if os.path.lexists(absolute):
            _reject_link_or_reparse(absolute)
            if not stat.S_ISREG(os.lstat(absolute).st_mode):
                raise StorageError("외부 내보내기 대상은 일반 파일이어야 합니다.")
        return absolute

    def _prepare_external_export(
        self,
        run_id: str,
        destination: Path,
    ) -> _ManagedExportStage:
        safe_segment(run_id, "run_id")
        destination = self._external_export_destination(destination)
        parent_info = _ensure_plain_directory(destination.parent)
        destination = self._external_export_destination(destination)
        operation_id = uuid4().hex
        lease = self._acquire_operation_lease(operation_id)
        if lease is None:  # pragma: no cover - UUID collision defense
            raise StorageError("내보내기 작업 잠금을 획득할 수 없습니다.")
        staged = _external_export_operation_path(destination, operation_id, "staged")
        backup = _external_export_operation_path(destination, operation_id, "backup")
        owner_path = self._export_owners_root / f"{operation_id}.json"
        token = secrets.token_hex(32)
        target_key = _external_export_target_key(
            destination,
            int(parent_info.st_dev),
            int(parent_info.st_ino),
        )
        if any(os.path.lexists(path) for path in (staged, backup, owner_path)):
            _release_run_lease(lease, remove=True)
            raise StorageError("외부 내보내기 복구 경로가 이미 존재합니다.")
        owner_payload: dict[str, object] = {
            "version": _MANIFEST_VERSION,
            "kind": "external_export_owner",
            "operation_id": operation_id,
            "run_id": run_id,
            "destination_path": str(destination),
            "target_key": target_key,
            "ownership_token": token,
            "parent_device": int(parent_info.st_dev),
            "parent_inode": int(parent_info.st_ino),
        }
        try:
            _write_json_atomic(owner_path, owner_payload)
            manifest_path = self._write_manifest(
                operation_id,
                {
                    "version": _MANIFEST_VERSION,
                    "kind": "external_export",
                    "destination_scope": "external",
                    "phase": "PREPARED",
                    "operation_id": operation_id,
                    "run_id": run_id,
                    "destination_path": str(destination),
                    "target_key": target_key,
                    "ownership_token": token,
                    "parent_device": int(parent_info.st_dev),
                    "parent_inode": int(parent_info.st_ino),
                },
            )
        except BaseException:
            try:
                _unlink_regular(owner_path, missing_ok=True)
            finally:
                _release_run_lease(lease, remove=True)
            raise
        return _ManagedExportStage(operation_id, staged, lease, manifest_path)

    def _read_external_export_owner(
        self,
        operation_id: str,
        manifest: dict[str, Any],
    ) -> _ExternalExportOwner:
        if (
            manifest.get("kind") != "external_export"
            or manifest.get("destination_scope") != "external"
        ):
            raise StorageError("외부 내보내기 manifest 범위가 올바르지 않습니다.")
        owner_path = self._export_owners_root / f"{operation_id}.json"
        if not os.path.lexists(owner_path):
            raise StorageError("외부 내보내기 소유권 증표가 없습니다.")
        owner = _read_manifest(owner_path, operation_id)
        if owner.get("kind") != "external_export_owner":
            raise StorageError("외부 내보내기 소유권 증표 형식이 올바르지 않습니다.")
        run_id = _manifest_text(owner, "run_id")
        safe_segment(run_id, "run_id")
        destination_text = _manifest_text(owner, "destination_path")
        target_key = _manifest_text(owner, "target_key")
        if re.fullmatch(r"[0-9a-f]{64}", target_key) is None:
            raise StorageError("외부 내보내기 대상 키가 올바르지 않습니다.")
        token = _manifest_text(owner, "ownership_token")
        if re.fullmatch(r"[0-9a-f]{64}", token) is None:
            raise StorageError("외부 내보내기 소유권 토큰이 올바르지 않습니다.")
        parent_device = _manifest_int(owner, "parent_device")
        parent_inode = _manifest_int(owner, "parent_inode")
        expected_manifest_values = {
            "run_id": run_id,
            "destination_path": destination_text,
            "target_key": target_key,
            "ownership_token": token,
            "parent_device": parent_device,
            "parent_inode": parent_inode,
        }
        if any(manifest.get(key) != value for key, value in expected_manifest_values.items()):
            raise StorageError("외부 내보내기 manifest가 소유권 증표와 일치하지 않습니다.")
        destination = Path(destination_text)
        if not destination.is_absolute() or str(Path(os.path.abspath(destination))) != str(
            destination
        ):
            raise StorageError("외부 내보내기 소유권 경로가 정규 절대 경로가 아닙니다.")
        destination = self._external_export_destination(destination)
        _verify_plain_directory_identity(
            destination.parent,
            parent_device,
            parent_inode,
        )
        if target_key != _external_export_target_key(
            destination,
            parent_device,
            parent_inode,
        ):
            raise StorageError("외부 내보내기 대상 키가 소유권 경로와 일치하지 않습니다.")
        return _ExternalExportOwner(
            operation_id=operation_id,
            run_id=run_id,
            destination=destination,
            target_key=target_key,
            token=token,
            parent_device=parent_device,
            parent_inode=parent_inode,
            path=owner_path,
        )

    def _discard_external_export_stage(
        self,
        stage: _ManagedExportStage,
    ) -> BaseException | None:
        cleanup_error: BaseException | None = None
        owner_path = self._export_owners_root / f"{stage.operation_id}.json"
        try:
            manifest = _read_manifest(stage.manifest_path, stage.operation_id)
            owner = self._read_external_export_owner(stage.operation_id, manifest)
            expected_stage = _external_export_operation_path(
                owner.destination,
                stage.operation_id,
                "staged",
            )
            if stage.path != expected_stage:
                raise StorageError("외부 내보내기 staging 경로가 소유권 증표와 다릅니다.")
            if os.path.lexists(stage.path):
                _unlink_regular(stage.path, missing_ok=False)
            _remove_export_temporary_files(stage.path)
            _unlink_regular(stage.manifest_path, missing_ok=True)
            _unlink_regular(owner.path, missing_ok=True)
        except (OSError, StorageError, UnsafeStoragePath, UnsafeManagedPath) as error:
            cleanup_error = error
        try:
            _release_run_lease(stage.lease, remove=cleanup_error is None)
        except (OSError, UnsafeStoragePath, UnsafeManagedPath) as error:
            if cleanup_error is None:
                cleanup_error = error
            else:
                cleanup_error.add_note(
                    f"외부 내보내기 작업 잠금 정리도 실패했습니다: {type(error).__name__}"
                )
        if cleanup_error is None and os.path.lexists(owner_path):
            return StorageError("외부 내보내기 소유권 증표를 정리하지 못했습니다.")
        return cleanup_error

    def _prepare_managed_export(
        self,
        run_id: str,
        destination: Path,
    ) -> _ManagedExportStage:
        safe_segment(run_id, "run_id")
        operation_id = uuid4().hex
        lease = self._acquire_operation_lease(operation_id)
        if lease is None:  # pragma: no cover - UUID collision defense
            raise StorageError("내보내기 작업 잠금을 획득할 수 없습니다.")
        relative = destination.relative_to(self.exports_root).as_posix()
        staged_relative = _export_operation_relative(
            relative,
            operation_id,
            "staged",
        )
        backup_relative = _export_operation_relative(relative, operation_id, "backup")
        staged = self.exports_root / Path(staged_relative)
        if os.path.lexists(staged):  # pragma: no cover - UUID collision defense
            _release_run_lease(lease, remove=True)
            raise StorageError("내보내기 staging 경로가 이미 존재합니다.")
        try:
            manifest_path = self._write_manifest(
                operation_id,
                {
                    "version": _MANIFEST_VERSION,
                    "kind": "export",
                    "phase": "PREPARED",
                    "operation_id": operation_id,
                    "run_id": run_id,
                    "relative_path": relative,
                    "staged_relative": staged_relative,
                    "backup_relative": backup_relative,
                },
            )
        except BaseException:
            _release_run_lease(lease, remove=True)
            raise
        return _ManagedExportStage(operation_id, staged, lease, manifest_path)

    @staticmethod
    def _discard_managed_export_stage(stage: _ManagedExportStage) -> BaseException | None:
        cleanup_error: BaseException | None = None
        try:
            if os.path.lexists(stage.path):
                _unlink_regular(stage.path, missing_ok=False)
            _remove_export_temporary_files(stage.path)
            _unlink_regular(stage.manifest_path, missing_ok=True)
        except (OSError, UnsafeStoragePath, UnsafeManagedPath) as error:
            cleanup_error = error
        try:
            _release_run_lease(stage.lease, remove=cleanup_error is None)
        except (OSError, UnsafeStoragePath, UnsafeManagedPath) as error:
            if cleanup_error is None:
                cleanup_error = error
            else:
                cleanup_error.add_note(
                    f"내보내기 작업 잠금 정리도 실패했습니다: {type(error).__name__}"
                )
        return cleanup_error

    def _commit_managed_export(
        self,
        run_id: str,
        destination: Path,
        stage: _ManagedExportStage,
    ) -> None:
        maintenance = self._acquire_maintenance_lease()
        if maintenance is None:
            cleanup_error = self._discard_managed_export_stage(stage)
            error = StorageError("삭제 또는 다른 저장소 유지보수 작업이 진행 중입니다.")
            if cleanup_error is not None:
                error.add_note(
                    f"내보내기 staging 정리도 실패했습니다: {type(cleanup_error).__name__}"
                )
            raise error
        try:
            self._commit_managed_export_under_maintenance(run_id, destination, stage)
        finally:
            _release_run_lease(maintenance, remove=True)

    def _commit_managed_export_under_maintenance(
        self,
        run_id: str,
        destination: Path,
        stage: _ManagedExportStage,
    ) -> None:
        try:
            self._assert_managed_layout()
            exports_root = self.exports_root
            relative = destination.relative_to(exports_root).as_posix()
            operation_id = stage.operation_id
            staged_relative = _export_operation_relative(relative, operation_id, "staged")
            expected_staged = exports_root / Path(staged_relative)
            if stage.path != expected_staged:
                raise StorageError("내보내기 staging 경로가 작업 ID와 일치하지 않습니다.")
            expected_manifest = self._manifests_root / f"{operation_id}.json"
            if stage.manifest_path != expected_manifest:
                raise StorageError("내보내기 manifest 경로가 작업 ID와 일치하지 않습니다.")
            backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
            backup_relative = backup.relative_to(exports_root).as_posix()
            new_sha, new_size = _file_fingerprint(stage.path)
            previous_file_sha: str | None = None
            previous_file_size: int | None = None
            if os.path.lexists(destination):
                previous_file_sha, previous_file_size = _file_fingerprint(destination)
            with self._connection() as connection:
                self._require_run(connection, run_id)
                previous_row = connection.execute(
                    "SELECT sha256, byte_size FROM exports WHERE relative_path = ?",
                    (relative,),
                ).fetchone()
            previous_db_sha = str(previous_row["sha256"]) if previous_row else None
            previous_db_size = int(previous_row["byte_size"]) if previous_row else None
            if previous_row is not None and (
                previous_file_sha is None
                or previous_file_sha != previous_db_sha
                or previous_file_size != previous_db_size
            ):
                raise StorageError("기존 관리 내보내기 파일의 무결성이 일치하지 않습니다.")
        except (
            OSError,
            StorageError,
            UnsafeManagedPath,
            UnsafeStoragePath,
            ValueError,
        ) as error:
            prepare_cleanup_error = self._discard_managed_export_stage(stage)
            if prepare_cleanup_error is not None:
                error.add_note(
                    "내보내기 준비 실패 후 staging 정리도 실패했습니다: "
                    f"{type(prepare_cleanup_error).__name__}"
                )
            raise
        installed = False
        db_committed = False
        phase_payload: dict[str, object] | None = None
        try:
            phase_payload = {
                "version": _MANIFEST_VERSION,
                "kind": "export",
                "phase": "RENDERED",
                "operation_id": operation_id,
                "run_id": run_id,
                "relative_path": relative,
                "staged_relative": staged_relative,
                "backup_relative": backup_relative,
                "sha256": new_sha,
                "byte_size": new_size,
                "previous_file_sha256": previous_file_sha,
                "previous_file_byte_size": previous_file_size,
                "previous_db_sha256": previous_db_sha,
                "previous_db_byte_size": previous_db_size,
            }
            self._replace_manifest(stage.manifest_path, phase_payload)
            if os.path.lexists(destination):
                assert previous_file_sha is not None
                assert previous_file_size is not None
                _replace_file(
                    destination,
                    backup,
                    expected_sha256=previous_file_sha,
                    expected_size=previous_file_size,
                )
            _replace_file(
                stage.path,
                destination,
                expected_sha256=new_sha,
                expected_size=new_size,
            )
            installed = True
            phase_payload = {**phase_payload, "phase": "INSTALLED"}
            self._replace_manifest(stage.manifest_path, phase_payload)

            # File hashing, durable moves, and manifest fsync are deliberately
            # complete before this short writer transaction.  Recheck the DB
            # receipt state under the lock, then publish only the metadata.
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._require_run(connection, run_id)
                current_row = connection.execute(
                    "SELECT sha256, byte_size FROM exports WHERE relative_path = ?",
                    (relative,),
                ).fetchone()
                current_db = (
                    (str(current_row["sha256"]), int(current_row["byte_size"]))
                    if current_row is not None
                    else None
                )
                previous_db = (
                    (previous_db_sha, previous_db_size)
                    if previous_db_sha is not None and previous_db_size is not None
                    else None
                )
                if current_db != previous_db:
                    raise StorageError("내보내기 설치 중 DB 등록 상태가 변경되었습니다.")
                connection.execute(
                    """
                    INSERT INTO exports (
                        run_id, created_at, relative_path, sha256, byte_size
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(relative_path) DO UPDATE SET
                        run_id = excluded.run_id,
                        created_at = excluded.created_at,
                        sha256 = excluded.sha256,
                        byte_size = excluded.byte_size
                    """,
                    (
                        run_id,
                        _iso(None),
                        relative,
                        new_sha,
                        new_size,
                    ),
                )
            db_committed = True
            phase_payload = {**phase_payload, "phase": "DB_COMMITTED"}
            self._replace_manifest(stage.manifest_path, phase_payload)
        except (
            OSError,
            sqlite3.Error,
            StorageError,
            UnsafeManagedPath,
            UnsafeStoragePath,
        ) as error:
            if db_committed:
                try:
                    _release_run_lease(stage.lease, remove=False)
                except (OSError, UnsafeManagedPath, UnsafeStoragePath) as release_error:
                    error.add_note(
                        f"내보내기 복구 잠금 해제도 실패했습니다: {type(release_error).__name__}"
                    )
                raise StorageError(
                    "관리 내보내기는 완료되었지만 복구 상태 기록을 마치지 못했습니다."
                ) from error
            rollback_error: BaseException | None = None
            try:
                if os.path.lexists(backup):
                    if os.path.lexists(destination):
                        _verify_file_fingerprint(destination, new_sha, new_size)
                        _unlink_regular(destination, missing_ok=False)
                    assert previous_file_sha is not None
                    assert previous_file_size is not None
                    _replace_file(
                        backup,
                        destination,
                        expected_sha256=previous_file_sha,
                        expected_size=previous_file_size,
                    )
                elif installed:
                    _verify_file_fingerprint(destination, new_sha, new_size)
                    _unlink_regular(destination, missing_ok=False)
                if os.path.lexists(stage.path):
                    _unlink_regular(stage.path, missing_ok=False)
                _remove_export_temporary_files(stage.path)
                _unlink_regular(stage.manifest_path, missing_ok=True)
            except (OSError, UnsafeManagedPath, UnsafeStoragePath, StorageError) as restore_error:
                rollback_error = restore_error
            try:
                _release_run_lease(stage.lease, remove=rollback_error is None)
            except (OSError, UnsafeManagedPath, UnsafeStoragePath) as release_error:
                if rollback_error is None:
                    rollback_error = release_error
                else:
                    rollback_error.add_note(
                        f"내보내기 작업 잠금 정리도 실패했습니다: {type(release_error).__name__}"
                    )
            if rollback_error is not None:
                error.add_note(
                    "관리 내보내기 등록 실패 후 이전 상태 정리도 실패했습니다: "
                    f"{type(rollback_error).__name__}"
                )
            raise
        final_cleanup_error: BaseException | None = None
        try:
            if os.path.lexists(backup):
                _unlink_regular(backup, missing_ok=False)
            _remove_export_temporary_files(stage.path)
            _unlink_regular(stage.manifest_path, missing_ok=False)
        except (OSError, UnsafeManagedPath, UnsafeStoragePath) as error:
            final_cleanup_error = error
        try:
            _release_run_lease(stage.lease, remove=final_cleanup_error is None)
        except (OSError, UnsafeManagedPath, UnsafeStoragePath) as error:
            if final_cleanup_error is None:
                final_cleanup_error = error
            else:
                final_cleanup_error.add_note(
                    f"내보내기 작업 잠금 정리도 실패했습니다: {type(error).__name__}"
                )
        if final_cleanup_error is not None:
            raise StorageError(
                "관리 내보내기는 완료되었지만 복구 파일을 정리하지 못했습니다."
            ) from final_cleanup_error

    def _commit_external_export(
        self,
        run_id: str,
        destination: Path,
        stage: _ManagedExportStage,
    ) -> None:
        maintenance = self._acquire_maintenance_lease()
        if maintenance is None:
            cleanup_error = self._discard_external_export_stage(stage)
            error = StorageError("삭제 또는 다른 저장소 유지보수 작업이 진행 중입니다.")
            if cleanup_error is not None:
                error.add_note(
                    f"외부 내보내기 staging 정리도 실패했습니다: {type(cleanup_error).__name__}"
                )
            raise error
        try:
            self._commit_external_export_under_maintenance(run_id, destination, stage)
        finally:
            _release_run_lease(maintenance, remove=True)

    def _commit_external_export_under_maintenance(
        self,
        run_id: str,
        destination: Path,
        stage: _ManagedExportStage,
    ) -> None:
        try:
            manifest = _read_manifest(stage.manifest_path, stage.operation_id)
            owner = self._read_external_export_owner(stage.operation_id, manifest)
            if owner.run_id != run_id or owner.destination != destination:
                raise StorageError("외부 내보내기 대상이 소유권 증표와 일치하지 않습니다.")
            expected_manifest = self._manifests_root / f"{stage.operation_id}.json"
            expected_stage = _external_export_operation_path(
                destination,
                stage.operation_id,
                "staged",
            )
            if stage.manifest_path != expected_manifest or stage.path != expected_stage:
                raise StorageError("외부 내보내기 복구 경로가 작업 ID와 일치하지 않습니다.")
            backup = _external_export_operation_path(
                destination,
                stage.operation_id,
                "backup",
            )
            new_sha, new_size = _file_fingerprint(stage.path)
            previous_file_sha: str | None = None
            previous_file_size: int | None = None
            if os.path.lexists(destination):
                previous_file_sha, previous_file_size = _file_fingerprint(destination)
        except (
            OSError,
            StorageError,
            UnsafeManagedPath,
            UnsafeStoragePath,
            ValueError,
        ) as error:
            prepare_cleanup_error = self._discard_external_export_stage(stage)
            if prepare_cleanup_error is not None:
                error.add_note(
                    "외부 내보내기 준비 실패 후 staging 정리도 실패했습니다: "
                    f"{type(prepare_cleanup_error).__name__}"
                )
            raise

        installed = False
        database_committed = False
        phase_payload: dict[str, object] = {
            **manifest,
            "phase": "RENDERED",
            "sha256": new_sha,
            "byte_size": new_size,
            "previous_file_sha256": previous_file_sha,
            "previous_file_byte_size": previous_file_size,
        }
        try:
            self._replace_manifest(stage.manifest_path, phase_payload)
            if os.path.lexists(destination):
                assert previous_file_sha is not None
                assert previous_file_size is not None
                _verify_file_fingerprint(
                    destination,
                    previous_file_sha,
                    previous_file_size,
                )
                _replace_file(
                    destination,
                    backup,
                    expected_sha256=previous_file_sha,
                    expected_size=previous_file_size,
                )
                _verify_file_fingerprint(
                    backup,
                    previous_file_sha,
                    previous_file_size,
                )
            _replace_file(
                stage.path,
                destination,
                expected_sha256=new_sha,
                expected_size=new_size,
            )
            installed = True
            _verify_file_fingerprint(destination, new_sha, new_size)
            phase_payload = {**phase_payload, "phase": "INSTALLED"}
            self._replace_manifest(stage.manifest_path, phase_payload)

            # Revalidate the external ownership proof before entering the
            # transaction.  The operation and maintenance leases keep this
            # export serialized; SQLite then stores only the small receipt.
            current_owner = self._read_external_export_owner(stage.operation_id, phase_payload)
            if current_owner != owner:
                raise StorageError("외부 내보내기 소유권 증표가 설치 중 변경되었습니다.")
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._require_run(connection, run_id)
                connection.execute(
                    """
                    INSERT INTO external_export_commits (
                        operation_id, target_key, run_id,
                        committed_at, sha256, byte_size
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        stage.operation_id,
                        owner.target_key,
                        run_id,
                        _iso(None),
                        new_sha,
                        new_size,
                    ),
                )
            database_committed = True
            phase_payload = {**phase_payload, "phase": "DB_COMMITTED"}
            self._replace_manifest(stage.manifest_path, phase_payload)
        except (
            OSError,
            sqlite3.Error,
            StorageError,
            UnsafeManagedPath,
            UnsafeStoragePath,
        ) as error:
            if database_committed:
                try:
                    _release_run_lease(stage.lease, remove=False)
                except (OSError, UnsafeManagedPath, UnsafeStoragePath) as release_error:
                    error.add_note(
                        "외부 내보내기 복구 잠금 해제도 실패했습니다: "
                        f"{type(release_error).__name__}"
                    )
                raise StorageError(
                    "외부 내보내기는 완료되었지만 복구 상태를 정리하지 못했습니다."
                ) from error

            rollback_error: BaseException | None = None
            try:
                current_manifest = _read_manifest(stage.manifest_path, stage.operation_id)
                current_owner = self._read_external_export_owner(
                    stage.operation_id,
                    current_manifest,
                )
                if os.path.lexists(backup):
                    if previous_file_sha is None or previous_file_size is None:
                        raise StorageError("예상하지 못한 외부 내보내기 backup 파일이 있습니다.")
                    _verify_file_fingerprint(backup, previous_file_sha, previous_file_size)
                    if os.path.lexists(destination):
                        _verify_file_fingerprint(destination, new_sha, new_size)
                        _unlink_regular(destination, missing_ok=False)
                    _replace_file(
                        backup,
                        destination,
                        expected_sha256=previous_file_sha,
                        expected_size=previous_file_size,
                    )
                elif installed or (previous_file_sha is None and os.path.lexists(destination)):
                    _verify_file_fingerprint(destination, new_sha, new_size)
                    _unlink_regular(destination, missing_ok=False)
                elif previous_file_sha is not None:
                    assert previous_file_size is not None
                    _verify_file_fingerprint(
                        destination,
                        previous_file_sha,
                        previous_file_size,
                    )
                if os.path.lexists(stage.path):
                    _verify_file_fingerprint(stage.path, new_sha, new_size)
                    _unlink_regular(stage.path, missing_ok=False)
                _remove_export_temporary_files(stage.path)
                _unlink_regular(stage.manifest_path, missing_ok=True)
                _unlink_regular(current_owner.path, missing_ok=True)
            except (OSError, UnsafeManagedPath, UnsafeStoragePath, StorageError) as restore_error:
                rollback_error = restore_error
            try:
                _release_run_lease(stage.lease, remove=rollback_error is None)
            except (OSError, UnsafeManagedPath, UnsafeStoragePath) as release_error:
                if rollback_error is None:
                    rollback_error = release_error
                else:
                    rollback_error.add_note(
                        "외부 내보내기 작업 잠금 정리도 실패했습니다: "
                        f"{type(release_error).__name__}"
                    )
            if rollback_error is not None:
                error.add_note(
                    "외부 내보내기 실패 후 이전 상태 정리도 실패했습니다: "
                    f"{type(rollback_error).__name__}"
                )
            raise

        final_cleanup_error: BaseException | None = None
        try:
            final_manifest = _read_manifest(stage.manifest_path, stage.operation_id)
            final_owner = self._read_external_export_owner(
                stage.operation_id,
                final_manifest,
            )
            if final_manifest.get("phase") != "DB_COMMITTED":
                raise StorageError("외부 내보내기 완료 단계가 올바르지 않습니다.")
            if os.path.lexists(backup):
                if previous_file_sha is None or previous_file_size is None:
                    raise StorageError("예상하지 못한 외부 내보내기 backup 파일이 있습니다.")
                _verify_file_fingerprint(backup, previous_file_sha, previous_file_size)
                _unlink_regular(backup, missing_ok=False)
            _remove_export_temporary_files(stage.path)
            _unlink_regular(stage.manifest_path, missing_ok=False)
            _unlink_regular(final_owner.path, missing_ok=False)
            with self._connection() as connection:
                deleted = connection.execute(
                    "DELETE FROM external_export_commits WHERE operation_id = ?",
                    (stage.operation_id,),
                ).rowcount
                if deleted != 1:
                    raise StorageError("외부 내보내기 commit receipt가 일치하지 않습니다.")
        except (OSError, StorageError, UnsafeManagedPath, UnsafeStoragePath) as error:
            final_cleanup_error = error
        try:
            _release_run_lease(stage.lease, remove=final_cleanup_error is None)
        except (OSError, UnsafeManagedPath, UnsafeStoragePath) as error:
            if final_cleanup_error is None:
                final_cleanup_error = error
            else:
                final_cleanup_error.add_note(
                    f"외부 내보내기 작업 잠금 정리도 실패했습니다: {type(error).__name__}"
                )
        if final_cleanup_error is not None:
            raise StorageError(
                "외부 내보내기는 완료되었지만 복구 파일을 정리하지 못했습니다."
            ) from final_cleanup_error

    def _verify_run_raw_integrity(
        self,
        run_id: str,
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> None:
        """Verify Raw artifacts without retaining a long SQLite read snapshot."""

        last_id = 0
        verified_files = 0
        verified_bytes = 0
        with self._connection() as connection:
            self._require_run(connection, run_id)
            totals = connection.execute(
                """
                SELECT count(*), coalesce(sum(byte_size), 0)
                FROM raw_files WHERE run_id = ?
                """,
                (run_id,),
            ).fetchone()
        file_total = int(totals[0])
        byte_total = int(totals[1])
        if file_total == 0:
            return
        while True:
            _check_cancelled(cancel_check)
            with self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id, relative_path, sha256, byte_size
                    FROM raw_files
                    WHERE run_id = ? AND id > ?
                    ORDER BY id
                    LIMIT ?
                    """,
                    (run_id, last_id, _CSV_FETCH_BATCH),
                ).fetchall()
            if not rows:
                break
            for row in rows:
                _check_cancelled(cancel_check)
                path = _managed_file_path(
                    self.raw_root,
                    str(row["relative_path"]),
                    allow_missing=False,
                )
                _verify_file_fingerprint(
                    path,
                    str(row["sha256"]),
                    int(row["byte_size"]),
                    cancel_check=cancel_check,
                    progress=progress,
                    phase="export_raw_bytes",
                    completed_base=verified_bytes,
                    total=byte_total,
                )
                last_id = int(row["id"])
                verified_files += 1
                verified_bytes += int(row["byte_size"])
                _notify_progress(
                    progress,
                    "export_raw_files",
                    verified_files,
                    file_total,
                )

    @staticmethod
    def _latest_report_lifecycle_events(
        connection: sqlite3.Connection,
        run_id: str,
        latest_observations: tuple[dict[str, object], ...],
        *,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
    ) -> tuple[dict[str, object], ...]:
        """Keep only the latest lifecycle row needed by each displayed flow.

        A long-running monitor may contain many lifecycle rows.  The concise
        HTML report needs status only for its latest fifty flows, so retaining
        the complete lifecycle history would defeat the streaming export.
        """

        wanted_flows = {_report_flow_key(row) for row in latest_observations}
        wanted_sessions = {str(row.get("session_key") or "") for row in latest_observations} - {""}
        selected_flows: set[tuple[str, str, str, str, str]] = set()
        selected_sessions: set[str] = set()
        selected: list[dict[str, object]] = []
        cursor = connection.execute(
            """
            SELECT occurred_at, session_key, event_type
            FROM lifecycle_events
            WHERE run_id = ?
            ORDER BY occurred_at DESC, id DESC
            """,
            (run_id,),
        )
        scanned = 0
        while True:
            _check_cancelled(cancel_check)
            rows = cursor.fetchmany(_CSV_FETCH_BATCH)
            if not rows:
                break
            scanned += len(rows)
            _notify_progress(progress, "html_lifecycle", scanned, None)
            for row in rows:
                session_key = str(row["session_key"] or "")
                flow = _report_flow_key_from_session_key(session_key)
                keep_flow = flow in wanted_flows and flow not in selected_flows
                keep_session = (
                    session_key in wanted_sessions and session_key not in selected_sessions
                )
                if not keep_flow and not keep_session:
                    continue
                selected.append(dict(row))
                if keep_flow and flow is not None:
                    selected_flows.add(flow)
                if keep_session:
                    selected_sessions.add(session_key)
            if selected_flows >= wanted_flows and selected_sessions >= wanted_sessions:
                break
        return tuple(selected)

    def _collect_deletion_snapshot(
        self,
        run_id: str | None,
        *,
        connection: sqlite3.Connection | None = None,
        cancel_check: CancelCheck | None = None,
        progress: ProgressCallback | None = None,
        expected: _DeletionSnapshot | None = None,
    ) -> _DeletionSnapshot:
        _check_cancelled(cancel_check)
        if run_id is not None:
            safe_segment(run_id, "run_id")
        try:
            if connection is None:
                with self._connection() as owned_connection:
                    database_state = self._deletion_database_state(owned_connection, run_id)
            else:
                database_state = self._deletion_database_state(connection, run_id)
        except sqlite3.Error as error:
            raise StorageError(f"삭제 대상을 확인할 수 없습니다: {error}") from error

        run_ids, row_counts, registered_raw_paths, registered_export_paths = database_state

        if run_id is None:
            filesystem_raw_paths = set(
                _scan_regular_files(
                    self.raw_root,
                    cancel_check=cancel_check,
                    progress=progress,
                    phase="delete_scan_raw",
                )
            )
            filesystem_export_paths = set(
                _scan_regular_files(
                    self.exports_root,
                    cancel_check=cancel_check,
                    progress=progress,
                    phase="delete_scan_exports",
                )
            )
        else:
            filesystem_raw_paths = set(
                _scan_regular_files(
                    self.raw_root,
                    relative_directory=Path(run_id),
                    cancel_check=cancel_check,
                    progress=progress,
                    phase="delete_scan_raw",
                )
            )
            filesystem_export_paths = set()

        raw_files = _snapshot_managed_files(
            self.raw_root,
            registered_raw_paths | filesystem_raw_paths,
            registered_raw_paths,
            cancel_check=cancel_check,
            progress=progress,
            phase="delete_hash_raw",
            expected_files=expected.raw_files if expected is not None else (),
        )
        export_files = _snapshot_managed_files(
            self.exports_root,
            registered_export_paths | filesystem_export_paths,
            registered_export_paths,
            cancel_check=cancel_check,
            progress=progress,
            phase="delete_hash_exports",
            expected_files=expected.export_files if expected is not None else (),
        )
        total_bytes = sum(item.byte_size for item in raw_files)
        total_bytes += sum(item.byte_size for item in export_files)
        return _DeletionSnapshot(run_ids, row_counts, raw_files, export_files, total_bytes)

    def _require_no_new_deletion_files(
        self,
        run_id: str | None,
        *,
        cancel_check: CancelCheck | None,
        progress: ProgressCallback | None,
    ) -> None:
        remaining_raw = _scan_regular_files(
            self.raw_root,
            relative_directory=Path(run_id) if run_id is not None else None,
            cancel_check=cancel_check,
            progress=progress,
            phase="delete_recheck_raw",
        )
        remaining_exports = (
            _scan_regular_files(
                self.exports_root,
                cancel_check=cancel_check,
                progress=progress,
                phase="delete_recheck_exports",
            )
            if run_id is None
            else ()
        )
        if remaining_raw or remaining_exports:
            raise StorageError("삭제 격리 중 새 관리 파일이 생겼습니다. 다시 확인하십시오.")

    def _require_deletion_database_state(
        self,
        connection: sqlite3.Connection,
        run_id: str | None,
        expected: _DeletionSnapshot,
    ) -> None:
        run_ids, row_counts, raw_paths, export_paths = self._deletion_database_state(
            connection,
            run_id,
        )
        expected_raw_paths = {item.relative_path for item in expected.raw_files if item.registered}
        expected_export_paths = {
            item.relative_path for item in expected.export_files if item.registered
        }
        if (
            run_ids != expected.run_ids
            or row_counts != expected.row_counts
            or raw_paths != expected_raw_paths
            or export_paths != expected_export_paths
        ):
            raise StorageError("미리보기 이후 데이터베이스 기록이 변경되었습니다.")

    def _deletion_database_state(
        self,
        connection: sqlite3.Connection,
        run_id: str | None,
    ) -> tuple[tuple[str, ...], tuple[tuple[str, int], ...], set[str], set[str]]:
        if run_id is None:
            run_rows = connection.execute(
                "SELECT id, status FROM runs ORDER BY started_at, id"
            ).fetchall()
        else:
            self._require_run(connection, run_id)
            run_rows = connection.execute(
                "SELECT id, status FROM runs WHERE id = ?", (run_id,)
            ).fetchall()

        if any(row["status"] == "RUNNING" for row in run_rows):
            raise StorageError("RUNNING 상태의 조회 실행은 중지 후에만 삭제할 수 있습니다.")
        run_ids = tuple(str(row["id"]) for row in run_rows)

        if not run_ids:
            return (
                run_ids,
                tuple((table, 0) for table in _DELETION_TABLES),
                set(),
                set(),
            )

        placeholders = ",".join("?" for _ in run_ids)
        row_counts = tuple(
            (
                table,
                int(
                    connection.execute(
                        f"SELECT count(*) FROM {table} "  # noqa: S608
                        f"WHERE {'id' if table == 'runs' else 'run_id'} "
                        f"IN ({placeholders})",
                        run_ids,
                    ).fetchone()[0]
                ),
            )
            for table in _DELETION_TABLES
        )
        raw_rows = connection.execute(
            f"SELECT run_id, relative_path FROM raw_files "  # noqa: S608
            f"WHERE run_id IN ({placeholders}) ORDER BY relative_path",
            run_ids,
        ).fetchall()
        registered_raw_paths = {
            _validated_raw_relative(str(row["run_id"]), str(row["relative_path"]))
            for row in raw_rows
        }
        registered_export_paths = {
            str(row[0])
            for row in connection.execute(
                f"SELECT relative_path FROM exports "  # noqa: S608
                f"WHERE run_id IN ({placeholders}) ORDER BY relative_path",
                run_ids,
            ).fetchall()
        }
        return run_ids, row_counts, registered_raw_paths, registered_export_paths


def _execute_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA.split(";"):
        normalized = statement.strip()
        if normalized:
            connection.execute(normalized)


def _require_quick_check(connection: sqlite3.Connection) -> None:
    rows = tuple(str(row[0]) for row in connection.execute("PRAGMA quick_check").fetchall())
    if rows != ("ok",):
        raise StorageError("SQLite quick_check가 데이터베이스 손상을 감지했습니다.")


def _require_foreign_key_check(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise StorageError("SQLite 외래 키 무결성 검사가 실패했습니다.")


_REQUIRED_SCHEMA_COLUMNS = {
    "runs": {
        "id",
        "started_at",
        "ended_at",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "bidirectional",
        "status",
    },
    "raw_files": {
        "id",
        "run_id",
        "captured_at",
        "kind",
        "controller_name",
        "relative_path",
        "sha256",
        "byte_size",
    },
    "observations": {
        "id",
        "run_id",
        "raw_file_id",
        "observed_at",
        "controller_name",
        "controller_host",
        "protocol",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "counter",
        "priority",
        "tos",
        "age",
        "destination",
        "tunnel_age",
        "packets",
        "bytes_count",
        "flags",
        "cpu_id",
        "session_key",
    },
    "lifecycle_events": {
        "id",
        "run_id",
        "occurred_at",
        "session_key",
        "instance_id",
        "event_type",
        "controller_name",
        "details_json",
    },
    "controller_events": {
        "id",
        "run_id",
        "occurred_at",
        "previous_controller",
        "current_controller",
        "reason",
    },
    "diagnostic_events": {"id", "run_id", "occurred_at", "stage", "code", "message"},
    "exports": {"id", "run_id", "created_at", "relative_path", "sha256", "byte_size"},
    "external_export_commits": {
        "operation_id",
        "target_key",
        "run_id",
        "committed_at",
        "sha256",
        "byte_size",
    },
}
_REQUIRED_INDEXES = {
    "ix_observations_run_time",
    "ix_observations_run_session_time",
    "ix_lifecycle_run_time",
    "ix_controller_run_time",
    "ix_diagnostic_run_time",
    "ix_raw_files_run_time",
    "ix_exports_run_id",
}


def _validate_schema(connection: sqlite3.Connection) -> None:
    for table, expected in _REQUIRED_SCHEMA_COLUMNS.items():
        columns = {
            str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if not expected.issubset(columns):
            raise StorageError(f"필수 SQLite 테이블 구조가 올바르지 않습니다: {table}")
    indexes = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'"
        ).fetchall()
    }
    if not _REQUIRED_INDEXES.issubset(indexes):
        raise StorageError("필수 SQLite 인덱스가 누락되었습니다.")


def _paths_overlap(left: Path, right: Path) -> bool:
    return _path_is_within(left, right) or _path_is_within(right, left)


def _path_is_within(candidate: Path, root: Path) -> bool:
    absolute_candidate = Path(os.path.abspath(candidate))
    absolute_root = Path(os.path.abspath(root))
    return absolute_candidate == absolute_root or absolute_candidate.is_relative_to(absolute_root)


def _validate_operation_id(value: str) -> str:
    if _OPERATION_ID.fullmatch(value) is None:
        raise StorageError("저장 작업 ID가 올바르지 않습니다.")
    return value


def _acquire_file_lease(path: Path) -> _RunLease | None:
    path = Path(os.path.abspath(path))
    try:
        parent_before = reject_link_or_reparse(path.parent)
    except UnsafeManagedPath as error:
        raise StorageError(str(error)) from error
    if not stat.S_ISDIR(parent_before.st_mode):
        raise StorageError("잠금 파일의 상위 경로가 디렉터리가 아닙니다.")

    open_flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    before: os.stat_result | None = None
    created = False
    try:
        descriptor = os.open(path, open_flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            before = os.lstat(path)
            _validate_lease_file_info(before)
            descriptor = os.open(path, open_flags | getattr(os, "O_NOFOLLOW", 0))
        except UnsafeManagedPath as error:
            raise StorageError(str(error)) from error

    stream = os.fdopen(descriptor, "r+b", buffering=0)
    try:
        opened = os.fstat(stream.fileno())
        path_after_open = os.lstat(path)
        parent_after_open = reject_link_or_reparse(path.parent)
        _validate_lease_file_info(opened)
        _validate_lease_file_info(path_after_open)
        _require_same_file_identity(opened, path_after_open)
        if before is not None:
            _require_same_file_identity(before, opened)
        if not created and before is None:  # pragma: no cover - defensive invariant
            raise StorageError("기존 잠금 파일의 최초 신원을 확인할 수 없습니다.")
        _require_same_directory_identity(parent_before, parent_after_open)

        # Windows byte-range locking needs the first byte to exist.  No write
        # occurs until the opened handle, path, parent, regular-file type,
        # reparse state, and single-link identity all agree.
        if opened.st_size == 0:
            stream.write(b"0")
        stream.seek(0)
        after_write = os.fstat(stream.fileno())
        path_after_write = os.lstat(path)
        parent_after_write = reject_link_or_reparse(path.parent)
        _validate_lease_file_info(after_write)
        _validate_lease_file_info(path_after_write)
        _require_same_file_identity(opened, after_write)
        _require_same_file_identity(after_write, path_after_write)
        _require_same_directory_identity(parent_before, parent_after_write)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                fcntl: Any = importlib.import_module("fcntl")
                fcntl.flock(
                    stream.fileno(),
                    int(fcntl.LOCK_EX) | int(fcntl.LOCK_NB),
                )
        except OSError:
            stream.close()
            return None

        locked = os.fstat(stream.fileno())
        path_after_lock = os.lstat(path)
        parent_after_lock = reject_link_or_reparse(path.parent)
        _validate_lease_file_info(locked)
        _validate_lease_file_info(path_after_lock)
        _require_same_file_identity(after_write, locked)
        _require_same_file_identity(locked, path_after_lock)
        _require_same_directory_identity(parent_before, parent_after_lock)
        return _RunLease(path, stream, int(locked.st_dev), int(locked.st_ino))
    except Exception:
        stream.close()
        raise


def _validate_lease_file_info(info: os.stat_result) -> None:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or (reparse_flag and attributes & reparse_flag)
    ):
        raise StorageError("잠금 경로가 일반 비-reparse 파일이 아닙니다.")
    if int(info.st_nlink) != 1:
        raise StorageError("잠금 파일에는 hardlink를 사용할 수 없습니다.")


def _require_same_file_identity(left: os.stat_result, right: os.stat_result) -> None:
    if (int(left.st_dev), int(left.st_ino)) != (int(right.st_dev), int(right.st_ino)):
        raise StorageError("잠금 파일 경로가 여는 동안 다른 파일로 변경되었습니다.")


def _require_same_directory_identity(left: os.stat_result, right: os.stat_result) -> None:
    if not stat.S_ISDIR(right.st_mode) or (
        int(left.st_dev),
        int(left.st_ino),
    ) != (
        int(right.st_dev),
        int(right.st_ino),
    ):
        raise StorageError("잠금 파일의 상위 경로가 여는 동안 변경되었습니다.")


def _release_run_lease(lease: _RunLease, *, remove: bool) -> None:
    try:
        if not lease.stream.closed:
            lease.stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(lease.stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl: Any = importlib.import_module("fcntl")
                    fcntl.flock(lease.stream.fileno(), int(fcntl.LOCK_UN))
            except OSError:
                # Closing the descriptor below releases the OS lock even when
                # an explicit unlock reports a transient Windows error.
                pass
    finally:
        lease.stream.close()
    if remove:
        _remove_released_lease_with_retry(lease)


def _remove_released_lease_with_retry(lease: _RunLease) -> None:
    delays = (0.0, 0.05, 0.1, 0.2, 0.4)
    for attempt, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        if not os.path.lexists(lease.path):
            return
        try:
            info = os.lstat(lease.path)
        except FileNotFoundError:
            return
        _validate_lease_file_info(info)
        if (int(info.st_dev), int(info.st_ino)) != (lease.device, lease.inode):
            return
        try:
            lease.path.unlink()
            return
        except FileNotFoundError:
            return
        except OSError as error:
            retryable = os.name == "nt" and (
                getattr(error, "winerror", None) in {5, 32, 33}
                or (getattr(error, "winerror", None) is None and isinstance(error, PermissionError))
            )
            if attempt == len(delays) - 1 or not retryable:
                raise


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    data = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    _write_bytes_atomic(path, data)


def _replace_file(
    source: Path,
    destination: Path,
    *,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> None:
    """Replace a file with bounded retries for transient Windows sharing locks."""

    replace_with_retry(
        source,
        destination,
        replace=os.replace,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
    )


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _replace_file(
            temporary,
            path,
            expected_sha256=hashlib.sha256(data).hexdigest(),
            expected_size=len(data),
        )
    finally:
        if os.path.lexists(temporary):
            _unlink_regular(temporary, missing_ok=False)


def _read_manifest(path: Path, operation_id: str) -> dict[str, Any]:
    _validate_operation_id(operation_id)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise StorageError("저장 작업 manifest를 읽을 수 없습니다.") from error
    if not isinstance(payload, dict):
        raise StorageError("저장 작업 manifest 형식이 올바르지 않습니다.")
    if payload.get("version") != _MANIFEST_VERSION:
        raise StorageError("지원하지 않는 저장 작업 manifest 버전입니다.")
    if payload.get("operation_id") != operation_id:
        raise StorageError("저장 작업 manifest ID가 파일명과 일치하지 않습니다.")
    return payload


def _manifest_text(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise StorageError(f"manifest의 {key} 값이 올바르지 않습니다.")
    return value


def _manifest_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StorageError(f"manifest의 {key} 값이 올바르지 않습니다.")
    return value


def _manifest_fingerprint(
    payload: dict[str, Any],
    sha_key: str,
    size_key: str,
) -> tuple[str, int]:
    sha256 = _manifest_text(payload, sha_key)
    if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise StorageError(f"manifest의 {sha_key} 값이 올바르지 않습니다.")
    return sha256, _manifest_int(payload, size_key)


def _manifest_optional_fingerprint(
    payload: dict[str, Any],
    sha_key: str,
    size_key: str,
) -> tuple[str, int] | None:
    sha256 = payload.get(sha_key)
    byte_size = payload.get(size_key)
    if sha256 is None and byte_size is None:
        return None
    if (
        not isinstance(sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        or not isinstance(byte_size, int)
        or isinstance(byte_size, bool)
        or byte_size < 0
    ):
        raise StorageError(f"manifest의 {sha_key}/{size_key} 값이 올바르지 않습니다.")
    return sha256, byte_size


def _manifest_files(payload: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    raw_files = payload.get("files")
    if not isinstance(raw_files, list):
        raise StorageError("manifest 파일 목록이 올바르지 않습니다.")
    result: list[dict[str, Any]] = []
    for value in raw_files:
        if not isinstance(value, dict):
            raise StorageError("manifest 파일 항목이 올바르지 않습니다.")
        relative = _manifest_text(value, "relative_path")
        _safe_relative_parts(relative)
        sha256 = _manifest_text(value, "sha256")
        if re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise StorageError("manifest SHA-256 값이 올바르지 않습니다.")
        result.append(
            {
                "relative_path": relative,
                "sha256": sha256,
                "byte_size": _manifest_int(value, "byte_size"),
                "bundle_sections": _manifest_bundle_sections(value),
            }
        )
    return tuple(result)


def _manifest_bundle_sections(payload: dict[str, Any]) -> tuple[_RawBundleSection, ...]:
    raw_sections = payload.get("bundle_sections", [])
    if not isinstance(raw_sections, list):
        raise StorageError("Raw bundle manifest section 목록이 올바르지 않습니다.")
    sections: list[_RawBundleSection] = []
    for expected_index, value in enumerate(raw_sections, start=1):
        if not isinstance(value, dict):
            raise StorageError("Raw bundle manifest section이 올바르지 않습니다.")
        index = _manifest_int(value, "index")
        sha256 = _manifest_text(value, "sha256")
        if index != expected_index or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
            raise StorageError("Raw bundle manifest section 순서 또는 SHA-256이 올바르지 않습니다.")
        sections.append(
            _RawBundleSection(
                index=index,
                sha256=sha256,
                byte_size=_manifest_int(value, "byte_size"),
            )
        )
    if len(sections) == 1:
        raise StorageError("Raw poll bundle에는 두 개 이상의 section이 필요합니다.")
    return tuple(sections)


def _manifest_delete_files(payload: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    values = payload.get("files")
    if not isinstance(values, list):
        raise StorageError("삭제 manifest 파일 목록이 올바르지 않습니다.")
    result: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            raise StorageError("삭제 manifest 파일 항목이 올바르지 않습니다.")
        category = value.get("category")
        registered = value.get("registered")
        sha256 = value.get("sha256")
        if category not in {"raw", "export"} or not isinstance(registered, bool):
            raise StorageError("삭제 manifest 분류 값이 올바르지 않습니다.")
        if sha256 is not None and (
            not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
        ):
            raise StorageError("삭제 manifest SHA-256 값이 올바르지 않습니다.")
        relative = _manifest_text(value, "relative_path")
        _safe_relative_parts(relative)
        result.append(
            {
                "category": category,
                "registered": registered,
                "relative_path": relative,
                "sha256": sha256,
                "byte_size": _manifest_int(value, "byte_size"),
            }
        )
    return tuple(result)


def _file_fingerprint(
    path: Path,
    *,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
    phase: str = "file_hash",
    completed_base: int = 0,
    total: int | None = None,
) -> tuple[str, int]:
    _check_cancelled(cancel_check)
    _reject_link_or_reparse(path)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeStoragePath("관리 대상은 일반 파일이어야 합니다.")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (int(opened.st_dev), int(opened.st_ino)) != (
            int(info.st_dev),
            int(info.st_ino),
        ):
            raise StorageError("fingerprint 대상 파일이 열기 전에 변경되었습니다.")
        while True:
            _check_cancelled(cancel_check)
            chunk = stream.read(_HASH_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            _notify_progress(progress, phase, completed_base + size, total)
        opened_after = os.fstat(stream.fileno())
    after = os.lstat(path)
    if (
        int(opened_after.st_dev),
        int(opened_after.st_ino),
        int(opened_after.st_size),
        int(opened_after.st_mtime_ns),
    ) != (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
    ) or (
        int(after.st_dev),
        int(after.st_ino),
        int(after.st_size),
        int(after.st_mtime_ns),
    ) != (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mtime_ns),
    ):
        raise StorageError("fingerprint 계산 중 관리 파일이 변경되었습니다.")
    return digest.hexdigest(), size


def _verify_file_fingerprint(
    path: Path,
    sha256: str,
    byte_size: int,
    *,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
    phase: str = "file_hash",
    completed_base: int = 0,
    total: int | None = None,
) -> None:
    if (
        cancel_check is None
        and progress is None
        and phase == "file_hash"
        and completed_base == 0
        and total is None
    ):
        actual_sha, actual_size = _file_fingerprint(path)
    else:
        actual_sha, actual_size = _file_fingerprint(
            path,
            cancel_check=cancel_check,
            progress=progress,
            phase=phase,
            completed_base=completed_base,
            total=total,
        )
    if actual_sha != sha256 or actual_size != byte_size:
        raise StorageError("관리 파일의 SHA-256 또는 크기가 변경되었습니다.")


def _fingerprint_matches(path: Path, sha256: str, byte_size: int) -> bool:
    try:
        _verify_file_fingerprint(path, sha256, byte_size)
    except (OSError, UnsafeStoragePath, StorageError):
        return False
    return True


def _check_cancelled(cancel_check: CancelCheck | None) -> None:
    if cancel_check is not None and cancel_check():
        raise StorageError("작업이 취소되었습니다.", code=ErrorCode.CANCELLED)


def _notify_progress(
    progress: ProgressCallback | None,
    phase: str,
    completed: int,
    total: int | None,
) -> None:
    if progress is not None:
        progress(phase, completed, total)


def _snapshot_managed_files(
    root: Path,
    paths: set[str],
    registered_paths: set[str],
    *,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
    phase: str = "delete_hash",
    expected_files: tuple[_DeletionFile, ...] = (),
) -> tuple[_DeletionFile, ...]:
    result: list[_DeletionFile] = []
    expected_by_path = {item.relative_path: item for item in expected_files}
    ordered = sorted(paths)
    total = len(ordered)
    for index, relative in enumerate(ordered, start=1):
        _check_cancelled(cancel_check)
        path = _managed_file_path(root, relative, allow_missing=True)
        if os.path.lexists(path):
            info = os.lstat(path)
            identity = (int(info.st_dev), int(info.st_ino), int(info.st_mtime_ns))
            expected = expected_by_path.get(relative)
            if (
                expected is not None
                and expected.sha256 is not None
                and expected.byte_size == int(info.st_size)
                and (expected.device, expected.inode, expected.modified_ns) == identity
            ):
                sha256, byte_size = expected.sha256, expected.byte_size
            else:
                sha256, byte_size = _file_fingerprint(path)
            device, inode, modified_ns = identity
        else:
            sha256, byte_size = None, 0
            device, inode, modified_ns = None, None, None
        result.append(
            _DeletionFile(
                relative,
                sha256,
                byte_size,
                relative in registered_paths,
                device,
                inode,
                modified_ns,
            )
        )
        _notify_progress(progress, phase, index, total)
    return tuple(result)


def _iter_cursor_dicts(
    cursor: sqlite3.Cursor,
    *,
    batch_size: int,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
    phase: str = "rows",
    total: int | None = None,
) -> Iterator[dict[str, object]]:
    completed = 0
    while True:
        _check_cancelled(cancel_check)
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        for row in rows:
            yield dict(row)
        completed += len(rows)
        _notify_progress(progress, phase, completed, total)


def _raw_filename_segment(value: str, label: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._-")
    if not normalized:
        raise UnsafeStoragePath(f"{label}은 비어 있을 수 없습니다.")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{normalized[:48]}-{digest}"


def _select_snapshot_observations(
    snapshot: RawSnapshot,
    remaining: dict[str, SessionObservation],
) -> tuple[SessionObservation, ...]:
    if snapshot.observation_keys is None:
        observations = tuple(
            item for item in remaining.values() if item.controller_name == snapshot.device_name
        )
    else:
        observations = tuple(
            remaining[key] for key in snapshot.observation_keys if key in remaining
        )
    for observation in observations:
        remaining.pop(observation.session_key, None)
    return observations


def _raw_bundle_data(
    snapshots: tuple[RawSnapshot, ...],
    section_observations: tuple[tuple[SessionObservation, ...], ...],
) -> tuple[bytes, tuple[_RawBundleSection, ...]]:
    if len(snapshots) != len(section_observations) or len(snapshots) < 2:
        raise ValueError("Raw poll bundle에는 두 개 이상의 일치하는 section이 필요합니다.")
    buffer = io.BytesIO()

    def write_part(part: bytes) -> None:
        if buffer.tell() + len(part) > _MAX_POLL_RAW_BYTES:
            raise StorageError(
                "한 번의 조회에서 저장할 수 있는 Raw bundle 총량을 초과했습니다.",
                code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
            )
        buffer.write(part)

    write_part(_RAW_BUNDLE_MAGIC)
    write_part(
        json.dumps(
            {"snapshot_count": len(snapshots)},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    sections: list[_RawBundleSection] = []
    for index, (snapshot, observations) in enumerate(
        zip(snapshots, section_observations, strict=True),
        start=1,
    ):
        output = snapshot.output.encode("utf-8")
        digest = hashlib.sha256(output).hexdigest()
        section = _RawBundleSection(index, digest, len(output))
        sections.append(section)
        metadata = {
            "command": snapshot.command,
            "device_name": snapshot.device_name,
            "index": index,
            "observation_keys": [item.session_key for item in observations],
            "observed_at": _iso(snapshot.observed_at),
            "output_sha256": digest,
            "output_utf8_bytes": len(output),
        }
        write_part(f"--- BEGIN SNAPSHOT {index} ---\n".encode())
        write_part(
            json.dumps(
                metadata,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        write_part(output)
        write_part(f"\n--- END SNAPSHOT {index} ---\n".encode())
    data = buffer.getvalue()
    _verify_raw_bundle_stream(io.BytesIO(data), tuple(sections))
    return data, tuple(sections)


def _raw_artifact_for_data(
    run_id: str,
    *,
    kind: str,
    controller_name: str,
    data: bytes,
    captured_at: datetime,
) -> RawArtifact:
    run_segment = safe_segment(run_id, "run_id")
    if captured_at.tzinfo is None:
        raise ValueError("시간 값에는 timezone 정보가 필요합니다.")
    captured_utc = captured_at.astimezone(UTC)
    timestamp = captured_utc.strftime("%Y%m%dT%H%M%S.%fZ")
    filename = (
        f"{timestamp}_{_raw_filename_segment(kind, 'kind')}_"
        f"{_raw_filename_segment(controller_name, 'controller_name')}_"
        f"{uuid4().hex[:8]}.txt"
    )
    relative = (
        Path(run_segment) / captured_utc.strftime("%Y%m%d") / captured_utc.strftime("%H") / filename
    ).as_posix()
    return RawArtifact(relative, hashlib.sha256(data).hexdigest(), len(data))


def _raw_artifact_for_batch(
    run_id: str,
    *,
    kind: str,
    controller_name: str,
    content: str,
    captured_at: datetime,
) -> tuple[RawArtifact, bytes]:
    data = content.encode("utf-8")
    return _raw_artifact_for_data(
        run_id,
        kind=kind,
        controller_name=controller_name,
        data=data,
        captured_at=captured_at,
    ), data


def _verify_raw_bundle_file(
    path: Path,
    sections: tuple[_RawBundleSection, ...],
) -> None:
    with path.open("rb") as stream:
        _verify_raw_bundle_stream(stream, sections)


def _verify_raw_bundle_stream(
    stream: BinaryIO,
    sections: tuple[_RawBundleSection, ...],
) -> None:
    if stream.readline() != _RAW_BUNDLE_MAGIC:
        raise StorageError("Raw poll bundle 헤더가 올바르지 않습니다.")
    try:
        header = json.loads(stream.readline().decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise StorageError("Raw poll bundle 메타데이터를 읽을 수 없습니다.") from error
    if not isinstance(header, dict) or header.get("snapshot_count") != len(sections):
        raise StorageError("Raw poll bundle section 수가 일치하지 않습니다.")
    for section in sections:
        if stream.readline() != f"--- BEGIN SNAPSHOT {section.index} ---\n".encode():
            raise StorageError("Raw poll bundle section 시작 위치가 올바르지 않습니다.")
        try:
            metadata = json.loads(stream.readline().decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise StorageError("Raw poll bundle section 메타데이터를 읽을 수 없습니다.") from error
        if (
            not isinstance(metadata, dict)
            or metadata.get("index") != section.index
            or metadata.get("output_sha256") != section.sha256
            or metadata.get("output_utf8_bytes") != section.byte_size
            or not isinstance(metadata.get("device_name"), str)
            or not isinstance(metadata.get("command"), str)
            or not isinstance(metadata.get("observed_at"), str)
            or not isinstance(metadata.get("observation_keys"), list)
            or not all(isinstance(value, str) for value in metadata["observation_keys"])
        ):
            raise StorageError("Raw poll bundle section 메타데이터가 manifest와 다릅니다.")
        digest = hashlib.sha256()
        remaining = section.byte_size
        while remaining:
            chunk = stream.read(min(_HASH_CHUNK_SIZE, remaining))
            if not chunk:
                raise StorageError("Raw poll bundle section 본문이 잘렸습니다.")
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.hexdigest() != section.sha256:
            raise StorageError("Raw poll bundle section SHA-256이 일치하지 않습니다.")
        if stream.read(1) != b"\n" or stream.readline() != (
            f"--- END SNAPSHOT {section.index} ---\n".encode()
        ):
            raise StorageError("Raw poll bundle section 종료 위치가 올바르지 않습니다.")
    if stream.read(1):
        raise StorageError("Raw poll bundle 뒤에 예상하지 못한 데이터가 있습니다.")


def _insert_raw_file(
    connection: sqlite3.Connection,
    run_id: str,
    item: _PreparedRaw,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO raw_files (
            run_id, captured_at, kind, controller_name,
            relative_path, sha256, byte_size
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            _iso(item.captured_at),
            item.kind,
            item.controller_name,
            item.artifact.relative_path,
            item.artifact.sha256,
            item.artifact.byte_size,
        ),
    )
    return _last_row_id(cursor)


def _insert_observations(
    connection: sqlite3.Connection,
    run_id: str,
    observations: Iterable[SessionObservation],
    raw_file_id: int | None,
) -> None:
    connection.executemany(
        """
        INSERT INTO observations (
            run_id, raw_file_id, observed_at, controller_name,
            controller_host, protocol, source_ip, destination_ip,
            source_port, destination_port, counter, priority, tos,
            age, destination, tunnel_age, packets, bytes_count,
            flags, cpu_id, session_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            (
                run_id,
                raw_file_id,
                _iso(observation.observed_at),
                observation.controller_name,
                observation.controller_host,
                observation.protocol,
                observation.source_ip,
                observation.destination_ip,
                observation.source_port,
                observation.destination_port,
                observation.counter,
                observation.priority,
                observation.tos,
                observation.age,
                observation.destination,
                observation.tunnel_age,
                observation.packets,
                observation.bytes_count,
                observation.flags,
                observation.cpu_id,
                observation.session_key,
            )
            for observation in observations
        ),
    )


def _insert_diagnostic(
    connection: sqlite3.Connection,
    run_id: str,
    event: DiagnosticEvent,
) -> None:
    connection.execute(
        """
        INSERT INTO diagnostic_events (run_id, occurred_at, stage, code, message)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            run_id,
            _iso(event.occurred_at),
            _sanitize_diagnostic(event.stage),
            event.code.value if event.code is not None else None,
            _sanitize_diagnostic(event.message),
        ),
    )


def _insert_lifecycle_event(
    connection: sqlite3.Connection,
    run_id: str,
    event: LifecycleEvent,
) -> None:
    previous = event.previous_observation
    current = event.observation
    details: dict[str, object] = {"miss_count": event.miss_count}
    if previous is not None:
        details.update(
            {
                "previous_flags": previous.flags,
                "packet_delta": _numeric_delta(current.packets, previous.packets),
                "byte_delta": _numeric_delta(current.bytes_count, previous.bytes_count),
            }
        )
    event_type = _event_name(str(event.event_type.value), "event_type")
    connection.execute(
        """
        INSERT INTO lifecycle_events (
            run_id, occurred_at, session_key, instance_id, event_type,
            controller_name, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            _iso(event.occurred_at),
            current.session_key,
            _instance_id(event.instance_id),
            event_type,
            current.controller_name,
            json.dumps(details, ensure_ascii=False, sort_keys=True),
        ),
    )
    if event_type == "CONTROLLER_CHANGED" and previous is not None:
        connection.execute(
            """
            INSERT INTO controller_events (
                run_id, occurred_at, previous_controller, current_controller, reason
            ) VALUES (?, ?, ?, ?, 'CURRENT_SWITCH_CHANGED')
            """,
            (
                run_id,
                _iso(event.occurred_at),
                previous.controller_name,
                current.controller_name,
            ),
        )


def _numeric_delta(current: int | None, previous: int | None) -> int | None:
    if current is None or previous is None:
        return None
    return current - previous


def _report_flow_key(row: dict[str, object]) -> tuple[str, str, str, str, str]:
    return (
        str(row.get("protocol") or ""),
        str(row.get("source_ip") or ""),
        str(row.get("destination_ip") or ""),
        str(row.get("source_port") if row.get("source_port") is not None else ""),
        str(row.get("destination_port") if row.get("destination_port") is not None else ""),
    )


def _report_flow_key_from_session_key(
    session_key: str,
) -> tuple[str, str, str, str, str] | None:
    parts = session_key.split("|")
    if len(parts) != 6:
        return None
    return parts[1], parts[2], parts[3], parts[4], parts[5]


def _reject_managed_chain(root: Path, directory: Path) -> None:
    root_absolute = Path(os.path.abspath(root))
    directory_absolute = Path(os.path.abspath(directory))
    root_info = os.lstat(root_absolute)
    _reject_link_or_reparse(root_absolute)
    if not stat.S_ISDIR(root_info.st_mode):
        raise UnsafeStoragePath("관리 루트가 디렉터리가 아닙니다.")
    root_identity = int(root_info.st_dev), int(root_info.st_ino)

    # Walk the caller's original namespace upward instead of resolving the
    # child first.  This catches every junction component and treats Windows
    # 8.3 and long-name spellings as the same root by their directory identity,
    # in either alias direction.  Missing tail components are allowed because
    # callers also validate paths before creating them.
    current = directory_absolute
    while True:
        if os.path.lexists(current):
            info = os.lstat(current)
            _reject_link_or_reparse(current)
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafeStoragePath("관리 경로 구성 요소가 디렉터리가 아닙니다.")
            if (int(info.st_dev), int(info.st_ino)) == root_identity:
                return
        parent = current.parent
        if parent == current:
            break
        current = parent
    raise UnsafeStoragePath("관리 경로가 루트 밖을 가리킵니다.")


def _unlink_regular(path: Path, *, missing_ok: bool) -> None:
    if not os.path.lexists(path):
        if missing_ok:
            return
        raise FileNotFoundError(path)
    _reject_link_or_reparse(path)
    if not stat.S_ISREG(os.lstat(path).st_mode):
        raise UnsafeStoragePath("정리 대상이 일반 파일이 아닙니다.")
    path.unlink()


def _remove_tree_strict(root: Path) -> None:
    _reject_link_or_reparse(root)
    if not stat.S_ISDIR(os.lstat(root).st_mode):
        raise UnsafeStoragePath("정리 대상 staging 경로가 디렉터리가 아닙니다.")
    directories: list[Path] = [root]
    ordered: list[Path] = []
    while directories:
        directory = directories.pop()
        ordered.append(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                _reject_link_or_reparse(path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    directories.append(path)
                elif stat.S_ISREG(mode):
                    path.unlink()
                else:
                    raise UnsafeStoragePath("staging 경로에 일반 파일이 아닌 항목이 있습니다.")
    for directory in reversed(ordered):
        directory.rmdir()


def _database_references_file(
    connection: sqlite3.Connection,
    category: str,
    relative: str,
) -> bool:
    table = "raw_files" if category == "raw" else "exports"
    return (
        connection.execute(
            f"SELECT 1 FROM {table} WHERE relative_path = ?",  # noqa: S608
            (relative,),
        ).fetchone()
        is not None
    )


def _reconcile_deleted_file(
    canonical: Path,
    staged: Path,
    *,
    sha256: str | None,
    byte_size: int,
    should_restore: bool,
) -> None:
    canonical_exists = os.path.lexists(canonical)
    staged_exists = os.path.lexists(staged)
    if sha256 is None:
        if canonical_exists or staged_exists:
            raise StorageError("삭제 manifest에 없던 파일이 복구 경로에 존재합니다.")
        return
    if canonical_exists:
        _verify_file_fingerprint(canonical, sha256, byte_size)
    if staged_exists:
        _verify_file_fingerprint(staged, sha256, byte_size)
    if should_restore:
        if not canonical_exists and staged_exists:
            canonical.parent.mkdir(parents=True, exist_ok=True)
            _replace_file(
                staged,
                canonical,
                expected_sha256=sha256,
                expected_size=byte_size,
            )
        elif canonical_exists and staged_exists:
            staged.unlink()
        elif not canonical_exists:
            raise StorageError("삭제 중 격리된 파일을 복원할 수 없습니다.")
    else:
        if canonical_exists:
            raise StorageError("삭제 완료 상태에 예상하지 못한 원본 파일이 있습니다.")
        if staged_exists:
            staged.unlink()


_DELETION_TABLES = (
    "runs",
    "observations",
    "lifecycle_events",
    "controller_events",
    "diagnostic_events",
    "raw_files",
    "exports",
)


def _single_controller_name(observations: tuple[SessionObservation, ...]) -> str:
    names = {observation.controller_name for observation in observations}
    if len(names) != 1:
        raise StorageError("Raw 출력의 Controller 이름을 명시하십시오.")
    return names.pop()


def _last_row_id(cursor: sqlite3.Cursor) -> int:
    value = cursor.lastrowid
    if value is None:
        raise StorageError("SQLite가 생성된 행 ID를 반환하지 않았습니다.")
    return value


def _iso(value: datetime | None) -> str:
    result = value or datetime.now(UTC)
    if result.tzinfo is None:
        raise ValueError("시간 값에는 timezone 정보가 필요합니다.")
    return result.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event_name(value: str, label: str) -> str:
    normalized = value.strip().upper()
    if _EVENT_NAME.fullmatch(normalized) is None:
        raise ValueError(f"{label}은 영문 대문자, 숫자, 밑줄만 사용할 수 있습니다.")
    return normalized


def _instance_id(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("instance_id는 문자열이어야 합니다.")
    normalized = value.strip()
    if not normalized or len(normalized) > 128:
        raise ValueError("instance_id는 1~128자여야 합니다.")
    return normalized


def _sanitize_diagnostic(value: str) -> str:
    masked = _IPV4_TEXT.sub("<IPv4>", value)
    return _CREDENTIAL_TEXT.sub(lambda match: f"{match.group(1)}=<REDACTED>", masked)


def _managed_size(root: Path, relative: str) -> int:
    path = _managed_file_path(root, relative, allow_missing=True)
    if not os.path.lexists(path):
        return 0
    return path.stat().st_size


def _validated_raw_relative(run_id: str, relative: str) -> str:
    parts = _safe_relative_parts(relative)
    if len(parts) < 2 or parts[0] != run_id:
        raise UnsafeStoragePath("Raw 파일 경로가 실행 ID 디렉터리와 일치하지 않습니다.")
    return Path(*parts).as_posix()


def _export_operation_relative(relative: str, operation_id: str, kind: str) -> str:
    _validate_operation_id(operation_id)
    if kind not in {"backup", "staged"}:
        raise ValueError("지원하지 않는 내보내기 작업 파일 종류입니다.")
    path = Path(*_safe_relative_parts(relative))
    return path.with_name(f".{path.name}.{operation_id}.{kind}").as_posix()


def _external_export_operation_path(
    destination: Path,
    operation_id: str,
    kind: str,
) -> Path:
    _validate_operation_id(operation_id)
    if kind not in {"backup", "staged"}:
        raise ValueError("지원하지 않는 외부 내보내기 작업 파일 종류입니다.")
    absolute = Path(os.path.abspath(destination))
    if not absolute.name:
        raise UnsafeStoragePath("외부 내보내기 파일 이름이 올바르지 않습니다.")
    return absolute.with_name(f".{absolute.name}.{operation_id}.{kind}")


def _external_export_target_key(
    destination: Path,
    parent_device: int,
    parent_inode: int,
) -> str:
    normalized = os.path.normcase(str(Path(os.path.abspath(destination))))
    payload = f"{parent_device}\0{parent_inode}\0{normalized}".encode()
    return hashlib.sha256(payload).hexdigest()


def _external_recovery_target_unavailable(error: OSError) -> bool:
    if isinstance(error, (FileNotFoundError, NotADirectoryError)):
        return True
    return getattr(error, "winerror", None) in {2, 3, 21, 53, 64, 67, 121, 1231}


def _validate_external_export_aliases(path: Path) -> None:
    if os.name != "nt":
        return
    text = str(path).replace("/", "\\")
    lowered = text.casefold()
    if lowered.startswith(("\\\\?\\", "\\\\.\\", "\\??\\")):
        raise StorageError("Windows 장치 경로에는 내보낼 수 없습니다.")
    anchor = Path(path.anchor)
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    for part in path.relative_to(anchor).parts:
        if part.endswith((" ", ".")) or ":" in part:
            raise StorageError("Windows 별칭 또는 ADS 경로에는 내보낼 수 없습니다.")
        base = part.split(".", 1)[0].upper()
        if base in reserved:
            raise StorageError("Windows 예약 장치 이름에는 내보낼 수 없습니다.")


def _plain_directory_info(directory: Path, *, create: bool) -> os.stat_result:
    absolute = Path(os.path.abspath(directory))
    anchor = Path(absolute.anchor)
    if not absolute.is_absolute() or not anchor.anchor:
        raise UnsafeStoragePath("외부 내보내기 디렉터리가 절대 경로가 아닙니다.")
    current = anchor
    if not os.path.lexists(current):
        raise FileNotFoundError(current)
    _reject_link_or_reparse(current)
    if not stat.S_ISDIR(os.lstat(current).st_mode):
        raise NotADirectoryError(current)
    for part in absolute.relative_to(anchor).parts:
        current /= part
        if not os.path.lexists(current):
            if not create:
                raise FileNotFoundError(current)
            with suppress(FileExistsError):
                current.mkdir()
        _reject_link_or_reparse(current)
        if not stat.S_ISDIR(os.lstat(current).st_mode):
            raise NotADirectoryError(current)
    return os.lstat(absolute)


def _ensure_plain_directory(directory: Path) -> os.stat_result:
    return _plain_directory_info(directory, create=True)


def _verify_plain_directory_identity(
    directory: Path,
    expected_device: int,
    expected_inode: int,
) -> None:
    info = _plain_directory_info(directory, create=False)
    if (int(info.st_dev), int(info.st_ino)) != (expected_device, expected_inode):
        raise StorageError("외부 내보내기 디렉터리가 준비 이후 변경되었습니다.")


def _remove_export_temporary_files(staged: Path) -> None:
    parent = staged.parent
    if not os.path.lexists(parent):
        return
    _reject_link_or_reparse(parent)
    prefix = f".{staged.name}."
    with os.scandir(parent) as entries:
        candidates = [
            Path(entry.path)
            for entry in entries
            if entry.name.startswith(prefix) and entry.name.endswith(".tmp")
        ]
    for candidate in candidates:
        _unlink_regular(candidate, missing_ok=False)


def _safe_relative_parts(relative: str | Path) -> tuple[str, ...]:
    path = Path(relative)
    if path.is_absolute() or not path.parts:
        raise UnsafeStoragePath("관리 경로는 비어 있지 않은 상대 경로여야 합니다.")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafeStoragePath("관리 경로에 상위 또는 빈 경로 요소가 있습니다.")
    return tuple(path.parts)


def _managed_file_path(root: Path, relative: str, *, allow_missing: bool) -> Path:
    parts = _safe_relative_parts(relative)
    if os.path.lexists(root):
        _reject_link_or_reparse(root)
    root_resolved = root.resolve(strict=False)
    current = root_resolved
    for part in parts:
        current /= part
        if os.path.lexists(current):
            _reject_link_or_reparse(current)
    path = contained_path(root_resolved, Path(*parts))
    if os.path.lexists(path):
        mode = os.lstat(path).st_mode
        if not stat.S_ISREG(mode):
            raise UnsafeStoragePath("관리 대상은 일반 파일이어야 합니다.")
    elif not allow_missing:
        raise FileNotFoundError(path)
    return path


def _reject_link_or_reparse(path: Path) -> None:
    info = os.lstat(path)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or (reparse_flag and attributes & reparse_flag):
        raise UnsafeStoragePath("심볼릭 링크나 reparse point는 관리 대상으로 삭제할 수 없습니다.")


def _regular_file_size(path: Path) -> int:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or (reparse_flag and attributes & reparse_flag):
        raise UnsafeStoragePath("심볼릭 링크나 reparse point는 관리 대상으로 삭제할 수 없습니다.")
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeStoragePath("저장소 크기 확인 대상이 일반 파일이 아닙니다.")
    return int(info.st_size)


def _directory_revision(path: Path) -> tuple[int, int, int]:
    _reject_link_or_reparse(path)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeStoragePath("저장소 대조 루트가 디렉터리가 아닙니다.")
    return int(info.st_dev), int(info.st_ino), int(info.st_mtime_ns)


def _storage_tree_stats(
    root: Path,
    *,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
    phase: str = "storage_scan",
) -> tuple[int, int]:
    files = _scan_regular_files(
        root,
        include_internal=True,
        cancel_check=cancel_check,
        progress=progress,
        phase=phase,
    )
    total_bytes = 0
    total = len(files)
    for index, relative in enumerate(files, start=1):
        _check_cancelled(cancel_check)
        total_bytes += _regular_file_size(root / Path(relative))
        _notify_progress(progress, f"{phase}_sizes", index, total)
    return total_bytes, total


def _minimum_free_bytes(paths: Iterable[Path]) -> int:
    roots = {Path(os.path.abspath(path)) for path in paths}
    if not roots:
        raise ValueError("여유 공간 확인 경로가 필요합니다.")
    return min(int(shutil.disk_usage(path).free) for path in roots)


def _nearest_existing_directory(path: Path) -> Path:
    current = Path(os.path.abspath(path))
    while not os.path.lexists(current):
        parent = current.parent
        if parent == current:
            raise FileNotFoundError(path)
        current = parent
    if not current.is_dir():
        raise NotADirectoryError(current)
    return current


def _scan_regular_files(
    root: Path,
    *,
    relative_directory: Path | None = None,
    include_internal: bool = False,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
    phase: str = "scan_files",
) -> tuple[str, ...]:
    if os.path.lexists(root):
        _reject_link_or_reparse(root)
    root_resolved = root.resolve(strict=False)
    if relative_directory is None:
        start = root_resolved
    else:
        parts = _safe_relative_parts(relative_directory)
        start = contained_path(root_resolved, Path(*parts))
        if os.path.lexists(start):
            current = root_resolved
            for part in parts:
                current /= part
                _reject_link_or_reparse(current)

    if not os.path.lexists(start):
        return ()
    _reject_link_or_reparse(start)
    if not stat.S_ISDIR(os.lstat(start).st_mode):
        raise UnsafeStoragePath("관리 루트 아래 탐색 대상은 디렉터리여야 합니다.")

    files: list[str] = []
    directories = [start]
    while directories:
        _check_cancelled(cancel_check)
        directory = directories.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                _check_cancelled(cancel_check)
                path = Path(entry.path)
                _reject_link_or_reparse(path)
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    if not include_internal and (
                        entry.name.startswith(".delete-staging-")
                        or entry.name.startswith(".raw-staging-")
                    ):
                        continue
                    directories.append(path)
                elif stat.S_ISREG(mode):
                    files.append(path.relative_to(root_resolved).as_posix())
                    _notify_progress(progress, phase, len(files), None)
                else:
                    raise UnsafeStoragePath("관리 루트에 일반 파일이 아닌 항목이 있습니다.")
    return tuple(sorted(files))


def _stage_files(
    root: Path,
    files: tuple[_DeletionFile, ...],
    preview_id: str,
    category: str,
    staged: list[_StagedFile],
    *,
    cancel_check: CancelCheck | None = None,
    progress: ProgressCallback | None = None,
) -> None:
    if not files:
        return
    stage_name = f".delete-staging-{safe_segment(preview_id, 'preview_id')}"
    stage_root = contained_path(root, Path(stage_name))
    if os.path.lexists(stage_root):
        raise UnsafeStoragePath("삭제 격리 디렉터리가 이미 있습니다.")

    total = len(files)
    for index, item in enumerate(files, start=1):
        _check_cancelled(cancel_check)
        relative = item.relative_path
        source = _managed_file_path(root, relative, allow_missing=True)
        if not os.path.lexists(source):
            if item.sha256 is not None:
                raise StorageError("삭제 미리보기의 관리 파일이 사라졌습니다.")
            continue
        if item.sha256 is None:
            raise StorageError("삭제 미리보기 이후 관리 파일이 새로 생겼습니다.")
        source_info = os.lstat(source)
        if (
            int(source_info.st_size) != item.byte_size
            or int(source_info.st_dev) != item.device
            or int(source_info.st_ino) != item.inode
            or int(source_info.st_mtime_ns) != item.modified_ns
        ):
            raise StorageError("삭제 격리 직전에 관리 파일이 변경되었습니다.")
        parts = _safe_relative_parts(relative)
        destination = contained_path(stage_root, Path(*parts))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(destination):
            raise UnsafeStoragePath("삭제 격리 경로가 이미 있습니다.")
        _replace_file(
            source,
            destination,
            expected_sha256=item.sha256,
            expected_size=item.byte_size,
        )
        staged.append(
            _StagedFile(
                source,
                destination,
                category,
                relative,
                item.sha256,
                item.byte_size,
                item.registered,
                int(source_info.st_dev),
                int(source_info.st_ino),
                int(source_info.st_mtime_ns),
            )
        )
        _verify_file_fingerprint(destination, item.sha256, item.byte_size)
        _notify_progress(progress, f"delete_stage_{category}", index, total)


def _restore_staged_files(staged: list[_StagedFile]) -> OSError | None:
    first_error: OSError | None = None
    for item in reversed(staged):
        try:
            if os.path.lexists(item.source):
                raise FileExistsError(item.source)
            _verify_file_fingerprint(item.destination, item.sha256, item.byte_size)
            item.source.parent.mkdir(parents=True, exist_ok=True)
            _replace_file(
                item.destination,
                item.source,
                expected_sha256=item.sha256,
                expected_size=item.byte_size,
            )
        except (OSError, UnsafeStoragePath, StorageError) as error:
            if first_error is None:
                first_error = OSError(str(error))
    _remove_staging_directories(staged)
    return first_error


def _verify_staged_file_identities(staged: list[_StagedFile]) -> None:
    """Perform a metadata-only recheck while the SQLite write lock is held."""

    for item in staged:
        info = reject_link_or_reparse(item.destination)
        if (
            not stat.S_ISREG(info.st_mode)
            or int(info.st_dev) != item.device
            or int(info.st_ino) != item.inode
            or int(info.st_size) != item.byte_size
            or int(info.st_mtime_ns) != item.modified_ns
        ):
            raise StorageError("삭제 격리 파일이 데이터베이스 반영 직전에 변경되었습니다.")


def _purge_staged_files(staged: list[_StagedFile]) -> None:
    for item in staged:
        _reject_link_or_reparse(item.destination)
        if not stat.S_ISREG(os.lstat(item.destination).st_mode):
            raise UnsafeStoragePath("격리된 삭제 대상이 일반 파일이 아닙니다.")
        _verify_file_fingerprint(item.destination, item.sha256, item.byte_size)
        item.destination.unlink()
    _remove_staging_directories(staged)


def _remove_staging_directories(staged: list[_StagedFile]) -> None:
    directories = {
        parent
        for item in staged
        for parent in item.destination.parents
        if parent.name.startswith(".delete-staging-")
        or any(ancestor.name.startswith(".delete-staging-") for ancestor in parent.parents)
    }
    for directory in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        try:
            directory.rmdir()
        except (FileNotFoundError, OSError):
            continue


def _remove_known_empty_run_directories(root: Path, run_ids: tuple[str, ...]) -> None:
    for run_id in run_ids:
        run_directory = contained_path(root, Path(run_id))
        if not os.path.lexists(run_directory):
            continue
        _reject_link_or_reparse(run_directory)
        if not stat.S_ISDIR(os.lstat(run_directory).st_mode):
            raise UnsafeStoragePath("Raw 실행 경로가 디렉터리가 아닙니다.")
        directories = [run_directory]
        ordered: list[Path] = []
        while directories:
            directory = directories.pop()
            ordered.append(directory)
            with os.scandir(directory) as entries:
                for entry in entries:
                    path = Path(entry.path)
                    _reject_link_or_reparse(path)
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(path)
        for directory in reversed(ordered):
            try:
                directory.rmdir()
            except (FileNotFoundError, OSError):
                continue
