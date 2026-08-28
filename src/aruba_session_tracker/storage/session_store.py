"""SQLite-backed session history and safe manual deletion workflow."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO
from uuid import uuid4

from aruba_session_tracker.models import DiagnosticEvent, QueryRequest, SessionObservation
from aruba_session_tracker.paths import (
    DirectoryIdentity,
    UnsafeManagedPath,
    ensure_managed_directory,
    reject_link_or_reparse,
    reject_managed_file_link,
    verify_managed_directory,
)
from aruba_session_tracker.storage.csv_export import write_csv_atomic
from aruba_session_tracker.storage.html_report import (
    HTML_CONTROLLER_LIMIT,
    HTML_DIAGNOSTIC_LIMIT,
    HTML_LIFECYCLE_LIMIT,
    HTML_OBSERVATION_LIMIT,
    HTML_RAW_FILE_LIMIT,
    RunReportSnapshot,
    write_html_report_atomic,
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
    from aruba_session_tracker.services.tracker import QueryOutcome

_SCHEMA_VERSION = 2
_DELETE_PREVIEW_TTL_SECONDS = 300
_CSV_FETCH_BATCH = 1000
_HASH_CHUNK_SIZE = 1024 * 1024
_MANIFEST_VERSION = 1
_OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
_MANIFEST_TEMP_NAME = re.compile(r"\.(?P<operation_id>[0-9a-f]{32})\.json\.[0-9a-f]{32}\.tmp\Z")
_EVENT_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_IPV4_TEXT = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_CREDENTIAL_TEXT = re.compile(
    r"(?i)\b(username|user|password|passwd|secret|token)\s*[:=]\s*([^\s,;]+)"
)

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

CREATE INDEX IF NOT EXISTS ix_observations_run_time
    ON observations(run_id, observed_at);
CREATE INDEX IF NOT EXISTS ix_lifecycle_run_time
    ON lifecycle_events(run_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_controller_run_time
    ON controller_events(run_id, occurred_at);
CREATE INDEX IF NOT EXISTS ix_diagnostic_run_time
    ON diagnostic_events(run_id, occurred_at);
"""


class StorageError(RuntimeError):
    """Local history could not be read or safely changed."""


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


@dataclass(frozen=True, slots=True)
class _DeletionFile:
    relative_path: str
    sha256: str | None
    byte_size: int
    registered: bool


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
        self._raw = RawOutputStore(self.raw_root)
        self._initialized = False
        self._lock = threading.RLock()
        self._pending_deletions: dict[str, _PendingDeletion] = {}
        self._directory_identities: dict[Path, DirectoryIdentity] = {}
        self._run_leases: dict[str, _RunLease] = {}

    def initialize(self) -> None:
        with self._lock:
            if self._initialized:
                return
            try:
                self._prepare_managed_layout()
                with self._connection(uninitialized=True) as connection:
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

    def start_run(
        self,
        query: QueryRequest,
        *,
        run_id: str | None = None,
        started_at: datetime | None = None,
    ) -> str:
        self._ensure_initialized()
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
        """Record one poll and optionally link all rows to its raw UTF-8 file."""

        self._ensure_initialized()
        self._require_owned_running_run(run_id)
        values = tuple(observations)
        artifact: RawArtifact | None = None
        raw_file_id: int | None = None
        if raw_text is not None:
            selected_controller = controller_name or _single_controller_name(values)
            try:
                artifact = self._raw.write(
                    run_id,
                    kind=raw_kind,
                    controller_name=selected_controller,
                    content=raw_text,
                    captured_at=captured_at,
                )
            except (OSError, UnsafeStoragePath, ValueError) as error:
                raise StorageError(f"Raw 출력을 저장할 수 없습니다: {error}") from error

        try:
            with self._lock, self._connection() as connection:
                self._require_run(connection, run_id, require_running=True)
                if artifact is not None:
                    cursor = connection.execute(
                        """
                        INSERT INTO raw_files (
                            run_id, captured_at, kind, controller_name,
                            relative_path, sha256, byte_size
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            run_id,
                            _iso(captured_at),
                            raw_kind,
                            controller_name or _single_controller_name(values),
                            artifact.relative_path,
                            artifact.sha256,
                            artifact.byte_size,
                        ),
                    )
                    raw_file_id = _last_row_id(cursor)

                observation_ids = []
                for observation in values:
                    cursor = connection.execute(
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
                        ),
                    )
                    observation_ids.append(_last_row_id(cursor))
                return tuple(observation_ids)
        except (sqlite3.Error, StorageError) as error:
            if artifact is not None:
                with suppress(OSError, UnsafeStoragePath):
                    self._raw.remove(artifact.relative_path)
            if isinstance(error, StorageError):
                raise
            raise StorageError(f"세션 관측을 기록할 수 없습니다: {error}") from error

    def record_poll_batch(
        self,
        run_id: str,
        outcome: QueryOutcome,
        events: Sequence[LifecycleEvent] = (),
    ) -> None:
        """Persist one complete query/poll as one recoverable SQLite transaction."""

        self._ensure_initialized()
        safe_segment(run_id, "run_id")
        self._require_owned_running_run(run_id)
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
                            }
                            for item in prepared
                        ],
                    },
                )
                self._stage_prepared_raw(stage_root, prepared)
                with self._connection() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    self._require_run(connection, run_id, require_running=True)
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
                        os.replace(item.staged_path, item.destination)
                        installed.append(item)
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

    def export_run_csv(self, run_id: str, destination: Path | str | None = None) -> Path:
        self._ensure_initialized()
        safe_segment(run_id, "run_id")
        path = (
            Path(destination)
            if destination is not None
            else self.exports_root / f"run-{run_id}.csv"
        )
        stage: _ManagedExportStage | None = None
        try:
            managed_destination = self._managed_export_destination(path)
            output_path = path
            if managed_destination is not None:
                stage = self._prepare_managed_export(managed_destination)
                output_path = stage.path
            try:
                with self._lock, self._connection() as connection:
                    connection.execute("BEGIN")
                    self._require_run(connection, run_id)
                    self._verify_run_raw_integrity(connection, run_id)
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
                        output_path,
                        columns=_CSV_COLUMNS,
                        rows=_iter_cursor_dicts(cursor, batch_size=_CSV_FETCH_BATCH),
                    )
            except BaseException as error:
                if stage is not None:
                    cleanup_error = self._discard_managed_export_stage(stage)
                    if cleanup_error is not None:
                        error.add_note(
                            f"내보내기 staging 정리도 실패했습니다: {type(cleanup_error).__name__}"
                        )
                raise
            if managed_destination is None:
                return path
            assert stage is not None
            self._commit_managed_export(run_id, managed_destination, stage)
            return managed_destination
        except StorageError:
            raise
        except (OSError, sqlite3.Error) as error:
            raise StorageError(f"CSV를 내보낼 수 없습니다: {error}") from error

    def export_run_html(self, run_id: str, destination: Path | str | None = None) -> Path:
        """Export one completed run as a standalone, offline HTML5 report."""

        self._ensure_initialized()
        safe_segment(run_id, "run_id")
        path = (
            Path(destination)
            if destination is not None
            else self.exports_root / f"run-{run_id}.html"
        )
        try:
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN")
                run = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
                if run is None:
                    raise StorageError("요청한 조회 실행 기록이 없습니다.")
                if run["status"] == "RUNNING":
                    raise StorageError("RUNNING 상태의 실행은 중지 후 HTML 보고서를 만드십시오.")
                self._verify_run_raw_integrity(connection, run_id)

                controllers = connection.execute(
                    """
                    SELECT controller_name AS name FROM observations
                    WHERE run_id = ? AND controller_name IS NOT NULL
                    UNION
                    SELECT controller_name AS name FROM raw_files
                    WHERE run_id = ? AND controller_name IS NOT NULL
                    UNION
                    SELECT previous_controller AS name FROM controller_events
                    WHERE run_id = ? AND previous_controller IS NOT NULL
                    UNION
                    SELECT current_controller AS name FROM controller_events
                    WHERE run_id = ? AND current_controller IS NOT NULL
                    ORDER BY name
                    """,
                    (run_id, run_id, run_id, run_id),
                ).fetchall()
                mm_controllers = connection.execute(
                    """
                    SELECT DISTINCT controller_name AS name
                    FROM raw_files
                    WHERE run_id = ? AND kind = 'mm-location'
                          AND controller_name IS NOT NULL
                    ORDER BY name
                    """,
                    (run_id,),
                ).fetchall()
                md_controllers = connection.execute(
                    """
                    SELECT controller_name AS name FROM observations
                    WHERE run_id = ? AND controller_name IS NOT NULL
                    UNION
                    SELECT controller_name AS name FROM raw_files
                    WHERE run_id = ? AND kind = 'session' AND controller_name IS NOT NULL
                    UNION
                    SELECT previous_controller AS name FROM controller_events
                    WHERE run_id = ? AND previous_controller IS NOT NULL
                    UNION
                    SELECT current_controller AS name FROM controller_events
                    WHERE run_id = ? AND current_controller IS NOT NULL
                    ORDER BY name
                    """,
                    (run_id, run_id, run_id, run_id),
                ).fetchall()

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
                observations = connection.execute(
                    """
                    WITH ranked AS (
                        SELECT o.*,
                               row_number() OVER (
                                   PARTITION BY o.session_key
                                   ORDER BY o.observed_at DESC, o.id DESC
                               ) AS rank_in_session
                        FROM observations o
                        WHERE o.run_id = ?
                    )
                    SELECT observed_at, controller_name, controller_host, protocol,
                           source_ip, destination_ip, source_port, destination_port,
                           counter, priority, tos, age, destination, tunnel_age,
                           packets, bytes_count, flags, cpu_id, session_key
                    FROM ranked
                    WHERE rank_in_session = 1
                    ORDER BY observed_at DESC, id DESC
                    LIMIT ?
                    """,
                    (run_id, HTML_OBSERVATION_LIMIT),
                ).fetchall()

                lifecycle_total = int(
                    connection.execute(
                        "SELECT count(*) FROM lifecycle_events WHERE run_id = ?", (run_id,)
                    ).fetchone()[0]
                )
                lifecycle_counts = connection.execute(
                    """
                    SELECT event_type, count(*) AS event_count
                    FROM lifecycle_events
                    WHERE run_id = ?
                    GROUP BY event_type
                    ORDER BY event_type
                    """,
                    (run_id,),
                ).fetchall()
                lifecycle_events = connection.execute(
                    """
                    SELECT occurred_at, session_key, instance_id, event_type,
                           controller_name, details_json
                    FROM lifecycle_events
                    WHERE run_id = ?
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT ?
                    """,
                    (run_id, HTML_LIFECYCLE_LIMIT),
                ).fetchall()

                controller_total = int(
                    connection.execute(
                        "SELECT count(*) FROM controller_events WHERE run_id = ?", (run_id,)
                    ).fetchone()[0]
                )
                controller_events = connection.execute(
                    """
                    SELECT occurred_at, previous_controller, current_controller, reason
                    FROM controller_events
                    WHERE run_id = ?
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT ?
                    """,
                    (run_id, HTML_CONTROLLER_LIMIT),
                ).fetchall()

                diagnostic_total = int(
                    connection.execute(
                        "SELECT count(*) FROM diagnostic_events WHERE run_id = ?", (run_id,)
                    ).fetchone()[0]
                )
                diagnostics = connection.execute(
                    """
                    SELECT occurred_at, stage, code, message
                    FROM diagnostic_events
                    WHERE run_id = ?
                    ORDER BY occurred_at DESC, id DESC
                    LIMIT ?
                    """,
                    (run_id, HTML_DIAGNOSTIC_LIMIT),
                ).fetchall()

                raw_totals = connection.execute(
                    """
                    SELECT count(*) AS file_count, coalesce(sum(byte_size), 0) AS byte_count
                    FROM raw_files
                    WHERE run_id = ?
                    """,
                    (run_id,),
                ).fetchone()
                raw_files = connection.execute(
                    """
                    SELECT id, captured_at, kind, controller_name, sha256, byte_size
                    FROM raw_files
                    WHERE run_id = ?
                    ORDER BY captured_at DESC, id DESC
                    LIMIT ?
                    """,
                    (run_id, HTML_RAW_FILE_LIMIT),
                ).fetchall()

                snapshot = RunReportSnapshot(
                    run=dict(run),
                    controllers=tuple(str(row["name"]) for row in controllers),
                    mm_controllers=tuple(str(row["name"]) for row in mm_controllers),
                    md_controllers=tuple(str(row["name"]) for row in md_controllers),
                    observations=tuple(dict(row) for row in observations),
                    observation_total=observation_total,
                    unique_session_total=unique_session_total,
                    lifecycle_events=tuple(dict(row) for row in lifecycle_events),
                    lifecycle_total=lifecycle_total,
                    lifecycle_counts=tuple(
                        (str(row["event_type"]), int(row["event_count"]))
                        for row in lifecycle_counts
                    ),
                    controller_events=tuple(dict(row) for row in controller_events),
                    controller_total=controller_total,
                    diagnostics=tuple(dict(row) for row in diagnostics),
                    diagnostic_total=diagnostic_total,
                    raw_files=tuple(dict(row) for row in raw_files),
                    raw_file_total=int(raw_totals["file_count"]),
                    raw_byte_total=int(raw_totals["byte_count"]),
                )
            managed_destination = self._managed_export_destination(path)
            if managed_destination is None:
                return write_html_report_atomic(path, snapshot)
            stage = self._prepare_managed_export(managed_destination)
            try:
                write_html_report_atomic(stage.path, snapshot)
            except BaseException as error:
                cleanup_error = self._discard_managed_export_stage(stage)
                if cleanup_error is not None:
                    error.add_note(
                        f"HTML staging 정리도 실패했습니다: {type(cleanup_error).__name__}"
                    )
                raise
            self._commit_managed_export(run_id, managed_destination, stage)
            return managed_destination
        except StorageError:
            raise
        except (OSError, sqlite3.Error, ValueError) as error:
            raise StorageError(f"HTML 보고서를 내보낼 수 없습니다: {error}") from error

    def preview_delete(self, run_id: str | None = None) -> DeletePreview:
        """Create a five-minute, one-use deletion preview; this does not delete data."""

        self._ensure_initialized()
        with self._lock:
            try:
                snapshot = self._collect_deletion_snapshot(run_id)
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
            self._pending_deletions[preview_id] = _PendingDeletion(
                preview=preview,
                snapshot=snapshot,
                expires_monotonic=time.monotonic() + _DELETE_PREVIEW_TTL_SECONDS,
                target_run_id=run_id,
            )
            return preview

    def delete(self, preview: DeletePreview, *, confirmation_token: str) -> DeletionResult:
        """Delete exactly the unchanged items described by a valid preview."""

        self._ensure_initialized()
        with self._lock:
            pending = self._pending_deletions.get(preview.preview_id)
            if pending is None or pending.preview != preview:
                raise StorageError("먼저 현재 삭제 대상을 미리 확인해야 합니다.")
            if time.monotonic() > pending.expires_monotonic:
                self._pending_deletions.pop(preview.preview_id, None)
                raise StorageError("삭제 미리보기가 만료되었습니다. 다시 확인하십시오.")
            if not secrets.compare_digest(pending.preview.confirmation_token, confirmation_token):
                raise StorageError("삭제 확인 토큰이 일치하지 않습니다.")

            staged: list[_StagedFile] = []
            manifest_path: Path | None = None
            operation_lease = self._acquire_operation_lease(preview.preview_id)
            if operation_lease is None:
                raise StorageError("삭제 작업 잠금을 획득할 수 없습니다.")
            phase = "snapshot"
            try:
                with self._connection() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    current = self._collect_deletion_snapshot(
                        pending.target_run_id,
                        connection=connection,
                    )
                    if current != pending.snapshot:
                        self._pending_deletions.pop(preview.preview_id, None)
                        raise StorageError(
                            "미리보기 이후 기록이 변경되었습니다. 다시 확인하십시오."
                        )

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
                    )
                    _stage_files(
                        self.exports_root,
                        current.export_files,
                        preview.preview_id,
                        "export",
                        staged,
                    )

                    phase = "database"
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
                else:
                    if manifest_path is not None:
                        _unlink_regular(manifest_path, missing_ok=True)
                    _release_run_lease(operation_lease, remove=True)
                if isinstance(error, StorageError):
                    raise
                if isinstance(error, (UnsafeStoragePath, UnsafeManagedPath)):
                    raise StorageError(f"삭제 대상 경로가 안전하지 않습니다: {error}") from error
                if phase == "staging":
                    raise StorageError(
                        f"삭제 대상 파일을 안전하게 격리할 수 없습니다: {error}"
                    ) from error
                raise StorageError(f"데이터베이스 기록을 삭제할 수 없습니다: {error}") from error

            self._pending_deletions.pop(preview.preview_id, None)
            try:
                _purge_staged_files(staged)
                if manifest_path is not None:
                    _unlink_regular(manifest_path, missing_ok=False)
                _release_run_lease(operation_lease, remove=True)
            except (OSError, UnsafeStoragePath) as error:
                _release_run_lease(operation_lease, remove=False)
                raise StorageError(
                    "데이터베이스 삭제는 완료되었지만 격리된 파일을 마지막으로 제거하지 못했습니다."
                ) from error
            _remove_known_empty_run_directories(self.raw_root, current.run_ids)
            deleted_raw = sum(item.category == "raw" for item in staged)
            deleted_exports = sum(item.category == "export" for item in staged)
            return DeletionResult(
                deleted_runs=len(current.run_ids),
                deleted_database_rows=current.database_rows,
                deleted_raw_files=deleted_raw,
                deleted_export_files=deleted_exports,
            )

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

    def _acquire_run_lease(self, run_id: str) -> _RunLease | None:
        safe_segment(run_id, "run_id")
        return _acquire_file_lease(self._leases_root / f"run-{run_id}.lease")

    def _acquire_operation_lease(self, operation_id: str) -> _RunLease | None:
        _validate_operation_id(operation_id)
        return _acquire_file_lease(self._leases_root / f"operation-{operation_id}.lease")

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
    ) -> tuple[tuple[_PreparedRaw, ...], tuple[SessionObservation, ...]]:
        remaining = {item.session_key: item for item in outcome.observations}
        prepared: list[_PreparedRaw] = []
        for snapshot in outcome.raw_snapshots:
            if snapshot.observation_keys is None:
                observations = tuple(
                    item
                    for item in remaining.values()
                    if item.controller_name == snapshot.device_name
                )
            else:
                observations = tuple(
                    remaining[key] for key in snapshot.observation_keys if key in remaining
                )
            for observation in observations:
                remaining.pop(observation.session_key, None)
            raw_kind = "session" if "datapath" in snapshot.command else "mm-location"
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

    def _recover_operations(self) -> None:
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
                else:
                    raise StorageError("지원하지 않는 저장 작업 manifest 종류입니다.")
            finally:
                _release_run_lease(lease, remove=not os.path.lexists(path))

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
                    elif os.path.lexists(staged):
                        _verify_file_fingerprint(staged, item["sha256"], item["byte_size"])
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        os.replace(staged, destination)
                    else:
                        raise StorageError("DB가 참조하는 Raw 파일을 복구할 수 없습니다.")
                else:
                    for candidate in (destination, staged):
                        if os.path.lexists(candidate):
                            _verify_file_fingerprint(candidate, item["sha256"], item["byte_size"])
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
                os.replace(staged, destination)
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
                    os.replace(backup, destination)
                elif os.path.lexists(destination):
                    _verify_file_fingerprint(destination, *previous_file)
                else:
                    raise StorageError("이전 내보내기 파일을 복구할 수 없습니다.")
        else:
            raise StorageError("내보내기 DB 상태가 manifest와 달라 자동 복구할 수 없습니다.")
        for candidate in (staged, backup):
            if os.path.lexists(candidate):
                _unlink_regular(candidate, missing_ok=False)
        _unlink_regular(path, missing_ok=False)

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
                        os.replace(matching[0], destination)
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
    def _connection(self, *, uninitialized: bool = False) -> Iterator[sqlite3.Connection]:
        if not uninitialized and not self._initialized:
            raise StorageError("데이터베이스가 초기화되지 않았습니다.")
        if self._directory_identities:
            self._assert_managed_layout()
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
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

    def _prepare_managed_export(self, destination: Path) -> _ManagedExportStage:
        operation_id = uuid4().hex
        lease = self._acquire_operation_lease(operation_id)
        if lease is None:  # pragma: no cover - UUID collision defense
            raise StorageError("내보내기 작업 잠금을 획득할 수 없습니다.")
        staged_relative = _export_operation_relative(
            destination.relative_to(self.exports_root).as_posix(),
            operation_id,
            "staged",
        )
        staged = self.exports_root / Path(staged_relative)
        if os.path.lexists(staged):  # pragma: no cover - UUID collision defense
            _release_run_lease(lease, remove=True)
            raise StorageError("내보내기 staging 경로가 이미 존재합니다.")
        return _ManagedExportStage(operation_id, staged, lease)

    @staticmethod
    def _discard_managed_export_stage(stage: _ManagedExportStage) -> BaseException | None:
        cleanup_error: BaseException | None = None
        try:
            if os.path.lexists(stage.path):
                _unlink_regular(stage.path, missing_ok=False)
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
        try:
            self._assert_managed_layout()
            exports_root = self.exports_root
            relative = destination.relative_to(exports_root).as_posix()
            operation_id = stage.operation_id
            staged_relative = _export_operation_relative(relative, operation_id, "staged")
            expected_staged = exports_root / Path(staged_relative)
            if stage.path != expected_staged:
                raise StorageError("내보내기 staging 경로가 작업 ID와 일치하지 않습니다.")
            backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
            backup_relative = backup.relative_to(exports_root).as_posix()
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
            prepare_cleanup_error = self._discard_managed_export_stage(stage)
            if prepare_cleanup_error is not None:
                error.add_note(
                    "내보내기 준비 실패 후 staging 정리도 실패했습니다: "
                    f"{type(prepare_cleanup_error).__name__}"
                )
            raise
        manifest_path: Path | None = None
        installed = False
        try:
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._require_run(connection, run_id)
                previous_row = connection.execute(
                    "SELECT sha256, byte_size FROM exports WHERE relative_path = ?",
                    (relative,),
                ).fetchone()
                previous_db_sha = str(previous_row["sha256"]) if previous_row else None
                previous_db_size = int(previous_row["byte_size"]) if previous_row else None
                if previous_row is not None and (
                    previous_file_sha is None
                    or (
                        previous_file_sha != previous_db_sha
                        or previous_file_size != previous_db_size
                    )
                ):
                    raise StorageError("기존 관리 내보내기 파일의 무결성이 일치하지 않습니다.")
                manifest_path = self._write_manifest(
                    operation_id,
                    {
                        "version": _MANIFEST_VERSION,
                        "kind": "export",
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
                    },
                )
                if os.path.lexists(destination):
                    os.replace(destination, backup)
                os.replace(stage.path, destination)
                installed = True
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
        except (
            OSError,
            sqlite3.Error,
            StorageError,
            UnsafeManagedPath,
            UnsafeStoragePath,
        ) as error:
            rollback_error: BaseException | None = None
            try:
                if os.path.lexists(backup):
                    if os.path.lexists(destination):
                        _verify_file_fingerprint(destination, new_sha, new_size)
                        _unlink_regular(destination, missing_ok=False)
                    os.replace(backup, destination)
                elif installed:
                    _verify_file_fingerprint(destination, new_sha, new_size)
                    _unlink_regular(destination, missing_ok=False)
                if os.path.lexists(stage.path):
                    _unlink_regular(stage.path, missing_ok=False)
                if manifest_path is not None:
                    _unlink_regular(manifest_path, missing_ok=True)
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
            if manifest_path is not None:
                _unlink_regular(manifest_path, missing_ok=False)
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

    def _verify_run_raw_integrity(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> None:
        cursor = connection.execute(
            """
            SELECT relative_path, sha256, byte_size
            FROM raw_files WHERE run_id = ? ORDER BY id
            """,
            (run_id,),
        )
        while True:
            rows = cursor.fetchmany(_CSV_FETCH_BATCH)
            if not rows:
                break
            for row in rows:
                path = _managed_file_path(
                    self.raw_root,
                    str(row["relative_path"]),
                    allow_missing=False,
                )
                _verify_file_fingerprint(
                    path,
                    str(row["sha256"]),
                    int(row["byte_size"]),
                )

    def _collect_deletion_snapshot(
        self,
        run_id: str | None,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> _DeletionSnapshot:
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
            filesystem_raw_paths = set(_scan_regular_files(self.raw_root))
            filesystem_export_paths = set(_scan_regular_files(self.exports_root))
        else:
            filesystem_raw_paths = set(
                _scan_regular_files(self.raw_root, relative_directory=Path(run_id))
            )
            filesystem_export_paths = set()

        raw_files = _snapshot_managed_files(
            self.raw_root,
            registered_raw_paths | filesystem_raw_paths,
            registered_raw_paths,
        )
        export_files = _snapshot_managed_files(
            self.exports_root,
            registered_export_paths | filesystem_export_paths,
            registered_export_paths,
        )
        total_bytes = sum(item.byte_size for item in raw_files)
        total_bytes += sum(item.byte_size for item in export_files)
        return _DeletionSnapshot(run_ids, row_counts, raw_files, export_files, total_bytes)

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
}
_REQUIRED_INDEXES = {
    "ix_observations_run_time",
    "ix_lifecycle_run_time",
    "ix_controller_run_time",
    "ix_diagnostic_run_time",
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
    if os.path.lexists(path):
        try:
            info = reject_link_or_reparse(path)
        except UnsafeManagedPath as error:
            raise StorageError(str(error)) from error
        if not stat.S_ISREG(info.st_mode):
            raise StorageError("잠금 경로가 일반 파일이 아닙니다.")
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    stream = os.fdopen(descriptor, "r+b", buffering=0)
    try:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise StorageError("잠금 파일이 일반 파일이 아닙니다.")
        if info.st_size == 0:
            stream.write(b"0")
        stream.seek(0)
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
        return _RunLease(path, stream, int(info.st_dev), int(info.st_ino))
    except Exception:
        stream.close()
        raise


def _release_run_lease(lease: _RunLease, *, remove: bool) -> None:
    try:
        if not lease.stream.closed:
            lease.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lease.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl: Any = importlib.import_module("fcntl")
                fcntl.flock(lease.stream.fileno(), int(fcntl.LOCK_UN))
    finally:
        lease.stream.close()
    if remove and os.path.lexists(lease.path):
        info = os.lstat(lease.path)
        if int(info.st_dev) == lease.device and int(info.st_ino) == lease.inode:
            _unlink_regular(lease.path, missing_ok=False)


def _write_json_atomic(path: Path, payload: dict[str, object]) -> None:
    data = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    _write_bytes_atomic(path, data)


def _write_bytes_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
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
            }
        )
    return tuple(result)


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


def _file_fingerprint(path: Path) -> tuple[str, int]:
    _reject_link_or_reparse(path)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeStoragePath("관리 대상은 일반 파일이어야 합니다.")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    after = os.lstat(path)
    if (
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


def _verify_file_fingerprint(path: Path, sha256: str, byte_size: int) -> None:
    actual_sha, actual_size = _file_fingerprint(path)
    if actual_sha != sha256 or actual_size != byte_size:
        raise StorageError("관리 파일의 SHA-256 또는 크기가 변경되었습니다.")


def _fingerprint_matches(path: Path, sha256: str, byte_size: int) -> bool:
    try:
        _verify_file_fingerprint(path, sha256, byte_size)
    except (OSError, UnsafeStoragePath, StorageError):
        return False
    return True


def _snapshot_managed_files(
    root: Path,
    paths: set[str],
    registered_paths: set[str],
) -> tuple[_DeletionFile, ...]:
    result: list[_DeletionFile] = []
    for relative in sorted(paths):
        path = _managed_file_path(root, relative, allow_missing=True)
        if os.path.lexists(path):
            sha256, byte_size = _file_fingerprint(path)
        else:
            sha256, byte_size = None, 0
        result.append(_DeletionFile(relative, sha256, byte_size, relative in registered_paths))
    return tuple(result)


def _iter_cursor_dicts(
    cursor: sqlite3.Cursor,
    *,
    batch_size: int,
) -> Iterator[dict[str, object]]:
    while True:
        rows = cursor.fetchmany(batch_size)
        if not rows:
            return
        for row in rows:
            yield dict(row)


def _raw_filename_segment(value: str, label: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._-")
    if not normalized:
        raise UnsafeStoragePath(f"{label}은 비어 있을 수 없습니다.")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{normalized[:48]}-{digest}"


def _raw_artifact_for_batch(
    run_id: str,
    *,
    kind: str,
    controller_name: str,
    content: str,
    captured_at: datetime,
) -> tuple[RawArtifact, bytes]:
    run_segment = safe_segment(run_id, "run_id")
    if captured_at.tzinfo is None:
        raise ValueError("시간 값에는 timezone 정보가 필요합니다.")
    timestamp = captured_at.astimezone(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    filename = (
        f"{timestamp}_{_raw_filename_segment(kind, 'kind')}_"
        f"{_raw_filename_segment(controller_name, 'controller_name')}_"
        f"{uuid4().hex[:8]}.txt"
    )
    relative = (Path(run_segment) / filename).as_posix()
    data = content.encode("utf-8")
    return (
        RawArtifact(relative, hashlib.sha256(data).hexdigest(), len(data)),
        data,
    )


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


def _reject_managed_chain(root: Path, directory: Path) -> None:
    root_absolute = Path(os.path.abspath(root))
    directory_absolute = Path(os.path.abspath(directory))
    if not directory_absolute.is_relative_to(root_absolute):
        raise UnsafeStoragePath("관리 경로가 루트 밖을 가리킵니다.")
    current = root_absolute
    _reject_link_or_reparse(current)
    for part in directory_absolute.relative_to(root_absolute).parts:
        current /= part
        if os.path.lexists(current):
            _reject_link_or_reparse(current)


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
            os.replace(staged, canonical)
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


def _scan_regular_files(
    root: Path,
    *,
    relative_directory: Path | None = None,
    include_internal: bool = False,
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
        directory = directories.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
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
                else:
                    raise UnsafeStoragePath("관리 루트에 일반 파일이 아닌 항목이 있습니다.")
    return tuple(sorted(files))


def _stage_files(
    root: Path,
    files: tuple[_DeletionFile, ...],
    preview_id: str,
    category: str,
    staged: list[_StagedFile],
) -> None:
    if not files:
        return
    stage_name = f".delete-staging-{safe_segment(preview_id, 'preview_id')}"
    stage_root = contained_path(root, Path(stage_name))
    if os.path.lexists(stage_root):
        raise UnsafeStoragePath("삭제 격리 디렉터리가 이미 있습니다.")

    for item in files:
        relative = item.relative_path
        source = _managed_file_path(root, relative, allow_missing=True)
        if not os.path.lexists(source):
            if item.sha256 is not None:
                raise StorageError("삭제 미리보기의 관리 파일이 사라졌습니다.")
            continue
        if item.sha256 is None:
            raise StorageError("삭제 미리보기 이후 관리 파일이 새로 생겼습니다.")
        _verify_file_fingerprint(source, item.sha256, item.byte_size)
        parts = _safe_relative_parts(relative)
        destination = contained_path(stage_root, Path(*parts))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(destination):
            raise UnsafeStoragePath("삭제 격리 경로가 이미 있습니다.")
        os.replace(source, destination)
        staged.append(
            _StagedFile(
                source,
                destination,
                category,
                relative,
                item.sha256,
                item.byte_size,
                item.registered,
            )
        )
        _verify_file_fingerprint(destination, item.sha256, item.byte_size)


def _restore_staged_files(staged: list[_StagedFile]) -> OSError | None:
    first_error: OSError | None = None
    for item in reversed(staged):
        try:
            if os.path.lexists(item.source):
                raise FileExistsError(item.source)
            _verify_file_fingerprint(item.destination, item.sha256, item.byte_size)
            item.source.parent.mkdir(parents=True, exist_ok=True)
            os.replace(item.destination, item.source)
        except (OSError, UnsafeStoragePath, StorageError) as error:
            if first_error is None:
                first_error = OSError(str(error))
    _remove_staging_directories(staged)
    return first_error


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
        directory = contained_path(root, Path(run_id))
        try:
            directory.rmdir()
        except (FileNotFoundError, OSError):
            continue
