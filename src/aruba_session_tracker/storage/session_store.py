"""SQLite-backed session history and safe manual deletion workflow."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from aruba_session_tracker.models import DiagnosticEvent, QueryRequest, SessionObservation
from aruba_session_tracker.storage.csv_export import write_csv_atomic
from aruba_session_tracker.storage.raw import (
    RawArtifact,
    RawOutputStore,
    UnsafeStoragePath,
    contained_path,
    safe_segment,
)

_SCHEMA_VERSION = 2
_DELETE_PREVIEW_TTL_SECONDS = 300
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
    raw_paths: tuple[str, ...]
    export_paths: tuple[str, ...]
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


class SessionStore:
    """Facade for run history, raw capture, CSV export, and confirmed deletion."""

    def __init__(
        self,
        db_path: Path | str,
        raw_root: Path | str,
        exports_root: Path | str,
    ) -> None:
        self.db_path = Path(db_path)
        self.raw_root = Path(raw_root)
        self.exports_root = Path(exports_root)
        self._raw = RawOutputStore(self.raw_root)
        self._initialized = False
        self._lock = threading.RLock()
        self._pending_deletions: dict[str, _PendingDeletion] = {}

    def initialize(self) -> None:
        with self._lock:
            if self._initialized:
                return
            try:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                self.raw_root.mkdir(parents=True, exist_ok=True)
                self.exports_root.mkdir(parents=True, exist_ok=True)
                with self._connection(uninitialized=True) as connection:
                    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    if version not in {0, 1, _SCHEMA_VERSION}:
                        raise StorageError(
                            f"지원하지 않는 데이터베이스 스키마 버전입니다: {version}"
                        )
                    connection.executescript(_SCHEMA)
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
                    connection.execute(
                        """
                        UPDATE runs
                        SET ended_at = ?, status = 'INTERRUPTED'
                        WHERE status = 'RUNNING'
                        """,
                        (_iso(None),),
                    )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                self._initialized = True
            except (OSError, sqlite3.Error) as error:
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
        try:
            with self._lock, self._connection() as connection:
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
            return identifier
        except (sqlite3.Error, UnsafeStoragePath) as error:
            raise StorageError(f"조회 실행 기록을 시작할 수 없습니다: {error}") from error

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
            with self._lock, self._connection() as connection:
                cursor = connection.execute(
                    """
                    UPDATE runs SET ended_at = ?, status = ?
                    WHERE id = ? AND status = 'RUNNING'
                    """,
                    (_iso(ended_at), normalized_status, run_id),
                )
                if cursor.rowcount != 1:
                    self._raise_missing_or_not_running(connection, run_id)
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
        try:
            with self._lock, self._connection() as connection:
                self._require_run(connection, run_id)
                rows = connection.execute(
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
                ).fetchall()
            written = write_csv_atomic(
                path,
                columns=_CSV_COLUMNS,
                rows=(dict(row) for row in rows),
            )
            self._register_managed_export(run_id, written)
            return written
        except (OSError, sqlite3.Error) as error:
            raise StorageError(f"CSV를 내보낼 수 없습니다: {error}") from error

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
                raw_files=len(snapshot.raw_paths),
                export_files=len(snapshot.export_paths),
                total_file_bytes=snapshot.total_file_bytes,
                expires_at=expires_at,
                summary=(
                    f"{scope}: 실행 {len(snapshot.run_ids)}개, DB 행 "
                    f"{snapshot.database_rows}개, Raw {len(snapshot.raw_paths)}개, "
                    f"CSV {len(snapshot.export_paths)}개를 삭제합니다."
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

            try:
                current = self._collect_deletion_snapshot(pending.target_run_id)
            except UnsafeStoragePath as error:
                raise StorageError(f"삭제 대상 경로가 안전하지 않습니다: {error}") from error
            if current != pending.snapshot:
                self._pending_deletions.pop(preview.preview_id, None)
                raise StorageError("미리보기 이후 기록이 변경되었습니다. 다시 확인하십시오.")

            staged: list[_StagedFile] = []
            try:
                _stage_files(
                    self.raw_root,
                    current.raw_paths,
                    preview.preview_id,
                    "raw",
                    staged,
                )
                _stage_files(
                    self.exports_root,
                    current.export_paths,
                    preview.preview_id,
                    "export",
                    staged,
                )
            except (OSError, UnsafeStoragePath) as error:
                restoration_error = _restore_staged_files(staged)
                if restoration_error is not None:
                    raise StorageError(
                        "삭제 대상을 격리하는 중 실패했고 일부 파일을 원위치로 복원하지 못했습니다."
                    ) from restoration_error
                raise StorageError(
                    f"삭제 대상 파일을 안전하게 격리할 수 없습니다: {error}"
                ) from error

            try:
                with self._connection() as connection:
                    if current.run_ids:
                        placeholders = ",".join("?" for _ in current.run_ids)
                        cursor = connection.execute(
                            f"DELETE FROM runs WHERE id IN ({placeholders})",  # noqa: S608
                            current.run_ids,
                        )
                        if cursor.rowcount != len(current.run_ids):
                            raise StorageError("삭제 대상 실행 기록이 미리보기와 다릅니다.")
            except (sqlite3.Error, StorageError) as error:
                restoration_error = _restore_staged_files(staged)
                if restoration_error is not None:
                    raise StorageError(
                        "데이터베이스 삭제가 취소되었지만 일부 파일을 원위치로 복원하지 못했습니다."
                    ) from restoration_error
                if isinstance(error, StorageError):
                    raise
                raise StorageError(f"데이터베이스 기록을 삭제할 수 없습니다: {error}") from error

            self._pending_deletions.pop(preview.preview_id, None)
            try:
                _purge_staged_files(staged)
            except (OSError, UnsafeStoragePath) as error:
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

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.initialize()

    @contextmanager
    def _connection(self, *, uninitialized: bool = False) -> Iterator[sqlite3.Connection]:
        if not uninitialized and not self._initialized:
            raise StorageError("데이터베이스가 초기화되지 않았습니다.")
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

    def _register_managed_export(self, run_id: str, path: Path) -> None:
        exports_root = self.exports_root.resolve(strict=False)
        resolved = path.resolve(strict=False)
        if resolved == exports_root or not resolved.is_relative_to(exports_root):
            return
        relative = resolved.relative_to(exports_root).as_posix()
        data = resolved.read_bytes()
        try:
            with self._lock, self._connection() as connection:
                self._require_run(connection, run_id)
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
                        hashlib.sha256(data).hexdigest(),
                        len(data),
                    ),
                )
        except sqlite3.Error:
            resolved.unlink(missing_ok=True)
            raise

    def _collect_deletion_snapshot(
        self,
        run_id: str | None,
    ) -> _DeletionSnapshot:
        if run_id is not None:
            safe_segment(run_id, "run_id")
        try:
            with self._connection() as connection:
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

                if run_ids:
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
                else:
                    row_counts = tuple((table, 0) for table in _DELETION_TABLES)
                    registered_raw_paths = set()
                    registered_export_paths = set()
        except sqlite3.Error as error:
            raise StorageError(f"삭제 대상을 확인할 수 없습니다: {error}") from error

        if run_id is None:
            filesystem_raw_paths = set(_scan_regular_files(self.raw_root))
            filesystem_export_paths = set(_scan_regular_files(self.exports_root))
        else:
            filesystem_raw_paths = set(
                _scan_regular_files(self.raw_root, relative_directory=Path(run_id))
            )
            filesystem_export_paths = set()

        raw_paths = tuple(sorted(registered_raw_paths | filesystem_raw_paths))
        export_paths = tuple(sorted(registered_export_paths | filesystem_export_paths))
        total_bytes = sum(_managed_size(self.raw_root, item) for item in raw_paths)
        total_bytes += sum(_managed_size(self.exports_root, item) for item in export_paths)
        return _DeletionSnapshot(run_ids, row_counts, raw_paths, export_paths, total_bytes)


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


def _safe_relative_parts(relative: str | Path) -> tuple[str, ...]:
    path = Path(relative)
    if path.is_absolute() or not path.parts:
        raise UnsafeStoragePath("관리 경로는 비어 있지 않은 상대 경로여야 합니다.")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise UnsafeStoragePath("관리 경로에 상위 또는 빈 경로 요소가 있습니다.")
    return tuple(path.parts)


def _managed_file_path(root: Path, relative: str, *, allow_missing: bool) -> Path:
    parts = _safe_relative_parts(relative)
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
) -> tuple[str, ...]:
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
                    directories.append(path)
                elif stat.S_ISREG(mode):
                    files.append(path.relative_to(root_resolved).as_posix())
                else:
                    raise UnsafeStoragePath("관리 루트에 일반 파일이 아닌 항목이 있습니다.")
    return tuple(sorted(files))


def _stage_files(
    root: Path,
    relative_paths: tuple[str, ...],
    preview_id: str,
    category: str,
    staged: list[_StagedFile],
) -> None:
    if not relative_paths:
        return
    stage_name = f".delete-staging-{safe_segment(preview_id, 'preview_id')}"
    stage_root = contained_path(root, Path(stage_name))
    if os.path.lexists(stage_root):
        raise UnsafeStoragePath("삭제 격리 디렉터리가 이미 있습니다.")

    for relative in relative_paths:
        source = _managed_file_path(root, relative, allow_missing=True)
        if not os.path.lexists(source):
            continue
        parts = _safe_relative_parts(relative)
        destination = contained_path(stage_root, Path(*parts))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(destination):
            raise UnsafeStoragePath("삭제 격리 경로가 이미 있습니다.")
        os.replace(source, destination)
        staged.append(_StagedFile(source, destination, category))


def _restore_staged_files(staged: list[_StagedFile]) -> OSError | None:
    first_error: OSError | None = None
    for item in reversed(staged):
        try:
            if os.path.lexists(item.source):
                raise FileExistsError(item.source)
            item.source.parent.mkdir(parents=True, exist_ok=True)
            os.replace(item.destination, item.source)
        except OSError as error:
            if first_error is None:
                first_error = error
    _remove_staging_directories(staged)
    return first_error


def _purge_staged_files(staged: list[_StagedFile]) -> None:
    for item in staged:
        _reject_link_or_reparse(item.destination)
        if not stat.S_ISREG(os.lstat(item.destination).st_mode):
            raise UnsafeStoragePath("격리된 삭제 대상이 일반 파일이 아닙니다.")
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
