from __future__ import annotations

import csv
import errno
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

import aruba_session_tracker.storage.durable_io as durable_io_module
import aruba_session_tracker.storage.raw as raw_module
import aruba_session_tracker.storage.session_store as session_store_module
from aruba_session_tracker.models import (
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
    StorageFailureBoundary,
    StorageFailureKind,
)
from aruba_session_tracker.raw_bundle import persisted_raw_size
from aruba_session_tracker.services.monitoring import LifecycleEvent, LifecycleEventType
from aruba_session_tracker.services.tracker import QueryOutcome, RawSnapshot
from aruba_session_tracker.storage import (
    DeletePreview,
    DeletionResult,
    RunReportSnapshot,
    SessionStore,
    StorageError,
    StorageHealth,
    guard_csv_cell,
)


def _store(tmp_path: Path) -> SessionStore:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    return store


def _observation(
    *,
    controller_name: str = "MD-01",
    controller_host: str = "198.51.100.21",
    packets: int = 12,
    bytes_count: int = 2048,
    observed_at: datetime | None = None,
) -> SessionObservation:
    return SessionObservation(
        controller_name=controller_name,
        controller_host=controller_host,
        protocol=6,
        source_ip="192.0.2.100",
        destination_ip="203.0.113.80",
        source_port=53000,
        destination_port=443,
        counter="0/0",
        priority=0,
        tos=0,
        age=2,
        destination="local",
        tunnel_age=0,
        packets=packets,
        bytes_count=bytes_count,
        flags="FC",
        cpu_id=1,
        raw_line="sensitive raw line",
        observed_at=observed_at or datetime(2026, 8, 28, 8, 0, tzinfo=UTC),
    )


def _run(store: SessionStore) -> str:
    return store.start_run(QueryRequest("192.0.2.100", "203.0.113.80", 53000, 443))


def test_storage_error_metadata_is_optional_and_code_inference_is_typed() -> None:
    legacy = StorageError("legacy caller")
    assert legacy.code is None
    assert legacy.failure_kind is None
    assert legacy.boundary is None

    limited = StorageError("bounded", code=ErrorCode.OUTPUT_LIMIT_EXCEEDED)
    assert limited.failure_kind is StorageFailureKind.OUTPUT_LIMIT
    limited.at_boundary(StorageFailureBoundary.QUERY_RESULT)
    assert limited.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert limited.boundary is StorageFailureBoundary.QUERY_RESULT

    database = StorageError("database").at_boundary(StorageFailureBoundary.QUERY_START)
    assert database.code is ErrorCode.DB_WRITE_FAILED
    assert database.failure_kind is StorageFailureKind.DATABASE_WRITE


def test_start_run_cleanup_failure_does_not_mask_typed_primary_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    original_release = session_store_module._release_run_lease

    @contextmanager
    def fail_connection(*, uninitialized: bool = False) -> Iterator[sqlite3.Connection]:
        del uninitialized
        raise sqlite3.DatabaseError("sanitized start failure")
        yield  # pragma: no cover - contextmanager generator contract

    def release_then_fail(
        lease: object,
        *,
        remove: bool,
    ) -> None:
        original_release(lease, remove=remove)  # type: ignore[arg-type]
        raise OSError("sanitized cleanup failure")

    monkeypatch.setattr(store, "_connection", fail_connection)
    monkeypatch.setattr(session_store_module, "_release_run_lease", release_then_fail)

    with pytest.raises(StorageError) as caught:
        store.start_run(QueryRequest("192.0.2.100", "203.0.113.80"))

    assert caught.value.code is ErrorCode.DB_WRITE_FAILED
    assert caught.value.failure_kind is StorageFailureKind.DATABASE_WRITE
    assert caught.value.boundary is StorageFailureBoundary.QUERY_START
    assert any("잠금 정리도 실패" in note for note in caught.value.__notes__)


def test_single_ip_query_round_trips_without_a_schema_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = store.start_run(QueryRequest("", "203.0.113.80", 53000, 443))

    row = store.list_runs()[0]
    assert row["id"] == run_id
    assert row["source_ip"] == ""
    assert row["destination_ip"] == "203.0.113.80"
    assert row["source_port"] == 53000
    assert row["destination_port"] == 443

    store.finish_run(run_id)


def _run_export_crash(
    store: SessionStore,
    run_id: str,
    destination: Path,
    target_phase: str,
    export_format: str = "csv",
) -> subprocess.CompletedProcess[str]:
    repository = Path(__file__).resolve().parents[1]
    worker = Path(__file__).with_name("export_phase_crash_worker.py")
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(repository / "src") + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(worker),
            str(store.db_path),
            str(store.raw_root),
            str(store.exports_root),
            run_id,
            str(destination),
            target_phase,
            export_format,
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )


def test_storage_path_helpers_cover_fail_closed_boundary_branches(tmp_path: Path) -> None:
    managed_root = tmp_path / "managed"
    managed_root.mkdir()
    assert session_store_module._managed_size(managed_root, "missing.bin") == 0
    managed_file = managed_root / "present.bin"
    managed_file.write_bytes(b"abc")
    assert session_store_module._managed_size(managed_root, "present.bin") == 3

    operation_id = "a" * 32
    with pytest.raises(ValueError, match="지원하지 않는"):
        session_store_module._export_operation_relative("report.csv", operation_id, "other")
    with pytest.raises(ValueError, match="지원하지 않는"):
        session_store_module._external_export_operation_path(
            tmp_path / "report.csv", operation_id, "other"
        )
    with pytest.raises(ValueError, match="여유 공간"):
        session_store_module._minimum_free_bytes(())
    with pytest.raises(session_store_module.UnsafeStoragePath, match="상대 경로"):
        session_store_module._safe_relative_parts(tmp_path.resolve())

    assert session_store_module._regular_file_size(tmp_path / "absent.bin") == 0
    with pytest.raises(session_store_module.UnsafeStoragePath, match="일반 파일"):
        session_store_module._regular_file_size(managed_root)


def test_initialize_creates_required_schema(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        lifecycle_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(lifecycle_events)").fetchall()
        }

    assert {
        "runs",
        "observations",
        "lifecycle_events",
        "controller_events",
        "diagnostic_events",
        "raw_files",
        "exports",
        "poll_commits",
    }.issubset(tables)
    assert version == 3
    assert "instance_id" in lifecycle_columns


def test_wal_mode_is_configured_only_during_initialize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    statements: list[str] = []
    original_connect = session_store_module.sqlite3.connect

    def traced_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        connection = original_connect(*args, **kwargs)  # type: ignore[arg-type]
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(session_store_module.sqlite3, "connect", traced_connect)
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    normalized = [statement.upper().replace(" ", "") for statement in statements]
    assert normalized.count("PRAGMAJOURNAL_MODE=WAL") == 1

    statements.clear()
    store.list_runs()
    normalized = [statement.upper().replace(" ", "") for statement in statements]
    assert "PRAGMAJOURNAL_MODE=WAL" not in normalized
    assert "PRAGMAFOREIGN_KEYS=ON" in normalized
    assert "PRAGMABUSY_TIMEOUT=10000" in normalized
    assert "PRAGMASYNCHRONOUS=FULL" in normalized


def test_connection_closes_when_setup_pragma_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    original_connect = session_store_module.sqlite3.connect
    connections: list[SimpleNamespace] = []

    def failing_connect(*args: object, **kwargs: object) -> SimpleNamespace:
        wrapped = original_connect(*args, **kwargs)  # type: ignore[arg-type]
        connection = SimpleNamespace(closed=False)
        connection.row_factory = wrapped.row_factory

        def execute(statement: str, *parameters: object) -> sqlite3.Cursor:
            if statement == "PRAGMA busy_timeout = 10000":
                raise sqlite3.OperationalError("sanitized setup pragma fixture")
            return wrapped.execute(statement, *parameters)

        def close() -> None:
            connection.closed = True
            wrapped.close()

        connection.execute = execute
        connection.close = close
        connections.append(connection)
        return connection

    monkeypatch.setattr(session_store_module.sqlite3, "connect", failing_connect)

    with pytest.raises(StorageError, match="sanitized setup pragma fixture"):
        store.list_runs()

    assert len(connections) == 1
    assert connections[0].closed is True


def test_initialize_migrates_v1_lifecycle_instance_id(tmp_path: Path) -> None:
    db_path = tmp_path / "tracker.db"
    with closing(sqlite3.connect(db_path)) as connection, connection:
        connection.executescript(
            """
            CREATE TABLE runs (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                bidirectional INTEGER NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE lifecycle_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
                occurred_at TEXT NOT NULL,
                session_key TEXT NOT NULL,
                event_type TEXT NOT NULL,
                controller_name TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            INSERT INTO runs VALUES (
                'legacy-run', '2026-08-28T00:00:00.000Z',
                '2026-08-28T00:01:00.000Z', '192.0.2.1', '203.0.113.1',
                NULL, NULL, 1, 'COMPLETED'
            );
            INSERT INTO lifecycle_events (
                run_id, occurred_at, session_key, event_type,
                controller_name, details_json
            ) VALUES (
                'legacy-run', '2026-08-28T00:00:30.000Z', 'legacy-key',
                'OPENED', 'MD-01', '{}'
            );
            PRAGMA user_version = 1;
            """
        )

    store = SessionStore(db_path, tmp_path / "raw", tmp_path / "exports")
    store.initialize()

    with closing(sqlite3.connect(db_path)) as connection, connection:
        instance_id = connection.execute("SELECT instance_id FROM lifecycle_events").fetchone()[0]
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert instance_id == "legacy-1"
    assert version == 3


def test_initialize_migrates_v2_history_and_adds_empty_poll_receipts(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="v2 migration raw")
    store.finish_run(run_id)
    store.close()
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute("DROP TABLE poll_commits")
        connection.execute("PRAGMA user_version = 2")

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    with closing(sqlite3.connect(store.db_path)) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        run = connection.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
        observation_count = connection.execute(
            "SELECT count(*) FROM observations WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        raw_count = connection.execute(
            "SELECT count(*) FROM raw_files WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
        receipt_count = connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0]

    assert version == 3
    assert run == ("COMPLETED",)
    assert observation_count == 1
    assert raw_count == 1
    assert receipt_count == 0
    assert len(tuple(store.raw_root.rglob("*.txt"))) == 1


@pytest.mark.parametrize(
    ("malformation", "expected_message"),
    [
        ("primary_key", "키 제약"),
        ("operation_unique", "UNIQUE"),
        ("index_columns", "run 조회 인덱스"),
        ("run_cascade", "run 삭제 연계"),
        ("format_checks", "형식 제약"),
    ],
)
def test_initialize_rejects_malformed_poll_commit_constraints(
    tmp_path: Path,
    malformation: str,
    expected_message: str,
) -> None:
    store = _store(tmp_path)
    store.close()
    poll_id_column = (
        "poll_id TEXT"
        if malformation == "primary_key"
        else "poll_id TEXT NOT NULL PRIMARY KEY CHECK ("
        "length(poll_id) = 32 AND poll_id NOT GLOB '*[^0-9a-f]*')"
    )
    operation_id_column = (
        "operation_id TEXT NOT NULL UNIQUE"
        if malformation == "format_checks"
        else "operation_id TEXT NOT NULL "
        f"{' ' if malformation == 'operation_unique' else 'UNIQUE '}CHECK ("
        "length(operation_id) = 32 "
        "AND operation_id NOT GLOB '*[^0-9a-f]*' "
        "AND operation_id = poll_id)"
    )
    run_id_column = (
        "run_id TEXT NOT NULL REFERENCES runs(id)"
        if malformation == "run_cascade"
        else "run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE"
    )
    payload_column = (
        "payload_sha256 TEXT NOT NULL"
        if malformation == "format_checks"
        else "payload_sha256 TEXT NOT NULL CHECK ("
        "length(payload_sha256) = 64 "
        "AND payload_sha256 NOT GLOB '*[^0-9a-f]*')"
    )
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute("DROP TABLE poll_commits")
        connection.execute(
            f"""
            CREATE TABLE poll_commits (
                {poll_id_column},
                {operation_id_column},
                {run_id_column},
                {payload_column},
                committed_at TEXT NOT NULL
            )
            """
        )
        index_columns = "poll_id, run_id" if malformation == "index_columns" else "run_id, poll_id"
        connection.execute(f"CREATE INDEX ix_poll_commits_run_id ON poll_commits({index_columns})")
        connection.execute("PRAGMA user_version = 3")

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match=expected_message):
        reopened.initialize()


def test_initialize_fails_closed_on_foreign_key_corruption(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute(
            """
            INSERT INTO diagnostic_events (
                run_id, occurred_at, stage, code, message
            ) VALUES ('missing-run', '2026-08-28T00:00:00.000Z', 'test', NULL, 'broken')
            """
        )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="외래 키"):
        reopened.initialize()


def test_initialize_preserves_a_run_leased_by_another_live_store(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    store.initialize()
    assert store.list_runs()[0]["status"] == "RUNNING"

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()
    row = reopened.list_runs()[0]
    assert row["id"] == run_id
    assert row["status"] == "RUNNING"
    assert row["ended_at"] is None

    store.finish_run(run_id)
    assert reopened.list_runs()[0]["status"] == "COMPLETED"


def test_file_lease_rejects_hardlink_without_modifying_external_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    external = tmp_path / "external-empty-file.bin"
    external.write_bytes(b"")
    lease_path = store._leases_root / "hardlink-canary.lease"
    try:
        os.link(external, lease_path)
    except OSError as error:
        pytest.skip(f"hardlink creation is unavailable: {error}")

    with pytest.raises(StorageError, match="hardlink"):
        session_store_module._acquire_file_lease(lease_path)

    assert external.read_bytes() == b""
    assert lease_path.read_bytes() == b""
    assert os.stat(external).st_nlink >= 2


def test_release_run_lease_closes_stream_before_removing_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    lease = store._acquire_operation_lease("a" * 32)
    assert lease is not None
    original_unlink = Path.unlink
    closed_when_removed: list[bool] = []

    def observe_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path == lease.path:
            closed_when_removed.append(lease.stream.closed)
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", observe_unlink)
    try:
        session_store_module._release_run_lease(lease, remove=True)
    finally:
        if not lease.stream.closed:
            lease.stream.close()
        if os.path.lexists(lease.path):
            original_unlink(lease.path)

    assert closed_when_removed == [True]
    assert not os.path.lexists(lease.path)


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-violation retry test")
def test_release_run_lease_retries_transient_windows_unlink_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    lease = store._acquire_operation_lease("b" * 32)
    assert lease is not None
    original_unlink = Path.unlink
    attempts = 0

    def transient_unlink(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal attempts
        if path == lease.path:
            attempts += 1
            if attempts == 1:
                error = PermissionError("fixture sharing violation")
                error.winerror = 32
                raise error
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", transient_unlink)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _seconds: None)
    try:
        session_store_module._release_run_lease(lease, remove=True)
    finally:
        if not lease.stream.closed:
            lease.stream.close()
        if os.path.lexists(lease.path):
            original_unlink(lease.path)

    assert attempts == 2
    assert lease.stream.closed
    assert not os.path.lexists(lease.path)


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-violation retry test")
def test_release_run_lease_retries_transient_windows_identity_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    lease = store._acquire_operation_lease("c" * 32)
    assert lease is not None
    original_from_path = session_store_module.windows_file_metadata.from_path
    original_unlink = Path.unlink
    attempts = 0

    def transient_native_metadata(
        path: Path,
    ) -> session_store_module.windows_file_metadata.WindowsFileMetadata:
        nonlocal attempts
        if os.fspath(path) == os.fspath(lease.path):
            attempts += 1
            if attempts == 1:
                error = PermissionError("fixture sharing violation")
                error.winerror = 32
                raise error
        return original_from_path(path)

    monkeypatch.setattr(
        session_store_module.windows_file_metadata,
        "from_path",
        transient_native_metadata,
    )
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _seconds: None)
    try:
        session_store_module._release_run_lease(lease, remove=True)
    finally:
        if not lease.stream.closed:
            lease.stream.close()
        if os.path.lexists(lease.path):
            original_unlink(lease.path)

    assert attempts == 2
    assert lease.stream.closed
    assert not os.path.lexists(lease.path)


def test_second_store_cannot_mutate_another_process_owned_run(tmp_path: Path) -> None:
    owner = _store(tmp_path)
    run_id = _run(owner)
    other = SessionStore(owner.db_path, owner.raw_root, owner.exports_root)
    other.initialize()

    with pytest.raises(StorageError, match="시작한 프로세스"):
        other.record_query(run_id, [_observation()], raw_text="must not write")
    with pytest.raises(StorageError, match="시작한 프로세스"):
        other.finish_run(run_id)

    assert owner.list_runs()[0]["status"] == "RUNNING"
    assert not tuple(owner.raw_root.rglob("*.txt"))
    owner.finish_run(run_id)


def test_initialize_interrupts_a_run_after_its_process_exits(tmp_path: Path) -> None:
    db_path = tmp_path / "tracker.db"
    raw_root = tmp_path / "raw"
    exports_root = tmp_path / "exports"
    script = """
import os
import sys
from aruba_session_tracker.models import QueryRequest
from aruba_session_tracker.storage import SessionStore
store = SessionStore(sys.argv[1], sys.argv[2], sys.argv[3])
store.initialize()
store.start_run(QueryRequest('192.0.2.1', '203.0.113.1'), run_id='crashed-run')
os._exit(0)
"""
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script, str(db_path), str(raw_root), str(exports_root)],
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0

    reopened = SessionStore(db_path, raw_root, exports_root)
    reopened.initialize()
    row = reopened.list_runs()[0]
    assert row["id"] == "crashed-run"
    assert row["status"] == "INTERRUPTED"
    assert row["ended_at"] is not None


def test_record_query_links_relative_raw_path_sha256_and_legacy_kind(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    raw_text = "한글 Raw 출력\n"

    observation_ids = store.record_query(
        run_id,
        [_observation(controller_name="서울-MD")],
        raw_text=raw_text,
        controller_name="서울-MD",
        raw_kind="legacy-custom-kind",
    )

    assert len(observation_ids) == 1
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        relative_path, digest, size, raw_kind = connection.execute(
            "SELECT relative_path, sha256, byte_size, kind FROM raw_files WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        stored_raw_line = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='observations'"
        ).fetchone()[0]

    assert not Path(relative_path).is_absolute()
    raw_path = store.raw_root / relative_path
    assert raw_path.read_text(encoding="utf-8") == raw_text
    assert digest == hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    assert size == len(raw_text.encode("utf-8"))
    assert raw_kind == "legacy-custom-kind"
    assert "raw_line" not in stored_raw_line


def test_single_snapshot_preserves_unicode_only_controller_name(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    controller_name = "서울장비🔥"
    raw_text = "순수 유니코드 장비 Raw 출력\n"

    store.record_query(
        run_id,
        [_observation(controller_name=controller_name)],
        raw_text=raw_text,
        controller_name=controller_name,
    )

    with closing(sqlite3.connect(store.db_path)) as connection:
        stored_name, relative_path = connection.execute(
            "SELECT controller_name, relative_path FROM raw_files WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    assert stored_name == controller_name
    assert re.search(r"controller-[0-9a-f]{8}", Path(relative_path).name)
    assert Path(relative_path).name.isascii()
    assert (store.raw_root / relative_path).read_text(encoding="utf-8") == raw_text


def test_record_poll_batch_is_atomic_when_a_late_insert_fails(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        diagnostics=(
            DiagnosticEvent(stage="poll", code=ErrorCode.DB_WRITE_FAILED, message="late"),
        ),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "raw batch",
                observation.observed_at,
            ),
        ),
        authoritative=True,
    )
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER fail_batch_diagnostic
            BEFORE INSERT ON diagnostic_events
            BEGIN
                SELECT RAISE(ABORT, 'forced late batch failure');
            END
            """
        )

    with pytest.raises(StorageError, match="batch"):
        store.record_poll_batch(run_id, outcome)

    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM diagnostic_events").fetchone()[0] == 0
    assert not tuple(store.raw_root.rglob("*.txt"))
    assert not tuple((tmp_path / ".operations" / "manifests").glob("*.json"))
    assert not tuple(store.raw_root.glob(".raw-staging-*"))


def test_record_poll_batch_is_exactly_once_for_the_same_poll_id(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "1" * 32
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        diagnostics=(
            DiagnosticEvent(
                stage="poll",
                code=ErrorCode.PARSE_PARTIAL,
                message="sanitized fixture diagnostic",
            ),
        ),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "exactly-once raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        ),
        authoritative=True,
    )
    events = (
        LifecycleEvent(
            LifecycleEventType.STARTED,
            "fixture-instance",
            observation,
            occurred_at=observation.observed_at,
        ),
    )

    first = store.record_poll_batch(run_id, outcome, events, poll_id=poll_id)
    second = store.record_poll_batch(run_id, outcome, events, poll_id=poll_id)

    assert first.status is session_store_module.PollPersistenceStatus.COMMITTED
    assert second.status is session_store_module.PollPersistenceStatus.ALREADY_COMMITTED
    with closing(sqlite3.connect(store.db_path)) as connection:
        counts = {
            table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]  # noqa: S608
            for table in (
                "poll_commits",
                "raw_files",
                "observations",
                "diagnostic_events",
                "lifecycle_events",
            )
        }
    assert counts == {
        "poll_commits": 1,
        "raw_files": 1,
        "observations": 1,
        "diagnostic_events": 1,
        "lifecycle_events": 1,
    }
    assert len(tuple(store.raw_root.rglob("*.txt"))) == 1


@pytest.mark.parametrize("include_raw", (False, True))
def test_poll_batch_uses_native_windows_metadata_when_crt_stat_is_incomplete(
    include_raw: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation()
    original_lstat = os.lstat

    def incomplete_regular_lstat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> os.stat_result:
        info = original_lstat(path, *args, **kwargs)  # type: ignore[arg-type]
        if not stat.S_ISREG(info.st_mode):
            return info
        values = list(info)
        values[1] = 0
        values[2] = 0
        values[6] = 0
        return os.stat_result(values)

    def native_info(info: os.stat_result) -> object:
        attributes = 0x10 if stat.S_ISDIR(info.st_mode) else 0
        return session_store_module.windows_file_metadata.WindowsFileMetadata(
            volume_serial_number=int(info.st_dev),
            file_index=int(info.st_ino),
            number_of_links=int(info.st_nlink),
            file_attributes=attributes,
            file_size=int(info.st_size),
            modified_ns=int(info.st_mtime_ns),
        )

    monkeypatch.setattr(os, "lstat", incomplete_regular_lstat)
    monkeypatch.setattr(
        session_store_module.windows_file_metadata,
        "available",
        lambda: True,
    )
    monkeypatch.setattr(
        session_store_module.windows_file_metadata,
        "from_path",
        lambda path: native_info(os.stat(path, follow_symlinks=False)),
    )
    monkeypatch.setattr(
        session_store_module.windows_file_metadata,
        "from_descriptor",
        lambda descriptor: native_info(os.fstat(descriptor)),
    )
    outcome = QueryOutcome(
        observations=(observation,) if include_raw else (),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "native metadata raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        )
        if include_raw
        else (),
        authoritative=True,
    )

    result = store.record_poll_batch(
        run_id,
        outcome,
        poll_id=("b" if include_raw else "a") * 32,
    )

    assert result.status is session_store_module.PollPersistenceStatus.COMMITTED
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == int(
            include_raw
        )
    assert not tuple(store._manifests_root.glob("*.json"))
    assert not tuple(store.raw_root.glob(".raw-staging-*"))
    store.finish_run(run_id)


def test_raw_staging_and_compact_temporary_fit_legacy_windows_path_limit() -> None:
    profile_root = (
        PureWindowsPath("C:/Users")
        / "very-long-corporate-username"
        / "AppData/Local/ArubaSessionTracker"
    )
    stage_root = profile_root / "raw" / f".raw-staging-{'a' * 32}"
    staged = stage_root / session_store_module._raw_staged_name("b" * 64)
    temporary = staged.with_name(f".tmp-{'c' * 32}")

    assert staged.parent == stage_root
    assert len(str(staged)) < 260
    assert len(str(temporary)) < 260
    assert "very-long-corporate-username" in str(staged)
    assert staged.name not in temporary.name


def test_compact_atomic_temporary_does_not_repeat_destination_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / f"{'d' * 64}.raw"
    captured_source: Path | None = None
    original_replace = session_store_module._replace_file

    def capture_replace(source: Path, target: Path, **kwargs: object) -> None:
        nonlocal captured_source
        captured_source = source
        original_replace(source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        session_store_module,
        "uuid4",
        lambda: SimpleNamespace(hex="e" * 32),
    )
    monkeypatch.setattr(session_store_module, "_replace_file", capture_replace)

    session_store_module._write_bytes_atomic(
        destination,
        b"raw payload",
        compact_temporary=True,
    )

    assert captured_source is not None
    assert captured_source.name == f".tmp-{'e' * 32}"
    assert destination.read_bytes() == b"raw payload"


def test_raw_manifest_staged_name_is_digest_bound_and_legacy_compatible() -> None:
    digest = "f" * 64
    common = {
        "relative_path": "run/20260902/08/raw.txt",
        "sha256": digest,
        "byte_size": 3,
    }

    current = session_store_module._manifest_files(
        {"files": [{**common, "staged_name": f"{digest}.raw"}]}
    )
    legacy = session_store_module._manifest_files({"files": [common]})

    assert current[0]["staged_name"] == f"{digest}.raw"
    assert legacy[0]["staged_name"] is None
    with pytest.raises(StorageError, match="staging 파일명"):
        session_store_module._manifest_files({"files": [{**common, "staged_name": "other.raw"}]})


def test_record_poll_batch_rejects_reused_poll_id_with_different_payload(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "2" * 32
    observation = _observation()
    store.record_poll_batch(
        run_id,
        QueryOutcome(observations=(observation,), authoritative=True),
        poll_id=poll_id,
    )

    with pytest.raises(StorageError, match="다른 poll 내용"):
        store.record_poll_batch(
            run_id,
            QueryOutcome(
                observations=(replace(observation, packets=observation.packets + 1),),
                authoritative=True,
            ),
            poll_id=poll_id,
        )

    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


def test_record_poll_batch_rejects_reused_poll_id_for_another_run(tmp_path: Path) -> None:
    store = _store(tmp_path)
    first_run_id = _run(store)
    second_run_id = _run(store)
    poll_id = "3" * 32
    outcome = QueryOutcome(observations=(_observation(),), authoritative=True)
    store.record_poll_batch(first_run_id, outcome, poll_id=poll_id)

    with pytest.raises(StorageError, match="다른 poll 내용"):
        store.record_poll_batch(second_run_id, outcome, poll_id=poll_id)

    with closing(sqlite3.connect(store.db_path)) as connection:
        receipt_run_id = connection.execute(
            "SELECT run_id FROM poll_commits WHERE poll_id = ?", (poll_id,)
        ).fetchone()[0]
        first_count = connection.execute(
            "SELECT count(*) FROM observations WHERE run_id = ?", (first_run_id,)
        ).fetchone()[0]
        second_count = connection.execute(
            "SELECT count(*) FROM observations WHERE run_id = ?", (second_run_id,)
        ).fetchone()[0]
    assert receipt_run_id == first_run_id
    assert first_count == 1
    assert second_count == 0


def test_poll_commit_retries_busy_once_without_duplicate_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    original_commit = SessionStore._commit_poll_batch_once
    attempts = 0
    sleeps: list[float] = []

    def fail_busy_once(self: SessionStore, *args: object, **kwargs: object) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            error = sqlite3.OperationalError("sanitized busy fixture")
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error
        return original_commit(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(SessionStore, "_commit_poll_batch_once", fail_busy_once)
    monkeypatch.setattr(session_store_module.time, "sleep", sleeps.append)

    result = store.record_poll_batch(
        run_id,
        QueryOutcome(observations=(_observation(),), authoritative=True),
        poll_id="4" * 32,
    )

    assert result.status is session_store_module.PollPersistenceStatus.COMMITTED
    assert attempts == 2
    assert sleeps == [session_store_module._POLL_COMMIT_RETRY_DELAYS[1]]
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


@pytest.mark.parametrize(
    "sqlite_code",
    [
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
        *[
            value
            for name in (
                "SQLITE_IOERR_LOCK",
                "SQLITE_IOERR_RDLOCK",
                "SQLITE_IOERR_CHECKRESERVEDLOCK",
                "SQLITE_IOERR_SHMLOCK",
            )
            if isinstance(value := getattr(sqlite3, name, None), int)
        ],
    ],
)
def test_poll_commit_retries_only_explicit_lock_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sqlite_code: int,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    original_commit = SessionStore._commit_poll_batch_once
    attempts = 0

    def fail_lock_once(self: SessionStore, *args: object, **kwargs: object) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            error = sqlite3.OperationalError("sanitized lock fixture")
            error.sqlite_errorcode = sqlite_code
            raise error
        return original_commit(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(SessionStore, "_commit_poll_batch_once", fail_lock_once)
    result = store.record_poll_batch(
        run_id,
        QueryOutcome(observations=(_observation(),), authoritative=True),
        poll_id="a" * 32,
    )

    assert result.status is session_store_module.PollPersistenceStatus.COMMITTED
    assert attempts == 2
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


def test_poll_commit_busy_exhaustion_has_typed_query_result_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    def always_busy(*_args: object, **_kwargs: object) -> bool:
        error = sqlite3.OperationalError("sanitized busy fixture")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        raise error

    monkeypatch.setattr(store, "_commit_poll_batch_once", always_busy)
    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            run_id,
            QueryOutcome(observations=(_observation(),), authoritative=True),
            poll_id="b" * 32,
        )

    assert caught.value.code is ErrorCode.STORAGE_BUSY
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_BUSY
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT


def test_poll_commit_receipt_retries_transient_sqlite_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    original_connection = store._connection
    attempts = 0
    sleeps: list[float] = []

    @contextmanager
    def flaky_connection(*, uninitialized: bool = False) -> Iterator[sqlite3.Connection]:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            error = sqlite3.OperationalError("sanitized receipt lock fixture")
            error.sqlite_errorcode = sqlite3.SQLITE_LOCKED
            raise error
        with original_connection(uninitialized=uninitialized) as connection:
            yield connection

    monkeypatch.setattr(store, "_connection", flaky_connection)
    monkeypatch.setattr(session_store_module.time, "sleep", sleeps.append)

    assert store._poll_commit_receipt("c" * 32) is None
    assert attempts == 3
    assert sleeps == list(session_store_module._POLL_COMMIT_RETRY_DELAYS[1:])


def test_poll_commit_does_not_retry_non_lock_operational_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    attempts = 0

    def fail_io(self: SessionStore, *args: object, **kwargs: object) -> bool:
        del self, args, kwargs
        nonlocal attempts
        attempts += 1
        error = sqlite3.OperationalError("sanitized io fixture")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        raise error

    monkeypatch.setattr(SessionStore, "_commit_poll_batch_once", fail_io)

    with pytest.raises(StorageError, match="batch"):
        store.record_poll_batch(
            run_id,
            QueryOutcome(observations=(_observation(),), authoritative=True),
            poll_id="5" * 32,
        )

    assert attempts == 1
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 0


def test_poll_commit_receipt_resolves_lost_commit_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "6" * 32
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "lost acknowledgement raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        ),
        authoritative=True,
    )
    original_commit = SessionStore._commit_poll_batch_once
    attempts = 0

    def commit_then_lose_ack(self: SessionStore, *args: object, **kwargs: object) -> bool:
        nonlocal attempts
        attempts += 1
        original_commit(self, *args, **kwargs)  # type: ignore[arg-type]
        error = sqlite3.OperationalError("sanitized lost acknowledgement")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        raise error

    monkeypatch.setattr(SessionStore, "_commit_poll_batch_once", commit_then_lose_ack)

    result = store.record_poll_batch(run_id, outcome, poll_id=poll_id)

    assert result.status is session_store_module.PollPersistenceStatus.ALREADY_COMMITTED
    assert attempts == 1
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1
    assert len(tuple(store.raw_root.rglob("*.txt"))) == 1


def test_indeterminate_poll_commit_keeps_recovery_anchor_and_reuses_poll_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "e" * 32
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "indeterminate commit raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        ),
        authoritative=True,
    )
    original_receipt = store._poll_commit_receipt
    original_commit = store._commit_poll_batch_once
    commit_attempted = False

    def fail_commit(*_args: object, **_kwargs: object) -> bool:
        nonlocal commit_attempted
        commit_attempted = True
        error = sqlite3.OperationalError("sanitized unknown commit fixture")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        raise error

    def fail_receipt_after_commit_attempt(
        candidate: str,
        *,
        uninitialized: bool = False,
    ) -> tuple[str, str] | None:
        if commit_attempted:
            raise sqlite3.OperationalError("sanitized receipt probe fixture")
        return original_receipt(candidate, uninitialized=uninitialized)

    monkeypatch.setattr(store, "_commit_poll_batch_once", fail_commit)
    monkeypatch.setattr(store, "_poll_commit_receipt", fail_receipt_after_commit_attempt)

    with pytest.raises(session_store_module.PollPersistenceIndeterminate) as captured:
        store.record_poll_batch(run_id, outcome, poll_id=poll_id)

    manifest = store._manifests_root / f"{poll_id}.json"
    assert captured.value.poll_id == poll_id
    assert captured.value.code is ErrorCode.PERSISTENCE_INDETERMINATE
    assert captured.value.failure_kind is StorageFailureKind.PERSISTENCE_INDETERMINATE
    assert captured.value.boundary is StorageFailureBoundary.QUERY_RESULT
    assert manifest.exists()
    assert json.loads(manifest.read_text(encoding="utf-8"))["phase"] == "INSTALLED"
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 0

    monkeypatch.setattr(store, "_commit_poll_batch_once", original_commit)
    monkeypatch.setattr(store, "_poll_commit_receipt", original_receipt)
    result = store.record_poll_batch(run_id, outcome, poll_id=poll_id)

    assert result.status is session_store_module.PollPersistenceStatus.COMMITTED
    assert not manifest.exists()
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1
    assert len(tuple(store.raw_root.rglob("*.txt"))) == 1


def test_committed_poll_cleanup_failure_is_pending_and_restart_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "7" * 32
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "restart recovery raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        ),
        authoritative=True,
    )
    manifest = store._manifests_root / f"{poll_id}.json"
    original_unlink = Path.unlink
    failed = False

    def fail_manifest_cleanup_once(path: Path, *args: object, **kwargs: object) -> None:
        nonlocal failed
        if path == manifest and not failed:
            failed = True
            raise OSError("sanitized committed cleanup fixture")
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "unlink", fail_manifest_cleanup_once)

    result = store.record_poll_batch(run_id, outcome, poll_id=poll_id)

    assert result.status is session_store_module.PollPersistenceStatus.COMMITTED_RECOVERY_PENDING
    assert result.cleanup_error_type == "OSError"
    assert manifest.exists()
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        relative_path = connection.execute(
            "SELECT relative_path FROM raw_files WHERE run_id = ?", (run_id,)
        ).fetchone()[0]
    assert (store.raw_root / relative_path).exists()

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert not manifest.exists()
    repeated = store.record_poll_batch(run_id, outcome, poll_id=poll_id)
    assert repeated.status is session_store_module.PollPersistenceStatus.ALREADY_COMMITTED
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


def test_committed_poll_lease_cleanup_failure_keeps_recovery_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "a" * 32
    outcome = QueryOutcome(authoritative=True)
    manifest = store._manifests_root / f"{poll_id}.json"
    operation_lease_path = store._leases_root / f"operation-{poll_id}.lease"
    original_remove_lease = session_store_module._remove_released_lease_with_retry
    failed = False

    def fail_operation_lease_once(lease: session_store_module._RunLease) -> None:
        nonlocal failed
        if lease.path == operation_lease_path and not failed:
            failed = True
            raise OSError("sanitized operation lease cleanup fixture")
        original_remove_lease(lease)

    monkeypatch.setattr(
        session_store_module,
        "_remove_released_lease_with_retry",
        fail_operation_lease_once,
    )

    result = store.record_poll_batch(run_id, outcome, poll_id=poll_id)

    assert result.status is session_store_module.PollPersistenceStatus.COMMITTED_RECOVERY_PENDING
    assert result.cleanup_error_type == "OSError"
    assert manifest.exists()
    assert operation_lease_path.exists()
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert not manifest.exists()
    assert not operation_lease_path.exists()
    repeated = store.record_poll_batch(run_id, outcome, poll_id=poll_id)
    assert repeated.status is session_store_module.PollPersistenceStatus.ALREADY_COMMITTED
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1


def test_startup_recovers_committed_poll_receipt_without_raw_files(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "8" * 32
    outcome = QueryOutcome(authoritative=True)
    store.record_poll_batch(run_id, outcome, poll_id=poll_id)
    with closing(sqlite3.connect(store.db_path)) as connection:
        payload_sha256 = connection.execute(
            "SELECT payload_sha256 FROM poll_commits WHERE poll_id = ?", (poll_id,)
        ).fetchone()[0]
    manifest = store._write_manifest(
        poll_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": poll_id,
            "poll_id": poll_id,
            "run_id": run_id,
            "payload_sha256": payload_sha256,
            "phase": "DB_COMMITTED",
            "stage_root": f".raw-staging-{poll_id}",
            "files": [],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert not manifest.exists()
    result = store.record_poll_batch(run_id, outcome, poll_id=poll_id)
    assert result.status is session_store_module.PollPersistenceStatus.ALREADY_COMMITTED
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 0


def test_startup_rejects_poll_manifest_with_mismatched_database_fingerprint(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "d" * 32
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "fingerprint fixture raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        ),
        authoritative=True,
    )
    store.record_poll_batch(run_id, outcome, poll_id=poll_id)
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative_path, _sha256, byte_size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        payload_sha256 = connection.execute(
            "SELECT payload_sha256 FROM poll_commits WHERE poll_id = ?", (poll_id,)
        ).fetchone()[0]
    raw_path = store.raw_root / str(relative_path)
    original_bytes = raw_path.read_bytes()
    manifest = store._write_manifest(
        poll_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": poll_id,
            "poll_id": poll_id,
            "run_id": run_id,
            "payload_sha256": payload_sha256,
            "phase": "DB_COMMITTED",
            "stage_root": f".raw-staging-{poll_id}",
            "files": [
                {
                    "relative_path": relative_path,
                    "sha256": "0" * 64,
                    "byte_size": byte_size,
                }
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="fingerprint"):
        reopened.initialize()

    assert manifest.exists()
    assert raw_path.read_bytes() == original_bytes


@pytest.mark.parametrize("database_deleted", (False, True))
def test_startup_recovers_delete_before_older_committed_poll_manifest(
    tmp_path: Path,
    database_deleted: bool,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "0" * 32
    delete_id = "f" * 32
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "delete ordering raw",
                observation.observed_at,
                (observation.session_key,),
            ),
        ),
        authoritative=True,
    )
    store.record_poll_batch(run_id, outcome, poll_id=poll_id)
    store.finish_run(run_id)
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative_path, sha256, byte_size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        payload_sha256 = connection.execute(
            "SELECT payload_sha256 FROM poll_commits WHERE poll_id = ?", (poll_id,)
        ).fetchone()[0]
    raw_manifest = store._write_manifest(
        poll_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": poll_id,
            "poll_id": poll_id,
            "run_id": run_id,
            "payload_sha256": payload_sha256,
            "phase": "DB_COMMITTED",
            "stage_root": f".raw-staging-{poll_id}",
            "files": [
                {
                    "relative_path": relative_path,
                    "sha256": sha256,
                    "byte_size": byte_size,
                }
            ],
        },
    )
    snapshot = store._collect_deletion_snapshot(run_id)
    delete_manifest = store._write_manifest(
        delete_id,
        {
            "version": 1,
            "kind": "delete",
            "operation_id": delete_id,
            "files": [
                {
                    "category": "raw",
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "byte_size": item.byte_size,
                    "registered": item.registered,
                }
                for item in snapshot.raw_files
            ],
        },
    )
    staged: list[session_store_module._StagedFile] = []
    session_store_module._stage_files(
        store.raw_root,
        snapshot.raw_files,
        delete_id,
        "raw",
        staged,
    )
    raw_path = store.raw_root / str(relative_path)
    assert not raw_path.exists()
    if database_deleted:
        with closing(sqlite3.connect(store.db_path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("DELETE FROM runs WHERE id = ?", (run_id,))

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert not raw_manifest.exists()
    assert not delete_manifest.exists()
    assert not tuple(store.raw_root.glob(".delete-staging-*"))
    with closing(sqlite3.connect(store.db_path)) as connection:
        run_count = connection.execute(
            "SELECT count(*) FROM runs WHERE id = ?", (run_id,)
        ).fetchone()[0]
        receipt_count = connection.execute(
            "SELECT count(*) FROM poll_commits WHERE poll_id = ?", (poll_id,)
        ).fetchone()[0]
    assert run_count == int(not database_deleted)
    assert receipt_count == int(not database_deleted)
    assert raw_path.exists() is not database_deleted


def test_deleting_run_cascades_poll_commit_receipts(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    poll_id = "9" * 32
    store.record_poll_batch(
        run_id,
        QueryOutcome(observations=(_observation(),), authoritative=True),
        poll_id=poll_id,
    )
    store.finish_run(run_id)
    preview = store.preview_delete(run_id)

    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert result.deleted_runs == 1
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert (
            connection.execute("SELECT count(*) FROM runs WHERE id = ?", (run_id,)).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM poll_commits WHERE poll_id = ?", (poll_id,)
            ).fetchone()[0]
            == 0
        )


def test_raw_file_install_runs_without_sqlite_writer_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    checked_install = False
    original_replace = session_store_module._replace_file

    def observe_replace(
        source: Path,
        target: Path,
        **kwargs: object,
    ) -> None:
        nonlocal checked_install
        if target.is_relative_to(store.raw_root) and not target.name.startswith("."):
            with closing(sqlite3.connect(store.db_path, timeout=0.1)) as connection:
                connection.execute("PRAGMA busy_timeout = 100")
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            checked_install = True
        original_replace(source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "_replace_file", observe_replace)

    store.record_query(run_id, [_observation()], raw_text="writer-lock-canary")

    assert checked_install is True
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1


@pytest.mark.parametrize("limit_kind", ("observations", "raw"))
def test_record_poll_batch_rejects_storage_limits_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_kind: str,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    first = _observation()
    second = replace(first, destination_port=8443)
    if limit_kind == "observations":
        monkeypatch.setattr(session_store_module, "_MAX_POLL_OBSERVATIONS", 1)
        outcome = QueryOutcome(observations=(first, second), authoritative=True)
    else:
        monkeypatch.setattr(session_store_module, "_MAX_POLL_RAW_BYTES", 3)
        outcome = QueryOutcome(
            raw_snapshots=(RawSnapshot("MD-01", "show test", "1234"),),
            authoritative=True,
        )

    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(run_id, outcome)

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert caught.value.failure_kind is StorageFailureKind.OUTPUT_LIMIT
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 0
    assert not tuple(store.raw_root.rglob("*.txt"))
    assert not tuple(store._manifests_root.glob("*.json"))


def test_poll_batch_allows_bounded_lifecycle_events_above_observation_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _observation()
    second = replace(first, destination_port=8443)
    outcome = QueryOutcome(observations=(first, second), authoritative=True)
    monkeypatch.setattr(session_store_module, "_MAX_POLL_OBSERVATIONS", 2)
    monkeypatch.setattr(session_store_module, "_MAX_POLL_LIFECYCLE_EVENTS", 8)

    SessionStore._validate_poll_batch_limits(outcome, (object(),) * 8)  # type: ignore[arg-type]

    with pytest.raises(StorageError) as caught:
        SessionStore._validate_poll_batch_limits(  # type: ignore[arg-type]
            outcome,
            (object(),) * 9,
        )
    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_poll_bundle_limit_counts_metadata_and_delimiters_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    monkeypatch.setattr(session_store_module, "_MAX_POLL_RAW_BYTES", 512)
    observed_at = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
    outcome = QueryOutcome(
        raw_snapshots=(
            RawSnapshot("M1", "show one", "A" * 200, observed_at, observation_keys=()),
            RawSnapshot("M2", "show two", "B" * 200, observed_at, observation_keys=()),
        ),
        authoritative=True,
    )

    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(run_id, outcome)

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 0
    assert not tuple(store.raw_root.rglob("*.txt"))
    assert not tuple(store._manifests_root.glob("*.json"))


def test_poll_bundle_exact_persisted_boundary_matches_shared_sizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observed_at = datetime(2026, 8, 28, 8, 0, tzinfo=UTC)
    snapshots = (
        RawSnapshot("서울-MM", "show one", "가" * 40, observed_at, observation_keys=()),
        RawSnapshot("서울-MD", "show two", "B" * 40, observed_at, observation_keys=()),
    )
    expected_size = persisted_raw_size(snapshots)
    monkeypatch.setattr(session_store_module, "_MAX_POLL_RAW_BYTES", expected_size)

    store.record_poll_batch(
        run_id,
        QueryOutcome(raw_snapshots=snapshots, authoritative=True),
        poll_id="d" * 32,
    )

    raw_files = tuple(store.raw_root.rglob("*.txt"))
    assert len(raw_files) == 1
    assert raw_files[0].stat().st_size == expected_size

    rejected_run_id = _run(store)
    monkeypatch.setattr(session_store_module, "_MAX_POLL_RAW_BYTES", expected_size - 1)
    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            rejected_run_id,
            QueryOutcome(raw_snapshots=snapshots, authoritative=True),
            poll_id="e" * 32,
        )
    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert caught.value.failure_kind is StorageFailureKind.OUTPUT_LIMIT
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT
    store.finish_run(run_id)
    store.finish_run(rejected_run_id, status="FAILED")


def test_nontransient_raw_path_error_is_not_reported_as_database_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    def fail_path(*_args: object, **_kwargs: object) -> object:
        raise OSError("sanitized raw path fixture")

    monkeypatch.setattr(store, "_prepare_poll_raw_files", fail_path)
    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            run_id,
            QueryOutcome(authoritative=True),
            poll_id="f" * 32,
        )

    assert caught.value.code is ErrorCode.STORAGE_PATH_FAILED
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT
    store.finish_run(run_id, status="FAILED")


def test_poll_batch_prevalidation_wraps_path_error_at_query_result_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    original_initialized_check = store._ensure_initialized

    def fail_initialized_check() -> None:
        raise PermissionError("sanitized prevalidation path fixture")

    monkeypatch.setattr(store, "_ensure_initialized", fail_initialized_check)
    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            run_id,
            QueryOutcome(authoritative=True),
            poll_id="0" * 32,
        )

    assert caught.value.code is ErrorCode.STORAGE_PATH_FAILED
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT

    monkeypatch.setattr(store, "_ensure_initialized", original_initialized_check)
    store.finish_run(run_id, status="FAILED")


def test_poll_id_validation_is_typed_at_query_result_boundary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            run_id,
            QueryOutcome(authoritative=True),
            poll_id="not-a-valid-poll-id",
        )

    assert caught.value.code is ErrorCode.DB_WRITE_FAILED
    assert caught.value.failure_kind is StorageFailureKind.DATABASE_WRITE
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT
    store.finish_run(run_id, status="FAILED")


@pytest.mark.parametrize(
    ("error_attribute", "error_number"),
    (("errno", errno.ENOSPC), ("winerror", 112), ("winerror", 39)),
)
def test_actual_disk_full_errors_preserve_low_space_query_result_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_attribute: str,
    error_number: int,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    def fail_write(*_args: object, **_kwargs: object) -> object:
        if error_attribute == "errno":
            error = OSError(error_number, "sanitized disk-full fixture")
        else:
            error = OSError("sanitized disk-full fixture")
            error.winerror = error_number
        raise error

    monkeypatch.setattr(store, "_prepare_poll_raw_files", fail_write)
    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            run_id,
            QueryOutcome(authoritative=True),
            poll_id="1" * 32,
        )

    assert caught.value.code is ErrorCode.STORAGE_LOW_SPACE
    assert caught.value.failure_kind is StorageFailureKind.LOW_SPACE
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT
    store.finish_run(run_id, status="FAILED")


def test_sqlite_full_preserves_low_space_query_result_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    def fail_full(*_args: object, **_kwargs: object) -> bool:
        error = sqlite3.OperationalError("sanitized SQLite full fixture")
        error.sqlite_errorcode = sqlite3.SQLITE_FULL
        raise error

    monkeypatch.setattr(store, "_commit_poll_batch_once", fail_full)
    with pytest.raises(StorageError) as caught:
        store.record_poll_batch(
            run_id,
            QueryOutcome(authoritative=True),
            poll_id="2" * 32,
        )

    assert caught.value.code is ErrorCode.STORAGE_LOW_SPACE
    assert caught.value.failure_kind is StorageFailureKind.LOW_SPACE
    assert caught.value.boundary is StorageFailureBoundary.QUERY_RESULT
    store.finish_run(run_id, status="FAILED")


def test_record_poll_batch_uses_explicit_same_controller_raw_provenance(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation(packets=99)
    first_output = "first same-controller snapshot"
    second_output = "second same-controller snapshot packets=99"
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                first_output,
                observation.observed_at - timedelta(seconds=1),
                observation_keys=(),
            ),
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                second_output,
                observation.observed_at,
                observation_keys=(observation.session_key,),
            ),
        ),
        authoritative=True,
    )

    store.record_poll_batch(run_id, outcome)

    with closing(sqlite3.connect(store.db_path)) as connection:
        relative_path, kind, controller_name = connection.execute(
            """
            SELECT rf.relative_path, rf.kind, rf.controller_name
            FROM observations AS observation
            JOIN raw_files AS rf ON rf.id = observation.raw_file_id
            WHERE observation.run_id = ?
            """,
            (run_id,),
        ).fetchone()
        raw_file_count = connection.execute(
            "SELECT count(*) FROM raw_files WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    raw_path = store.raw_root / relative_path
    sections = (
        session_store_module._RawBundleSection(
            1,
            hashlib.sha256(first_output.encode()).hexdigest(),
            len(first_output.encode()),
        ),
        session_store_module._RawBundleSection(
            2,
            hashlib.sha256(second_output.encode()).hexdigest(),
            len(second_output.encode()),
        ),
    )
    assert raw_file_count == 1
    assert kind == "poll-bundle"
    assert controller_name == "POLL_BUNDLE"
    session_store_module._verify_raw_bundle_file(raw_path, sections)
    bundle = raw_path.read_text(encoding="utf-8")
    assert first_output in bundle
    assert second_output in bundle
    assert '"snapshot_count":2' in bundle
    assert '"observation_keys":[]' in bundle
    assert f'"observation_keys":["{observation.session_key}"]' in bundle


def test_poll_batch_persists_cross_controller_overlap_without_schema_change(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    first = _observation(controller_name="MD-01", controller_host="198.51.100.21")
    second = _observation(controller_name="MD-02", controller_host="198.51.100.22")
    outcome = QueryOutcome(
        observations=(first, second),
        diagnostics=(
            DiagnosticEvent(
                stage="MONITOR_STATE",
                code=ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS,
                message="fixture overlap",
            ),
        ),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "first controller output",
                observation_keys=(first.session_key,),
            ),
            RawSnapshot(
                "MD-02",
                "show datapath session table 192.0.2.100",
                "second controller output",
                observation_keys=(second.session_key,),
            ),
        ),
        authoritative=True,
    )

    store.record_poll_batch(run_id, outcome)

    with closing(sqlite3.connect(store.db_path)) as connection:
        observations = connection.execute(
            """
            SELECT controller_host, session_key, raw_file_id
            FROM observations WHERE run_id = ? ORDER BY controller_host
            """,
            (run_id,),
        ).fetchall()
        diagnostic_code = connection.execute(
            "SELECT code FROM diagnostic_events WHERE run_id = ?",
            (run_id,),
        ).fetchone()[0]
        schema_version = connection.execute("PRAGMA user_version").fetchone()[0]

    assert [row[:2] for row in observations] == [
        (first.controller_host, first.session_key),
        (second.controller_host, second.session_key),
    ]
    assert observations[0][2] is not None
    assert observations[1][2] == observations[0][2]
    assert diagnostic_code == ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS.value
    assert schema_version == 3


def test_poll_bundle_keeps_csv_references_and_deletes_as_one_file(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    first = _observation(controller_name="MD-01")
    second = replace(
        first,
        controller_name="MD-02",
        controller_host="198.51.100.22",
        destination_port=8443,
    )
    store.record_poll_batch(
        run_id,
        QueryOutcome(
            observations=(first, second),
            raw_snapshots=(
                RawSnapshot(
                    "MD-01",
                    "show datapath session table first",
                    "first body",
                    first.observed_at,
                    observation_keys=(first.session_key,),
                ),
                RawSnapshot(
                    "MD-02",
                    "show datapath session table second",
                    "second body",
                    second.observed_at,
                    observation_keys=(second.session_key,),
                ),
            ),
            authoritative=True,
        ),
    )
    store.finish_run(run_id)

    exported = store.export_run_csv(run_id, tmp_path / "bundle.csv")
    with exported.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == 2
    assert len({row["raw_relative_path"] for row in rows}) == 1
    assert len({row["raw_sha256"] for row in rows}) == 1

    preview = store.preview_delete(run_id)
    result = store.delete(preview, confirmation_token=preview.confirmation_token)
    assert preview.raw_files == 1
    assert result.deleted_raw_files == 1
    assert not tuple(store.raw_root.rglob("*.txt"))


def test_raw_bundle_section_hash_detects_tampered_body(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation()
    outputs = ("first-body", "second-body")
    store.record_poll_batch(
        run_id,
        QueryOutcome(
            observations=(observation,),
            raw_snapshots=(
                RawSnapshot("MM-01", "show first", outputs[0], observation.observed_at, ()),
                RawSnapshot(
                    "MD-01",
                    "show second",
                    outputs[1],
                    observation.observed_at,
                    (observation.session_key,),
                ),
            ),
            authoritative=True,
        ),
    )
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative_path = str(connection.execute("SELECT relative_path FROM raw_files").fetchone()[0])
    raw_path = store.raw_root / relative_path
    sections = tuple(
        session_store_module._RawBundleSection(
            index,
            hashlib.sha256(output.encode()).hexdigest(),
            len(output.encode()),
        )
        for index, output in enumerate(outputs, start=1)
    )
    session_store_module._verify_raw_bundle_file(raw_path, sections)
    tampered = raw_path.read_bytes().replace(b"first-body", b"first-bodz", 1)
    raw_path.write_bytes(tampered)

    with pytest.raises(StorageError, match="section SHA-256"):
        session_store_module._verify_raw_bundle_file(raw_path, sections)


def test_startup_recovers_committed_poll_bundle_manifest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation()
    outputs = ("mm raw", "md raw")
    store.record_poll_batch(
        run_id,
        QueryOutcome(
            observations=(observation,),
            raw_snapshots=(
                RawSnapshot("MM-01", "show mm", outputs[0], observation.observed_at, ()),
                RawSnapshot(
                    "MD-01",
                    "show md",
                    outputs[1],
                    observation.observed_at,
                    (observation.session_key,),
                ),
            ),
            authoritative=True,
        ),
    )
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative_path, sha256, byte_size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files"
        ).fetchone()
    sections = [
        {
            "index": index,
            "sha256": hashlib.sha256(output.encode()).hexdigest(),
            "byte_size": len(output.encode()),
        }
        for index, output in enumerate(outputs, start=1)
    ]
    operation_id = "b" * 32
    stage_root = store.raw_root / f".raw-staging-{operation_id}"
    staged = stage_root / Path(str(relative_path))
    staged.parent.mkdir(parents=True)
    os.replace(store.raw_root / str(relative_path), staged)
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": operation_id,
            "run_id": run_id,
            "stage_root": stage_root.name,
            "files": [
                {
                    "relative_path": relative_path,
                    "sha256": sha256,
                    "byte_size": byte_size,
                    "bundle_sections": sections,
                }
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    destination = store.raw_root / str(relative_path)
    assert destination.exists()
    assert not staged.exists()
    assert not manifest.exists()
    session_store_module._verify_raw_bundle_file(
        destination,
        tuple(
            session_store_module._RawBundleSection(
                int(section["index"]),
                str(section["sha256"]),
                int(section["byte_size"]),
            )
            for section in sections
        ),
    )


def test_startup_completes_committed_raw_batch_manifest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation()
    outcome = QueryOutcome(
        observations=(observation,),
        raw_snapshots=(
            RawSnapshot(
                "MD-01",
                "show datapath session table 192.0.2.100",
                "committed raw",
                observation.observed_at,
            ),
        ),
        authoritative=True,
    )
    store.record_poll_batch(run_id, outcome)
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative, sha256, byte_size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files"
        ).fetchone()
    operation_id = "c" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": operation_id,
            "run_id": run_id,
            "stage_root": f".raw-staging-{operation_id}",
            "files": [
                {
                    "relative_path": relative,
                    "sha256": sha256,
                    "byte_size": byte_size,
                }
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert (store.raw_root / relative).read_text(encoding="utf-8") == "committed raw"
    assert not manifest.exists()


def test_raw_batch_manifest_cannot_target_another_run_directory(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)
    unrelated = store.raw_root / "another-run" / "unrelated.txt"
    unrelated.parent.mkdir()
    unrelated_data = b"must not be deleted"
    unrelated.write_bytes(unrelated_data)
    operation_id = "7" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": operation_id,
            "run_id": run_id,
            "stage_root": f".raw-staging-{operation_id}",
            "files": [
                {
                    "relative_path": unrelated.relative_to(store.raw_root).as_posix(),
                    "sha256": hashlib.sha256(unrelated_data).hexdigest(),
                    "byte_size": len(unrelated_data),
                }
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="실행 ID"):
        reopened.initialize()

    assert unrelated.read_bytes() == unrelated_data
    assert manifest.exists()


def test_busy_manifest_temporary_file_is_not_deleted_by_concurrent_initializer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    operation_id = "8" * 32
    lease = store._acquire_operation_lease(operation_id)
    assert lease is not None
    destination = store._manifests_root / f"{operation_id}.json"
    replace_started = threading.Event()
    continue_replace = threading.Event()
    errors: list[BaseException] = []
    original_replace = session_store_module.os.replace

    def pause_manifest_replace(source: Path | str, target: Path | str) -> None:
        if Path(target) == destination:
            replace_started.set()
            assert continue_replace.wait(timeout=10)
        original_replace(source, target)

    monkeypatch.setattr(session_store_module.os, "replace", pause_manifest_replace)

    def write_manifest() -> None:
        try:
            store._write_manifest(
                operation_id,
                {
                    "version": 1,
                    "kind": "raw_batch",
                    "operation_id": operation_id,
                    "run_id": "fixture-run",
                    "stage_root": f".raw-staging-{operation_id}",
                    "files": [],
                },
            )
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    writer = threading.Thread(target=write_manifest, daemon=True)
    writer.start()
    try:
        assert replace_started.wait(timeout=10)
        temporary = tuple(store._manifests_root.glob(f".{operation_id}.json.*.tmp"))
        assert len(temporary) == 1

        reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
        reopened.initialize()

        assert temporary[0].exists()
    finally:
        continue_replace.set()
        writer.join(timeout=10)
        session_store_module._release_run_lease(lease, remove=True)

    assert not writer.is_alive()
    assert errors == []
    assert destination.exists()


@pytest.mark.parametrize(
    ("entry_kind", "expected_message"),
    [
        ("directory", "하위 디렉터리"),
        ("temporary", "임시 파일"),
        ("unknown", "인식할 수 없는 저장 작업"),
    ],
)
def test_startup_rejects_unrecognized_manifest_directory_entries(
    tmp_path: Path,
    entry_kind: str,
    expected_message: str,
) -> None:
    store = _store(tmp_path)
    if entry_kind == "directory":
        (store._manifests_root / "unexpected").mkdir()
    elif entry_kind == "temporary":
        (store._manifests_root / "unexpected.tmp").write_text("keep", encoding="utf-8")
    else:
        (store._manifests_root / "unexpected.bin").write_text("keep", encoding="utf-8")

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match=expected_message):
        reopened.initialize()


@pytest.mark.parametrize(
    ("invalid_case", "expected_message"),
    [
        ("kind", "지원하지 않는"),
        ("run_id", "실행 ID"),
        ("stage", "staging"),
        ("duplicate", "중복"),
        ("files", "파일 목록"),
        ("entry", "파일 항목"),
        ("sha256", "SHA-256"),
    ],
)
def test_startup_rejects_malformed_raw_batch_manifests(
    tmp_path: Path,
    invalid_case: str,
    expected_message: str,
) -> None:
    store = _store(tmp_path)
    operation_id = "5" * 32
    relative = "fixture-run/capture.txt"
    file_item: object = {
        "relative_path": relative,
        "sha256": "0" * 64,
        "byte_size": 0,
    }
    files: object = [file_item]
    payload: dict[str, object] = {
        "version": 1,
        "kind": "raw_batch",
        "operation_id": operation_id,
        "run_id": "fixture-run",
        "stage_root": f".raw-staging-{operation_id}",
        "files": files,
    }
    if invalid_case == "kind":
        payload["kind"] = "unknown"
    elif invalid_case == "run_id":
        payload["run_id"] = "../fixture-run"
    elif invalid_case == "stage":
        payload["stage_root"] = ".raw-staging-wrong"
    elif invalid_case == "duplicate":
        payload["files"] = [file_item, file_item]
    elif invalid_case == "files":
        payload["files"] = {}
    elif invalid_case == "entry":
        payload["files"] = ["not-a-file-entry"]
    else:
        payload["files"] = [
            {
                "relative_path": relative,
                "sha256": "invalid",
                "byte_size": 0,
            }
        ]
    manifest = store._write_manifest(operation_id, payload)

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match=expected_message):
        reopened.initialize()

    assert manifest.exists()


def test_startup_rejects_partially_committed_raw_batch(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="registered raw")
    store.finish_run(run_id)
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative, sha256, byte_size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    operation_id = "4" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": operation_id,
            "run_id": run_id,
            "stage_root": f".raw-staging-{operation_id}",
            "files": [
                {
                    "relative_path": relative,
                    "sha256": sha256,
                    "byte_size": byte_size,
                },
                {
                    "relative_path": f"{run_id}/missing.txt",
                    "sha256": "1" * 64,
                    "byte_size": 1,
                },
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="일부만"):
        reopened.initialize()

    assert manifest.exists()


def test_startup_restores_committed_raw_file_from_batch_staging(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    raw_data = b"committed staged raw"
    store.record_query(run_id, [_observation()], raw_text=raw_data.decode())
    store.finish_run(run_id)
    with closing(sqlite3.connect(store.db_path)) as connection:
        relative, sha256, byte_size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    operation_id = "3" * 32
    destination = store.raw_root / Path(relative)
    staged = store.raw_root / f".raw-staging-{operation_id}" / Path(relative)
    staged.parent.mkdir(parents=True)
    os.replace(destination, staged)
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": operation_id,
            "run_id": run_id,
            "stage_root": f".raw-staging-{operation_id}",
            "files": [
                {
                    "relative_path": relative,
                    "sha256": sha256,
                    "byte_size": byte_size,
                }
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert destination.read_bytes() == raw_data
    assert not staged.exists()
    assert not manifest.exists()


@pytest.mark.parametrize(
    ("manifest_format", "symlink_location"),
    (
        ("flat", "stage_root"),
        ("legacy", "stage_root"),
        ("legacy", "intermediate"),
    ),
)
def test_raw_batch_recovery_rejects_symlinked_staging_before_external_access(
    manifest_format: str,
    symlink_location: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    operation_id = "9" * 32
    run_id = "uncommitted-run"
    relative = f"{run_id}/20260902/08/capture.txt"
    victim_data = b"external victim must stay private"
    digest = hashlib.sha256(victim_data).hexdigest()
    stage_root = store.raw_root / f".raw-staging-{operation_id}"
    external_root = tmp_path / f"external-{manifest_format}-{symlink_location}"
    external_root.mkdir()

    if symlink_location == "stage_root":
        victim_relative = Path(digest + ".raw") if manifest_format == "flat" else Path(relative)
        victim = external_root / victim_relative
        victim.parent.mkdir(parents=True, exist_ok=True)
        victim.write_bytes(victim_data)
        try:
            stage_root.symlink_to(external_root, target_is_directory=True)
        except OSError as error:
            pytest.skip(f"symlink creation is unavailable: {error}")
    else:
        assert manifest_format == "legacy"
        stage_root.mkdir()
        victim = external_root / "20260902/08/capture.txt"
        victim.parent.mkdir(parents=True)
        victim.write_bytes(victim_data)
        try:
            (stage_root / run_id).symlink_to(external_root, target_is_directory=True)
        except OSError as error:
            pytest.skip(f"symlink creation is unavailable: {error}")

    file_payload: dict[str, object] = {
        "relative_path": relative,
        "sha256": digest,
        "byte_size": len(victim_data),
    }
    payload: dict[str, object] = {
        "version": 1,
        "kind": "raw_batch",
        "operation_id": operation_id,
        "run_id": run_id,
        "stage_root": stage_root.name,
        "files": [file_payload],
    }
    if manifest_format == "flat":
        file_payload["staged_name"] = f"{digest}.raw"
        payload.update(
            {
                "poll_id": operation_id,
                "payload_sha256": "a" * 64,
                "phase": "PREPARED",
            }
        )
    manifest = store._write_manifest(operation_id, payload)
    victim_resolved = victim.resolve(strict=True)
    fingerprint_attempts: list[Path] = []
    unlink_attempts: list[Path] = []
    original_verify = session_store_module._verify_file_fingerprint
    original_unlink = Path.unlink

    def observe_fingerprint(path: Path, *args: object, **kwargs: object) -> None:
        if path.resolve(strict=False) == victim_resolved:
            fingerprint_attempts.append(path)
        original_verify(path, *args, **kwargs)  # type: ignore[arg-type]

    def block_external_unlink(path: Path, *args: object, **kwargs: object) -> None:
        if path.resolve(strict=False) == victim_resolved:
            unlink_attempts.append(path)
            raise AssertionError("recovery attempted to delete an external victim")
        original_unlink(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "_verify_file_fingerprint", observe_fingerprint)
    monkeypatch.setattr(Path, "unlink", block_external_unlink)

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match=r"link|reparse|staging|관리 경로"):
        reopened.initialize()

    assert fingerprint_attempts == []
    assert unlink_attempts == []
    assert victim.read_bytes() == victim_data
    assert manifest.exists()


@pytest.mark.parametrize(
    ("sha256", "byte_size"),
    [
        (None, 0),
        ("invalid", 0),
        ("0" * 64, None),
        ("0" * 64, True),
        ("0" * 64, -1),
    ],
)
def test_optional_manifest_fingerprint_rejects_partial_or_invalid_pairs(
    sha256: object,
    byte_size: object,
) -> None:
    with pytest.raises(StorageError, match="fingerprint_sha/fingerprint_size"):
        session_store_module._manifest_optional_fingerprint(
            {
                "fingerprint_sha": sha256,
                "fingerprint_size": byte_size,
            },
            "fingerprint_sha",
            "fingerprint_size",
        )


@pytest.mark.parametrize(
    ("document", "expected_message"),
    [
        ("{", "읽을 수 없습니다"),
        ("[]", "형식"),
        ('{"version": 99, "operation_id": "22222222222222222222222222222222"}', "버전"),
        ('{"version": 1, "operation_id": "11111111111111111111111111111111"}', "파일명"),
    ],
)
def test_manifest_reader_rejects_corrupt_or_mismatched_documents(
    tmp_path: Path,
    document: str,
    expected_message: str,
) -> None:
    operation_id = "2" * 32
    manifest = tmp_path / f"{operation_id}.json"
    manifest.write_text(document, encoding="utf-8")

    with pytest.raises(StorageError, match=expected_message):
        session_store_module._read_manifest(manifest, operation_id)


def test_manifest_scalar_validators_reject_missing_or_invalid_values() -> None:
    with pytest.raises(StorageError, match="required"):
        session_store_module._manifest_text({}, "required")
    with pytest.raises(StorageError, match="byte_size"):
        session_store_module._manifest_int({"byte_size": True}, "byte_size")
    with pytest.raises(StorageError, match="sha256"):
        session_store_module._manifest_fingerprint(
            {"sha256": "invalid", "byte_size": 0},
            "sha256",
            "byte_size",
        )


def test_startup_removes_uncommitted_raw_batch_files(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _run(store)
    operation_id = "d" * 32
    relative = "uncommitted-run/capture.txt"
    data = b"uncommitted raw"
    sha256 = hashlib.sha256(data).hexdigest()
    destination = store.raw_root / Path(relative)
    staged = store.raw_root / f".raw-staging-{operation_id}" / Path(relative)
    destination.parent.mkdir()
    staged.parent.mkdir(parents=True)
    destination.write_bytes(data)
    staged.write_bytes(data)
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "raw_batch",
            "operation_id": operation_id,
            "run_id": "uncommitted-run",
            "stage_root": f".raw-staging-{operation_id}",
            "files": [
                {
                    "relative_path": relative,
                    "sha256": sha256,
                    "byte_size": len(data),
                }
            ],
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert not destination.exists()
    assert not staged.exists()
    assert not manifest.exists()


def test_report_fails_closed_when_registered_raw_content_changes(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="original raw")
    store.finish_run(run_id)
    raw_path = next(store.raw_root.rglob("*.txt"))
    raw_path.write_text("tampered raw", encoding="utf-8")

    with pytest.raises(StorageError, match="SHA-256"):
        store.export_run_csv(run_id)
    with pytest.raises(StorageError, match="SHA-256"):
        store.export_run_html(run_id)

    assert not tuple(store.exports_root.rglob("*.csv"))
    assert not tuple(store.exports_root.rglob("*.html"))


def test_store_detects_managed_root_identity_swap(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original_raw_root = store.raw_root.with_name("raw-original")
    os.replace(store.raw_root, original_raw_root)
    store.raw_root.mkdir()

    with pytest.raises(StorageError, match="실행 중 다른 디렉터리"):
        store.list_runs()

    assert original_raw_root.is_dir()


@pytest.mark.skipif(os.name != "nt", reason="Windows junction safety test")
def test_initialize_rejects_a_windows_junction_managed_root(tmp_path: Path) -> None:
    target = tmp_path / "outside"
    target.mkdir()
    sentinel = target / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    junction = tmp_path / "raw-junction"
    command = [
        os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
        "/d",
        "/c",
        "mklink",
        "/J",
        str(junction),
        str(target),
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
        with pytest.raises(session_store_module.UnsafeStoragePath, match="reparse point"):
            session_store_module._reject_managed_chain(junction, target)
        store = SessionStore(tmp_path / "tracker.db", junction, tmp_path / "exports")
        with pytest.raises(StorageError, match="reparse point"):
            store.initialize()
        assert sentinel.read_text(encoding="utf-8") == "keep"
    finally:
        junction.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="Windows 8.3 path-alias test")
def test_record_query_accepts_equivalent_windows_short_root_alias(tmp_path: Path) -> None:
    import ctypes

    managed_root = tmp_path / "managed root with spaces"
    managed_root.mkdir()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_short_path = kernel32.GetShortPathNameW
    get_short_path.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    )
    get_short_path.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_short_path(str(managed_root), buffer, len(buffer))
    if length == 0:
        pytest.skip(f"8.3 path alias is unavailable: WinError {ctypes.get_last_error()}")
    if length >= len(buffer):  # pragma: no cover - impossible for pytest temp paths
        pytest.skip("8.3 path alias exceeds the test buffer")
    short_root = Path(buffer.value)
    if os.path.normcase(os.path.abspath(short_root)) == os.path.normcase(
        os.path.abspath(managed_root)
    ):
        pytest.skip("8.3 short-name generation is disabled on this volume")

    store = SessionStore(
        short_root / "tracker.db",
        short_root / "raw",
        short_root / "exports",
    )
    store.initialize()
    run_id = _run(store)
    try:
        observation_ids = store.record_query(
            run_id,
            [_observation()],
            raw_text="short-alias-raw",
        )
    finally:
        if run_id in store._run_leases:
            store.finish_run(run_id)

    assert len(observation_ids) == 1
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 1
    assert len(tuple(store.raw_root.rglob("*.txt"))) == 1
    assert not tuple(store._leases_root.glob("operation-*.lease"))

    target = managed_root / "raw" / "junction-target"
    (target / "child").mkdir(parents=True)
    junction = managed_root / "raw" / "junction-alias"
    completed = subprocess.run(  # noqa: S603
        [
            os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
            "/d",
            "/c",
            "mklink",
            "/J",
            str(junction),
            str(target),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    try:
        with pytest.raises(session_store_module.UnsafeStoragePath, match="reparse point"):
            session_store_module._reject_managed_chain(
                short_root / "raw",
                junction / "child",
            )
        inverse_length = get_short_path(
            str(junction / "child"),
            buffer,
            len(buffer),
        )
        assert 0 < inverse_length < len(buffer)
        with pytest.raises(session_store_module.UnsafeStoragePath, match="reparse point"):
            session_store_module._reject_managed_chain(
                managed_root / "raw",
                Path(buffer.value),
            )
    finally:
        junction.rmdir()


def test_raw_relative_path_does_not_depend_on_windows_root_alias_spelling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured_root = tmp_path / "configured-long-name" / "raw"
    equivalent_alias = tmp_path / "ALIAS" / "raw"
    equivalent_alias.mkdir(parents=True)

    def simulated_windows_alias(_root: Path, relative: Path) -> Path:
        return equivalent_alias / relative

    monkeypatch.setattr(raw_module, "contained_path", simulated_windows_alias)
    store = raw_module.RawOutputStore(configured_root)
    artifact = store.write(
        "run-alias-test",
        kind="session",
        controller_name="MD-01",
        content="fixture",
        captured_at=datetime(2026, 8, 28, 9, 0, tzinfo=UTC),
    )

    assert artifact.relative_path.startswith("run-alias-test/")
    assert not Path(artifact.relative_path).is_absolute()
    assert (equivalent_alias / artifact.relative_path).read_text(encoding="utf-8") == "fixture"


def test_lifecycle_controller_and_sanitized_diagnostic_are_recorded(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation()

    store.record_lifecycle(
        run_id,
        session_key=observation.session_key,
        instance_id="instance-001",
        event_type="opened",
        controller_name="MD-01",
        details={"packets": 12},
    )
    store.record_controller_event(
        run_id,
        previous_controller="MD-01",
        current_controller="MD-02",
        reason="client 192.0.2.100 moved",
    )
    store.record_diagnostic(
        DiagnosticEvent(
            stage="SSH 198.51.100.21",
            code=ErrorCode.AUTH_FAILED,
            message="username=operator password=do-not-store at 198.51.100.21",
        ),
        run_id=run_id,
    )

    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        lifecycle = connection.execute(
            "SELECT instance_id, event_type, details_json FROM lifecycle_events"
        ).fetchone()
        reason = connection.execute("SELECT reason FROM controller_events").fetchone()[0]
        stage, code, message = connection.execute(
            "SELECT stage, code, message FROM diagnostic_events"
        ).fetchone()

    assert lifecycle == ("instance-001", "OPENED", '{"packets": 12}')
    assert reason == "client <IPv4> moved"
    assert stage == "SSH <IPv4>"
    assert code == "AUTH_FAILED"
    assert message == "username=<REDACTED> password=<REDACTED> at <IPv4>"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=2+2", "'=2+2"),
        ("  -1+1", "'  -1+1"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("normal", "normal"),
        (123, "123"),
    ],
)
def test_csv_formula_guard(value: object, expected: str) -> None:
    assert guard_csv_cell(value) == expected


def test_csv_is_utf8_bom_and_registered_for_confirmed_delete(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation(controller_name="=DANGEROUS")], raw_text="raw")

    exported = store.export_run_csv(run_id)
    store.finish_run(run_id)

    assert exported.read_bytes().startswith(b"\xef\xbb\xbf")
    with exported.open("r", encoding="utf-8-sig", newline="") as stream:
        row = next(csv.DictReader(stream))
    assert row["controller_name"] == "'=DANGEROUS"

    preview = store.preview_delete(run_id)
    assert preview.raw_files == 1
    assert preview.export_files == 1
    assert "Raw 1개" in preview.summary
    invalid_token = "invalid-" + preview.confirmation_token
    with pytest.raises(StorageError, match="토큰"):
        store.delete(preview, confirmation_token=invalid_token)

    result = store.delete(preview, confirmation_token=preview.confirmation_token)
    assert result.deleted_runs == 1
    assert result.deleted_raw_files == 1
    assert result.deleted_export_files == 1
    assert not exported.exists()
    assert store.list_runs() == ()


def test_csv_export_uses_the_bounded_cursor_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    seen_batch_sizes: list[int] = []
    original = session_store_module._iter_cursor_dicts

    def observe_batches(
        cursor: sqlite3.Cursor,
        *,
        batch_size: int,
        **kwargs: object,
    ) -> Iterator[dict[str, object]]:
        seen_batch_sizes.append(batch_size)
        return original(cursor, batch_size=batch_size, **kwargs)

    monkeypatch.setattr(session_store_module, "_iter_cursor_dicts", observe_batches)
    exported = store.export_run_csv(run_id, tmp_path / "stream.csv")

    assert exported.exists()
    assert seen_batch_sizes == [1000]


def test_streaming_csv_export_does_not_hold_store_lock_against_poll_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    renderer_started = threading.Event()
    release_renderer = threading.Event()
    original_writer = session_store_module.write_csv_atomic

    def blocking_writer(*args: object, **kwargs: object) -> Path:
        renderer_started.set()
        if not release_renderer.wait(timeout=10):
            raise TimeoutError("CSV renderer test synchronization timed out")
        return original_writer(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "write_csv_atomic", blocking_writer)
    export_errors: list[BaseException] = []

    def export() -> None:
        try:
            store.export_run_csv(run_id, tmp_path / "concurrent.csv")
        except BaseException as error:  # pragma: no cover - asserted below
            export_errors.append(error)

    exporter = threading.Thread(target=export)
    exporter.start()
    assert renderer_started.wait(timeout=5)
    write_completed = threading.Event()

    def write_poll() -> None:
        store.record_query(run_id, [replace(_observation(), destination_port=8443)])
        write_completed.set()

    writer = threading.Thread(target=write_poll)
    writer.start()
    try:
        assert write_completed.wait(timeout=5)
    finally:
        release_renderer.set()
    writer.join(timeout=5)
    exporter.join(timeout=10)

    assert not writer.is_alive()
    assert not exporter.is_alive()
    assert export_errors == []
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM observations WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
            == 2
        )


@pytest.mark.parametrize("external", (False, True), ids=("managed", "external"))
def test_export_file_install_and_manifest_fsync_run_without_sqlite_writer_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    external: bool,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = (
        tmp_path / "chosen" / "report.csv" if external else store.exports_root / "report.csv"
    )
    if external:
        destination.parent.mkdir()
    checked_phases: list[str] = []
    checked_install = False
    original_manifest = store._replace_manifest
    original_replace = session_store_module._replace_file

    def assert_writer_available() -> None:
        with closing(sqlite3.connect(store.db_path, timeout=0.1)) as connection:
            connection.execute("PRAGMA busy_timeout = 100")
            connection.execute("BEGIN IMMEDIATE")
            connection.rollback()

    def observe_manifest(path: Path, payload: dict[str, object]) -> None:
        phase = str(payload.get("phase") or "")
        if phase in {"RENDERED", "INSTALLED", "DB_COMMITTED"}:
            assert_writer_available()
            checked_phases.append(phase)
        original_manifest(path, payload)

    def observe_replace(
        source: Path,
        target: Path,
        **kwargs: object,
    ) -> None:
        nonlocal checked_install
        if target == destination:
            assert_writer_available()
            checked_install = True
        original_replace(source, target, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "_replace_manifest", observe_manifest)
    monkeypatch.setattr(session_store_module, "_replace_file", observe_replace)

    exported = store.export_run_csv(run_id, destination)

    assert exported == destination
    assert checked_install is True
    assert checked_phases == ["RENDERED", "INSTALLED", "DB_COMMITTED"]


@pytest.mark.parametrize("html", (False, True), ids=("csv", "html"))
def test_export_cancellation_is_observed_during_chunked_raw_integrity_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    html: bool,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    raw_bytes = b"R" * (session_store_module._HASH_CHUNK_SIZE * 2 + 17)
    store.record_query(
        run_id,
        [_observation()],
        raw_text=raw_bytes.decode("ascii"),
    )
    store.finish_run(run_id)
    cancel_requested = False
    byte_progress: list[tuple[int, int | None]] = []

    def request_cancel(
        phase: str,
        completed: int,
        total: int | None,
    ) -> None:
        nonlocal cancel_requested
        if phase == "export_raw_bytes":
            byte_progress.append((completed, total))
            cancel_requested = True

    def fail_renderer(*_args: object, **_kwargs: object) -> None:
        pytest.fail("renderer must not start after Raw integrity cancellation")

    monkeypatch.setattr(session_store_module, "write_csv_atomic", fail_renderer)
    monkeypatch.setattr(
        session_store_module,
        "write_html_report_stream_atomic",
        fail_renderer,
    )
    destination = tmp_path / "chosen" / ("cancelled.html" if html else "cancelled.csv")
    destination.parent.mkdir()
    export = store.export_run_html if html else store.export_run_csv

    with pytest.raises(StorageError) as caught:
        export(
            run_id,
            destination,
            cancel_check=lambda: cancel_requested,
            progress=request_cancel,
        )

    assert caught.value.code is ErrorCode.CANCELLED
    assert byte_progress == [
        (session_store_module._HASH_CHUNK_SIZE, len(raw_bytes)),
    ]
    assert not destination.exists()
    assert not tuple(store._manifests_root.glob("*.json"))
    assert not tuple(store._export_owners_root.glob("*.json"))


def test_delete_rejects_stale_preview(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="first")
    store.finish_run(run_id)
    preview = store.preview_delete(run_id)
    orphan = store.raw_root / run_id / "new-orphan.txt"
    orphan.write_text("changed", encoding="utf-8")

    with pytest.raises(StorageError, match="변경"):
        store.delete(preview, confirmation_token=preview.confirmation_token)

    assert len(store.list_runs()) == 1


def test_delete_rejects_same_size_content_change_after_preview(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="AAAA")
    store.finish_run(run_id)
    preview = store.preview_delete(run_id)
    raw_path = next(store.raw_root.rglob("*.txt"))
    raw_path.write_text("BBBB", encoding="utf-8")

    with pytest.raises(StorageError, match="변경"):
        store.delete(preview, confirmation_token=preview.confirmation_token)

    assert raw_path.read_text(encoding="utf-8") == "BBBB"
    assert store.list_runs()[0]["id"] == run_id


def test_startup_recovers_delete_staging_when_database_still_references_file(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="recover me")
    store.finish_run(run_id)
    snapshot = store._collect_deletion_snapshot(run_id)
    operation_id = "a" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "delete",
            "operation_id": operation_id,
            "files": [
                {
                    "category": "raw",
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "byte_size": item.byte_size,
                    "registered": item.registered,
                }
                for item in snapshot.raw_files
            ],
        },
    )
    staged: list[session_store_module._StagedFile] = []
    session_store_module._stage_files(
        store.raw_root,
        snapshot.raw_files,
        operation_id,
        "raw",
        staged,
    )
    original = staged[0].source
    assert not original.exists()
    assert manifest.exists()

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert original.read_text(encoding="utf-8") == "recover me"
    assert not manifest.exists()
    assert not tuple(store.raw_root.glob(".delete-staging-*"))


def test_startup_purges_delete_staging_after_database_delete_committed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="delete committed")
    store.finish_run(run_id)
    snapshot = store._collect_deletion_snapshot(run_id)
    operation_id = "b" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "delete",
            "operation_id": operation_id,
            "files": [
                {
                    "category": "raw",
                    "relative_path": item.relative_path,
                    "sha256": item.sha256,
                    "byte_size": item.byte_size,
                    "registered": item.registered,
                }
                for item in snapshot.raw_files
            ],
        },
    )
    staged: list[session_store_module._StagedFile] = []
    session_store_module._stage_files(
        store.raw_root,
        snapshot.raw_files,
        operation_id,
        "raw",
        staged,
    )
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DELETE FROM runs WHERE id = ?", (run_id,))

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert reopened.list_runs() == ()
    assert not manifest.exists()
    assert not tuple(store.raw_root.glob(".delete-staging-*"))


def test_delete_fails_closed_for_tampered_relative_path(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="raw")
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute(
            "UPDATE raw_files SET relative_path = '../outside.txt' WHERE run_id = ?",
            (run_id,),
        )
    store.finish_run(run_id)

    with pytest.raises(StorageError, match="안전하지"):
        store.preview_delete(run_id)

    assert outside.read_text(encoding="utf-8") == "keep"


def test_external_csv_export_is_not_managed_or_deleted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    external = tmp_path / "chosen" / "history.csv"

    store.export_run_csv(run_id, external)
    preview = store.preview_delete(run_id)
    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert preview.export_files == 0
    assert result.deleted_export_files == 0
    assert external.exists()


def test_running_run_rejects_html_export_without_creating_an_artifact(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    with pytest.raises(StorageError, match=r"RUNNING.*중지"):
        store.export_run_html(run_id)

    assert not tuple(store.exports_root.rglob("*.html"))
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM exports").fetchone()[0] == 0


def test_default_csv_and_html_are_managed_and_deleted_together(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="raw evidence")
    store.finish_run(run_id)

    csv_export = store.export_run_csv(run_id)
    html_export = store.export_run_html(run_id)
    preview = store.preview_delete(run_id)

    assert csv_export.parent == store.exports_root
    assert html_export.parent == store.exports_root
    assert preview.raw_files == 1
    assert preview.export_files == 2
    assert "내보내기 파일 2개" in preview.summary

    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert result.deleted_export_files == 2
    assert not csv_export.exists()
    assert not html_export.exists()
    assert store.list_runs() == ()


def test_external_html_export_is_not_managed_or_deleted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    external = tmp_path / "chosen" / "history.html"

    exported = store.export_run_html(run_id, external)
    preview = store.preview_delete(run_id)
    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert exported == external
    assert preview.export_files == 0
    assert result.deleted_export_files == 0
    assert external.exists()


def test_managed_html_is_rolled_back_if_another_instance_deletes_the_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exporter = _store(tmp_path)
    deleter = SessionStore(exporter.db_path, exporter.raw_root, exporter.exports_root)
    deleter.initialize()
    run_id = _run(exporter)
    exporter.record_query(run_id, [_observation()])
    exporter.finish_run(run_id)
    preview = deleter.preview_delete(run_id)
    original_writer = session_store_module.write_html_report_stream_atomic

    def write_then_delete(
        destination: Path,
        snapshot: RunReportSnapshot,
        observation_history: Iterator[dict[str, object]],
        *,
        logical_session_total: int,
    ) -> Path:
        written = original_writer(
            destination,
            snapshot,
            observation_history,
            logical_session_total=logical_session_total,
        )
        deleter.delete(preview, confirmation_token=preview.confirmation_token)
        return written

    monkeypatch.setattr(
        session_store_module,
        "write_html_report_stream_atomic",
        write_then_delete,
    )
    destination = exporter.exports_root / f"run-{run_id}.html"

    with pytest.raises(StorageError, match="조회 실행 기록이 없습니다"):
        exporter.export_run_html(run_id, destination)

    assert not destination.exists()
    assert exporter.list_runs() == ()


def test_managed_html_restores_the_previous_file_if_registration_update_fails(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = store.export_run_html(run_id)
    previous = destination.read_bytes()
    with closing(sqlite3.connect(store.db_path)) as connection:
        connection.execute(
            """
            CREATE TRIGGER fail_export_update
            BEFORE UPDATE ON exports
            BEGIN
                SELECT RAISE(ABORT, 'forced export registration failure');
            END
            """
        )

    with pytest.raises(StorageError, match="HTML 보고서를 내보낼 수 없습니다"):
        store.export_run_html(run_id)

    assert destination.read_bytes() == previous
    assert not tuple(store.exports_root.glob("*.backup"))
    assert not tuple(store.exports_root.glob("*.staged"))
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM exports").fetchone()[0] == 1


def test_startup_finishes_a_committed_managed_export_swap(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = store.export_run_csv(run_id)
    old_data = destination.read_bytes()
    old_sha = hashlib.sha256(old_data).hexdigest()
    operation_id = "e" * 32
    backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
    staged = destination.with_name(f".{destination.name}.{operation_id}.staged")
    new_data = b"new managed export"
    new_sha = hashlib.sha256(new_data).hexdigest()
    os.replace(destination, backup)
    destination.write_bytes(new_data)
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute(
            "UPDATE exports SET sha256 = ?, byte_size = ? WHERE relative_path = ?",
            (new_sha, len(new_data), destination.name),
        )
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "export",
            "operation_id": operation_id,
            "run_id": run_id,
            "relative_path": destination.name,
            "staged_relative": staged.name,
            "backup_relative": backup.name,
            "sha256": new_sha,
            "byte_size": len(new_data),
            "previous_file_sha256": old_sha,
            "previous_file_byte_size": len(old_data),
            "previous_db_sha256": old_sha,
            "previous_db_byte_size": len(old_data),
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert destination.read_bytes() == new_data
    assert not backup.exists()
    assert not manifest.exists()


def test_startup_rolls_back_an_uncommitted_managed_export_swap(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = store.export_run_csv(run_id)
    old_data = destination.read_bytes()
    old_sha = hashlib.sha256(old_data).hexdigest()
    operation_id = "f" * 32
    backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
    staged = destination.with_name(f".{destination.name}.{operation_id}.staged")
    new_data = b"uncommitted replacement"
    new_sha = hashlib.sha256(new_data).hexdigest()
    os.replace(destination, backup)
    destination.write_bytes(new_data)
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "export",
            "operation_id": operation_id,
            "run_id": run_id,
            "relative_path": destination.name,
            "staged_relative": staged.name,
            "backup_relative": backup.name,
            "sha256": new_sha,
            "byte_size": len(new_data),
            "previous_file_sha256": old_sha,
            "previous_file_byte_size": len(old_data),
            "previous_db_sha256": old_sha,
            "previous_db_byte_size": len(old_data),
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert destination.read_bytes() == old_data
    assert not backup.exists()
    assert not manifest.exists()


def test_startup_does_not_treat_a_busy_manifest_export_as_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = store.export_run_csv(run_id)
    old_data = destination.read_bytes()
    old_sha = hashlib.sha256(old_data).hexdigest()
    operation_id = "9" * 32
    staged = destination.with_name(f".{destination.name}.{operation_id}.staged")
    backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
    new_data = b"active export replacement"
    staged.write_bytes(new_data)
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "export",
            "operation_id": operation_id,
            "run_id": run_id,
            "relative_path": destination.name,
            "staged_relative": staged.name,
            "backup_relative": backup.name,
            "sha256": hashlib.sha256(new_data).hexdigest(),
            "byte_size": len(new_data),
            "previous_file_sha256": old_sha,
            "previous_file_byte_size": len(old_data),
            "previous_db_sha256": old_sha,
            "previous_db_byte_size": len(old_data),
        },
    )
    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    original_acquire = reopened._acquire_operation_lease

    def simulate_busy_operation(nonce: str) -> session_store_module._RunLease | None:
        if nonce == operation_id:
            return None
        return original_acquire(nonce)

    monkeypatch.setattr(reopened, "_acquire_operation_lease", simulate_busy_operation)

    reopened.initialize()

    assert destination.read_bytes() == old_data
    assert staged.read_bytes() == new_data
    assert manifest.exists()


def test_active_managed_export_stage_survives_a_concurrent_initializer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = store.exports_root / f"run-{run_id}.csv"
    stage_written = threading.Event()
    continue_export = threading.Event()
    errors: list[BaseException] = []
    results: list[Path] = []
    original_writer = session_store_module.write_csv_atomic

    def pause_after_stage_write(
        path: Path | str,
        *,
        columns: tuple[str, ...],
        rows: Iterator[dict[str, object]],
    ) -> Path:
        written = original_writer(path, columns=columns, rows=rows)
        stage_written.set()
        assert continue_export.wait(timeout=10)
        return written

    monkeypatch.setattr(session_store_module, "write_csv_atomic", pause_after_stage_write)

    def export() -> None:
        try:
            results.append(store.export_run_csv(run_id, destination))
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    worker = threading.Thread(target=export, daemon=True)
    worker.start()
    try:
        assert stage_written.wait(timeout=10)
        staged = tuple(store.exports_root.glob(f".{destination.name}.*.staged"))
        assert len(staged) == 1

        reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
        reopened.initialize()

        assert staged[0].exists()
    finally:
        continue_export.set()
        worker.join(timeout=10)

    assert not worker.is_alive()
    assert errors == []
    assert results == [destination]
    assert destination.exists()
    assert not tuple(store.exports_root.glob(f".{destination.name}.*.staged"))


@pytest.mark.parametrize("tampered_field", ["staged_relative", "backup_relative"])
def test_export_manifest_cannot_delete_an_unrelated_managed_file(
    tmp_path: Path,
    tampered_field: str,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = store.export_run_csv(run_id)
    data = destination.read_bytes()
    operation_id = "6" * 32
    staged = destination.with_name(f".{destination.name}.{operation_id}.staged")
    backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
    unrelated = store.exports_root / "unrelated-user-file.txt"
    unrelated_data = b"must not be unlinked"
    unrelated.write_bytes(unrelated_data)
    payload: dict[str, object] = {
        "version": 1,
        "kind": "export",
        "operation_id": operation_id,
        "run_id": run_id,
        "relative_path": destination.name,
        "staged_relative": staged.name,
        "backup_relative": backup.name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "byte_size": len(data),
        "previous_file_sha256": None,
        "previous_file_byte_size": None,
        "previous_db_sha256": None,
        "previous_db_byte_size": None,
    }
    payload[tampered_field] = unrelated.name
    manifest = store._write_manifest(operation_id, payload)

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="작업 ID"):
        reopened.initialize()

    assert unrelated.read_bytes() == unrelated_data
    assert destination.read_bytes() == data
    assert manifest.exists()


def test_delete_write_lock_prevents_a_late_managed_html_orphan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deleter = _store(tmp_path)
    exporter = SessionStore(deleter.db_path, deleter.raw_root, deleter.exports_root)
    exporter.initialize()
    run_id = _run(deleter)
    deleter.finish_run(run_id)
    preview = deleter.preview_delete(run_id)
    delete_locked = threading.Event()
    continue_delete = threading.Event()
    original_stage_files = session_store_module._stage_files
    first_stage = True

    def pause_after_locked_snapshot(
        root: Path,
        relative_paths: tuple[session_store_module._DeletionFile, ...],
        preview_id: str,
        category: str,
        staged: list[session_store_module._StagedFile],
        **kwargs: object,
    ) -> None:
        nonlocal first_stage
        if first_stage:
            first_stage = False
            delete_locked.set()
            if not continue_delete.wait(timeout=10):
                raise TimeoutError("delete test synchronization timed out")
        original_stage_files(root, relative_paths, preview_id, category, staged, **kwargs)

    monkeypatch.setattr(session_store_module, "_stage_files", pause_after_locked_snapshot)
    deletion_results: list[object] = []
    deletion_errors: list[Exception] = []
    export_errors: list[Exception] = []

    def delete_run() -> None:
        try:
            deletion_results.append(
                deleter.delete(preview, confirmation_token=preview.confirmation_token)
            )
        except Exception as error:  # pragma: no cover - assertion reports thread failures
            deletion_errors.append(error)

    def export_run() -> None:
        try:
            exporter.export_run_html(run_id)
        except Exception as error:  # expected after delete commits
            export_errors.append(error)

    delete_thread = threading.Thread(target=delete_run)
    export_thread = threading.Thread(target=export_run)
    delete_thread.start()
    assert delete_locked.wait(timeout=10)
    export_thread.start()
    deadline = time.monotonic() + 10
    while not export_errors and time.monotonic() < deadline:
        time.sleep(0.01)
    assert export_errors
    continue_delete.set()
    delete_thread.join(timeout=10)
    export_thread.join(timeout=10)

    assert not delete_thread.is_alive()
    assert not export_thread.is_alive()
    assert not deletion_errors
    assert len(deletion_results) == 1
    assert len(export_errors) == 1
    assert isinstance(export_errors[0], StorageError)
    assert "유지보수" in str(export_errors[0])
    assert deleter.list_runs() == ()
    assert not tuple(exporter.exports_root.rglob("*.html"))
    assert not tuple(exporter.exports_root.glob("*.staged"))
    assert not tuple(exporter.exports_root.glob("*.backup"))


def test_html_export_contains_results_and_excludes_technical_metadata(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    observation = _observation(controller_name="서울-MD-01")
    raw_body = "PRIVATE-RAW-BODY username=raw-user password=raw-secret"
    raw_digest = hashlib.sha256(raw_body.encode("utf-8")).hexdigest()
    store.record_query(
        run_id,
        [observation],
        raw_text=raw_body,
        controller_name="서울-MD-01",
        raw_kind="session",
    )
    store.record_query(
        run_id,
        [],
        raw_text="MM location evidence",
        controller_name="서울-MM-01",
        raw_kind="mm-location",
    )
    store.record_lifecycle(
        run_id,
        session_key=observation.session_key,
        instance_id="instance-report-001",
        event_type="opened",
        controller_name="서울-MD-01",
        details={"miss_count": 0, "previous_flags": "F"},
    )
    store.record_controller_event(
        run_id,
        previous_controller="서울-MD-01",
        current_controller="서울-MD-02",
        reason="CURRENT_SWITCH_CHANGED",
    )
    store.record_diagnostic(
        DiagnosticEvent(
            stage="SSH 198.51.100.99",
            code=ErrorCode.AUTH_FAILED,
            message="username=operator password=do-not-export at 198.51.100.99",
        ),
        run_id=run_id,
    )
    store.finish_run(run_id, status="PARTIAL")

    exported = store.export_run_html(run_id, tmp_path / "chosen" / "result.html")
    document = exported.read_text(encoding="utf-8")
    raw_relative = next(store.raw_root.rglob("*.txt")).relative_to(store.raw_root).as_posix()

    assert "세션 추적 결과" in document
    assert "일부 수집" in document
    assert "서울-MD-01" in document
    assert "192.0.2.100:53000" in document
    assert "203.0.113.80:443" in document
    assert "확인됨" in document
    assert run_id not in document
    assert "PARTIAL" not in document
    assert "instance-report-001" not in document
    assert "OPENED" not in document
    assert "MISS 횟수: 0" not in document
    assert "이전 Flags: F" not in document
    assert "서울-MD-02" not in document
    assert "CURRENT_SWITCH_CHANGED" not in document
    assert "AUTH_FAILED" not in document
    assert "username" not in document.casefold()
    assert "password" not in document.casefold()
    assert "198.51.100.99" not in document
    assert "198.51.100.21" not in document
    assert "서울-MM-01" not in document
    assert "mm-location" not in document
    assert "DB ID" not in document
    assert raw_digest not in document
    assert "PRIVATE-RAW-BODY" not in document
    assert "raw-user" not in document
    assert "raw-secret" not in document
    assert raw_relative not in document


def test_html_export_uses_database_id_order_for_equal_observation_and_lifecycle_times(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    same_time = datetime(2026, 8, 28, 8, 5, tzinfo=UTC)
    first = _observation(
        controller_name="MD-A",
        controller_host="198.51.100.21",
        packets=987_654_321,
        bytes_count=123_456_789,
        observed_at=same_time,
    )
    last = _observation(
        controller_name="MD-B",
        controller_host="198.51.100.22",
        packets=987_654_322,
        bytes_count=123_456_790,
        observed_at=same_time,
    )
    store.record_query(run_id, (first,))
    store.record_query(run_id, (last,))
    store.record_lifecycle(
        run_id,
        session_key=first.session_key,
        instance_id="same-time-instance",
        event_type="MISSED",
        controller_name=first.controller_name,
        occurred_at=same_time,
    )
    store.record_lifecycle(
        run_id,
        session_key=last.session_key,
        instance_id="same-time-instance",
        event_type="COUNTERS_CHANGED",
        controller_name=last.controller_name,
        occurred_at=same_time,
    )
    store.finish_run(run_id, ended_at=same_time)

    document = store.export_run_html(run_id).read_text(encoding="utf-8")
    csv_path = store.export_run_csv(run_id, tmp_path / "counter-preservation.csv")
    with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
        csv_rows = list(csv.DictReader(stream))
    with closing(sqlite3.connect(store.db_path)) as connection:
        stored_counters = connection.execute(
            "SELECT packets, bytes_count FROM observations ORDER BY id"
        ).fetchall()
    latest = re.search(
        r'<section id="latest-sessions">(?P<body>.*?)</section>', document, re.DOTALL
    )
    history = re.search(
        r'<section id="observation-history">(?P<body>.*?)</section>', document, re.DOTALL
    )

    assert latest is not None and history is not None
    latest_body = latest.group("body")
    history_body = history.group("body")
    assert (
        len(
            re.findall(
                r'<tbody\b[^>]*>\s*<tr\b(?=[^>]*\bclass="[^"]*\breport-row\b)',
                latest_body,
            )
        )
        == 1
    )
    assert "MD-B" in latest_body
    assert ">확인됨<" in latest_body
    assert "session-changes" not in document
    assert "세션별 수치 변화" not in document
    assert "987654321" not in document
    assert "123456789" not in document
    assert history_body.index("MD-A") < history_body.index("MD-B")
    assert [(row["packets"], row["bytes_count"]) for row in csv_rows] == [
        ("987654321", "123456789"),
        ("987654322", "123456790"),
    ]
    assert stored_counters == [(987_654_321, 123_456_789), (987_654_322, 123_456_790)]


def test_html_export_frequency_ignores_malformed_sqlite_protocols_and_ports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    rows = (
        (6, 53000, 443, "valid"),
        (6, "", 443, "text-source-port"),
        ("invalid", 22, 443, "text-protocol"),
        (300, 22, 443, "high-protocol"),
        (6, 22, 70000, "high-destination-port"),
        (6, -1, 0, "low-ports"),
    )
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.executemany(
            """
            INSERT INTO observations (
                run_id, raw_file_id, observed_at, controller_name,
                controller_host, protocol, source_ip, destination_ip,
                source_port, destination_port, counter, priority, tos,
                age, destination, tunnel_age, packets, bytes_count,
                flags, cpu_id, session_key
            ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    run_id,
                    "2026-08-28T08:00:00.000Z",
                    "MD-01",
                    "198.51.100.21",
                    protocol,
                    "192.0.2.100",
                    "203.0.113.80",
                    source_port,
                    destination_port,
                    "0/0",
                    0,
                    0,
                    1,
                    "local",
                    1,
                    1,
                    128,
                    "FC",
                    1,
                    session_key,
                )
                for protocol, source_port, destination_port, session_key in rows
            ),
        )
    store.finish_run(run_id)

    captured: list[tuple[tuple[int, int, int, int], ...] | None] = []

    def capture_frequency_summary(
        destination: Path | str,
        snapshot: RunReportSnapshot,
        observation_history: Iterator[dict[str, object]],
        *,
        logical_session_total: int,
    ) -> Path:
        del observation_history, logical_session_total
        captured.append(snapshot.protocol_port_frequency_summary)
        path = Path(destination)
        path.write_text("<!doctype html><title>fixture</title>", encoding="utf-8")
        return path

    monkeypatch.setattr(
        session_store_module,
        "write_html_report_stream_atomic",
        capture_frequency_summary,
    )
    store.export_run_html(run_id, tmp_path / "malformed-frequency.html")

    assert captured == [
        (
            (6, 443, 0, 2),
            (6, 22, 1, 0),
            (6, 53000, 1, 0),
        )
    ]


def test_html_export_contains_every_stored_row_without_ui_or_legacy_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    raw_directory = store.raw_root / run_id / "legacy-bulk"
    raw_directory.mkdir(parents=True)
    raw_rows: list[tuple[object, ...]] = []
    for index in range(501):
        content = f"private-raw-body-{index}".encode()
        relative = f"{run_id}/legacy-bulk/capture-{index:04d}.txt"
        (store.raw_root / Path(relative)).write_bytes(content)
        raw_rows.append(
            (
                run_id,
                "2026-08-28T08:00:00.000Z",
                "oldest-raw-kind" if index == 0 else "session",
                "MD-01",
                relative,
                hashlib.sha256(content).hexdigest(),
                len(content),
            )
        )

    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executemany(
            """
            INSERT INTO observations (
                run_id, raw_file_id, observed_at, controller_name,
                controller_host, protocol, source_ip, destination_ip,
                source_port, destination_port, counter, priority, tos,
                age, destination, tunnel_age, packets, bytes_count,
                flags, cpu_id, session_key
            ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    run_id,
                    "2026-08-28T08:01:00.000Z",
                    "OLDEST-OBSERVATION-CONTROLLER" if index == 0 else "MD-01",
                    "198.51.100.21",
                    6,
                    "192.0.2.100",
                    "203.0.113.80",
                    53000,
                    443,
                    "0/0",
                    0,
                    0,
                    index,
                    "local",
                    index,
                    index,
                    index * 128,
                    "FC",
                    index % 4,
                    "one-stable-session-key",
                )
                for index in range(2_005)
            ),
        )
        connection.executemany(
            """
            INSERT INTO lifecycle_events (
                run_id, occurred_at, session_key, instance_id,
                event_type, controller_name, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    run_id,
                    "2026-08-28T08:02:00.000Z",
                    "one-stable-session-key",
                    "OLDEST-LIFECYCLE-INSTANCE" if index == 0 else f"instance-{index:04d}",
                    "OPENED",
                    "MD-01",
                    "{}",
                )
                for index in range(1_001)
            ),
        )
        connection.executemany(
            """
            INSERT INTO controller_events (
                run_id, occurred_at, previous_controller, current_controller, reason
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                (
                    run_id,
                    "2026-08-28T08:03:00.000Z",
                    "MD-01",
                    "MD-02",
                    "OLDEST-CONTROLLER-REASON" if index == 0 else f"REASON-{index:04d}",
                )
                for index in range(501)
            ),
        )
        connection.executemany(
            """
            INSERT INTO diagnostic_events (run_id, occurred_at, stage, code, message)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                (
                    run_id,
                    "2026-08-28T08:04:00.000Z",
                    "fixture",
                    None,
                    "OLDEST-DIAGNOSTIC-MESSAGE" if index == 0 else f"diagnostic-{index:04d}",
                )
                for index in range(501)
            ),
        )
        connection.executemany(
            """
            INSERT INTO raw_files (
                run_id, captured_at, kind, controller_name,
                relative_path, sha256, byte_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            raw_rows,
        )

    store.finish_run(run_id)
    original_writer = session_store_module.write_html_report_stream_atomic
    streaming_inputs: list[bool] = []
    frequency_summaries: list[
        tuple[
            tuple[tuple[str, int, int], ...] | None,
            tuple[tuple[int, int, int, int], ...] | None,
        ]
    ] = []

    def observe_streaming_writer(
        destination: Path,
        snapshot: RunReportSnapshot,
        observation_history: Iterator[dict[str, object]],
        *,
        logical_session_total: int,
    ) -> Path:
        streaming_inputs.append(not isinstance(observation_history, (tuple, list)))
        frequency_summaries.append(
            (snapshot.ip_frequency_summary, snapshot.protocol_port_frequency_summary)
        )
        return original_writer(
            destination,
            snapshot,
            observation_history,
            logical_session_total=logical_session_total,
        )

    monkeypatch.setattr(
        session_store_module,
        "write_html_report_stream_atomic",
        observe_streaming_writer,
    )
    destination = store.export_run_html(run_id, tmp_path / "all-stored-data.html")
    document = destination.read_text(encoding="utf-8")
    history_section = re.search(
        r'<section id="observation-history">(?P<body>.*?)</section>',
        document,
        flags=re.DOTALL,
    )
    assert history_section is not None
    history_body = history_section.group("body")
    history_table_body = re.search(
        r"<tbody\b[^>]*>(?P<body>.*?)</tbody>",
        history_body,
        re.DOTALL,
    )
    assert history_table_body is not None

    assert (
        len(
            re.findall(
                r'<tr\b(?=[^>]*\bclass="[^"]*\breport-row\b)',
                history_table_body.group("body"),
            )
        )
        == 2_005
    )
    assert "OLDEST-OBSERVATION-CONTROLLER" in history_body
    assert "OLDEST-LIFECYCLE-INSTANCE" not in document
    assert "OLDEST-CONTROLLER-REASON" not in document
    assert "OLDEST-DIAGNOSTIC-MESSAGE" not in document
    assert "oldest-raw-kind" not in document
    assert "capture-0000.txt" not in document
    assert "private-raw-body-0" not in document
    assert "총 2,005회 · 출발지 2,005회 · 목적지 0회" in document
    assert "총 2,005회 · 출발지 0회 · 목적지 2,005회" in document
    assert (
        '<summary id="history-filter-summary" aria-controls="observation-history-body">'
        "전체 추적 이력 2,005/2,005건 보기</summary>"
    ) in document
    assert "세션별 수치 변화" not in document
    assert "패킷" not in document
    assert "바이트" not in document
    assert streaming_inputs == [True]
    assert frequency_summaries == [
        (
            (("192.0.2.100", 2_005, 0), ("203.0.113.80", 0, 2_005)),
            ((6, 443, 0, 2_005), (6, 53000, 2_005, 0)),
        )
    ]


def test_record_writes_and_second_finish_require_running_run(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)

    with pytest.raises(StorageError, match="RUNNING"):
        store.record_query(run_id, [_observation()], raw_text="must be rolled back")
    with pytest.raises(StorageError, match="RUNNING"):
        store.record_lifecycle(
            run_id,
            session_key="key",
            instance_id="instance-002",
            event_type="MISSED",
            controller_name="MD-01",
        )
    with pytest.raises(StorageError, match="RUNNING"):
        store.record_controller_event(run_id, current_controller="MD-01")
    with pytest.raises(StorageError, match="RUNNING"):
        store.record_diagnostic(
            DiagnosticEvent(stage="poll", code=None, message="done"), run_id=run_id
        )
    with pytest.raises(StorageError, match="RUNNING"):
        store.finish_run(run_id, status="FAILED")

    assert tuple(store.raw_root.rglob("*.txt")) == ()
    assert store.list_runs()[0]["status"] == "COMPLETED"


def test_finish_run_retries_lease_cleanup_after_database_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    lease_path = store._run_leases[run_id].path
    release_calls: list[bool] = []
    original_release = session_store_module._release_run_lease

    def fail_first_cleanup(
        lease: session_store_module._RunLease,
        *,
        remove: bool,
    ) -> None:
        release_calls.append(remove)
        if len(release_calls) == 1:
            original_release(lease, remove=False)
            raise OSError("forced lease cleanup failure")
        original_release(lease, remove=remove)

    monkeypatch.setattr(session_store_module, "_release_run_lease", fail_first_cleanup)

    with pytest.raises(StorageError, match="잠금 파일"):
        store.finish_run(run_id)

    assert store.list_runs()[0]["status"] == "COMPLETED"
    assert run_id in store._run_leases
    assert lease_path.exists()

    store.finish_run(run_id)

    assert release_calls == [True, True]
    assert run_id not in store._run_leases
    assert not lease_path.exists()
    with pytest.raises(StorageError, match="RUNNING"):
        store.finish_run(run_id)


def test_preview_delete_rejects_running_run_for_single_and_full_scope(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _run(store)

    with pytest.raises(StorageError, match="RUNNING"):
        store.preview_delete(store.list_runs()[0]["id"])
    with pytest.raises(StorageError, match="RUNNING"):
        store.preview_delete()


def test_full_delete_includes_orphan_regular_files(tmp_path: Path) -> None:
    store = _store(tmp_path)
    orphan_raw = store.raw_root / "orphan" / "capture.txt"
    orphan_export = store.exports_root / "orphan.csv"
    orphan_raw.parent.mkdir()
    orphan_raw.write_text("raw", encoding="utf-8")
    orphan_export.write_text("csv", encoding="utf-8")

    preview = store.preview_delete()
    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert preview.raw_files == 1
    assert preview.export_files == 1
    assert result.deleted_runs == 0
    assert result.deleted_raw_files == 1
    assert result.deleted_export_files == 1
    assert not orphan_raw.exists()
    assert not orphan_export.exists()


def test_per_run_delete_includes_only_that_runs_orphan_raw_files(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)
    target = store.raw_root / run_id / "unregistered.txt"
    unrelated = store.raw_root / "another-run" / "keep.txt"
    target.parent.mkdir()
    unrelated.parent.mkdir()
    target.write_text("delete", encoding="utf-8")
    unrelated.write_text("keep", encoding="utf-8")

    preview = store.preview_delete(run_id)
    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert preview.raw_files == 1
    assert result.deleted_raw_files == 1
    assert not target.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"


def test_delete_rolls_staged_files_back_when_database_commit_fails(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="preserve me")
    store.finish_run(run_id)
    raw_path = next(store.raw_root.rglob("*.txt"))
    preview = store.preview_delete(run_id)
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.execute(
            """
            CREATE TRIGGER prevent_run_delete
            BEFORE DELETE ON runs
            BEGIN
                SELECT RAISE(ABORT, 'blocked for test');
            END
            """
        )

    with pytest.raises(StorageError, match="데이터베이스"):
        store.delete(preview, confirmation_token=preview.confirmation_token)

    assert raw_path.read_text(encoding="utf-8") == "preserve me"
    assert len(store.list_runs()) == 1
    assert not tuple(store.raw_root.glob(".delete-staging-*"))


def test_delete_restores_a_file_after_transient_post_move_verification_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="restore after verification failure")
    store.finish_run(run_id)
    raw_path = next(store.raw_root.rglob("*.txt"))
    preview = store.preview_delete(run_id)
    original_verify = session_store_module._verify_file_fingerprint
    failed_after_move = False

    def fail_first_staged_verification(path: Path, sha256: str, byte_size: int) -> None:
        nonlocal failed_after_move
        if not failed_after_move and any(
            part.startswith(".delete-staging-") for part in path.parts
        ):
            failed_after_move = True
            raise StorageError("forced post-move fingerprint failure")
        original_verify(path, sha256, byte_size)

    monkeypatch.setattr(
        session_store_module,
        "_verify_file_fingerprint",
        fail_first_staged_verification,
    )

    with pytest.raises(StorageError, match="post-move"):
        store.delete(preview, confirmation_token=preview.confirmation_token)

    assert failed_after_move is True
    assert raw_path.read_text(encoding="utf-8") == "restore after verification failure"
    assert len(store.list_runs()) == 1
    assert not tuple(store.raw_root.glob(".delete-staging-*"))
    assert not tuple(store._manifests_root.glob("*.json"))


def test_delete_keeps_manifest_when_post_move_file_cannot_be_restored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    raw_text = "recover from retained manifest"
    store.record_query(run_id, [_observation()], raw_text=raw_text)
    store.finish_run(run_id)
    raw_path = next(store.raw_root.rglob("*.txt"))
    preview = store.preview_delete(run_id)
    original_verify = session_store_module._verify_file_fingerprint

    def fail_staged_verification(path: Path, sha256: str, byte_size: int) -> None:
        if any(part.startswith(".delete-staging-") for part in path.parts):
            raise StorageError("forced persistent staging verification failure")
        original_verify(path, sha256, byte_size)

    monkeypatch.setattr(
        session_store_module,
        "_verify_file_fingerprint",
        fail_staged_verification,
    )

    with pytest.raises(StorageError, match="persistent staging"):
        store.delete(preview, confirmation_token=preview.confirmation_token)

    stage_roots = tuple(store.raw_root.glob(".delete-staging-*"))
    staged_files = tuple(path for stage_root in stage_roots for path in stage_root.rglob("*.txt"))
    manifests = tuple(store._manifests_root.glob("*.json"))
    assert not raw_path.exists()
    assert len(staged_files) == 1
    assert len(manifests) == 1
    assert len(store.list_runs()) == 1

    monkeypatch.setattr(
        session_store_module,
        "_verify_file_fingerprint",
        original_verify,
    )
    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert raw_path.read_text(encoding="utf-8") == raw_text
    assert not tuple(store.raw_root.glob(".delete-staging-*"))
    assert not manifests[0].exists()


def test_delete_fails_closed_for_symlink_in_managed_scope(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)
    run_directory = store.raw_root / run_id
    run_directory.mkdir()
    target = tmp_path / "target.txt"
    target.write_text("keep", encoding="utf-8")
    link = run_directory / "linked.txt"
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")

    with pytest.raises(StorageError, match="안전하지"):
        store.preview_delete(run_id)

    assert target.read_text(encoding="utf-8") == "keep"


def test_storage_health_reports_managed_usage_and_thresholds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(
        run_id,
        [_observation()],
        raw_text="raw-health",
        captured_at=datetime(2026, 8, 28, 8, 15, tzinfo=UTC),
    )
    store.finish_run(run_id)
    exported = store.export_run_csv(run_id)
    monkeypatch.setattr(
        session_store_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=6 * 1024**3),
    )

    health = store.storage_health()

    assert health.database_bytes == store.db_path.stat().st_size
    assert health.wal_bytes >= 0
    assert health.raw_file_count == 1
    assert health.raw_bytes == len(b"raw-health")
    assert health.export_file_count == 1
    assert health.export_bytes == exported.stat().st_size
    assert health.total_managed_bytes == (
        health.database_bytes + health.wal_bytes + health.raw_bytes + health.export_bytes
    )
    assert health.total_file_count == 2
    assert health.free_bytes == 6 * 1024**3
    assert health.warning is False
    assert health.hard_stop is False

    warning = StorageHealth(0, 0, 0, 0, 0, 0, 5 * 1024**3 - 1)
    hard_stop = StorageHealth(0, 0, 0, 0, 0, 0, 1024**3 - 1)
    assert warning.warning is True
    assert warning.hard_stop is False
    assert hard_stop.warning is True
    assert hard_stop.hard_stop is True


@pytest.mark.parametrize(
    ("failure", "expected_kind", "expected_code"),
    (
        ("path", StorageFailureKind.STORAGE_PATH, ErrorCode.STORAGE_PATH_FAILED),
        ("space", StorageFailureKind.LOW_SPACE, ErrorCode.STORAGE_LOW_SPACE),
        ("database", StorageFailureKind.DATABASE_WRITE, ErrorCode.DB_WRITE_FAILED),
    ),
)
def test_storage_health_preserves_typed_failure_kind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    expected_kind: StorageFailureKind,
    expected_code: ErrorCode,
) -> None:
    store = _store(tmp_path)

    def fail_health() -> StorageHealth:
        if failure == "path":
            raise PermissionError("sanitized health path fixture")
        if failure == "space":
            raise OSError(errno.ENOSPC, "sanitized health space fixture")
        raise sqlite3.DatabaseError("sanitized health database fixture")

    if failure == "path":
        monkeypatch.setattr(store, "_ensure_initialized", fail_health)
    else:
        monkeypatch.setattr(store, "_storage_health_unlocked", fail_health)
    with pytest.raises(StorageError) as caught:
        store.storage_health()

    assert caught.value.code is expected_code
    assert caught.value.failure_kind is expected_kind
    assert caught.value.boundary is None


def test_storage_health_tolerates_sqlite_wal_disappearing_after_presence_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    wal_path = Path(f"{store.db_path}-wal")
    original_lexists = os.path.lexists
    original_lstat = os.lstat

    def stale_presence(path: os.PathLike[str] | str) -> bool:
        if Path(path) == wal_path:
            return True
        return original_lexists(path)

    def vanished_wal(path: os.PathLike[str] | str) -> os.stat_result:
        if Path(path) == wal_path:
            raise FileNotFoundError(path)
        return original_lstat(path)

    monkeypatch.setattr(session_store_module.os.path, "lexists", stale_presence)
    monkeypatch.setattr(session_store_module.os, "lstat", vanished_wal)

    health = store.storage_health()

    assert health.wal_bytes == 0


def test_first_storage_health_is_incremental_until_explicit_reconciliation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    orphan = store.raw_root / "orphan" / "capture.txt"
    orphan.parent.mkdir()
    orphan.write_bytes(b"orphan")
    scans: list[Path] = []
    original_scan = session_store_module._storage_tree_stats

    def count_scan(root: Path, **kwargs: object) -> tuple[int, int]:
        scans.append(root)
        return original_scan(root, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "_storage_tree_stats", count_scan)

    initial = store.storage_health()
    assert scans == []
    assert initial.raw_file_count == 0

    reconciled = store.reconcile_storage_health()
    assert scans == [store.raw_root, store.exports_root]
    assert reconciled.raw_file_count == 1
    assert reconciled.raw_bytes == len(b"orphan")

    monkeypatch.setattr(session_store_module.time, "monotonic", lambda: 10**12)
    store.storage_health()
    assert scans == [store.raw_root, store.exports_root]


def test_deep_storage_reconciliation_does_not_hold_store_lock_against_poll_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    scan_started = threading.Event()
    release_scan = threading.Event()
    original_scan = session_store_module._storage_tree_stats

    def blocking_scan(root: Path, **kwargs: object) -> tuple[int, int]:
        if not scan_started.is_set():
            scan_started.set()
            if not release_scan.wait(timeout=10):
                raise TimeoutError("storage reconciliation synchronization timed out")
        return original_scan(root, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "_storage_tree_stats", blocking_scan)
    results: list[StorageHealth] = []
    errors: list[BaseException] = []

    def reconcile() -> None:
        try:
            results.append(store.reconcile_storage_health())
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    reconciliation = threading.Thread(target=reconcile)
    reconciliation.start()
    assert scan_started.wait(timeout=5)
    assert store.storage_health().raw_file_count == 0
    write_completed = threading.Event()

    def write_poll() -> None:
        store.record_query(run_id, [_observation()], raw_text="reconcile-concurrency")
        write_completed.set()

    writer = threading.Thread(target=write_poll)
    writer.start()
    try:
        assert write_completed.wait(timeout=5)
    finally:
        release_scan.set()
    writer.join(timeout=5)
    reconciliation.join(timeout=10)

    assert not writer.is_alive()
    assert not reconciliation.is_alive()
    assert errors == []
    assert len(results) == 1
    assert results[0].raw_file_count == 1


def test_deep_storage_reconciliation_supports_cancel_and_releases_lease(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    orphan_root = store.raw_root / "orphans"
    orphan_root.mkdir()
    for index in range(3):
        (orphan_root / f"{index}.txt").write_text("raw", encoding="utf-8")
    cancel_requested = False
    progress_events: list[tuple[str, int, int | None]] = []

    def request_cancel(phase: str, completed: int, total: int | None) -> None:
        nonlocal cancel_requested
        progress_events.append((phase, completed, total))
        cancel_requested = True

    with pytest.raises(StorageError) as caught:
        store.reconcile_storage_health(
            cancel_check=lambda: cancel_requested,
            progress=request_cancel,
        )

    assert caught.value.code is ErrorCode.CANCELLED
    assert progress_events
    recovered = store.reconcile_storage_health()
    assert recovered.raw_file_count == 3


def test_export_and_delete_preview_support_cooperative_cancellation(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        connection.executemany(
            """
            INSERT INTO observations (
                run_id, raw_file_id, observed_at, controller_name,
                controller_host, protocol, source_ip, destination_ip,
                source_port, destination_port, counter, priority, tos,
                age, destination, tunnel_age, packets, bytes_count,
                flags, cpu_id, session_key
            ) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                (
                    run_id,
                    "2026-08-28T08:01:00.000Z",
                    "MD-01",
                    "198.51.100.21",
                    6,
                    "192.0.2.100",
                    "203.0.113.80",
                    53000 + index,
                    443,
                    "0/0",
                    0,
                    0,
                    index,
                    "local",
                    0,
                    index,
                    index,
                    "FC",
                    1,
                    f"session-{index}",
                )
                for index in range(1_500)
            ),
        )
    store.finish_run(run_id)
    checks = 0
    progress_events: list[tuple[str, int, int | None]] = []

    def cancel_export() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 4

    with pytest.raises(StorageError) as caught:
        store.export_run_csv(
            run_id,
            tmp_path / "cancelled.csv",
            cancel_check=cancel_export,
            progress=lambda *event: progress_events.append(event),
        )
    assert caught.value.code is ErrorCode.CANCELLED
    assert progress_events
    assert not (tmp_path / "cancelled.csv").exists()
    assert not tuple(store._manifests_root.glob("*.json"))

    orphan_root = store.raw_root / "orphan"
    orphan_root.mkdir()
    for index in range(5):
        (orphan_root / f"{index}.txt").write_text("raw", encoding="utf-8")
    preview_checks = 0

    def cancel_preview() -> bool:
        nonlocal preview_checks
        preview_checks += 1
        return preview_checks >= 4

    with pytest.raises(StorageError) as caught:
        store.preview_delete(cancel_check=cancel_preview)
    assert caught.value.code is ErrorCode.CANCELLED
    assert store._pending_deletions == {}


def test_delete_reuses_unchanged_preview_fingerprint_before_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="one managed raw")
    store.finish_run(run_id)
    calls = 0
    original = session_store_module._file_fingerprint

    def count_fingerprint(path: Path) -> tuple[str, int]:
        nonlocal calls
        calls += 1
        return original(path)

    monkeypatch.setattr(session_store_module, "_file_fingerprint", count_fingerprint)
    preview = store.preview_delete(run_id)
    assert calls == 1

    result = store.delete(preview, confirmation_token=preview.confirmation_token)
    assert result.deleted_raw_files == 1
    # Preview hashes once; delete then verifies the staged file and final purge.
    assert calls == 3


def test_delete_stages_large_files_before_taking_sqlite_write_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="staging outside transaction")
    store.finish_run(run_id)
    preview = store.preview_delete(run_id)
    original_stage = session_store_module._stage_files
    write_lock_available: list[bool] = []

    def observe_stage(
        root: Path,
        files: tuple[session_store_module._DeletionFile, ...],
        preview_id: str,
        category: str,
        staged: list[session_store_module._StagedFile],
        **kwargs: object,
    ) -> None:
        if not write_lock_available:
            with closing(sqlite3.connect(store.db_path, timeout=0.1)) as connection:
                connection.execute("PRAGMA busy_timeout = 100")
                connection.execute("BEGIN IMMEDIATE")
                connection.rollback()
            write_lock_available.append(True)
        original_stage(root, files, preview_id, category, staged, **kwargs)

    monkeypatch.setattr(session_store_module, "_stage_files", observe_stage)

    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert write_lock_available == [True]
    assert result.deleted_runs == 1


def test_delete_preview_scan_does_not_hold_store_lock_against_poll_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    completed_run = _run(store)
    store.record_query(completed_run, [_observation()], raw_text="preview scan")
    store.finish_run(completed_run)
    active_run = _run(store)
    scan_started = threading.Event()
    release_scan = threading.Event()
    original_snapshot = session_store_module._snapshot_managed_files

    def blocking_snapshot(*args: object, **kwargs: object) -> object:
        if not scan_started.is_set():
            scan_started.set()
            if not release_scan.wait(timeout=10):
                raise TimeoutError("delete preview scan synchronization timed out")
        return original_snapshot(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "_snapshot_managed_files", blocking_snapshot)
    previews: list[DeletePreview] = []
    preview_errors: list[BaseException] = []

    def create_preview() -> None:
        try:
            previews.append(store.preview_delete(completed_run))
        except BaseException as error:  # pragma: no cover - asserted below
            preview_errors.append(error)

    preview_thread = threading.Thread(target=create_preview)
    preview_thread.start()
    assert scan_started.wait(timeout=5)
    write_completed = threading.Event()

    def write_poll() -> None:
        store.record_query(active_run, [replace(_observation(), destination_port=8443)])
        write_completed.set()

    writer = threading.Thread(target=write_poll)
    writer.start()
    try:
        assert write_completed.wait(timeout=5)
    finally:
        release_scan.set()
    writer.join(timeout=5)
    preview_thread.join(timeout=10)

    assert not writer.is_alive()
    assert not preview_thread.is_alive()
    assert preview_errors == []
    assert len(previews) == 1
    assert store.discard_delete_preview(previews[0]) is True


def test_delete_file_staging_does_not_hold_store_lock_against_poll_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    completed_run = _run(store)
    store.record_query(completed_run, [_observation()], raw_text="delete staging")
    store.finish_run(completed_run)
    active_run = _run(store)
    preview = store.preview_delete(completed_run)
    stage_started = threading.Event()
    release_stage = threading.Event()
    original_stage = session_store_module._stage_files

    def blocking_stage(*args: object, **kwargs: object) -> None:
        if not stage_started.is_set():
            stage_started.set()
            if not release_stage.wait(timeout=10):
                raise TimeoutError("delete staging synchronization timed out")
        original_stage(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(session_store_module, "_stage_files", blocking_stage)
    deletion_results: list[DeletionResult] = []
    deletion_errors: list[BaseException] = []

    def delete_run() -> None:
        try:
            deletion_results.append(
                store.delete(preview, confirmation_token=preview.confirmation_token)
            )
        except BaseException as error:  # pragma: no cover - asserted below
            deletion_errors.append(error)

    delete_thread = threading.Thread(target=delete_run)
    delete_thread.start()
    assert stage_started.wait(timeout=5)
    write_completed = threading.Event()

    def write_poll() -> None:
        store.record_query(active_run, [replace(_observation(), destination_port=9443)])
        write_completed.set()

    writer = threading.Thread(target=write_poll)
    writer.start()
    try:
        assert write_completed.wait(timeout=5)
    finally:
        release_stage.set()
    writer.join(timeout=5)
    delete_thread.join(timeout=10)

    assert not writer.is_alive()
    assert not delete_thread.is_alive()
    assert deletion_errors == []
    assert len(deletion_results) == 1
    assert deletion_results[0].deleted_runs == 1


def test_database_checkpoint_and_atomic_user_backup(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="backup raw")
    store.finish_run(run_id)
    progress_events: list[tuple[str, int, int | None]] = []
    backup = store.backup_database(
        tmp_path / "user-backups" / "tracker-backup.db",
        progress=lambda *event: progress_events.append(event),
    )

    assert backup.exists()
    assert progress_events
    with closing(sqlite3.connect(backup)) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("SELECT count(*) FROM runs").fetchone()[0] == 1
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 1
    busy, log_pages, checkpointed_pages = store.checkpoint_database()
    assert busy in {0, 1}
    assert log_pages >= 0
    assert checkpointed_pages >= 0


def test_low_space_blocks_growth_with_stable_error_but_allows_run_finish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    monkeypatch.setattr(
        session_store_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=1024**3 - 1),
    )

    store.finish_run(run_id)
    with pytest.raises(StorageError) as caught:
        store.start_run(QueryRequest("192.0.2.1", "203.0.113.1"))

    assert caught.value.code is ErrorCode.STORAGE_LOW_SPACE
    assert caught.value.failure_kind is StorageFailureKind.LOW_SPACE
    assert caught.value.boundary is StorageFailureBoundary.QUERY_START
    assert len(store.list_runs()) == 1
    assert store.list_runs()[0]["status"] == "COMPLETED"


def test_finish_run_wraps_managed_path_failure_at_finalize_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    original_assert_layout = store._assert_managed_layout

    def fail_layout() -> None:
        raise session_store_module.UnsafeManagedPath("sanitized managed-path fixture")

    monkeypatch.setattr(store, "_assert_managed_layout", fail_layout)
    with pytest.raises(StorageError) as caught:
        store.finish_run(run_id)

    assert caught.value.code is ErrorCode.STORAGE_PATH_FAILED
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH
    assert caught.value.boundary is StorageFailureBoundary.QUERY_FINALIZE

    monkeypatch.setattr(store, "_assert_managed_layout", original_assert_layout)
    store.finish_run(run_id, status="FAILED")


def test_export_preflight_reserves_space_for_the_staged_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    estimate = store._estimate_export_bytes(run_id, html=False)
    monkeypatch.setattr(
        session_store_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(
            free=session_store_module.STORAGE_HARD_STOP_FREE_BYTES + estimate - 1
        ),
    )

    with pytest.raises(StorageError) as caught:
        store.export_run_csv(run_id, tmp_path / "preflight.csv")

    assert caught.value.code is ErrorCode.STORAGE_LOW_SPACE
    assert caught.value.failure_kind is StorageFailureKind.LOW_SPACE
    assert caught.value.boundary is None
    assert not (tmp_path / "preflight.csv").exists()
    assert not tuple(store._manifests_root.glob("*.json"))


@pytest.mark.windows
def test_windows_atomic_replace_retries_transient_sharing_violation(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows sharing violations apply only on Windows")
    source = tmp_path / "source.tmp"
    destination = tmp_path / "destination.txt"
    source.write_bytes(b"replacement")
    attempts = 0

    def flaky_replace(current: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            error = PermissionError("fixture sharing violation")
            error.winerror = 32
            raise error
        os.replace(current, target)

    durable_io_module.replace_with_retry(source, destination, replace=flaky_replace)

    assert attempts == 3
    assert destination.read_bytes() == b"replacement"


@pytest.mark.windows
def test_windows_file_retry_accepts_errno_only_eacces_without_busy_reclassification() -> None:
    if os.name != "nt":
        pytest.skip("Windows CRT access-denied behavior applies only on Windows")
    error = PermissionError(errno.EACCES, "fixture transient access denial")

    assert getattr(error, "winerror", None) is None
    assert durable_io_module.is_retryable_windows_file_operation_error(error) is True
    assert durable_io_module.is_transient_windows_file_error(error) is False
    assert (
        session_store_module._storage_failure_kind_from_exception(error)
        is StorageFailureKind.STORAGE_PATH
    )


@pytest.mark.windows
def test_windows_file_operation_retries_errno_only_eacces() -> None:
    if os.name != "nt":
        pytest.skip("Windows CRT access-denied behavior applies only on Windows")
    attempts = 0

    def flaky_operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(errno.EACCES, "fixture transient access denial")
        return "recovered"

    result = durable_io_module.retry_windows_file_operation(
        flaky_operation,
        delays=(0.0, 0.0),
    )

    assert result == "recovered"
    assert attempts == 2


@pytest.mark.windows
def test_windows_file_operation_persistent_errno_only_eacces_stays_path_failure() -> None:
    if os.name != "nt":
        pytest.skip("Windows CRT access-denied behavior applies only on Windows")
    attempts = 0

    def blocked_operation() -> None:
        nonlocal attempts
        attempts += 1
        raise PermissionError(errno.EACCES, "fixture persistent access denial")

    with pytest.raises(PermissionError) as caught:
        durable_io_module.retry_windows_file_operation(
            blocked_operation,
            delays=(0.0, 0.0, 0.0),
        )

    assert attempts == 3
    assert (
        session_store_module._storage_failure_kind_from_exception(caught.value)
        is StorageFailureKind.STORAGE_PATH
    )


@pytest.mark.windows
def test_windows_atomic_replace_retries_errno_only_eacces(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows CRT access-denied behavior applies only on Windows")
    source = tmp_path / "source.tmp"
    destination = tmp_path / "destination.txt"
    source.write_bytes(b"replacement")
    attempts = 0

    def flaky_replace(current: Path, target: Path) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError(errno.EACCES, "fixture transient access denial")
        os.replace(current, target)

    durable_io_module.replace_with_retry(source, destination, replace=flaky_replace)

    assert attempts == 2
    assert destination.read_bytes() == b"replacement"


@pytest.mark.windows
def test_windows_file_retry_rejects_eacces_with_unrelated_winerror() -> None:
    if os.name != "nt":
        pytest.skip("Windows CRT access-denied behavior applies only on Windows")
    error = PermissionError(errno.EACCES, "fixture unrelated Windows failure")
    error.winerror = 65

    assert durable_io_module.is_retryable_windows_file_operation_error(error) is False


@pytest.mark.windows
def test_windows_atomic_replace_retries_initial_fingerprint_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows sharing violations apply only on Windows")
    source = tmp_path / "source.tmp"
    destination = tmp_path / "destination.txt"
    source.write_bytes(b"replacement")
    original_file_state = durable_io_module._file_state
    attempts = 0

    def flaky_file_state(
        path: Path,
        *,
        with_hash: bool,
        use_native_windows_identity: bool = False,
    ) -> object:
        nonlocal attempts
        if path == source and not with_hash:
            attempts += 1
            if attempts == 1:
                error = PermissionError("fixture sharing violation")
                error.winerror = 32
                raise error
        return original_file_state(
            path,
            with_hash=with_hash,
            use_native_windows_identity=use_native_windows_identity,
        )

    monkeypatch.setattr(durable_io_module, "_file_state", flaky_file_state)
    monkeypatch.setattr(durable_io_module.time, "sleep", lambda _delay: None)

    durable_io_module.replace_with_retry(source, destination)

    assert attempts == 2
    assert destination.read_bytes() == b"replacement"


@pytest.mark.windows
def test_windows_file_fingerprint_retries_transient_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows sharing violations apply only on Windows")
    target = tmp_path / "fingerprint.txt"
    content = b"trusted fingerprint content"
    target.write_bytes(content)
    original_open = Path.open
    attempts = 0

    def flaky_open(self: Path, *args: object, **kwargs: object) -> object:
        nonlocal attempts
        if self == target:
            attempts += 1
            if attempts == 1:
                error = PermissionError("fixture sharing violation")
                error.winerror = 32
                raise error
        return original_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", flaky_open)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _delay: None)

    digest, byte_size = session_store_module._file_fingerprint(target)

    assert attempts == 2
    assert digest == hashlib.sha256(content).hexdigest()
    assert byte_size == len(content)


@pytest.mark.windows
def test_windows_existing_lease_retries_transient_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows sharing violations apply only on Windows")
    lease_path = tmp_path / "lease.lock"
    lease_path.write_bytes(b"0")
    original_open = os.open
    attempts = 0

    def flaky_open(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal attempts
        if os.fspath(path) == os.fspath(lease_path) and not flags & os.O_EXCL:
            attempts += 1
            if attempts == 1:
                error = PermissionError("fixture sharing violation")
                error.winerror = 32
                raise error
        return original_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", flaky_open)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _delay: None)

    lease = session_store_module._acquire_file_lease(lease_path)
    assert lease is not None
    session_store_module._release_run_lease(lease, remove=True)

    assert attempts == 2
    assert not lease_path.exists()


@pytest.mark.windows
def test_windows_lease_lock_persistent_errno_only_eacces_returns_busy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows byte-range locking applies only on Windows")
    import msvcrt

    lease_path = tmp_path / "lease.lock"
    original_locking = msvcrt.locking
    attempts = 0

    def blocked_locking(descriptor: int, mode: int, byte_count: int) -> None:
        nonlocal attempts
        if mode == msvcrt.LK_NBLCK:
            attempts += 1
            raise PermissionError(errno.EACCES, "fixture transient access denial")
        original_locking(descriptor, mode, byte_count)

    monkeypatch.setattr(msvcrt, "locking", blocked_locking)
    monkeypatch.setattr(session_store_module.time, "sleep", lambda _delay: None)

    lease = session_store_module._acquire_file_lease(lease_path)

    assert lease is None
    assert attempts == len(session_store_module._LEASE_FILE_RETRY_DELAYS)


@pytest.mark.windows
def test_windows_replace_retry_fails_closed_if_source_changes(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows sharing violations apply only on Windows")
    source = tmp_path / "source.tmp"
    destination = tmp_path / "destination.txt"
    original = b"trusted replacement"
    source.write_bytes(original)
    attempts = 0

    def mutate_then_fail(_current: Path, _target: Path) -> None:
        nonlocal attempts
        attempts += 1
        source.write_bytes(b"tampered replacement")
        error = PermissionError("fixture sharing violation")
        error.winerror = 32
        raise error

    with pytest.raises(OSError, match="identity or fingerprint changed"):
        durable_io_module.replace_with_retry(
            source,
            destination,
            replace=mutate_then_fail,
            expected_sha256=hashlib.sha256(original).hexdigest(),
            expected_size=len(original),
        )

    assert attempts == 1
    assert not destination.exists()


def test_atomic_replace_rejects_same_size_corruption_before_first_attempt(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.tmp"
    destination = tmp_path / "destination.txt"
    trusted = b"trusted-content"
    corrupted = b"altered-content"
    assert len(corrupted) == len(trusted)
    source.write_bytes(corrupted)
    replace_calls = 0

    def unexpected_replace(_current: Path, _target: Path) -> None:
        nonlocal replace_calls
        replace_calls += 1

    with pytest.raises(OSError, match="differs from expected content"):
        durable_io_module.replace_with_retry(
            source,
            destination,
            replace=unexpected_replace,
            expected_sha256=hashlib.sha256(trusted).hexdigest(),
            expected_size=len(trusted),
        )

    assert replace_calls == 0
    assert source.read_bytes() == corrupted
    assert not destination.exists()


def test_atomic_replace_revalidates_destination_before_first_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_parent = tmp_path / "source"
    destination_parent = tmp_path / "destination"
    source_parent.mkdir()
    destination_parent.mkdir()
    source = source_parent / "source.tmp"
    destination = destination_parent / "destination.txt"
    source.write_bytes(b"replacement")
    destination.write_bytes(b"trusted-old")
    replace_calls = 0
    mutated = False
    original_validate = durable_io_module._validate_directory_state

    def mutate_before_destination_validation(
        path: Path,
        expected: object,
    ) -> None:
        nonlocal mutated
        if path == destination_parent and not mutated:
            mutated = True
            destination.write_bytes(b"altered-old")
        original_validate(path, expected)

    def unexpected_replace(_current: Path, _target: Path) -> None:
        nonlocal replace_calls
        replace_calls += 1

    monkeypatch.setattr(
        durable_io_module,
        "_validate_directory_state",
        mutate_before_destination_validation,
    )

    with pytest.raises(OSError, match="identity or fingerprint changed"):
        durable_io_module.replace_with_retry(
            source,
            destination,
            replace=unexpected_replace,
        )

    assert mutated is True
    assert replace_calls == 0
    assert source.read_bytes() == b"replacement"
    assert destination.read_bytes() == b"altered-old"


def test_query_capacity_check_is_fast_and_fails_before_a_poll(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(
        session_store_module,
        "_storage_tree_stats",
        lambda _root: pytest.fail("quick query capacity check scanned managed files"),
    )
    free_bytes = [2 * 1024**3]
    monkeypatch.setattr(
        session_store_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=free_bytes[0]),
    )

    store.ensure_query_capacity()
    free_bytes[0] = 1024**3 - 1
    with pytest.raises(StorageError) as caught:
        store.ensure_query_capacity()

    assert caught.value.code is ErrorCode.STORAGE_LOW_SPACE
    assert caught.value.failure_kind is StorageFailureKind.LOW_SPACE
    assert caught.value.boundary is StorageFailureBoundary.QUERY_PREFLIGHT


def test_query_capacity_wraps_path_error_at_preflight_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)

    def fail_initialized_check() -> None:
        raise PermissionError("sanitized preflight path fixture")

    monkeypatch.setattr(store, "_ensure_initialized", fail_initialized_check)
    with pytest.raises(StorageError) as caught:
        store.ensure_query_capacity()

    assert caught.value.code is ErrorCode.STORAGE_PATH_FAILED
    assert caught.value.failure_kind is StorageFailureKind.STORAGE_PATH
    assert caught.value.boundary is StorageFailureBoundary.QUERY_PREFLIGHT


def test_delete_preview_discard_expiry_sweep_and_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)
    clock = [100.0]
    monkeypatch.setattr(session_store_module.time, "monotonic", lambda: clock[0])

    discarded = store.preview_delete(run_id)
    assert store.discard_delete_preview(discarded) is True
    assert store.discard_delete_preview(discarded) is False
    with pytest.raises(StorageError, match="먼저"):
        store.delete(discarded, confirmation_token=discarded.confirmation_token)

    previews = [store.preview_delete(run_id) for _ in range(16)]
    with pytest.raises(StorageError, match="최대 16개"):
        store.preview_delete(run_id)

    clock[0] += 301
    replacement = store.preview_delete(run_id)
    assert store.discard_delete_preview(previews[0]) is False
    assert store.discard_delete_preview(replacement) is True


def test_new_raw_paths_are_hour_sharded_and_legacy_flat_paths_remain_usable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(
        run_id,
        [_observation()],
        raw_text="legacy-compatible",
        captured_at=datetime(2026, 8, 28, 8, 15, tzinfo=UTC),
    )
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        relative = str(
            connection.execute(
                "SELECT relative_path FROM raw_files WHERE run_id = ?", (run_id,)
            ).fetchone()[0]
        )
        parts = Path(relative).parts
        assert parts[:3] == (run_id, "20260828", "08")
        sharded = store.raw_root / Path(relative)
        legacy = store.raw_root / run_id / "legacy-flat.txt"
        os.replace(sharded, legacy)
        connection.execute(
            "UPDATE raw_files SET relative_path = ? WHERE run_id = ?",
            (legacy.relative_to(store.raw_root).as_posix(), run_id),
        )

    store.finish_run(run_id)
    assert store.export_run_csv(run_id).exists()
    preview = store.preview_delete(run_id)
    result = store.delete(preview, confirmation_token=preview.confirmation_token)

    assert result.deleted_raw_files == 1
    assert not (store.raw_root / run_id).exists()


def test_schema_adds_long_run_query_indexes_and_remains_quick_check_clean(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    with closing(sqlite3.connect(store.db_path)) as connection:
        indexes = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()
        }
        quick_check = tuple(row[0] for row in connection.execute("PRAGMA quick_check"))

    assert {
        "ix_observations_run_session_time",
        "ix_raw_files_run_time",
        "ix_exports_run_id",
    }.issubset(indexes)
    assert quick_check == ("ok",)


def test_managed_export_persists_all_durable_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    phases: list[str] = []
    original_write = store._write_manifest
    original_replace = store._replace_manifest

    def capture_write(operation_id: str, payload: dict[str, object]) -> Path:
        phases.append(str(payload.get("phase")))
        return original_write(operation_id, payload)

    def capture_replace(path: Path, payload: dict[str, object]) -> None:
        phases.append(str(payload.get("phase")))
        original_replace(path, payload)

    monkeypatch.setattr(store, "_write_manifest", capture_write)
    monkeypatch.setattr(store, "_replace_manifest", capture_replace)

    destination = store.export_run_csv(run_id)

    assert destination.exists()
    assert phases == ["PREPARED", "RENDERED", "INSTALLED", "DB_COMMITTED"]
    assert not tuple(store._manifests_root.glob("*.json"))
    assert not tuple(store._leases_root.glob("operation-*.lease"))


@pytest.mark.parametrize(
    ("target_phase", "new_export_committed"),
    (
        ("PREPARED", False),
        ("RENDERED", False),
        ("INSTALLED", False),
        ("DB_COMMITTED", True),
    ),
)
def test_startup_recovers_managed_export_after_hard_exit_at_each_phase(
    tmp_path: Path,
    target_phase: str,
    new_export_committed: bool,
) -> None:
    store = _store(tmp_path)
    original_run_id = _run(store)
    store.record_query(original_run_id, [_observation(packets=12)])
    store.finish_run(original_run_id)
    destination = store.exports_root / "shared.csv"
    store.export_run_csv(original_run_id, destination)
    original_bytes = destination.read_bytes()

    replacement_run_id = store.start_run(
        QueryRequest("192.0.2.101", "203.0.113.81", 53001, 8443),
        run_id=f"replacement-{target_phase.lower()}",
    )
    store.record_query(
        replacement_run_id,
        [_observation(controller_name="MD-02", packets=99)],
    )
    store.finish_run(replacement_run_id)
    expected_path = tmp_path / f"expected-{target_phase.lower()}.csv"
    store.export_run_csv(replacement_run_id, expected_path)
    replacement_bytes = expected_path.read_bytes()
    assert replacement_bytes != original_bytes

    repository = Path(__file__).resolve().parents[1]
    worker = Path(__file__).with_name("export_phase_crash_worker.py")
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(repository / "src") + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(worker),
            str(store.db_path),
            str(store.raw_root),
            str(store.exports_root),
            replacement_run_id,
            str(destination),
            target_phase,
        ],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 91, (completed.stdout, completed.stderr)

    manifests = tuple(store._manifests_root.glob("*.json"))
    assert len(manifests) == 1
    assert json.loads(manifests[0].read_text(encoding="utf-8"))["phase"] == target_phase
    assert len(tuple(store._leases_root.glob("operation-*.lease"))) == 1

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()
    expected_run_id = replacement_run_id if new_export_committed else original_run_id
    expected_bytes = replacement_bytes if new_export_committed else original_bytes
    expected_sha = hashlib.sha256(expected_bytes).hexdigest()
    with closing(sqlite3.connect(reopened.db_path)) as connection:
        export_rows = tuple(
            connection.execute(
                "SELECT run_id, sha256, byte_size FROM exports WHERE relative_path = ?",
                (destination.name,),
            )
        )
        quick_check = tuple(str(row[0]) for row in connection.execute("PRAGMA quick_check"))
        foreign_key_check = tuple(connection.execute("PRAGMA foreign_key_check"))

    assert destination.read_bytes() == expected_bytes
    assert export_rows == ((expected_run_id, expected_sha, len(expected_bytes)),)
    assert quick_check == ("ok",)
    assert foreign_key_check == ()
    assert not tuple(reopened.exports_root.rglob("*.staged"))
    assert not tuple(reopened.exports_root.rglob("*.backup"))
    assert not tuple(reopened.exports_root.rglob("*.tmp"))
    assert not tuple(reopened._manifests_root.iterdir())
    assert not tuple(reopened._leases_root.iterdir())


@pytest.mark.parametrize("preexisting_destination", (False, True))
@pytest.mark.parametrize("export_format", ("csv", "html"))
@pytest.mark.parametrize(
    "target_phase",
    (
        "PREPARED",
        "RENDERED",
        "INSTALLED",
        "DB_RECEIPT_COMMITTED",
        "DB_COMMITTED",
    ),
)
def test_startup_recovers_external_export_after_every_durable_boundary(
    tmp_path: Path,
    preexisting_destination: bool,
    export_format: str,
    target_phase: str,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation(packets=77)])
    store.finish_run(run_id)
    suffix = ".csv" if export_format == "csv" else ".html"
    destination = tmp_path / "user-chosen" / f"report{suffix}"
    previous_bytes = f"previous-user-file-{export_format}".encode()
    if preexisting_destination:
        destination.parent.mkdir(parents=True)
        destination.write_bytes(previous_bytes)

    expected_path = tmp_path / "expected" / f"report{suffix}"
    if export_format == "csv":
        store.export_run_csv(run_id, expected_path)
    else:
        store.export_run_html(run_id, expected_path)
    replacement_bytes = expected_path.read_bytes()
    assert replacement_bytes != previous_bytes

    completed = _run_export_crash(
        store,
        run_id,
        destination,
        target_phase,
        export_format,
    )
    assert completed.returncode == 91, (completed.stdout, completed.stderr)

    manifests = tuple(store._manifests_root.glob("*.json"))
    owners = tuple(store._export_owners_root.glob("*.json"))
    assert len(manifests) == 1
    assert len(owners) == 1
    manifest_phase = json.loads(manifests[0].read_text(encoding="utf-8"))["phase"]
    assert manifest_phase == (
        "INSTALLED" if target_phase == "DB_RECEIPT_COMMITTED" else target_phase
    )
    receipt_expected = target_phase in {"DB_RECEIPT_COMMITTED", "DB_COMMITTED"}
    with closing(sqlite3.connect(store.db_path)) as connection:
        receipt_count = int(
            connection.execute("SELECT count(*) FROM external_export_commits").fetchone()[0]
        )
    assert receipt_count == int(receipt_expected)

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()
    if receipt_expected:
        assert destination.read_bytes() == replacement_bytes
    elif preexisting_destination:
        assert destination.read_bytes() == previous_bytes
    else:
        assert not destination.exists()

    with closing(sqlite3.connect(reopened.db_path)) as connection:
        quick_check = tuple(str(row[0]) for row in connection.execute("PRAGMA quick_check"))
        foreign_key_check = tuple(connection.execute("PRAGMA foreign_key_check"))
        managed_exports = int(connection.execute("SELECT count(*) FROM exports").fetchone()[0])
        receipts = int(
            connection.execute("SELECT count(*) FROM external_export_commits").fetchone()[0]
        )
    assert quick_check == ("ok",)
    assert foreign_key_check == ()
    assert managed_exports == 0
    assert receipts == 0
    assert not tuple(destination.parent.glob(f".{destination.name}.*"))
    assert not tuple(reopened._manifests_root.iterdir())
    assert not tuple(reopened._leases_root.iterdir())
    assert not tuple(reopened._export_owners_root.iterdir())


@pytest.mark.parametrize("export_format", ("csv", "html"))
@pytest.mark.parametrize(
    "target_phase",
    (
        "PREPARED",
        "RENDERED",
        "INSTALLED",
        "DB_RECEIPT_COMMITTED",
        "DB_COMMITTED",
    ),
)
def test_missing_external_export_target_is_deferred_without_blocking_startup(
    tmp_path: Path,
    export_format: str,
    target_phase: str,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    suffix = ".csv" if export_format == "csv" else ".html"
    destination = tmp_path / "removable-drive" / f"report{suffix}"
    destination.parent.mkdir()
    previous_bytes = f"previous report {export_format}".encode()
    destination.write_bytes(previous_bytes)

    expected_path = tmp_path / "expected" / f"report{suffix}"
    if export_format == "csv":
        store.export_run_csv(run_id, expected_path)
    else:
        store.export_run_html(run_id, expected_path)
    replacement_bytes = expected_path.read_bytes()
    assert replacement_bytes != previous_bytes

    completed = _run_export_crash(
        store,
        run_id,
        destination,
        target_phase,
        export_format,
    )
    assert completed.returncode == 91, (completed.stdout, completed.stderr)

    detached = tmp_path / "detached-removable-drive"
    destination.parent.rename(detached)
    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert reopened.pending_external_recovery_count == 1
    assert reopened.list_runs()[0]["id"] == run_id
    assert tuple(reopened._manifests_root.glob("*.json"))
    detached.rename(destination.parent)

    assert reopened.retry_pending_external_recoveries() == 0
    expected_bytes = (
        replacement_bytes
        if target_phase in {"DB_RECEIPT_COMMITTED", "DB_COMMITTED"}
        else previous_bytes
    )
    assert destination.read_bytes() == expected_bytes
    assert not tuple(reopened._manifests_root.glob("*.json"))
    assert not tuple(reopened._export_owners_root.glob("*.json"))


@pytest.mark.parametrize(
    "winerror",
    (
        2,
        3,
        21,
        53,
        55,
        59,
        64,
        67,
        121,
        1201,
        1203,
        1222,
        1229,
        1231,
        1232,
        1233,
        1235,
        1236,
        1237,
        2250,
    ),
)
def test_external_recovery_target_unavailable_accepts_only_disconnect_winerrors(
    winerror: int,
) -> None:
    error = OSError("synthetic external target disconnect")
    error.winerror = winerror

    assert session_store_module._external_recovery_target_unavailable(error)


@pytest.mark.parametrize("winerror", (5, 65, 1219, 267))
def test_external_recovery_target_unavailable_rejects_security_and_config_winerrors(
    winerror: int,
) -> None:
    error = OSError("synthetic external target policy failure")
    error.winerror = winerror

    assert not session_store_module._external_recovery_target_unavailable(error)


def test_external_recovery_target_unavailable_rejects_non_directory_path() -> None:
    assert not session_store_module._external_recovery_target_unavailable(
        NotADirectoryError("synthetic external target parent is not a directory")
    )


@pytest.mark.parametrize("winerror", (59, 1222, 2250))
def test_disconnected_external_recovery_is_deferred_and_local_history_remains_available(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    winerror: int,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)
    operation_id = "a" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "external_export",
            "operation_id": operation_id,
        },
    )
    store.close()

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)

    def raise_disconnected_target(_path: Path, _payload: dict[str, object]) -> None:
        error = OSError("synthetic external target disconnect")
        error.winerror = winerror
        raise error

    monkeypatch.setattr(
        reopened,
        "_recover_external_export_manifest",
        raise_disconnected_target,
    )

    reopened.initialize()

    assert reopened.pending_external_recovery_count == 1
    assert reopened.list_runs()[0]["id"] == run_id
    assert manifest.exists()


@pytest.mark.parametrize("winerror", (5, 65, 1219, 267))
def test_external_recovery_security_and_config_errors_fail_startup_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    winerror: int,
) -> None:
    store = _store(tmp_path)
    operation_id = "b" * 32
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "external_export",
            "operation_id": operation_id,
        },
    )
    store.close()

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)

    def raise_policy_failure(_path: Path, _payload: dict[str, object]) -> None:
        error = OSError("synthetic external target policy failure")
        error.winerror = winerror
        raise error

    monkeypatch.setattr(
        reopened,
        "_recover_external_export_manifest",
        raise_policy_failure,
    )

    with pytest.raises(StorageError, match="데이터베이스를 초기화할 수 없습니다"):
        reopened.initialize()

    assert reopened.pending_external_recovery_count == 0
    assert manifest.exists()


def test_external_recovery_parent_replaced_by_regular_file_fails_startup_closed(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = tmp_path / "removable-drive" / "report.csv"

    completed = _run_export_crash(store, run_id, destination, "PREPARED")
    assert completed.returncode == 91, (completed.stdout, completed.stderr)
    manifest = next(store._manifests_root.glob("*.json"))
    owner = next(store._export_owners_root.glob("*.json"))

    detached_parent = tmp_path / "detached-removable-drive"
    destination.parent.rename(detached_parent)
    replacement_bytes = b"must-not-be-treated-as-a-detached-directory"
    destination.parent.write_bytes(replacement_bytes)

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="데이터베이스를 초기화할 수 없습니다"):
        reopened.initialize()

    assert reopened.pending_external_recovery_count == 0
    assert destination.parent.read_bytes() == replacement_bytes
    assert detached_parent.is_dir()
    assert manifest.exists()
    assert owner.exists()


def test_pending_external_recovery_does_not_hold_store_lock_against_poll_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store._pending_external_recoveries["a" * 32] = "FileNotFoundError"
    recovery_started = threading.Event()
    release_recovery = threading.Event()

    def slow_recovery() -> bool:
        recovery_started.set()
        if not release_recovery.wait(timeout=10):
            raise TimeoutError("external recovery synchronization timed out")
        return True

    monkeypatch.setattr(store, "_recover_operations", slow_recovery)
    results: list[int] = []
    errors: list[BaseException] = []

    def retry_recovery() -> None:
        try:
            results.append(store.retry_pending_external_recoveries())
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    recovery = threading.Thread(target=retry_recovery)
    recovery.start()
    assert recovery_started.wait(timeout=5)
    assert store.storage_health().raw_file_count == 0
    write_completed = threading.Event()

    def write_poll() -> None:
        store.record_query(run_id, [_observation()], raw_text="recovery-concurrency")
        write_completed.set()

    writer = threading.Thread(target=write_poll)
    writer.start()
    try:
        assert write_completed.wait(timeout=5)
    finally:
        release_recovery.set()
    writer.join(timeout=5)
    recovery.join(timeout=10)

    assert not writer.is_alive()
    assert not recovery.is_alive()
    assert errors == []
    assert results == [0]


def test_external_export_manifest_path_tamper_cannot_touch_unrelated_file(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = tmp_path / "chosen" / "report.csv"
    destination.parent.mkdir()
    original_bytes = b"original-external-export"
    destination.write_bytes(original_bytes)
    victim = tmp_path / "unrelated-user-file.txt"
    victim_bytes = b"must-never-be-replaced-or-deleted"
    victim.write_bytes(victim_bytes)

    completed = _run_export_crash(store, run_id, destination, "RENDERED")
    assert completed.returncode == 91, (completed.stdout, completed.stderr)
    manifest = next(store._manifests_root.glob("*.json"))
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["destination_path"] = str(victim)
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="소유권 증표"):
        reopened.initialize()

    assert victim.read_bytes() == victim_bytes
    assert destination.read_bytes() == original_bytes
    assert manifest.exists()


def test_external_export_recovery_requires_independent_owner_marker(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    destination = tmp_path / "chosen" / "report.html"
    destination.parent.mkdir()
    destination.write_bytes(b"previous-html")

    completed = _run_export_crash(store, run_id, destination, "INSTALLED", "html")
    assert completed.returncode == 91, (completed.stdout, completed.stderr)
    owner = next(store._export_owners_root.glob("*.json"))
    owner.unlink()
    installed_bytes = destination.read_bytes()

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    with pytest.raises(StorageError, match="소유권 증표가 없습니다"):
        reopened.initialize()

    assert destination.read_bytes() == installed_bytes
    assert next(store._manifests_root.glob("*.json")).exists()


@pytest.mark.parametrize(
    "protected_destination",
    ("database", "wal", "raw", "operations"),
)
def test_external_export_rejects_application_managed_destinations(
    tmp_path: Path,
    protected_destination: str,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()], raw_text="raw-evidence")
    store.finish_run(run_id)
    destinations = {
        "database": store.db_path,
        "wal": Path(f"{store.db_path}-wal"),
        "raw": store.raw_root / "user-report.csv",
        "operations": store._operations_root / "user-report.csv",
    }

    with pytest.raises(StorageError, match="관리 저장소"):
        store.export_run_csv(run_id, destinations[protected_destination])

    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert not tuple(store._manifests_root.glob("*.json"))
    assert not tuple(store._export_owners_root.glob("*.json"))


@pytest.mark.windows
@pytest.mark.parametrize("unsafe_name", ("report.csv:stream", "CON.csv", "report.csv."))
def test_external_export_rejects_windows_alias_and_device_names(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows path alias rules apply only on Windows")
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)

    with pytest.raises(StorageError, match="Windows"):
        store.export_run_csv(run_id, tmp_path / "chosen" / unsafe_name)

    assert not tuple(store._manifests_root.glob("*.json"))
    assert not tuple(store._export_owners_root.glob("*.json"))


def test_startup_recovers_prepared_export_and_partial_renderer_temp(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.finish_run(run_id)
    operation_id = "4" * 32
    destination = store.exports_root / f"run-{run_id}.csv"
    staged = destination.with_name(f".{destination.name}.{operation_id}.staged")
    backup = destination.with_name(f".{destination.name}.{operation_id}.backup")
    staged.write_bytes(b"rendered-but-not-recorded")
    temporary = staged.with_name(f".{staged.name}.partial.tmp")
    temporary.write_bytes(b"partial")
    manifest = store._write_manifest(
        operation_id,
        {
            "version": 1,
            "kind": "export",
            "phase": "PREPARED",
            "operation_id": operation_id,
            "run_id": run_id,
            "relative_path": destination.name,
            "staged_relative": staged.name,
            "backup_relative": backup.name,
        },
    )

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()

    assert not destination.exists()
    assert not staged.exists()
    assert not temporary.exists()
    assert not manifest.exists()
    with closing(sqlite3.connect(store.db_path)) as connection:
        assert connection.execute("SELECT count(*) FROM exports").fetchone()[0] == 0
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"


def test_startup_finishes_export_after_db_commit_phase_write_fault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    store.record_query(run_id, [_observation()])
    store.finish_run(run_id)
    original_replace = store._replace_manifest

    def fail_db_committed_phase(path: Path, payload: dict[str, object]) -> None:
        if payload.get("phase") == "DB_COMMITTED":
            raise OSError("forced phase write fault")
        original_replace(path, payload)

    monkeypatch.setattr(store, "_replace_manifest", fail_db_committed_phase)

    with pytest.raises(StorageError, match="복구 상태"):
        store.export_run_csv(run_id)

    manifests = tuple(store._manifests_root.glob("*.json"))
    assert len(manifests) == 1
    assert json.loads(manifests[0].read_text(encoding="utf-8"))["phase"] == "INSTALLED"

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()
    destination = store.exports_root / f"run-{run_id}.csv"

    assert destination.exists()
    assert not manifests[0].exists()
    assert not tuple(store.exports_root.glob("*.backup"))
    with closing(sqlite3.connect(store.db_path)) as connection:
        row = connection.execute(
            "SELECT sha256, byte_size FROM exports WHERE relative_path = ?",
            (destination.name,),
        ).fetchone()
        assert row == (
            hashlib.sha256(destination.read_bytes()).hexdigest(),
            destination.stat().st_size,
        )
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
