from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import aruba_session_tracker.storage.raw as raw_module
import aruba_session_tracker.storage.session_store as session_store_module
from aruba_session_tracker.models import (
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.services.tracker import QueryOutcome, RawSnapshot
from aruba_session_tracker.storage import (
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
    }.issubset(tables)
    assert version == 2
    assert "instance_id" in lifecycle_columns


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
    assert version == 2


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


def test_record_query_links_relative_raw_path_and_sha256(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)
    raw_text = "한글 Raw 출력\n"

    observation_ids = store.record_query(
        run_id,
        [_observation(controller_name="서울-MD")],
        raw_text=raw_text,
        controller_name="서울-MD",
    )

    assert len(observation_ids) == 1
    with closing(sqlite3.connect(store.db_path)) as connection, connection:
        relative_path, digest, size = connection.execute(
            "SELECT relative_path, sha256, byte_size FROM raw_files WHERE run_id = ?",
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
    assert "raw_line" not in stored_raw_line


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
        assert connection.execute("SELECT count(*) FROM raw_files").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM observations").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM diagnostic_events").fetchone()[0] == 0
    assert not tuple(store.raw_root.rglob("*.txt"))
    assert not tuple((tmp_path / ".operations" / "manifests").glob("*.json"))
    assert not tuple(store.raw_root.glob(".raw-staging-*"))


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
        relative_path = connection.execute(
            """
            SELECT rf.relative_path
            FROM observations AS observation
            JOIN raw_files AS rf ON rf.id = observation.raw_file_id
            WHERE observation.run_id = ?
            """,
            (run_id,),
        ).fetchone()[0]
        raw_file_count = connection.execute(
            "SELECT count(*) FROM raw_files WHERE run_id = ?", (run_id,)
        ).fetchone()[0]

    assert raw_file_count == 2
    assert (store.raw_root / relative_path).read_text(encoding="utf-8") == second_output


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
        store = SessionStore(tmp_path / "tracker.db", junction, tmp_path / "exports")
        with pytest.raises(StorageError, match="reparse point"):
            store.initialize()
        assert sentinel.read_text(encoding="utf-8") == "keep"
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
    ) -> Iterator[dict[str, object]]:
        seen_batch_sizes.append(batch_size)
        return original(cursor, batch_size=batch_size)

    monkeypatch.setattr(session_store_module, "_iter_cursor_dicts", observe_batches)
    exported = store.export_run_csv(run_id, tmp_path / "stream.csv")

    assert exported.exists()
    assert seen_batch_sizes == [1000]


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
    original_writer = session_store_module.write_html_report_atomic

    def write_then_delete(destination: Path, snapshot: RunReportSnapshot) -> Path:
        written = original_writer(destination, snapshot)
        deleter.delete(preview, confirmation_token=preview.confirmation_token)
        return written

    monkeypatch.setattr(session_store_module, "write_html_report_atomic", write_then_delete)
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
        relative_paths: tuple[str, ...],
        preview_id: str,
        category: str,
        staged: list[session_store_module._StagedFile],
    ) -> None:
        nonlocal first_stage
        if first_stage:
            first_stage = False
            delete_locked.set()
            if not continue_delete.wait(timeout=10):
                raise TimeoutError("delete test synchronization timed out")
        original_stage_files(root, relative_paths, preview_id, category, staged)

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
    while not tuple(exporter.exports_root.glob("*.staged")) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert tuple(exporter.exports_root.glob("*.staged"))
    continue_delete.set()
    delete_thread.join(timeout=10)
    export_thread.join(timeout=10)

    assert not delete_thread.is_alive()
    assert not export_thread.is_alive()
    assert not deletion_errors
    assert len(deletion_results) == 1
    assert len(export_errors) == 1
    assert isinstance(export_errors[0], StorageError)
    assert "조회 실행 기록이 없습니다" in str(export_errors[0])
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
    assert latest_body.count("<tbody><tr>") == 1
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


def test_html_export_contains_every_stored_row_without_ui_or_legacy_limits(
    tmp_path: Path,
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
    destination = store.export_run_html(run_id, tmp_path / "all-stored-data.html")
    document = destination.read_text(encoding="utf-8")
    history_section = re.search(
        r'<section id="observation-history">(?P<body>.*?)</section>',
        document,
        flags=re.DOTALL,
    )
    assert history_section is not None
    history_body = history_section.group("body")
    history_table_body = re.search(r"<tbody>(?P<body>.*?)</tbody>", history_body, re.DOTALL)
    assert history_table_body is not None

    assert history_table_body.group("body").count("<tr>") == 2_005
    assert "OLDEST-OBSERVATION-CONTROLLER" in history_body
    assert "OLDEST-LIFECYCLE-INSTANCE" not in document
    assert "OLDEST-CONTROLLER-REASON" not in document
    assert "OLDEST-DIAGNOSTIC-MESSAGE" not in document
    assert "oldest-raw-kind" not in document
    assert "capture-0000.txt" not in document
    assert "private-raw-body-0" not in document
    assert "<summary>전체 추적 이력 2,005건 보기</summary>" in document
    assert "세션별 수치 변화" not in document
    assert "패킷" not in document
    assert "바이트" not in document


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
    assert len(store.list_runs()) == 1
    assert store.list_runs()[0]["status"] == "COMPLETED"


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
