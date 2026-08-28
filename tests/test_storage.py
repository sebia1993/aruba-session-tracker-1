from __future__ import annotations

import csv
import hashlib
import sqlite3
import threading
import time
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

import pytest

import aruba_session_tracker.storage.raw as raw_module
import aruba_session_tracker.storage.session_store as session_store_module
from aruba_session_tracker.models import (
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.storage import (
    RunReportSnapshot,
    SessionStore,
    StorageError,
    guard_csv_cell,
)


def _store(tmp_path: Path) -> SessionStore:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    return store


def _observation(*, controller_name: str = "MD-01", packets: int = 12) -> SessionObservation:
    return SessionObservation(
        controller_name=controller_name,
        controller_host="198.51.100.21",
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
        bytes_count=2048,
        flags="FC",
        cpu_id=1,
        raw_line="sensitive raw line",
        observed_at=datetime(2026, 8, 28, 8, 0, tzinfo=UTC),
    )


def _run(store: SessionStore) -> str:
    return store.start_run(QueryRequest("192.0.2.100", "203.0.113.80", 53000, 443))


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


def test_initialize_interrupts_stale_run_once_per_store_instance(tmp_path: Path) -> None:
    store = _store(tmp_path)
    run_id = _run(store)

    store.initialize()
    assert store.list_runs()[0]["status"] == "RUNNING"

    reopened = SessionStore(store.db_path, store.raw_root, store.exports_root)
    reopened.initialize()
    row = reopened.list_runs()[0]
    assert row["id"] == run_id
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


def test_html_export_includes_run_events_diagnostics_and_raw_metadata_only(
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

    assert run_id in document
    assert "PARTIAL" in document
    assert "서울-MD-01" in document
    assert "instance-report-001" in document
    assert "OPENED" in document
    assert "MISS 횟수: 0" in document
    assert "이전 Flags: F" in document
    assert "서울-MD-02" in document
    assert "CURRENT_SWITCH_CHANGED" in document
    assert "AUTH_FAILED" in document
    assert "username=&lt;REDACTED&gt;" in document
    assert "password=&lt;REDACTED&gt;" in document
    assert "198.51.100.99" not in document
    assert "서울-MM-01" in document
    assert "mm-location" in document
    assert "DB ID" in document
    assert raw_digest in document
    assert "PRIVATE-RAW-BODY" not in document
    assert "raw-user" not in document
    assert "raw-secret" not in document
    assert raw_relative not in document


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
