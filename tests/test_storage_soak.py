from __future__ import annotations

import gc
import json
import os
import sqlite3
import subprocess
import sys
import tracemalloc
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from aruba_session_tracker.models import QueryRequest
from aruba_session_tracker.storage import SessionStore, StorageError


@pytest.mark.soak
@pytest.mark.windows
def test_storage_poll_soak(tmp_path: Path) -> None:
    """Exercise durable local persistence only; this never opens a network connection."""

    if os.name != "nt":
        pytest.skip("Windows process resource counters are required for this soak")
    polls = int(os.environ.get("ARUBA_SOAK_POLLS", "2000"))
    if not 1 <= polls <= 100_000:
        raise ValueError("ARUBA_SOAK_POLLS must be between 1 and 100000")

    repository = Path(__file__).resolve().parents[1]
    worker = Path(__file__).with_name("storage_soak_worker.py")
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(repository / "src") + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, str(worker), str(tmp_path), str(polls)],
        cwd=repository,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=max(120, polls // 10),
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    output_lines = tuple(line for line in completed.stdout.splitlines() if line.strip())
    assert output_lines, completed.stderr[-4000:]
    result = json.loads(output_lines[-1])

    reopened = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    reopened.initialize()
    raw_files = tuple(reopened.raw_root.rglob("*.txt"))
    health = reopened.storage_health()
    with closing(sqlite3.connect(reopened.db_path)) as connection:
        counts = {
            "runs": int(connection.execute("SELECT count(*) FROM runs").fetchone()[0]),
            "observations": int(
                connection.execute("SELECT count(*) FROM observations").fetchone()[0]
            ),
            "raw_files": int(connection.execute("SELECT count(*) FROM raw_files").fetchone()[0]),
            "diagnostic_events": int(
                connection.execute("SELECT count(*) FROM diagnostic_events").fetchone()[0]
            ),
        }
        quick_check = tuple(str(row[0]) for row in connection.execute("PRAGMA quick_check"))
        foreign_key_check = tuple(connection.execute("PRAGMA foreign_key_check"))

    baseline = result["baseline"]
    final = result["final"]
    handle_delta = int(final["handles"]) - int(baseline["handles"])
    thread_delta = int(final["threads"]) - int(baseline["threads"])
    memory_delta = max(
        0,
        int(final["working_set_bytes"]) - int(baseline["working_set_bytes"]),
    )
    memory_limit = min(128 * 1024**2, int(int(baseline["working_set_bytes"]) * 0.20))

    assert counts == {
        "runs": 1,
        "observations": polls,
        "raw_files": polls,
        "diagnostic_events": int(result["expected_diagnostics"]),
    }
    assert len(raw_files) == polls
    assert all(len(path.relative_to(reopened.raw_root).parts) == 4 for path in raw_files)
    assert health.raw_file_count == polls
    assert health.raw_bytes == int(result["expected_raw_bytes"])
    assert health.export_file_count == 0
    assert quick_check == ("ok",)
    assert foreign_key_check == ()
    assert not tuple(reopened._manifests_root.iterdir())
    assert not tuple(reopened._leases_root.iterdir())
    assert handle_delta <= 5, (baseline, final)
    assert thread_delta <= 1, (baseline, final)
    assert memory_delta <= memory_limit, (baseline, final, memory_limit)


@pytest.mark.soak
def test_delete_preview_lifecycle_soak_releases_pending_and_traced_memory(
    tmp_path: Path,
) -> None:
    """Repeat every preview terminal path without retaining pending snapshots."""

    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    retained_run_id = store.start_run(QueryRequest("192.0.2.10", "203.0.113.10"))
    store.finish_run(retained_run_id)
    route_counts = {"cancel": 0, "expiry": 0, "error": 0, "success": 0}
    baseline_current: int | None = None

    tracemalloc.start(5)
    try:
        for iteration in range(1_000):
            route = ("cancel", "expiry", "error", "success")[iteration % 4]
            if route == "success":
                run_id = store.start_run(
                    QueryRequest(
                        f"192.0.2.{iteration % 250 + 1}",
                        f"203.0.113.{iteration % 250 + 1}",
                    ),
                    run_id=f"preview-soak-{iteration:04d}",
                )
                store.finish_run(run_id)
                preview = store.preview_delete(run_id)
                result = store.delete(
                    preview,
                    confirmation_token=preview.confirmation_token,
                )
                assert result.deleted_runs == 1
            else:
                preview = store.preview_delete(retained_run_id)
                if route == "cancel":
                    assert store.discard_delete_preview(preview) is True
                elif route == "expiry":
                    pending = store._pending_deletions[preview.preview_id]
                    store._pending_deletions[preview.preview_id] = replace(
                        pending,
                        expires_monotonic=-1.0,
                    )
                    assert store.discard_delete_preview(preview) is False
                else:
                    invalid_confirmation = preview.confirmation_token + "-invalid"
                    with pytest.raises(StorageError, match="토큰"):
                        store.delete(preview, confirmation_token=invalid_confirmation)
                    assert store.discard_delete_preview(preview) is True

            route_counts[route] += 1
            assert len(store._pending_deletions) == 0
            if iteration == 99:
                gc.collect()
                baseline_current = tracemalloc.get_traced_memory()[0]

        gc.collect()
        final_current = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()

    assert baseline_current is not None
    assert route_counts == {"cancel": 250, "expiry": 250, "error": 250, "success": 250}
    assert len(store._pending_deletions) == 0
    assert len(store.list_runs()) == 1
    assert not tuple(store._manifests_root.iterdir())
    assert not tuple(store._leases_root.iterdir())
    assert final_current <= baseline_current + 512 * 1024
