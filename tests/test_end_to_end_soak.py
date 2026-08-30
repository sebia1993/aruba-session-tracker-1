from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.soak
@pytest.mark.windows
def test_fixture_ssh_parser_runtime_storage_soak(tmp_path: Path) -> None:
    """Exercise the full local collection pipeline without contacting a device."""

    if os.name != "nt":
        pytest.skip("Windows process resource counters are required for this soak")
    polls = int(os.environ.get("ARUBA_SOAK_POLLS", "2000"))
    if not 1 <= polls <= 50_000:
        raise ValueError("ARUBA_SOAK_POLLS must be between 1 and 50000")

    repository = Path(__file__).resolve().parents[1]
    worker = Path(__file__).with_name("end_to_end_soak_worker.py")
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
        timeout=max(300, polls // 4),
    )
    assert completed.returncode == 0, completed.stderr[-6000:]
    lines = tuple(line for line in completed.stdout.splitlines() if line.strip())
    assert lines, completed.stderr[-6000:]
    result = json.loads(lines[-1])

    baseline = result["baseline"]
    final = result["final"]
    handle_delta = int(final["handles"]) - int(baseline["handles"])
    thread_delta = int(final["threads"]) - int(baseline["threads"])
    memory_delta = max(
        0,
        int(final["working_set_bytes"]) - int(baseline["working_set_bytes"]),
    )
    memory_limit = min(128 * 1024**2, int(int(baseline["working_set_bytes"]) * 0.20))

    assert result["counts"] == {
        "runs": 1,
        "observations": polls * 2,
        "raw_files": polls,
        "lifecycle_events": 2,
    }
    assert result["connections"] >= polls + 1
    assert result["raw_files_on_disk"] == polls
    assert result["quick_check"] == ["ok"]
    assert result["foreign_key_check"] == []
    assert result["pending_manifests"] == 0
    assert result["pending_leases"] == 0
    assert handle_delta <= 5, (baseline, final)
    assert thread_delta <= 1, (baseline, final)
    assert memory_delta <= memory_limit, (baseline, final, memory_limit)
