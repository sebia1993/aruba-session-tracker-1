from __future__ import annotations

import gc
import json
import os
import sqlite3
import sys
from contextlib import AbstractContextManager, closing
from dataclasses import asdict
from pathlib import Path
from types import TracebackType
from typing import Self

from storage_soak_worker import windows_process_usage

from aruba_session_tracker.collectors import CancellationToken, CommandConnection
from aruba_session_tracker.commands import (
    NO_PAGING_COMMAND,
    build_datapath_session_command,
    build_global_user_command,
)
from aruba_session_tracker.models import AppConfig, Credentials, DeviceTarget, QueryRequest
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.runtime import RuntimeExecutor
from aruba_session_tracker.storage import SessionStore

FIXTURES = Path(__file__).with_name("fixtures")
SECRET_CANARY = "END_TO_END_SOAK_PASSWORD_CANARY"  # noqa: S105 - deliberate fixture canary


class _FixtureConnection(AbstractContextManager[CommandConnection]):
    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc_value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        self.close()

    def send_command(self, command: str, *, read_timeout: float) -> str:
        if read_timeout <= 0:
            raise AssertionError("collector supplied a non-positive read timeout")
        return self._responses[command]

    def close(self) -> None:
        return None


class _FixtureFactory:
    def __init__(self) -> None:
        self.source = (FIXTURES / "global_user_one.txt").read_text(encoding="utf-8")
        self.empty = (FIXTURES / "global_user_empty.txt").read_text(encoding="utf-8")
        self.sessions = (FIXTURES / "datapath_sessions.txt").read_text(encoding="utf-8")
        self.connections = 0

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: object,
        cancel_token: CancellationToken,
        deadline: object,
    ) -> AbstractContextManager[CommandConnection]:
        del host_key_approval, deadline
        cancel_token.raise_if_cancelled()
        if credentials.password != SECRET_CANARY:
            raise AssertionError("unexpected fixture credential")
        self.connections += 1
        if target.host == "192.0.2.1":
            responses = {
                NO_PAGING_COMMAND: "",
                build_global_user_command("192.0.2.10"): self.source,
                build_global_user_command("203.0.113.20"): self.empty,
            }
        elif target.host == "198.51.100.11":
            responses = {
                NO_PAGING_COMMAND: "",
                build_datapath_session_command("192.0.2.10"): self.sessions,
            }
        else:
            raise AssertionError(f"unexpected fixture target: {target.name}")
        return _FixtureConnection(responses)


def run_end_to_end_soak(root: Path, polls: int) -> dict[str, object]:
    app_root = root / "app"
    paths = AppPaths(
        root=app_root,
        config=app_root / "config.json",
        known_hosts=app_root / "known_hosts",
        database=app_root / "tracker.db",
        raw=app_root / "raw",
        exports=app_root / "exports",
    )
    paths.ensure()
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _FixtureFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)  # type: ignore[arg-type]
    config = AppConfig(
        mm_primary=DeviceTarget("MM-Primary", "192.0.2.1"),
        mm_standby=DeviceTarget("MM-Standby", "192.0.2.2", enabled=False),
        managed_devices=(DeviceTarget("MD-Document-01", "198.51.100.11"),),
        location_interval_seconds=30,
    )
    request = QueryRequest("192.0.2.10", "203.0.113.20")
    credentials = Credentials("fixture-user", SECRET_CANARY)
    warmup_polls = min(100, polls)
    baseline = None

    for index in range(polls):
        result = executor.execute(
            config,
            request,
            credentials,
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda *_args: True,
            full_scan_approval=lambda *_args: False,
        )
        if len(result.observations) != 2:
            raise AssertionError(f"unexpected observation count at poll {index}")
        if index + 1 == warmup_polls:
            gc.collect()
            baseline = windows_process_usage()

    executor.stop_monitor()
    gc.collect()
    final = windows_process_usage()
    if baseline is None:
        raise AssertionError("resource baseline was not captured")

    with closing(sqlite3.connect(paths.database)) as connection:
        counts = {
            "runs": int(connection.execute("SELECT count(*) FROM runs").fetchone()[0]),
            "observations": int(
                connection.execute("SELECT count(*) FROM observations").fetchone()[0]
            ),
            "raw_files": int(connection.execute("SELECT count(*) FROM raw_files").fetchone()[0]),
            "poll_commits": int(
                connection.execute("SELECT count(*) FROM poll_commits").fetchone()[0]
            ),
            "lifecycle_events": int(
                connection.execute("SELECT count(*) FROM lifecycle_events").fetchone()[0]
            ),
        }
        quick_check = tuple(str(row[0]) for row in connection.execute("PRAGMA quick_check"))
        foreign_key_check = tuple(connection.execute("PRAGMA foreign_key_check"))

    for path in app_root.rglob("*"):
        if path.is_file() and SECRET_CANARY.encode("utf-8") in path.read_bytes():
            raise AssertionError(f"credential canary persisted in {path.name}")

    return {
        "baseline": asdict(baseline),
        "final": asdict(final),
        "connections": factory.connections,
        "counts": counts,
        "quick_check": quick_check,
        "foreign_key_check": foreign_key_check,
        "raw_files_on_disk": len(tuple(paths.raw.rglob("*.txt"))),
        "pending_manifests": len(tuple(store._manifests_root.iterdir())),
        "pending_leases": len(tuple(store._leases_root.iterdir())),
    }


if __name__ == "__main__":
    if os.name != "nt" or len(sys.argv) != 3:
        raise SystemExit(2)
    result = run_end_to_end_soak(Path(sys.argv[1]), int(sys.argv[2]))
    print(json.dumps(result, sort_keys=True))
