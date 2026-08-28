from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
from threading import Event, Thread
from types import TracebackType
from typing import Self

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

FIXTURES = Path(__file__).parent / "fixtures"


class _Connection(AbstractContextManager[CommandConnection]):
    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def send_command(self, command: str, *, read_timeout: float) -> str:
        del read_timeout
        return self._responses[command]

    def close(self) -> None:
        return None


class _Factory:
    def __init__(self) -> None:
        self._source = (FIXTURES / "global_user_one.txt").read_text(encoding="utf-8")
        self._empty = (FIXTURES / "global_user_empty.txt").read_text(encoding="utf-8")
        self._sessions = (FIXTURES / "datapath_sessions.txt").read_text(encoding="utf-8")

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: object,
        cancel_token: CancellationToken,
    ) -> AbstractContextManager[CommandConnection]:
        del credentials, host_key_approval
        cancel_token.raise_if_cancelled()
        if target.host == "192.0.2.1":
            responses = {
                NO_PAGING_COMMAND: "",
                build_global_user_command("192.0.2.10"): self._source,
                build_global_user_command("203.0.113.20"): self._empty,
            }
        else:
            responses = {
                NO_PAGING_COMMAND: "",
                build_datapath_session_command("192.0.2.10"): self._sessions,
            }
        return _Connection(responses)


class _BlockingConnection(_Connection):
    def __init__(self, responses: dict[str, str], started: Event, release: Event) -> None:
        super().__init__(responses)
        self._started = started
        self._release = release
        self._blocked_once = False

    def send_command(self, command: str, *, read_timeout: float) -> str:
        if not self._blocked_once:
            self._blocked_once = True
            self._started.set()
            if not self._release.wait(timeout=5):
                raise TimeoutError("test did not release the blocking SSH fake")
        return super().send_command(command, read_timeout=read_timeout)


class _BlockingFactory(_Factory):
    def __init__(self, started: Event, release: Event) -> None:
        super().__init__()
        self._started = started
        self._release = release
        self._used_block = False

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: object,
        cancel_token: CancellationToken,
    ) -> AbstractContextManager[CommandConnection]:
        connection = super().connect(
            target,
            credentials,
            host_key_approval=host_key_approval,
            cancel_token=cancel_token,
        )
        if self._used_block:
            return connection
        self._used_block = True
        assert isinstance(connection, _Connection)
        return _BlockingConnection(connection._responses, self._started, self._release)


def _config() -> AppConfig:
    return AppConfig(
        mm_primary=DeviceTarget("MM-1", "192.0.2.1"),
        mm_standby=DeviceTarget("MM-2", "192.0.2.2"),
        managed_devices=(DeviceTarget("MD-1", "198.51.100.11"),),
    )


def _paths(tmp_path: Path) -> AppPaths:
    root = tmp_path / "app"
    return AppPaths(
        root=root,
        config=root / "config.json",
        known_hosts=root / "known_hosts",
        database=root / "tracker.db",
        raw=root / "raw",
        exports=root / "exports",
    )


def test_runtime_query_persists_observations_raw_and_diagnostics(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)

    outcome = executor.execute(
        _config(),
        request,
        Credentials("operator", "session-only"),
        monitoring=False,
        cancel_token=CancellationToken(),
        host_key_approval=lambda _target, _info: True,
        full_scan_approval=lambda _request, _devices: False,
    )

    assert outcome.authoritative is True
    assert len(outcome.observations) == 2
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "COMPLETED"
    assert runs[0]["observation_count"] == 2
    assert len(tuple(paths.raw.rglob("*.txt"))) == 3
    exported = store.export_run_csv(str(runs[0]["id"]))
    assert exported.read_bytes().startswith(b"\xef\xbb\xbf")


def test_runtime_monitor_reuses_one_run_and_finishes_on_stop(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")

    for _ in range(2):
        executor.execute(
            _config(),
            request,
            credentials,
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )
    executor.stop_monitor()

    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "STOPPED"
    assert runs[0]["observation_count"] == 4


def test_runtime_stop_waits_for_inflight_poll_persistence(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    started = Event()
    release = Event()
    executor = RuntimeExecutor(paths, store, ssh_factory=_BlockingFactory(started, release))
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    failures: list[BaseException] = []

    def poll() -> None:
        try:
            executor.execute(
                _config(),
                request,
                Credentials("operator", "session-only"),
                monitoring=True,
                cancel_token=CancellationToken(),
                host_key_approval=lambda _target, _info: True,
                full_scan_approval=lambda _request, _devices: False,
            )
        except BaseException as error:  # pragma: no cover - asserted below
            failures.append(error)

    worker = Thread(target=poll)
    worker.start()
    assert started.wait(timeout=5)

    executor.stop_monitor()
    assert store.list_runs()[0]["status"] == "RUNNING"
    release.set()
    worker.join(timeout=10)

    assert not worker.is_alive()
    assert failures == []
    run = store.list_runs()[0]
    assert run["status"] == "STOPPED"
    assert run["observation_count"] == 2
