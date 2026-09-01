from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import AbstractContextManager, closing, suppress
from pathlib import Path
from threading import Barrier, BrokenBarrierError, Event, Lock, Thread
from types import TracebackType
from typing import Self

import pytest

from aruba_session_tracker.collectors import CancellationToken, CommandConnection
from aruba_session_tracker.commands import (
    NO_PAGING_COMMAND,
    build_datapath_session_command,
    build_global_user_command,
)
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.runtime import RuntimeExecutor, _one_shot_status
from aruba_session_tracker.services import MonitorPollResult, QueryOutcome
from aruba_session_tracker.storage import (
    PollPersistenceIndeterminate,
    PollPersistenceResult,
    PollPersistenceStatus,
    SessionStore,
    StorageError,
)

FIXTURES = Path(__file__).parent / "fixtures"


class _Connection(AbstractContextManager[CommandConnection]):
    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses
        self.closed = False

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
        self.closed = True


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
        deadline: object,
    ) -> AbstractContextManager[CommandConnection]:
        del credentials, host_key_approval, deadline
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


class _RecordingFactory(_Factory):
    def __init__(self) -> None:
        super().__init__()
        self.targets: list[str] = []
        self.passwords: list[str] = []
        self.connections: list[_Connection] = []

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: object,
        cancel_token: CancellationToken,
        deadline: object,
    ) -> AbstractContextManager[CommandConnection]:
        self.targets.append(target.name)
        self.passwords.append(credentials.password)
        connection = super().connect(
            target,
            credentials,
            host_key_approval=host_key_approval,
            cancel_token=cancel_token,
            deadline=deadline,
        )
        assert isinstance(connection, _Connection)
        self.connections.append(connection)
        return connection


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
        self.cancel_tokens: list[CancellationToken] = []

    def connect(
        self,
        target: DeviceTarget,
        credentials: Credentials,
        *,
        host_key_approval: object,
        cancel_token: CancellationToken,
        deadline: object,
    ) -> AbstractContextManager[CommandConnection]:
        self.cancel_tokens.append(cancel_token)
        connection = super().connect(
            target,
            credentials,
            host_key_approval=host_key_approval,
            cancel_token=cancel_token,
            deadline=deadline,
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
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
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
    assert factory.targets == ["MM-1", "MD-1"]
    assert all(connection.closed for connection in factory.connections)
    assert executor.last_persistence_status is PollPersistenceStatus.COMMITTED
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "COMPLETED"
    assert runs[0]["observation_count"] == 2
    raw_paths = tuple(paths.raw.rglob("*.txt"))
    assert len(raw_paths) == 1
    with closing(sqlite3.connect(paths.database)) as connection:
        raw_row = connection.execute(
            "SELECT kind, controller_name, sha256, byte_size FROM raw_files"
        ).fetchone()
    bundle = raw_paths[0].read_bytes()
    assert raw_row == (
        "poll-bundle",
        "POLL_BUNDLE",
        hashlib.sha256(bundle).hexdigest(),
        len(bundle),
    )
    lines = bundle.splitlines()
    assert lines[0] == b"ARUBA_SESSION_TRACKER_RAW_BUNDLE_V1"
    assert json.loads(lines[1]) == {"snapshot_count": 3}
    metadata_rows = [json.loads(line) for line in lines if line.startswith(b'{"command"')]
    assert len(metadata_rows) == 3
    assert [row["index"] for row in metadata_rows] == [1, 2, 3]
    assert all(len(row["output_sha256"]) == 64 for row in metadata_rows)
    assert all(row["output_utf8_bytes"] > 0 for row in metadata_rows)
    exported = store.export_run_csv(str(runs[0]["id"]))
    assert exported.read_bytes().startswith(b"\xef\xbb\xbf")


def test_runtime_one_shot_retries_indeterminate_commit_with_same_poll_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_batch = store.record_poll_batch
    poll_ids: list[str] = []

    def lose_first_commit_ack(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            raise PollPersistenceIndeterminate(
                "fixture commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", lose_first_commit_ack)
    execute_kwargs = {
        "monitoring": False,
        "cancel_token": CancellationToken(),
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    with pytest.raises(PollPersistenceIndeterminate):
        executor.execute(
            _config(),
            request,
            credentials,
            **execute_kwargs,  # type: ignore[arg-type]
        )
    target_count = len(factory.targets)
    assert store.list_runs()[0]["status"] == "RUNNING"

    outcome = executor.execute(
        _config(),
        request,
        credentials,
        **execute_kwargs,  # type: ignore[arg-type]
    )

    assert isinstance(outcome, QueryOutcome)
    assert poll_ids[0] == poll_ids[1]
    assert len(poll_ids[0]) == 32
    assert factory.targets == factory.targets[:target_count]
    assert executor.last_persistence_status is PollPersistenceStatus.ALREADY_COMMITTED
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "COMPLETED"
    assert runs[0]["observation_count"] == 2


def test_runtime_one_shot_preserves_indeterminate_poll_after_retry_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_batch = store.record_poll_batch
    poll_ids: list[str] = []

    def fail_between_receipt_checks(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        if len(poll_ids) == 2:
            raise StorageError("fixture transient receipt check failure")
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            raise PollPersistenceIndeterminate(
                "fixture commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", fail_between_receipt_checks)
    execute_kwargs = {
        "monitoring": False,
        "cancel_token": CancellationToken(),
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    with pytest.raises(PollPersistenceIndeterminate):
        executor.execute(
            _config(),
            request,
            credentials,
            **execute_kwargs,  # type: ignore[arg-type]
        )
    target_count = len(factory.targets)
    with pytest.raises(StorageError, match="transient receipt"):
        executor.execute(
            _config(),
            request,
            credentials,
            **execute_kwargs,  # type: ignore[arg-type]
        )

    assert executor._pending_one_shot_persistence is not None
    assert store.list_runs()[0]["status"] == "RUNNING"
    assert len(factory.targets) == target_count

    outcome = executor.execute(
        _config(),
        request,
        credentials,
        **execute_kwargs,  # type: ignore[arg-type]
    )

    assert isinstance(outcome, QueryOutcome)
    assert poll_ids == [poll_ids[0]] * 3
    assert executor._pending_one_shot_persistence is None
    assert len(factory.targets) == target_count
    run = store.list_runs()[0]
    assert run["status"] == "COMPLETED"
    assert run["observation_count"] == 2


def test_runtime_one_shot_cancellation_is_persisted_as_cancelled(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    cancel_token = CancellationToken()
    cancel_token.cancel()

    outcome = executor.execute(
        _config(),
        QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443),
        Credentials("operator", "session-only"),
        monitoring=False,
        cancel_token=cancel_token,
        host_key_approval=lambda _target, _info: True,
        full_scan_approval=lambda _request, _devices: False,
    )

    assert outcome.cancelled is True
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "CANCELLED"
    assert len(outcome.diagnostics) == 1


def test_one_shot_status_is_completed_for_authoritative_empty_result() -> None:
    assert _one_shot_status(QueryOutcome(authoritative=True)) == "COMPLETED"


def test_one_shot_status_is_partial_only_when_positive_evidence_remains() -> None:
    observation = SessionObservation(
        controller_name="MD-1",
        controller_host="198.51.100.11",
        protocol=6,
        source_ip="192.0.2.10",
        destination_ip="203.0.113.20",
        source_port=54321,
        destination_port=443,
    )
    outcome = QueryOutcome(
        observations=(observation,),
        diagnostics=(DiagnosticEvent("MD_QUERY", ErrorCode.MD_UNREACHABLE, "sanitized"),),
        authoritative=False,
    )

    assert _one_shot_status(outcome) == "PARTIAL"


@pytest.mark.parametrize(
    "code",
    [
        ErrorCode.PARSE_PARTIAL,
        ErrorCode.COMMAND_REJECTED,
        ErrorCode.OUTPUT_LIMIT_EXCEEDED,
        ErrorCode.MD_UNREACHABLE,
    ],
)
def test_one_shot_status_is_failed_for_zero_observation_technical_failure(
    code: ErrorCode,
) -> None:
    outcome = QueryOutcome(
        diagnostics=(DiagnosticEvent("QUERY", code, "sanitized"),),
        authoritative=False,
    )

    assert _one_shot_status(outcome) == "FAILED"


def test_runtime_retries_one_shot_finalization_before_the_next_query(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_finish = store.finish_run
    finish_attempts = 0

    def fail_first_finish(run_id: str, status: str = "COMPLETED") -> None:
        nonlocal finish_attempts
        finish_attempts += 1
        if finish_attempts == 1:
            raise OSError("fixture one-shot finalize failure")
        original_finish(run_id, status=status)

    monkeypatch.setattr(store, "finish_run", fail_first_finish)
    with pytest.raises(RuntimeError, match="종료 상태"):
        executor.execute(
            _config(),
            request,
            credentials,
            monitoring=False,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

    assert executor.last_shutdown_error == "OSError"
    assert store.list_runs()[0]["status"] == "RUNNING"

    executor.execute(
        _config(),
        request,
        credentials,
        monitoring=False,
        cancel_token=CancellationToken(),
        host_key_approval=lambda _target, _info: True,
        full_scan_approval=lambda _request, _devices: False,
    )

    assert finish_attempts == 3
    assert executor.last_shutdown_error is None
    assert [run["status"] for run in store.list_runs()] == ["COMPLETED", "COMPLETED"]


def test_runtime_serializes_concurrent_pending_finish_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    run_id = store.start_run(QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443))
    executor._pending_finishes[run_id] = "STOPPED"
    original_finish = store.finish_run
    finish_rendezvous = Barrier(2)
    first_finish_entered = Event()
    attempt_lock = Lock()
    attempts = 0

    def synchronized_finish(candidate: str, status: str = "COMPLETED") -> None:
        nonlocal attempts
        with attempt_lock:
            attempts += 1
            attempt = attempts
        if attempt == 1:
            first_finish_entered.set()
        with suppress(BrokenBarrierError):
            # Without RuntimeExecutor's retry lock both callers arrive here,
            # then one succeeds and the other re-queues an already-finished run.
            finish_rendezvous.wait(timeout=2)
        original_finish(candidate, status=status)

    monkeypatch.setattr(store, "finish_run", synchronized_finish)
    failures: list[BaseException] = []
    failure_lock = Lock()

    def retry_pending_finish() -> None:
        try:
            executor._retry_pending_finishes(required=True)
        except BaseException as error:  # pragma: no cover - asserted below
            with failure_lock:
                failures.append(error)

    first = Thread(target=retry_pending_finish)
    second = Thread(target=retry_pending_finish)
    first.start()
    assert first_finish_entered.wait(timeout=5)
    second.start()
    first.join(timeout=10)
    second.join(timeout=10)

    assert not first.is_alive()
    assert not second.is_alive()
    assert failures == []
    assert attempts == 1
    assert executor._pending_finishes == {}
    assert store.list_runs()[0]["status"] == "STOPPED"


def test_runtime_monitor_reuses_one_run_and_finishes_on_stop(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
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

    assert factory.targets == ["MM-1", "MD-1"]
    assert all(connection.closed for connection in factory.connections)
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "STOPPED"
    assert runs[0]["observation_count"] == 4
    assert runs[0]["lifecycle_count"] == 2


def test_runtime_commits_monitor_state_when_cleanup_recovery_is_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_batch = store.record_poll_batch

    def report_pending_cleanup(*args: object, **kwargs: object) -> PollPersistenceResult:
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        return PollPersistenceResult(
            poll_id=result.poll_id,
            status=PollPersistenceStatus.COMMITTED_RECOVERY_PENDING,
            cleanup_error_type="OSError",
        )

    monkeypatch.setattr(store, "record_poll_batch", report_pending_cleanup)
    common = {
        "monitoring": True,
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    first = executor.execute(
        _config(),
        request,
        credentials,
        cancel_token=CancellationToken(),
        **common,  # type: ignore[arg-type]
    )
    second = executor.execute(
        _config(),
        request,
        credentials,
        cancel_token=CancellationToken(),
        **common,  # type: ignore[arg-type]
    )
    executor.stop_monitor()

    assert isinstance(first, MonitorPollResult)
    assert isinstance(second, MonitorPollResult)
    assert first.events
    assert all(event.event_type.value == "STARTED" for event in first.events)
    assert second.events == ()
    assert executor.last_persistence_status is PollPersistenceStatus.COMMITTED_RECOVERY_PENDING
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "STOPPED"
    assert runs[0]["observation_count"] == 4


def test_runtime_retries_indeterminate_monitor_commit_without_discarding_prepared_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_batch = store.record_poll_batch
    poll_ids: list[str] = []

    def lose_first_commit_ack(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            raise PollPersistenceIndeterminate(
                "fixture monitor commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", lose_first_commit_ack)
    common = {
        "monitoring": True,
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    with pytest.raises(PollPersistenceIndeterminate):
        executor.execute(
            _config(),
            request,
            credentials,
            cancel_token=CancellationToken(),
            **common,  # type: ignore[arg-type]
        )
    assert store.list_runs()[0]["status"] == "RUNNING"

    recovered = executor.execute(
        _config(),
        request,
        credentials,
        cancel_token=CancellationToken(),
        **common,  # type: ignore[arg-type]
    )

    assert poll_ids[0] == poll_ids[1]
    assert len(poll_ids[0]) == 32
    assert recovered.events
    assert all(event.event_type.value == "STARTED" for event in recovered.events)
    assert executor.last_persistence_status is PollPersistenceStatus.ALREADY_COMMITTED
    executor.stop_monitor()
    runs = store.list_runs()
    assert len(runs) == 1
    assert runs[0]["status"] == "STOPPED"
    assert runs[0]["observation_count"] == 2
    assert runs[0]["lifecycle_count"] == len(recovered.events)


def test_runtime_monitor_preserves_indeterminate_poll_after_retry_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_batch = store.record_poll_batch
    poll_ids: list[str] = []

    def fail_between_receipt_checks(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        if len(poll_ids) == 2:
            raise StorageError("fixture transient monitor receipt check failure")
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            raise PollPersistenceIndeterminate(
                "fixture monitor commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", fail_between_receipt_checks)
    common = {
        "monitoring": True,
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    with pytest.raises(PollPersistenceIndeterminate):
        executor.execute(
            _config(),
            request,
            credentials,
            cancel_token=CancellationToken(),
            **common,  # type: ignore[arg-type]
        )
    target_count = len(factory.targets)
    with pytest.raises(StorageError, match="transient monitor receipt"):
        executor.execute(
            _config(),
            request,
            credentials,
            cancel_token=CancellationToken(),
            **common,  # type: ignore[arg-type]
        )

    assert executor._pending_monitor_persistence is not None
    assert store.list_runs()[0]["status"] == "RUNNING"
    assert len(factory.targets) == target_count

    recovered = executor.execute(
        _config(),
        request,
        credentials,
        cancel_token=CancellationToken(),
        **common,  # type: ignore[arg-type]
    )
    executor.stop_monitor()

    assert isinstance(recovered, MonitorPollResult)
    assert poll_ids == [poll_ids[0]] * 3
    assert executor._pending_monitor_persistence is None
    assert len(factory.targets) == target_count
    run = store.list_runs()[0]
    assert run["status"] == "STOPPED"
    assert run["observation_count"] == 2
    assert run["lifecycle_count"] == len(recovered.events)


def test_runtime_stop_retries_indeterminate_monitor_commit_before_finishing_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    original_batch = store.record_poll_batch
    poll_ids: list[str] = []

    def lose_first_commit_ack(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            raise PollPersistenceIndeterminate(
                "fixture monitor commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", lose_first_commit_ack)
    with pytest.raises(PollPersistenceIndeterminate):
        executor.execute(
            _config(),
            request,
            Credentials("operator", "session-only"),
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

    executor.stop_monitor()

    assert poll_ids[0] == poll_ids[1]
    assert executor.last_persistence_status is PollPersistenceStatus.ALREADY_COMMITTED
    run = store.list_runs()[0]
    assert run["status"] == "STOPPED"
    assert run["observation_count"] == 2
    assert run["lifecycle_count"] > 0


def test_runtime_stop_preserves_indeterminate_poll_after_retry_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    original_batch = store.record_poll_batch
    poll_ids: list[str] = []

    def fail_between_receipt_checks(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        if len(poll_ids) == 2:
            raise StorageError("fixture transient stop receipt check failure")
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            raise PollPersistenceIndeterminate(
                "fixture monitor commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", fail_between_receipt_checks)
    with pytest.raises(PollPersistenceIndeterminate):
        executor.execute(
            _config(),
            request,
            Credentials("operator", "session-only"),
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

    with pytest.raises(StorageError, match="transient stop receipt"):
        executor.stop_monitor()

    assert executor._pending_monitor_persistence is not None
    assert executor._monitor is not None
    assert store.list_runs()[0]["status"] == "RUNNING"

    executor.stop_monitor()

    assert poll_ids == [poll_ids[0]] * 3
    assert executor._pending_monitor_persistence is None
    run = store.list_runs()[0]
    assert run["status"] == "STOPPED"
    assert run["observation_count"] == 2
    assert run["lifecycle_count"] > 0


def test_runtime_concurrent_stop_consumes_indeterminate_monitor_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    original_batch = store.record_poll_batch
    committed = Event()
    release_ack = Event()
    poll_ids: list[str] = []
    failures: list[BaseException] = []

    def lose_blocked_commit_ack(*args: object, **kwargs: object) -> PollPersistenceResult:
        poll_id = str(kwargs["poll_id"])
        poll_ids.append(poll_id)
        result = original_batch(*args, **kwargs)  # type: ignore[arg-type]
        if len(poll_ids) == 1:
            committed.set()
            assert release_ack.wait(timeout=5)
            raise PollPersistenceIndeterminate(
                "fixture concurrent commit acknowledgement lost",
                poll_id=poll_id,
            )
        return result

    monkeypatch.setattr(store, "record_poll_batch", lose_blocked_commit_ack)

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
    assert committed.wait(timeout=5)

    executor.stop_monitor()
    release_ack.set()
    worker.join(timeout=10)

    assert not worker.is_alive()
    assert failures == []
    assert poll_ids[0] == poll_ids[1]
    assert executor.last_persistence_status is PollPersistenceStatus.ALREADY_COMMITTED
    assert executor._pending_monitor_persistence is None
    assert executor._active_monitor_poll is None
    run = store.list_runs()[0]
    assert run["status"] == "STOPPED"
    assert run["observation_count"] == 2
    assert run["lifecycle_count"] > 0


def test_runtime_restarts_monitor_when_its_identity_changes(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)

    executor.execute(
        _config(),
        request,
        Credentials("operator-a", "session-only"),
        monitoring=True,
        cancel_token=CancellationToken(),
        host_key_approval=lambda _target, _info: True,
        full_scan_approval=lambda _request, _devices: False,
    )
    executor.execute(
        _config(),
        request,
        Credentials("operator-b", "session-only"),
        monitoring=True,
        cancel_token=CancellationToken(),
        host_key_approval=lambda _target, _info: True,
        full_scan_approval=lambda _request, _devices: False,
    )
    executor.stop_monitor()

    runs = store.list_runs()
    assert len(runs) == 2
    assert sorted(run["status"] for run in runs) == ["RESTARTED", "STOPPED"]
    assert all(run["observation_count"] == 2 for run in runs)


def test_runtime_stop_waits_for_inflight_poll_persistence(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    started = Event()
    release = Event()
    factory = _BlockingFactory(started, release)
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
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
    assert run["observation_count"] == 0


def test_runtime_rejects_overlapping_monitor_polls_and_stop_cancels_owner(
    tmp_path: Path,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    started = Event()
    release = Event()
    factory = _BlockingFactory(started, release)
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
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
        except BaseException as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    worker = Thread(target=poll)
    worker.start()
    assert started.wait(timeout=5)

    with pytest.raises(RuntimeError, match="이미 진행"):
        executor.execute(
            _config(),
            request,
            Credentials("operator", "session-only"),
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

    executor.stop_monitor()
    assert any(token.is_cancelled for token in factory.cancel_tokens)
    release.set()
    worker.join(timeout=10)

    assert not worker.is_alive()
    assert failures == []
    assert store.list_runs()[0]["status"] == "STOPPED"


def test_runtime_retries_failed_monitor_finalization_before_next_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    execute_kwargs = {
        "monitoring": True,
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    executor.execute(
        _config(),
        request,
        credentials,
        cancel_token=CancellationToken(),
        **execute_kwargs,  # type: ignore[arg-type]
    )
    original_finish = store.finish_run
    finish_attempts = 0

    def flaky_finish(run_id: str, status: str = "COMPLETED") -> None:
        nonlocal finish_attempts
        finish_attempts += 1
        if finish_attempts <= 2:
            raise OSError("fixture finalize failure")
        original_finish(run_id, status=status)

    monkeypatch.setattr(store, "finish_run", flaky_finish)
    with pytest.raises(RuntimeError, match="종료 상태"):
        executor.stop_monitor()

    assert executor.last_shutdown_error == "OSError"
    assert store.list_runs()[0]["status"] == "RUNNING"

    executor.execute(
        _config(),
        request,
        credentials,
        cancel_token=CancellationToken(),
        **execute_kwargs,  # type: ignore[arg-type]
    )
    executor.stop_monitor()

    assert executor.last_shutdown_error is None
    assert finish_attempts == 4
    assert [run["status"] for run in store.list_runs()] == ["STOPPED", "STOPPED"]


def test_runtime_discards_unpersisted_monitor_state_after_batch_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    original_batch = store.record_poll_batch
    batch_calls = 0

    def fail_once(*args: object, **kwargs: object) -> PollPersistenceResult:
        nonlocal batch_calls
        batch_calls += 1
        if batch_calls == 1:
            raise OSError("fixture batch failure")
        return original_batch(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "record_poll_batch", fail_once)
    with pytest.raises(OSError, match="batch failure"):
        executor.execute(
            _config(),
            request,
            credentials,
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

    assert all(connection.closed for connection in factory.connections)

    result = executor.execute(
        _config(),
        request,
        credentials,
        monitoring=True,
        cancel_token=CancellationToken(),
        host_key_approval=lambda _target, _info: True,
        full_scan_approval=lambda _request, _devices: False,
    )
    executor.stop_monitor()

    assert result.events
    assert all(event.event_type.value == "STARTED" for event in result.events)
    runs = store.list_runs()
    assert [run["status"] for run in runs] == ["STOPPED", "FAILED"]
    assert runs[0]["lifecycle_count"] == len(result.events)
    assert runs[1]["lifecycle_count"] == 0


def test_runtime_cancelled_monitor_failure_finishes_stopped_and_releases_ownership(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store, ssh_factory=_Factory())
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    credentials = Credentials("operator", "session-only")
    cancel_token = CancellationToken()
    original_batch = store.record_poll_batch
    batch_calls = 0

    def cancel_and_fail_once(*args: object, **kwargs: object) -> PollPersistenceResult:
        nonlocal batch_calls
        batch_calls += 1
        if batch_calls == 1:
            cancel_token.cancel()
            raise OSError("fixture cancelled persistence failure")
        return original_batch(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "record_poll_batch", cancel_and_fail_once)
    with pytest.raises(OSError, match="cancelled persistence failure"):
        executor.execute(
            _config(),
            request,
            credentials,
            monitoring=True,
            cancel_token=cancel_token,
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

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
    assert [run["status"] for run in runs] == ["STOPPED", "STOPPED"]
    assert runs[0]["lifecycle_count"] > 0
    assert runs[1]["lifecycle_count"] == 0


def test_runtime_restarts_monitor_when_in_memory_credentials_change(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)
    common = {
        "monitoring": True,
        "host_key_approval": lambda _target, _info: True,
        "full_scan_approval": lambda _request, _devices: False,
    }

    executor.execute(
        _config(),
        request,
        Credentials("operator", "first-session-secret"),
        cancel_token=CancellationToken(),
        **common,  # type: ignore[arg-type]
    )
    first_identity_connections = tuple(factory.connections)
    executor.execute(
        _config(),
        request,
        Credentials("operator", "second-session-secret"),
        cancel_token=CancellationToken(),
        **common,  # type: ignore[arg-type]
    )

    assert all(connection.closed for connection in first_identity_connections)
    assert factory.passwords[:2] == ["first-session-secret", "first-session-secret"]
    assert factory.passwords[-2:] == ["second-session-secret", "second-session-secret"]
    assert "second-session-secret" not in str(executor._monitor_signature)
    assert [run["status"] for run in store.list_runs()] == ["RUNNING", "RESTARTED"]
    executor.stop_monitor()


def test_runtime_can_invalidate_cached_monitor_location(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    factory = _RecordingFactory()
    executor = RuntimeExecutor(paths, store, ssh_factory=factory)
    request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443)

    def poll() -> None:
        executor.execute(
            _config(),
            request,
            Credentials("operator", "session-only"),
            monitoring=True,
            cancel_token=CancellationToken(),
            host_key_approval=lambda _target, _info: True,
            full_scan_approval=lambda _request, _devices: False,
        )

    poll()
    factory.targets.clear()
    poll()
    assert factory.targets == []

    previous_connections = tuple(factory.connections)
    executor.invalidate_monitor_location()
    assert all(connection.closed for connection in previous_connections)
    factory.targets.clear()
    poll()
    assert factory.targets == ["MM-1", "MD-1"]
    executor.stop_monitor()
