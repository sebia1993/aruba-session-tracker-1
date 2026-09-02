from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from uuid import uuid4

from aruba_session_tracker.collectors import (
    CancellationToken,
    HostKeyApproval,
    MonitoringSSHConnectionFactory,
    SSHConnectionFactory,
    StrictNetmikoFactory,
)
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    QueryRequest,
    StorageFailureBoundary,
)
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.services import (
    FullScanApproval,
    MonitorEngine,
    MonitorPollResult,
    QueryOutcome,
    TrackerCallbacks,
    TrackerService,
)
from aruba_session_tracker.services.monitoring import _PreparedMonitorPoll
from aruba_session_tracker.storage import (
    PollPersistenceIndeterminate,
    PollPersistenceResult,
    PollPersistenceStatus,
    SessionStore,
    StorageError,
)


@dataclass(slots=True)
class _ActiveMonitorPoll:
    poll_id: str
    generation: int
    run_id: str | None
    cancel_token: CancellationToken


@dataclass(frozen=True, slots=True)
class _DetachedMonitor:
    run_id: str | None
    ssh_pool: MonitoringSSHConnectionFactory | None

    def close_connections(self) -> None:
        if self.ssh_pool is not None:
            self.ssh_pool.close()


@dataclass(frozen=True, slots=True)
class _PendingOneShotPersistence:
    poll_id: str
    run_id: str
    signature: str
    request: QueryRequest
    outcome: QueryOutcome


@dataclass(frozen=True, slots=True)
class _PendingMonitorPersistence:
    poll_id: str
    generation: int
    run_id: str
    monitor: MonitorEngine
    prepared: _PreparedMonitorPoll


class RuntimeExecutor:
    """Bridge query services to persistence without ever persisting credentials."""

    def __init__(
        self,
        paths: AppPaths,
        store: SessionStore,
        *,
        ssh_factory: SSHConnectionFactory | None = None,
    ) -> None:
        self._paths = paths
        self._store = store
        self._ssh_factory = ssh_factory
        self._lock = threading.RLock()
        self._monitor: MonitorEngine | None = None
        self._monitor_ssh_pool: MonitoringSSHConnectionFactory | None = None
        self._monitor_signature: str | None = None
        self._monitor_credentials: Credentials | None = None
        self._monitor_run_id: str | None = None
        self._monitor_generation = 0
        self._active_monitor_poll: _ActiveMonitorPoll | None = None
        self._pending_one_shot_persistence: _PendingOneShotPersistence | None = None
        self._pending_one_shot_retrying = False
        self._one_shot_active = False
        self._pending_monitor_persistence: _PendingMonitorPersistence | None = None
        self._monitor_stop_requested = False
        self._pending_finishes: dict[str, str] = {}
        self._finish_retry_lock = threading.Lock()
        self.last_persistence_status: PollPersistenceStatus | None = None
        self.last_shutdown_error: str | None = None

    def execute(
        self,
        config: AppConfig,
        request: QueryRequest,
        credentials: Credentials,
        *,
        monitoring: bool,
        cancel_token: CancellationToken,
        host_key_approval: HostKeyApproval,
        full_scan_approval: FullScanApproval,
    ) -> QueryOutcome | MonitorPollResult:
        self._retry_pending_finishes(required=True)
        recovered = self._retry_pending_one_shot_persistence(
            signature=_monitor_signature(config, request, credentials.username),
            request=request,
            monitoring=monitoring,
        )
        if recovered is not None:
            return recovered
        if monitoring:
            try:
                return self._execute_monitor_poll(
                    config,
                    request,
                    credentials,
                    cancel_token=cancel_token,
                    host_key_approval=host_key_approval,
                    full_scan_approval=full_scan_approval,
                )
            except PollPersistenceIndeterminate:
                # The poll's finally block has released its active lease. If a
                # concurrent stop arrived while persistence became
                # indeterminate, consume that stop here so shutdown cannot
                # report success while leaving a pending RUNNING monitor.
                stopped = self._recover_stopped_monitor_after_indeterminate()
                if stopped is not None:
                    return stopped
                raise
        with self._lock:
            if self._one_shot_active:
                raise RuntimeError("단일 조회가 이미 진행 중입니다.")
            self._one_shot_active = True
        try:
            return self._execute_one_shot(
                config,
                request,
                credentials,
                cancel_token=cancel_token,
                host_key_approval=host_key_approval,
                full_scan_approval=full_scan_approval,
            )
        finally:
            with self._lock:
                self._one_shot_active = False

    def _execute_one_shot(
        self,
        config: AppConfig,
        request: QueryRequest,
        credentials: Credentials,
        *,
        cancel_token: CancellationToken,
        host_key_approval: HostKeyApproval,
        full_scan_approval: FullScanApproval,
    ) -> QueryOutcome:
        service = self._service(config, host_key_approval, full_scan_approval)
        try:
            run_id = self._store.start_run(request)
        except StorageError as exc:
            exc.at_boundary(StorageFailureBoundary.QUERY_START)
            raise
        poll_id = uuid4().hex
        try:
            outcome = service.query_once(
                request,
                credentials,
                full_scan_approval=full_scan_approval,
                cancel_token=cancel_token,
            )
        except Exception as exc:
            finish_error = self._finish_or_queue(run_id, "FAILED")
            if finish_error is not None:
                exc.add_note("실행 실패 상태도 저장하지 못했습니다.")
            raise
        try:
            persistence = self._store.record_poll_batch(run_id, outcome, poll_id=poll_id)
            self._remember_persistence(poll_id, persistence)
        except PollPersistenceIndeterminate as exc:
            with self._lock:
                self._pending_one_shot_persistence = _PendingOneShotPersistence(
                    poll_id=poll_id,
                    run_id=run_id,
                    signature=_monitor_signature(config, request, credentials.username),
                    request=request,
                    outcome=outcome,
                )
            self._require_indeterminate_poll_id(exc, poll_id)
            raise
        except StorageError as exc:
            exc.at_boundary(StorageFailureBoundary.QUERY_RESULT)
            finish_error = self._finish_or_queue(run_id, "FAILED")
            if finish_error is not None:
                exc.add_note("실행 실패 상태도 저장하지 못했습니다.")
            raise
        except Exception as exc:
            finish_error = self._finish_or_queue(run_id, "FAILED")
            if finish_error is not None:
                exc.add_note("실행 실패 상태도 저장하지 못했습니다.")
            raise
        status = _one_shot_status(outcome)
        finish_error = self._finish_or_queue(run_id, status)
        if finish_error is not None:
            if isinstance(finish_error, StorageError):
                raise finish_error
            raise RuntimeError("실행 종료 상태를 저장하지 못했습니다.") from finish_error
        return outcome

    def stop_monitor(self) -> None:
        detached: _DetachedMonitor | None = None
        active_token: CancellationToken | None = None
        pending: _PendingMonitorPersistence | None = None
        retry_lease: _ActiveMonitorPoll | None = None
        with self._lock:
            self._monitor_stop_requested = True
            if self._active_monitor_poll is not None:
                active_token = self._active_monitor_poll.cancel_token
            elif self._pending_monitor_persistence is not None:
                pending = self._pending_monitor_persistence
                if (
                    pending.monitor is not self._monitor
                    or pending.generation != self._monitor_generation
                    or pending.run_id != self._monitor_run_id
                ):
                    raise RuntimeError("보류된 모니터링 저장 상태가 현재 실행과 일치하지 않습니다.")
                retry_token = CancellationToken()
                retry_token.cancel()
                retry_lease = _ActiveMonitorPoll(
                    poll_id=pending.poll_id,
                    generation=pending.generation,
                    run_id=pending.run_id,
                    cancel_token=retry_token,
                )
                self._active_monitor_poll = retry_lease
            else:
                detached = self._detach_monitor_locked()
        if active_token is not None:
            active_token.cancel()
        if pending is not None and retry_lease is not None:
            self._resolve_pending_monitor_stop(pending, retry_lease)
            return
        if detached is not None:
            detached.close_connections()
            if detached.run_id is not None:
                self._finish_or_queue(detached.run_id, "STOPPED")
        self._retry_pending_finishes(required=True)

    def _resolve_pending_monitor_stop(
        self,
        pending: _PendingMonitorPersistence,
        lease: _ActiveMonitorPoll,
    ) -> MonitorPollResult:
        try:
            persistence = self._store.record_poll_batch(
                pending.run_id,
                pending.prepared.result.outcome,
                events=pending.prepared.result.events,
                poll_id=pending.poll_id,
            )
            self._remember_persistence(pending.poll_id, persistence)
            recovered = pending.monitor._commit_prepared(pending.prepared)
        except PollPersistenceIndeterminate as exc:
            with self._lock:
                if self._active_monitor_poll is lease:
                    self._active_monitor_poll = None
            self._require_indeterminate_poll_id(exc, pending.poll_id)
            raise
        except Exception:
            # This is a retry of an already-indeterminate commit. Preserve the
            # prepared state and poll ID on every non-successful result so a
            # later stop/retry cannot create a duplicate poll.
            with self._lock:
                if self._active_monitor_poll is lease:
                    self._active_monitor_poll = None
            raise

        detached: _DetachedMonitor | None = None
        with self._lock:
            if self._pending_monitor_persistence is pending:
                self._pending_monitor_persistence = None
            detached = (
                self._detach_monitor_locked() if self._lease_owns_monitor_locked(lease) else None
            )
            if self._active_monitor_poll is lease:
                self._active_monitor_poll = None
        if detached is not None:
            detached.close_connections()
            if detached.run_id is not None:
                self._finish_or_queue(detached.run_id, "STOPPED")
        self._retry_pending_finishes(required=True)
        return recovered

    def _recover_stopped_monitor_after_indeterminate(self) -> MonitorPollResult | None:
        with self._lock:
            pending = self._pending_monitor_persistence
            if (
                not self._monitor_stop_requested
                or self._active_monitor_poll is not None
                or pending is None
            ):
                return None
            if (
                pending.monitor is not self._monitor
                or pending.generation != self._monitor_generation
                or pending.run_id != self._monitor_run_id
            ):
                raise RuntimeError("보류된 모니터링 저장 상태가 현재 실행과 일치하지 않습니다.")
            retry_token = CancellationToken()
            retry_token.cancel()
            lease = _ActiveMonitorPoll(
                poll_id=pending.poll_id,
                generation=pending.generation,
                run_id=pending.run_id,
                cancel_token=retry_token,
            )
            self._active_monitor_poll = lease
        return self._resolve_pending_monitor_stop(pending, lease)

    def invalidate_monitor_location(self) -> None:
        """Drop network-bound state and refresh MM routing on the next poll."""

        with self._lock:
            if self._monitor is not None:
                self._monitor.invalidate_location()
            ssh_pool = self._monitor_ssh_pool
        if ssh_pool is not None:
            ssh_pool.invalidate()

    def _execute_monitor_poll(
        self,
        config: AppConfig,
        request: QueryRequest,
        credentials: Credentials,
        *,
        cancel_token: CancellationToken,
        host_key_approval: HostKeyApproval,
        full_scan_approval: FullScanApproval,
    ) -> MonitorPollResult:
        signature = _monitor_signature(config, request, credentials.username)
        restart_detached: _DetachedMonitor | None = None
        pending: _PendingMonitorPersistence | None = None
        with self._lock:
            if self._active_monitor_poll is not None:
                raise RuntimeError("모니터링 조회가 이미 진행 중입니다.")
            pending = self._pending_monitor_persistence
            if pending is not None and (
                pending.monitor is not self._monitor
                or pending.generation != self._monitor_generation
                or pending.run_id != self._monitor_run_id
            ):
                raise RuntimeError("보류된 모니터링 저장 상태가 현재 실행과 일치하지 않습니다.")
            lease = _ActiveMonitorPoll(
                poll_id=pending.poll_id if pending is not None else uuid4().hex,
                generation=(
                    pending.generation if pending is not None else self._monitor_generation
                ),
                run_id=pending.run_id if pending is not None else self._monitor_run_id,
                cancel_token=cancel_token,
            )
            self._active_monitor_poll = lease
            if (
                pending is None
                and self._monitor is not None
                and (
                    self._monitor_signature != signature or self._monitor_credentials != credentials
                )
            ):
                restart_detached = self._detach_monitor_locked(reset_stop_request=False)

        if restart_detached is not None:
            restart_detached.close_connections()

        prepared: _PreparedMonitorPoll | None = None
        monitor: MonitorEngine | None = None
        run_id: str | None = None
        persistence_indeterminate = False
        pending_retry_failed = False
        unattached_pool: MonitoringSSHConnectionFactory | None = None
        try:
            if pending is not None:
                monitor = pending.monitor
                run_id = pending.run_id
                prepared = pending.prepared
                persistence = self._store.record_poll_batch(
                    run_id,
                    prepared.result.outcome,
                    events=prepared.result.events,
                    poll_id=pending.poll_id,
                )
                self._remember_persistence(pending.poll_id, persistence)
                recovered = monitor._commit_prepared(prepared)
                prepared = None
                with self._lock:
                    if self._pending_monitor_persistence is pending:
                        self._pending_monitor_persistence = None
                    same_identity = (
                        self._monitor_signature == signature
                        and self._monitor_credentials == credentials
                    )
                    stop_requested = self._monitor_stop_requested
                if same_identity or stop_requested:
                    return recovered

                with self._lock:
                    if not self._lease_owns_monitor_locked(lease):
                        raise RuntimeError("모니터링 실행 소유권이 변경되었습니다.")
                    restart_detached = self._detach_monitor_locked(reset_stop_request=False)
                    lease.poll_id = uuid4().hex
                    lease.generation = self._monitor_generation
                    lease.run_id = None
                restart_detached.close_connections()
                pending = None

            restart_run_id = restart_detached.run_id if restart_detached is not None else None
            if restart_run_id is not None:
                finish_error = self._finish_or_queue(restart_run_id, "RESTARTED")
                if finish_error is not None:
                    if isinstance(finish_error, StorageError):
                        raise finish_error
                    raise RuntimeError("이전 모니터링 종료 상태를 저장하지 못했습니다.") from (
                        finish_error
                    )

            with self._lock:
                needs_monitor = self._monitor is None
            if needs_monitor:
                ssh_pool = MonitoringSSHConnectionFactory(
                    self._base_ssh_factory(),
                    credentials,
                )
                unattached_pool = ssh_pool
                service = self._service(
                    config,
                    host_key_approval,
                    full_scan_approval,
                    ssh_factory=ssh_pool,
                )
                monitor = MonitorEngine(
                    service,
                    request,
                    credentials,
                    full_scan_approval=full_scan_approval,
                )
                try:
                    run_id = self._store.start_run(request)
                except StorageError as exc:
                    exc.at_boundary(StorageFailureBoundary.QUERY_START)
                    raise
                with self._lock:
                    if self._active_monitor_poll is not lease:
                        raise RuntimeError("모니터링 실행 소유권이 변경되었습니다.")
                    self._monitor_generation += 1
                    self._monitor = monitor
                    self._monitor_ssh_pool = ssh_pool
                    self._monitor_signature = signature
                    self._monitor_credentials = credentials
                    self._monitor_run_id = run_id
                    lease.generation = self._monitor_generation
                    lease.run_id = run_id
                    unattached_pool = None
            else:
                with self._lock:
                    monitor = self._monitor
                    run_id = self._monitor_run_id
                    lease.generation = self._monitor_generation
                    lease.run_id = run_id

            if monitor is None or run_id is None:
                raise RuntimeError("모니터링 실행을 초기화하지 못했습니다.")

            prepared = monitor._prepare_for_persistence(cancel_token=cancel_token)
            result = prepared.result
            persistence = self._store.record_poll_batch(
                run_id,
                result.outcome,
                events=result.events,
                poll_id=lease.poll_id,
            )
            self._remember_persistence(lease.poll_id, persistence)
            committed = monitor._commit_prepared(prepared)
            prepared = None
            return committed
        except PollPersistenceIndeterminate as exc:
            persistence_indeterminate = True
            if prepared is not None and monitor is not None and run_id is not None:
                with self._lock:
                    if self._lease_owns_monitor_locked(lease):
                        self._pending_monitor_persistence = _PendingMonitorPersistence(
                            poll_id=lease.poll_id,
                            generation=lease.generation,
                            run_id=run_id,
                            monitor=monitor,
                            prepared=prepared,
                        )
                    else:
                        raise RuntimeError(
                            "확인할 수 없는 poll 저장 상태의 소유권이 변경되었습니다."
                        ) from exc
            self._require_indeterminate_poll_id(exc, lease.poll_id)
            raise
        except Exception as exc:
            if isinstance(exc, StorageError):
                exc.at_boundary(StorageFailureBoundary.QUERY_RESULT)
            if pending is not None and prepared is pending.prepared:
                # Once a previous attempt became indeterminate, only a
                # confirmed committed result may release this prepared poll.
                # Treat every other retry failure as fail-closed: discarding it
                # could allow a new poll ID to duplicate an earlier commit.
                pending_retry_failed = True
                with self._lock:
                    if self._active_monitor_poll is lease:
                        self._active_monitor_poll = None
                raise
            if prepared is not None and monitor is not None:
                monitor._discard_prepared(prepared)
            failed_detached: _DetachedMonitor | None = None
            with self._lock:
                if (
                    self._pending_monitor_persistence is not None
                    and self._pending_monitor_persistence.prepared is prepared
                ):
                    self._pending_monitor_persistence = None
                stop_requested = self._monitor_stop_requested or cancel_token.is_cancelled
                if self._lease_owns_monitor_locked(lease):
                    failed_detached = self._detach_monitor_locked()
                elif self._monitor_stop_requested and self._monitor is None:
                    self._monitor_stop_requested = False
            if failed_detached is not None:
                failed_detached.close_connections()
                failed_run_id = failed_detached.run_id
            else:
                failed_run_id = None
            if failed_run_id is not None:
                finish_error = self._finish_or_queue(
                    failed_run_id,
                    "STOPPED" if stop_requested else "FAILED",
                )
                if finish_error is not None:
                    exc.add_note("모니터링 종료 상태도 저장하지 못했습니다.")
            with self._lock:
                if self._active_monitor_poll is lease:
                    self._active_monitor_poll = None
            raise
        finally:
            if unattached_pool is not None:
                unattached_pool.close()
            stopped_detached: _DetachedMonitor | None = None
            with self._lock:
                if persistence_indeterminate or pending_retry_failed:
                    if self._active_monitor_poll is lease:
                        self._active_monitor_poll = None
                elif self._monitor_stop_requested and self._lease_owns_monitor_locked(lease):
                    stopped_detached = self._detach_monitor_locked()
                elif self._monitor_stop_requested and self._monitor is None:
                    self._monitor_stop_requested = False
                if stopped_detached is None and self._active_monitor_poll is lease:
                    self._active_monitor_poll = None
            if stopped_detached is not None:
                stopped_detached.close_connections()
                stopped_run_id = stopped_detached.run_id
            else:
                stopped_run_id = None
            if stopped_run_id is not None:
                finish_error = self._finish_or_queue(stopped_run_id, "STOPPED")
                with self._lock:
                    if self._active_monitor_poll is lease:
                        self._active_monitor_poll = None
                if finish_error is not None:
                    if isinstance(finish_error, StorageError):
                        raise finish_error
                    raise RuntimeError("모니터링 종료 상태를 저장하지 못했습니다.") from (
                        finish_error
                    )

    def _service(
        self,
        config: AppConfig,
        host_key_approval: HostKeyApproval,
        full_scan_approval: FullScanApproval,
        *,
        ssh_factory: SSHConnectionFactory | None = None,
    ) -> TrackerService:
        factory = ssh_factory or self._base_ssh_factory()
        callbacks = TrackerCallbacks(
            host_key_approval=host_key_approval,
            full_scan_approval=full_scan_approval,
        )
        return TrackerService(config, factory, callbacks)

    def _base_ssh_factory(self) -> SSHConnectionFactory:
        return self._ssh_factory or StrictNetmikoFactory(self._paths.known_hosts)

    def _lease_owns_monitor_locked(self, lease: _ActiveMonitorPoll) -> bool:
        return (
            lease.generation == self._monitor_generation
            and lease.run_id is not None
            and lease.run_id == self._monitor_run_id
        )

    def _detach_monitor_locked(
        self,
        *,
        reset_stop_request: bool = True,
    ) -> _DetachedMonitor:
        run_id = self._monitor_run_id
        ssh_pool = self._monitor_ssh_pool
        self._monitor = None
        self._monitor_ssh_pool = None
        self._monitor_signature = None
        self._monitor_credentials = None
        self._monitor_run_id = None
        self._monitor_generation += 1
        if reset_stop_request:
            self._monitor_stop_requested = False
        return _DetachedMonitor(run_id, ssh_pool)

    def _finish_or_queue(self, run_id: str, status: str) -> Exception | None:
        try:
            self._store.finish_run(run_id, status=status)
        except Exception as exc:
            if isinstance(exc, StorageError):
                exc.at_boundary(StorageFailureBoundary.QUERY_FINALIZE)
            with self._lock:
                self._pending_finishes[run_id] = status
                self.last_shutdown_error = type(exc).__name__
            return exc
        with self._lock:
            self._pending_finishes.pop(run_id, None)
            if not self._pending_finishes:
                self.last_shutdown_error = None
        return None

    def _retry_pending_one_shot_persistence(
        self,
        *,
        signature: str,
        request: QueryRequest,
        monitoring: bool,
    ) -> QueryOutcome | None:
        with self._lock:
            pending = self._pending_one_shot_persistence
            if pending is None:
                return None
            if self._one_shot_active:
                raise RuntimeError("이전 단일 조회가 아직 종료되지 않았습니다.")
            if self._pending_one_shot_retrying:
                raise RuntimeError("이전 단일 조회의 저장 상태를 확인하고 있습니다.")
            self._pending_one_shot_retrying = True

        try:
            try:
                persistence = self._store.record_poll_batch(
                    pending.run_id,
                    pending.outcome,
                    poll_id=pending.poll_id,
                )
                self._remember_persistence(pending.poll_id, persistence)
            except PollPersistenceIndeterminate as exc:
                self._require_indeterminate_poll_id(exc, pending.poll_id)
                raise
            except StorageError as exc:
                exc.at_boundary(StorageFailureBoundary.QUERY_RESULT)
                # Preserve the exact pending poll for the same reason as the
                # general failure path below.
                raise
            except Exception:
                # The first attempt's commit state is still unknown. Preserve
                # the exact request, result, run and poll ID until a durable
                # receipt confirms success; starting a fresh query here could
                # duplicate a commit that actually completed.
                raise

            with self._lock:
                if self._pending_one_shot_persistence is pending:
                    self._pending_one_shot_persistence = None
            status = _one_shot_status(pending.outcome)
            finish_error = self._finish_or_queue(pending.run_id, status)
            if finish_error is not None:
                if isinstance(finish_error, StorageError):
                    raise finish_error
                raise RuntimeError("실행 종료 상태를 저장하지 못했습니다.") from finish_error
            if not monitoring and signature == pending.signature and request == pending.request:
                return pending.outcome
            return None
        finally:
            with self._lock:
                self._pending_one_shot_retrying = False

    def _remember_persistence(
        self,
        poll_id: str,
        persistence: PollPersistenceResult,
    ) -> None:
        committed_statuses = {
            PollPersistenceStatus.COMMITTED,
            PollPersistenceStatus.ALREADY_COMMITTED,
            PollPersistenceStatus.COMMITTED_RECOVERY_PENDING,
        }
        if persistence.poll_id != poll_id or persistence.status not in committed_statuses:
            raise PollPersistenceIndeterminate(
                "poll 저장 결과를 확인할 수 없어 동일 poll ID로 복구해야 합니다.",
                poll_id=poll_id,
            )
        with self._lock:
            self.last_persistence_status = persistence.status

    @staticmethod
    def _require_indeterminate_poll_id(
        error: PollPersistenceIndeterminate,
        poll_id: str,
    ) -> None:
        if error.poll_id != poll_id:
            raise RuntimeError("확인할 수 없는 poll 저장 상태의 ID가 일치하지 않습니다.") from error

    def _retry_pending_finishes(self, *, required: bool) -> None:
        # A query and a concurrent stop can both reach this recovery point.
        # Serialize the complete snapshot-and-retry pass so a second caller
        # cannot retry a run after the first caller has already finished it and
        # released its ownership lease.
        with self._finish_retry_lock:
            with self._lock:
                pending = tuple(self._pending_finishes.items())
            first_error: Exception | None = None
            for run_id, status in pending:
                error = self._finish_or_queue(run_id, status)
                if error is not None and first_error is None:
                    first_error = error
            if required and first_error is not None:
                if isinstance(first_error, StorageError):
                    raise first_error
                raise RuntimeError("이전 실행 종료 상태를 저장하지 못했습니다.") from first_error


def _monitor_signature(config: AppConfig, request: QueryRequest, username: str) -> str:
    value = {
        "config": config.to_dict(),
        "request": {
            "source_ip": request.source_ip,
            "destination_ip": request.destination_ip,
            "source_port": request.source_port,
            "destination_port": request.destination_port,
            "bidirectional": request.bidirectional,
        },
        "username": username,
    }
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _one_shot_status(outcome: QueryOutcome) -> str:
    if outcome.cancelled:
        return "CANCELLED"
    if outcome.authoritative:
        return "COMPLETED"
    if outcome.observations:
        return "PARTIAL"
    return "FAILED"
