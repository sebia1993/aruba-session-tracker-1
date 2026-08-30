from __future__ import annotations

import json
import threading
from dataclasses import dataclass

from aruba_session_tracker.collectors import (
    CancellationToken,
    HostKeyApproval,
    SSHConnectionFactory,
    StrictNetmikoFactory,
)
from aruba_session_tracker.models import AppConfig, Credentials, QueryRequest
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
from aruba_session_tracker.storage import SessionStore


@dataclass(slots=True)
class _ActiveMonitorPoll:
    poll_id: int
    generation: int
    run_id: str | None
    cancel_token: CancellationToken


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
        self._monitor_signature: str | None = None
        self._monitor_credentials: Credentials | None = None
        self._monitor_run_id: str | None = None
        self._monitor_generation = 0
        self._next_poll_id = 0
        self._active_monitor_poll: _ActiveMonitorPoll | None = None
        self._monitor_stop_requested = False
        self._pending_finishes: dict[str, str] = {}
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
        if monitoring:
            return self._execute_monitor_poll(
                config,
                request,
                credentials,
                cancel_token=cancel_token,
                host_key_approval=host_key_approval,
                full_scan_approval=full_scan_approval,
            )
        service = self._service(config, host_key_approval, full_scan_approval)
        run_id = self._store.start_run(request)
        try:
            outcome = service.query_once(
                request,
                credentials,
                full_scan_approval=full_scan_approval,
                cancel_token=cancel_token,
            )
            self._store.record_poll_batch(run_id, outcome)
        except Exception as exc:
            finish_error = self._finish_or_queue(run_id, "FAILED")
            if finish_error is not None:
                exc.add_note("실행 실패 상태도 저장하지 못했습니다.")
            raise
        status = _one_shot_status(outcome)
        finish_error = self._finish_or_queue(run_id, status)
        if finish_error is not None:
            raise RuntimeError("실행 종료 상태를 저장하지 못했습니다.") from finish_error
        return outcome

    def stop_monitor(self) -> None:
        run_id: str | None = None
        active_token: CancellationToken | None = None
        with self._lock:
            self._monitor_stop_requested = True
            if self._active_monitor_poll is not None:
                active_token = self._active_monitor_poll.cancel_token
            else:
                run_id = self._detach_monitor_locked()
        if active_token is not None:
            active_token.cancel()
        if run_id is not None:
            self._finish_or_queue(run_id, "STOPPED")
        self._retry_pending_finishes(required=True)

    def invalidate_monitor_location(self) -> None:
        """Force the next monitor poll to refresh MM routing information."""

        with self._lock:
            if self._monitor is not None:
                self._monitor.invalidate_location()

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
        restart_run_id: str | None = None
        with self._lock:
            if self._active_monitor_poll is not None:
                raise RuntimeError("모니터링 조회가 이미 진행 중입니다.")
            self._next_poll_id += 1
            lease = _ActiveMonitorPoll(
                poll_id=self._next_poll_id,
                generation=self._monitor_generation,
                run_id=self._monitor_run_id,
                cancel_token=cancel_token,
            )
            self._active_monitor_poll = lease
            if self._monitor is not None and (
                self._monitor_signature != signature or self._monitor_credentials != credentials
            ):
                restart_run_id = self._detach_monitor_locked(reset_stop_request=False)

        prepared: _PreparedMonitorPoll | None = None
        monitor: MonitorEngine | None = None
        run_id: str | None = None
        try:
            if restart_run_id is not None:
                finish_error = self._finish_or_queue(restart_run_id, "RESTARTED")
                if finish_error is not None:
                    raise RuntimeError("이전 모니터링 종료 상태를 저장하지 못했습니다.") from (
                        finish_error
                    )

            with self._lock:
                needs_monitor = self._monitor is None
            if needs_monitor:
                service = self._service(config, host_key_approval, full_scan_approval)
                monitor = MonitorEngine(
                    service,
                    request,
                    credentials,
                    full_scan_approval=full_scan_approval,
                )
                run_id = self._store.start_run(request)
                with self._lock:
                    if self._active_monitor_poll is not lease:
                        raise RuntimeError("모니터링 실행 소유권이 변경되었습니다.")
                    self._monitor_generation += 1
                    self._monitor = monitor
                    self._monitor_signature = signature
                    self._monitor_credentials = credentials
                    self._monitor_run_id = run_id
                    lease.generation = self._monitor_generation
                    lease.run_id = run_id
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
            self._store.record_poll_batch(run_id, result.outcome, events=result.events)
            committed = monitor._commit_prepared(prepared)
            prepared = None
            return committed
        except Exception as exc:
            if prepared is not None and monitor is not None:
                monitor._discard_prepared(prepared)
            failed_run_id: str | None = None
            with self._lock:
                stop_requested = self._monitor_stop_requested or cancel_token.is_cancelled
                if self._lease_owns_monitor_locked(lease):
                    failed_run_id = self._detach_monitor_locked()
                elif self._monitor_stop_requested and self._monitor is None:
                    self._monitor_stop_requested = False
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
            stopped_run_id: str | None = None
            with self._lock:
                if self._monitor_stop_requested and self._lease_owns_monitor_locked(lease):
                    stopped_run_id = self._detach_monitor_locked()
                elif self._monitor_stop_requested and self._monitor is None:
                    self._monitor_stop_requested = False
                if stopped_run_id is None and self._active_monitor_poll is lease:
                    self._active_monitor_poll = None
            if stopped_run_id is not None:
                finish_error = self._finish_or_queue(stopped_run_id, "STOPPED")
                with self._lock:
                    if self._active_monitor_poll is lease:
                        self._active_monitor_poll = None
                if finish_error is not None:
                    raise RuntimeError("모니터링 종료 상태를 저장하지 못했습니다.") from (
                        finish_error
                    )

    def _service(
        self,
        config: AppConfig,
        host_key_approval: HostKeyApproval,
        full_scan_approval: FullScanApproval,
    ) -> TrackerService:
        factory = self._ssh_factory or StrictNetmikoFactory(self._paths.known_hosts)
        callbacks = TrackerCallbacks(
            host_key_approval=host_key_approval,
            full_scan_approval=full_scan_approval,
        )
        return TrackerService(config, factory, callbacks)

    def _lease_owns_monitor_locked(self, lease: _ActiveMonitorPoll) -> bool:
        return (
            lease.generation == self._monitor_generation
            and lease.run_id is not None
            and lease.run_id == self._monitor_run_id
        )

    def _detach_monitor_locked(self, *, reset_stop_request: bool = True) -> str | None:
        run_id = self._monitor_run_id
        self._monitor = None
        self._monitor_signature = None
        self._monitor_credentials = None
        self._monitor_run_id = None
        self._monitor_generation += 1
        if reset_stop_request:
            self._monitor_stop_requested = False
        return run_id

    def _finish_or_queue(self, run_id: str, status: str) -> Exception | None:
        try:
            self._store.finish_run(run_id, status=status)
        except Exception as exc:
            with self._lock:
                self._pending_finishes[run_id] = status
                self.last_shutdown_error = type(exc).__name__
            return exc
        with self._lock:
            self._pending_finishes.pop(run_id, None)
            if not self._pending_finishes:
                self.last_shutdown_error = None
        return None

    def _retry_pending_finishes(self, *, required: bool) -> None:
        with self._lock:
            pending = tuple(self._pending_finishes.items())
        first_error: Exception | None = None
        for run_id, status in pending:
            error = self._finish_or_queue(run_id, status)
            if error is not None and first_error is None:
                first_error = error
        if required and first_error is not None:
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
