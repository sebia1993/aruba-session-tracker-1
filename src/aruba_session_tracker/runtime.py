from __future__ import annotations

import json
import threading

from aruba_session_tracker.collectors import (
    CancellationToken,
    HostKeyApproval,
    SSHConnectionFactory,
    StrictNetmikoFactory,
)
from aruba_session_tracker.models import AppConfig, Credentials, ErrorCode, QueryRequest
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.services import (
    FullScanApproval,
    LifecycleEvent,
    LifecycleEventType,
    MonitorEngine,
    MonitorPollResult,
    QueryOutcome,
    TrackerCallbacks,
    TrackerService,
)
from aruba_session_tracker.storage import SessionStore


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
        self._monitor_run_id: str | None = None
        self._active_monitor_polls = 0
        self._monitor_stop_requested = False
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
            self._persist_outcome(run_id, outcome)
            status = _one_shot_status(outcome)
            self._store.finish_run(run_id, status=status)
            return outcome
        except Exception:
            self._store.finish_run(run_id, status="FAILED")
            raise

    def stop_monitor(self) -> None:
        run_id: str | None = None
        with self._lock:
            self._monitor_stop_requested = True
            if self._active_monitor_polls == 0:
                run_id = self._detach_monitor_locked()
        if run_id is not None:
            self._finish_stopped_run(run_id)

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
        with self._lock:
            if self._monitor_stop_requested and self._active_monitor_polls:
                raise RuntimeError("이전 모니터링 조회를 중지하는 중입니다.")
            if self._monitor is None or self._monitor_signature != signature:
                if self._monitor_run_id is not None:
                    self._store.finish_run(self._monitor_run_id, status="RESTARTED")
                service = self._service(config, host_key_approval, full_scan_approval)
                self._monitor = MonitorEngine(
                    service,
                    request,
                    credentials,
                    full_scan_approval=full_scan_approval,
                )
                self._monitor_signature = signature
                self._monitor_run_id = self._store.start_run(request)
                self._monitor_stop_requested = False
            monitor = self._monitor
            run_id = self._monitor_run_id
            self._active_monitor_polls += 1
        if monitor is None or run_id is None:
            with self._lock:
                self._active_monitor_polls -= 1
            raise RuntimeError("모니터링 실행을 초기화하지 못했습니다.")
        try:
            result = monitor.poll_once(cancel_token=cancel_token)
            self._persist_outcome(run_id, result.outcome)
            for event in result.events:
                self._persist_lifecycle(run_id, event)
            return result
        finally:
            stopped_run_id: str | None = None
            with self._lock:
                self._active_monitor_polls -= 1
                if self._active_monitor_polls == 0 and self._monitor_stop_requested:
                    stopped_run_id = self._detach_monitor_locked()
            if stopped_run_id is not None:
                self._finish_stopped_run(stopped_run_id)

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

    def _persist_outcome(self, run_id: str, outcome: QueryOutcome) -> None:
        remaining = {item.session_key: item for item in outcome.observations}
        for snapshot in outcome.raw_snapshots:
            observations = tuple(
                item for item in remaining.values() if item.controller_name == snapshot.device_name
            )
            for observation in observations:
                remaining.pop(observation.session_key, None)
            raw_kind = "session" if "datapath" in snapshot.command else "mm-location"
            self._store.record_query(
                run_id,
                observations,
                raw_text=snapshot.output,
                controller_name=snapshot.device_name,
                raw_kind=raw_kind,
                captured_at=snapshot.observed_at,
            )
        if remaining:
            self._store.record_query(run_id, tuple(remaining.values()))
        for diagnostic in outcome.diagnostics:
            self._store.record_diagnostic(diagnostic, run_id=run_id)

    def _persist_lifecycle(self, run_id: str, event: LifecycleEvent) -> None:
        previous = event.previous_observation
        current = event.observation
        details: dict[str, object] = {"miss_count": event.miss_count}
        if previous is not None:
            details.update(
                {
                    "previous_flags": previous.flags,
                    "packet_delta": _delta(current.packets, previous.packets),
                    "byte_delta": _delta(current.bytes_count, previous.bytes_count),
                }
            )
        self._store.record_lifecycle(
            run_id,
            instance_id=event.instance_id,
            session_key=current.session_key,
            event_type=event.event_type.value,
            controller_name=current.controller_name,
            details=details,
            occurred_at=event.occurred_at,
        )
        if event.event_type is LifecycleEventType.CONTROLLER_CHANGED and previous is not None:
            self._store.record_controller_event(
                run_id,
                previous_controller=previous.controller_name,
                current_controller=current.controller_name,
                reason="CURRENT_SWITCH_CHANGED",
                occurred_at=event.occurred_at,
            )

    def _detach_monitor_locked(self) -> str | None:
        run_id = self._monitor_run_id
        self._monitor = None
        self._monitor_signature = None
        self._monitor_run_id = None
        self._monitor_stop_requested = False
        return run_id

    def _finish_stopped_run(self, run_id: str) -> None:
        try:
            self._store.finish_run(run_id, status="STOPPED")
        except Exception as exc:
            self.last_shutdown_error = type(exc).__name__


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


def _delta(current: int | None, previous: int | None) -> int | None:
    if current is None or previous is None:
        return None
    return current - previous


def _one_shot_status(outcome: QueryOutcome) -> str:
    if outcome.cancelled:
        return "CANCELLED"
    if outcome.authoritative:
        return "COMPLETED"
    failed_codes = {
        ErrorCode.AUTH_FAILED,
        ErrorCode.HOST_KEY_CHANGED,
        ErrorCode.HOST_KEY_UNKNOWN,
        ErrorCode.MM_UNREACHABLE,
        ErrorCode.PROMPT_PARSE_FAILED,
    }
    if any(diagnostic.code in failed_codes for diagnostic in outcome.diagnostics):
        return "FAILED"
    return "PARTIAL"
