"""Deterministic session lifecycle monitoring over :mod:`services.tracker`."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum

from aruba_session_tracker.collectors import (
    POLL_DEADLINE_SECONDS,
    CancellationToken,
    PollDeadline,
)
from aruba_session_tracker.models import (
    Credentials,
    DeviceTarget,
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)

from .tracker import (
    MAX_POLL_OBSERVATIONS,
    FullScanApproval,
    LocationSnapshot,
    PollBudget,
    QueryOutcome,
    RawSnapshot,
    TrackerService,
)

_LOGGER = logging.getLogger(__name__)
_TRANSIENT_BACKOFF_SECONDS = (5, 10, 20, 40, 80, 160, 300)


class MonitorDaemonError(RuntimeError):
    """Sanitized terminal failure retained by the optional daemon runner."""

    def __init__(self, exception_type: str, code: str | None = None) -> None:
        self.exception_type = exception_type
        self.code = code
        detail = f" ({code})" if code is not None else ""
        super().__init__(f"Monitor daemon stopped: {exception_type}{detail}")


class LifecycleEventType(StrEnum):
    STARTED = "STARTED"
    OBSERVED = "OBSERVED"
    MISSED = "MISSED"
    CLOSED = "CLOSED"
    CONTROLLER_CHANGED = "CONTROLLER_CHANGED"
    FLAGS_CHANGED = "FLAGS_CHANGED"
    COUNTERS_CHANGED = "COUNTERS_CHANGED"


@dataclass(frozen=True, slots=True)
class SessionInstance:
    instance_id: str
    flow_key: str
    first_seen: datetime
    last_seen: datetime
    miss_count: int
    observation: SessionObservation


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    event_type: LifecycleEventType
    instance_id: str
    observation: SessionObservation
    previous_observation: SessionObservation | None = None
    miss_count: int = 0
    occurred_at: datetime = field(default_factory=lambda: datetime.min.replace(tzinfo=UTC))


@dataclass(frozen=True, slots=True)
class MonitorPollResult:
    outcome: QueryOutcome
    events: tuple[LifecycleEvent, ...]
    active_sessions: tuple[SessionInstance, ...]
    consecutive_misses: int
    refreshed_location: bool
    consecutive_transient_failures: int
    retry_after_seconds: int

    @property
    def observations(self) -> tuple[SessionObservation, ...]:
        return self.outcome.observations

    @property
    def diagnostics(self) -> tuple[DiagnosticEvent, ...]:
        return self.outcome.diagnostics

    @property
    def used_mm(self) -> str | None:
        return self.outcome.used_mm

    @property
    def controllers(self) -> tuple[str, ...]:
        return self.outcome.controllers

    @property
    def raw_snapshots(self) -> tuple[RawSnapshot, ...]:
        return self.outcome.raw_snapshots

    @property
    def authoritative(self) -> bool:
        return self.outcome.authoritative

    @property
    def cancelled(self) -> bool:
        return self.outcome.cancelled


LifecycleCallback = Callable[[LifecycleEvent], None]
MonitorFailureCallback = Callable[[Exception], None]
MonotonicClock = Callable[[], float]
WallClock = Callable[[], datetime]


@dataclass(slots=True)
class _ActiveSession:
    instance_id: str
    flow_key: str
    first_seen: datetime
    last_seen: datetime
    miss_count: int
    observation: SessionObservation
    controller_observations: dict[str, SessionObservation]
    confirmed_controller_observation: SessionObservation | None

    def snapshot(self) -> SessionInstance:
        return SessionInstance(
            instance_id=self.instance_id,
            flow_key=self.flow_key,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            miss_count=self.miss_count,
            observation=self.observation,
        )


@dataclass(slots=True)
class _PreparedMonitorPoll:
    owner_id: int
    generation: int
    location_epoch: int
    result: MonitorPollResult
    location_snapshot: LocationSnapshot | None
    last_location_refresh: float | None
    consecutive_misses: int
    consecutive_transient_failures: int
    active: dict[str, _ActiveSession]
    fallback_devices: tuple[DeviceTarget, ...]


class MonitorEngine:
    """Poll at MD cadence, refresh MM at location cadence, and emit lifecycle events."""

    def __init__(
        self,
        service: TrackerService,
        request: QueryRequest,
        credentials: Credentials,
        callbacks: LifecycleCallback | None = None,
        *,
        failure_callback: MonitorFailureCallback | None = None,
        full_scan_approval: FullScanApproval | None = None,
        monotonic_clock: MonotonicClock = time.monotonic,
        wall_clock: WallClock | None = None,
    ) -> None:
        self._service = service
        self._request = request
        self._credentials = credentials
        self._callback = callbacks
        self._failure_callback = failure_callback
        self._full_scan_approval = full_scan_approval
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._location_snapshot: LocationSnapshot | None = None
        self._last_location_refresh: float | None = None
        self._location_epoch = 0
        self._consecutive_misses = 0
        self._consecutive_transient_failures = 0
        self._active: dict[str, _ActiveSession] = {}
        self._fallback_devices: tuple[DeviceTarget, ...] = ()
        self._thread: threading.Thread | None = None
        self._cancel_token: CancellationToken | None = None
        self._lock = threading.RLock()
        self._last_result: MonitorPollResult | None = None
        self._last_error: MonitorDaemonError | None = None
        self._prepare_generation = 0
        self._prepared_generation: int | None = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    @property
    def last_result(self) -> MonitorPollResult | None:
        with self._lock:
            return self._last_result

    @property
    def last_error(self) -> MonitorDaemonError | None:
        with self._lock:
            return self._last_error

    def invalidate_location(self) -> None:
        """Discard cached MM routing without racing an in-flight prepared poll."""

        with self._lock:
            self._location_epoch += 1
            self._location_snapshot = None
            self._last_location_refresh = None
            self._fallback_devices = ()

    def poll_once(self, *, cancel_token: CancellationToken | None = None) -> MonitorPollResult:
        prepared = self._prepare_for_persistence(cancel_token=cancel_token)
        try:
            return self._commit_prepared(prepared)
        except BaseException:
            self._discard_prepared(prepared)
            raise

    def _prepare_for_persistence(
        self,
        *,
        cancel_token: CancellationToken | None = None,
    ) -> _PreparedMonitorPoll:
        """Query and calculate a poll without changing committed monitor state."""
        token = cancel_token or CancellationToken()
        with self._lock:
            if self._prepared_generation is not None:
                raise RuntimeError("모니터링 조회가 이미 진행 중입니다.")
            self._prepare_generation += 1
            generation = self._prepare_generation
            self._prepared_generation = generation
            location_epoch = self._location_epoch
            location_snapshot = self._location_snapshot
            last_location_refresh = self._last_location_refresh
            consecutive_misses = self._consecutive_misses
            consecutive_transient_failures = self._consecutive_transient_failures
            active = _clone_active(self._active)
            fallback_devices = self._fallback_devices

        try:
            return self._calculate_prepared_poll(
                token,
                generation=generation,
                location_epoch=location_epoch,
                location_snapshot=location_snapshot,
                last_location_refresh=last_location_refresh,
                consecutive_misses=consecutive_misses,
                consecutive_transient_failures=consecutive_transient_failures,
                active=active,
                fallback_devices=fallback_devices,
            )
        except BaseException:
            with self._lock:
                if self._prepared_generation == generation:
                    self._prepared_generation = None
            raise

    def _calculate_prepared_poll(
        self,
        token: CancellationToken,
        *,
        generation: int,
        location_epoch: int,
        location_snapshot: LocationSnapshot | None,
        last_location_refresh: float | None,
        consecutive_misses: int,
        consecutive_transient_failures: int,
        active: dict[str, _ActiveSession],
        fallback_devices: tuple[DeviceTarget, ...],
    ) -> _PreparedMonitorPoll:
        now_monotonic = self._monotonic_clock()
        deadline = PollDeadline(now_monotonic + POLL_DEADLINE_SECONDS, self._monotonic_clock)
        poll_budget = PollBudget()
        refresh = (
            location_snapshot is None
            or last_location_refresh is None
            or now_monotonic - last_location_refresh
            >= self._service.config.location_interval_seconds
        )
        required_controller_hosts = tuple(
            dict.fromkeys(
                controller_host
                for item in active.values()
                for controller_host in item.controller_observations
            )
        )
        outcome = self._query(
            token,
            refresh=refresh,
            location_snapshot=location_snapshot,
            allow_full_scan=refresh,
            fallback_devices=() if refresh else fallback_devices,
            required_controller_hosts=required_controller_hosts,
            poll_budget=poll_budget,
            deadline=deadline,
        )
        if refresh and outcome.used_mm is not None:
            location_snapshot = outcome.location_snapshot
            last_location_refresh = self._monotonic_clock()
            fallback_devices = self._matched_fallback_devices(outcome)

        if outcome.authoritative:
            observed_flows = {_flow_key(item) for item in outcome.observations}
            second_miss_pending = any(
                flow_key not in observed_flows and item.miss_count + 1 == 2
                for flow_key, item in active.items()
            )
            # Refresh MM on the second authoritative MISS of any active flow.
            # This also covers a moved flow while another matched flow remains.
            if second_miss_pending and not refresh:
                refreshed = self._query(
                    token,
                    refresh=True,
                    location_snapshot=location_snapshot,
                    allow_full_scan=True,
                    fallback_devices=(),
                    required_controller_hosts=required_controller_hosts,
                    poll_budget=poll_budget,
                    deadline=deadline,
                )
                outcome = _merge_outcomes(outcome, refreshed)
                refresh = True
                if refreshed.used_mm is not None:
                    location_snapshot = refreshed.location_snapshot
                    last_location_refresh = self._monotonic_clock()
                    fallback_devices = self._matched_fallback_devices(refreshed)

        outcome = _with_controller_overlap_diagnostic(outcome)
        events: list[LifecycleEvent] = []
        observed_flows = {_flow_key(item) for item in outcome.observations}
        prospective_flows = set(active) | observed_flows
        if len(prospective_flows) > MAX_POLL_OBSERVATIONS:
            outcome = replace(
                outcome,
                diagnostics=(
                    *outcome.diagnostics,
                    DiagnosticEvent(
                        stage="MONITOR_STATE",
                        code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                        message=(
                            "모니터링 활성 상태 한도를 초과하여 미관측 상태를 종료 판정 없이 "
                            "폐기하고 현재 관측 상태로 복구했습니다."
                        ),
                    ),
                ),
                authoritative=False,
            )
            # Current positive observations remain useful. Reconcile to those
            # bounded flows while dropping stale state without emitting a
            # potentially false MISS/CLOSED event.
            events.extend(
                self._apply_observations(
                    active,
                    outcome.observations,
                    absence_is_authoritative=False,
                )
            )
            for flow_key in tuple(active):
                if flow_key not in observed_flows:
                    del active[flow_key]
            if outcome.observations:
                consecutive_misses = 0
        else:
            if outcome.observations:
                consecutive_misses = 0
            elif outcome.authoritative:
                consecutive_misses += 1
            # Positive observations are useful even from a partial multi-device
            # poll; only an authoritative absence may advance MISS/CLOSED state.
            events.extend(
                self._apply_observations(
                    active,
                    outcome.observations,
                    absence_is_authoritative=outcome.authoritative,
                )
            )

        has_transient_failure = any(
            event.transient and not event.recovered for event in outcome.diagnostics
        )
        if has_transient_failure:
            consecutive_transient_failures += 1
            retry_after_seconds = _transient_backoff(consecutive_transient_failures)
        else:
            consecutive_transient_failures = 0
            retry_after_seconds = 0
        result = MonitorPollResult(
            outcome=outcome,
            events=tuple(events),
            active_sessions=tuple(item.snapshot() for item in active.values()),
            consecutive_misses=consecutive_misses,
            refreshed_location=refresh,
            consecutive_transient_failures=consecutive_transient_failures,
            retry_after_seconds=retry_after_seconds,
        )
        return _PreparedMonitorPoll(
            owner_id=id(self),
            generation=generation,
            location_epoch=location_epoch,
            result=result,
            location_snapshot=location_snapshot,
            last_location_refresh=last_location_refresh,
            consecutive_misses=consecutive_misses,
            consecutive_transient_failures=consecutive_transient_failures,
            active=active,
            fallback_devices=fallback_devices,
        )

    def _commit_prepared(self, prepared: _PreparedMonitorPoll) -> MonitorPollResult:
        """Commit exactly the poll prepared by this engine and emit its callbacks."""
        with self._lock:
            self._validate_prepared_locked(prepared)
            if prepared.location_epoch == self._location_epoch:
                self._location_snapshot = prepared.location_snapshot
                self._last_location_refresh = prepared.last_location_refresh
                self._fallback_devices = prepared.fallback_devices
            self._consecutive_misses = prepared.consecutive_misses
            self._consecutive_transient_failures = prepared.consecutive_transient_failures
            self._active = prepared.active
            self._last_result = prepared.result
            self._last_error = None
        try:
            for event in prepared.result.events:
                if self._callback is not None:
                    try:
                        self._callback(event)
                    except Exception as exc:
                        # Persistence and monitor state are already committed.  A
                        # notification consumer must not turn that successful
                        # poll into an apparent failure or make it replayable.
                        _LOGGER.warning(
                            "Lifecycle callback failed after commit (%s).",
                            type(exc).__name__,
                        )
            return prepared.result
        finally:
            with self._lock:
                if self._prepared_generation == prepared.generation:
                    self._prepared_generation = None

    def _discard_prepared(self, prepared: _PreparedMonitorPoll) -> None:
        """Release an uncommitted poll after persistence or caller failure."""
        with self._lock:
            if prepared.owner_id != id(self):
                raise RuntimeError("다른 모니터링 실행의 조회 결과입니다.")
            if self._prepared_generation == prepared.generation:
                self._prepared_generation = None

    def _validate_prepared_locked(self, prepared: _PreparedMonitorPoll) -> None:
        if prepared.owner_id != id(self) or self._prepared_generation != prepared.generation:
            raise RuntimeError("현재 모니터링 조회와 일치하지 않는 결과입니다.")

    def run(self, cancel_token: CancellationToken | None = None) -> None:
        token = cancel_token or CancellationToken()
        current_thread = threading.current_thread()
        try:
            while not token.is_cancelled:
                result = self.poll_once(cancel_token=token)
                wait_seconds = (
                    result.retry_after_seconds
                    if result.retry_after_seconds > 0
                    else self._service.config.session_interval_seconds
                )
                if token.wait(wait_seconds):
                    break
        except Exception as exc:
            failure = _sanitize_daemon_failure(exc)
            with self._lock:
                self._last_error = failure
            if self._failure_callback is not None:
                try:
                    self._failure_callback(failure)
                except Exception as callback_exc:
                    _LOGGER.warning(
                        "Monitor failure callback failed (%s).",
                        type(callback_exc).__name__,
                    )
        finally:
            with self._lock:
                if self._thread is current_thread and self._cancel_token is token:
                    self._thread = None
                    self._cancel_token = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                raise RuntimeError("모니터링이 이미 실행 중입니다.")
            token = CancellationToken()
            self._last_error = None
            thread = threading.Thread(
                target=self.run,
                args=(token,),
                name="aruba-session-monitor",
                daemon=True,
            )
            self._cancel_token = token
            self._thread = thread
            thread.start()

    def stop(self, *, wait: bool = True, timeout: float = 10.0) -> None:
        with self._lock:
            token = self._cancel_token
            thread = self._thread
        if token is not None:
            token.cancel()
        if wait and thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        with self._lock:
            if thread is not None and self._thread is thread and not thread.is_alive():
                self._thread = None
                if self._cancel_token is token:
                    self._cancel_token = None

    def _query(
        self,
        token: CancellationToken,
        *,
        refresh: bool,
        location_snapshot: LocationSnapshot | None,
        allow_full_scan: bool,
        fallback_devices: tuple[DeviceTarget, ...],
        required_controller_hosts: tuple[str, ...],
        poll_budget: PollBudget,
        deadline: PollDeadline,
    ) -> QueryOutcome:
        return self._service.query_once(
            self._request,
            self._credentials,
            full_scan_approval=self._full_scan_approval,
            cancel_token=token,
            location_snapshot=location_snapshot,
            refresh_locations=refresh,
            allow_full_scan=allow_full_scan,
            fallback_devices=fallback_devices,
            required_controller_hosts=required_controller_hosts,
            poll_budget=poll_budget,
            deadline=deadline,
        )

    def _matched_fallback_devices(self, outcome: QueryOutcome) -> tuple[DeviceTarget, ...]:
        if not outcome.full_scan_eligible:
            return ()
        matched_hosts = {item.controller_host for item in outcome.observations}
        return tuple(
            device
            for device in self._service.config.managed_devices
            if device.enabled and device.host in matched_hosts
        )

    def _apply_observations(
        self,
        active_sessions: dict[str, _ActiveSession],
        observations: tuple[SessionObservation, ...],
        *,
        absence_is_authoritative: bool,
    ) -> list[LifecycleEvent]:
        observed_by_flow = _group_observations_by_flow(observations)
        now = self._wall_clock()
        events: list[LifecycleEvent] = []

        for flow_key, current_controller_observations in observed_by_flow.items():
            active = active_sessions.get(flow_key)
            if active is None:
                observation = _representative_observation(current_controller_observations)
                confirmed = (
                    observation
                    if absence_is_authoritative and len(current_controller_observations) == 1
                    else None
                )
                active = _ActiveSession(
                    instance_id=str(uuid.uuid4()),
                    flow_key=flow_key,
                    first_seen=now,
                    last_seen=now,
                    miss_count=0,
                    observation=observation,
                    controller_observations=dict(current_controller_observations),
                    confirmed_controller_observation=confirmed,
                )
                active_sessions[flow_key] = active
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.STARTED,
                        active.instance_id,
                        observation,
                        occurred_at=now,
                    )
                )
                continue

            previous = active.observation
            previous_confirmed = active.confirmed_controller_observation
            previous_miss_count = active.miss_count
            if absence_is_authoritative:
                active.controller_observations = dict(current_controller_observations)
            else:
                # A failed required-controller query cannot prove that its last
                # positive observation disappeared.  Retain that controller in
                # the next poll scope while merging every new positive result.
                active.controller_observations.update(current_controller_observations)

            preferred_host = (
                previous_confirmed.controller_host
                if previous_confirmed is not None
                and previous_confirmed.controller_host in current_controller_observations
                else previous.controller_host
                if previous.controller_host in current_controller_observations
                else None
            )
            observation = _representative_observation(
                current_controller_observations,
                preferred_host=preferred_host,
            )
            active.observation = observation
            active.last_seen = now
            active.miss_count = 0
            if previous_miss_count > 0:
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.OBSERVED,
                        active.instance_id,
                        observation,
                        previous_observation=previous,
                        occurred_at=now,
                    )
                )

            # Only an authoritative singleton can establish controller
            # ownership.  An overlap (or any partial poll) remains positive
            # evidence but must not manufacture a controller transition.
            confirmed_transition = (
                previous_confirmed
                if absence_is_authoritative and len(current_controller_observations) == 1
                else None
            )
            if (
                confirmed_transition is not None
                and confirmed_transition.controller_host != observation.controller_host
            ):
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.CONTROLLER_CHANGED,
                        active.instance_id,
                        observation,
                        previous_observation=confirmed_transition,
                        occurred_at=now,
                    )
                )
            if confirmed_transition is not None and confirmed_transition.flags != observation.flags:
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.FLAGS_CHANGED,
                        active.instance_id,
                        observation,
                        previous_observation=confirmed_transition,
                        occurred_at=now,
                    )
                )
            if confirmed_transition is not None and _counter_reset_or_identity_changed(
                confirmed_transition, observation
            ):
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.COUNTERS_CHANGED,
                        active.instance_id,
                        observation,
                        previous_observation=confirmed_transition,
                        occurred_at=now,
                    )
                )

            if absence_is_authoritative and len(current_controller_observations) == 1:
                active.confirmed_controller_observation = observation
            elif (
                previous_confirmed is not None
                and previous_confirmed.controller_host in current_controller_observations
            ):
                # Refresh the baseline for the previously confirmed owner while
                # deliberately keeping ownership unresolved during overlap.
                active.confirmed_controller_observation = current_controller_observations[
                    previous_confirmed.controller_host
                ]

        for flow_key, active in tuple(active_sessions.items()):
            if flow_key in observed_by_flow:
                continue
            if not absence_is_authoritative:
                continue
            active.miss_count += 1
            event_type = (
                LifecycleEventType.CLOSED
                if active.miss_count >= self._service.config.close_after_misses
                else LifecycleEventType.MISSED
            )
            events.append(
                LifecycleEvent(
                    event_type,
                    active.instance_id,
                    active.observation,
                    miss_count=active.miss_count,
                    occurred_at=now,
                )
            )
            if event_type == LifecycleEventType.CLOSED:
                del active_sessions[flow_key]
        return events


def _sanitize_daemon_failure(exc: Exception) -> MonitorDaemonError:
    raw_code = getattr(exc, "code", None)
    code = raw_code.value if isinstance(raw_code, ErrorCode) else None
    return MonitorDaemonError(type(exc).__name__, code)


def _clone_active(active: dict[str, _ActiveSession]) -> dict[str, _ActiveSession]:
    return {
        flow_key: _ActiveSession(
            instance_id=item.instance_id,
            flow_key=item.flow_key,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            miss_count=item.miss_count,
            observation=item.observation,
            controller_observations=dict(item.controller_observations),
            confirmed_controller_observation=item.confirmed_controller_observation,
        )
        for flow_key, item in active.items()
    }


def _counter_reset_or_identity_changed(
    previous: SessionObservation,
    current: SessionObservation,
) -> bool:
    """Keep lifecycle counter events for resets, not routine monotonic increments."""

    if previous.counter != current.counter:
        return True
    return any(
        prior is not None and latest is not None and latest < prior
        for prior, latest in (
            (previous.packets, current.packets),
            (previous.bytes_count, current.bytes_count),
        )
    )


def _flow_key(observation: SessionObservation) -> str:
    """Identity excludes controller so a move is an event, not a new session."""
    return "|".join(
        (
            str(observation.protocol),
            observation.source_ip,
            observation.destination_ip,
            str(observation.source_port),
            str(observation.destination_port),
        )
    )


def _group_observations_by_flow(
    observations: tuple[SessionObservation, ...],
) -> dict[str, dict[str, SessionObservation]]:
    grouped: dict[str, dict[str, SessionObservation]] = {}
    for observation in observations:
        grouped.setdefault(_flow_key(observation), {})[observation.controller_host] = observation
    return grouped


def _representative_observation(
    controller_observations: dict[str, SessionObservation],
    *,
    preferred_host: str | None = None,
) -> SessionObservation:
    if preferred_host is not None and preferred_host in controller_observations:
        return controller_observations[preferred_host]
    return min(
        controller_observations.values(),
        key=lambda item: (item.controller_host, item.controller_name, item.session_key),
    )


def _with_controller_overlap_diagnostic(outcome: QueryOutcome) -> QueryOutcome:
    overlaps = any(
        len(controller_observations) > 1
        for controller_observations in _group_observations_by_flow(outcome.observations).values()
    )
    if not overlaps or any(
        item.code is ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS for item in outcome.diagnostics
    ):
        return outcome
    return replace(
        outcome,
        diagnostics=(
            *outcome.diagnostics,
            DiagnosticEvent(
                stage="MONITOR_STATE",
                code=ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS,
                message=(
                    "동일 흐름이 여러 MD에서 동시에 관측되어 Controller 변경 확정을 보류했습니다."
                ),
            ),
        ),
    )


def _merge_outcomes(first: QueryOutcome, second: QueryOutcome) -> QueryOutcome:
    """Retain first-pass evidence while the refreshed pass determines authority/data."""
    second_flow_keys = {_flow_key(item) for item in second.observations}
    observations = {
        item.session_key: item
        for item in first.observations
        if _flow_key(item) not in second_flow_keys
    }
    second_observations = {item.session_key: item for item in second.observations}
    superseded_keys = {
        item.session_key for item in first.observations if _flow_key(item) in second_flow_keys
    }
    observations.update(second_observations)
    first_remaining = {item.session_key: item for item in first.observations}
    first_raw_snapshots: list[RawSnapshot] = []
    for snapshot in first.raw_snapshots:
        keys = snapshot.observation_keys
        if keys is None:
            keys = tuple(
                key
                for key, item in first_remaining.items()
                if item.controller_name == snapshot.device_name
            )
        for key in keys:
            first_remaining.pop(key, None)
        first_raw_snapshots.append(
            replace(
                snapshot,
                observation_keys=tuple(key for key in keys if key not in superseded_keys),
            )
        )
    return QueryOutcome(
        observations=tuple(observations.values()),
        diagnostics=tuple(
            replace(event, recovered=True) if second.authoritative and event.transient else event
            for event in first.diagnostics
        )
        + second.diagnostics,
        used_mm=second.used_mm or first.used_mm,
        controllers=tuple(dict.fromkeys(first.controllers + second.controllers)),
        raw_snapshots=tuple(first_raw_snapshots) + second.raw_snapshots,
        source_location=second.source_location,
        destination_location=second.destination_location,
        full_scan_eligible=second.full_scan_eligible,
        authoritative=second.authoritative,
    )


def _transient_backoff(consecutive_failures: int) -> int:
    index = max(0, min(consecutive_failures - 1, len(_TRANSIENT_BACKOFF_SECONDS) - 1))
    return _TRANSIENT_BACKOFF_SECONDS[index]
