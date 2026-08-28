"""Deterministic session lifecycle monitoring over :mod:`services.tracker`."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from aruba_session_tracker.collectors import CancellationToken
from aruba_session_tracker.models import (
    Credentials,
    DiagnosticEvent,
    QueryRequest,
    SessionObservation,
)

from .tracker import (
    FullScanApproval,
    LocationSnapshot,
    QueryOutcome,
    RawSnapshot,
    TrackerService,
)


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

    def snapshot(self) -> SessionInstance:
        return SessionInstance(
            instance_id=self.instance_id,
            flow_key=self.flow_key,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            miss_count=self.miss_count,
            observation=self.observation,
        )


class MonitorEngine:
    """Poll at MD cadence, refresh MM at location cadence, and emit lifecycle events."""

    def __init__(
        self,
        service: TrackerService,
        request: QueryRequest,
        credentials: Credentials,
        callbacks: LifecycleCallback | None = None,
        *,
        full_scan_approval: FullScanApproval | None = None,
        monotonic_clock: MonotonicClock = time.monotonic,
        wall_clock: WallClock | None = None,
    ) -> None:
        self._service = service
        self._request = request
        self._credentials = credentials
        self._callback = callbacks
        self._full_scan_approval = full_scan_approval
        self._monotonic_clock = monotonic_clock
        self._wall_clock = wall_clock or (lambda: datetime.now(UTC))
        self._location_snapshot: LocationSnapshot | None = None
        self._last_location_refresh: float | None = None
        self._consecutive_misses = 0
        self._active: dict[str, _ActiveSession] = {}
        self._thread: threading.Thread | None = None
        self._cancel_token: CancellationToken | None = None
        self._lock = threading.RLock()
        self._last_result: MonitorPollResult | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_result(self) -> MonitorPollResult | None:
        with self._lock:
            return self._last_result

    def poll_once(self, *, cancel_token: CancellationToken | None = None) -> MonitorPollResult:
        token = cancel_token or CancellationToken()
        now_monotonic = self._monotonic_clock()
        refresh = (
            self._location_snapshot is None
            or self._last_location_refresh is None
            or now_monotonic - self._last_location_refresh
            >= self._service.config.location_interval_seconds
        )
        outcome = self._query(token, refresh=refresh)
        if refresh and outcome.used_mm is not None:
            self._remember_locations(outcome, now_monotonic)

        if outcome.authoritative:
            observed_flows = {_flow_key(item) for item in outcome.observations}
            second_miss_pending = any(
                flow_key not in observed_flows and active.miss_count + 1 == 2
                for flow_key, active in self._active.items()
            )
            # Refresh MM on the second authoritative MISS of any active flow.
            # This also covers a moved flow while another matched flow remains.
            if second_miss_pending and not refresh:
                refreshed = self._query(token, refresh=True)
                outcome = _merge_outcomes(outcome, refreshed)
                refresh = True
                if refreshed.used_mm is not None:
                    self._remember_locations(refreshed, now_monotonic)

        events: list[LifecycleEvent] = []
        if outcome.observations:
            self._consecutive_misses = 0
        elif outcome.authoritative:
            self._consecutive_misses += 1
        # Positive observations are useful even from a partial multi-device
        # poll; only an authoritative absence may advance MISS/CLOSED state.
        events.extend(
            self._apply_observations(
                outcome.observations,
                absence_is_authoritative=outcome.authoritative,
            )
        )

        for event in events:
            if self._callback is not None:
                self._callback(event)

        result = MonitorPollResult(
            outcome=outcome,
            events=tuple(events),
            active_sessions=tuple(item.snapshot() for item in self._active.values()),
            consecutive_misses=self._consecutive_misses,
            refreshed_location=refresh,
        )
        with self._lock:
            self._last_result = result
        return result

    def run(self, cancel_token: CancellationToken | None = None) -> None:
        token = cancel_token or CancellationToken()
        while not token.is_cancelled:
            self.poll_once(cancel_token=token)
            if token.wait(self._service.config.session_interval_seconds):
                break

    def start(self) -> None:
        with self._lock:
            if self.is_running:
                raise RuntimeError("모니터링이 이미 실행 중입니다.")
            token = CancellationToken()
            self._cancel_token = token
            self._thread = threading.Thread(
                target=self.run,
                args=(token,),
                name="aruba-session-monitor",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, wait: bool = True, timeout: float = 10.0) -> None:
        with self._lock:
            token = self._cancel_token
            thread = self._thread
        if token is not None:
            token.cancel()
        if wait and thread is not None and thread is not threading.current_thread():
            thread.join(timeout)

    def _query(self, token: CancellationToken, *, refresh: bool) -> QueryOutcome:
        return self._service.query_once(
            self._request,
            self._credentials,
            full_scan_approval=self._full_scan_approval,
            cancel_token=token,
            location_snapshot=self._location_snapshot,
            refresh_locations=refresh,
        )

    def _remember_locations(self, outcome: QueryOutcome, refreshed_at: float) -> None:
        self._location_snapshot = outcome.location_snapshot
        self._last_location_refresh = refreshed_at

    def _apply_observations(
        self,
        observations: tuple[SessionObservation, ...],
        *,
        absence_is_authoritative: bool,
    ) -> list[LifecycleEvent]:
        observed_by_flow = {_flow_key(item): item for item in observations}
        now = self._wall_clock()
        events: list[LifecycleEvent] = []

        for flow_key, observation in observed_by_flow.items():
            active = self._active.get(flow_key)
            if active is None:
                active = _ActiveSession(
                    instance_id=str(uuid.uuid4()),
                    flow_key=flow_key,
                    first_seen=now,
                    last_seen=now,
                    miss_count=0,
                    observation=observation,
                )
                self._active[flow_key] = active
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
            active.observation = observation
            active.last_seen = now
            active.miss_count = 0
            events.append(
                LifecycleEvent(
                    LifecycleEventType.OBSERVED,
                    active.instance_id,
                    observation,
                    previous_observation=previous,
                    occurred_at=now,
                )
            )
            if previous.controller_host != observation.controller_host:
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.CONTROLLER_CHANGED,
                        active.instance_id,
                        observation,
                        previous_observation=previous,
                        occurred_at=now,
                    )
                )
            if previous.flags != observation.flags:
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.FLAGS_CHANGED,
                        active.instance_id,
                        observation,
                        previous_observation=previous,
                        occurred_at=now,
                    )
                )
            if (previous.packets, previous.bytes_count, previous.counter) != (
                observation.packets,
                observation.bytes_count,
                observation.counter,
            ):
                events.append(
                    LifecycleEvent(
                        LifecycleEventType.COUNTERS_CHANGED,
                        active.instance_id,
                        observation,
                        previous_observation=previous,
                        occurred_at=now,
                    )
                )

        for flow_key, active in tuple(self._active.items()):
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
                del self._active[flow_key]
        return events


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


def _merge_outcomes(first: QueryOutcome, second: QueryOutcome) -> QueryOutcome:
    """Retain first-pass evidence while the refreshed pass determines authority/data."""
    observations = {_flow_key(item): item for item in first.observations}
    observations.update({_flow_key(item): item for item in second.observations})
    return QueryOutcome(
        observations=tuple(observations.values()),
        diagnostics=first.diagnostics + second.diagnostics,
        used_mm=second.used_mm or first.used_mm,
        controllers=tuple(dict.fromkeys(first.controllers + second.controllers)),
        raw_snapshots=first.raw_snapshots + second.raw_snapshots,
        source_location=second.source_location,
        destination_location=second.destination_location,
        full_scan_eligible=second.full_scan_eligible,
        authoritative=second.authoritative,
    )
