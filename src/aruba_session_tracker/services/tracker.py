"""Fail-closed MM-to-MD session query orchestration."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    HostKeyApproval,
    PollDeadline,
    SSHCollector,
    SSHConnectionFactory,
    run_bounded_approval,
)
from aruba_session_tracker.commands import (
    NO_PAGING_COMMAND,
    build_datapath_session_command,
    build_global_user_command,
)
from aruba_session_tracker.models import (
    AppConfig,
    ControllerLocation,
    Credentials,
    DeviceTarget,
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.parsers import (
    GlobalUserStatus,
    ParseError,
    parse_datapath_sessions,
    parse_global_user_table,
)

FullScanApproval = (
    Callable[[QueryRequest, tuple[DeviceTarget, ...]], bool]
    | Callable[[QueryRequest, tuple[DeviceTarget, ...], PollDeadline], bool]
)
ProgressCallback = Callable[[str, str], None]
MAX_POLL_RAW_BYTES = 32 * 1024 * 1024
MAX_POLL_OBSERVATIONS = 20_000


@dataclass(slots=True)
class PollBudget:
    """Aggregate in-memory limits shared by every query pass in one poll."""

    max_raw_bytes: int = MAX_POLL_RAW_BYTES
    max_observations: int = MAX_POLL_OBSERVATIONS
    raw_bytes: int = 0
    observations: int = 0

    def __post_init__(self) -> None:
        for name, value in (
            ("max_raw_bytes", self.max_raw_bytes),
            ("max_observations", self.max_observations),
            ("raw_bytes", self.raw_bytes),
            ("observations", self.observations),
        ):
            if type(value) is not int:
                raise TypeError(f"{name} must be an integer.")
        if self.max_raw_bytes < 1 or self.max_observations < 1:
            raise ValueError("Poll budget limits must be positive.")
        if self.max_raw_bytes > MAX_POLL_RAW_BYTES:
            raise ValueError("max_raw_bytes exceeds the tracker safety boundary.")
        if self.max_observations > MAX_POLL_OBSERVATIONS:
            raise ValueError("max_observations exceeds the tracker safety boundary.")
        if not 0 <= self.raw_bytes <= self.max_raw_bytes:
            raise ValueError("raw_bytes is outside the configured poll budget.")
        if not 0 <= self.observations <= self.max_observations:
            raise ValueError("observations is outside the configured poll budget.")

    @property
    def remaining_observations(self) -> int:
        return max(0, self.max_observations - self.observations)

    def consume_raw(self, output: str) -> bool:
        byte_size = len(output.encode("utf-8", errors="replace"))
        if self.raw_bytes + byte_size > self.max_raw_bytes:
            return False
        self.raw_bytes += byte_size
        return True

    def consume_observations(self, count: int) -> bool:
        if type(count) is not int:
            raise TypeError("count must be an integer.")
        if count < 0 or self.observations + count > self.max_observations:
            return False
        self.observations += count
        return True


@dataclass(slots=True)
class TrackerCallbacks:
    host_key_approval: HostKeyApproval | None = None
    full_scan_approval: FullScanApproval | None = None
    progress: ProgressCallback | None = None


@dataclass(frozen=True, slots=True)
class RawSnapshot:
    device_name: str
    command: str
    output: str = field(repr=False)
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    observation_keys: tuple[str, ...] | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass(frozen=True, slots=True)
class LocationSnapshot:
    source: ControllerLocation | None
    destination: ControllerLocation | None
    used_mm: str | None
    full_scan_eligible: bool = False
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class QueryOutcome:
    observations: tuple[SessionObservation, ...] = ()
    diagnostics: tuple[DiagnosticEvent, ...] = ()
    used_mm: str | None = None
    controllers: tuple[str, ...] = ()
    raw_snapshots: tuple[RawSnapshot, ...] = ()
    source_location: ControllerLocation | None = None
    destination_location: ControllerLocation | None = None
    full_scan_eligible: bool = False
    authoritative: bool = False

    @property
    def location_snapshot(self) -> LocationSnapshot:
        return LocationSnapshot(
            source=self.source_location,
            destination=self.destination_location,
            used_mm=self.used_mm,
            full_scan_eligible=self.full_scan_eligible,
        )

    @property
    def cancelled(self) -> bool:
        return any(event.code is ErrorCode.CANCELLED for event in self.diagnostics)


class TrackerService:
    """Resolve client locations on MM and query only relevant managed devices."""

    def __init__(
        self,
        config: AppConfig,
        ssh_factory: SSHConnectionFactory,
        callbacks: TrackerCallbacks | None = None,
        *,
        collector: SSHCollector | None = None,
    ) -> None:
        self.config = config
        self._callbacks = callbacks or TrackerCallbacks()
        self._collector = collector or SSHCollector(ssh_factory)
        self._full_scan_cursor = 0
        self._full_scan_cursor_lock = threading.Lock()

    def query_once(
        self,
        request: QueryRequest,
        credentials: Credentials,
        *,
        full_scan_approval: FullScanApproval | None = None,
        cancel_token: CancellationToken | None = None,
        location_snapshot: LocationSnapshot | None = None,
        refresh_locations: bool = True,
        allow_full_scan: bool = True,
        fallback_devices: tuple[DeviceTarget, ...] = (),
        required_controller_hosts: tuple[str, ...] = (),
        poll_budget: PollBudget | None = None,
        deadline: PollDeadline | None = None,
    ) -> QueryOutcome:
        token = cancel_token or CancellationToken()
        budget = poll_budget or PollBudget()
        poll_deadline = deadline or PollDeadline.after()
        diagnostics: list[DiagnosticEvent] = []
        raw_snapshots: list[RawSnapshot] = []
        controllers: list[str] = []
        authoritative = True

        if refresh_locations or location_snapshot is None:
            locations = self._resolve_locations(
                request,
                credentials,
                token,
                diagnostics,
                raw_snapshots,
                budget,
                poll_deadline,
            )
            if locations is None:
                return QueryOutcome(
                    diagnostics=tuple(diagnostics),
                    raw_snapshots=tuple(raw_snapshots),
                    authoritative=False,
                )
        else:
            locations = location_snapshot

        source_location = locations.source
        destination_location = locations.destination
        enabled_devices = tuple(device for device in self.config.managed_devices if device.enabled)
        required_devices: list[DeviceTarget] = []
        for host in dict.fromkeys(required_controller_hosts):
            matches = tuple(device for device in enabled_devices if device.host == host)
            if len(matches) != 1:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_ROUTE",
                        code=(
                            ErrorCode.CURRENT_SWITCH_AMBIGUOUS
                            if len(matches) > 1
                            else ErrorCode.CURRENT_SWITCH_UNMAPPED
                        ),
                        message="활성 세션을 관측한 MD를 현재 설정에 안전하게 매핑하지 못했습니다.",
                    )
                )
                return QueryOutcome(
                    diagnostics=tuple(diagnostics),
                    used_mm=locations.used_mm,
                    raw_snapshots=tuple(raw_snapshots),
                    source_location=source_location,
                    destination_location=destination_location,
                    full_scan_eligible=locations.full_scan_eligible,
                    authoritative=False,
                )
            required_devices.append(matches[0])
        device_candidates: list[tuple[DeviceTarget, str]] = []

        source_device = self._device_for_location(source_location, diagnostics)
        destination_device = self._device_for_location(destination_location, diagnostics)
        # A known-but-unmapped or ambiguous Current switch means that a
        # negative result from the remaining MD candidates cannot prove the
        # session is absent.  Keep positive evidence, but never advance the
        # monitor MISS/CLOSED state from that partial routing result.
        if any(
            event.code
            in {
                ErrorCode.CURRENT_SWITCH_AMBIGUOUS,
                ErrorCode.CURRENT_SWITCH_UNMAPPED,
            }
            for event in diagnostics
        ):
            authoritative = False
        if source_device is not None:
            device_candidates.append((source_device, request.source_ip))
        if destination_device is not None and destination_device != source_device:
            device_candidates.append((destination_device, request.destination_ip))

        # Full scan is permitted only for two explicit NOT_FOUND results.  An
        # ambiguous, malformed or unmapped location must never be upgraded to
        # permission to scan every MD.
        full_scan = locations.full_scan_eligible
        if full_scan and fallback_devices:
            requested_fallback = tuple(dict.fromkeys((*fallback_devices, *required_devices)))
            fallback = tuple(device for device in requested_fallback if device in enabled_devices)
            if len(fallback) != len(requested_fallback):
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_ROUTE",
                        code=ErrorCode.CURRENT_SWITCH_UNMAPPED,
                        message="이전 전수조회 대상이 현재 활성 MD 설정과 일치하지 않습니다.",
                    )
                )
                return QueryOutcome(
                    diagnostics=tuple(diagnostics),
                    used_mm=locations.used_mm,
                    raw_snapshots=tuple(raw_snapshots),
                    source_location=source_location,
                    destination_location=destination_location,
                    full_scan_eligible=True,
                    authoritative=False,
                )
            device_candidates = [
                (device, request.source_ip) for device in self._rotated_full_scan_devices(fallback)
            ]
        elif full_scan and allow_full_scan:
            approval = full_scan_approval or self._callbacks.full_scan_approval
            try:
                token.raise_if_cancelled()
                poll_deadline.raise_if_expired()
                approved = approval is not None and run_bounded_approval(
                    approval,
                    request,
                    enabled_devices,
                    cancel_token=token,
                    deadline=poll_deadline,
                )
                token.raise_if_cancelled()
                poll_deadline.raise_if_expired()
            except CollectorError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_SCAN",
                        code=exc.code,
                        message=str(exc),
                        transient=exc.retryable_network,
                    )
                )
                return QueryOutcome(
                    diagnostics=tuple(diagnostics),
                    used_mm=locations.used_mm,
                    raw_snapshots=tuple(raw_snapshots),
                    source_location=source_location,
                    destination_location=destination_location,
                    full_scan_eligible=locations.full_scan_eligible,
                    authoritative=False,
                )
            if not approved:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_SCAN",
                        code=ErrorCode.CLIENT_NOT_FOUND_ON_MM,
                        message=(
                            "MM에서 두 주소의 위치를 찾지 못해 전체 MD 조회를 실행하지 않았습니다."
                        ),
                    )
                )
                return QueryOutcome(
                    diagnostics=tuple(diagnostics),
                    used_mm=locations.used_mm,
                    raw_snapshots=tuple(raw_snapshots),
                    source_location=source_location,
                    destination_location=destination_location,
                    full_scan_eligible=locations.full_scan_eligible,
                    authoritative=False,
                )
            device_candidates = [
                (device, request.source_ip)
                for device in self._rotated_full_scan_devices(enabled_devices)
            ]
        elif full_scan:
            diagnostics.append(
                DiagnosticEvent(
                    stage="MD_SCAN",
                    code=ErrorCode.CLIENT_NOT_FOUND_ON_MM,
                    message="다음 MM 위치 갱신 전까지 MD 전수조회를 반복하지 않습니다.",
                )
            )
            return QueryOutcome(
                diagnostics=tuple(diagnostics),
                used_mm=locations.used_mm,
                raw_snapshots=tuple(raw_snapshots),
                source_location=source_location,
                destination_location=destination_location,
                full_scan_eligible=True,
                authoritative=False,
            )

        if not full_scan:
            candidate_devices = {device for device, _filter_ip in device_candidates}
            for device in required_devices:
                if device not in candidate_devices:
                    device_candidates.append((device, request.source_ip))
                    candidate_devices.add(device)

        if not device_candidates:
            diagnostics.append(
                DiagnosticEvent(
                    stage="MD_ROUTE",
                    code=ErrorCode.CURRENT_SWITCH_UNMAPPED,
                    message="조회할 수 있는 등록 MD를 결정하지 못했습니다.",
                )
            )
            return QueryOutcome(
                diagnostics=tuple(diagnostics),
                used_mm=locations.used_mm,
                raw_snapshots=tuple(raw_snapshots),
                source_location=source_location,
                destination_location=destination_location,
                full_scan_eligible=locations.full_scan_eligible,
                authoritative=False,
            )

        observations: dict[str, SessionObservation] = {}
        for index, (device, filter_ip) in enumerate(device_candidates):
            self._progress("MD_QUERY", device.name)
            device_deadline = (
                _fair_device_deadline(
                    poll_deadline,
                    remaining_devices=len(device_candidates) - index,
                )
                if len(device_candidates) > 1
                else poll_deadline
            )
            try:
                poll_deadline.raise_if_expired()
                batch = self._collector.collect(
                    device,
                    credentials,
                    (
                        NO_PAGING_COMMAND,
                        build_datapath_session_command(filter_ip),
                    ),
                    host_key_approval=self._callbacks.host_key_approval,
                    cancel_token=token,
                    deadline=device_deadline,
                )
            except CollectorError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_QUERY",
                        code=_md_error_code(exc),
                        message=f"선택한 MD에서 세션 출력을 수집하지 못했습니다: {exc}",
                        transient=exc.retryable_network,
                    )
                )
                authoritative = False
                if exc.code in {
                    ErrorCode.AUTH_FAILED,
                    ErrorCode.CANCELLED,
                    ErrorCode.HOST_KEY_CHANGED,
                    ErrorCode.HOST_KEY_UNKNOWN,
                }:
                    break
                if exc.code is ErrorCode.POLL_DEADLINE_EXCEEDED:
                    try:
                        poll_deadline.raise_if_expired()
                    except CollectorError:
                        break
                continue

            controllers.append(device.name)
            command = build_datapath_session_command(filter_ip)
            output = batch.output_for(command)
            if not budget.consume_raw(output):
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_COLLECT",
                        code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                        message="한 번의 조회에서 저장할 수 있는 Raw 출력 총량을 초과했습니다.",
                    )
                )
                authoritative = False
                break
            snapshot_index = len(raw_snapshots)
            raw_snapshots.append(RawSnapshot(device.name, command, output, observation_keys=()))
            try:
                parsed = parse_datapath_sessions(
                    output,
                    controller_name=device.name,
                    controller_host=device.host,
                    max_observations=budget.remaining_observations,
                )
            except ParseError as exc:
                parse_code = _parse_error_code(exc)
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_PARSE",
                        code=parse_code,
                        message=f"MD 세션 출력을 안전하게 해석하지 못했습니다: {exc}",
                    )
                )
                authoritative = False
                if parse_code is ErrorCode.OUTPUT_LIMIT_EXCEEDED:
                    break
                continue
            if not budget.consume_observations(len(parsed)):
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_PARSE",
                        code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                        message="한 번의 조회에서 처리할 수 있는 관측 수를 초과했습니다.",
                    )
                )
                authoritative = False
                break
            matched_keys: list[str] = []
            for observation in parsed:
                if request.matches(observation):
                    key = observation.session_key
                    if key not in observations:
                        observations[key] = observation
                        matched_keys.append(key)
            raw_snapshots[snapshot_index] = replace(
                raw_snapshots[snapshot_index],
                observation_keys=tuple(dict.fromkeys(matched_keys)),
            )

        if not observations and authoritative:
            diagnostics.append(
                DiagnosticEvent(
                    stage="MD_FILTER",
                    code=ErrorCode.SESSION_NOT_FOUND,
                    message="요청 조건과 일치하는 세션을 찾지 못했습니다.",
                )
            )

        return QueryOutcome(
            observations=tuple(observations.values()),
            diagnostics=tuple(diagnostics),
            used_mm=locations.used_mm,
            controllers=tuple(controllers),
            raw_snapshots=tuple(raw_snapshots),
            source_location=source_location,
            destination_location=destination_location,
            full_scan_eligible=locations.full_scan_eligible,
            authoritative=authoritative,
        )

    def _resolve_locations(
        self,
        request: QueryRequest,
        credentials: Credentials,
        token: CancellationToken,
        diagnostics: list[DiagnosticEvent],
        raw_snapshots: list[RawSnapshot],
        budget: PollBudget,
        deadline: PollDeadline,
    ) -> LocationSnapshot | None:
        commands: tuple[str, ...] = (
            NO_PAGING_COMMAND,
            build_global_user_command(request.source_ip),
            build_global_user_command(request.destination_ip),
        )
        # Preserve order while avoiding duplicate commands for equal addresses.
        commands = tuple(dict.fromkeys(commands))
        batch = None
        selected_mm: DeviceTarget | None = None
        selected_index: int | None = None
        for index, target in enumerate((self.config.mm_primary, self.config.mm_standby)):
            if not target.enabled:
                continue
            if index > 0:
                self._progress("MM_FAILOVER", target.name)
            else:
                self._progress("MM_QUERY", target.name)
            try:
                deadline.raise_if_expired()
                batch = self._collector.collect(
                    target,
                    credentials,
                    commands,
                    host_key_approval=self._callbacks.host_key_approval,
                    cancel_token=token,
                    deadline=deadline,
                )
                selected_mm = target
                selected_index = index
                break
            except CollectorError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MM_QUERY",
                        code=exc.code,
                        message=f"MM 조회 실패: {exc}",
                        transient=exc.retryable_network,
                    )
                )
                if exc.code is ErrorCode.POLL_DEADLINE_EXCEEDED:
                    return None
                # Authentication, cancellation and host-key failures must never be bypassed.
                if not exc.retryable_network or index > 0:
                    return None
        if batch is None or selected_mm is None:
            if not diagnostics:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MM_QUERY",
                        code=ErrorCode.MM_UNREACHABLE,
                        message="사용 가능한 MM이 없습니다.",
                    )
                )
            return None

        if selected_index is not None and selected_index > 0:
            diagnostics[:] = [
                replace(event, recovered=True)
                if event.stage == "MM_QUERY" and event.transient
                else event
                for event in diagnostics
            ]

        resolved: list[ControllerLocation | None] = []
        not_found: list[bool] = []
        for client_ip in (request.source_ip, request.destination_ip):
            command = build_global_user_command(client_ip)
            output = batch.output_for(command)
            if not budget.consume_raw(output):
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MM_COLLECT",
                        code=ErrorCode.OUTPUT_LIMIT_EXCEEDED,
                        message="한 번의 조회에서 저장할 수 있는 Raw 출력 총량을 초과했습니다.",
                    )
                )
                return None
            raw_snapshots.append(
                RawSnapshot(selected_mm.name, command, output, observation_keys=())
            )
            try:
                lookup = parse_global_user_table(output, client_ip=client_ip)
            except ParseError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MM_PARSE",
                        code=_parse_error_code(exc),
                        message=(f"MM 위치 출력을 안전하게 해석하지 못했습니다: {exc}"),
                    )
                )
                return None
            if lookup.status == GlobalUserStatus.FOUND and len(lookup.current_switches) == 1:
                resolved.append(
                    ControllerLocation(
                        client_ip=client_ip,
                        current_switch=lookup.current_switches[0],
                        mm_name=selected_mm.name,
                    )
                )
                not_found.append(False)
            elif lookup.status == GlobalUserStatus.AMBIGUOUS or len(lookup.current_switches) > 1:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MM_PARSE",
                        code=ErrorCode.CURRENT_SWITCH_AMBIGUOUS,
                        message=(
                            "한 주소에 여러 Current switch가 반환되어 자동 선택하지 않았습니다."
                        ),
                    )
                )
                resolved.append(None)
                not_found.append(False)
            else:
                resolved.append(None)
                not_found.append(True)

        return LocationSnapshot(
            source=resolved[0],
            destination=resolved[1],
            used_mm=selected_mm.name,
            full_scan_eligible=all(not_found),
        )

    def _device_for_location(
        self,
        location: ControllerLocation | None,
        diagnostics: list[DiagnosticEvent],
    ) -> DeviceTarget | None:
        if location is None:
            return None
        needle = _normalize_switch(location.current_switch)
        matches = [
            device
            for device in self.config.managed_devices
            if device.enabled
            and needle
            in {
                _normalize_switch(device.name),
                _normalize_switch(device.host),
                _normalize_switch(device.name.split(".", 1)[0]),
            }
        ]
        if len(matches) == 1:
            return matches[0]
        diagnostics.append(
            DiagnosticEvent(
                stage="MD_ROUTE",
                code=(
                    ErrorCode.CURRENT_SWITCH_AMBIGUOUS
                    if len(matches) > 1
                    else ErrorCode.CURRENT_SWITCH_UNMAPPED
                ),
                message="Current switch를 등록된 MD 한 대에 안전하게 매핑하지 못했습니다.",
            )
        )
        return None

    def _rotated_full_scan_devices(
        self,
        devices: tuple[DeviceTarget, ...],
    ) -> tuple[DeviceTarget, ...]:
        if len(devices) < 2:
            return devices
        with self._full_scan_cursor_lock:
            start = self._full_scan_cursor % len(devices)
            self._full_scan_cursor = (start + 1) % len(devices)
        return devices[start:] + devices[:start]

    def _progress(self, stage: str, device_name: str) -> None:
        if self._callbacks.progress is not None:
            self._callbacks.progress(stage, device_name)


def _normalize_switch(value: str) -> str:
    return value.strip().rstrip(".").casefold()


def _fair_device_deadline(
    parent: PollDeadline,
    *,
    remaining_devices: int,
) -> PollDeadline:
    if remaining_devices < 1:
        raise ValueError("remaining_devices must be positive")
    remaining = parent.remaining_seconds
    if remaining <= 0:
        parent.raise_if_expired()
    now = parent.expires_at - remaining
    fair_share = remaining / remaining_devices
    return PollDeadline(min(parent.expires_at, now + max(0.001, fair_share)), parent.clock)


def _md_error_code(exc: CollectorError) -> ErrorCode:
    if exc.code == ErrorCode.MM_UNREACHABLE:
        return ErrorCode.MD_UNREACHABLE
    return exc.code


def _parse_error_code(exc: ParseError) -> ErrorCode:
    code = getattr(exc, "code", None)
    if isinstance(code, ErrorCode):
        return code
    normalized = str(exc).casefold()
    if any(
        marker in normalized
        for marker in (
            "invalid command",
            "unknown command",
            "rejected",
            "did not recognize",
            "unsupported",
            "거부",
            "지원하지",
        )
    ):
        return ErrorCode.COMMAND_VARIANT_UNVERIFIED
    return ErrorCode.PARSE_PARTIAL
