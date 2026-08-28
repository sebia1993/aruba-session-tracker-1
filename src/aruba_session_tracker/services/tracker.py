"""Fail-closed MM-to-MD session query orchestration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from aruba_session_tracker.collectors import (
    CancellationToken,
    CollectorError,
    HostKeyApproval,
    SSHCollector,
    SSHConnectionFactory,
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

FullScanApproval = Callable[[QueryRequest, tuple[DeviceTarget, ...]], bool]
ProgressCallback = Callable[[str, str], None]


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

    def query_once(
        self,
        request: QueryRequest,
        credentials: Credentials,
        *,
        full_scan_approval: FullScanApproval | None = None,
        cancel_token: CancellationToken | None = None,
        location_snapshot: LocationSnapshot | None = None,
        refresh_locations: bool = True,
    ) -> QueryOutcome:
        token = cancel_token or CancellationToken()
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
        if full_scan:
            approval = full_scan_approval or self._callbacks.full_scan_approval
            approved = (
                not token.is_cancelled
                and approval is not None
                and approval(request, enabled_devices)
            )
            if token.is_cancelled:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_SCAN",
                        code=ErrorCode.CANCELLED,
                        message="작업이 취소되었습니다.",
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
            device_candidates = [(device, request.source_ip) for device in enabled_devices]

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
            # In normal mode the destination MD is queried only if the source MD had no match.
            if not full_scan and index > 0 and observations:
                break
            self._progress("MD_QUERY", device.name)
            try:
                batch = self._collector.collect(
                    device,
                    credentials,
                    (
                        NO_PAGING_COMMAND,
                        build_datapath_session_command(filter_ip),
                    ),
                    host_key_approval=self._callbacks.host_key_approval,
                    cancel_token=token,
                )
            except CollectorError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_QUERY",
                        code=_md_error_code(exc),
                        message=f"선택한 MD에서 세션 출력을 수집하지 못했습니다: {exc}",
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
                continue

            controllers.append(device.name)
            command = build_datapath_session_command(filter_ip)
            output = batch.output_for(command)
            snapshot_index = len(raw_snapshots)
            raw_snapshots.append(RawSnapshot(device.name, command, output, observation_keys=()))
            try:
                parsed = parse_datapath_sessions(
                    output,
                    controller_name=device.name,
                    controller_host=device.host,
                )
            except ParseError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MD_PARSE",
                        code=_parse_error_code(exc),
                        message=f"MD 세션 출력을 안전하게 해석하지 못했습니다: {exc}",
                    )
                )
                authoritative = False
                continue
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
        for index, target in enumerate((self.config.mm_primary, self.config.mm_standby)):
            if not target.enabled:
                continue
            if index > 0:
                self._progress("MM_FAILOVER", target.name)
            else:
                self._progress("MM_QUERY", target.name)
            try:
                batch = self._collector.collect(
                    target,
                    credentials,
                    commands,
                    host_key_approval=self._callbacks.host_key_approval,
                    cancel_token=token,
                )
                selected_mm = target
                break
            except CollectorError as exc:
                diagnostics.append(
                    DiagnosticEvent(
                        stage="MM_QUERY",
                        code=exc.code,
                        message=f"MM 조회 실패: {exc}",
                    )
                )
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

        resolved: list[ControllerLocation | None] = []
        not_found: list[bool] = []
        for client_ip in (request.source_ip, request.destination_ip):
            command = build_global_user_command(client_ip)
            output = batch.output_for(command)
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

    def _progress(self, stage: str, device_name: str) -> None:
        if self._callbacks.progress is not None:
            self._callbacks.progress(stage, device_name)


def _normalize_switch(value: str) -> str:
    return value.strip().rstrip(".").casefold()


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
