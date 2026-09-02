from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from time import monotonic
from typing import Protocol, cast

from PySide6.QtCore import QObject, QRunnable, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QCloseEvent, QColor, QDesktopServices, QFont, QResizeEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from aruba_session_tracker import __version__
from aruba_session_tracker.analysis import protocol_label, service_definition
from aruba_session_tracker.collectors.ssh import (
    CancellationToken,
    CollectorError,
    HostKeyInfo,
    PollDeadline,
)
from aruba_session_tracker.config import ConfigError, ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    ErrorCode,
    QueryRequest,
    SessionObservation,
    StorageFailureBoundary,
)
from aruba_session_tracker.parsers import overall_flag_severity
from aruba_session_tracker.paths import UnsafeManagedPath
from aruba_session_tracker.storage import (
    DeletePreview,
    SessionStore,
    StorageError,
    UnsafeStoragePath,
)
from aruba_session_tracker.support_codes import (
    SupportCode,
    UiFailureKey,
    support_code_for,
    support_code_for_ui_failure,
)
from aruba_session_tracker.ui.developer_inspector import (
    DeveloperInspectorController,
    UiElementMetadata,
)
from aruba_session_tracker.ui.runtime_environment import RuntimeEnvironmentMonitor
from aruba_session_tracker.ui.shutdown import ShutdownCoordinator

_UI_SOURCE_PATH = "src/aruba_session_tracker/ui/main_window.py"
_MAX_VISIBLE_RESULT_ROWS = 2_000
_DETAIL_COLUMN_INDEXES = (0, 6, 7, 8, 9, 10, 11, 13)
_STORAGE_HEALTH_INTERVAL_SECONDS = 60.0
# Advisory only: the supported five-second interval reaches 100,000 Raw files
# in about 5.8 days.  Surface the filesystem-pressure risk before the first
# full week without changing the existing free-space hard stop.
_RAW_FILE_COUNT_WARNING = 100_000
_OPERATOR_STATES = frozenset({"대기", "조회 중", "정상", "재시도 중", "확인 필요"})
_OPERATOR_STATE_ROLES = {
    "대기": "neutral",
    "조회 중": "active",
    "정상": "success",
    "재시도 중": "warning",
    "확인 필요": "danger",
}
_HISTORY_STATUS_LABELS = {
    "RUNNING": "진행 중",
    "COMPLETED": "완료",
    "STOPPED": "중지",
    "PARTIAL": "일부 결과",
    "FAILED": "실패",
    "INTERRUPTED": "수집 중단",
    "RESTARTED": "조건 변경 종료",
    "CANCELLED": "취소",
}
_RESULT_RENDER_CHUNK_SIZE = 200
_COMPACT_RESULT_LAYOUT_HEIGHT = 760
_FILTER_VALUE_ROLE = int(Qt.ItemDataRole.UserRole) + 1
_RUN_ID_ROLE = int(Qt.ItemDataRole.UserRole) + 2
_FILTER_COLUMNS = {
    2: "출발지 IP",
    3: "출발지 포트",
    4: "목적지 IP",
    5: "목적지 포트",
}
_KST = timezone(timedelta(hours=9), "KST")
_RESULT_TABLE_ACCESSIBLE_DESCRIPTION = (
    "조회된 세션의 프로토콜, 출발지와 목적지, 관측 상태와 마지막 확인 시각을 "
    "표시합니다. 관측 상태는 이번 조회에서 세션이 보였는지를 뜻하며 장비 장애나 "
    "통신 성공 판정이 아닙니다. 상세 열 보기에서 원문 장비 Flags를 확인할 수 있습니다."
)


@dataclass(frozen=True, slots=True)
class _DisplayRow:
    observation: SessionObservation
    packet_delta: str
    byte_delta: str
    lifecycle_status: str | None


@dataclass(frozen=True, slots=True)
class _PreparedDisplayOutcome:
    outcome: object
    visible_rows: tuple[_DisplayRow, ...]
    total_rows: int
    next_counters: dict[str, tuple[int | None, int | None]]


class _ResultFilterDialog(QDialog):
    """Small keyboard-accessible transient selector for one result column."""

    def __init__(
        self,
        parent: QWidget,
        *,
        title: str,
        values: tuple[tuple[object, str], ...],
        selected: set[object],
        filter_active: bool,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"{title} 필터")
        self.setModal(True)
        self.setMinimumWidth(300)
        self.setObjectName("resultFilterDialog")
        layout = QVBoxLayout(self)
        self.search_edit = QLineEdit(self)
        self.search_edit.setPlaceholderText("검색어 입력")
        self.search_edit.setAccessibleName(f"{title} 필터 검색")
        layout.addWidget(self.search_edit)
        self.values_list = QListWidget(self)
        self.values_list.setAccessibleName(f"{title} 필터 값 목록")
        self.values_list.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        for value, display in values:
            item = QListWidgetItem(display, self.values_list)
            item.setData(Qt.ItemDataRole.UserRole, value)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            check_state = (
                Qt.CheckState.Checked
                if not filter_active or value in selected
                else Qt.CheckState.Unchecked
            )
            item.setCheckState(check_state)
        layout.addWidget(self.values_list, 1)
        action_row = QHBoxLayout()
        select_all = QPushButton("모두 선택", self)
        clear_all = QPushButton("모두 해제", self)
        select_all.clicked.connect(self._select_all)
        clear_all.clicked.connect(self._clear_all)
        action_row.addWidget(select_all)
        action_row.addWidget(clear_all)
        action_row.addStretch(1)
        layout.addLayout(action_row)
        button_row = QHBoxLayout()
        apply_button = QPushButton("적용", self)
        cancel_button = QPushButton("취소", self)
        apply_button.setDefault(True)
        apply_button.clicked.connect(self.accept)
        cancel_button.clicked.connect(self.reject)
        button_row.addStretch(1)
        button_row.addWidget(apply_button)
        button_row.addWidget(cancel_button)
        layout.addLayout(button_row)
        self.search_edit.textChanged.connect(self._filter_items)
        self.search_edit.setFocus()

    def selected_values(self) -> set[object]:
        values: set[object] = set()
        for index in range(self.values_list.count()):
            item = self.values_list.item(index)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                values.add(item.data(Qt.ItemDataRole.UserRole))
        return values

    def _filter_items(self, text: str) -> None:
        query = text.strip().casefold()
        for index in range(self.values_list.count()):
            item = self.values_list.item(index)
            if item is not None:
                item.setHidden(bool(query) and query not in item.text().casefold())

    def _select_all(self) -> None:
        for index in range(self.values_list.count()):
            item = self.values_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)

    def _clear_all(self) -> None:
        for index in range(self.values_list.count()):
            item = self.values_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)


@dataclass(frozen=True, slots=True)
class _HistoryReadResult:
    runs: tuple[object, ...]
    pending_external_recoveries: int
    storage_health: object | None


class QueryExecutor(Protocol):
    def execute(
        self,
        config: AppConfig,
        request: QueryRequest,
        credentials: Credentials,
        *,
        monitoring: bool,
        cancel_token: CancellationToken,
        host_key_approval: Callable[[DeviceTarget, HostKeyInfo], bool],
        full_scan_approval: Callable[..., bool],
    ) -> object: ...

    def stop_monitor(self) -> None: ...


class _SignalEmitter(Protocol):
    def emit(self, *args: object) -> None: ...


def _emit_if_alive(signal: _SignalEmitter, *args: object) -> bool:
    """Emit from a daemon worker unless Qt is already tearing the sender down."""

    try:
        signal.emit(*args)
    except RuntimeError:
        return False
    return True


class _TaskSignals(QObject):
    succeeded = Signal(int, object)
    failed = Signal(int, object)
    finished = Signal(int)
    storage_warning = Signal(int, bool)
    storage_health_updated = Signal(int, object)
    storage_health_unavailable = Signal(int)


class _QueryTask(QRunnable):
    def __init__(
        self,
        executor: QueryExecutor,
        config: AppConfig,
        request: QueryRequest,
        credentials: Credentials,
        monitoring: bool,
        token: CancellationToken,
        host_key_approval: Callable[[DeviceTarget, HostKeyInfo], bool],
        full_scan_approval: Callable[..., bool],
        generation: int,
        query_capacity_check: Callable[[], None] | None = None,
        storage_health_check: Callable[[], object] | None = None,
        previous_counters: dict[str, tuple[int | None, int | None]] | None = None,
        close_after_misses: int = 3,
    ) -> None:
        super().__init__()
        self.signals = _TaskSignals()
        self.generation = generation
        self._executor = executor
        self._config = config
        self._request = request
        self._credentials = credentials
        self._monitoring = monitoring
        self._token = token
        self._host_key_approval = host_key_approval
        self._full_scan_approval = full_scan_approval
        self._query_capacity_check = query_capacity_check
        self._storage_health_check = storage_health_check
        self._previous_counters = dict(previous_counters or {})
        self._close_after_misses = close_after_misses

    @Slot()
    def run(self) -> None:
        try:
            if self._query_capacity_check is not None:
                try:
                    self._query_capacity_check()
                except StorageError as capacity_error:
                    capacity_error.at_boundary(StorageFailureBoundary.QUERY_PREFLIGHT)
                    raise
            if self._storage_health_check is not None:
                try:
                    health = self._storage_health_check()
                except Exception as health_error:
                    fatal_code = _fatal_storage_health_code(health_error)
                    if fatal_code is not None:
                        if isinstance(health_error, StorageError):
                            health_error.at_boundary(StorageFailureBoundary.QUERY_PREFLIGHT)
                        existing_code = getattr(
                            getattr(health_error, "code", None),
                            "value",
                            None,
                        )
                        if existing_code == fatal_code.value:
                            raise
                        raise StorageError(
                            "저장소 안전성 또는 저장 가능 상태를 확인하지 못했습니다.",
                            code=fatal_code,
                            boundary=StorageFailureBoundary.QUERY_PREFLIGHT,
                        ) from health_error
                    _emit_if_alive(
                        self.signals.storage_health_unavailable,
                        self.generation,
                    )
                else:
                    _emit_if_alive(
                        self.signals.storage_health_updated,
                        self.generation,
                        health,
                    )
                    if bool(getattr(health, "warning", False)):
                        hard_stop = bool(getattr(health, "hard_stop", False))
                        _emit_if_alive(
                            self.signals.storage_warning,
                            self.generation,
                            hard_stop,
                        )
                        if hard_stop:
                            raise StorageError(
                                "저장 공간이 부족하여 새 조회를 시작할 수 없습니다.",
                                code=ErrorCode.STORAGE_LOW_SPACE,
                                boundary=StorageFailureBoundary.QUERY_PREFLIGHT,
                            )
            outcome = self._executor.execute(
                self._config,
                self._request,
                self._credentials,
                monitoring=self._monitoring,
                cancel_token=self._token,
                host_key_approval=self._host_key_approval,
                full_scan_approval=self._full_scan_approval,
            )
            prepared = _prepare_display_outcome(
                outcome,
                previous_counters=self._previous_counters,
                close_after_misses=self._close_after_misses,
                monitoring=self._monitoring,
            )
        except Exception as exc:
            _emit_if_alive(self.signals.failed, self.generation, exc)
        else:
            _emit_if_alive(self.signals.succeeded, self.generation, prepared)
        finally:
            _emit_if_alive(self.signals.finished, self.generation)


class _StorageTaskSignals(QObject):
    succeeded = Signal(int, str, object)
    failed = Signal(int, str, object)
    finished = Signal(int, str)
    progress = Signal(int, str, str, int, int)


class _StorageTask(QRunnable):
    def __init__(
        self,
        generation: int,
        kind: str,
        operation: Callable[
            [Callable[[], bool], Callable[[str, int, int | None], None]],
            object,
        ],
        context: object | None = None,
    ) -> None:
        super().__init__()
        self.signals = _StorageTaskSignals()
        self.generation = generation
        self.kind = kind
        self.context = context
        self._operation = operation
        self._cancel_requested = threading.Event()

    def request_cancel(self) -> None:
        self._cancel_requested.set()

    def cancelled(self) -> bool:
        return self._cancel_requested.is_set()

    def _report_progress(self, phase: str, completed: int, total: int | None) -> None:
        _emit_if_alive(
            self.signals.progress,
            self.generation,
            self.kind,
            phase,
            completed,
            -1 if total is None else total,
        )

    @Slot()
    def run(self) -> None:
        try:
            result = self._operation(self.cancelled, self._report_progress)
        except Exception as exc:
            _emit_if_alive(self.signals.failed, self.generation, self.kind, exc)
        else:
            _emit_if_alive(self.signals.succeeded, self.generation, self.kind, result)
        finally:
            _emit_if_alive(self.signals.finished, self.generation, self.kind)


class _ApprovalRequest:
    def __init__(self, title: str, message: str, generation: int | None) -> None:
        self.title = title
        self.message = message
        self.generation = generation
        self.answer = False
        self.event = threading.Event()


class ApprovalBridge(QObject):
    requested = Signal(object)
    dismiss_requested = Signal(object)

    def __init__(self, owner: QWidget | None = None) -> None:
        super().__init__(owner)
        self._owner = owner
        self._lock = threading.Lock()
        self._pending: set[_ApprovalRequest] = set()
        self._dialogs: dict[_ApprovalRequest, QMessageBox] = {}
        self._shutting_down = False
        self.requested.connect(self._show_request)
        self.dismiss_requested.connect(self._dismiss_request)

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def approve_host_key(
        self,
        target: DeviceTarget,
        info: HostKeyInfo,
        deadline: PollDeadline | None = None,
        *,
        cancel_token: CancellationToken | None = None,
        generation: int | None = None,
    ) -> bool:
        request = _ApprovalRequest(
            "SSH 호스트 키 승인",
            f"장비: {target.name}\n주소: {target.host}:{target.port}\n"
            f"알고리즘: {info.algorithm}\n지문: {info.sha256_fingerprint}\n\n"
            "장비의 실제 지문과 일치하는지 확인한 뒤 승인하십시오.",
            generation,
        )
        return self._request_answer(request, cancel_token, deadline)

    def approve_full_scan(
        self,
        _request: QueryRequest,
        devices: tuple[DeviceTarget, ...],
        deadline: PollDeadline | None = None,
        *,
        cancel_token: CancellationToken | None = None,
        generation: int | None = None,
    ) -> bool:
        targets = "\n".join(f"- {device.name}: {device.host}:{device.port}" for device in devices)
        request = _ApprovalRequest(
            f"MD {len(devices)}대 전수조회 확인",
            "입력한 IP를 MM에서 찾지 못했습니다.\n"
            "다음 활성 MD를 한 대씩 순차 조회합니다.\n\n"
            f"{targets}\n\n장비 부하와 조회 권한을 확인한 뒤 진행하십시오.",
            generation,
        )
        return self._request_answer(request, cancel_token, deadline)

    def cancel_pending(self, generation: int | None = None) -> None:
        with self._lock:
            requests = tuple(
                request
                for request in self._pending
                if generation is None or request.generation == generation
            )
        for request in requests:
            self._complete_request(request, False, dismiss=True)

    def shutdown(self) -> None:
        with self._lock:
            self._shutting_down = True
        self.cancel_pending()

    def _request_answer(
        self,
        request: _ApprovalRequest,
        cancel_token: CancellationToken | None,
        deadline: PollDeadline | None,
    ) -> bool:
        if cancel_token is not None and cancel_token.is_cancelled:
            return False
        if deadline is not None and deadline.remaining_seconds <= 0:
            return False
        with self._lock:
            if self._shutting_down:
                return False
            self._pending.add(request)

        if cancel_token is not None and cancel_token.is_cancelled:
            self._complete_request(request, False, dismiss=False)
            return False
        if QThread.currentThread() == self.thread():
            self._show_request_blocking(request, cancel_token, deadline)
        else:
            self.requested.emit(request)

        while True:
            wait_seconds = 0.05
            if deadline is not None:
                remaining = deadline.remaining_seconds
                if remaining <= 0:
                    self._complete_request(request, False, dismiss=True)
                    return False
                wait_seconds = min(wait_seconds, remaining)
            if request.event.wait(wait_seconds):
                break
            if cancel_token is not None and cancel_token.is_cancelled:
                self._complete_request(request, False, dismiss=True)
                return False
        if cancel_token is not None and cancel_token.is_cancelled:
            return False
        if deadline is not None and deadline.remaining_seconds <= 0:
            return False
        return request.answer

    def _complete_request(
        self,
        request: _ApprovalRequest,
        answer: bool,
        *,
        dismiss: bool,
    ) -> bool:
        with self._lock:
            if request not in self._pending:
                return False
            self._pending.remove(request)
            request.answer = answer
            request.event.set()
        if dismiss:
            self.dismiss_requested.emit(request)
        return True

    def _show_request_blocking(
        self,
        request: _ApprovalRequest,
        cancel_token: CancellationToken | None,
        deadline: PollDeadline | None,
    ) -> None:
        with self._lock:
            if request not in self._pending:
                return
        if cancel_token is None and deadline is None:
            selected_button = QMessageBox.question(
                self._owner,
                request.title,
                request.message,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            self._complete_request(
                request,
                selected_button == QMessageBox.StandardButton.Yes,
                dismiss=False,
            )
            return

        dialog = QMessageBox(
            QMessageBox.Icon.Question,
            request.title,
            request.message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            self._owner,
        )
        dialog.setObjectName("approvalDialog")
        dialog.setProperty("popupSurface", "approval")
        dialog.setDefaultButton(QMessageBox.StandardButton.No)
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self._dialogs[request] = dialog
        expiry_timer = QTimer(dialog)
        expiry_timer.setInterval(50)

        def reject_if_stopped() -> None:
            cancelled = cancel_token is not None and cancel_token.is_cancelled
            expired = deadline is not None and deadline.remaining_seconds <= 0
            if cancelled or expired:
                self._complete_request(request, False, dismiss=False)
                dialog.done(QMessageBox.StandardButton.No.value)

        expiry_timer.timeout.connect(reject_if_stopped)
        expiry_timer.start()
        dialog.exec()
        expiry_timer.stop()
        clicked = dialog.clickedButton()
        yes_button = QMessageBox.StandardButton.Yes
        approved = clicked is not None and dialog.standardButton(clicked) == yes_button
        self._dialogs.pop(request, None)
        self._complete_request(
            request,
            approved,
            dismiss=False,
        )
        dialog.deleteLater()

    @Slot(object)
    def _show_request(self, request: _ApprovalRequest) -> None:
        with self._lock:
            if request not in self._pending:
                return
        dialog = QMessageBox(
            QMessageBox.Icon.Question,
            request.title,
            request.message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            self._owner,
        )
        dialog.setObjectName("approvalDialog")
        dialog.setProperty("popupSurface", "approval")
        dialog.setDefaultButton(QMessageBox.StandardButton.No)
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        self._dialogs[request] = dialog
        dialog.finished.connect(
            lambda _result, current=request, current_dialog=dialog: self._dialog_finished(
                current,
                current_dialog,
            )
        )
        with self._lock:
            still_pending = request in self._pending
        if not still_pending:
            self._dismiss_request(request)
            return
        dialog.open()

    def _dialog_finished(self, request: _ApprovalRequest, dialog: QMessageBox) -> None:
        clicked = dialog.clickedButton()
        yes_button = QMessageBox.StandardButton.Yes
        answer = clicked is not None and dialog.standardButton(clicked) == yes_button
        self._dialogs.pop(request, None)
        self._complete_request(request, answer, dismiss=False)
        dialog.deleteLater()

    @Slot(object)
    def _dismiss_request(self, request: _ApprovalRequest) -> None:
        dialog = self._dialogs.get(request)
        if dialog is not None:
            dialog.done(QMessageBox.StandardButton.No.value)


class MainWindow(QMainWindow):
    def __init__(
        self,
        config_repository: ConfigRepository,
        store: SessionStore,
        executor: QueryExecutor,
        developer_inspector: DeveloperInspectorController | None = None,
        *,
        shutdown_grace_milliseconds: int = 15_000,
        close_grace_milliseconds: int | None = None,
    ) -> None:
        super().__init__()
        close_grace = (
            shutdown_grace_milliseconds
            if close_grace_milliseconds is None
            else close_grace_milliseconds
        )
        if type(close_grace) is not int or close_grace < 1:
            raise ValueError("close_grace_milliseconds must be a positive integer")
        self._config_repository = config_repository
        self._store = store
        self._executor = executor
        self._developer_inspector = developer_inspector
        self._approval = ApprovalBridge(self)
        self._cancel_token: CancellationToken | None = None
        self._current_task: _QueryTask | None = None
        self._task_generation = 0
        self._user_cancel_generation: int | None = None
        self._environment_cancel_generation: int | None = None
        self._query_running = False
        self._monitoring = False
        self._closing_requested = False
        self._close_when_idle = False
        self._close_recovery_deferred = False
        self._shutdown_finalization_succeeded: bool | None = None
        self._storage_task_running = False
        self._storage_task_generation = 0
        self._current_storage_task: _StorageTask | None = None
        self._pending_preview_discards: list[DeletePreview] = []
        self._history_task_running = False
        self._history_task_generation = 0
        self._current_history_task: _StorageTask | None = None
        self._history_dirty = False
        self._history_revision = 0
        self._storage_reconciliation_pending = True
        self._next_monitor_delay_seconds = 0.0
        self._next_storage_health_check_at = 0.0
        self._last_counters: dict[str, tuple[int | None, int | None]] = {}
        self._run_started_at: datetime | None = None
        self._run_started_monotonic: float | None = None
        self._result_filter_values: dict[int, set[object]] = {}
        self._result_filter_popup: QWidget | None = None
        self._monitor_timer = QTimer(self)
        self._monitor_timer.setSingleShot(True)
        self._monitor_timer.timeout.connect(self._start_query)
        self._close_grace_timer = QTimer(self)
        self._close_grace_timer.setSingleShot(True)
        self._close_grace_timer.setInterval(close_grace)
        self._close_grace_timer.timeout.connect(self._close_grace_expired)
        self._result_render_timer = QTimer(self)
        self._result_render_timer.setSingleShot(True)
        self._result_render_timer.timeout.connect(self._render_next_result_chunk)
        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(1000)
        self._elapsed_timer.timeout.connect(self._refresh_elapsed_labels)
        self._history_elapsed_timer = QTimer(self)
        self._history_elapsed_timer.setInterval(1000)
        self._history_elapsed_timer.timeout.connect(self._refresh_history_elapsed_cells)
        self._result_render_generation = 0
        self._pending_result_rows: tuple[_DisplayRow, ...] = ()
        self._pending_result_index = 0
        self._pending_result_total_rows = 0
        self._result_total_rows = 0
        self._shutdown = ShutdownCoordinator(
            self._executor.stop_monitor,
            self,
            grace_milliseconds=shutdown_grace_milliseconds,
        )
        self._shutdown.stage_changed.connect(self._shutdown_stage_changed)
        self._shutdown.settled.connect(self._shutdown_settled)
        self._runtime_environment = RuntimeEnvironmentMonitor(self)
        self._runtime_environment.discontinuity.connect(self._runtime_discontinuity)

        self.setWindowTitle(f"Aruba Session Tracker {__version__}")
        self.resize(1320, 820)
        self.setMinimumSize(1080, 680)
        self._build_ui()
        self._apply_style()
        self._load_config()
        self._update_setup_guide()
        self._refresh_history()

    @property
    def clean_shutdown_completed(self) -> bool:
        return self._shutdown_finalization_succeeded is True and not self._close_recovery_deferred

    def _build_ui(self) -> None:
        self.central_root = QWidget()
        self.central_layout = QVBoxLayout(self.central_root)
        self.central_layout.setContentsMargins(0, 0, 0, 0)
        self.central_layout.setSpacing(0)
        if self._developer_inspector is not None:
            self._developer_inspector.attach_host_layout(
                self.central_root,
                self.central_layout,
            )

        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("주요 운영 화면")
        self.tabs.setAccessibleDescription(
            "세션 조회, 장비 설정, 기록 및 내보내기 화면을 전환합니다."
        )
        self.query_page = self._build_query_tab()
        self.settings_page = self._build_settings_tab()
        self.history_page = self._build_history_tab()
        self.tabs.addTab(self.query_page, "세션 조회")
        self.tabs.addTab(self.settings_page, "장비 설정")
        self.tabs.addTab(self.history_page, "기록 및 내보내기")
        self.nav_identity = QFrame()
        self.nav_identity.setObjectName("navIdentity")
        nav_identity_layout = QHBoxLayout(self.nav_identity)
        nav_identity_layout.setContentsMargins(16, 9, 16, 9)
        nav_identity_layout.setSpacing(10)
        self.product_name_label = QLabel("ARUBA SESSION TRACKER")
        self.product_name_label.setObjectName("productName")
        self.product_meta_label = QLabel(f"v{__version__} · 로컬 전용 · 읽기 전용 조회")
        self.product_meta_label.setObjectName("productMeta")
        nav_identity_layout.addWidget(self.product_name_label)
        nav_identity_layout.addWidget(self.product_meta_label)
        self.tabs.setCornerWidget(self.nav_identity, Qt.Corner.TopRightCorner)
        self.tabs.currentChanged.connect(self._tab_changed)
        self.central_layout.addWidget(self.tabs, 1)
        self.setCentralWidget(self.central_root)
        self.statusBar().showMessage("실제 장비 접속 전 SSH 지문을 반드시 확인하십시오.")
        self._register_developer_inspector_catalog()

    def _build_query_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.setup_guide = QFrame()
        self.setup_guide.setObjectName("setupGuide")
        guide_layout = QHBoxLayout(self.setup_guide)
        guide_layout.setContentsMargins(10, 8, 10, 8)
        self.setup_guide_label = QLabel(
            "아직 조회할 장비가 설정되지 않았습니다. 먼저 MM과 MD 주소를 등록해 주세요."
        )
        self.setup_guide_label.setWordWrap(True)
        self.open_settings_button = QPushButton("장비 설정 열기")
        self.open_settings_button.setAccessibleName("장비 설정 열기")
        self.open_settings_button.setAccessibleDescription(
            "조회할 MM과 MD 주소를 입력하는 장비 설정 탭으로 이동합니다."
        )
        self.open_settings_button.clicked.connect(self._open_settings)
        guide_layout.addWidget(self.setup_guide_label, 1)
        guide_layout.addWidget(self.open_settings_button)
        layout.addWidget(self.setup_guide)

        self.connection_group = QGroupBox("로그인 정보 · 이번 실행에만 사용")
        connection_layout = QGridLayout(self.connection_group)
        self.username_edit = QLineEdit()
        self.username_edit.setAccessibleName("사용자 이름")
        self.username_edit.setAccessibleDescription(
            "현재 실행에만 사용하는 장비 로그인 사용자 이름입니다."
        )
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setAccessibleName("암호")
        self.password_edit.setAccessibleDescription(
            "현재 실행에만 사용하는 장비 로그인 암호이며 저장되지 않습니다."
        )
        connection_layout.addWidget(QLabel("SSH 사용자 이름"), 0, 0)
        connection_layout.addWidget(self.username_edit, 0, 1)
        connection_layout.addWidget(QLabel("SSH 암호"), 0, 2)
        connection_layout.addWidget(self.password_edit, 0, 3)

        self.query_group = QGroupBox("조회할 세션 흐름 · IP 하나 이상 입력")
        query_layout = QHBoxLayout(self.query_group)
        self.source_ip_edit = QLineEdit()
        self.source_ip_edit.setAccessibleName("출발지 IP")
        self.source_ip_edit.setAccessibleDescription(
            "조회할 출발지 IP 주소입니다. 출발지와 목적지 중 하나 이상 입력합니다."
        )
        self.destination_ip_edit = QLineEdit()
        self.destination_ip_edit.setAccessibleName("목적지 IP")
        self.destination_ip_edit.setAccessibleDescription(
            "조회할 목적지 IP 주소입니다. 출발지와 목적지 중 하나 이상 입력합니다."
        )

        self.source_endpoint_panel = QFrame()
        self.source_endpoint_panel.setObjectName("flowEndpointCard")
        self.source_endpoint_panel.setProperty("endpointRole", "source")
        source_endpoint_layout = QVBoxLayout(self.source_endpoint_panel)
        source_endpoint_layout.setContentsMargins(12, 9, 12, 11)
        source_endpoint_layout.setSpacing(4)
        source_eyebrow = QLabel("출발지")
        source_eyebrow.setObjectName("flowEyebrow")
        source_label = QLabel("출발지 IP")
        source_label.setObjectName("flowFieldLabel")
        source_label.setBuddy(self.source_ip_edit)
        source_endpoint_layout.addWidget(source_eyebrow)
        source_endpoint_layout.addWidget(source_label)
        source_endpoint_layout.addWidget(self.source_ip_edit)

        self.query_direction_panel = QFrame()
        self.query_direction_panel.setObjectName("flowDirectionPanel")
        direction_layout = QVBoxLayout(self.query_direction_panel)
        direction_layout.setContentsMargins(10, 7, 10, 7)
        direction_layout.setSpacing(4)
        direction_layout.addStretch(1)
        direction_caption = QLabel("조회 방향")
        direction_caption.setObjectName("flowDirectionCaption")
        direction_caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.query_direction_label = QLabel("양방향 조회")
        self.query_direction_label.setObjectName("flowDirectionLabel")
        self.query_direction_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.query_direction_label.setAccessibleName("조회 방향")
        direction_layout.addWidget(direction_caption)
        direction_layout.addWidget(self.query_direction_label)
        direction_layout.addStretch(1)

        self.destination_endpoint_panel = QFrame()
        self.destination_endpoint_panel.setObjectName("flowEndpointCard")
        self.destination_endpoint_panel.setProperty("endpointRole", "destination")
        destination_endpoint_layout = QVBoxLayout(self.destination_endpoint_panel)
        destination_endpoint_layout.setContentsMargins(12, 9, 12, 11)
        destination_endpoint_layout.setSpacing(4)
        destination_eyebrow = QLabel("목적지")
        destination_eyebrow.setObjectName("flowEyebrow")
        destination_label = QLabel("목적지 IP")
        destination_label.setObjectName("flowFieldLabel")
        destination_label.setBuddy(self.destination_ip_edit)
        destination_endpoint_layout.addWidget(destination_eyebrow)
        destination_endpoint_layout.addWidget(destination_label)
        destination_endpoint_layout.addWidget(self.destination_ip_edit)

        query_layout.addWidget(self.source_endpoint_panel, 1)
        query_layout.addWidget(self.query_direction_panel)
        query_layout.addWidget(self.destination_endpoint_panel, 1)

        self.advanced_toggle_button = QPushButton("고급 조건 보기")
        self.advanced_toggle_button.setCheckable(True)
        self.advanced_toggle_button.setAccessibleName("고급 조건 펼치기 또는 접기")
        self.advanced_toggle_button.setAccessibleDescription(
            "Enable 암호, 포트, 양방향 검색 조건을 표시하거나 숨깁니다."
        )
        self.advanced_toggle_button.toggled.connect(self._set_advanced_visible)
        self.advanced_panel = QGroupBox("고급 조건")
        advanced_layout = QGridLayout(self.advanced_panel)
        self.enable_edit = QLineEdit()
        self.enable_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.enable_edit.setAccessibleName("Enable 암호")
        self.enable_edit.setAccessibleDescription(
            "필요한 장비에서만 현재 실행에 사용할 Enable 암호입니다."
        )
        self.source_port_edit = QLineEdit()
        self.source_port_edit.setAccessibleName("출발지 포트")
        self.source_port_edit.setAccessibleDescription(
            "선택 사항인 출발지 포트 번호입니다. 비우면 모든 포트를 조회합니다."
        )
        self.destination_port_edit = QLineEdit()
        self.destination_port_edit.setAccessibleName("목적지 포트")
        self.destination_port_edit.setAccessibleDescription(
            "선택 사항인 목적지 포트 번호입니다. 비우면 모든 포트를 조회합니다."
        )
        self.bidirectional_check = QCheckBox("양방향 검색 (IP와 포트를 함께 교환)")
        self.bidirectional_check.setAccessibleName("양방향 검색")
        self.bidirectional_check.setAccessibleDescription(
            "입력한 IP와 포트 조건을 서로 바꾼 반대 방향도 함께 검색합니다."
        )
        self.bidirectional_check.setChecked(True)
        self.bidirectional_check.toggled.connect(self._update_query_direction_presentation)
        self._update_query_direction_presentation(True)
        advanced_layout.addWidget(QLabel("Enable 암호 (선택)"), 0, 0)
        advanced_layout.addWidget(self.enable_edit, 0, 1)
        advanced_layout.addWidget(QLabel("출발지 포트 (선택)"), 0, 2)
        advanced_layout.addWidget(self.source_port_edit, 0, 3)
        advanced_layout.addWidget(QLabel("목적지 포트 (선택)"), 0, 4)
        advanced_layout.addWidget(self.destination_port_edit, 0, 5)
        advanced_layout.addWidget(self.bidirectional_check, 0, 6)
        for column in (1, 3, 5):
            advanced_layout.setColumnStretch(column, 1)
        self.advanced_panel.setVisible(False)

        self.query_action_bar = QFrame()
        self.query_action_bar.setObjectName("queryActionBar")
        actions = QHBoxLayout(self.query_action_bar)
        actions.setContentsMargins(10, 8, 10, 8)
        actions.setSpacing(8)
        self.monitor_button = QPushButton("지속 모니터링 시작")
        self.monitor_button.setDefault(True)
        self.monitor_button.setAccessibleName("지속 모니터링 시작")
        self.monitor_button.setAccessibleDescription(
            "입력한 조건으로 반복 세션 모니터링을 시작합니다."
        )
        self.query_button = QPushButton("현재 조회")
        self.query_button.setAccessibleName("현재 조회")
        self.query_button.setAccessibleDescription("입력한 조건으로 세션을 한 번만 조회합니다.")
        self.stop_button = QPushButton("중지")
        self.stop_button.setAccessibleName("조회 또는 모니터링 중지")
        self.stop_button.setAccessibleDescription(
            "진행 중인 조회나 반복 모니터링을 안전하게 중지합니다."
        )
        self.stop_button.setEnabled(False)
        self.query_button.clicked.connect(self._start_query)
        self.monitor_button.clicked.connect(self._start_monitoring)
        self.stop_button.clicked.connect(self._stop_work)
        actions.addWidget(self.monitor_button)
        actions.addWidget(self.query_button)
        actions.addWidget(self.stop_button)
        actions.addStretch(1)
        self.state_caption = QLabel("실행 상태")
        self.state_caption.setObjectName("stateCaption")
        actions.addWidget(self.state_caption)
        self.state_label = QLabel("대기")
        self.state_label.setObjectName("stateLabel")
        self.state_label.setProperty("stateRole", _OPERATOR_STATE_ROLES["대기"])
        actions.addWidget(self.state_label)

        primary_inputs = QHBoxLayout()
        primary_inputs.setSpacing(10)
        primary_inputs.addWidget(self.query_group, 1)
        primary_inputs.addWidget(self.connection_group, 1)
        layout.addLayout(primary_inputs)
        layout.addWidget(self.advanced_toggle_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.advanced_panel)
        layout.addWidget(self.query_action_bar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setObjectName("resultSplitter")
        splitter.setChildrenCollapsible(False)
        self.result_splitter = splitter
        result_panel = QWidget()
        result_layout = QVBoxLayout(result_panel)
        self.results_header = QFrame()
        self.results_header.setObjectName("resultsHeader")
        results_header_layout = QVBoxLayout(self.results_header)
        results_header_layout.setContentsMargins(0, 0, 0, 0)
        results_header_layout.setSpacing(7)
        result_options = QHBoxLayout()
        result_options.setSpacing(10)
        result_title_block = QVBoxLayout()
        result_title_block.setSpacing(1)
        self.results_title_label = QLabel("세션 조회 결과")
        self.results_title_label.setObjectName("sectionTitle")
        self.result_status_guide = QLabel(
            "관측 상태=이번 조회에서 세션이 보였는지(장비 장애·통신 성공 판정 아님) · "
            "장비 Flags=원문 참고 정보"
        )
        self.result_status_guide.setObjectName("sectionHint")
        self.result_status_guide.setAccessibleName("결과 상태 안내")
        self.result_status_guide.setAccessibleDescription(
            "관측 상태는 이번 조회에서 세션이 보였는지를 뜻하며 장비 장애나 "
            "통신 성공 판정이 아닙니다. 장비 Flags는 상세 확인을 위한 원문 참고 정보입니다."
        )
        self.result_status_guide.setToolTip(
            "관측 상태는 이번 조회에서 세션이 보였는지를 뜻하며 장비 장애나 "
            "통신 성공 판정이 아닙니다.\n"
            "장비 Flags는 상세 확인을 위한 원문 참고 정보입니다."
        )
        result_title_block.addWidget(self.results_title_label)
        result_title_block.addWidget(self.result_status_guide)
        result_options.addLayout(result_title_block, 1)
        self.context_label = QLabel("MM/MD: 아직 조회하지 않음")
        self.elapsed_label = QLabel("시작 시각: - · 경과: 00:00:00")
        self.elapsed_label.setObjectName("elapsedSummary")
        self.elapsed_label.setAccessibleName("조회 시작 시각과 경과 시간")
        self.elapsed_label.setAccessibleDescription(
            "현재 조회 또는 모니터링의 시작 시각과 경과 시간을 표시합니다."
        )
        self.detail_columns_toggle = QCheckBox("상세 열 보기")
        self.detail_columns_toggle.setAccessibleName("상세 결과 열 보기")
        self.detail_columns_toggle.setAccessibleDescription(
            "장비, 패킷, 바이트, 변화량, 세션 경과, CPU ID와 원문 장비 Flags 열을 "
            "표시하거나 숨깁니다. 목적지 포트는 기본 표시됩니다."
        )
        self.result_filter_button = QPushButton("결과 필터")
        self.result_filter_button.setAccessibleName("결과 필터")
        self.result_filter_button.setAccessibleDescription(
            "출발지와 목적지 IP 및 포트 결과를 여러 개 선택해 필터링합니다."
        )
        self.result_filter_button.clicked.connect(self._open_result_filter_menu)
        self.clear_result_filters_button = QPushButton("필터 모두 해제")
        self.clear_result_filters_button.setAccessibleName("결과 필터 모두 해제")
        self.clear_result_filters_button.clicked.connect(self._clear_result_filters)
        self.clear_result_filters_button.setEnabled(False)
        self.raw_diagnostics_toggle = QCheckBox("상세 정보 보기")
        self.raw_diagnostics_toggle.setAccessibleName("Raw 및 진단 패널 보기")
        self.raw_diagnostics_toggle.setAccessibleDescription(
            "선택한 Raw 행과 진단 이벤트 패널을 표시하거나 숨깁니다."
        )
        result_options.addWidget(self.detail_columns_toggle)
        result_options.addWidget(self.result_filter_button)
        result_options.addWidget(self.clear_result_filters_button)
        result_options.addWidget(self.raw_diagnostics_toggle)
        results_header_layout.addLayout(result_options)
        results_header_layout.addWidget(self.context_label)
        results_header_layout.addWidget(self.elapsed_label)
        self.result_table = QTableWidget(0, 16)
        self.result_table.setAccessibleName("세션 조회 결과 표")
        self.result_table.setAccessibleDescription(_RESULT_TABLE_ACCESSIBLE_DESCRIPTION)
        self.result_table.setHorizontalHeaderLabels(
            [
                "장비",
                "프로토콜",
                "출발지 IP",
                "출발지 포트",
                "목적지 IP",
                "목적지 포트",
                "패킷",
                "바이트",
                "패킷 변화",
                "바이트 변화",
                "세션 경과",
                "CPU ID",
                "마지막 확인 시각",
                "장비 Flags",
                "관측 상태",
                "",
            ]
        )
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        widths = (120, 82, 140, 96, 140, 96, 85, 95, 96, 96, 88, 70, 150, 90, 210, 190)
        for column, width in enumerate(widths):
            header.resizeSection(column, width)
        header_help = {
            13: "Aruba 장비가 반환한 원문 Flags이며 상세 확인용입니다.",
            14: (
                "장비 조회 결과에서 이 세션이 보였는지를 표시합니다. "
                "장비 전체 상태나 통신 성공 여부를 뜻하지 않습니다."
            ),
        }
        for column, help_text in header_help.items():
            header_item = self.result_table.horizontalHeaderItem(column)
            if header_item is not None:
                header_item.setToolTip(help_text)
        for column in _DETAIL_COLUMN_INDEXES:
            self.result_table.setColumnHidden(column, True)
        self.result_table.setColumnHidden(15, True)
        header.sectionClicked.connect(self._result_header_clicked)
        self.detail_columns_toggle.toggled.connect(self._set_detail_columns_visible)
        self.result_table.itemSelectionChanged.connect(self._show_selected_raw)
        result_layout.addWidget(self.results_header)
        self.result_empty_label = QLabel(
            "조회 조건을 입력한 뒤 현재 조회 또는 지속 모니터링을 시작하십시오."
        )
        self.result_empty_label.setObjectName("emptyState")
        self.result_empty_label.setAccessibleName("조회 결과 안내")
        self.result_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.result_empty_label.setWordWrap(True)
        result_layout.addWidget(self.result_empty_label)
        result_layout.addWidget(self.result_table)

        self.details = QTabWidget()
        self.details.setAccessibleName("조회 상세 정보")
        self.details.setAccessibleDescription("선택 행 Raw와 진단 이벤트를 전환합니다.")
        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setAccessibleName("선택 행 Raw")
        self.raw_view.setAccessibleDescription("선택한 결과 행의 원본 장비 출력 일부를 표시합니다.")
        self.diagnostics_list = QListWidget()
        self.diagnostics_list.setAccessibleName("진단 이벤트")
        self.diagnostics_list.setAccessibleDescription(
            "조회 과정의 안전한 진단 코드와 설명을 표시합니다."
        )
        self.details.addTab(self.raw_view, "선택 행 Raw")
        self.details.addTab(self.diagnostics_list, "진단 이벤트")
        self.details.setVisible(False)
        self.raw_diagnostics_toggle.toggled.connect(self._set_details_visible)
        self._update_filter_controls()
        splitter.addWidget(result_panel)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        focus_order = (
            self.open_settings_button,
            self.source_ip_edit,
            self.destination_ip_edit,
            self.username_edit,
            self.password_edit,
            self.advanced_toggle_button,
            self.enable_edit,
            self.source_port_edit,
            self.destination_port_edit,
            self.bidirectional_check,
            self.monitor_button,
            self.query_button,
            self.stop_button,
            self.detail_columns_toggle,
            self.result_filter_button,
            self.clear_result_filters_button,
            self.raw_diagnostics_toggle,
            self.result_table,
        )
        for index, widget in enumerate(focus_order[:-1]):
            QWidget.setTabOrder(widget, focus_order[index + 1])
        return page

    @Slot()
    def _open_settings(self) -> None:
        self.tabs.setCurrentWidget(self.settings_page)

    @Slot(bool)
    def _set_advanced_visible(self, visible: bool) -> None:
        self.advanced_panel.setVisible(visible)
        self.advanced_toggle_button.setText("고급 조건 숨기기" if visible else "고급 조건 보기")
        self._sync_result_splitter_orientation(reset_sizes=self.raw_diagnostics_toggle.isChecked())

    @Slot(bool)
    def _update_query_direction_presentation(self, bidirectional: bool) -> None:
        self.query_direction_label.setText("양방향 조회" if bidirectional else "입력 방향 조회")
        self.query_direction_label.setProperty(
            "directionRole",
            "bidirectional" if bidirectional else "forward",
        )
        self.query_direction_label.style().unpolish(self.query_direction_label)
        self.query_direction_label.style().polish(self.query_direction_label)
        self.query_direction_label.update()

    @Slot(bool)
    def _set_detail_columns_visible(self, visible: bool) -> None:
        for column in _DETAIL_COLUMN_INDEXES:
            self.result_table.setColumnHidden(column, not visible)
        self.result_table.setColumnHidden(15, True)

    @Slot(int)
    def _result_header_clicked(self, logical_index: int) -> None:
        if logical_index in _FILTER_COLUMNS:
            self._open_result_filter_menu(logical_index)

    @Slot()
    def _open_result_filter_menu(self, column: int | None = None) -> None:
        if column is None:
            menu = QMenu(self)
            menu.setObjectName("resultFilterMenu")
            menu.setProperty("popupSurface", "menu")
            for logical_index, _label in _FILTER_COLUMNS.items():
                action = menu.addAction(self._filter_header_text(logical_index))
                action.triggered.connect(
                    lambda _checked=False, index=logical_index: self._open_result_filter_dialog(
                        index
                    )
                )
            menu.exec(
                self.result_filter_button.mapToGlobal(self.result_filter_button.rect().bottomLeft())
            )
            return
        self._open_result_filter_dialog(column)

    def _open_result_filter_dialog(self, column: int) -> None:
        values = self._filter_candidates(column)
        if not values:
            self.statusBar().showMessage("현재 결과에 필터링할 값이 없습니다.", 3000)
            return
        selected = self._result_filter_values.get(column, set())
        dialog = _ResultFilterDialog(
            self,
            title=_FILTER_COLUMNS[column],
            values=values,
            selected=selected,
            filter_active=column in self._result_filter_values,
        )
        self._result_filter_popup = dialog
        try:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            chosen = dialog.selected_values()
            all_values = {value for value, _display in values}
            if chosen == all_values:
                self._result_filter_values.pop(column, None)
            else:
                self._result_filter_values[column] = chosen
            self._apply_result_filters()
        finally:
            self._result_filter_popup = None
            dialog.deleteLater()

    def _filter_candidates(self, column: int) -> tuple[tuple[object, str], ...]:
        candidates: dict[object, str] = {}
        observed_services: dict[object, set[str]] = {}
        for row in range(self.result_table.rowCount()):
            item = self.result_table.item(row, column)
            if item is None:
                continue
            raw = item.data(_FILTER_VALUE_ROLE)
            if raw is None:
                raw = item.text()
            if raw in (None, ""):
                continue
            if column in (3, 5):
                try:
                    port = int(raw)
                except (TypeError, ValueError):
                    continue
                service = self._service_label_for_row(row, column, port)
                observed_services.setdefault(port, set()).add(service)
                candidates[port] = str(port)
            else:
                candidates[str(raw)] = str(raw)
        for value in self._result_filter_values.get(column, set()):
            if value not in candidates:
                candidates[value] = f"{value} (현재 결과 없음)"
        result: list[tuple[object, str]] = []
        for value in sorted(
            candidates,
            key=lambda item: int(item) if isinstance(item, int) else str(item),
        ):
            display = candidates[value]
            if isinstance(value, int):
                services = observed_services.get(value, set())
                if len(services) == 1 and next(iter(services)):
                    display = next(iter(services))
            result.append((value, display))
        return tuple(result)

    def _service_label_for_row(self, row: int, column: int, port: int) -> str:
        protocol_item = self.result_table.item(row, 1)
        try:
            protocol_text = protocol_item.data(_FILTER_VALUE_ROLE) if protocol_item else None
            if type(protocol_text) is not int:
                return str(port)
            protocol = protocol_text
        except (TypeError, ValueError):
            return str(port)
        try:
            service = service_definition(protocol, port)
        except (TypeError, ValueError):
            service = None
        return _format_port(port, service)

    def _filter_header_text(self, column: int) -> str:
        label = _FILTER_COLUMNS[column]
        selected = self._result_filter_values.get(column)
        suffix = f" [{len(selected)}]" if selected is not None else ""
        return f"{label}{suffix} ▾"

    def _update_filter_controls(self) -> None:
        active = bool(self._result_filter_values)
        self.clear_result_filters_button.setEnabled(active)
        active_count = sum(len(values) for values in self._result_filter_values.values())
        self.result_filter_button.setText("결과 필터" + (f" [{active_count}]" if active else ""))
        for column in _FILTER_COLUMNS:
            item = self.result_table.horizontalHeaderItem(column)
            if item is not None:
                item.setText(self._filter_header_text(column))

    @Slot()
    def _clear_result_filters(self) -> None:
        self._result_filter_values.clear()
        self._apply_result_filters()

    def _apply_result_filters(self) -> None:
        for row in range(self.result_table.rowCount()):
            self.result_table.setRowHidden(row, not self._row_matches_result_filters(row))
        self._update_filter_controls()
        visible = sum(
            not self.result_table.isRowHidden(row) for row in range(self.result_table.rowCount())
        )
        current_row = self.result_table.currentRow()
        selection_model = self.result_table.selectionModel()
        selected_rows = selection_model.selectedRows() if selection_model is not None else ()
        hidden_selection = any(
            self.result_table.isRowHidden(index.row()) for index in selected_rows
        )
        if (current_row >= 0 and self.result_table.isRowHidden(current_row)) or hidden_selection:
            self.result_table.clearSelection()
            if selection_model is not None:
                selection_model.clearCurrentIndex()
            self.raw_view.setPlainText("결과 행을 선택하면 해당 Raw 행을 표시합니다.")
        loaded_rows = self.result_table.rowCount()
        if self.result_table.rowCount() and visible == 0:
            empty_scope = (
                f"화면에 불러온 {loaded_rows:,}행 중 "
                if self._result_total_rows > loaded_rows
                else ""
            )
            self.result_empty_label.setText(f"{empty_scope}필터 조건에 맞는 행이 없습니다.")
            self.result_empty_label.setVisible(not self.raw_diagnostics_toggle.isChecked())
        elif self.result_table.rowCount():
            self.result_empty_label.setVisible(False)
        context = self.context_label.text()
        if "결과표 표시:" in context:
            prefix = context.split("결과표 표시:", 1)[0]
            filter_suffix = " · 필터 적용" if self._result_filter_values else ""
            count_summary = f"{visible}/{self._result_total_rows}"
            if self._result_total_rows > loaded_rows:
                count_summary = f"{visible}/{loaded_rows} · 전체 결과: {self._result_total_rows}"
            self._set_result_context(f"{prefix}결과표 표시: {count_summary}{filter_suffix}")
        controller = self.findChild(QObject, "darkNocConsoleController")
        schedule_refresh = getattr(controller, "schedule_refresh", None)
        if callable(schedule_refresh):
            schedule_refresh()

    def _row_matches_result_filters(self, row: int) -> bool:
        for column, selected in self._result_filter_values.items():
            item = self.result_table.item(row, column)
            value = item.data(_FILTER_VALUE_ROLE) if item is not None else None
            if value not in selected:
                return False
        return True

    @Slot(bool)
    def _set_details_visible(self, visible: bool) -> None:
        self.details.setVisible(visible)
        self.raw_diagnostics_toggle.setText("상세 정보 숨기기" if visible else "상세 정보 보기")
        visible_rows = sum(
            not self.result_table.isRowHidden(row) for row in range(self.result_table.rowCount())
        )
        self.result_empty_label.setVisible(visible_rows == 0 and not visible)
        if visible:
            self._sync_result_splitter_orientation(reset_sizes=True)

    def _sync_result_splitter_orientation(self, *, reset_sizes: bool = False) -> None:
        compact = (
            self.height() < _COMPACT_RESULT_LAYOUT_HEIGHT or self.advanced_toggle_button.isChecked()
        )
        orientation = Qt.Orientation.Horizontal if compact else Qt.Orientation.Vertical
        changed = self.result_splitter.orientation() != orientation
        self.result_splitter.setOrientation(orientation)
        if compact:
            self.details.setMinimumWidth(300)
            self.details.setMinimumHeight(0)
        else:
            self.details.setMinimumWidth(0)
            self.details.setMinimumHeight(180)
        if changed or reset_sizes:
            self._reset_result_splitter_sizes()
            QTimer.singleShot(0, self, self._reset_result_splitter_sizes)

    @Slot()
    def _reset_result_splitter_sizes(self) -> None:
        if self.result_splitter.orientation() == Qt.Orientation.Horizontal:
            available = max(self.result_splitter.width(), 600)
            self.result_splitter.setSizes([max(300, available - 320), 320])
            return
        available = max(self.result_splitter.height(), 300)
        self.result_splitter.setSizes([max(120, available - 180), 180])

    def _set_state(self, state: str) -> None:
        if state not in _OPERATOR_STATES:
            raise ValueError("invalid operator state")
        self.state_label.setText(state)
        self.state_label.setProperty("stateRole", _OPERATOR_STATE_ROLES[state])
        self.state_label.style().unpolish(self.state_label)
        self.state_label.style().polish(self.state_label)
        self.state_label.update()

    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.mm_group = QGroupBox("Mobility Conductor (MM)")
        mm_layout = QGridLayout(self.mm_group)
        self.mm_primary_name = QLineEdit("MM-Conductor")
        self.mm_primary_name.setAccessibleName("Primary MM 표시 이름")
        self.mm_primary_host = QLineEdit()
        self.mm_primary_host.setAccessibleName("Primary MM IPv4")
        self.mm_primary_port = self._port_spin()
        self.mm_primary_port.setAccessibleName("Primary MM SSH 포트")
        self.mm_primary_enabled = QCheckBox()
        self.mm_primary_enabled.setChecked(True)
        self.mm_primary_enabled.setAccessibleName("Primary MM 사용")
        self.mm_standby_name = QLineEdit("MM-Standby")
        self.mm_standby_name.setAccessibleName("Standby MM 표시 이름")
        self.mm_standby_host = QLineEdit()
        self.mm_standby_host.setAccessibleName("Standby MM IPv4")
        self.mm_standby_port = self._port_spin()
        self.mm_standby_port.setAccessibleName("Standby MM SSH 포트")
        self.mm_standby_enabled = QCheckBox()
        self.mm_standby_enabled.setChecked(True)
        self.mm_standby_enabled.setAccessibleName("Standby MM 사용")
        mm_layout.addWidget(QLabel("구분"), 0, 0)
        mm_layout.addWidget(QLabel("표시 이름"), 0, 1)
        mm_layout.addWidget(QLabel("IPv4"), 0, 2)
        mm_layout.addWidget(QLabel("SSH 포트"), 0, 3)
        mm_layout.addWidget(QLabel("사용"), 0, 4)
        mm_layout.addWidget(QLabel("Primary"), 1, 0)
        mm_layout.addWidget(self.mm_primary_name, 1, 1)
        mm_layout.addWidget(self.mm_primary_host, 1, 2)
        mm_layout.addWidget(self.mm_primary_port, 1, 3)
        mm_layout.addWidget(self.mm_primary_enabled, 1, 4)
        mm_layout.addWidget(QLabel("Standby"), 2, 0)
        mm_layout.addWidget(self.mm_standby_name, 2, 1)
        mm_layout.addWidget(self.mm_standby_host, 2, 2)
        mm_layout.addWidget(self.mm_standby_port, 2, 3)
        mm_layout.addWidget(self.mm_standby_enabled, 2, 4)

        self.md_group = QGroupBox("Managed Device (MD, 7240XM)")
        md_layout = QVBoxLayout(self.md_group)
        self.md_table = QTableWidget(4, 4)
        self.md_table.setAccessibleName("Managed Device 설정 표")
        self.md_table.setAccessibleDescription(
            "최대 네 대의 MD 사용 여부, 이름, IPv4와 포트를 설정합니다."
        )
        self.md_table.setHorizontalHeaderLabels(["사용", "표시 이름", "IPv4", "SSH 포트"])
        self.md_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        for row in range(4):
            enabled = QTableWidgetItem()
            enabled.setCheckState(_checked_state() if row == 0 else _unchecked_state())
            self.md_table.setItem(row, 0, enabled)
            self.md_table.setItem(row, 1, QTableWidgetItem(f"MD-{row + 1:02d}"))
            self.md_table.setItem(row, 2, QTableWidgetItem(""))
            self.md_table.setItem(row, 3, QTableWidgetItem("22"))
        md_layout.addWidget(self.md_table)

        self.timing_group = QGroupBox("모니터링 판정 기준")
        timing_layout = QFormLayout(self.timing_group)
        self.session_interval = QSpinBox()
        self.session_interval.setRange(3, 300)
        self.session_interval.setValue(5)
        self.location_interval = QSpinBox()
        self.location_interval.setRange(10, 3600)
        self.location_interval.setValue(30)
        self.close_misses = QSpinBox()
        self.close_misses.setRange(2, 10)
        self.close_misses.setValue(3)
        self.session_interval.setAccessibleName("세션 조회 주기")
        self.location_interval.setAccessibleName("클라이언트 위치 재확인 주기")
        self.close_misses.setAccessibleName("세션 종료 확인 횟수")
        self.close_misses.setAccessibleDescription(
            "세션이 연속으로 보이지 않는 횟수가 이 값에 도달하면 종료로 확정합니다."
        )
        self.close_misses.setToolTip("세션이 연속으로 N회 보이지 않을 때 종료로 확정합니다.")
        timing_layout.addRow("세션 조회 주기 (초)", self.session_interval)
        timing_layout.addRow("클라이언트 위치 재확인 주기 (초)", self.location_interval)
        timing_layout.addRow("세션 종료 확인 횟수 (회)", self.close_misses)

        save_row = QHBoxLayout()
        self.save_config_button = QPushButton("장비 설정 저장")
        self.save_config_button.setAccessibleName("장비 설정 저장")
        self.save_config_button.setAccessibleDescription(
            "MM, MD와 모니터링 주기 설정을 로컬에 저장합니다."
        )
        self.save_config_button.clicked.connect(self._save_config)
        save_row.addWidget(self.save_config_button)
        save_row.addStretch(1)
        self.settings_privacy_notice = QLabel(
            "장비 주소와 주기만 저장합니다. 사용자 이름과 암호는 저장하지 않습니다."
        )
        self.settings_privacy_notice.setWordWrap(True)

        layout.addWidget(self.mm_group)
        layout.addWidget(self.md_group)
        layout.addWidget(self.timing_group)
        layout.addLayout(save_row)
        layout.addWidget(self.settings_privacy_notice)
        layout.addStretch(1)
        return page

    def _build_history_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.history_toolbar = QFrame()
        self.history_toolbar.setObjectName("historyToolbar")
        toolbar = QHBoxLayout(self.history_toolbar)
        toolbar.setContentsMargins(10, 8, 10, 8)
        toolbar.setSpacing(8)
        self.refresh_history_button = QPushButton("새로고침")
        self.export_button = QPushButton("CSV 내보내기")
        self.html_export_button = QPushButton("HTML 보고서")
        self.delete_button = QPushButton("선택 삭제")
        self.delete_all_button = QPushButton("전체 기록 삭제")
        self.refresh_history_button.setAccessibleName("기록 새로고침")
        self.export_button.setAccessibleName("선택 실행 CSV 내보내기")
        self.html_export_button.setAccessibleName("선택 실행 HTML 보고서 내보내기")
        self.delete_button.setAccessibleName("선택 실행 삭제")
        self.delete_all_button.setAccessibleName("전체 기록 삭제")
        self.refresh_history_button.clicked.connect(self._refresh_history)
        self.export_button.clicked.connect(self._export_selected_run)
        self.html_export_button.clicked.connect(self._export_selected_run_html)
        self.delete_button.clicked.connect(lambda: self._delete_history(all_runs=False))
        self.delete_all_button.clicked.connect(lambda: self._delete_history(all_runs=True))
        toolbar.addWidget(self.refresh_history_button)
        self.history_export_label = QLabel("내보내기")
        self.history_export_label.setObjectName("toolbarSectionLabel")
        toolbar.addWidget(self.history_export_label)
        toolbar.addWidget(self.export_button)
        toolbar.addWidget(self.html_export_button)
        toolbar.addStretch(1)
        self.history_delete_label = QLabel("기록 정리")
        self.history_delete_label.setObjectName("toolbarSectionLabel")
        toolbar.addWidget(self.history_delete_label)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.delete_all_button)
        layout.addWidget(self.history_toolbar)
        self.storage_status_label = QLabel("저장소 현황을 확인하는 중입니다.")
        self.storage_status_label.setObjectName("storageStatus")
        self.storage_status_label.setAccessibleName("저장소 사용 현황")
        self.storage_status_label.setWordWrap(True)
        layout.addWidget(self.storage_status_label)
        self.history_empty_label = QLabel("기록을 불러오는 중입니다.")
        self.history_empty_label.setObjectName("emptyState")
        self.history_empty_label.setAccessibleName("실행 기록 안내")
        self.history_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.history_empty_label.setWordWrap(True)
        layout.addWidget(self.history_empty_label)
        self.history_table = QTableWidget(0, 7)
        self.history_table.setAccessibleName("실행 기록 표")
        self.history_table.setAccessibleDescription(
            "저장된 실행의 조회 대상 IP, 시작·종료 시각, 경과 시간, "
            "상태, 관측 결과 수와 최근 전달 코드를 표시합니다."
        )
        self.history_table.setHorizontalHeaderLabels(
            [
                "조회 대상",
                "시작 시각",
                "종료 시각",
                "경과 시간",
                "상태",
                "관측 결과",
                "최근 전달 코드",
            ]
        )
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.history_table.itemSelectionChanged.connect(self._sync_history_action_state)
        layout.addWidget(self.history_table)
        self.history_privacy_notice = QLabel(
            "Raw TXT, SQLite, CSV와 HTML 보고서에는 내부 IP 및 세션 메타데이터가 "
            "평문으로 남을 수 있습니다. "
            "자동 삭제하지 않으므로 보존 정책에 따라 수동으로 삭제하십시오."
        )
        self.history_privacy_notice.setWordWrap(True)
        layout.addWidget(self.history_privacy_notice)
        self._sync_history_action_state()
        return page

    def _update_setup_guide(self) -> None:
        configured_mm = any(
            enabled.isChecked() and bool(host.text().strip())
            for enabled, host in (
                (self.mm_primary_enabled, self.mm_primary_host),
                (self.mm_standby_enabled, self.mm_standby_host),
            )
        )
        configured_md = any(
            self._setting_item(row, 0).checkState() == _checked_state()
            and bool(self._setting_item(row, 2).text().strip())
            for row in range(self.md_table.rowCount())
        )
        self.setup_guide.setVisible(not (configured_mm and configured_md))

    @Slot(int)
    def _tab_changed(self, index: int) -> None:
        if self.tabs.widget(index) is self.history_page and self._history_dirty:
            self._refresh_history()
        if self.tabs.widget(index) is self.history_page:
            self._sync_history_elapsed_timer()
        else:
            self._history_elapsed_timer.stop()

    def _register_developer_inspector_catalog(self) -> None:
        inspector = self._developer_inspector
        if inspector is None:
            return

        common = "앱 > 공통"
        query = "앱 > 세션 조회"
        settings = "앱 > 장비 설정"
        history = "앱 > 기록 및 내보내기"
        widgets: tuple[tuple[QWidget, UiElementMetadata], ...] = (
            (self, _ui_metadata("메인 창", "MAIN-WINDOW", common, "애플리케이션 기본 창")),
            (
                self.statusBar(),
                _ui_metadata("상태 표시줄", "MAIN-STATUS-BAR", common, "작업 상태와 안내 표시"),
            ),
            (self.tabs, _ui_metadata("주 탭", "MAIN-TABS", common, "운영 화면 전환")),
            (
                self.tabs.tabBar(),
                _ui_metadata("주 탭 표시줄", "MAIN-TAB-BAR", common, "운영 화면 탭 선택"),
            ),
            (
                self.query_page,
                _ui_metadata("세션 조회 화면", "MAIN-QUERY-VIEW", query, "세션 조회 작업 화면"),
            ),
            (
                self.settings_page,
                _ui_metadata(
                    "장비 설정 화면", "MAIN-SETTINGS-VIEW", settings, "장비와 모니터링 설정 화면"
                ),
            ),
            (
                self.history_page,
                _ui_metadata(
                    "기록 및 내보내기 화면",
                    "MAIN-HISTORY-VIEW",
                    history,
                    "저장된 실행 기록 관리 화면",
                ),
            ),
            (
                self.connection_group,
                _ui_metadata(
                    "실행 자격증명 영역",
                    "MAIN-QUERY-CREDENTIALS-GROUP",
                    query,
                    "현재 실행에만 사용하는 자격증명 입력 영역",
                ),
            ),
            (
                self.username_edit,
                _ui_metadata(
                    "사용자 이름 입력",
                    "MAIN-QUERY-CREDENTIALS-USERNAME",
                    query,
                    "SSH 사용자 이름 입력",
                ),
            ),
            (
                self.password_edit,
                _ui_metadata(
                    "암호 입력",
                    "MAIN-QUERY-CREDENTIALS-PASSWORD",
                    query,
                    "세션 전용 SSH 암호 입력",
                ),
            ),
            (
                self.enable_edit,
                _ui_metadata(
                    "Enable 암호 입력",
                    "MAIN-QUERY-CREDENTIALS-ENABLE-SECRET",
                    query,
                    "선택적 Enable 암호 입력",
                ),
            ),
            (
                self.query_group,
                _ui_metadata(
                    "세션 조건 영역",
                    "MAIN-QUERY-CONDITIONS-GROUP",
                    query,
                    "조회할 세션 조건 입력 영역",
                ),
            ),
            (
                self.source_ip_edit,
                _ui_metadata(
                    "출발지 IP 입력", "MAIN-QUERY-CONDITIONS-SOURCE-IP", query, "출발지 IPv4 입력"
                ),
            ),
            (
                self.destination_ip_edit,
                _ui_metadata(
                    "목적지 IP 입력",
                    "MAIN-QUERY-CONDITIONS-DESTINATION-IP",
                    query,
                    "목적지 IPv4 입력",
                ),
            ),
            (
                self.source_port_edit,
                _ui_metadata(
                    "출발지 포트 입력",
                    "MAIN-QUERY-CONDITIONS-SOURCE-PORT",
                    query,
                    "선택적 출발지 포트 입력",
                ),
            ),
            (
                self.destination_port_edit,
                _ui_metadata(
                    "목적지 포트 입력",
                    "MAIN-QUERY-CONDITIONS-DESTINATION-PORT",
                    query,
                    "선택적 목적지 포트 입력",
                ),
            ),
            (
                self.bidirectional_check,
                _ui_metadata(
                    "양방향 검색 선택",
                    "MAIN-QUERY-CONDITIONS-BIDIRECTIONAL",
                    query,
                    "IP와 포트를 교환한 반대 방향 포함 여부 선택",
                ),
            ),
            (
                self.query_button,
                _ui_metadata("현재 조회", "MAIN-QUERY-RUN", query, "단일 조회 시작"),
            ),
            (
                self.monitor_button,
                _ui_metadata(
                    "지속 모니터링 시작",
                    "MAIN-QUERY-MONITOR-START",
                    query,
                    "지속 모니터링 시작",
                ),
            ),
            (
                self.stop_button,
                _ui_metadata("중지", "MAIN-QUERY-STOP", query, "실행 중인 작업 중지"),
            ),
            (
                self.state_label,
                _ui_metadata("조회 상태", "MAIN-QUERY-STATE", query, "현재 조회 상태 표시"),
            ),
            (
                self.context_label,
                _ui_metadata(
                    "MM/MD 문맥", "MAIN-QUERY-CONTEXT", query, "조회에 사용된 장비 문맥 표시"
                ),
            ),
            (
                self.detail_columns_toggle,
                _ui_metadata(
                    "상세 열 보기",
                    "MAIN-QUERY-DETAIL-COLUMNS-TOGGLE",
                    query,
                    "결과 표의 상세 열을 현재 프로세스에서만 표시하거나 숨김",
                ),
            ),
            (
                self.result_table,
                _ui_metadata("조회 결과 표", "MAIN-QUERY-RESULT-TABLE", query, "세션 조회 결과 표"),
            ),
            (
                self.result_table.horizontalHeader(),
                _ui_metadata(
                    "조회 결과 표 헤더",
                    "MAIN-QUERY-RESULT-TABLE-HEADER",
                    query,
                    "결과 열 제목 표시",
                ),
            ),
            (
                self.result_table.viewport(),
                _ui_metadata(
                    "조회 결과 표 본문", "MAIN-QUERY-RESULT-TABLE-BODY", query, "결과 행 표시 영역"
                ),
            ),
            (
                self.details,
                _ui_metadata(
                    "조회 상세 탭", "MAIN-QUERY-DETAIL-TABS", query, "Raw와 진단 상세 전환"
                ),
            ),
            (
                self.details.tabBar(),
                _ui_metadata(
                    "조회 상세 탭 표시줄",
                    "MAIN-QUERY-DETAIL-TAB-BAR",
                    query,
                    "Raw와 진단 상세 탭 선택",
                ),
            ),
            (
                self.raw_view,
                _ui_metadata("Raw 보기", "MAIN-QUERY-RAW-VIEW", query, "선택 행 Raw 표시"),
            ),
            (
                self.diagnostics_list,
                _ui_metadata(
                    "진단 이벤트 목록",
                    "MAIN-QUERY-DIAGNOSTICS-LIST",
                    query,
                    "조회 진단 이벤트 표시",
                ),
            ),
            (
                self.mm_group,
                _ui_metadata(
                    "Mobility Conductor 영역", "MAIN-SETTINGS-MM-GROUP", settings, "MM 설정 영역"
                ),
            ),
            (
                self.mm_primary_name,
                _ui_metadata(
                    "Primary MM 표시 이름",
                    "MAIN-SETTINGS-MM-PRIMARY-NAME",
                    settings,
                    "Primary MM 표시 이름 입력",
                ),
            ),
            (
                self.mm_primary_host,
                _ui_metadata(
                    "Primary MM 주소",
                    "MAIN-SETTINGS-MM-PRIMARY-HOST",
                    settings,
                    "Primary MM IPv4 입력",
                ),
            ),
            (
                self.mm_primary_port,
                _ui_metadata(
                    "Primary MM SSH 포트",
                    "MAIN-SETTINGS-MM-PRIMARY-PORT",
                    settings,
                    "Primary MM SSH 포트 입력",
                ),
            ),
            (
                self.mm_primary_enabled,
                _ui_metadata(
                    "Primary MM 사용",
                    "MAIN-SETTINGS-MM-PRIMARY-ENABLED",
                    settings,
                    "Primary MM 사용 여부 선택",
                ),
            ),
            (
                self.mm_standby_name,
                _ui_metadata(
                    "Standby MM 표시 이름",
                    "MAIN-SETTINGS-MM-STANDBY-NAME",
                    settings,
                    "Standby MM 표시 이름 입력",
                ),
            ),
            (
                self.mm_standby_host,
                _ui_metadata(
                    "Standby MM 주소",
                    "MAIN-SETTINGS-MM-STANDBY-HOST",
                    settings,
                    "Standby MM IPv4 입력",
                ),
            ),
            (
                self.mm_standby_port,
                _ui_metadata(
                    "Standby MM SSH 포트",
                    "MAIN-SETTINGS-MM-STANDBY-PORT",
                    settings,
                    "Standby MM SSH 포트 입력",
                ),
            ),
            (
                self.mm_standby_enabled,
                _ui_metadata(
                    "Standby MM 사용",
                    "MAIN-SETTINGS-MM-STANDBY-ENABLED",
                    settings,
                    "Standby MM 사용 여부 선택",
                ),
            ),
            (
                self.md_group,
                _ui_metadata(
                    "Managed Devices 영역", "MAIN-SETTINGS-MD-GROUP", settings, "MD 설정 영역"
                ),
            ),
            (
                self.md_table,
                _ui_metadata(
                    "Managed Devices 표", "MAIN-SETTINGS-MD-TABLE", settings, "MD 설정 표"
                ),
            ),
            (
                self.md_table.horizontalHeader(),
                _ui_metadata(
                    "Managed Devices 표 헤더",
                    "MAIN-SETTINGS-MD-TABLE-HEADER",
                    settings,
                    "MD 설정 열 제목 표시",
                ),
            ),
            (
                self.md_table.viewport(),
                _ui_metadata(
                    "Managed Devices 표 본문",
                    "MAIN-SETTINGS-MD-TABLE-BODY",
                    settings,
                    "MD 설정 행 표시 영역",
                ),
            ),
            (
                self.timing_group,
                _ui_metadata(
                    "모니터링 영역", "MAIN-SETTINGS-MONITOR-GROUP", settings, "모니터링 주기 설정"
                ),
            ),
            (
                self.session_interval,
                _ui_metadata(
                    "세션 조회 주기",
                    "MAIN-SETTINGS-MONITOR-SESSION-INTERVAL",
                    settings,
                    "세션 조회 주기 입력",
                ),
            ),
            (
                self.location_interval,
                _ui_metadata(
                    "클라이언트 위치 재확인 주기",
                    "MAIN-SETTINGS-MONITOR-LOCATION-INTERVAL",
                    settings,
                    "클라이언트 위치 재확인 주기 입력",
                ),
            ),
            (
                self.close_misses,
                _ui_metadata(
                    "세션 종료 확인 횟수",
                    "MAIN-SETTINGS-MONITOR-CLOSE-MISSES",
                    settings,
                    "세션이 보이지 않을 때 종료로 확정하기 위한 연속 미확인 횟수 입력",
                ),
            ),
            (
                self.save_config_button,
                _ui_metadata(
                    "장비 설정 저장", "MAIN-SETTINGS-SAVE", settings, "장비와 주기 설정 저장"
                ),
            ),
            (
                self.settings_privacy_notice,
                _ui_metadata(
                    "설정 보안 안내",
                    "MAIN-SETTINGS-PRIVACY-NOTICE",
                    settings,
                    "자격증명 비저장 안내",
                ),
            ),
            (
                self.refresh_history_button,
                _ui_metadata(
                    "기록 새로고침", "MAIN-HISTORY-REFRESH", history, "저장된 실행 기록 새로고침"
                ),
            ),
            (
                self.export_button,
                _ui_metadata(
                    "CSV 내보내기", "MAIN-HISTORY-EXPORT-CSV", history, "선택 실행 CSV 내보내기"
                ),
            ),
            (
                self.html_export_button,
                _ui_metadata(
                    "HTML 보고서 내보내기",
                    "MAIN-HISTORY-EXPORT-HTML",
                    history,
                    "선택 실행 HTML 보고서 내보내기",
                ),
            ),
            (
                self.delete_button,
                _ui_metadata(
                    "선택 실행 삭제",
                    "MAIN-HISTORY-DELETE-SELECTED",
                    history,
                    "선택한 실행 기록 삭제",
                ),
            ),
            (
                self.delete_all_button,
                _ui_metadata(
                    "전체 기록 삭제", "MAIN-HISTORY-DELETE-ALL", history, "모든 실행 기록 삭제"
                ),
            ),
            (
                self.history_table,
                _ui_metadata(
                    "실행 기록 표", "MAIN-HISTORY-RUN-TABLE", history, "저장된 실행 기록 표"
                ),
            ),
            (
                self.history_table.horizontalHeader(),
                _ui_metadata(
                    "실행 기록 표 헤더",
                    "MAIN-HISTORY-RUN-TABLE-HEADER",
                    history,
                    "기록 열 제목 표시",
                ),
            ),
            (
                self.history_table.viewport(),
                _ui_metadata(
                    "실행 기록 표 본문", "MAIN-HISTORY-RUN-TABLE-BODY", history, "기록 행 표시 영역"
                ),
            ),
            (
                self.history_privacy_notice,
                _ui_metadata(
                    "기록 개인정보 안내",
                    "MAIN-HISTORY-PRIVACY-NOTICE",
                    history,
                    "로컬 기록과 내보내기 데이터 보안 안내",
                ),
            ),
        )
        for widget, metadata in widgets:
            inspector.register_widget(widget, metadata)

        for metadata in (
            _ui_metadata(
                "조회 결과 선택 행",
                "MAIN-QUERY-RESULT-TABLE-SELECTION",
                query,
                "조회 결과에서 선택한 행 개념",
            ),
            _ui_metadata(
                "Managed Devices 선택 셀",
                "MAIN-SETTINGS-MD-TABLE-SELECTION",
                settings,
                "MD 설정에서 선택한 셀 개념",
            ),
            _ui_metadata(
                "실행 기록 선택 행",
                "MAIN-HISTORY-RUN-TABLE-SELECTION",
                history,
                "실행 기록에서 선택한 행 개념",
            ),
        ):
            inspector.register_catalog_item(metadata)

    @staticmethod
    def _port_spin() -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(1, 65535)
        spin.setValue(22)
        return spin

    def _read_config_from_ui(self) -> AppConfig:
        devices: list[DeviceTarget] = []
        for row in range(self.md_table.rowCount()):
            enabled_item = self.md_table.item(row, 0)
            name_item = self.md_table.item(row, 1)
            host_item = self.md_table.item(row, 2)
            port_item = self.md_table.item(row, 3)
            enabled = enabled_item is not None and enabled_item.checkState() == _checked_state()
            host = host_item.text().strip() if host_item else ""
            if not host and not enabled:
                continue
            if not host:
                raise ValueError(f"MD {row + 1}의 IPv4를 입력하십시오.")
            devices.append(
                DeviceTarget(
                    name=name_item.text().strip() if name_item else f"MD-{row + 1:02d}",
                    host=host,
                    port=int(port_item.text()) if port_item else 22,
                    enabled=enabled,
                )
            )
        return AppConfig(
            mm_primary=DeviceTarget(
                self.mm_primary_name.text(),
                self.mm_primary_host.text().strip(),
                self.mm_primary_port.value(),
                self.mm_primary_enabled.isChecked(),
            ),
            mm_standby=DeviceTarget(
                self.mm_standby_name.text(),
                self.mm_standby_host.text().strip(),
                self.mm_standby_port.value(),
                self.mm_standby_enabled.isChecked(),
            ),
            managed_devices=tuple(devices),
            session_interval_seconds=self.session_interval.value(),
            location_interval_seconds=self.location_interval.value(),
            close_after_misses=self.close_misses.value(),
        )

    def _load_config(self) -> None:
        try:
            config = self._config_repository.load()
        except (ConfigError, OSError, ValueError):
            support_code = support_code_for_ui_failure(UiFailureKey.CONFIG_READ_FAILED)
            QMessageBox.warning(
                self,
                "설정 읽기 실패",
                "설정 파일을 안전하게 읽지 못했습니다. 파일 형식과 권한을 확인하십시오."
                f"\n\n전달 코드: {support_code.value}",
            )
            return
        if config is None:
            return
        self.mm_primary_name.setText(config.mm_primary.name)
        self.mm_primary_host.setText(config.mm_primary.host)
        self.mm_primary_port.setValue(config.mm_primary.port)
        self.mm_primary_enabled.setChecked(config.mm_primary.enabled)
        self.mm_standby_name.setText(config.mm_standby.name)
        self.mm_standby_host.setText(config.mm_standby.host)
        self.mm_standby_port.setValue(config.mm_standby.port)
        self.mm_standby_enabled.setChecked(config.mm_standby.enabled)
        self.session_interval.setValue(config.session_interval_seconds)
        self.location_interval.setValue(config.location_interval_seconds)
        self.close_misses.setValue(config.close_after_misses)
        for row in range(self.md_table.rowCount()):
            self._setting_item(row, 0).setCheckState(_unchecked_state())
            self._setting_item(row, 1).setText(f"MD-{row + 1:02d}")
            self._setting_item(row, 2).setText("")
            self._setting_item(row, 3).setText("22")
        for row, device in enumerate(config.managed_devices[: self.md_table.rowCount()]):
            self._setting_item(row, 0).setCheckState(
                _checked_state() if device.enabled else _unchecked_state()
            )
            self._setting_item(row, 1).setText(device.name)
            self._setting_item(row, 2).setText(device.host)
            self._setting_item(row, 3).setText(str(device.port))

    def _setting_item(self, row: int, column: int) -> QTableWidgetItem:
        item = self.md_table.item(row, column)
        if item is None:
            item = QTableWidgetItem()
            self.md_table.setItem(row, column, item)
        return item

    @Slot()
    def _save_config(self) -> None:
        try:
            config = self._read_config_from_ui()
            self._config_repository.save(config)
        except (ConfigError, OSError, ValueError):
            support_code = support_code_for_ui_failure(UiFailureKey.CONFIG_SAVE_FAILED)
            QMessageBox.warning(
                self,
                "설정 저장 실패",
                "설정 파일을 안전하게 저장하지 못했습니다. 저장 위치의 권한을 확인하십시오."
                f"\n\n전달 코드: {support_code.value}",
            )
            return
        self._update_setup_guide()
        self.statusBar().showMessage("장비 설정을 안전하게 저장했습니다.", 5000)

    def _read_query(self) -> tuple[AppConfig, QueryRequest, Credentials]:
        config = self._read_config_from_ui()
        source_port = _optional_port(self.source_port_edit.text(), "출발지 포트")
        destination_port = _optional_port(self.destination_port_edit.text(), "목적지 포트")
        request = QueryRequest(
            self.source_ip_edit.text().strip(),
            self.destination_ip_edit.text().strip(),
            source_port,
            destination_port,
            self.bidirectional_check.isChecked(),
        )
        credentials = Credentials(
            self.username_edit.text(),
            self.password_edit.text(),
            self.enable_edit.text(),
        )
        return config, request, credentials

    @Slot()
    def _start_query(self) -> None:
        if (
            self._query_running
            or self._storage_task_running
            or self._closing_requested
            or self._shutdown.active
            or self._shutdown.restart_required
        ):
            return
        try:
            config, request, credentials = self._read_query()
        except ValueError as exc:
            self._show_query_input_error(exc)
            return
        if not self._monitoring:
            self._last_counters.clear()
            self._clear_result_filters()
            self._run_started_at = datetime.now(UTC)
            self._run_started_monotonic = monotonic()
        elif self._run_started_at is None:
            self._run_started_at = datetime.now(UTC)
            self._run_started_monotonic = monotonic()
        elif self._run_started_monotonic is None:
            self._run_started_monotonic = monotonic()
        self._elapsed_timer.start()
        self._refresh_elapsed_labels()
        self._shutdown.reset()
        self._shutdown_finalization_succeeded = None
        self._query_running = True
        self._task_generation += 1
        generation = self._task_generation
        token = CancellationToken()
        self._cancel_token = token
        self._set_busy(True)
        self._set_state("조회 중")

        def approve_host_key(
            target: DeviceTarget,
            info: HostKeyInfo,
            deadline: PollDeadline | None = None,
        ) -> bool:
            return self._approval.approve_host_key(
                target,
                info,
                cancel_token=token,
                generation=generation,
                deadline=deadline,
            )

        def approve_full_scan(
            current_request: QueryRequest,
            devices: tuple[DeviceTarget, ...],
            deadline: PollDeadline | None = None,
        ) -> bool:
            return self._approval.approve_full_scan(
                current_request,
                devices,
                cancel_token=token,
                generation=generation,
                deadline=deadline,
            )

        query_capacity_check = getattr(self._store, "ensure_query_capacity", None)
        if not callable(query_capacity_check):
            query_capacity_check = None
        storage_health_check = getattr(self._store, "storage_health", None)
        if not callable(storage_health_check):
            storage_health_check = None
        elif self._monitoring:
            now = monotonic()
            if now < self._next_storage_health_check_at:
                storage_health_check = None
            else:
                self._next_storage_health_check_at = now + _STORAGE_HEALTH_INTERVAL_SECONDS
        task = _QueryTask(
            self._executor,
            config,
            request,
            credentials,
            self._monitoring,
            token,
            approve_host_key,
            approve_full_scan,
            generation,
            query_capacity_check,
            storage_health_check,
            dict(self._last_counters),
            self.close_misses.value(),
        )
        self._current_task = task
        task.signals.succeeded.connect(self._task_succeeded)
        task.signals.failed.connect(self._task_failed)
        task.signals.finished.connect(self._query_finished)
        task.signals.storage_warning.connect(self._show_storage_warning)
        task.signals.storage_health_updated.connect(self._storage_health_updated)
        task.signals.storage_health_unavailable.connect(self._show_storage_health_unavailable)
        _start_daemon_task(task.run, f"aruba-session-query-{generation}")

    @Slot()
    def _start_monitoring(self) -> None:
        if (
            self._monitoring
            or self._closing_requested
            or self._shutdown.active
            or self._shutdown.restart_required
        ):
            return
        try:
            self._read_query()
        except ValueError as exc:
            self._show_query_input_error(exc)
            return
        self._last_counters.clear()
        self._run_started_at = datetime.now(UTC)
        self._run_started_monotonic = monotonic()
        self._clear_result_filters()
        self._monitoring = True
        self._next_storage_health_check_at = 0.0
        self._next_monitor_delay_seconds = float(self.session_interval.value())
        self._set_monitor_inputs_enabled(False)
        self.monitor_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._start_query()

    def _show_query_input_error(self, exc: ValueError) -> None:
        QMessageBox.warning(self, "입력 확인", str(exc))
        self._cancel_active_work()
        self._set_state("확인 필요")
        self.statusBar().showMessage("입력값을 확인한 뒤 다시 시도해 주세요.", 5000)

    @Slot()
    def _stop_work(self) -> None:
        status = "조회 중" if self._query_running else "대기"
        self.statusBar().showMessage("진행 중인 조회를 안전하게 중지하고 있습니다.", 5000)
        self._cancel_active_work(status=status, user_requested=True)

    def _cancel_active_work(
        self,
        *,
        status: str | None = None,
        user_requested: bool = False,
    ) -> None:
        was_active = self._query_running or self._monitoring
        self._monitoring = False
        self._last_counters.clear()
        self._monitor_timer.stop()
        if self._cancel_token is not None:
            self._cancel_token.cancel()
        current_generation = (
            self._current_task.generation if self._current_task is not None else None
        )
        if user_requested and current_generation is not None:
            self._user_cancel_generation = current_generation
        self._approval.cancel_pending(current_generation)
        if was_active or self._closing_requested:
            self._shutdown.request()
        if status is not None and was_active:
            self._set_state(status)
        self._set_monitor_inputs_enabled(True)
        self._set_busy(self._query_running)
        if not self._query_running:
            self._elapsed_timer.stop()

    @Slot(int, object)
    def _task_succeeded(self, generation: int, outcome: object) -> None:
        if (
            not self._owns_task(generation)
            or self._closing_requested
            or self._user_cancel_generation == generation
            or self._environment_cancel_generation == generation
        ):
            return
        self._display_outcome(outcome)

    @Slot(int, object)
    def _task_failed(self, generation: int, exc: object) -> None:
        if (
            not self._owns_task(generation)
            or self._closing_requested
            or self._environment_cancel_generation == generation
        ):
            return
        failure = exc if isinstance(exc, Exception) else RuntimeError("invalid task failure")
        self._display_failure(failure)

    def _owns_task(self, generation: int) -> bool:
        return (
            self._current_task is not None
            and self._current_task.generation == generation
            and self._task_generation == generation
        )

    def _set_result_context(self, text: str) -> None:
        self.context_label.setText(text)
        self._sync_result_accessibility_context()

    @Slot()
    def _refresh_elapsed_labels(self) -> None:
        started = self._run_started_at
        if started is None:
            self.elapsed_label.setText("시작 시각: - · 경과: 00:00:00")
            return
        monotonic_started = self._run_started_monotonic
        elapsed = (
            _format_elapsed_seconds(monotonic() - monotonic_started)
            if monotonic_started is not None
            else "00:00:00"
        )
        local_started = started.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")
        self.elapsed_label.setText(f"시작 시각: {local_started} · 경과: {elapsed}")

    def _sync_result_accessibility_context(self) -> None:
        context = self.context_label.text().strip()
        suffix = f" 현재 조회 범위: {context}." if context else ""
        if self._result_filter_values:
            suffix += " 현재 결과 필터가 적용되어 있습니다."
        self.result_table.setAccessibleDescription(
            f"{_RESULT_TABLE_ACCESSIBLE_DESCRIPTION}{suffix}"
        )

    @Slot(object)
    def _display_outcome(self, outcome: object) -> None:
        prepared = (
            outcome
            if isinstance(outcome, _PreparedDisplayOutcome)
            else _prepare_display_outcome(
                outcome,
                previous_counters=self._last_counters,
                close_after_misses=self.close_misses.value(),
                monitoring=self._monitoring,
            )
        )
        outcome = prepared.outcome
        observations = tuple(getattr(outcome, "observations", ()))
        authoritative = bool(getattr(outcome, "authoritative", False))
        self._result_render_timer.stop()
        self._result_render_generation += 1
        self._pending_result_rows = prepared.visible_rows
        self._pending_result_index = 0
        self._pending_result_total_rows = prepared.total_rows
        self._result_total_rows = prepared.total_rows
        self.result_table.setRowCount(0)
        self.result_empty_label.setText(
            "조회 조건과 일치하는 세션이 없습니다."
            if authoritative
            else "확인 가능한 세션 결과가 없습니다. 진단 이벤트를 확인하십시오."
        )
        self.result_empty_label.setVisible(
            not prepared.visible_rows and not self.raw_diagnostics_toggle.isChecked()
        )
        self._render_next_result_chunk()
        self._last_counters = prepared.next_counters if self._monitoring else {}
        used_mm = getattr(outcome, "used_mm", None) or "-"
        controllers = ", ".join(getattr(outcome, "controllers", ())) or "-"
        self._set_result_context(
            f"MM: {used_mm}   |   조회 MD: {controllers}   |   "
            f"이번 조회 발견 행: {len(observations)}   |   "
            f"결과표 표시: {len(prepared.visible_rows)}/{prepared.total_rows}"
        )
        if self._result_filter_values:
            self._apply_result_filters()
        self.diagnostics_list.clear()
        for event in getattr(outcome, "diagnostics", ()):
            code = getattr(event, "code", None)
            code_text = getattr(code, "value", code) if code is not None else "INFO"
            stage = str(getattr(event, "stage", "-"))
            support_code = support_code_for(stage, code)
            self.diagnostics_list.addItem(
                f"[{support_code.value}] [{stage}] {code_text}: {getattr(event, 'message', '')}"
            )
        if prepared.total_rows > _MAX_VISIBLE_RESULT_ROWS:
            self.diagnostics_list.addItem(
                "[UI] DISPLAY_LIMIT: 화면에는 처음 2,000행만 표시했습니다. "
                "전체 결과는 저장된 기록 또는 내보내기에서 확인하십시오."
            )
        self.raw_view.setPlainText("결과 행을 선택하면 해당 Raw 행을 표시합니다.")

        retry_after = _nonnegative_float(getattr(outcome, "retry_after_seconds", 0))
        transient_failures = _nonnegative_int(getattr(outcome, "consecutive_transient_failures", 0))
        self._next_monitor_delay_seconds = (
            retry_after if retry_after > 0 else float(self.session_interval.value())
        )
        fatal_event = _fatal_diagnostic_event(outcome)
        fatal_code = _diagnostic_code_text(fatal_event)
        if bool(getattr(outcome, "cancelled", False)):
            self._set_state("대기")
        elif fatal_code is not None:
            if self._monitoring:
                self._cancel_active_work()
            reason = {
                "AUTH_FAILED": "인증 확인",
                "HOST_KEY_CHANGED": "호스트 키 확인",
                "HOST_KEY_UNKNOWN": "호스트 키 승인 필요",
                "PROMPT_PARSE_FAILED": "장비 응답 확인",
                "COMMAND_REJECTED": "명령 권한 확인",
                "COMMAND_VARIANT_UNVERIFIED": "장비 명령 변형 확인",
                "DB_WRITE_FAILED": "로컬 기록 저장 확인",
                "STORAGE_LOW_SPACE": "저장 공간 확인",
            }.get(fatal_code, "연결 확인")
            support_code = support_code_for(
                str(getattr(fatal_event, "stage", "-")),
                getattr(fatal_event, "code", None),
            )
            self._set_state("확인 필요")
            self.statusBar().showMessage(
                f"{reason}: 전달 코드 {support_code.value}를 확인해 주세요.", 10000
            )
            if fatal_code != "HOST_KEY_UNKNOWN":
                QMessageBox.warning(
                    self,
                    "조회 중단",
                    f"{reason}: 진단 이벤트를 확인하십시오.\n\n전달 코드: {support_code.value}",
                )
        elif self._monitoring and transient_failures > 0:
            self._set_state("재시도 중")
        elif authoritative:
            self._set_state("정상")
        else:
            self._set_state("확인 필요")
        self._mark_history_dirty()

    @Slot()
    def _render_next_result_chunk(self) -> None:
        start = self._pending_result_index
        if start >= len(self._pending_result_rows):
            self._pending_result_rows = ()
            self._pending_result_index = 0
            self.result_table.viewport().update()
            return
        stop = min(start + _RESULT_RENDER_CHUNK_SIZE, len(self._pending_result_rows))
        self.result_table.setUpdatesEnabled(False)
        try:
            for row in self._pending_result_rows[start:stop]:
                self._append_observation(
                    row.observation,
                    packet_delta=row.packet_delta,
                    byte_delta=row.byte_delta,
                    lifecycle_status=row.lifecycle_status,
                )
        finally:
            self.result_table.setUpdatesEnabled(True)
        self._pending_result_index = stop
        self.result_table.viewport().update()
        if stop < len(self._pending_result_rows):
            self._result_render_timer.start(0)
        else:
            self._pending_result_rows = ()
            self._pending_result_index = 0
            self._apply_result_filters()

    def _append_observation(
        self,
        observation: SessionObservation,
        *,
        packet_delta: str = "-",
        byte_delta: str = "-",
        lifecycle_status: str | None = None,
    ) -> None:
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        severity = overall_flag_severity(observation.flags)
        observation_status = lifecycle_status or "현재 관측됨"
        source_port = _format_port_for_observation(observation.protocol, observation.source_port)
        destination_port = _format_port_for_observation(
            observation.protocol,
            observation.destination_port,
        )
        values = (
            observation.controller_name,
            _safe_protocol_label(observation.protocol),
            observation.source_ip,
            source_port,
            observation.destination_ip,
            destination_port,
            _display_number(observation.packets),
            _display_number(observation.bytes_count),
            packet_delta,
            byte_delta,
            _display_number(observation.age),
            _display_number(observation.cpu_id),
            _display_observed_at(observation),
            observation.flags or "-",
            observation_status,
            "",
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setData(_raw_data_role(), observation.raw_line)
            if column == 1:
                item.setData(_FILTER_VALUE_ROLE, observation.protocol)
            if column in (2, 4):
                item.setData(_FILTER_VALUE_ROLE, value)
            if column in (3, 5):
                port = observation.source_port if column == 3 else observation.destination_port
                item.setData(_FILTER_VALUE_ROLE, port)
                try:
                    service = service_definition(observation.protocol, port)
                except (TypeError, ValueError):
                    service = None
                if service is not None:
                    item.setToolTip(
                        "포트 번호 기준 대표 서비스 후보입니다. "
                        "실제 트래픽 서비스와 다를 수 있습니다."
                    )
            if column == 13 and self.property("themeContrast") != "high":
                item.setForeground(
                    _severity_color(
                        severity.name,
                        dark=self.property("darkNocConsoleInstalled") is True,
                    )
                )
            if column == 14:
                item.setToolTip(
                    f"{observation_status}\n이 값은 장비 장애나 통신 성공 판정이 아닙니다."
                )
            self.result_table.setItem(row, column, item)
        if self._result_filter_values:
            self.result_table.setRowHidden(row, not self._row_matches_result_filters(row))

    @Slot()
    def _show_selected_raw(self) -> None:
        row = self.result_table.currentRow()
        if row < 0:
            return
        item = self.result_table.item(row, 0)
        raw = item.data(_raw_data_role()) if item is not None else ""
        self.raw_view.setPlainText(str(raw or ""))

    @Slot(object)
    def _display_failure(self, exc: Exception) -> None:
        code, message = _safe_query_failure(exc)
        support_reference = _support_reference_for_query_failure(exc, code)
        self._cancel_active_work()
        self.result_empty_label.setText(
            "조회가 취소되었습니다. 조건을 확인한 뒤 다시 시작할 수 있습니다."
            if code == ErrorCode.CANCELLED.value
            else "조회 결과를 표시하지 못했습니다. 진단 이벤트를 확인하십시오."
        )
        self.result_empty_label.setVisible(
            self.result_table.rowCount() == 0 and not self.raw_diagnostics_toggle.isChecked()
        )
        self.diagnostics_list.clear()
        self.diagnostics_list.addItem(f"[{support_reference}] [{code}] {message}")
        self._set_state("대기" if code == ErrorCode.CANCELLED.value else "확인 필요")
        if code != ErrorCode.CANCELLED.value:
            self.raw_diagnostics_toggle.setChecked(True)
            self.details.setCurrentWidget(self.diagnostics_list)
            QMessageBox.warning(
                self,
                "조회 실패",
                f"{code}: {message}\n\n전달 코드: {support_reference}",
            )

    @Slot(int)
    def _query_finished(self, generation: int) -> None:
        if not self._owns_task(generation):
            return
        self._approval.cancel_pending(generation)
        user_cancelled = self._user_cancel_generation == generation
        environment_cancelled = self._environment_cancel_generation == generation
        self._query_running = False
        self._current_task = None
        self._user_cancel_generation = None
        self._environment_cancel_generation = None
        self._set_busy(False)
        self._cancel_token = None
        self._refresh_elapsed_labels()
        if not self._monitoring:
            self._elapsed_timer.stop()
        if user_cancelled and not self._closing_requested:
            self._set_state("대기")
        elif environment_cancelled and self._monitoring and not self._closing_requested:
            self._set_state("재시도 중")
            self._next_monitor_delay_seconds = 1.0
        if self._monitoring and not self._closing_requested:
            interval_ms = max(1_000, round(self._next_monitor_delay_seconds * 1_000))
            self._monitor_timer.start(interval_ms)
        self._drain_preview_discard_queue()
        if self._close_when_idle:
            self._close_if_idle()

    @Slot(str)
    def _runtime_discontinuity(self, reason: str) -> None:
        invalidate = getattr(self._executor, "invalidate_monitor_location", None)
        if callable(invalidate):
            try:
                invalidate()
            except Exception:
                support_code = support_code_for_ui_failure(UiFailureKey.RUNTIME_CLEANUP_FAILED)
                self.diagnostics_list.addItem(
                    f"[{support_code.value}] [RUNTIME_ENVIRONMENT] "
                    "위치 캐시를 초기화하지 못했습니다."
                )
        if not self._monitoring or self._closing_requested:
            return
        self._monitor_timer.stop()
        self._next_monitor_delay_seconds = 1.0
        self._set_state("재시도 중")
        reason_label = "절전 복귀" if reason == "SYSTEM_RESUMED" else "네트워크 변경"
        self.statusBar().showMessage(
            f"{reason_label}을 감지했습니다. 다음 조회에서 MM 위치를 다시 확인합니다.",
            10_000,
        )
        if self._query_running and self._current_task is not None:
            self._environment_cancel_generation = self._current_task.generation
            if self._cancel_token is not None:
                self._cancel_token.cancel()
            self._approval.cancel_pending(self._current_task.generation)
            return
        self._monitor_timer.start(1_000)

    @Slot(str)
    def _shutdown_stage_changed(self, stage: str) -> None:
        self.statusBar().showMessage(stage)
        self._set_busy(self._query_running)

    @Slot(bool, str)
    def _shutdown_settled(self, succeeded: bool, exception_type: str) -> None:
        if not self._close_recovery_deferred:
            self._shutdown_finalization_succeeded = succeeded
        if not succeeded:
            support_code = support_code_for_ui_failure(UiFailureKey.SHUTDOWN_INCOMPLETE)
            message = (
                f"[{support_code.value}] [SHUTDOWN_DEFERRED] "
                "종료 기록은 다음 실행에서 안전하게 복구합니다."
                if exception_type == "ShutdownGraceTimeout"
                else f"[{support_code.value}] [SHUTDOWN_FINALIZE_FAILED] "
                "종료 기록 정리를 완료하지 못했습니다."
            )
            self.diagnostics_list.addItem(message)
            if not self._closing_requested:
                self._set_state("확인 필요")
        self._set_busy(self._query_running)
        self._close_if_idle()

    def _set_busy(self, busy: bool) -> None:
        interactive = not self._closing_requested
        available = (
            interactive
            and not self._storage_task_running
            and not self._shutdown.active
            and not self._shutdown.restart_required
        )
        self.query_button.setEnabled(available and not busy and not self._monitoring)
        self.stop_button.setEnabled(available and (busy or self._monitoring))
        if not self._monitoring:
            self.monitor_button.setEnabled(available and not busy)
        self._apply_history_action_state(available=available, busy=busy)

    @Slot()
    def _sync_history_action_state(self) -> None:
        available = (
            not self._closing_requested
            and not self._storage_task_running
            and not self._shutdown.active
            and not self._shutdown.restart_required
        )
        self._apply_history_action_state(available=available, busy=self._query_running)

    def _apply_history_action_state(self, *, available: bool, busy: bool) -> None:
        history_mutable = (
            available and not busy and not self._monitoring and not self._history_task_running
        )
        has_rows = self.history_table.rowCount() > 0
        has_selection = self._selected_run_id() is not None
        self.refresh_history_button.setEnabled(history_mutable)
        self.export_button.setEnabled(history_mutable and has_selection)
        self.html_export_button.setEnabled(history_mutable and has_selection)
        self.delete_button.setEnabled(history_mutable and has_selection)
        self.delete_all_button.setEnabled(history_mutable and has_rows)

    def _set_monitor_inputs_enabled(self, enabled: bool) -> None:
        for widget in (
            self.connection_group,
            self.query_group,
            self.advanced_toggle_button,
            self.advanced_panel,
            self.mm_group,
            self.md_group,
            self.timing_group,
            self.save_config_button,
        ):
            widget.setEnabled(enabled)

    def _selected_run_id(self) -> str | None:
        selection_model = self.history_table.selectionModel()
        if selection_model is None:
            return None
        selected_rows = selection_model.selectedRows(0)
        if len(selected_rows) != 1:
            return None
        row = selected_rows[0].row()
        item = self.history_table.item(row, 0)
        if item is None:
            return None
        value = item.data(_RUN_ID_ROLE)
        return str(value) if value not in (None, "") else None

    @Slot()
    def _refresh_history(self) -> None:
        if (
            self._closing_requested
            or self._history_task_running
            or self._storage_task_running
            or self._shutdown.active
            or self._shutdown.restart_required
        ):
            return
        if self.history_table.rowCount() == 0:
            self.history_empty_label.setText("기록을 불러오는 중입니다.")
            self.history_empty_label.setVisible(True)
        self._history_task_generation += 1
        generation = self._history_task_generation
        reconcile_storage = self._storage_reconciliation_pending
        context = (self._selected_run_id(), self._history_revision, reconcile_storage)
        task = _StorageTask(
            generation,
            "history-list",
            lambda cancel_check, progress: _read_history_task(
                self._store,
                cancel_check,
                progress,
                reconcile_storage=reconcile_storage,
            ),
            context,
        )
        self._history_task_running = True
        self._current_history_task = task
        task.signals.succeeded.connect(self._history_task_succeeded)
        task.signals.failed.connect(self._history_task_failed)
        self._set_busy(self._query_running)
        _start_daemon_task(task.run, f"aruba-session-history-{generation}")

    def _mark_history_dirty(self) -> None:
        self._history_revision += 1
        self._history_dirty = True

    def _finish_history_task(self, generation: int, kind: str) -> _StorageTask | None:
        task = self._current_history_task
        if task is None or task.generation != generation or task.kind != kind:
            return None
        self._history_task_running = False
        self._current_history_task = None
        self._set_busy(self._query_running)
        return task

    @Slot(int, str, object)
    def _history_task_succeeded(self, generation: int, kind: str, result: object) -> None:
        task = self._finish_history_task(generation, kind)
        if task is None:
            return
        if self._closing_requested:
            self._drain_preview_discard_queue()
            self._close_if_idle()
            return
        if not isinstance(result, _HistoryReadResult):
            self._history_dirty = True
            self._show_history_read_failure()
            support_code = support_code_for_ui_failure(UiFailureKey.HISTORY_READ_FAILED)
            self.statusBar().showMessage(
                "기록 읽기 실패: 로컬 기록을 안전하게 읽지 못했습니다. "
                f"전달 코드 {support_code.value}",
                5000,
            )
            self._drain_preview_discard_queue()
            self._close_if_idle()
            return
        selected_run_id: str | None = None
        requested_revision = -1
        requested_reconciliation = False
        if isinstance(task.context, tuple) and len(task.context) == 3:
            selected_value, revision_value, reconciliation_value = task.context
            if isinstance(selected_value, str):
                selected_run_id = selected_value
            if isinstance(revision_value, int):
                requested_revision = revision_value
            requested_reconciliation = reconciliation_value is True
        if requested_reconciliation:
            self._storage_reconciliation_pending = False
        if result.storage_health is not None:
            self._update_storage_status(result.storage_health)
        self._render_history(result.runs, selected_run_id)
        self._history_dirty = requested_revision != self._history_revision
        if result.pending_external_recoveries > 0:
            self.statusBar().showMessage(
                "외부 보고서 복구 "
                f"{result.pending_external_recoveries}건 대기 중입니다. "
                "외부 저장 위치를 다시 사용할 수 있게 한 뒤 새로 고침을 누르십시오.",
                15_000,
            )
        self._drain_preview_discard_queue()
        self._close_if_idle()

    @Slot(int, str, object)
    def _history_task_failed(self, generation: int, kind: str, _exc: object) -> None:
        if self._finish_history_task(generation, kind) is None:
            return
        self._history_dirty = True
        if not self._closing_requested:
            self._show_history_read_failure()
            support_code = support_code_for_ui_failure(UiFailureKey.HISTORY_READ_FAILED)
            self.statusBar().showMessage(
                "기록 읽기 실패: 로컬 기록을 안전하게 읽지 못했습니다. "
                f"전달 코드 {support_code.value}",
                5000,
            )
        self._drain_preview_discard_queue()
        self._close_if_idle()

    def _show_history_read_failure(self) -> None:
        if self.history_table.rowCount() != 0:
            return
        support_code = support_code_for_ui_failure(UiFailureKey.HISTORY_READ_FAILED)
        self.history_empty_label.setText(
            "기록을 확인하지 못했습니다. 새로고침으로 다시 시도하십시오. "
            f"(전달 코드 {support_code.value})"
        )
        self.history_empty_label.setVisible(True)

    def _render_history(
        self,
        runs: tuple[object, ...],
        selected_run_id: str | None,
    ) -> None:
        self.history_table.setRowCount(0)
        selected_row = -1
        for run in runs:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            if isinstance(run, dict):
                internal_run_id = str(run.get("id", ""))
                started_at = str(run.get("started_at", ""))
                ended_at = str(run.get("ended_at", "") or "")
                status_value = str(run.get("status", ""))
                values = (
                    _display_run_identifier(run),
                    _display_timestamp(started_at),
                    _display_timestamp(ended_at) if ended_at else "-",
                    _format_elapsed_from_text(started_at, ended_at)
                    if ended_at
                    else _format_elapsed(_parse_timestamp(started_at), datetime.now(UTC))
                    if status_value == "RUNNING"
                    else "-",
                    status_value,
                    str(run.get("observation_count", 0)),
                    str(run.get("latest_support_code", "") or "-"),
                )
            else:
                internal_run_id = str(getattr(run, "run_id", ""))
                started_at = str(getattr(run, "started_at", ""))
                ended_at = str(getattr(run, "finished_at", "") or "")
                status_value = str(getattr(run, "status", ""))
                values = (
                    _display_run_identifier(
                        {
                            "id": getattr(run, "run_id", ""),
                            "source_ip": getattr(run, "source_ip", ""),
                            "destination_ip": getattr(run, "destination_ip", ""),
                            "started_at": started_at,
                        }
                    ),
                    _display_timestamp(started_at),
                    _display_timestamp(ended_at) if ended_at else "-",
                    _format_elapsed_from_text(started_at, ended_at)
                    if ended_at
                    else _format_elapsed(_parse_timestamp(started_at), datetime.now(UTC))
                    if status_value == "RUNNING"
                    else "-",
                    status_value,
                    str(getattr(run, "observation_count", 0)),
                    str(getattr(run, "latest_support_code", "") or "-"),
                )
            for column, value in enumerate(values):
                display_value = _history_status_label(value) if column == 4 else value
                item = QTableWidgetItem(display_value)
                if column == 0:
                    item.setData(_RUN_ID_ROLE, internal_run_id)
                if column == 1:
                    item.setData(Qt.ItemDataRole.UserRole, started_at)
                if column == 4 and display_value != value:
                    item.setToolTip(f"저장 상태 코드: {value}")
                if column == 6:
                    item.setToolTip(
                        "사내 정보 없이 전달할 수 있는 최근 진단 코드입니다. "
                        "'-'는 저장된 전달 코드가 없다는 뜻입니다."
                    )
                self.history_table.setItem(row, column, item)
            if internal_run_id == selected_run_id:
                selected_row = row
        if selected_row >= 0:
            self.history_table.selectRow(selected_row)
        self.history_empty_label.setText(
            "저장된 실행 기록이 없습니다. 세션 조회를 완료하면 이곳에서 내보낼 수 있습니다."
        )
        self.history_empty_label.setVisible(self.history_table.rowCount() == 0)
        self._sync_history_action_state()
        self._sync_history_elapsed_timer()

    def _sync_history_elapsed_timer(self) -> None:
        if self.tabs.currentWidget() is not self.history_page:
            self._history_elapsed_timer.stop()
            return
        running = False
        for row in range(self.history_table.rowCount()):
            status_item = self.history_table.item(row, 4)
            if status_item is not None and status_item.text() == "진행 중":
                running = True
                break
        if running:
            self._history_elapsed_timer.start()
        else:
            self._history_elapsed_timer.stop()

    @Slot()
    def _refresh_history_elapsed_cells(self) -> None:
        for row in range(self.history_table.rowCount()):
            status_item = self.history_table.item(row, 4)
            if status_item is None or status_item.text() != "진행 중":
                continue
            start_item = self.history_table.item(row, 1)
            if start_item is None:
                continue
            started = _parse_timestamp(
                start_item.data(Qt.ItemDataRole.UserRole) or start_item.text()
            )
            if started is None:
                continue
            elapsed_item = self.history_table.item(row, 3)
            if elapsed_item is not None:
                elapsed_item.setText(_format_elapsed(started, datetime.now(UTC)))

    @Slot()
    def _export_selected_run(self) -> None:
        run_id = self._selected_run_id()
        if run_id is None:
            QMessageBox.information(self, "CSV 내보내기", "실행 기록을 선택하십시오.")
            return
        default_name = f"aruba-session-{run_id}.csv"
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "CSV 저장",
            default_name,
            "CSV 파일 (*.csv)",
        )
        if not destination:
            return
        output_path = Path(destination)
        self._start_storage_task(
            "export-csv",
            lambda cancel_check, progress: self._store.export_run_csv(
                run_id,
                output_path,
                cancel_check=cancel_check,
                progress=progress,
            ),
            status="CSV 내보내기 중",
        )

    @Slot()
    def _export_selected_run_html(self) -> None:
        run_id = self._selected_run_id()
        if run_id is None:
            QMessageBox.information(self, "HTML 보고서", "실행 기록을 선택하십시오.")
            return
        default_name = f"aruba-session-{run_id}.html"
        destination, _ = QFileDialog.getSaveFileName(
            self,
            "HTML 보고서 저장",
            default_name,
            "HTML 문서 (*.html)",
        )
        if not destination:
            return
        output_path = Path(destination)
        self._start_storage_task(
            "export-html",
            lambda cancel_check, progress: self._store.export_run_html(
                run_id,
                output_path,
                cancel_check=cancel_check,
                progress=progress,
            ),
            status="HTML 보고서 만드는 중",
        )

    def _delete_history(self, *, all_runs: bool) -> None:
        run_id = None if all_runs else self._selected_run_id()
        if not all_runs and run_id is None:
            QMessageBox.information(self, "기록 삭제", "삭제할 실행 기록을 선택하십시오.")
            return
        self._start_storage_task(
            "delete-preview",
            lambda cancel_check, progress: self._store.preview_delete(
                run_id,
                cancel_check=cancel_check,
                progress=progress,
            ),
            status="삭제 대상 확인 중",
        )

    def _start_storage_task(
        self,
        kind: str,
        operation: Callable[
            [Callable[[], bool], Callable[[str, int, int | None], None]],
            object,
        ],
        *,
        status: str,
        context: object | None = None,
        allow_while_closing: bool = False,
    ) -> bool:
        if (
            self._storage_task_running
            or self._history_task_running
            or self._query_running
            or self._monitoring
            or (self._shutdown.active and not allow_while_closing)
            or (self._shutdown.restart_required and not allow_while_closing)
        ):
            return False
        if self._closing_requested and not allow_while_closing:
            return False
        self._storage_task_generation += 1
        generation = self._storage_task_generation
        task = _StorageTask(generation, kind, operation, context)
        self._storage_task_running = True
        self._current_storage_task = task
        task.signals.succeeded.connect(self._storage_task_succeeded)
        task.signals.failed.connect(self._storage_task_failed)
        task.signals.progress.connect(self._storage_task_progress)
        self._set_busy(self._query_running)
        self.statusBar().showMessage(status)
        _start_daemon_task(task.run, f"aruba-session-storage-{generation}-{kind}")
        return True

    @Slot(int, bool)
    def _show_storage_warning(self, generation: int, hard_stop: bool) -> None:
        if not self._owns_task(generation) or self._closing_requested:
            return
        message = (
            "저장 공간이 매우 부족합니다. 오래된 기록을 정리한 뒤 다시 시도하세요."
            if hard_stop
            else "저장 공간이 부족해지고 있습니다. 오래된 기록을 정리해 주세요."
        )
        self.statusBar().showMessage(message, 15000)

    @Slot(int)
    def _show_storage_health_unavailable(self, generation: int) -> None:
        if not self._owns_task(generation) or self._closing_requested:
            return
        self.statusBar().showMessage(
            "저장소 사용량 요약을 확인하지 못했습니다. 세션 조회는 계속합니다.",
            10_000,
        )

    @Slot(int, object)
    def _storage_health_updated(self, generation: int, health: object) -> None:
        if not self._owns_task(generation) or self._closing_requested:
            return
        self._update_storage_status(health)

    def _update_storage_status(self, health: object) -> None:
        self.storage_status_label.setText(_storage_status_text(health))

    @Slot(int, str, str, int, int)
    def _storage_task_progress(
        self,
        generation: int,
        kind: str,
        phase: str,
        completed: int,
        total: int,
    ) -> None:
        task = self._current_storage_task
        if task is None or task.generation != generation or task.kind != kind:
            return
        label = {
            "export-csv": "CSV 내보내기",
            "export-html": "HTML 보고서 만들기",
            "delete-preview": "삭제 대상 확인",
        }.get(kind, "로컬 기록 작업")
        safe_phase = {
            "READ": "기록 읽는 중",
            "RENDER": "문서 만드는 중",
            "HASH": "무결성 확인 중",
            "INSTALL": "파일 저장 중",
            "SCAN": "대상 확인 중",
        }.get(phase.upper(), "안전하게 처리 중")
        amount = f" ({completed}/{total})" if total >= 0 else ""
        self.statusBar().showMessage(f"{label}: {safe_phase}{amount}")

    def _finish_storage_task(self, generation: int, kind: str) -> _StorageTask | None:
        task = self._current_storage_task
        if task is None or task.generation != generation or task.kind != kind:
            return None
        self._storage_task_running = False
        self._current_storage_task = None
        self._set_busy(self._query_running)
        return task

    def _queue_preview_discard(self, preview: DeletePreview) -> None:
        if preview not in self._pending_preview_discards:
            self._pending_preview_discards.append(preview)

    def _drain_preview_discard_queue(self) -> bool:
        if not self._pending_preview_discards:
            return False
        preview = self._pending_preview_discards[0]
        started = self._start_storage_task(
            "delete-discard",
            lambda _cancel_check, _progress: self._store.discard_delete_preview(preview),
            status="삭제 확인 정리 중",
            context=preview,
            allow_while_closing=True,
        )
        if started:
            self._pending_preview_discards.pop(0)
        return started

    @Slot(int, str, object)
    def _storage_task_succeeded(self, generation: int, kind: str, result: object) -> None:
        task = self._finish_storage_task(generation, kind)
        if task is None:
            return
        if kind == "delete-preview":
            if not isinstance(result, DeletePreview):
                self._show_storage_failure(kind)
                self._close_if_idle()
                return
            if self._closing_requested:
                self._queue_preview_discard(result)
                self._drain_preview_discard_queue()
                self._close_if_idle()
                return
            self._confirm_delete_preview(result)
            return
        if kind == "delete-commit":
            self._mark_history_dirty()
            self.statusBar().showMessage("선택한 기록을 삭제했습니다.", 5000)
            if not self._closing_requested:
                self._refresh_history()
        elif kind == "delete-discard":
            if not self._closing_requested:
                self.statusBar().showMessage("삭제를 취소했습니다.", 3000)
        elif kind == "export-csv":
            self.statusBar().showMessage("CSV 내보내기를 완료했습니다.", 5000)
            if not self._closing_requested:
                self._show_export_completion("CSV 내보내기", result)
        elif kind == "export-html":
            self.statusBar().showMessage("HTML 보고서를 만들었습니다.", 5000)
            if not self._closing_requested:
                self._show_export_completion("HTML 보고서", result)
        self._drain_preview_discard_queue()
        self._close_if_idle()

    def _show_export_completion(self, title: str, result: object) -> None:
        path = Path(result) if isinstance(result, (str, Path)) else None
        dialog = QMessageBox(self)
        dialog.setObjectName("exportCompletionDialog")
        dialog.setProperty("popupSurface", "completion")
        dialog.setIcon(QMessageBox.Icon.Information)
        dialog.setWindowTitle(f"{title} 완료")
        if path is None:
            dialog.setText(f"{title}를 완료했습니다.")
        else:
            dialog.setText(f"{title}를 저장했습니다.")
            dialog.setInformativeText(path.name)
        open_button = dialog.addButton("파일 열기", QMessageBox.ButtonRole.AcceptRole)
        dialog.addButton("확인", QMessageBox.ButtonRole.RejectRole)
        dialog.setDefaultButton(open_button)
        dialog.exec()
        if dialog.clickedButton() is not open_button or path is None:
            return
        try:
            opened = QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
        except (OSError, RuntimeError):
            opened = False
        if not opened:
            self.statusBar().showMessage(
                f"기본 앱으로 파일을 열지 못했습니다. 저장 위치: {path.name}",
                7000,
            )

    def _confirm_delete_preview(self, preview: DeletePreview) -> None:
        answer = QMessageBox.warning(
            self,
            "기록 삭제 확인",
            f"실행: {len(preview.run_ids)}건\n"
            f"DB 행: {preview.database_rows}개\n"
            f"Raw TXT: {preview.raw_files}개\n"
            f"관리 내보내기(CSV/HTML): {preview.export_files}개\n"
            f"파일 크기: {_display_bytes(preview.total_file_bytes)}\n\n"
            "위 대상을 영구 삭제합니다. 계속하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer == QMessageBox.StandardButton.Yes:
            started = self._start_storage_task(
                "delete-commit",
                lambda cancel_check, progress: self._store.delete(
                    preview,
                    confirmation_token=preview.confirmation_token,
                    cancel_check=cancel_check,
                    progress=progress,
                ),
                status="기록 삭제 중",
                context=preview,
            )
            if not started:
                self._queue_preview_discard(preview)
                self._drain_preview_discard_queue()
            return
        self._queue_preview_discard(preview)
        self._drain_preview_discard_queue()

    @Slot(int, str, object)
    def _storage_task_failed(self, generation: int, kind: str, _exc: object) -> None:
        task = self._finish_storage_task(generation, kind)
        if task is None:
            return
        if kind == "delete-commit" and isinstance(task.context, DeletePreview):
            self._queue_preview_discard(task.context)
        self._show_storage_failure(kind)
        self._drain_preview_discard_queue()
        self._close_if_idle()

    def _show_storage_failure(self, kind: str) -> None:
        support_code = _support_code_for_storage_failure(kind)
        if kind == "delete-discard":
            self.statusBar().showMessage(
                f"삭제 취소 상태를 정리하지 못했습니다. 전달 코드 {support_code.value}",
                5000,
            )
            return
        title, message = {
            "export-csv": ("내보내기 실패", "CSV 파일을 안전하게 내보내지 못했습니다."),
            "export-html": ("HTML 보고서 실패", "HTML 보고서를 안전하게 만들지 못했습니다."),
            "delete-preview": ("삭제 준비 실패", "삭제 대상을 안전하게 확인하지 못했습니다."),
            "delete-commit": ("삭제 실패", "확인된 기록을 안전하게 삭제하지 못했습니다."),
        }.get(kind, ("작업 실패", "로컬 파일 작업을 안전하게 마치지 못했습니다."))
        self.statusBar().showMessage(f"{message} 전달 코드 {support_code.value}", 5000)
        if not self._closing_requested:
            QMessageBox.warning(
                self,
                title,
                f"{message}\n\n전달 코드: {support_code.value}",
            )

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: palette(window); color: palette(window-text); }
            #setupGuide { background: palette(alternate-base); border: 1px solid palette(mid);
                          border-radius: 4px; }
            QGroupBox { font-weight: 600; border: 1px solid palette(mid); border-radius: 5px;
                        margin-top: 8px; padding-top: 10px; background: palette(window); }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QPushButton { min-height: 30px; padding: 0 14px; }
            QPushButton:default { background: palette(highlight);
                                  color: palette(highlighted-text); }
            QLineEdit, QSpinBox, QTableWidget, QPlainTextEdit, QListWidget {
                background: palette(base); color: palette(text);
                border: 1px solid palette(mid); border-radius: 3px;
            }
            #stateLabel { font-weight: 700; color: palette(window-text); padding: 6px 12px;
                          background: palette(alternate-base); border-radius: 4px; }
            """
        )
        font = QFont("Malgun Gothic", 9)
        application = QApplication.instance()
        if isinstance(application, QApplication):
            application.setFont(font)

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if hasattr(self, "result_splitter"):
            self._sync_result_splitter_orientation()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self._close_recovery_deferred:
            event.accept()
            return
        self._closing_requested = True
        self._close_when_idle = True
        self._result_render_timer.stop()
        self._elapsed_timer.stop()
        self._history_elapsed_timer.stop()
        self._pending_result_rows = ()
        self._pending_result_index = 0
        self._cancel_active_work(user_requested=True)
        if self._current_storage_task is not None:
            self._current_storage_task.request_cancel()
        if self._current_history_task is not None:
            self._current_history_task.request_cancel()
        self._approval.shutdown()
        self._drain_preview_discard_queue()
        if (
            self._query_running
            or self._storage_task_running
            or self._history_task_running
            or self._shutdown.active
            or self._pending_preview_discards
        ):
            if not self._close_grace_timer.isActive():
                self._close_grace_timer.start()
            self._set_state("확인 필요")
            self.statusBar().showMessage("진행 중인 작업을 안전하게 정리한 뒤 종료합니다.")
            event.ignore()
            return
        self._close_grace_timer.stop()
        event.accept()

    @Slot()
    def _close_grace_expired(self) -> None:
        if not self._closing_requested:
            return
        if not (
            self._query_running
            or self._storage_task_running
            or self._history_task_running
            or self._shutdown.active
            or self._pending_preview_discards
        ):
            self._close_if_idle()
            return
        self._close_recovery_deferred = True
        self._shutdown_finalization_succeeded = False
        self._monitoring = False
        self._monitor_timer.stop()
        if self._cancel_token is not None:
            self._cancel_token.cancel()
        if self._current_storage_task is not None:
            self._current_storage_task.request_cancel()
        if self._current_history_task is not None:
            self._current_history_task.request_cancel()
        self._task_generation += 1
        self._storage_task_generation += 1
        self._history_task_generation += 1
        self._query_running = False
        self._storage_task_running = False
        self._history_task_running = False
        self._current_task = None
        self._current_storage_task = None
        self._current_history_task = None
        self._pending_preview_discards.clear()
        self.statusBar().showMessage("완료되지 않은 로컬 작업은 다음 실행에서 안전하게 복구합니다.")
        QTimer.singleShot(0, self, self.close)

    def _close_if_idle(self) -> None:
        if not self._close_when_idle:
            return
        if self._pending_preview_discards:
            self._drain_preview_discard_queue()
        if (
            self._query_running
            or self._storage_task_running
            or self._history_task_running
            or self._shutdown.active
            or self._pending_preview_discards
        ):
            return
        QTimer.singleShot(0, self, self.close)


def _optional_port(text: str, label: str) -> int | None:
    stripped = text.strip()
    if not stripped:
        return None
    if not stripped.isascii() or not stripped.isdecimal():
        raise ValueError(f"{label}는 0~65535 숫자여야 합니다.")
    value = int(stripped)
    if not 0 <= value <= 65535:
        raise ValueError(f"{label}는 0~65535 범위여야 합니다.")
    return value


def _start_daemon_task(operation: Callable[[], None], name: str) -> threading.Thread:
    worker = threading.Thread(target=operation, name=name, daemon=True)
    worker.start()
    return worker


def _read_history_task(
    store: SessionStore,
    cancel_check: Callable[[], bool],
    progress: Callable[[str, int, int | None], None],
    *,
    reconcile_storage: bool = False,
) -> _HistoryReadResult:
    if cancel_check():
        raise StorageError("기록 읽기가 취소되었습니다.", code=ErrorCode.CANCELLED)
    reconcile = getattr(store, "reconcile_storage_health", None)
    storage_health: object | None = None
    if reconcile_storage and callable(reconcile):
        progress("SCAN", 0, None)
        storage_health = reconcile(cancel_check=cancel_check, progress=progress)
        if cancel_check():
            raise StorageError("기록 읽기가 취소되었습니다.", code=ErrorCode.CANCELLED)
        progress("SCAN", 1, 1)
    pending_recoveries = store.pending_external_recovery_count
    if pending_recoveries > 0:
        progress("RECOVER", 0, pending_recoveries)
        if cancel_check():
            raise StorageError("기록 읽기가 취소되었습니다.", code=ErrorCode.CANCELLED)
        pending_recoveries = store.retry_pending_external_recoveries()
        if cancel_check():
            raise StorageError("기록 읽기가 취소되었습니다.", code=ErrorCode.CANCELLED)
        progress("RECOVER", 1, 1)
    progress("READ", 0, None)
    result = tuple(store.list_runs(limit=100))
    if cancel_check():
        raise StorageError("기록 읽기가 취소되었습니다.", code=ErrorCode.CANCELLED)
    progress("READ", len(result), len(result))
    if storage_health is None and not reconcile_storage:
        health_check = getattr(store, "storage_health", None)
        if callable(health_check):
            try:
                storage_health = health_check()
            except Exception as error:
                if _fatal_storage_health_code(error) is not None:
                    raise
    return _HistoryReadResult(result, pending_recoveries, storage_health)


def _fatal_storage_health_code(exc: Exception) -> ErrorCode | None:
    """Keep security/capacity failures fatal while usage totals stay advisory."""

    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, (UnsafeManagedPath, UnsafeStoragePath)):
            return ErrorCode.STORAGE_PATH_FAILED
        code = getattr(getattr(current, "code", None), "value", None)
        kind = getattr(current, "failure_kind", None)
        failure_kind = getattr(kind, "value", kind)
        if code == ErrorCode.STORAGE_PATH_FAILED.value or failure_kind == "STORAGE_PATH":
            return ErrorCode.STORAGE_PATH_FAILED
        if code == ErrorCode.STORAGE_LOW_SPACE.value or failure_kind == "LOW_SPACE":
            return ErrorCode.STORAGE_LOW_SPACE
        current = current.__cause__
    return None


def _safe_query_failure(exc: Exception) -> tuple[str, str]:
    raw_code = getattr(getattr(exc, "code", None), "value", None)
    known_codes = {item.value for item in ErrorCode}
    if isinstance(exc, CollectorError) and isinstance(raw_code, str) and raw_code in known_codes:
        return raw_code, str(exc) or "안전하게 처리할 수 없는 조회 오류가 발생했습니다."
    if isinstance(exc, StorageError):
        if raw_code == ErrorCode.CANCELLED.value:
            return ErrorCode.CANCELLED.value, "작업이 취소되었습니다."
        kind = getattr(exc, "failure_kind", None)
        failure_kind = getattr(kind, "value", kind)
        storage_codes = {
            ErrorCode.DB_WRITE_FAILED.value,
            ErrorCode.STORAGE_LOW_SPACE.value,
            ErrorCode.STORAGE_PATH_FAILED.value,
            ErrorCode.STORAGE_BUSY.value,
            ErrorCode.OUTPUT_LIMIT_EXCEEDED.value,
            ErrorCode.PERSISTENCE_INDETERMINATE.value,
        }
        code = (
            raw_code
            if isinstance(raw_code, str) and raw_code in storage_codes
            else {
                "DATABASE_WRITE": ErrorCode.DB_WRITE_FAILED.value,
                "STORAGE_PATH": ErrorCode.STORAGE_PATH_FAILED.value,
                "STORAGE_BUSY": ErrorCode.STORAGE_BUSY.value,
                "LOW_SPACE": ErrorCode.STORAGE_LOW_SPACE.value,
                "OUTPUT_LIMIT": ErrorCode.OUTPUT_LIMIT_EXCEEDED.value,
                "PERSISTENCE_INDETERMINATE": ErrorCode.PERSISTENCE_INDETERMINATE.value,
            }.get(str(failure_kind), ErrorCode.DB_WRITE_FAILED.value)
        )
        message = {
            ErrorCode.DB_WRITE_FAILED.value: "로컬 조회 기록을 안전하게 저장하지 못했습니다.",
            ErrorCode.STORAGE_LOW_SPACE.value: (
                "저장 공간이 부족합니다. 오래된 기록을 정리한 뒤 다시 시도하십시오."
            ),
            ErrorCode.STORAGE_PATH_FAILED.value: (
                "로컬 저장 경로를 안전하게 사용할 수 없습니다. "
                "저장소 권한과 보안 상태를 확인하십시오."
            ),
            ErrorCode.STORAGE_BUSY.value: (
                "로컬 저장소가 다른 작업에서 사용 중입니다. 잠시 후 다시 시도하십시오."
            ),
            ErrorCode.OUTPUT_LIMIT_EXCEEDED.value: (
                "조회 결과가 안전 저장 한도를 초과했습니다. 조회 조건을 좁힌 뒤 다시 시도하십시오."
            ),
            ErrorCode.PERSISTENCE_INDETERMINATE.value: (
                "조회 기록의 저장 완료 여부를 확인하지 못했습니다. 같은 조회를 다시 시도하십시오."
            ),
        }.get(code, "로컬 조회 기록을 안전하게 저장하지 못했습니다.")
        return code, message
    return (
        "UNEXPECTED",
        f"예상하지 못한 내부 오류가 발생했습니다. 오류 유형: {type(exc).__name__}",
    )


def _support_code_for_query_failure(code: str) -> SupportCode:
    key = {
        ErrorCode.AUTH_FAILED.value: UiFailureKey.QUERY_AUTH_FAILED,
        ErrorCode.DB_WRITE_FAILED.value: UiFailureKey.QUERY_DB_WRITE_FAILED,
        ErrorCode.STORAGE_LOW_SPACE.value: UiFailureKey.QUERY_STORAGE_LOW_SPACE,
        ErrorCode.STORAGE_PATH_FAILED.value: UiFailureKey.QUERY_STORAGE_PATH_FAILED,
        ErrorCode.STORAGE_BUSY.value: UiFailureKey.QUERY_STORAGE_BUSY,
        ErrorCode.OUTPUT_LIMIT_EXCEEDED.value: UiFailureKey.QUERY_OUTPUT_LIMIT_EXCEEDED,
        ErrorCode.PERSISTENCE_INDETERMINATE.value: (UiFailureKey.QUERY_PERSISTENCE_INDETERMINATE),
    }.get(code, UiFailureKey.QUERY_UNEXPECTED)
    return support_code_for_ui_failure(key)


def _support_reference_for_query_failure(exc: Exception, code: str) -> str:
    """Add a non-sensitive persistence stage to AS86 field reports.

    AS86 remains the stable support-code assignment.  The single-letter suffix
    only identifies which storage boundary failed, so an operator can type a
    useful field report without copying paths, credentials, or device output.
    """

    base = _support_code_for_query_failure(code).value
    if code != ErrorCode.STORAGE_PATH_FAILED.value:
        return base
    boundary_value = getattr(exc, "boundary", None)
    boundary = boundary_value if isinstance(boundary_value, StorageFailureBoundary) else None
    suffix_by_boundary = {
        StorageFailureBoundary.QUERY_PREFLIGHT: "P",
        StorageFailureBoundary.QUERY_START: "S",
        StorageFailureBoundary.QUERY_RESULT: "R",
        StorageFailureBoundary.QUERY_FINALIZE: "F",
    }
    suffix = suffix_by_boundary.get(boundary) if boundary is not None else None
    return f"{base}-{suffix}" if suffix is not None else base


def _support_code_for_storage_failure(kind: str) -> SupportCode:
    key = {
        "export-csv": UiFailureKey.EXPORT_CSV_FAILED,
        "export-html": UiFailureKey.EXPORT_HTML_FAILED,
        "delete-preview": UiFailureKey.DELETE_PREVIEW_FAILED,
        "delete-commit": UiFailureKey.DELETE_COMMIT_FAILED,
        "delete-discard": UiFailureKey.DELETE_DISCARD_FAILED,
    }.get(kind, UiFailureKey.RUNTIME_CLEANUP_FAILED)
    return support_code_for_ui_failure(key)


def _ui_metadata(
    name_ko: str,
    stable_id: str,
    screen_path: str,
    purpose: str,
) -> UiElementMetadata:
    return UiElementMetadata(
        name_ko=name_ko,
        stable_id=stable_id,
        screen_path=screen_path,
        source_path=_UI_SOURCE_PATH,
        purpose=purpose,
    )


def _display_number(value: int | None) -> str:
    return "-" if value is None else f"{value:,}"


def _safe_protocol_label(value: object) -> str:
    if type(value) is not int or not 0 <= value <= 255:
        return str(value)
    return protocol_label(value)


def _format_port(port: int, service: object | None = None) -> str:
    if service is None:
        return str(port)
    label = str(getattr(service, "label", "")).strip()
    return f"{port}({label})" if label else str(port)


def _format_port_for_observation(protocol: int, port: int) -> str:
    try:
        service = service_definition(protocol, port)
    except (TypeError, ValueError):
        service = None
    return _format_port(port, service)


def _display_observed_at(observation: SessionObservation) -> str:
    return observation.observed_at.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")


def _parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _display_timestamp(value: object) -> str:
    parsed = _parse_timestamp(value)
    if parsed is None:
        return "-"
    return parsed.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")


def _format_elapsed(started: datetime | None, ended: datetime | None) -> str:
    if started is None or ended is None:
        return "-"
    if started.tzinfo is None:
        started = started.replace(tzinfo=UTC)
    if ended.tzinfo is None:
        ended = ended.replace(tzinfo=UTC)
    elapsed_seconds = (ended - started).total_seconds()
    if elapsed_seconds < 0:
        return "-"
    return _format_elapsed_seconds(elapsed_seconds)


def _format_elapsed_seconds(elapsed_seconds: float) -> str:
    seconds = int(max(0, elapsed_seconds))
    days, remainder = divmod(seconds, 86_400)
    hours, remainder = divmod(remainder, 3_600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}일 {hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _format_elapsed_from_text(started: object, ended: object) -> str:
    start_value = _parse_timestamp(started)
    end_value = _parse_timestamp(ended)
    if end_value is None:
        return "-"
    return _format_elapsed(start_value, end_value)


def _display_run_identifier(run: dict[str, object]) -> str:
    source = str(run.get("source_ip") or "").strip()
    destination = str(run.get("destination_ip") or "").strip()
    if source and destination:
        return f"{source} → {destination}"
    if source:
        return f"출발지: {source}"
    if destination:
        return f"목적지: {destination}"
    return "조회 대상 없음"


def _flow_key(observation: SessionObservation) -> str:
    return "|".join(
        (
            str(observation.protocol),
            observation.source_ip,
            observation.destination_ip,
            str(observation.source_port),
            str(observation.destination_port),
        )
    )


def _prepare_display_outcome(
    outcome: object,
    *,
    previous_counters: dict[str, tuple[int | None, int | None]],
    close_after_misses: int,
    monitoring: bool,
) -> _PreparedDisplayOutcome:
    observations = tuple(getattr(outcome, "observations", ()))
    active_sessions = tuple(getattr(outcome, "active_sessions", ()))
    lifecycle_events = tuple(getattr(outcome, "events", ()))
    authoritative = bool(getattr(outcome, "authoritative", False))
    observed_by_flow: dict[str, list[SessionObservation]] = {}
    for item in observations:
        if isinstance(item, SessionObservation):
            observed_by_flow.setdefault(_flow_key(item), []).append(item)
    event_types_by_flow: dict[str, set[str]] = {}
    closed_observations: dict[str, SessionObservation] = {}
    for event in lifecycle_events:
        event_observation = getattr(event, "observation", None)
        event_type = getattr(getattr(event, "event_type", None), "value", "")
        if not isinstance(event_observation, SessionObservation):
            continue
        flow_key = _flow_key(event_observation)
        event_types_by_flow.setdefault(flow_key, set()).add(str(event_type))
        if event_type == "CLOSED":
            closed_observations[flow_key] = event_observation

    rows: list[_DisplayRow] = []
    next_counters: dict[str, tuple[int | None, int | None]] = {}
    displayed_active_flows: set[str] = set()
    if active_sessions:
        for session in active_sessions:
            active_observation = getattr(session, "observation", None)
            if not isinstance(active_observation, SessionObservation):
                continue
            flow_key = _flow_key(active_observation)
            displayed_active_flows.add(flow_key)
            current_observations = observed_by_flow.get(flow_key, [])
            display_observations = current_observations or [active_observation]
            event_types = set(event_types_by_flow.get(flow_key, set()))
            if len(current_observations) > 1:
                event_types.add("CONTROLLER_OVERLAP")
            for observation in sorted(
                display_observations,
                key=lambda item: (item.controller_host, item.controller_name, item.session_key),
            ):
                is_observed = bool(current_observations)
                counter_key = observation.session_key
                previous = previous_counters.get(counter_key)
                packet_delta = (
                    _counter_delta(
                        observation.packets,
                        None if previous is None else previous[0],
                    )
                    if is_observed
                    else "-"
                )
                byte_delta = (
                    _counter_delta(
                        observation.bytes_count,
                        None if previous is None else previous[1],
                    )
                    if is_observed
                    else "-"
                )
                rows.append(
                    _DisplayRow(
                        observation,
                        packet_delta,
                        byte_delta,
                        _lifecycle_status(
                            event_types,
                            miss_count=int(getattr(session, "miss_count", 0)),
                            close_after_misses=close_after_misses,
                            is_observed=is_observed,
                            authoritative=authoritative,
                        ),
                    )
                )
                next_counters[counter_key] = (
                    observation.packets,
                    observation.bytes_count,
                )
        for flow_key, observation in closed_observations.items():
            if flow_key not in displayed_active_flows:
                rows.append(
                    _DisplayRow(
                        observation,
                        "-",
                        "-",
                        f"{close_after_misses}회 연속 미관측 · 종료 확인",
                    )
                )
    else:
        for observation in observations:
            if not isinstance(observation, SessionObservation):
                continue
            counter_key = observation.session_key
            previous = previous_counters.get(counter_key)
            rows.append(
                _DisplayRow(
                    observation,
                    _counter_delta(
                        observation.packets,
                        None if previous is None else previous[0],
                    ),
                    _counter_delta(
                        observation.bytes_count,
                        None if previous is None else previous[1],
                    ),
                    "현재 관측됨",
                )
            )
            next_counters[counter_key] = (observation.packets, observation.bytes_count)
    return _PreparedDisplayOutcome(
        outcome=outcome,
        visible_rows=tuple(rows[:_MAX_VISIBLE_RESULT_ROWS]),
        total_rows=len(rows),
        next_counters=next_counters if monitoring else {},
    )


def _counter_delta(current: int | None, previous: int | None) -> str:
    if current is None or previous is None or current < previous:
        return "-"
    return f"+{current - previous:,}"


def _lifecycle_status(
    event_types: set[str],
    *,
    miss_count: int,
    close_after_misses: int,
    is_observed: bool,
    authoritative: bool,
) -> str | None:
    if not is_observed:
        if not authoritative:
            return "조회 결과 신뢰 불가 · 이전 관측 유지"
        return f"이번 조회에서 미관측 ({miss_count}/{close_after_misses}) · 종료 판단 보류"
    labels = []
    if "STARTED" in event_types:
        labels.append("처음 관측")
    if "CONTROLLER_CHANGED" in event_types:
        labels.append("관측 MD 변경")
    if "CONTROLLER_OVERLAP" in event_types:
        labels.append("여러 MD에서 동시 관측")
    if "FLAGS_CHANGED" in event_types:
        labels.append("Flags 변경")
    return "현재 관측됨" + (" · " + " · ".join(labels) if labels else "")


def _fatal_diagnostic_event(outcome: object) -> object | None:
    fatal = {
        "AUTH_FAILED",
        "COMMAND_REJECTED",
        "COMMAND_VARIANT_UNVERIFIED",
        "CURRENT_SWITCH_AMBIGUOUS",
        "CURRENT_SWITCH_UNMAPPED",
        "DB_WRITE_FAILED",
        "HOST_KEY_CHANGED",
        "HOST_KEY_UNKNOWN",
        "MM_UNREACHABLE",
        "OUTPUT_LIMIT_EXCEEDED",
        "PROMPT_PARSE_FAILED",
        "STORAGE_LOW_SPACE",
    }
    for diagnostic in getattr(outcome, "diagnostics", ()):
        if bool(getattr(diagnostic, "transient", False)) or bool(
            getattr(diagnostic, "recovered", False)
        ):
            continue
        code = getattr(getattr(diagnostic, "code", None), "value", None)
        if code in fatal:
            return cast(object, diagnostic)
    return None


def _diagnostic_code_text(diagnostic: object | None) -> str | None:
    code = getattr(getattr(diagnostic, "code", None), "value", None)
    return str(code) if isinstance(code, str) else None


def _fatal_diagnostic_code(outcome: object) -> str | None:
    """Compatibility helper retained for callers that only need the raw code."""

    return _diagnostic_code_text(_fatal_diagnostic_event(outcome))


def _nonnegative_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0.0
    return max(0.0, float(value))


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _display_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB")
    amount = float(max(value, 0))
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{amount:.1f} {unit}" if unit != "B" else f"{int(amount)} B"
        amount /= 1024
    return f"{value} B"


def _storage_status_text(health: object) -> str:
    raw_file_count = _nonnegative_int(getattr(health, "raw_file_count", 0))
    raw_bytes = _nonnegative_int(getattr(health, "raw_bytes", 0))
    total_managed_bytes = _nonnegative_int(getattr(health, "total_managed_bytes", 0))
    free_bytes = _nonnegative_int(getattr(health, "free_bytes", 0))
    summary = (
        f"저장소 · Raw 파일 {raw_file_count:,}개 · Raw 용량 {_display_bytes(raw_bytes)} · "
        f"전체 관리 데이터 {_display_bytes(total_managed_bytes)} · "
        f"여유 공간 {_display_bytes(free_bytes)}"
    )
    if raw_file_count >= _RAW_FILE_COUNT_WARNING:
        summary += (
            "\n주의: Raw 파일이 "
            f"{_RAW_FILE_COUNT_WARNING:,}개 이상입니다. 자동 삭제되지 않으므로 "
            "보존 정책에 따라 오래된 기록을 수동으로 정리하십시오."
        )
    return summary


def _history_status_label(value: str) -> str:
    normalized = value.strip().upper()
    return _HISTORY_STATUS_LABELS.get(normalized, value or "-")


def _checked_state() -> Qt.CheckState:
    return Qt.CheckState.Checked


def _unchecked_state() -> Qt.CheckState:
    return Qt.CheckState.Unchecked


def _raw_data_role() -> int:
    return int(Qt.ItemDataRole.UserRole)


def _severity_color(severity: str, *, dark: bool = False) -> QColor:
    if dark:
        return {
            "CRITICAL": QColor("#E05C65"),
            "WARNING": QColor("#E4A83C"),
            "CHECK": QColor("#E4A83C"),
        }.get(severity.upper(), QColor("#B9CBD8"))
    return {
        "CRITICAL": QColor("#b42318"),
        "WARNING": QColor("#b54708"),
        "CHECK": QColor("#7a5d00"),
    }.get(severity.upper(), QColor("#344054"))
