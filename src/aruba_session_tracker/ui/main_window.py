from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from time import monotonic
from typing import Protocol

from PySide6.QtCore import QObject, QRunnable, Qt, QThread, QThreadPool, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
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
    QMainWindow,
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
from aruba_session_tracker.collectors.ssh import CancellationToken, CollectorError, HostKeyInfo
from aruba_session_tracker.config import ConfigError, ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.parsers import interpret_flags, overall_flag_severity
from aruba_session_tracker.storage import DeletePreview, SessionStore, StorageError
from aruba_session_tracker.ui.developer_inspector import (
    DeveloperInspectorController,
    UiElementMetadata,
)

_UI_SOURCE_PATH = "src/aruba_session_tracker/ui/main_window.py"
_MAX_VISIBLE_RESULT_ROWS = 2_000
_DETAIL_COLUMN_INDEXES = range(5, 12)
_STORAGE_HEALTH_INTERVAL_SECONDS = 60.0
_OPERATOR_STATES = frozenset({"대기", "조회 중", "정상", "재시도 중", "확인 필요"})


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


class _TaskSignals(QObject):
    succeeded = Signal(int, object)
    failed = Signal(int, object)
    finished = Signal(int)
    storage_warning = Signal(int, bool)


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

    @Slot()
    def run(self) -> None:
        try:
            if self._query_capacity_check is not None:
                self._query_capacity_check()
            if self._storage_health_check is not None:
                health = self._storage_health_check()
                if bool(getattr(health, "warning", False)):
                    hard_stop = bool(getattr(health, "hard_stop", False))
                    self.signals.storage_warning.emit(
                        self.generation,
                        hard_stop,
                    )
                    if hard_stop:
                        raise StorageError(
                            "저장 공간이 부족하여 새 조회를 시작할 수 없습니다.",
                            code=ErrorCode.STORAGE_LOW_SPACE,
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
        except Exception as exc:
            self.signals.failed.emit(self.generation, exc)
        else:
            self.signals.succeeded.emit(self.generation, outcome)
        finally:
            self.signals.finished.emit(self.generation)


class _StorageTaskSignals(QObject):
    succeeded = Signal(int, str, object)
    failed = Signal(int, str, object)
    finished = Signal(int, str)


class _StorageTask(QRunnable):
    def __init__(
        self,
        generation: int,
        kind: str,
        operation: Callable[[], object],
        context: object | None = None,
    ) -> None:
        super().__init__()
        self.signals = _StorageTaskSignals()
        self.generation = generation
        self.kind = kind
        self.context = context
        self._operation = operation

    @Slot()
    def run(self) -> None:
        try:
            result = self._operation()
        except Exception as exc:
            self.signals.failed.emit(self.generation, self.kind, exc)
        else:
            self.signals.succeeded.emit(self.generation, self.kind, result)
        finally:
            self.signals.finished.emit(self.generation, self.kind)


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
        return self._request_answer(request, cancel_token)

    def approve_full_scan(
        self,
        _request: QueryRequest,
        devices: tuple[DeviceTarget, ...],
        *,
        cancel_token: CancellationToken | None = None,
        generation: int | None = None,
    ) -> bool:
        targets = "\n".join(f"- {device.name}: {device.host}:{device.port}" for device in devices)
        request = _ApprovalRequest(
            f"MD {len(devices)}대 전수조회 확인",
            "Source와 Destination을 MM에서 찾지 못했습니다.\n"
            "다음 활성 MD를 한 대씩 순차 조회합니다.\n\n"
            f"{targets}\n\n장비 부하와 조회 권한을 확인한 뒤 진행하십시오.",
            generation,
        )
        return self._request_answer(request, cancel_token)

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
    ) -> bool:
        if cancel_token is not None and cancel_token.is_cancelled:
            return False
        with self._lock:
            if self._shutting_down:
                return False
            self._pending.add(request)

        if cancel_token is not None and cancel_token.is_cancelled:
            self._complete_request(request, False, dismiss=False)
            return False
        if QThread.currentThread() == self.thread():
            self._show_request_blocking(request)
        else:
            self.requested.emit(request)

        while not request.event.wait(0.05):
            if cancel_token is not None and cancel_token.is_cancelled:
                self._complete_request(request, False, dismiss=True)
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

    def _show_request_blocking(self, request: _ApprovalRequest) -> None:
        with self._lock:
            if request not in self._pending:
                return
        answer = QMessageBox.question(
            self._owner,
            request.title,
            request.message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        self._complete_request(
            request,
            answer == QMessageBox.StandardButton.Yes,
            dismiss=False,
        )

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
    ) -> None:
        super().__init__()
        self._config_repository = config_repository
        self._store = store
        self._executor = executor
        self._developer_inspector = developer_inspector
        self._thread_pool = QThreadPool(self)
        self._thread_pool.setMaxThreadCount(1)
        self._history_thread_pool = QThreadPool(self)
        self._history_thread_pool.setMaxThreadCount(1)
        self._approval = ApprovalBridge(self)
        self._cancel_token: CancellationToken | None = None
        self._current_task: _QueryTask | None = None
        self._task_generation = 0
        self._user_cancel_generation: int | None = None
        self._query_running = False
        self._monitoring = False
        self._closing_requested = False
        self._close_when_idle = False
        self._storage_task_running = False
        self._storage_task_generation = 0
        self._current_storage_task: _StorageTask | None = None
        self._pending_preview_discards: list[DeletePreview] = []
        self._history_task_running = False
        self._history_task_generation = 0
        self._current_history_task: _StorageTask | None = None
        self._history_dirty = False
        self._history_revision = 0
        self._next_monitor_delay_seconds = 0.0
        self._next_storage_health_check_at = 0.0
        self._last_counters: dict[str, tuple[int | None, int | None]] = {}
        self._monitor_timer = QTimer(self)
        self._monitor_timer.setSingleShot(True)
        self._monitor_timer.timeout.connect(self._start_query)

        self.setWindowTitle(f"Aruba Session Tracker {__version__}")
        self.resize(1320, 820)
        self.setMinimumSize(1080, 680)
        self._build_ui()
        self._apply_style()
        self._load_config()
        self._update_setup_guide()
        self._refresh_history()

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
        self.query_page = self._build_query_tab()
        self.settings_page = self._build_settings_tab()
        self.history_page = self._build_history_tab()
        self.tabs.addTab(self.query_page, "세션 조회")
        self.tabs.addTab(self.settings_page, "장비 설정")
        self.tabs.addTab(self.history_page, "기록 및 내보내기")
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

        self.connection_group = QGroupBox("실행 세션 자격증명 (저장하지 않음)")
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
        connection_layout.addWidget(QLabel("사용자 이름"), 0, 0)
        connection_layout.addWidget(self.username_edit, 0, 1)
        connection_layout.addWidget(QLabel("암호"), 0, 2)
        connection_layout.addWidget(self.password_edit, 0, 3)

        self.query_group = QGroupBox("세션 조건")
        query_layout = QGridLayout(self.query_group)
        self.source_ip_edit = QLineEdit()
        self.source_ip_edit.setAccessibleName("Source IP")
        self.source_ip_edit.setAccessibleDescription("조회할 출발지 IP 주소입니다.")
        self.destination_ip_edit = QLineEdit()
        self.destination_ip_edit.setAccessibleName("Destination IP")
        self.destination_ip_edit.setAccessibleDescription("조회할 목적지 IP 주소입니다.")
        query_layout.addWidget(QLabel("Source IP"), 0, 0)
        query_layout.addWidget(self.source_ip_edit, 0, 1)
        query_layout.addWidget(QLabel("Destination IP"), 0, 2)
        query_layout.addWidget(self.destination_ip_edit, 0, 3)

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
        self.source_port_edit.setAccessibleName("Source 포트")
        self.source_port_edit.setAccessibleDescription(
            "선택 사항인 출발지 포트 번호입니다. 비우면 모든 포트를 조회합니다."
        )
        self.destination_port_edit = QLineEdit()
        self.destination_port_edit.setAccessibleName("Destination 포트")
        self.destination_port_edit.setAccessibleDescription(
            "선택 사항인 목적지 포트 번호입니다. 비우면 모든 포트를 조회합니다."
        )
        self.bidirectional_check = QCheckBox("양방향 검색 (IP와 포트를 함께 교환)")
        self.bidirectional_check.setAccessibleName("양방향 검색")
        self.bidirectional_check.setAccessibleDescription(
            "Source와 Destination IP 및 포트를 서로 바꾼 방향도 함께 검색합니다."
        )
        self.bidirectional_check.setChecked(True)
        advanced_layout.addWidget(QLabel("Enable 암호(선택)"), 0, 0)
        advanced_layout.addWidget(self.enable_edit, 0, 1, 1, 3)
        advanced_layout.addWidget(QLabel("SPort (선택)"), 1, 0)
        advanced_layout.addWidget(self.source_port_edit, 1, 1)
        advanced_layout.addWidget(QLabel("DPort (선택)"), 1, 2)
        advanced_layout.addWidget(self.destination_port_edit, 1, 3)
        advanced_layout.addWidget(self.bidirectional_check, 2, 0, 1, 4)
        self.advanced_panel.setVisible(False)

        actions = QHBoxLayout()
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
        self.state_label = QLabel("대기")
        self.state_label.setObjectName("stateLabel")
        actions.addWidget(self.state_label)

        layout.addWidget(self.connection_group)
        layout.addWidget(self.query_group)
        layout.addWidget(self.advanced_toggle_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.advanced_panel)
        layout.addLayout(actions)

        splitter = QSplitter()
        result_panel = QWidget()
        result_layout = QVBoxLayout(result_panel)
        result_options = QHBoxLayout()
        self.context_label = QLabel("MM/MD: 아직 조회하지 않음")
        self.detail_columns_toggle = QCheckBox("상세 열 보기")
        self.detail_columns_toggle.setAccessibleName("상세 결과 열 보기")
        self.detail_columns_toggle.setAccessibleDescription(
            "DPort, 패킷, 바이트, 변화량, Age, CPU 열을 표시하거나 숨깁니다."
        )
        self.raw_diagnostics_toggle = QCheckBox("상세 정보 보기")
        self.raw_diagnostics_toggle.setAccessibleName("Raw 및 진단 패널 보기")
        self.raw_diagnostics_toggle.setAccessibleDescription(
            "선택한 Raw 행과 진단 이벤트 패널을 표시하거나 숨깁니다."
        )
        result_options.addWidget(self.context_label, 1)
        result_options.addWidget(self.detail_columns_toggle)
        result_options.addWidget(self.raw_diagnostics_toggle)
        self.result_table = QTableWidget(0, 15)
        self.result_table.setHorizontalHeaderLabels(
            [
                "Controller",
                "Protocol",
                "Source",
                "SPort",
                "Destination",
                "DPort",
                "Packets",
                "Bytes",
                "ΔPackets",
                "ΔBytes",
                "Age",
                "CPU",
                "마지막 관측(로컬)",
                "Flags",
                "상태",
            ]
        )
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.result_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.result_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        widths = (110, 70, 125, 70, 125, 70, 85, 95, 85, 85, 70, 55, 150, 80)
        for column, width in enumerate(widths):
            header.resizeSection(column, width)
        for column in _DETAIL_COLUMN_INDEXES:
            self.result_table.setColumnHidden(column, True)
        self.detail_columns_toggle.toggled.connect(self._set_detail_columns_visible)
        self.result_table.itemSelectionChanged.connect(self._show_selected_raw)
        result_layout.addLayout(result_options)
        result_layout.addWidget(self.result_table)

        self.details = QTabWidget()
        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.diagnostics_list = QListWidget()
        self.details.addTab(self.raw_view, "선택 행 Raw")
        self.details.addTab(self.diagnostics_list, "진단 이벤트")
        self.details.setVisible(False)
        self.raw_diagnostics_toggle.toggled.connect(self._set_details_visible)
        splitter.addWidget(result_panel)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        focus_order = (
            self.open_settings_button,
            self.username_edit,
            self.password_edit,
            self.source_ip_edit,
            self.destination_ip_edit,
            self.advanced_toggle_button,
            self.enable_edit,
            self.source_port_edit,
            self.destination_port_edit,
            self.bidirectional_check,
            self.monitor_button,
            self.query_button,
            self.stop_button,
            self.detail_columns_toggle,
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

    @Slot(bool)
    def _set_detail_columns_visible(self, visible: bool) -> None:
        for column in _DETAIL_COLUMN_INDEXES:
            self.result_table.setColumnHidden(column, not visible)

    @Slot(bool)
    def _set_details_visible(self, visible: bool) -> None:
        self.details.setVisible(visible)
        self.raw_diagnostics_toggle.setText("상세 정보 숨기기" if visible else "상세 정보 보기")

    def _set_state(self, state: str) -> None:
        if state not in _OPERATOR_STATES:
            raise ValueError("invalid operator state")
        self.state_label.setText(state)

    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.mm_group = QGroupBox("Mobility Conductor")
        mm_layout = QGridLayout(self.mm_group)
        self.mm_primary_name = QLineEdit("MM-Conductor")
        self.mm_primary_host = QLineEdit()
        self.mm_primary_port = self._port_spin()
        self.mm_primary_enabled = QCheckBox()
        self.mm_primary_enabled.setChecked(True)
        self.mm_standby_name = QLineEdit("MM-Standby")
        self.mm_standby_host = QLineEdit()
        self.mm_standby_port = self._port_spin()
        self.mm_standby_enabled = QCheckBox()
        self.mm_standby_enabled.setChecked(True)
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

        self.md_group = QGroupBox("Managed Devices (7240XM)")
        md_layout = QVBoxLayout(self.md_group)
        self.md_table = QTableWidget(4, 4)
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

        self.timing_group = QGroupBox("모니터링")
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
        timing_layout.addRow("MD 세션 조회(초)", self.session_interval)
        timing_layout.addRow("MM 위치 재확인(초)", self.location_interval)
        timing_layout.addRow("종료 판정 MISS", self.close_misses)

        save_row = QHBoxLayout()
        self.save_config_button = QPushButton("장비 설정 저장")
        self.save_config_button.clicked.connect(self._save_config)
        save_row.addWidget(self.save_config_button)
        save_row.addStretch(1)
        self.settings_privacy_notice = QLabel(
            "장비 주소와 주기만 저장합니다. 사용자 이름과 암호는 저장하지 않습니다."
        )
        self.settings_privacy_notice.setWordWrap(True)
        save_row.addWidget(self.settings_privacy_notice)

        layout.addWidget(self.mm_group)
        layout.addWidget(self.md_group)
        layout.addWidget(self.timing_group)
        layout.addLayout(save_row)
        layout.addStretch(1)
        return page

    def _build_history_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        toolbar = QHBoxLayout()
        self.refresh_history_button = QPushButton("새로고침")
        self.export_button = QPushButton("선택 실행 CSV 내보내기")
        self.html_export_button = QPushButton("선택 실행 HTML 보고서")
        self.delete_button = QPushButton("선택 실행 삭제")
        self.delete_all_button = QPushButton("전체 기록 삭제")
        self.refresh_history_button.clicked.connect(self._refresh_history)
        self.export_button.clicked.connect(self._export_selected_run)
        self.html_export_button.clicked.connect(self._export_selected_run_html)
        self.delete_button.clicked.connect(lambda: self._delete_history(all_runs=False))
        self.delete_all_button.clicked.connect(lambda: self._delete_history(all_runs=True))
        toolbar.addWidget(self.refresh_history_button)
        toolbar.addWidget(self.export_button)
        toolbar.addWidget(self.html_export_button)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.delete_all_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)
        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(["Run ID", "시작", "종료", "상태", "관측 행"])
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.history_table)
        self.history_privacy_notice = QLabel(
            "Raw TXT, SQLite, CSV와 HTML 보고서에는 내부 IP 및 세션 메타데이터가 "
            "평문으로 남을 수 있습니다. "
            "자동 삭제하지 않으므로 보존 정책에 따라 수동으로 삭제하십시오."
        )
        self.history_privacy_notice.setWordWrap(True)
        layout.addWidget(self.history_privacy_notice)
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
                    "Source IP 입력", "MAIN-QUERY-CONDITIONS-SOURCE-IP", query, "출발지 IPv4 입력"
                ),
            ),
            (
                self.destination_ip_edit,
                _ui_metadata(
                    "Destination IP 입력",
                    "MAIN-QUERY-CONDITIONS-DESTINATION-IP",
                    query,
                    "목적지 IPv4 입력",
                ),
            ),
            (
                self.source_port_edit,
                _ui_metadata(
                    "Source 포트 입력",
                    "MAIN-QUERY-CONDITIONS-SOURCE-PORT",
                    query,
                    "선택적 출발지 포트 입력",
                ),
            ),
            (
                self.destination_port_edit,
                _ui_metadata(
                    "Destination 포트 입력",
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
                    "MD 세션 조회 주기",
                    "MAIN-SETTINGS-MONITOR-SESSION-INTERVAL",
                    settings,
                    "MD 세션 조회 주기 입력",
                ),
            ),
            (
                self.location_interval,
                _ui_metadata(
                    "MM 위치 재확인 주기",
                    "MAIN-SETTINGS-MONITOR-LOCATION-INTERVAL",
                    settings,
                    "MM 위치 재확인 주기 입력",
                ),
            ),
            (
                self.close_misses,
                _ui_metadata(
                    "종료 판정 MISS",
                    "MAIN-SETTINGS-MONITOR-CLOSE-MISSES",
                    settings,
                    "세션 종료 판정 MISS 횟수 입력",
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
            QMessageBox.warning(
                self,
                "설정 읽기 실패",
                "설정 파일을 안전하게 읽지 못했습니다. 파일 형식과 권한을 확인하십시오.",
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
            QMessageBox.warning(
                self,
                "설정 저장 실패",
                "설정 파일을 안전하게 저장하지 못했습니다. 저장 위치의 권한을 확인하십시오.",
            )
            return
        self._update_setup_guide()
        self.statusBar().showMessage("장비 설정을 안전하게 저장했습니다.", 5000)

    def _read_query(self) -> tuple[AppConfig, QueryRequest, Credentials]:
        config = self._read_config_from_ui()
        source_port = _optional_port(self.source_port_edit.text(), "SPort")
        destination_port = _optional_port(self.destination_port_edit.text(), "DPort")
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
        if self._query_running or self._storage_task_running or self._closing_requested:
            return
        if not self._monitoring:
            self._last_counters.clear()
        try:
            config, request, credentials = self._read_query()
        except ValueError as exc:
            QMessageBox.warning(self, "입력 확인", str(exc))
            self._cancel_active_work()
            self._set_state("확인 필요")
            self.statusBar().showMessage("입력값을 확인한 뒤 다시 시도해 주세요.", 5000)
            return
        self._query_running = True
        self._task_generation += 1
        generation = self._task_generation
        token = CancellationToken()
        self._cancel_token = token
        self._set_busy(True)
        self._set_state("조회 중")

        def approve_host_key(target: DeviceTarget, info: HostKeyInfo) -> bool:
            return self._approval.approve_host_key(
                target,
                info,
                cancel_token=token,
                generation=generation,
            )

        def approve_full_scan(
            current_request: QueryRequest,
            devices: tuple[DeviceTarget, ...],
        ) -> bool:
            return self._approval.approve_full_scan(
                current_request,
                devices,
                cancel_token=token,
                generation=generation,
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
        )
        self._current_task = task
        task.signals.succeeded.connect(self._task_succeeded)
        task.signals.failed.connect(self._task_failed)
        task.signals.finished.connect(self._query_finished)
        task.signals.storage_warning.connect(self._show_storage_warning)
        self._thread_pool.start(task)

    @Slot()
    def _start_monitoring(self) -> None:
        if self._monitoring or self._closing_requested:
            return
        self._last_counters.clear()
        self._monitoring = True
        self._next_storage_health_check_at = 0.0
        self._next_monitor_delay_seconds = float(self.session_interval.value())
        self._set_monitor_inputs_enabled(False)
        self.monitor_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._start_query()

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
        try:
            self._executor.stop_monitor()
        except Exception:
            self.diagnostics_list.addItem(
                "[UNEXPECTED] 모니터링 중지 정리 중 내부 오류가 발생했습니다."
            )
        if status is not None and was_active:
            self._set_state(status)
        self._set_monitor_inputs_enabled(True)
        self._set_busy(self._query_running)

    @Slot(int, object)
    def _task_succeeded(self, generation: int, outcome: object) -> None:
        if (
            not self._owns_task(generation)
            or self._closing_requested
            or self._user_cancel_generation == generation
        ):
            return
        self._display_outcome(outcome)

    @Slot(int, object)
    def _task_failed(self, generation: int, exc: object) -> None:
        if not self._owns_task(generation) or self._closing_requested:
            return
        failure = exc if isinstance(exc, Exception) else RuntimeError("invalid task failure")
        self._display_failure(failure)

    def _owns_task(self, generation: int) -> bool:
        return (
            self._current_task is not None
            and self._current_task.generation == generation
            and self._task_generation == generation
        )

    @Slot(object)
    def _display_outcome(self, outcome: object) -> None:
        observations = tuple(getattr(outcome, "observations", ()))
        active_sessions = tuple(getattr(outcome, "active_sessions", ()))
        lifecycle_events = tuple(getattr(outcome, "events", ()))
        authoritative = bool(getattr(outcome, "authoritative", False))
        observed_by_flow = {
            _flow_key(item): item for item in observations if isinstance(item, SessionObservation)
        }
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

        rows: list[tuple[SessionObservation, str, str, str | None]] = []
        next_counters: dict[str, tuple[int | None, int | None]] = {}
        if active_sessions:
            for session in active_sessions:
                observation = getattr(session, "observation", None)
                if not isinstance(observation, SessionObservation):
                    continue
                flow_key = _flow_key(observation)
                is_observed = flow_key in observed_by_flow
                previous = self._last_counters.get(flow_key)
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
                    (
                        observation,
                        packet_delta,
                        byte_delta,
                        _lifecycle_status(
                            event_types_by_flow.get(flow_key, set()),
                            miss_count=int(getattr(session, "miss_count", 0)),
                            close_after_misses=self.close_misses.value(),
                            is_observed=is_observed,
                            authoritative=authoritative,
                        ),
                    )
                )
                next_counters[flow_key] = (observation.packets, observation.bytes_count)
            for flow_key, observation in closed_observations.items():
                if flow_key not in next_counters:
                    rows.append(
                        (
                            observation,
                            "-",
                            "-",
                            f"종료 확인 ({self.close_misses.value()}회 연속 MISS)",
                        )
                    )
        else:
            for observation in observations:
                if not isinstance(observation, SessionObservation):
                    continue
                flow_key = _flow_key(observation)
                previous = self._last_counters.get(flow_key)
                rows.append(
                    (
                        observation,
                        _counter_delta(
                            observation.packets,
                            None if previous is None else previous[0],
                        ),
                        _counter_delta(
                            observation.bytes_count,
                            None if previous is None else previous[1],
                        ),
                        None,
                    ),
                )
                next_counters[flow_key] = (observation.packets, observation.bytes_count)

        self.result_table.setUpdatesEnabled(False)
        try:
            self.result_table.setRowCount(0)
            for observation, packet_delta, byte_delta, lifecycle_status in rows[
                :_MAX_VISIBLE_RESULT_ROWS
            ]:
                self._append_observation(
                    observation,
                    packet_delta=packet_delta,
                    byte_delta=byte_delta,
                    lifecycle_status=lifecycle_status,
                )
        finally:
            self.result_table.setUpdatesEnabled(True)
            self.result_table.viewport().update()
        self._last_counters = next_counters if self._monitoring else {}
        used_mm = getattr(outcome, "used_mm", None) or "-"
        controllers = ", ".join(getattr(outcome, "controllers", ())) or "-"
        self.context_label.setText(
            f"MM: {used_mm}   |   조회 MD: {controllers}   |   "
            f"현재 일치: {len(observations)}   |   "
            f"화면 표시: {self.result_table.rowCount()}/{len(rows)}"
        )
        self.diagnostics_list.clear()
        for event in getattr(outcome, "diagnostics", ()):
            code = getattr(event, "code", None)
            code_text = getattr(code, "value", code) if code is not None else "INFO"
            self.diagnostics_list.addItem(
                f"[{getattr(event, 'stage', '-')}] {code_text}: {getattr(event, 'message', '')}"
            )
        if len(rows) > _MAX_VISIBLE_RESULT_ROWS:
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
        fatal_code = _fatal_diagnostic_code(outcome)
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
            self._set_state("확인 필요")
            self.statusBar().showMessage(
                f"{reason}: 진단 이벤트의 안전한 오류 코드를 확인해 주세요.", 10000
            )
            if fatal_code != "HOST_KEY_UNKNOWN":
                QMessageBox.warning(
                    self,
                    "조회 중단",
                    f"{reason}: 진단 이벤트에서 안전한 오류 코드를 확인하십시오.",
                )
        elif self._monitoring and transient_failures > 0:
            self._set_state("재시도 중")
        elif authoritative:
            self._set_state("정상")
        else:
            self._set_state("확인 필요")
        self._mark_history_dirty()

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
        flag_details = interpret_flags(observation.flags)
        severity = overall_flag_severity(observation.flags)
        flag_status = ", ".join(item.label_ko for item in flag_details) or "정상/정보 없음"
        status = (
            f"{lifecycle_status} · {flag_status}" if lifecycle_status is not None else flag_status
        )
        values = (
            observation.controller_name,
            str(observation.protocol),
            observation.source_ip,
            str(observation.source_port),
            observation.destination_ip,
            str(observation.destination_port),
            _display_number(observation.packets),
            _display_number(observation.bytes_count),
            packet_delta,
            byte_delta,
            _display_number(observation.age),
            _display_number(observation.cpu_id),
            _display_observed_at(observation),
            observation.flags or "-",
            status,
        )
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setData(_raw_data_role(), observation.raw_line)
            if column in (13, 14):
                item.setForeground(_severity_color(severity.name))
            self.result_table.setItem(row, column, item)

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
        self._cancel_active_work()
        self.diagnostics_list.clear()
        self.diagnostics_list.addItem(f"[{code}] {message}")
        self._set_state("대기" if code == ErrorCode.CANCELLED.value else "확인 필요")
        if code != ErrorCode.CANCELLED.value:
            self.raw_diagnostics_toggle.setChecked(True)
            self.details.setCurrentWidget(self.diagnostics_list)
            QMessageBox.warning(self, "조회 실패", f"{code}: {message}")

    @Slot(int)
    def _query_finished(self, generation: int) -> None:
        if not self._owns_task(generation):
            return
        self._approval.cancel_pending(generation)
        user_cancelled = self._user_cancel_generation == generation
        self._query_running = False
        self._current_task = None
        self._user_cancel_generation = None
        self._set_busy(False)
        self._cancel_token = None
        if user_cancelled and not self._closing_requested:
            self._set_state("대기")
        if self._monitoring and not self._closing_requested:
            interval_ms = max(1_000, round(self._next_monitor_delay_seconds * 1_000))
            self._monitor_timer.start(interval_ms)
        self._drain_preview_discard_queue()
        if self._close_when_idle:
            self._close_if_idle()

    def _set_busy(self, busy: bool) -> None:
        interactive = not self._closing_requested
        available = interactive and not self._storage_task_running
        self.query_button.setEnabled(available and not busy and not self._monitoring)
        self.stop_button.setEnabled(available and (busy or self._monitoring))
        if not self._monitoring:
            self.monitor_button.setEnabled(available and not busy)
        history_mutable = (
            available and not busy and not self._monitoring and not self._history_task_running
        )
        self.refresh_history_button.setEnabled(history_mutable)
        self.export_button.setEnabled(history_mutable)
        self.html_export_button.setEnabled(history_mutable)
        self.delete_button.setEnabled(history_mutable)
        self.delete_all_button.setEnabled(history_mutable)

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
        row = self.history_table.currentRow()
        if row < 0:
            return None
        item = self.history_table.item(row, 0)
        return item.text() if item else None

    @Slot()
    def _refresh_history(self) -> None:
        if self._closing_requested or self._history_task_running or self._storage_task_running:
            return
        self._history_task_generation += 1
        generation = self._history_task_generation
        context = (self._selected_run_id(), self._history_revision)
        task = _StorageTask(
            generation,
            "history-list",
            lambda: tuple(self._store.list_runs(limit=100)),
            context,
        )
        self._history_task_running = True
        self._current_history_task = task
        task.signals.succeeded.connect(self._history_task_succeeded)
        task.signals.failed.connect(self._history_task_failed)
        self._set_busy(self._query_running)
        self._history_thread_pool.start(task)

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
        if not isinstance(result, tuple):
            self._history_dirty = True
            self.statusBar().showMessage(
                "기록 읽기 실패: 로컬 기록을 안전하게 읽지 못했습니다.", 5000
            )
            self._drain_preview_discard_queue()
            self._close_if_idle()
            return
        selected_run_id: str | None = None
        requested_revision = -1
        if isinstance(task.context, tuple) and len(task.context) == 2:
            selected_value, revision_value = task.context
            if isinstance(selected_value, str):
                selected_run_id = selected_value
            if isinstance(revision_value, int):
                requested_revision = revision_value
        self._render_history(result, selected_run_id)
        self._history_dirty = requested_revision != self._history_revision
        self._drain_preview_discard_queue()
        self._close_if_idle()

    @Slot(int, str, object)
    def _history_task_failed(self, generation: int, kind: str, _exc: object) -> None:
        if self._finish_history_task(generation, kind) is None:
            return
        self._history_dirty = True
        if not self._closing_requested:
            self.statusBar().showMessage(
                "기록 읽기 실패: 로컬 기록을 안전하게 읽지 못했습니다.", 5000
            )
        self._drain_preview_discard_queue()
        self._close_if_idle()

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
                values = (
                    str(run.get("id", "")),
                    str(run.get("started_at", "")),
                    str(run.get("ended_at", "") or "-"),
                    str(run.get("status", "")),
                    str(run.get("observation_count", 0)),
                )
            else:
                values = (
                    str(getattr(run, "run_id", "")),
                    str(getattr(run, "started_at", "")),
                    str(getattr(run, "finished_at", "") or "-"),
                    str(getattr(run, "status", "")),
                    str(getattr(run, "observation_count", 0)),
                )
            for column, value in enumerate(values):
                self.history_table.setItem(row, column, QTableWidgetItem(value))
            if values[0] == selected_run_id:
                selected_row = row
        if selected_row >= 0:
            self.history_table.selectRow(selected_row)

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
            lambda: self._store.export_run_csv(run_id, output_path),
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
            lambda: self._store.export_run_html(run_id, output_path),
            status="HTML 보고서 만드는 중",
        )

    def _delete_history(self, *, all_runs: bool) -> None:
        run_id = None if all_runs else self._selected_run_id()
        if not all_runs and run_id is None:
            QMessageBox.information(self, "기록 삭제", "삭제할 실행 기록을 선택하십시오.")
            return
        self._start_storage_task(
            "delete-preview",
            lambda: self._store.preview_delete(run_id),
            status="삭제 대상 확인 중",
        )

    def _start_storage_task(
        self,
        kind: str,
        operation: Callable[[], object],
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
        self._set_busy(self._query_running)
        self.statusBar().showMessage(status)
        self._thread_pool.start(task)
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
            lambda: self._store.discard_delete_preview(preview),
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
                QMessageBox.information(self, "내보내기 완료", str(result))
        elif kind == "export-html":
            self.statusBar().showMessage("HTML 보고서를 만들었습니다.", 5000)
            if not self._closing_requested:
                QMessageBox.information(self, "HTML 보고서 완료", str(result))
        self._drain_preview_discard_queue()
        self._close_if_idle()

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
                lambda: self._store.delete(
                    preview,
                    confirmation_token=preview.confirmation_token,
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
        if kind == "delete-discard":
            self.statusBar().showMessage("삭제 취소 상태를 정리하지 못했습니다.", 5000)
            return
        title, message = {
            "export-csv": ("내보내기 실패", "CSV 파일을 안전하게 내보내지 못했습니다."),
            "export-html": ("HTML 보고서 실패", "HTML 보고서를 안전하게 만들지 못했습니다."),
            "delete-preview": ("삭제 준비 실패", "삭제 대상을 안전하게 확인하지 못했습니다."),
            "delete-commit": ("삭제 실패", "확인된 기록을 안전하게 삭제하지 못했습니다."),
        }.get(kind, ("작업 실패", "로컬 파일 작업을 안전하게 마치지 못했습니다."))
        self.statusBar().showMessage(message, 5000)
        if not self._closing_requested:
            QMessageBox.warning(self, title, message)

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

    def closeEvent(self, event: QCloseEvent) -> None:
        self._closing_requested = True
        self._close_when_idle = True
        self._cancel_active_work(user_requested=True)
        self._approval.shutdown()
        self._drain_preview_discard_queue()
        if (
            self._query_running
            or self._storage_task_running
            or self._history_task_running
            or self._pending_preview_discards
        ):
            self._set_state("확인 필요")
            self.statusBar().showMessage("진행 중인 작업을 안전하게 정리한 뒤 종료합니다.")
            event.ignore()
            return
        event.accept()

    def _close_if_idle(self) -> None:
        if not self._close_when_idle:
            return
        if self._pending_preview_discards:
            self._drain_preview_discard_queue()
        if (
            self._query_running
            or self._storage_task_running
            or self._history_task_running
            or self._pending_preview_discards
        ):
            return
        QTimer.singleShot(0, self.close)


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


def _safe_query_failure(exc: Exception) -> tuple[str, str]:
    raw_code = getattr(getattr(exc, "code", None), "value", None)
    known_codes = {item.value for item in ErrorCode}
    if isinstance(exc, CollectorError) and isinstance(raw_code, str) and raw_code in known_codes:
        return raw_code, str(exc) or "안전하게 처리할 수 없는 조회 오류가 발생했습니다."
    if isinstance(exc, StorageError):
        if raw_code == ErrorCode.STORAGE_LOW_SPACE.value:
            return raw_code, "저장 공간이 부족합니다. 오래된 기록을 정리한 뒤 다시 시도하십시오."
        return ErrorCode.DB_WRITE_FAILED.value, "로컬 조회 기록을 안전하게 저장하지 못했습니다."
    return (
        "UNEXPECTED",
        f"예상하지 못한 내부 오류가 발생했습니다. 오류 유형: {type(exc).__name__}",
    )


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


def _display_observed_at(observation: SessionObservation) -> str:
    return observation.observed_at.astimezone().strftime("%Y-%m-%d %H:%M:%S")


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
            return "확인 불가 · 이전 관측 유지"
        return f"MISS {miss_count}/{close_after_misses} · 종료 확인 중"
    labels = []
    if "STARTED" in event_types:
        labels.append("새 세션")
    if "CONTROLLER_CHANGED" in event_types:
        labels.append("MD 변경")
    if "FLAGS_CHANGED" in event_types:
        labels.append("플래그 변경")
    return "활성" + (" · " + " · ".join(labels) if labels else "")


def _fatal_diagnostic_code(outcome: object) -> str | None:
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
            return str(code)
    return None


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


def _checked_state() -> Qt.CheckState:
    return Qt.CheckState.Checked


def _unchecked_state() -> Qt.CheckState:
    return Qt.CheckState.Unchecked


def _raw_data_role() -> int:
    return int(Qt.ItemDataRole.UserRole)


def _severity_color(severity: str) -> QColor:
    return {
        "CRITICAL": QColor("#b42318"),
        "WARNING": QColor("#b54708"),
        "CHECK": QColor("#7a5d00"),
    }.get(severity.upper(), QColor("#344054"))
