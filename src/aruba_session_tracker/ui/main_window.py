from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
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

from aruba_session_tracker.collectors.ssh import CancellationToken, HostKeyInfo
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.parsers import interpret_flags, overall_flag_severity
from aruba_session_tracker.storage import SessionStore


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
    succeeded = Signal(object)
    failed = Signal(object)
    finished = Signal()


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
    ) -> None:
        super().__init__()
        self.signals = _TaskSignals()
        self._executor = executor
        self._config = config
        self._request = request
        self._credentials = credentials
        self._monitoring = monitoring
        self._token = token
        self._host_key_approval = host_key_approval
        self._full_scan_approval = full_scan_approval

    @Slot()
    def run(self) -> None:
        try:
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
            self.signals.failed.emit(exc)
        else:
            self.signals.succeeded.emit(outcome)
        finally:
            self.signals.finished.emit()


class _ApprovalRequest:
    def __init__(self, title: str, message: str) -> None:
        self.title = title
        self.message = message
        self.answer = False
        self.event = threading.Event()


class ApprovalBridge(QObject):
    requested = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.requested.connect(self._show_request)

    def approve_host_key(self, target: DeviceTarget, info: HostKeyInfo) -> bool:
        request = _ApprovalRequest(
            "SSH 호스트 키 승인",
            f"장비: {target.name}\n주소: {target.host}:{target.port}\n"
            f"알고리즘: {info.algorithm}\n지문: {info.sha256_fingerprint}\n\n"
            "장비의 실제 지문과 일치하는지 확인한 뒤 승인하십시오.",
        )
        self.requested.emit(request)
        request.event.wait()
        return request.answer

    def approve_full_scan(
        self,
        _request: QueryRequest,
        devices: tuple[DeviceTarget, ...],
    ) -> bool:
        targets = "\n".join(f"- {device.name}: {device.host}:{device.port}" for device in devices)
        request = _ApprovalRequest(
            f"MD {len(devices)}대 전수조회 확인",
            "Source와 Destination을 MM에서 찾지 못했습니다.\n"
            "다음 활성 MD를 한 대씩 순차 조회합니다.\n\n"
            f"{targets}\n\n장비 부하와 조회 권한을 확인한 뒤 진행하십시오.",
        )
        self.requested.emit(request)
        request.event.wait()
        return request.answer

    @Slot(object)
    def _show_request(self, request: _ApprovalRequest) -> None:
        try:
            request.answer = (
                QMessageBox.question(
                    QApplication.activeWindow(),
                    request.title,
                    request.message,
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            )
        finally:
            request.event.set()


class MainWindow(QMainWindow):
    def __init__(
        self,
        config_repository: ConfigRepository,
        store: SessionStore,
        executor: QueryExecutor,
    ) -> None:
        super().__init__()
        self._config_repository = config_repository
        self._store = store
        self._executor = executor
        self._thread_pool = QThreadPool(self)
        self._approval = ApprovalBridge(self)
        self._cancel_token: CancellationToken | None = None
        self._query_running = False
        self._monitoring = False
        self._last_counters: dict[str, tuple[int | None, int | None]] = {}
        self._monitor_timer = QTimer(self)
        self._monitor_timer.timeout.connect(self._start_query)

        self.setWindowTitle("Aruba Session Tracker 0.1.0")
        self.resize(1320, 820)
        self.setMinimumSize(1080, 680)
        self._build_ui()
        self._apply_style()
        self._load_config()
        self._refresh_history()

    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._build_query_tab(), "세션 조회")
        tabs.addTab(self._build_settings_tab(), "장비 설정")
        tabs.addTab(self._build_history_tab(), "기록 및 내보내기")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("실제 장비 접속 전 SSH 지문을 반드시 확인하십시오.")

    def _build_query_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.connection_group = QGroupBox("실행 세션 자격증명 (저장하지 않음)")
        connection_layout = QGridLayout(self.connection_group)
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.enable_edit = QLineEdit()
        self.enable_edit.setEchoMode(QLineEdit.EchoMode.Password)
        connection_layout.addWidget(QLabel("사용자 이름"), 0, 0)
        connection_layout.addWidget(self.username_edit, 0, 1)
        connection_layout.addWidget(QLabel("암호"), 0, 2)
        connection_layout.addWidget(self.password_edit, 0, 3)
        connection_layout.addWidget(QLabel("Enable 암호(선택)"), 0, 4)
        connection_layout.addWidget(self.enable_edit, 0, 5)

        self.query_group = QGroupBox("세션 조건")
        query_layout = QGridLayout(self.query_group)
        self.source_ip_edit = QLineEdit()
        self.destination_ip_edit = QLineEdit()
        self.source_port_edit = QLineEdit()
        self.destination_port_edit = QLineEdit()
        self.bidirectional_check = QCheckBox("양방향 검색 (IP와 포트를 함께 교환)")
        self.bidirectional_check.setChecked(True)
        query_layout.addWidget(QLabel("Source IP"), 0, 0)
        query_layout.addWidget(self.source_ip_edit, 0, 1)
        query_layout.addWidget(QLabel("Destination IP"), 0, 2)
        query_layout.addWidget(self.destination_ip_edit, 0, 3)
        query_layout.addWidget(QLabel("SPort (선택)"), 1, 0)
        query_layout.addWidget(self.source_port_edit, 1, 1)
        query_layout.addWidget(QLabel("DPort (선택)"), 1, 2)
        query_layout.addWidget(self.destination_port_edit, 1, 3)
        query_layout.addWidget(self.bidirectional_check, 2, 0, 1, 4)

        actions = QHBoxLayout()
        self.query_button = QPushButton("현재 조회")
        self.monitor_button = QPushButton("지속 모니터링 시작")
        self.stop_button = QPushButton("중지")
        self.stop_button.setEnabled(False)
        self.query_button.clicked.connect(self._start_query)
        self.monitor_button.clicked.connect(self._start_monitoring)
        self.stop_button.clicked.connect(self._stop_work)
        actions.addWidget(self.query_button)
        actions.addWidget(self.monitor_button)
        actions.addWidget(self.stop_button)
        actions.addStretch(1)
        self.state_label = QLabel("대기")
        self.state_label.setObjectName("stateLabel")
        actions.addWidget(self.state_label)

        layout.addWidget(self.connection_group)
        layout.addWidget(self.query_group)
        layout.addLayout(actions)

        splitter = QSplitter()
        result_panel = QWidget()
        result_layout = QVBoxLayout(result_panel)
        self.context_label = QLabel("MM/MD: 아직 조회하지 않음")
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
        self.result_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.itemSelectionChanged.connect(self._show_selected_raw)
        result_layout.addWidget(self.context_label)
        result_layout.addWidget(self.result_table)

        details = QTabWidget()
        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        self.diagnostics_list = QListWidget()
        details.addTab(self.raw_view, "선택 행 Raw")
        details.addTab(self.diagnostics_list, "진단 이벤트")
        splitter.addWidget(result_panel)
        splitter.addWidget(details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        return page

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
        warning = QLabel("장비 주소와 주기만 저장합니다. 사용자 이름과 암호는 저장하지 않습니다.")
        warning.setWordWrap(True)
        save_row.addWidget(warning)

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
        refresh_button = QPushButton("새로고침")
        self.export_button = QPushButton("선택 실행 CSV 내보내기")
        self.delete_button = QPushButton("선택 실행 삭제")
        self.delete_all_button = QPushButton("전체 기록 삭제")
        refresh_button.clicked.connect(self._refresh_history)
        self.export_button.clicked.connect(self._export_selected_run)
        self.delete_button.clicked.connect(lambda: self._delete_history(all_runs=False))
        self.delete_all_button.clicked.connect(lambda: self._delete_history(all_runs=True))
        toolbar.addWidget(refresh_button)
        toolbar.addWidget(self.export_button)
        toolbar.addWidget(self.delete_button)
        toolbar.addWidget(self.delete_all_button)
        toolbar.addStretch(1)
        layout.addLayout(toolbar)
        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(["Run ID", "시작", "종료", "상태", "세션 수"])
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.history_table)
        note = QLabel(
            "Raw TXT와 SQLite에는 내부 IP 및 세션 메타데이터가 평문으로 남습니다. "
            "자동 삭제하지 않으므로 보존 정책에 따라 수동으로 삭제하십시오."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        return page

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
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "설정 읽기 실패", str(exc))
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
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "설정 저장 실패", str(exc))
            return
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
        if self._query_running:
            return
        if not self._monitoring:
            self._last_counters.clear()
        try:
            config, request, credentials = self._read_query()
        except ValueError as exc:
            QMessageBox.warning(self, "입력 확인", str(exc))
            self._stop_work()
            return
        self._query_running = True
        self._cancel_token = CancellationToken()
        self._set_busy(True)
        self.state_label.setText("조회 중")
        task = _QueryTask(
            self._executor,
            config,
            request,
            credentials,
            self._monitoring,
            self._cancel_token,
            self._approval.approve_host_key,
            self._approval.approve_full_scan,
        )
        task.signals.succeeded.connect(self._display_outcome)
        task.signals.failed.connect(self._display_failure)
        task.signals.finished.connect(self._query_finished)
        self._thread_pool.start(task)

    @Slot()
    def _start_monitoring(self) -> None:
        if self._monitoring:
            return
        self._last_counters.clear()
        self._monitoring = True
        self._set_monitor_inputs_enabled(False)
        self._monitor_timer.setInterval(self.session_interval.value() * 1000)
        self.monitor_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self._start_query()

    @Slot()
    def _stop_work(self) -> None:
        self._monitoring = False
        self._last_counters.clear()
        self._monitor_timer.stop()
        if self._cancel_token is not None:
            self._cancel_token.cancel()
        self._executor.stop_monitor()
        self.state_label.setText("중지 요청")
        self._set_monitor_inputs_enabled(True)
        self._set_busy(self._query_running)

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

        self.result_table.setRowCount(0)
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
                self._append_observation(
                    observation,
                    packet_delta=packet_delta,
                    byte_delta=byte_delta,
                    lifecycle_status=_lifecycle_status(
                        event_types_by_flow.get(flow_key, set()),
                        miss_count=int(getattr(session, "miss_count", 0)),
                        close_after_misses=self.close_misses.value(),
                        is_observed=is_observed,
                        authoritative=authoritative,
                    ),
                )
                next_counters[flow_key] = (observation.packets, observation.bytes_count)
            for flow_key, observation in closed_observations.items():
                if flow_key not in next_counters:
                    self._append_observation(
                        observation,
                        lifecycle_status=(f"종료 확인 ({self.close_misses.value()}회 연속 MISS)"),
                    )
        else:
            for observation in observations:
                if not isinstance(observation, SessionObservation):
                    continue
                flow_key = _flow_key(observation)
                previous = self._last_counters.get(flow_key)
                self._append_observation(
                    observation,
                    packet_delta=_counter_delta(
                        observation.packets,
                        None if previous is None else previous[0],
                    ),
                    byte_delta=_counter_delta(
                        observation.bytes_count,
                        None if previous is None else previous[1],
                    ),
                )
                next_counters[flow_key] = (observation.packets, observation.bytes_count)
        self._last_counters = next_counters if self._monitoring else {}
        used_mm = getattr(outcome, "used_mm", None) or "-"
        controllers = ", ".join(getattr(outcome, "controllers", ())) or "-"
        self.context_label.setText(
            f"MM: {used_mm}   |   조회 MD: {controllers}   |   "
            f"현재 일치: {len(observations)}   |   표시: {self.result_table.rowCount()}"
        )
        self.diagnostics_list.clear()
        for event in getattr(outcome, "diagnostics", ()):
            code = getattr(event, "code", None)
            code_text = getattr(code, "value", code) if code is not None else "INFO"
            self.diagnostics_list.addItem(
                f"[{getattr(event, 'stage', '-')}] {code_text}: {getattr(event, 'message', '')}"
            )
        raw_snapshots = getattr(outcome, "raw_snapshots", ())
        if raw_snapshots:
            raw_text = "\n\n".join(
                str(getattr(snapshot, "output", snapshot)) for snapshot in raw_snapshots
            )
            self.raw_view.setPlainText(raw_text)
        fatal_code = _fatal_diagnostic_code(outcome)
        if bool(getattr(outcome, "cancelled", False)):
            self.state_label.setText("중지됨")
        elif fatal_code is not None:
            if self._monitoring:
                self._stop_work()
            state = {
                "AUTH_FAILED": "인증 실패",
                "HOST_KEY_CHANGED": "호스트 키 변경 감지",
                "HOST_KEY_UNKNOWN": "호스트 키 승인 안 됨",
                "PROMPT_PARSE_FAILED": "프롬프트 확인 실패",
            }.get(fatal_code, "접속 실패")
            self.state_label.setText(state)
            if fatal_code != "HOST_KEY_UNKNOWN":
                QMessageBox.warning(
                    self,
                    "조회 중단",
                    f"{state}: 진단 이벤트에서 안전한 오류 코드를 확인하십시오.",
                )
        elif authoritative:
            self.state_label.setText("모니터링" if self._monitoring else "완료")
        else:
            self.state_label.setText("확인 불가 · 진단 확인")
        self._refresh_history()

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
            item.setData(_raw_data_role(), observation.raw_line)
            if column in (13, 14):
                item.setForeground(_severity_color(severity.name))
            self.result_table.setItem(row, column, item)

    @Slot()
    def _show_selected_raw(self) -> None:
        items = self.result_table.selectedItems()
        if not items:
            return
        raw = items[0].data(_raw_data_role())
        self.raw_view.setPlainText(str(raw or ""))

    @Slot(object)
    def _display_failure(self, exc: Exception) -> None:
        code = getattr(getattr(exc, "code", None), "value", None)
        message = str(exc) or "알 수 없는 오류가 발생했습니다."
        self.diagnostics_list.addItem(f"[{code or 'UNEXPECTED'}] {message}")
        self.state_label.setText("실패")
        if code not in {"CANCELLED"}:
            QMessageBox.warning(self, "조회 실패", f"{code + ': ' if code else ''}{message}")
        self._stop_work()

    @Slot()
    def _query_finished(self) -> None:
        self._query_running = False
        self._set_busy(False)
        self._cancel_token = None
        if self._monitoring:
            self._monitor_timer.start()

    def _set_busy(self, busy: bool) -> None:
        self.query_button.setEnabled(not busy and not self._monitoring)
        self.stop_button.setEnabled(busy or self._monitoring)
        if not self._monitoring:
            self.monitor_button.setEnabled(not busy)
        history_mutable = not busy and not self._monitoring
        self.export_button.setEnabled(history_mutable)
        self.delete_button.setEnabled(history_mutable)
        self.delete_all_button.setEnabled(history_mutable)

    def _set_monitor_inputs_enabled(self, enabled: bool) -> None:
        for widget in (
            self.connection_group,
            self.query_group,
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
        try:
            runs = self._store.list_runs(limit=100)
        except Exception as exc:
            self.statusBar().showMessage(f"기록 읽기 실패: {exc}", 5000)
            return
        self.history_table.setRowCount(0)
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
        try:
            exported = self._store.export_run_csv(run_id, Path(destination))
        except Exception as exc:
            QMessageBox.warning(self, "내보내기 실패", str(exc))
            return
        QMessageBox.information(self, "내보내기 완료", str(exported))

    def _delete_history(self, *, all_runs: bool) -> None:
        run_id = None if all_runs else self._selected_run_id()
        if not all_runs and run_id is None:
            QMessageBox.information(self, "기록 삭제", "삭제할 실행 기록을 선택하십시오.")
            return
        try:
            preview = self._store.preview_delete(run_id)
        except Exception as exc:
            QMessageBox.warning(self, "삭제 준비 실패", str(exc))
            return
        run_count = len(getattr(preview, "run_ids", ()))
        answer = QMessageBox.warning(
            self,
            "기록 삭제 확인",
            f"실행: {run_count}건\n"
            f"DB 행: {getattr(preview, 'database_rows', 0)}개\n"
            f"Raw TXT: {getattr(preview, 'raw_files', 0)}개\n"
            f"관리 CSV: {getattr(preview, 'export_files', 0)}개\n"
            f"파일 크기: {_display_bytes(int(getattr(preview, 'total_file_bytes', 0)))}\n\n"
            "위 대상을 영구 삭제합니다. 계속하시겠습니까?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._store.delete(preview, confirmation_token=preview.confirmation_token)
        except Exception as exc:
            QMessageBox.warning(self, "삭제 실패", str(exc))
            return
        self._refresh_history()
        self.statusBar().showMessage("선택한 기록을 삭제했습니다.", 5000)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow { background: #f4f6f8; }
            QGroupBox { font-weight: 600; border: 1px solid #c8d0d8; border-radius: 5px;
                        margin-top: 8px; padding-top: 10px; background: white; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
            QPushButton { min-height: 30px; padding: 0 14px; }
            QPushButton:default { background: #1769aa; color: white; }
            QLineEdit, QSpinBox, QTableWidget, QPlainTextEdit, QListWidget {
                background: white; border: 1px solid #b8c2cc; border-radius: 3px;
            }
            #stateLabel { font-weight: 700; color: #174a72; padding: 6px 12px;
                          background: #e4f1fb; border-radius: 4px; }
            """
        )
        font = QFont("Malgun Gothic", 9)
        application = QApplication.instance()
        if isinstance(application, QApplication):
            application.setFont(font)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._stop_work()
        if self._query_running:
            QMessageBox.information(
                self,
                "종료 대기",
                "진행 중인 SSH 작업을 취소했습니다. 정리 후 다시 종료하십시오.",
            )
            event.ignore()
            return
        event.accept()


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
        "HOST_KEY_CHANGED",
        "HOST_KEY_UNKNOWN",
        "MM_UNREACHABLE",
        "PROMPT_PARSE_FAILED",
    }
    for diagnostic in getattr(outcome, "diagnostics", ()):
        code = getattr(getattr(diagnostic, "code", None), "value", None)
        if code in fatal:
            return str(code)
    return None


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
