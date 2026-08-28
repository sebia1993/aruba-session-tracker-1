from __future__ import annotations

import gc
import threading
import time
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QMessageBox, QWidget

from aruba_session_tracker.collectors.ssh import CancellationToken, CollectorError, HostKeyInfo
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    DeviceTarget,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import SessionStore, StorageError
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.main_window import (
    ApprovalBridge,
    _counter_delta,
    _display_bytes,
    _fatal_diagnostic_code,
    _lifecycle_status,
    _optional_port,
    _safe_query_failure,
)


class _Executor:
    def __init__(self) -> None:
        self.stopped = False

    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        return QueryOutcome(
            observations=(
                SessionObservation(
                    controller_name="MD-01",
                    controller_host="198.51.100.21",
                    protocol=6,
                    source_ip="192.0.2.101",
                    destination_ip="203.0.113.50",
                    source_port=50000,
                    destination_port=443,
                    packets=10,
                    bytes_count=2048,
                    flags="DY",
                    cpu_id=1,
                    raw_line="sanitized row",
                ),
            ),
            used_mm="MM-Conductor",
            controllers=("MD-01",),
            authoritative=True,
        )

    def stop_monitor(self) -> None:
        self.stopped = True


def _configure_valid_query(window: MainWindow) -> None:
    window.mm_primary_host.setText("192.0.2.1")
    window.mm_standby_host.setText("192.0.2.2")
    window.md_table.item(0, 2).setText("198.51.100.21")
    for row in range(1, 4):
        window.md_table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
    window.username_edit.setText("operator")
    window.password_edit.setText("session-only")
    window.source_ip_edit.setText("192.0.2.101")
    window.destination_ip_edit.setText("203.0.113.50")
    window.source_port_edit.setText("50000")
    window.destination_port_edit.setText("443")


def test_main_window_runs_query_and_renders_korean_flag_status(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    executor = _Executor()
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, executor)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()

    _configure_valid_query(window)

    qtbot.mouseClick(window.query_button, Qt.MouseButton.LeftButton)  # type: ignore[attr-defined]
    qtbot.waitUntil(lambda: window.result_table.rowCount() == 1, timeout=3000)  # type: ignore[attr-defined]

    assert window.result_table.item(0, 14).text() == "차단, SYN 없음"
    assert "MM-Conductor" in window.context_label.text()
    assert window.password_edit.text() == "session-only"
    window.close()


def test_counter_delta_is_only_shown_for_monotonic_samples() -> None:
    assert _counter_delta(15, 10) == "+5"
    assert _counter_delta(10, 10) == "+0"
    assert _counter_delta(2, 10) == "-"
    assert _counter_delta(None, 10) == "-"


def test_optional_port_accepts_only_blank_or_ascii_port_range() -> None:
    assert _optional_port("  ", "출발지 포트") is None
    assert _optional_port(" 443 ", "목적지 포트") == 443
    assert _optional_port("0", "목적지 포트") == 0
    assert _optional_port("65535", "목적지 포트") == 65535

    with pytest.raises(ValueError, match="0~65535 숫자"):
        _optional_port("\uff14\uff14\uff13", "목적지 포트")
    with pytest.raises(ValueError, match="0~65535 숫자"):
        _optional_port("not-a-port", "목적지 포트")
    with pytest.raises(ValueError, match="0~65535 범위"):
        _optional_port("65536", "목적지 포트")


def test_safe_query_failure_maps_known_storage_and_unexpected_errors() -> None:
    assert _safe_query_failure(CollectorError(ErrorCode.CANCELLED, "취소됨")) == (
        ErrorCode.CANCELLED.value,
        "취소됨",
    )
    assert _safe_query_failure(StorageError("sensitive database path")) == (
        ErrorCode.DB_WRITE_FAILED.value,
        "로컬 조회 기록을 안전하게 저장하지 못했습니다.",
    )
    assert _safe_query_failure(RuntimeError("sensitive runtime detail")) == (
        "UNEXPECTED",
        "예상하지 못한 내부 오류가 발생했습니다. 오류 유형: RuntimeError",
    )


def test_lifecycle_status_distinguishes_uncertain_missing_and_active_changes() -> None:
    assert (
        _lifecycle_status(
            set(),
            miss_count=1,
            close_after_misses=3,
            is_observed=False,
            authoritative=False,
        )
        == "확인 불가 · 이전 관측 유지"
    )
    assert (
        _lifecycle_status(
            set(),
            miss_count=2,
            close_after_misses=3,
            is_observed=False,
            authoritative=True,
        )
        == "MISS 2/3 · 종료 확인 중"
    )
    assert (
        _lifecycle_status(
            set(),
            miss_count=0,
            close_after_misses=3,
            is_observed=True,
            authoritative=True,
        )
        == "활성"
    )
    assert (
        _lifecycle_status(
            {"STARTED", "CONTROLLER_CHANGED", "FLAGS_CHANGED"},
            miss_count=0,
            close_after_misses=3,
            is_observed=True,
            authoritative=True,
        )
        == "활성 · 새 세션 · MD 변경 · 플래그 변경"
    )


def test_fatal_diagnostic_code_and_file_size_display_cover_boundaries() -> None:
    nonfatal = SimpleNamespace(code=ErrorCode.PARSE_PARTIAL)
    fatal = SimpleNamespace(code=ErrorCode.AUTH_FAILED)

    assert _fatal_diagnostic_code(SimpleNamespace(diagnostics=(nonfatal, fatal))) == "AUTH_FAILED"
    assert _fatal_diagnostic_code(SimpleNamespace(diagnostics=(nonfatal,))) is None
    assert _fatal_diagnostic_code(SimpleNamespace()) is None

    assert _display_bytes(-1) == "0 B"
    assert _display_bytes(1023) == "1023 B"
    assert _display_bytes(1024) == "1.0 KiB"
    assert _display_bytes(1024**2) == "1.0 MiB"
    assert _display_bytes(1024**3) == "1.0 GiB"


def test_html_report_export_is_independent_from_csv(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    run_id = store.start_run(QueryRequest("192.0.2.10", "203.0.113.20", 53000, 443))
    store.record_query(
        run_id,
        (
            SessionObservation(
                controller_name="MD-01",
                controller_host="198.51.100.21",
                protocol=6,
                source_ip="192.0.2.10",
                destination_ip="203.0.113.20",
                source_port=53000,
                destination_port=443,
                flags="FC",
            ),
        ),
    )
    store.finish_run(run_id)
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.history_table.selectRow(0)
    destination = tmp_path / "사용자 선택" / "result.html"
    messages: list[tuple[str, str]] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(destination), "HTML 문서 (*.html)"),
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "information",
        lambda _parent, title, message: messages.append((title, str(message))),
    )

    window._export_selected_run_html()

    assert window.export_button.text() == "선택 실행 CSV 내보내기"
    assert window.html_export_button.text() == "선택 실행 HTML 보고서"
    assert destination.is_file()
    assert messages == [("HTML 보고서 완료", str(destination))]
    window.close()


def test_history_export_failure_does_not_display_sensitive_exception_text(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    run_id = store.start_run(QueryRequest("192.0.2.10", "203.0.113.20", 53000, 443))
    store.finish_run(run_id)
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.history_table.selectRow(0)
    sensitive_details = "password=do-not-display C:\\sensitive\\customer.db"
    warnings: list[str] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QFileDialog,
        "getSaveFileName",
        lambda *_args, **_kwargs: (str(tmp_path / "result.csv"), "CSV (*.csv)"),
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        store,
        "export_run_csv",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError(sensitive_details)),
    )
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda _parent, _title, message, *_args: warnings.append(str(message)),
    )

    window._export_selected_run()

    assert warnings == ["CSV 파일을 안전하게 내보내지 못했습니다."]
    assert sensitive_details not in warnings[0]
    window.close()


def test_loading_one_md_disables_unused_blank_rows(qtbot: object, tmp_path: Path) -> None:
    repository = ConfigRepository(tmp_path / "config.json")
    repository.save(
        AppConfig(
            mm_primary=DeviceTarget("MM-1", "192.0.2.1"),
            mm_standby=DeviceTarget("MM-2", "192.0.2.2"),
            managed_devices=(DeviceTarget("MD-1", "198.51.100.21"),),
        )
    )
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    window = MainWindow(repository, store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    assert window.md_table.item(0, 0).checkState() == Qt.CheckState.Checked
    assert all(
        window.md_table.item(row, 0).checkState() == Qt.CheckState.Unchecked for row in range(1, 4)
    )
    assert window._read_config_from_ui().managed_devices == (DeviceTarget("MD-1", "198.51.100.21"),)
    window.close()


def test_full_scan_approval_lists_exact_active_targets(
    qtbot: object,
    monkeypatch: object,
) -> None:
    owner = QWidget()
    qtbot.addWidget(owner)  # type: ignore[attr-defined]
    captured: list[tuple[object, str, str]] = []

    def answer(
        _parent: object,
        title: str,
        message: str,
        _buttons: object,
        _default: object,
    ) -> QMessageBox.StandardButton:
        captured.append((_parent, title, message))
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", answer)  # type: ignore[attr-defined]
    bridge = ApprovalBridge(owner)
    devices = (
        DeviceTarget("MD-A", "198.51.100.21"),
        DeviceTarget("MD-B", "198.51.100.22", 2222),
    )

    assert bridge.approve_full_scan(QueryRequest("192.0.2.1", "203.0.113.1"), devices)
    assert captured[0][0] is owner
    assert captured[0][1] == "MD 2대 전수조회 확인"
    assert "MD-A: 198.51.100.21:22" in captured[0][2]
    assert "MD-B: 198.51.100.22:2222" in captured[0][2]


def test_approval_shutdown_before_queued_dispatch_wakes_worker_without_dialog(
    qtbot: object,
) -> None:
    owner = QWidget()
    qtbot.addWidget(owner)  # type: ignore[attr-defined]
    bridge = ApprovalBridge(owner)
    token = CancellationToken()
    answers: list[bool] = []
    worker = threading.Thread(
        target=lambda: answers.append(
            bridge.approve_host_key(
                DeviceTarget("MD-01", "198.51.100.21"),
                HostKeyInfo("ssh-ed25519", "SHA256:fixture"),
                cancel_token=token,
                generation=7,
            )
        )
    )

    worker.start()
    try:
        deadline = time.monotonic() + 3
        while bridge.pending_count != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert bridge.pending_count == 1
    finally:
        bridge.shutdown()
        worker.join(timeout=3)
    assert not worker.is_alive()
    assert answers == [False]

    qtbot.wait(20)  # type: ignore[attr-defined]
    assert bridge.pending_count == 0
    assert not owner.findChildren(QMessageBox)


def test_approval_cancellation_dismisses_open_dialog_and_wakes_worker(qtbot: object) -> None:
    owner = QWidget()
    qtbot.addWidget(owner)  # type: ignore[attr-defined]
    bridge = ApprovalBridge(owner)
    token = CancellationToken()
    answers: list[bool] = []
    worker = threading.Thread(
        target=lambda: answers.append(
            bridge.approve_full_scan(
                QueryRequest("192.0.2.1", "203.0.113.1"),
                (DeviceTarget("MD-01", "198.51.100.21"),),
                cancel_token=token,
                generation=11,
            )
        )
    )

    worker.start()
    try:
        qtbot.waitUntil(  # type: ignore[attr-defined]
            lambda: bridge.pending_count == 1 and bool(owner.findChildren(QMessageBox)),
            timeout=3000,
        )
        token.cancel()
        qtbot.waitUntil(lambda: not worker.is_alive(), timeout=3000)  # type: ignore[attr-defined]
    finally:
        token.cancel()
        bridge.shutdown()
        worker.join(timeout=3)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not owner.findChildren(QMessageBox),
        timeout=3000,
    )

    assert answers == [False]
    assert bridge.pending_count == 0


class _FailingExecutor(_Executor):
    def __init__(self, failure: Exception) -> None:
        super().__init__()
        self.failure = failure

    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        raise self.failure


class _EmptyStore:
    def list_runs(self, *, limit: int = 100) -> tuple[object, ...]:
        del limit
        return ()


class _ApprovalExecutor(_Executor):
    def __init__(self) -> None:
        super().__init__()
        self.answer: bool | None = None

    def execute(self, *_args: object, **kwargs: object) -> QueryOutcome:
        approval = kwargs["host_key_approval"]
        assert callable(approval)
        self.answer = approval(
            DeviceTarget("MD-01", "198.51.100.21"),
            HostKeyInfo("ssh-ed25519", "SHA256:fixture"),
        )
        return QueryOutcome()


def test_close_drains_open_approval_and_suppresses_late_result(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    executor = _ApprovalExecutor()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        executor,
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)
    messages: list[str] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "information",
        lambda _parent, _title, message, *_args: messages.append(str(message)),
    )

    window._start_query()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window._approval.pending_count == 1 and bool(window.findChildren(QMessageBox)),
        timeout=3000,
    )

    assert not window.close()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3000)  # type: ignore[attr-defined]

    assert executor.answer is False
    assert window._approval.pending_count == 0
    assert window.result_table.rowCount() == 0
    assert window.diagnostics_list.count() == 0
    assert messages == ["진행 중인 SSH 작업을 취소했습니다. 정리 후 다시 종료하십시오."]
    assert window.close()


def test_invalid_input_keeps_input_status_instead_of_stop_status(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Ok,
    )

    window._start_query()

    assert not window._query_running
    assert window.state_label.text() == "입력 확인 필요"
    window.close()


def test_unexpected_query_failure_is_sanitized_and_remains_failed(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    sensitive_details = "password=do-not-display C:\\sensitive\\customer.db"
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,
        _FailingExecutor(RuntimeError(sensitive_details)),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)
    warnings: list[str] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda _parent, _title, message, *_args: warnings.append(str(message)),
    )

    window._start_query()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3000)  # type: ignore[attr-defined]

    diagnostic = window.diagnostics_list.item(window.diagnostics_list.count() - 1).text()
    assert window.state_label.text() == "실패"
    assert "UNEXPECTED" in diagnostic
    assert "RuntimeError" in diagnostic
    assert sensitive_details not in diagnostic
    assert all(sensitive_details not in message for message in warnings)
    window.close()


def test_cancelled_query_failure_remains_stopped_without_warning(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,
        _FailingExecutor(CollectorError(ErrorCode.CANCELLED, "작업이 취소되었습니다.")),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)
    warnings: list[str] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda _parent, _title, message, *_args: warnings.append(str(message)),
    )

    window._start_query()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3000)  # type: ignore[attr-defined]

    assert window.state_label.text() == "중지됨"
    assert warnings == []
    window.close()


class _SlowExecutor(_Executor):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()
        self.call_count = 0

    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        self.call_count += 1
        self.started.set()
        if not self.release.wait(timeout=3):
            raise TimeoutError("slow fixture was not released")
        return super().execute()


class _CountingExecutor(_Executor):
    def __init__(self) -> None:
        super().__init__()
        self.call_count = 0

    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        self.call_count += 1
        return super().execute()


def test_query_worker_lifecycle_soak_leaves_no_owned_task_or_approval(
    qtbot: object,
    tmp_path: Path,
) -> None:
    executor = _CountingExecutor()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        executor,
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    tracemalloc.start()
    baseline_bytes = 0
    retained_bytes = 0
    try:
        for expected_calls in range(1, 501):
            window._start_query()
            qtbot.waitUntil(  # type: ignore[attr-defined]
                lambda: not window._query_running,
                timeout=3000,
            )
            assert executor.call_count == expected_calls
            assert window._current_task is None
            assert window._approval.pending_count == 0
            if expected_calls == 25:
                gc.collect()
                baseline_bytes = tracemalloc.get_traced_memory()[0]
        gc.collect()
        retained_bytes = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()

    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window._thread_pool.activeThreadCount() == 0,
        timeout=3000,
    )
    assert window.result_table.rowCount() == 1
    assert retained_bytes - baseline_bytes <= 16 * 1024 * 1024
    window.close()


def test_user_stop_suppresses_late_success_and_finishes_stopped(
    qtbot: object,
    tmp_path: Path,
) -> None:
    executor = _SlowExecutor()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        executor,
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    window._start_query()
    assert executor.started.wait(timeout=3)
    window._stop_work()
    assert window.state_label.text() == "중지 요청"

    executor.release.set()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3000)  # type: ignore[attr-defined]

    assert window.state_label.text() == "중지됨"
    assert window.result_table.rowCount() == 0
    window.close()


def test_slow_monitor_ignores_heartbeat_and_stale_task_signals(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    executor = _SlowExecutor()
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, executor)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    window._start_monitoring()
    assert executor.started.wait(timeout=3)
    generation = window._task_generation
    assert window._current_task is not None
    assert window._thread_pool.maxThreadCount() == 1

    window._monitor_timer.timeout.emit()
    window._task_succeeded(generation - 1, _Executor().execute())
    window._task_failed(generation - 1, RuntimeError("stale failure"))
    assert executor.call_count == 1
    assert window.result_table.rowCount() == 0
    assert window.diagnostics_list.count() == 0
    assert window.state_label.text() == "조회 중"

    executor.release.set()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3000)  # type: ignore[attr-defined]
    assert window.result_table.rowCount() == 1
    assert window.state_label.text() == "모니터링"
    window._stop_work()
    window.close()
