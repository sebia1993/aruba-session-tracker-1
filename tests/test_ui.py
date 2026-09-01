from __future__ import annotations

import gc
import os
import subprocess
import sys
import threading
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QFileDialog, QGridLayout, QMessageBox, QWidget

from aruba_session_tracker.collectors.ssh import (
    CancellationToken,
    CollectorError,
    HostKeyInfo,
    PollDeadline,
)
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    DeviceTarget,
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import DeletePreview, SessionStore, StorageError
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.main_window import (
    _OPERATOR_STATES,
    _RAW_FILE_COUNT_WARNING,
    ApprovalBridge,
    _counter_delta,
    _display_bytes,
    _fatal_diagnostic_code,
    _history_status_label,
    _lifecycle_status,
    _optional_port,
    _prepare_display_outcome,
    _safe_query_failure,
    _storage_status_text,
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


def _next_keyboard_focus(widget: QWidget) -> QWidget:
    candidate = widget.nextInFocusChain()
    while candidate is not widget:
        if (
            not widget.isAncestorOf(candidate)
            and candidate.isVisible()
            and candidate.isEnabled()
            and candidate.focusPolicy() != Qt.FocusPolicy.NoFocus
        ):
            return candidate
        candidate = candidate.nextInFocusChain()
    raise AssertionError("keyboard focus chain has no next control")


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

    assert window.result_table.item(0, 1).text() == "TCP (6)"
    assert window.result_table.item(0, 5).toolTip() == (
        "포트 번호 기준 대표 서비스 후보: HTTPS (443)"
    )
    assert window.result_table.item(0, 14).text() == "현재 관측됨"
    assert window.result_table.item(0, 15).text() == "차단, SYN 없음"
    assert "MM-Conductor" in window.context_label.text()
    assert window.password_edit.text() == "session-only"
    window.close()


def test_presentation_tracks_query_direction_and_empty_states(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=3000)  # type: ignore[attr-defined]

    assert window.result_empty_label.isVisible()
    assert not window.history_empty_label.isHidden()
    assert window.history_empty_label.text().startswith("저장된 실행 기록이 없습니다")
    assert not window.export_button.isEnabled()
    assert not window.html_export_button.isEnabled()
    assert not window.delete_button.isEnabled()
    assert not window.delete_all_button.isEnabled()
    assert window.query_direction_label.text() == "양방향 조회"
    assert window.query_direction_label.property("directionRole") == "bidirectional"

    window.raw_diagnostics_toggle.setChecked(True)
    assert window.result_empty_label.isHidden()
    window.tabs.setCurrentWidget(window.settings_page)
    window._display_outcome(
        QueryOutcome(
            observations=(),
            used_mm="MM-Conductor",
            controllers=("MD-01",),
            authoritative=True,
        )
    )
    window.tabs.setCurrentWidget(window.query_page)
    assert window.details.isVisible()
    assert window.result_empty_label.isHidden()
    window.raw_diagnostics_toggle.setChecked(False)
    assert window.result_empty_label.isVisible()

    window.bidirectional_check.setChecked(False)
    assert window.query_direction_label.text() == "입력 방향 조회"
    assert window.query_direction_label.property("directionRole") == "forward"

    _configure_valid_query(window)
    qtbot.mouseClick(window.query_button, Qt.MouseButton.LeftButton)  # type: ignore[attr-defined]
    qtbot.waitUntil(lambda: window.result_table.rowCount() == 1, timeout=3000)  # type: ignore[attr-defined]
    assert not window.result_empty_label.isVisible()

    window._render_history(
        (
            {
                "id": "presentation-run",
                "started_at": "2026-08-31T01:00:00Z",
                "ended_at": "2026-08-31T01:00:05Z",
                "status": "COMPLETED",
                "observation_count": 1,
                "latest_support_code": "AS20",
            },
        ),
        None,
    )
    assert not window.history_empty_label.isVisible()
    assert window.history_table.columnCount() == 6
    assert window.history_table.item(0, 5).text() == "AS20"
    assert "사내 정보 없이" in window.history_table.item(0, 5).toolTip()
    assert window.delete_all_button.isEnabled()
    assert not window.export_button.isEnabled()
    window.history_table.selectRow(0)
    assert window.export_button.isEnabled()
    assert window.html_export_button.isEnabled()
    assert window.delete_button.isEnabled()
    window.history_table.clearSelection()
    assert window._selected_run_id() is None
    assert not window.export_button.isEnabled()
    assert not window.html_export_button.isEnabled()
    assert not window.delete_button.isEnabled()
    assert window.delete_all_button.isEnabled()
    for control in (
        window.tabs,
        window.result_table,
        window.details,
        window.raw_view,
        window.diagnostics_list,
        window.mm_primary_name,
        window.mm_primary_host,
        window.mm_primary_port,
        window.mm_standby_name,
        window.mm_standby_host,
        window.mm_standby_port,
        window.md_table,
        window.save_config_button,
        window.refresh_history_button,
        window.export_button,
        window.html_export_button,
        window.delete_button,
        window.delete_all_button,
        window.history_table,
    ):
        assert control.accessibleName()
    window.close()


def test_counter_delta_is_only_shown_for_monotonic_samples() -> None:
    assert _counter_delta(15, 10) == "+5"
    assert _counter_delta(10, 10) == "+0"
    assert _counter_delta(2, 10) == "-"
    assert _counter_delta(None, 10) == "-"


def test_result_semantic_labels_fall_back_for_out_of_range_legacy_values(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    observation = SessionObservation(
        controller_name="MD-legacy",
        controller_host="198.51.100.21",
        protocol=999,
        source_ip="192.0.2.10",
        destination_ip="203.0.113.20",
        source_port=70_000,
        destination_port=70_001,
    )

    window._append_observation(observation)

    assert window.result_table.item(0, 1).text() == "999"
    assert window.result_table.item(0, 3).toolTip() == ""
    assert window.result_table.item(0, 5).toolTip() == ""
    assert window.result_table.item(0, 14).text() == "현재 관측됨"
    assert "장비 장애" in window.result_table.item(0, 14).toolTip()
    assert window.result_table.item(0, 15).text() == "표시된 특이사항 없음"
    assert "정상 통신을 보장하지" in window.result_table.item(0, 15).toolTip()
    window.close()


def test_operator_state_vocabulary_is_fixed_to_five_plain_states() -> None:
    assert {
        "대기",
        "조회 중",
        "정상",
        "재시도 중",
        "확인 필요",
    } == _OPERATOR_STATES


def test_operator_states_keep_plain_text_and_assign_semantic_visual_roles(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    for state, role in (
        ("대기", "neutral"),
        ("조회 중", "active"),
        ("정상", "success"),
        ("재시도 중", "warning"),
        ("확인 필요", "danger"),
    ):
        window._set_state(state)
        assert window.state_label.text() == state
        assert window.state_label.property("stateRole") == role

    window.close()


def test_history_status_presenter_translates_known_codes_without_guessing_unknowns() -> None:
    assert _history_status_label("COMPLETED") == "완료"
    assert _history_status_label(" partial ") == "일부 결과"
    assert _history_status_label("FAILED") == "실패"
    assert _history_status_label("STOPPED") == "중지"
    assert _history_status_label("INTERRUPTED") == "수집 중단"
    assert _history_status_label("RESTARTED") == "조건 변경 종료"
    assert _history_status_label("CANCELLED") == "취소"
    assert _history_status_label("RUNNING") == "진행 중"
    assert _history_status_label("RECOVERED_CUSTOM") == "RECOVERED_CUSTOM"
    assert _history_status_label("") == "-"


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
    assert _safe_query_failure(
        StorageError("sensitive disk detail", code=ErrorCode.STORAGE_LOW_SPACE)
    ) == (
        ErrorCode.STORAGE_LOW_SPACE.value,
        "저장 공간이 부족합니다. 오래된 기록을 정리한 뒤 다시 시도하십시오.",
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
        == "조회 결과 신뢰 불가 · 이전 관측 유지"
    )
    assert (
        _lifecycle_status(
            set(),
            miss_count=2,
            close_after_misses=3,
            is_observed=False,
            authoritative=True,
        )
        == "이번 조회에서 미관측 (2/3) · 종료 판단 보류"
    )
    assert (
        _lifecycle_status(
            set(),
            miss_count=0,
            close_after_misses=3,
            is_observed=True,
            authoritative=True,
        )
        == "현재 관측됨"
    )
    assert (
        _lifecycle_status(
            {"STARTED", "CONTROLLER_CHANGED", "FLAGS_CHANGED"},
            miss_count=0,
            close_after_misses=3,
            is_observed=True,
            authoritative=True,
        )
        == "현재 관측됨 · 처음 관측 · 관측 MD 변경 · Flags 변경"
    )


def test_display_preparation_keeps_same_flow_from_multiple_controllers_visible() -> None:
    first = SessionObservation(
        controller_name="MD-01",
        controller_host="198.51.100.21",
        protocol=6,
        source_ip="192.0.2.10",
        destination_ip="203.0.113.20",
        source_port=54321,
        destination_port=443,
        packets=10,
        bytes_count=100,
    )
    second = SessionObservation(
        controller_name="MD-02",
        controller_host="198.51.100.22",
        protocol=6,
        source_ip="192.0.2.10",
        destination_ip="203.0.113.20",
        source_port=54321,
        destination_port=443,
        packets=20,
        bytes_count=200,
    )
    prepared = _prepare_display_outcome(
        SimpleNamespace(
            observations=(second, first),
            active_sessions=(SimpleNamespace(observation=first, miss_count=0),),
            events=(),
            authoritative=True,
        ),
        previous_counters={
            first.session_key: (5, 50),
            second.session_key: (15, 150),
        },
        close_after_misses=3,
        monitoring=True,
    )

    assert [row.observation.controller_name for row in prepared.visible_rows] == [
        "MD-01",
        "MD-02",
    ]
    assert [(row.packet_delta, row.byte_delta) for row in prepared.visible_rows] == [
        ("+5", "+50"),
        ("+5", "+50"),
    ]
    assert {row.lifecycle_status for row in prepared.visible_rows} == {
        "현재 관측됨 · 여러 MD에서 동시 관측"
    }
    assert prepared.total_rows == 2
    assert prepared.next_counters == {
        first.session_key: (10, 100),
        second.session_key: (20, 200),
    }


def test_fatal_diagnostic_code_and_file_size_display_cover_boundaries() -> None:
    nonfatal = SimpleNamespace(code=ErrorCode.PARSE_PARTIAL)
    fatal = SimpleNamespace(code=ErrorCode.AUTH_FAILED)
    command_policy = SimpleNamespace(code=ErrorCode.COMMAND_VARIANT_UNVERIFIED)
    storage = SimpleNamespace(code=ErrorCode.STORAGE_LOW_SPACE)
    transient_mm = SimpleNamespace(
        code=ErrorCode.MM_UNREACHABLE,
        transient=True,
        recovered=False,
    )

    assert _fatal_diagnostic_code(SimpleNamespace(diagnostics=(nonfatal, fatal))) == "AUTH_FAILED"
    assert (
        _fatal_diagnostic_code(SimpleNamespace(diagnostics=(command_policy,)))
        == "COMMAND_VARIANT_UNVERIFIED"
    )
    for safety_code in (
        ErrorCode.CURRENT_SWITCH_AMBIGUOUS,
        ErrorCode.CURRENT_SWITCH_UNMAPPED,
        ErrorCode.OUTPUT_LIMIT_EXCEEDED,
    ):
        assert (
            _fatal_diagnostic_code(
                SimpleNamespace(diagnostics=(SimpleNamespace(code=safety_code),))
            )
            == safety_code.value
        )
    assert _fatal_diagnostic_code(SimpleNamespace(diagnostics=(storage,))) == "STORAGE_LOW_SPACE"
    assert _fatal_diagnostic_code(SimpleNamespace(diagnostics=(transient_mm,))) is None
    assert _fatal_diagnostic_code(SimpleNamespace(diagnostics=(nonfatal,))) is None
    assert _fatal_diagnostic_code(SimpleNamespace()) is None

    assert _display_bytes(-1) == "0 B"
    assert _display_bytes(1023) == "1023 B"
    assert _display_bytes(1024) == "1.0 KiB"
    assert _display_bytes(1024**2) == "1.0 MiB"
    assert _display_bytes(1024**3) == "1.0 GiB"


def test_storage_status_text_reports_usage_and_advises_at_raw_file_threshold() -> None:
    below_threshold = SimpleNamespace(
        raw_file_count=_RAW_FILE_COUNT_WARNING - 1,
        raw_bytes=2 * 1024**3,
        total_managed_bytes=3 * 1024**3,
        free_bytes=20 * 1024**3,
    )
    at_threshold = SimpleNamespace(
        raw_file_count=_RAW_FILE_COUNT_WARNING,
        raw_bytes=2 * 1024**3,
        total_managed_bytes=3 * 1024**3,
        free_bytes=20 * 1024**3,
    )

    normal = _storage_status_text(below_threshold)
    advisory = _storage_status_text(at_threshold)

    assert "Raw 파일 99,999개" in normal
    assert "Raw 용량 2.0 GiB" in normal
    assert "전체 관리 데이터 3.0 GiB" in normal
    assert "여유 공간 20.0 GiB" in normal
    assert "주의:" not in normal
    assert "Raw 파일 100,000개" in advisory
    assert "주의:" in advisory
    assert "자동 삭제되지 않으므로" in advisory


def test_history_tab_shows_read_only_storage_status_without_changing_default_tab(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    run_id = store.start_run(QueryRequest("192.0.2.10", "203.0.113.20"))
    store.record_query(
        run_id,
        (),
        raw_text="raw-status",
        controller_name="MD-01",
        captured_at=datetime(2026, 8, 31, 1, 0, tzinfo=UTC),
    )
    store.finish_run(run_id)

    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            not window._history_task_running
            and window.storage_status_label.text() != "저장소 현황을 확인하는 중입니다."
        ),
        timeout=5000,
    )

    status = window.storage_status_label.text()
    assert window.tabs.currentWidget() is window.query_page
    assert "Raw 파일 1개" in status
    assert "Raw 용량 10 B" in status
    assert "전체 관리 데이터" in status
    assert "여유 공간" in status
    assert "주의:" not in status
    window.close()


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
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and window.history_table.rowCount() == 1,
        timeout=5000,
    )
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
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._storage_task_running and destination.is_file(),
        timeout=5000,
    )

    assert window.export_button.text() == "CSV 내보내기"
    assert window.html_export_button.text() == "HTML 보고서"
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
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and window.history_table.rowCount() == 1,
        timeout=5000,
    )
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
    qtbot.waitUntil(lambda: not window._storage_task_running, timeout=5000)  # type: ignore[attr-defined]

    assert warnings == ["CSV 파일을 안전하게 내보내지 못했습니다.\n\n전달 코드: AS74"]
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


def test_approval_deadline_dismisses_open_dialog_and_wakes_worker(qtbot: object) -> None:
    owner = QWidget()
    qtbot.addWidget(owner)  # type: ignore[attr-defined]
    bridge = ApprovalBridge(owner)
    answers: list[bool] = []
    worker = threading.Thread(
        target=lambda: answers.append(
            bridge.approve_full_scan(
                QueryRequest("192.0.2.1", "203.0.113.1"),
                (DeviceTarget("MD-01", "198.51.100.21"),),
                deadline=PollDeadline.after(1.0),
                generation=12,
            )
        )
    )

    worker.start()
    try:
        qtbot.waitUntil(  # type: ignore[attr-defined]
            lambda: bridge.pending_count == 1 and bool(owner.findChildren(QMessageBox)),
            timeout=3000,
        )
        qtbot.waitUntil(lambda: not worker.is_alive(), timeout=3000)  # type: ignore[attr-defined]
    finally:
        bridge.shutdown()
        worker.join(timeout=3)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not owner.findChildren(QMessageBox),
        timeout=3000,
    )

    assert answers == [False]
    assert bridge.pending_count == 0


def test_approval_deadline_closes_direct_modal_request(qtbot: object) -> None:
    owner = QWidget()
    qtbot.addWidget(owner)  # type: ignore[attr-defined]
    bridge = ApprovalBridge(owner)
    started_at = time.monotonic()

    answer = bridge.approve_host_key(
        DeviceTarget("MD-01", "198.51.100.21"),
        HostKeyInfo("ssh-ed25519", "SHA256:fixture"),
        deadline=PollDeadline.after(0.1),
        generation=13,
    )

    assert answer is False
    assert time.monotonic() - started_at < 1.0
    assert bridge.pending_count == 0
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not owner.findChildren(QMessageBox),
        timeout=3000,
    )


class _FailingExecutor(_Executor):
    def __init__(self, failure: Exception) -> None:
        super().__init__()
        self.failure = failure

    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        raise self.failure


class _EmptyStore:
    @property
    def pending_external_recovery_count(self) -> int:
        return 0

    def retry_pending_external_recoveries(self) -> int:
        return 0

    def list_runs(self, *, limit: int = 100) -> tuple[object, ...]:
        del limit
        return ()


class _StorageHealthStore(_EmptyStore):
    def __init__(
        self,
        *,
        warning: bool = False,
        hard_stop: bool = False,
        capacity_failure: StorageError | None = None,
        raw_file_count: int = 0,
        raw_bytes: int = 0,
        total_managed_bytes: int = 0,
        free_bytes: int = 10 * 1024**3,
    ) -> None:
        self.warning = warning
        self.hard_stop = hard_stop
        self.capacity_failure = capacity_failure
        self.raw_file_count = raw_file_count
        self.raw_bytes = raw_bytes
        self.total_managed_bytes = total_managed_bytes
        self.free_bytes = free_bytes
        self.capacity_calls = 0
        self.health_calls = 0

    def ensure_query_capacity(self) -> None:
        self.capacity_calls += 1
        if self.capacity_failure is not None:
            raise self.capacity_failure

    def storage_health(self) -> object:
        self.health_calls += 1
        return SimpleNamespace(
            warning=self.warning,
            hard_stop=self.hard_stop,
            raw_file_count=self.raw_file_count,
            raw_bytes=self.raw_bytes,
            total_managed_bytes=self.total_managed_bytes,
            free_bytes=self.free_bytes,
        )


def _delete_preview_fixture() -> DeletePreview:
    return DeletePreview(
        preview_id="preview-1",
        confirmation_token="-".join(("confirmation", "fixture")),
        run_ids=("run-1",),
        database_rows=3,
        raw_files=1,
        export_files=1,
        total_file_bytes=1024,
        expires_at=datetime.now(UTC),
        summary="fixture preview",
    )


class _DelayedPreviewStore(_EmptyStore):
    def __init__(self, *, discard_fails: bool = False) -> None:
        self.preview = _delete_preview_fixture()
        self.discard_fails = discard_fails
        self.preview_started = threading.Event()
        self.preview_release = threading.Event()
        self.preview_threads: list[int] = []
        self.discard_threads: list[int] = []
        self.discarded: list[DeletePreview] = []

    def preview_delete(
        self,
        _run_id: str | None = None,
        **_kwargs: object,
    ) -> DeletePreview:
        self.preview_threads.append(threading.get_ident())
        self.preview_started.set()
        if not self.preview_release.wait(timeout=3):
            raise TimeoutError("delayed preview fixture was not released")
        return self.preview

    def discard_delete_preview(self, preview: DeletePreview) -> bool:
        self.discard_threads.append(threading.get_ident())
        self.discarded.append(preview)
        if self.discard_fails:
            raise StorageError("sanitized discard fixture")
        return preview == self.preview


class _CommitFailureStore(_EmptyStore):
    def __init__(self) -> None:
        self.preview = _delete_preview_fixture()
        self.delete_calls = 0
        self.discarded: list[DeletePreview] = []

    def preview_delete(
        self,
        _run_id: str | None = None,
        **_kwargs: object,
    ) -> DeletePreview:
        return self.preview

    def delete(
        self,
        preview: DeletePreview,
        *,
        confirmation_token: str,
        cancel_check: object | None = None,
        progress: object | None = None,
    ) -> object:
        assert preview == self.preview
        assert confirmation_token == self.preview.confirmation_token
        assert callable(cancel_check)
        assert callable(progress)
        self.delete_calls += 1
        raise StorageError("sanitized commit fixture")

    def discard_delete_preview(self, preview: DeletePreview) -> bool:
        self.discarded.append(preview)
        return preview == self.preview


class _CancelableDeleteStore(_EmptyStore):
    def __init__(self) -> None:
        self.preview = _delete_preview_fixture()
        self.delete_started = threading.Event()
        self.delete_cancelled = threading.Event()
        self.progress_events: list[tuple[str, int, int | None]] = []
        self.discarded: list[DeletePreview] = []

    def preview_delete(
        self,
        _run_id: str | None = None,
        **_kwargs: object,
    ) -> DeletePreview:
        return self.preview

    def delete(
        self,
        preview: DeletePreview,
        *,
        confirmation_token: str,
        cancel_check: object | None = None,
        progress: object | None = None,
    ) -> object:
        assert preview == self.preview
        assert confirmation_token == self.preview.confirmation_token
        assert callable(cancel_check)
        assert callable(progress)
        progress("SCAN", 0, None)
        self.progress_events.append(("SCAN", 0, None))
        self.delete_started.set()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if cancel_check():
                self.delete_cancelled.set()
                raise StorageError("cancelled delete fixture", code=ErrorCode.CANCELLED)
            time.sleep(0.005)
        raise TimeoutError("delete cancellation was not observed")

    def discard_delete_preview(self, preview: DeletePreview) -> bool:
        self.discarded.append(preview)
        return preview == self.preview


class _DelayedHistoryStore(_EmptyStore):
    def __init__(self, *, fail: bool) -> None:
        self.fail = fail
        self.started = threading.Event()
        self.release = threading.Event()
        self.thread_ids: list[int] = []

    def list_runs(self, *, limit: int = 100) -> tuple[object, ...]:
        del limit
        self.thread_ids.append(threading.get_ident())
        self.started.set()
        if not self.release.wait(timeout=3):
            raise TimeoutError("delayed history fixture was not released")
        if self.fail:
            raise StorageError("sanitized history fixture")
        return (
            {
                "id": "run-after-close",
                "started_at": "2026-08-29T00:00:00+00:00",
                "ended_at": None,
                "status": "RUNNING",
                "observation_count": 0,
            },
        )


def test_history_empty_state_distinguishes_loading_from_read_failure(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = _DelayedHistoryStore(fail=True)
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    assert store.started.wait(timeout=3)
    assert window.history_empty_label.text() == "기록을 불러오는 중입니다."
    assert not window.history_empty_label.isHidden()

    store.release.set()
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=5000)  # type: ignore[attr-defined]

    assert window.history_table.rowCount() == 0
    assert window.history_empty_label.text().startswith("기록을 확인하지 못했습니다")
    assert not window.history_empty_label.isHidden()
    assert not window.export_button.isEnabled()
    assert not window.delete_all_button.isEnabled()
    window.close()


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
    window.show()
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
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._query_running and not window.isVisible(),
        timeout=3000,
    )

    assert executor.answer is False
    assert window._approval.pending_count == 0
    assert window.result_table.rowCount() == 0
    assert window.diagnostics_list.count() == 0
    assert messages == []


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
    assert window.state_label.text() == "확인 필요"
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
    assert window.state_label.text() == "확인 필요"
    assert "UNEXPECTED" in diagnostic
    assert "AS72" in diagnostic
    assert "RuntimeError" in diagnostic
    assert sensitive_details not in diagnostic
    assert all(sensitive_details not in message for message in warnings)
    window.close()


def test_md_login_failure_shows_same_short_code_in_diagnostics_and_dialog(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    warnings: list[str] = []
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda _parent, _title, message, *_args: warnings.append(str(message)),
    )

    window._display_outcome(
        QueryOutcome(
            diagnostics=(
                DiagnosticEvent(
                    stage="MD_LOGIN",
                    code=ErrorCode.AUTH_FAILED,
                    message="등록 MD 1번에서 SSH 인증에 실패했습니다.",
                ),
            ),
        )
    )

    assert window.diagnostics_list.item(0).text().startswith("[AS20] [MD_LOGIN] AUTH_FAILED:")
    assert warnings == ["인증 확인: 진단 이벤트를 확인하십시오.\n\n전달 코드: AS20"]
    assert "AS20" in window.statusBar().currentMessage()
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

    assert window.state_label.text() == "대기"
    assert window.result_empty_label.text().startswith("조회가 취소되었습니다")
    assert warnings == []
    window.close()


def test_query_screen_defaults_to_primary_monitoring_and_progressive_details(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()

    assert window.setup_guide.isVisible()
    assert window.monitor_button.isDefault()
    assert window.query_group.title() == "조회할 세션 흐름 · IP 하나 이상 입력"
    assert window.connection_group.title() == "로그인 정보 · 이번 실행에만 사용"
    assert window.monitor_button.text() == "지속 모니터링 시작"
    assert window.query_button.text() == "현재 조회"
    assert window.advanced_toggle_button.text() == "고급 조건 보기"
    assert window.advanced_panel.title() == "고급 조건"
    assert window.raw_diagnostics_toggle.text() == "상세 정보 보기"
    assert not window.advanced_panel.isVisible()
    assert not window.details.isVisible()
    assert all(window.result_table.isColumnHidden(column) for column in (*range(5, 12), 13))
    assert [
        window.result_table.horizontalHeaderItem(column).text()
        for column in (0, 1, 2, 3, 4, 12, 14, 15)
    ] == [
        "장비",
        "프로토콜",
        "출발지 IP",
        "출발지 포트",
        "목적지 IP",
        "마지막 확인 시각",
        "관측 상태",
        "세션 특이사항",
    ]
    assert window.result_table.horizontalHeaderItem(13).text() == "장비 Flags"
    assert "장비 전체 상태" in window.result_table.horizontalHeaderItem(14).toolTip()
    assert "정상 통신을 보장하지" in window.result_table.horizontalHeaderItem(15).toolTip()

    window.advanced_toggle_button.setChecked(True)
    window.detail_columns_toggle.setChecked(True)
    window.raw_diagnostics_toggle.setChecked(True)
    assert window.advanced_panel.isVisible()
    assert window.details.isVisible()
    assert window.advanced_toggle_button.text() == "고급 조건 숨기기"
    assert window.raw_diagnostics_toggle.text() == "상세 정보 숨기기"
    assert all(not window.result_table.isColumnHidden(column) for column in (*range(5, 12), 13))
    advanced_layout = window.advanced_panel.layout()
    assert isinstance(advanced_layout, QGridLayout)
    for control in (
        window.enable_edit,
        window.source_port_edit,
        window.destination_port_edit,
        window.bidirectional_check,
    ):
        row, _column, _row_span, _column_span = advanced_layout.getItemPosition(
            advanced_layout.indexOf(control)
        )
        assert row == 0

    _configure_valid_query(window)
    window._update_setup_guide()
    assert not window.setup_guide.isVisible()
    window.close()


def test_query_progressive_controls_are_keyboard_and_accessibility_ready(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()

    controls = (
        window.open_settings_button,
        window.advanced_toggle_button,
        window.detail_columns_toggle,
        window.raw_diagnostics_toggle,
    )
    assert all(control.accessibleName() for control in controls)
    assert all(control.accessibleDescription() for control in controls)
    assert window.source_ip_edit.accessibleName() == "출발지 IP"
    assert window.destination_ip_edit.accessibleName() == "목적지 IP"
    assert "하나 이상" in window.source_ip_edit.accessibleDescription()
    assert "하나 이상" in window.destination_ip_edit.accessibleDescription()
    assert window.source_port_edit.accessibleName() == "출발지 포트"
    assert window.destination_port_edit.accessibleName() == "목적지 포트"
    assert "Source" not in window.bidirectional_check.accessibleDescription()
    assert "DPort" not in window.detail_columns_toggle.accessibleDescription()

    assert _next_keyboard_focus(window.source_ip_edit) is window.destination_ip_edit
    assert _next_keyboard_focus(window.destination_ip_edit) is window.username_edit
    assert _next_keyboard_focus(window.username_edit) is window.password_edit
    assert _next_keyboard_focus(window.password_edit) is window.advanced_toggle_button

    qtbot.keyClick(window.advanced_toggle_button, Qt.Key.Key_Space)  # type: ignore[attr-defined]
    assert window.advanced_toggle_button.isChecked()
    assert window.advanced_panel.isVisible()
    assert _next_keyboard_focus(window.advanced_toggle_button) is window.enable_edit
    qtbot.keyClick(window.detail_columns_toggle, Qt.Key.Key_Space)  # type: ignore[attr-defined]
    assert window.detail_columns_toggle.isChecked()
    assert all(not window.result_table.isColumnHidden(column) for column in (*range(5, 12), 13))
    qtbot.keyClick(window.raw_diagnostics_toggle, Qt.Key.Key_Space)  # type: ignore[attr-defined]
    assert window.raw_diagnostics_toggle.isChecked()
    assert window.details.isVisible()
    window.close()


def test_query_port_validation_uses_the_same_korean_labels_as_the_screen(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    window.source_port_edit.setText("invalid")
    with pytest.raises(ValueError, match="출발지 포트"):
        window._read_query()

    window.source_port_edit.clear()
    window.destination_port_edit.setText("65536")
    with pytest.raises(ValueError, match="목적지 포트"):
        window._read_query()

    window.close()


def test_query_accepts_either_ip_and_rejects_both_blank(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    window.destination_ip_edit.clear()
    _config, source_only, _credentials = window._read_query()
    assert source_only.source_ip == "192.0.2.101"
    assert source_only.destination_ip == ""

    window.source_ip_edit.clear()
    window.destination_ip_edit.setText("203.0.113.50")
    _config, destination_only, _credentials = window._read_query()
    assert destination_only.source_ip == ""
    assert destination_only.destination_ip == "203.0.113.50"

    window.destination_ip_edit.clear()
    with pytest.raises(ValueError, match="하나 이상"):
        window._read_query()

    window.close()


@pytest.mark.parametrize("scale_factor", ["1", "1.25", "1.5"])
def test_query_layout_smoke_at_supported_scale_in_isolated_process(
    tmp_path: Path,
    scale_factor: str,
) -> None:
    fixture_root = tmp_path / "한글 UI 경로" / scale_factor.replace(".", "_")
    script = r"""
import sys
import time
from pathlib import Path

from PySide6.QtWidgets import QApplication

from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import AppConfig, DeviceTarget
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.theme import apply_main_window_theme


class Executor:
    def execute(self, *_args, **_kwargs):
        return QueryOutcome()

    def stop_monitor(self):
        return None


app = QApplication([])
root = Path(sys.argv[1])
store = SessionStore(root / "세션.db", root / "원본", root / "내보내기")
store.initialize()
repository = ConfigRepository(root / "설정.json")
repository.save(
    AppConfig(
        mm_primary=DeviceTarget("MM-Primary", "192.0.2.10"),
        mm_standby=DeviceTarget("MM-Standby", "192.0.2.11"),
        managed_devices=(DeviceTarget("MD-01", "198.51.100.21"),),
    )
)
window = MainWindow(repository, store, Executor())
apply_main_window_theme(window)
window.resize(window.minimumSize())
window.show()
deadline = time.monotonic() + 3
while window._history_task_running and time.monotonic() < deadline:
    app.processEvents()
    time.sleep(0.01)
app.processEvents()
assert not window._history_task_running
assert window.width() >= window.minimumWidth()
assert window.height() >= window.minimumHeight()
assert window.monitor_button.isVisible()
assert window.query_button.isVisible()
assert window.result_table.isVisible()
assert window.monitor_button.geometry().width() > 0
assert window.result_table.viewport().geometry().width() > 100
assert window.monitor_button.accessibleName()
assert window.advanced_toggle_button.accessibleDescription()
assert window.advanced_panel.isHidden()
assert window.details.isHidden()
assert all(window.result_table.isColumnHidden(column) for column in (*range(5, 12), 13))
window.advanced_toggle_button.setChecked(True)
window.raw_diagnostics_toggle.setChecked(True)
app.processEvents()
assert window.advanced_panel.isVisible()
assert window.details.isVisible()
assert window.advanced_panel.height() >= window.advanced_panel.sizeHint().height()
for control in (
    window.enable_edit,
    window.source_port_edit,
    window.destination_port_edit,
    window.bidirectional_check,
):
    assert control.isVisible()
    assert control.geometry().height() > 0
    assert window.advanced_panel.rect().contains(control.geometry().topLeft())
    assert window.advanced_panel.rect().contains(control.geometry().bottomRight())
assert window.result_table.viewport().geometry().height() >= 40
assert window.details.width() >= 300
window.close()
app.processEvents()
"""
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_SCALE_FACTOR"] = scale_factor
    completed = subprocess.run(  # noqa: S603 - fixed interpreter and static smoke script.
        [sys.executable, "-c", script, str(fixture_root)],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_high_contrast_palette_and_korean_storage_path_keep_controls_visible(
    qtbot: object,
    tmp_path: Path,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    original_palette = application.palette()
    palette = QPalette(original_palette)
    palette.setColor(QPalette.ColorRole.Window, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#ffff00"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))
    application.setPalette(palette)
    fixture_root = tmp_path / "한글 경로" / "세션 기록"
    store = SessionStore(
        fixture_root / "세션.db",
        fixture_root / "원본",
        fixture_root / "내보내기",
    )
    store.initialize()
    window = MainWindow(
        ConfigRepository(fixture_root / "설정.json"),
        store,
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    try:
        window.show()
        qtbot.waitUntil(lambda: not window._history_task_running, timeout=3000)  # type: ignore[attr-defined]
        controls = (
            window.open_settings_button,
            window.username_edit,
            window.monitor_button,
            window.query_button,
            window.detail_columns_toggle,
            window.raw_diagnostics_toggle,
        )
        assert all(control.isVisible() for control in controls)
        assert all(control.sizeHint().width() > 0 for control in controls)
        assert window.monitor_button.text() == "지속 모니터링 시작"
        assert window.state_label.text() == "대기"
        line_palette = window.username_edit.palette()
        assert line_palette.color(QPalette.ColorRole.Base) != line_palette.color(
            QPalette.ColorRole.Text
        )
    finally:
        window.close()
        application.setPalette(original_palette)


def test_result_rendering_caps_visible_rows_without_dropping_outcome_count(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    observations = tuple(
        SessionObservation(
            controller_name="MD-01",
            controller_host="198.51.100.21",
            protocol=6,
            source_ip="192.0.2.10",
            destination_ip="203.0.113.20",
            source_port=10_000 + index,
            destination_port=443,
            raw_line=f"fixture row {index}",
        )
        for index in range(2_005)
    )

    window._display_outcome(
        SimpleNamespace(
            observations=observations,
            active_sessions=(),
            events=(),
            diagnostics=(),
            controllers=("MD-01",),
            used_mm="MM-01",
            authoritative=True,
            cancelled=False,
        )
    )

    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window.result_table.rowCount() == 2_000,
        timeout=5_000,
    )
    assert window.result_table.rowCount() == 2_000
    assert "화면 표시: 2000/2005" in window.context_label.text()
    assert "DISPLAY_LIMIT" in window.diagnostics_list.item(0).text()
    raw_role = int(Qt.ItemDataRole.UserRole)
    assert window.result_table.item(0, 0).data(raw_role)
    assert window.result_table.item(0, 1).data(raw_role) is None
    assert window._history_dirty
    window.close()


class _CountingHistoryStore(_EmptyStore):
    def __init__(self) -> None:
        self.list_calls = 0

    def list_runs(self, *, limit: int = 100) -> tuple[object, ...]:
        del limit
        self.list_calls += 1
        return ()


class _PendingRecoveryStore(_EmptyStore):
    def __init__(self) -> None:
        self.pending = 2
        self.retry_calls = 0
        self.retry_threads: list[int] = []

    @property
    def pending_external_recovery_count(self) -> int:
        return self.pending

    def retry_pending_external_recoveries(self) -> int:
        self.retry_calls += 1
        self.retry_threads.append(threading.get_ident())
        self.pending = 1
        return self.pending


def test_history_refresh_is_dirty_driven_instead_of_running_after_every_poll(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = _CountingHistoryStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and store.list_calls == 1,
        timeout=3000,
    )

    window._display_outcome(_Executor().execute())
    assert store.list_calls == 1
    assert window._history_dirty

    window.tabs.setCurrentWidget(window.history_page)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and store.list_calls == 2,
        timeout=3000,
    )
    assert not window._history_dirty
    window.close()


def test_history_refresh_retries_external_recovery_off_gui_thread_and_warns(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = _PendingRecoveryStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and store.retry_calls == 1,
        timeout=3000,
    )

    assert store.retry_threads
    assert all(thread_id != threading.get_ident() for thread_id in store.retry_threads)
    assert "외부 보고서 복구 1건 대기 중" in window.statusBar().currentMessage()
    assert (
        "외부 저장 위치를 다시 사용할 수 있게 한 뒤 새로 고침을 누르십시오."
        in window.statusBar().currentMessage()
    )
    window.close()


def test_cancelled_delete_preview_is_discarded_in_background(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    run_id = store.start_run(QueryRequest("192.0.2.10", "203.0.113.20"))
    store.finish_run(run_id)
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and window.history_table.rowCount() == 1,
        timeout=5000,
    )
    window.history_table.selectRow(0)
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.No,
    )

    window._delete_history(all_runs=False)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._storage_task_running and not store._pending_deletions,
        timeout=5000,
    )

    assert len(store.list_runs()) == 1
    window.close()


def test_close_waits_for_delayed_preview_and_discard_failure_without_stranding(
    qtbot: object,
    tmp_path: Path,
) -> None:
    store = _DelayedPreviewStore(discard_fails=True)
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=3000)  # type: ignore[attr-defined]

    window._delete_history(all_runs=True)
    assert store.preview_started.wait(timeout=3)
    assert not window.close()
    store.preview_release.set()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window.isVisible() and not window._storage_task_running,
        timeout=5000,
    )

    assert store.discarded == [store.preview]
    assert store.preview_threads
    assert store.discard_threads
    assert all(thread_id != threading.get_ident() for thread_id in store.discard_threads)
    assert window._pending_preview_discards == []


def test_delete_commit_failure_asynchronously_discards_exact_preview(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = _CommitFailureStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=3000)  # type: ignore[attr-defined]
    warnings: list[str] = []

    def answer_warning(
        _parent: object,
        title: str,
        message: str,
        *_args: object,
    ) -> QMessageBox.StandardButton:
        if title == "기록 삭제 확인":
            return QMessageBox.StandardButton.Yes
        warnings.append(str(message))
        return QMessageBox.StandardButton.Ok

    monkeypatch.setattr(QMessageBox, "warning", answer_warning)  # type: ignore[attr-defined]

    window._delete_history(all_runs=True)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._storage_task_running and bool(store.discarded),
        timeout=5000,
    )

    assert store.delete_calls == 1
    assert store.discarded == [store.preview]
    assert window._pending_preview_discards == []
    assert warnings == ["확인된 기록을 안전하게 삭제하지 못했습니다.\n\n전달 코드: AS77"]
    window.close()


def test_close_cancels_delete_commit_through_storage_callbacks(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = _CancelableDeleteStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=3000)  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )

    window._delete_history(all_runs=True)
    qtbot.waitUntil(store.delete_started.is_set, timeout=3000)  # type: ignore[attr-defined]
    assert not window.close()
    qtbot.waitUntil(store.delete_cancelled.is_set, timeout=3000)  # type: ignore[attr-defined]
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window.isVisible() and not window._storage_task_running,
        timeout=5000,
    )

    assert store.progress_events == [("SCAN", 0, None)]
    assert store.discarded == [store.preview]
    assert window.clean_shutdown_completed is True


def test_confirmation_start_failure_queues_exact_preview_cleanup(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = _CommitFailureStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=3000)  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        QMessageBox,
        "warning",
        lambda *_args, **_kwargs: QMessageBox.StandardButton.Yes,
    )
    window._closing_requested = True

    window._confirm_delete_preview(store.preview)
    qtbot.waitUntil(lambda: not window._storage_task_running, timeout=5000)  # type: ignore[attr-defined]

    assert store.delete_calls == 0
    assert store.discarded == [store.preview]
    assert window._pending_preview_discards == []


@pytest.mark.parametrize("fail", [False, True], ids=("success", "failure"))
def test_close_waits_for_background_history_result_and_skips_late_render(
    qtbot: object,
    tmp_path: Path,
    fail: bool,
) -> None:
    store = _DelayedHistoryStore(fail=fail)
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    assert store.started.wait(timeout=3)
    assert not window.close()

    store.release.set()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running and not window.isVisible(),
        timeout=5000,
    )

    assert store.thread_ids
    assert all(thread_id != threading.get_ident() for thread_id in store.thread_ids)
    assert window.history_table.rowCount() == 0


def test_transient_monitor_failure_uses_retry_delay_without_becoming_fatal(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _Executor(),
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window._monitoring = True
    diagnostic = SimpleNamespace(
        code=ErrorCode.MM_UNREACHABLE,
        stage="MM_QUERY",
        message="sanitized transient fixture",
        transient=True,
        recovered=False,
    )
    outcome = SimpleNamespace(
        observations=(),
        active_sessions=(),
        events=(),
        diagnostics=(diagnostic,),
        controllers=(),
        used_mm=None,
        authoritative=False,
        cancelled=False,
        consecutive_transient_failures=3,
        retry_after_seconds=20,
    )

    window._display_outcome(outcome)

    assert _fatal_diagnostic_code(outcome) is None
    assert window.state_label.text() == "재시도 중"
    assert window._next_monitor_delay_seconds == 20
    window._monitoring = False
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


def test_monitor_rechecks_storage_health_on_a_bounded_interval(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _StorageHealthStore(
        warning=True,
        raw_file_count=_RAW_FILE_COUNT_WARNING,
        raw_bytes=2 * 1024**3,
        total_managed_bytes=3 * 1024**3,
        free_bytes=4 * 1024**3,
    )
    executor = _CountingExecutor()
    popup_warnings: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda _parent, _title, message, *_args: popup_warnings.append(str(message)),
    )
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        executor,
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    window._start_monitoring()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: executor.call_count == 1 and not window._query_running,
        timeout=3000,
    )
    window._monitor_timer.stop()
    assert store.capacity_calls == 1
    assert store.health_calls == 1
    assert "저장 공간이 부족" in window.statusBar().currentMessage()
    assert "Raw 파일 100,000개" in window.storage_status_label.text()
    assert "주의:" in window.storage_status_label.text()
    assert popup_warnings == []

    window._start_query()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: executor.call_count == 2 and not window._query_running,
        timeout=3000,
    )
    window._monitor_timer.stop()
    assert store.capacity_calls == 2
    assert store.health_calls == 1

    window._next_storage_health_check_at = 0.0
    window._start_query()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: executor.call_count == 3 and not window._query_running,
        timeout=3000,
    )
    window._monitor_timer.stop()
    assert store.capacity_calls == 3
    assert store.health_calls == 2

    window._stop_work()
    window.close()


def test_storage_hard_stop_blocks_query_before_executor(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    store = _StorageHealthStore(
        capacity_failure=StorageError(
            "sensitive capacity detail",
            code=ErrorCode.STORAGE_LOW_SPACE,
        )
    )
    executor = _CountingExecutor()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        executor,
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

    assert store.capacity_calls == 1
    assert store.health_calls == 0
    assert executor.call_count == 0
    assert "STORAGE_LOW_SPACE" in window.diagnostics_list.item(0).text()
    assert warnings == [
        "STORAGE_LOW_SPACE: 저장 공간이 부족합니다. 오래된 기록을 정리한 뒤 다시 시도하십시오."
        "\n\n전달 코드: AS71"
    ]
    window.close()


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
        lambda: (
            not any(
                thread.name.startswith("aruba-session-query-") for thread in threading.enumerate()
            )
        ),
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
    assert window.state_label.text() == "조회 중"

    executor.release.set()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3000)  # type: ignore[attr-defined]

    assert window.state_label.text() == "대기"
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
    assert (
        sum(thread.name.startswith("aruba-session-query-") for thread in threading.enumerate()) == 1
    )

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
    assert window.state_label.text() == "정상"
    window._stop_work()
    window.close()
