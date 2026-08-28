from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    DeviceTarget,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.main_window import ApprovalBridge, _counter_delta


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
    del qtbot
    captured: list[tuple[str, str]] = []

    def answer(
        _parent: object,
        title: str,
        message: str,
        _buttons: object,
        _default: object,
    ) -> QMessageBox.StandardButton:
        captured.append((title, message))
        return QMessageBox.StandardButton.Yes

    monkeypatch.setattr(QMessageBox, "question", answer)  # type: ignore[attr-defined]
    bridge = ApprovalBridge()
    devices = (
        DeviceTarget("MD-A", "198.51.100.21"),
        DeviceTarget("MD-B", "198.51.100.22", 2222),
    )

    assert bridge.approve_full_scan(QueryRequest("192.0.2.1", "203.0.113.1"), devices)
    assert captured[0][0] == "MD 2대 전수조회 확인"
    assert "MD-A: 198.51.100.21:22" in captured[0][1]
    assert "MD-B: 198.51.100.22:2222" in captured[0][1]
