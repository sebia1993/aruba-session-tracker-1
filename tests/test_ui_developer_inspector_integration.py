from __future__ import annotations

from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QTableWidgetItem

from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.main import _send_plain_f12, main
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.ui import DeveloperInspectorController, MainWindow

EXPECTED_UI_IDS = {
    "MAIN-WINDOW",
    "MAIN-STATUS-BAR",
    "MAIN-TABS",
    "MAIN-TAB-BAR",
    "MAIN-QUERY-VIEW",
    "MAIN-SETTINGS-VIEW",
    "MAIN-HISTORY-VIEW",
    "MAIN-QUERY-CREDENTIALS-GROUP",
    "MAIN-QUERY-CREDENTIALS-USERNAME",
    "MAIN-QUERY-CREDENTIALS-PASSWORD",
    "MAIN-QUERY-CREDENTIALS-ENABLE-SECRET",
    "MAIN-QUERY-CONDITIONS-GROUP",
    "MAIN-QUERY-CONDITIONS-SOURCE-IP",
    "MAIN-QUERY-CONDITIONS-DESTINATION-IP",
    "MAIN-QUERY-CONDITIONS-SOURCE-PORT",
    "MAIN-QUERY-CONDITIONS-DESTINATION-PORT",
    "MAIN-QUERY-CONDITIONS-BIDIRECTIONAL",
    "MAIN-QUERY-RUN",
    "MAIN-QUERY-MONITOR-START",
    "MAIN-QUERY-STOP",
    "MAIN-QUERY-STATE",
    "MAIN-QUERY-CONTEXT",
    "MAIN-QUERY-DETAIL-COLUMNS-TOGGLE",
    "MAIN-QUERY-RESULT-TABLE",
    "MAIN-QUERY-RESULT-TABLE-HEADER",
    "MAIN-QUERY-RESULT-TABLE-BODY",
    "MAIN-QUERY-RESULT-TABLE-SELECTION",
    "MAIN-QUERY-DETAIL-TABS",
    "MAIN-QUERY-DETAIL-TAB-BAR",
    "MAIN-QUERY-RAW-VIEW",
    "MAIN-QUERY-DIAGNOSTICS-LIST",
    "MAIN-SETTINGS-MM-GROUP",
    "MAIN-SETTINGS-MM-PRIMARY-NAME",
    "MAIN-SETTINGS-MM-PRIMARY-HOST",
    "MAIN-SETTINGS-MM-PRIMARY-PORT",
    "MAIN-SETTINGS-MM-PRIMARY-ENABLED",
    "MAIN-SETTINGS-MM-STANDBY-NAME",
    "MAIN-SETTINGS-MM-STANDBY-HOST",
    "MAIN-SETTINGS-MM-STANDBY-PORT",
    "MAIN-SETTINGS-MM-STANDBY-ENABLED",
    "MAIN-SETTINGS-MD-GROUP",
    "MAIN-SETTINGS-MD-TABLE",
    "MAIN-SETTINGS-MD-TABLE-HEADER",
    "MAIN-SETTINGS-MD-TABLE-BODY",
    "MAIN-SETTINGS-MD-TABLE-SELECTION",
    "MAIN-SETTINGS-MONITOR-GROUP",
    "MAIN-SETTINGS-MONITOR-SESSION-INTERVAL",
    "MAIN-SETTINGS-MONITOR-LOCATION-INTERVAL",
    "MAIN-SETTINGS-MONITOR-CLOSE-MISSES",
    "MAIN-SETTINGS-SAVE",
    "MAIN-SETTINGS-PRIVACY-NOTICE",
    "MAIN-HISTORY-REFRESH",
    "MAIN-HISTORY-EXPORT-CSV",
    "MAIN-HISTORY-EXPORT-HTML",
    "MAIN-HISTORY-DELETE-SELECTED",
    "MAIN-HISTORY-DELETE-ALL",
    "MAIN-HISTORY-RUN-TABLE",
    "MAIN-HISTORY-RUN-TABLE-HEADER",
    "MAIN-HISTORY-RUN-TABLE-BODY",
    "MAIN-HISTORY-RUN-TABLE-SELECTION",
    "MAIN-HISTORY-PRIVACY-NOTICE",
}


class _Executor:
    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        return QueryOutcome(observations=(), used_mm=None, controllers=(), authoritative=True)

    def stop_monitor(self) -> None:
        pass


def _build_window(
    tmp_path: Path,
    inspector: DeveloperInspectorController | None = None,
) -> MainWindow:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    return MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,
        _Executor(),
        developer_inspector=inspector,
    )


def test_main_window_registers_exact_static_ui_catalog(qtbot: object, tmp_path: Path) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    inspector = DeveloperInspectorController(application, "v0.3.0")
    window = _build_window(tmp_path, inspector)
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    catalog = inspector.catalog
    assert len(catalog) == 61
    assert {metadata.stable_id for metadata in catalog} == EXPECTED_UI_IDS
    assert (
        sum(
            metadata.stable_id.startswith("MAIN-QUERY-") and metadata.stable_id != "MAIN-QUERY-VIEW"
            for metadata in catalog
        )
        == 24
    )
    assert all(
        metadata.source_path == "src/aruba_session_tracker/ui/main_window.py"
        for metadata in catalog
    )
    assert not inspector.enabled
    assert window.centralWidget() is window.central_root
    assert window.central_layout.indexOf(window.tabs) >= 0

    inspector.close()
    window.close()


def test_static_requests_never_copy_runtime_canaries(qtbot: object, tmp_path: Path) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    inspector = DeveloperInspectorController(application, "v0.3.0")
    window = _build_window(tmp_path, inspector)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    canary = "TOP-SECRET-CANARY-198.51.100.77"

    for editor in (
        window.username_edit,
        window.password_edit,
        window.enable_edit,
        window.source_ip_edit,
        window.destination_ip_edit,
        window.source_port_edit,
        window.destination_port_edit,
        window.mm_primary_name,
        window.mm_primary_host,
        window.mm_standby_name,
        window.mm_standby_host,
    ):
        editor.setText(canary)
    window.md_table.item(0, 1).setText(canary)
    window.md_table.item(0, 2).setText(canary)
    window.result_table.setRowCount(1)
    window.result_table.setItem(0, 0, QTableWidgetItem(canary))
    window.raw_view.setPlainText(canary)
    window.diagnostics_list.addItem(canary)
    window.history_table.setRowCount(1)
    window.history_table.setItem(0, 0, QTableWidgetItem(canary))
    window.context_label.setText(canary)
    window.state_label.setText(canary)

    static_output = "\n".join(inspector.request_text(metadata) for metadata in inspector.catalog)
    assert canary not in static_output
    assert "현재 현상:\n원하는 변경:" in static_output

    inspector.close()
    window.close()


def test_existing_three_argument_constructor_remains_supported(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(tmp_path)
    qtbot.addWidget(window)  # type: ignore[attr-defined]

    assert window._developer_inspector is None
    assert window.central_layout.count() == 1

    window.close()


def test_plain_f12_smoke_path_starts_off_and_toggles_without_qttest(
    qtbot: object,
    tmp_path: Path,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    inspector = DeveloperInspectorController(application, "v0.3.0")
    window = _build_window(tmp_path, inspector)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()

    assert not inspector.enabled
    _send_plain_f12(application, window)
    assert inspector.enabled
    _send_plain_f12(application, window)
    assert not inspector.enabled

    inspector.close()
    window.close()


def test_selection_click_identifies_button_without_running_its_action(
    qtbot: object,
    tmp_path: Path,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    inspector = DeveloperInspectorController(application, "v0.3.0")
    window = _build_window(tmp_path, inspector)
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    action_calls: list[bool] = []
    selected_ids: list[str] = []
    window.query_button.clicked.connect(lambda: action_calls.append(True))
    inspector.element_selected.connect(lambda metadata: selected_ids.append(metadata.stable_id))

    _send_plain_f12(application, window)
    assert inspector.begin_selection()
    qtbot.mouseClick(  # type: ignore[attr-defined]
        window.query_button,
        Qt.MouseButton.LeftButton,
    )

    assert action_calls == []
    assert selected_ids == ["MAIN-QUERY-RUN"]
    assert not inspector.selection_mode

    inspector.close()
    window.close()


def test_ui_inspector_cannot_be_enabled_by_command_line() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--ui-inspector"])

    assert exc_info.value.code == 2
