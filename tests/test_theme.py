from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QSizePolicy

from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.theme import apply_main_window_theme, build_stylesheet


class _Executor:
    def execute(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("theme test must not execute a query")

    def stop_monitor(self) -> None:
        return


def _relative_luminance(value: str) -> float:
    color = QColor(value)

    def channel(component: float) -> float:
        return component / 12.92 if component <= 0.04045 else ((component + 0.055) / 1.055) ** 2.4

    return (
        0.2126 * channel(color.redF())
        + 0.7152 * channel(color.greenF())
        + 0.0722 * channel(color.blueF())
    )


def _contrast_ratio(first: str, second: str) -> float:
    lighter, darker = sorted(
        (_relative_luminance(first), _relative_luminance(second)), reverse=True
    )
    return (lighter + 0.05) / (darker + 0.05)


def _build_window(qtbot: object, tmp_path: Path) -> MainWindow:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    window = MainWindow(ConfigRepository(tmp_path / "config.json"), store, _Executor())
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._history_task_running,
        timeout=3000,
    )
    return window


def test_theme_assigns_operational_roles_without_replacing_widgets(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    original_monitor_button = window.monitor_button
    original_result_table = window.result_table

    apply_main_window_theme(window)

    assert window.monitor_button is original_monitor_button
    assert window.result_table is original_result_table
    assert window.open_settings_button.property("buttonRole") == "primary"
    assert window.monitor_button.property("buttonRole") == "primary"
    assert window.query_button.property("buttonRole") == "secondary"
    assert window.advanced_toggle_button.property("buttonRole") == "tertiary"
    assert window.stop_button.property("buttonRole") == "dangerStrong"
    assert window.delete_button.property("buttonRole") == "danger"
    assert window.delete_all_button.property("buttonRole") == "dangerStrong"
    assert window.connection_group.property("panelRole") == "credentials"
    assert window.query_group.property("panelRole") == "query"
    assert window.advanced_panel.property("panelRole") == "advanced"
    assert window.mm_group.property("panelRole") == "controller"
    assert window.md_group.property("panelRole") == "controller"
    assert window.timing_group.property("panelRole") == "timing"
    assert window.context_label.objectName() == "contextSummary"
    assert window.state_label.property("stateRole") == "neutral"
    assert window.history_export_label.objectName() == "toolbarSectionLabel"
    assert window.history_delete_label.objectName() == "toolbarSectionLabel"
    assert window.raw_view.objectName() == "rawConsole"
    assert window.result_table.alternatingRowColors()
    assert window.result_table.verticalHeader().isHidden()
    assert window.result_table.verticalHeader().defaultSectionSize() == 30
    assert window.details.minimumWidth() == 300
    assert window.advanced_panel.sizePolicy().verticalPolicy() == QSizePolicy.Policy.Fixed
    assert window.tabs.elideMode() == Qt.TextElideMode.ElideNone
    for index in range(window.tabs.count()):
        tab_width = window.tabs.tabBar().tabRect(index).width()
        text_width = (
            window.tabs.tabBar().fontMetrics().horizontalAdvance(window.tabs.tabText(index))
        )
        assert tab_width >= text_width
    assert window.styleSheet() == build_stylesheet()
    window.close()


def test_theme_stylesheet_keeps_focus_and_semantic_action_states() -> None:
    stylesheet = build_stylesheet()

    assert 'QPushButton[buttonRole="primary"]' in stylesheet
    assert 'QPushButton[buttonRole="tertiary"]' in stylesheet
    assert 'QPushButton[buttonRole="dangerStrong"]' in stylesheet
    assert 'QLabel#stateLabel[stateRole="success"]' in stylesheet
    assert 'QLabel#stateLabel[stateRole="warning"]' in stylesheet
    assert 'QLabel#stateLabel[stateRole="danger"]' in stylesheet
    assert "QTabWidget#mainTabs QTabBar::tab:selected" in stylesheet
    assert "background-color: #102F49;" in stylesheet
    assert 'QMainWindow#mainWindow[themeContrast="high"]' in stylesheet
    assert "QLineEdit:focus" in stylesheet
    assert "QTableWidget::item:selected" in stylesheet
    assert "QPlainTextEdit#rawConsole" in stylesheet
    assert 'QPushButton[buttonRole="primary"]:focus' in stylesheet
    assert 'QPushButton[buttonRole="dangerStrong"]:focus' in stylesheet
    assert stylesheet.rfind('QPushButton[buttonRole="primary"]:focus') > stylesheet.rfind(
        'QPushButton[buttonRole="primary"]:pressed'
    )
    assert "QScrollBar::add-line:vertical" in stylesheet
    assert "QScrollBar::sub-line:horizontal" in stylesheet
    assert "width: 0;" not in stylesheet
    assert "height: 0;" not in stylesheet
    assert _contrast_ratio("#607D94", "#EEF3F7") >= 3.0
    assert 'QMainWindow#mainWindow[themeContrast="high"] QScrollBar::handle:vertical' in stylesheet
    assert "http://" not in stylesheet
    assert "https://" not in stylesheet


def test_theme_can_be_applied_twice_without_replacing_or_duplicating_widgets(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    original_widgets = (window.tabs, window.query_button, window.result_table, window.details)
    original_tab_count = window.tabs.count()
    original_query_layout_count = window.query_page.layout().count()

    apply_main_window_theme(window)
    first_stylesheet = window.styleSheet()
    apply_main_window_theme(window)

    assert (
        window.tabs,
        window.query_button,
        window.result_table,
        window.details,
    ) == original_widgets
    assert window.tabs.count() == original_tab_count
    assert window.query_page.layout().count() == original_query_layout_count
    assert window.styleSheet() == first_stylesheet == build_stylesheet()
    window.close()


def test_theme_uses_native_palette_roles_for_injected_high_contrast(
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
    window: MainWindow | None = None
    try:
        themed_window = _build_window(qtbot, tmp_path)
        window = themed_window
        apply_main_window_theme(themed_window)
        themed_window.show()

        assert themed_window.property("themeContrast") == "high"
        assert themed_window.monitor_button.isVisible()
        assert themed_window.query_button.isVisible()
        assert themed_window.monitor_button.sizeHint().width() > 0
        qtbot.waitUntil(  # type: ignore[attr-defined]
            lambda: themed_window.result_table.viewport().geometry().width() > 100,
            timeout=3000,
        )
        line_palette = themed_window.username_edit.palette()
        assert line_palette.color(QPalette.ColorRole.Base) != line_palette.color(
            QPalette.ColorRole.Text
        )
    finally:
        if window is not None:
            window.close()
        application.setPalette(original_palette)


def test_raw_console_keeps_terminal_contrast_after_widget_is_shown(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    apply_main_window_theme(window)
    window.raw_diagnostics_toggle.setChecked(True)
    window.show()
    qtbot.waitUntil(lambda: window.raw_view.isVisible(), timeout=3000)  # type: ignore[attr-defined]

    palette = window.raw_view.palette()
    text = palette.color(QPalette.ColorRole.Text).name()
    base = palette.color(QPalette.ColorRole.Base).name()
    assert _contrast_ratio(text, base) >= 4.5
    window.close()
