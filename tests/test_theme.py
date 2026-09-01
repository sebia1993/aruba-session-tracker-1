from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QWidget,
)

from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import SessionObservation
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


def _observation(*, flags: str = "D", raw_line: str = "sanitized raw row") -> SessionObservation:
    return SessionObservation(
        controller_name="MD-01",
        controller_host="198.51.100.21",
        protocol=6,
        source_ip="192.0.2.10",
        destination_ip="198.51.100.20",
        source_port=50000,
        destination_port=443,
        packets=10,
        bytes_count=2048,
        age=18,
        flags=flags,
        cpu_id=1,
        raw_line=raw_line,
        observed_at=datetime(2026, 9, 1, 3, 0, tzinfo=UTC),
    )


def test_theme_installs_dark_noc_shell_without_replacing_operational_widgets(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    original_tabs = window.tabs
    original_tab_bar = window.tabs.tabBar()
    original_state_label = window.state_label
    original_monitor_button = window.monitor_button
    original_result_table = window.result_table

    apply_main_window_theme(window)
    window.show()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window.result_splitter.orientation() == Qt.Orientation.Horizontal,
        timeout=3000,
    )

    assert window.tabs is original_tabs
    assert window.tabs.tabBar() is original_tab_bar
    assert window.state_label is original_state_label
    assert window.monitor_button is original_monitor_button
    assert window.result_table is original_result_table
    assert window.property("darkNocConsoleInstalled") is True
    assert window.tabs.tabPosition() == QTabWidget.TabPosition.North
    assert window.tabs.cornerWidget(Qt.Corner.TopRightCorner) is None
    assert all(window.tabs.tabIcon(index).isNull() for index in range(window.tabs.count()))
    window.tabs.tabBar().setFocus()
    QApplication.processEvents()
    tab_rects = [window.tabs.tabBar().tabRect(index) for index in range(window.tabs.count())]
    assert len({rect.width() for rect in tab_rects}) == 1
    assert len({rect.height() for rect in tab_rects}) == 1
    for index, rect in enumerate(tab_rects):
        label_width = (
            window.tabs.tabBar().fontMetrics().horizontalAdvance(window.tabs.tabText(index))
        )
        assert rect.width() >= label_width + 24
        assert rect.height() >= window.tabs.tabBar().fontMetrics().height()
    assert window.central_layout.itemAt(0).widget() is window.nav_identity
    assert window.nav_identity.isVisible()
    assert window.nav_identity.objectName() == "nocHeader"
    assert window.nav_identity.minimumHeight() == 66
    assert window.nav_identity.maximumHeight() == 66
    assert window.product_name_label.text() == "ARUBA SESSION TRACKER"
    assert "NETWORK SESSION INVESTIGATION CONSOLE" in window.product_meta_label.text()

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

    metric_strip = window.findChild(QFrame, "metricStrip")
    assert metric_strip is not None
    metric_values = metric_strip.findChildren(QLabel, "metricValue")
    assert len(metric_values) == 4
    assert [label.text() for label in metric_values] == ["0", "0", "0", "0"]

    assert window.details.count() == 3
    assert window.details.tabText(0) == "DETAILS"
    assert window.details.tabText(1) == "RAW CLI"
    assert window.details.tabText(2) == "DIAGNOSTICS"
    session_detail_page = window.findChild(QWidget, "sessionDetailPage")
    assert session_detail_page is not None
    assert window.details.minimumWidth() >= 340
    assert window.details.minimumHeight() == 0

    assert window.context_label.objectName() == "contextSummary"
    assert window.state_label.property("stateRole") == "neutral"
    assert window.source_endpoint_panel.property("endpointRole") == "source"
    assert window.destination_endpoint_panel.property("endpointRole") == "destination"
    assert window.query_direction_label.property("directionRole") == "bidirectional"
    assert window.result_empty_label.objectName() == "emptyState"
    assert window.history_empty_label.objectName() == "emptyState"
    assert window.history_toolbar.objectName() == "historyToolbar"
    assert window.raw_view.objectName() == "rawConsole"
    assert window.result_table.alternatingRowColors()
    assert window.result_table.verticalHeader().isHidden()
    assert window.result_table.verticalHeader().defaultSectionSize() == 30
    assert window.advanced_panel.sizePolicy().verticalPolicy() == QSizePolicy.Policy.Fixed
    assert window.tabs.elideMode() == Qt.TextElideMode.ElideNone
    assert window.styleSheet() == build_stylesheet()
    window.close()


def test_theme_stylesheet_uses_approved_dark_tokens_and_semantic_states() -> None:
    stylesheet = build_stylesheet()

    assert "background-color: #101720;" in stylesheet
    assert "background-color: #16212D;" in stylesheet
    assert "background-color: #0A1118;" in stylesheet
    assert "color: #E8EFF6;" in stylesheet
    assert "border-bottom: 3px solid #2F80ED;" in stylesheet
    assert "width: 176px;" in stylesheet
    assert "border-bottom: 3px solid transparent;" in stylesheet
    assert "#2DBE78" in stylesheet
    assert "#E4A83C" in stylesheet
    assert "#E05C65" in stylesheet
    assert 'QPushButton[buttonRole="primary"]' in stylesheet
    assert 'QPushButton[buttonRole="dangerStrong"]' in stylesheet
    assert 'QLabel#stateLabel[stateRole="success"]' in stylesheet
    assert 'QLabel#stateLabel[stateRole="warning"]' in stylesheet
    assert 'QLabel#stateLabel[stateRole="danger"]' in stylesheet
    assert "QTabBar#mainNavigationTabs::tab:selected" in stylesheet
    assert 'QMainWindow#mainWindow[themeContrast="high"]' in stylesheet
    assert "QLineEdit:focus" in stylesheet
    assert "QTableWidget::item:selected" in stylesheet
    assert "QPlainTextEdit#rawConsole" in stylesheet
    assert "QFrame#metricCard" in stylesheet
    assert "QFrame#sessionFlowCard" in stylesheet
    assert "QFrame#nocHeader" in stylesheet
    assert "QLabel#emptyState" in stylesheet
    assert "QSplitter::handle:vertical" in stylesheet
    assert "QCheckBox:focus" in stylesheet
    assert "QScrollBar::add-line:vertical" in stylesheet
    assert "QScrollBar::sub-line:horizontal" in stylesheet
    assert "width: 0;" not in stylesheet
    assert "height: 0;" not in stylesheet
    assert _contrast_ratio("#E8EFF6", "#101720") >= 7.0
    assert _contrast_ratio("#4D667A", "#101720") >= 3.0
    assert "http://" not in stylesheet
    assert "https://" not in stylesheet
    assert "gradient" not in stylesheet.casefold()


def test_theme_can_be_applied_twice_without_duplicate_shell_components(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    original_widgets = (window.tabs, window.query_button, window.result_table, window.details)
    original_tab_bar = window.tabs.tabBar()
    original_tab_count = window.tabs.count()

    apply_main_window_theme(window)
    first_stylesheet = window.styleSheet()
    first_details_count = window.details.count()
    first_metric_strip = window.findChild(QFrame, "metricStrip")
    assert first_metric_strip is not None
    first_header = window.nav_identity
    apply_main_window_theme(window)

    assert (
        window.tabs,
        window.query_button,
        window.result_table,
        window.details,
    ) == original_widgets
    assert window.tabs.count() == original_tab_count
    assert window.tabs.tabBar() is original_tab_bar
    assert window.tabs.cornerWidget(Qt.Corner.TopRightCorner) is None
    assert all(window.tabs.tabIcon(index).isNull() for index in range(window.tabs.count()))
    assert window.details.count() == first_details_count == 3
    assert window.findChild(QFrame, "metricStrip") is first_metric_strip
    assert window.nav_identity is first_header
    assert window.styleSheet() == first_stylesheet == build_stylesheet()
    window.close()


def test_detail_panel_preserves_results_viewport_for_wide_and_compact_layouts(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    apply_main_window_theme(window)
    window.resize(1320, 820)
    window.show()
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window.result_splitter.orientation() == Qt.Orientation.Horizontal,
        timeout=3000,
    )
    assert window.details.minimumWidth() >= 340
    assert window.details.minimumHeight() == 0

    window.resize(1100, 820)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.result_splitter.orientation() == Qt.Orientation.Vertical
            and window.details.minimumHeight() == 190
        ),
        timeout=3000,
    )
    assert window.details.minimumWidth() == 0
    assert window.details.minimumHeight() == 190

    window.resize(1080, 680)
    window.advanced_toggle_button.setChecked(True)
    window.raw_diagnostics_toggle.setChecked(True)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.result_splitter.orientation() == Qt.Orientation.Horizontal
            and window.details.minimumWidth() >= 340
        ),
        timeout=3000,
    )
    assert window.advanced_panel.isVisible()
    assert window.details.isVisible()
    assert window.details.minimumWidth() >= 340
    assert window.details.minimumHeight() == 0
    assert window.result_table.viewport().height() >= 40
    detail_tab_bar = window.details.tabBar()
    detail_tab_rects = [detail_tab_bar.tabRect(index) for index in range(window.details.count())]
    for index, rect in enumerate(detail_tab_rects):
        label_width = detail_tab_bar.fontMetrics().horizontalAdvance(window.details.tabText(index))
        assert rect.width() >= label_width + 12
        assert detail_tab_bar.rect().contains(rect)
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
        themed_window._append_observation(_observation())
        assert themed_window.result_table.item(0, 13).foreground().style() != Qt.BrushStyle.NoBrush
        apply_main_window_theme(themed_window)
        themed_window._append_observation(_observation(raw_line="second sanitized row"))
        themed_window.show()

        assert themed_window.property("themeContrast") == "high"
        assert themed_window.monitor_button.isVisible()
        assert themed_window.query_button.isVisible()
        qtbot.waitUntil(  # type: ignore[attr-defined]
            lambda: themed_window.result_table.viewport().geometry().width() > 100,
            timeout=3000,
        )
        line_palette = themed_window.username_edit.palette()
        assert line_palette.color(QPalette.ColorRole.Base) != line_palette.color(
            QPalette.ColorRole.Text
        )
        for row in range(themed_window.result_table.rowCount()):
            for column in (13, 14, 15):
                assert (
                    themed_window.result_table.item(row, column).foreground().style()
                    == Qt.BrushStyle.NoBrush
                )
    finally:
        if window is not None:
            window.close()
        application.setPalette(original_palette)


def test_theme_keeps_header_text_visible_in_light_high_contrast(
    qtbot: object,
    tmp_path: Path,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    original_palette = application.palette()
    palette = QPalette(original_palette)
    palette.setColor(QPalette.ColorRole.Window, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    application.setPalette(palette)
    window: MainWindow | None = None
    try:
        themed_window = _build_window(qtbot, tmp_path)
        window = themed_window
        apply_main_window_theme(themed_window)
        themed_window.show()
        qtbot.waitUntil(  # type: ignore[attr-defined]
            lambda: themed_window.product_name_label.isVisible(),
            timeout=3000,
        )

        assert themed_window.property("themeContrast") == "high"
        for label in (themed_window.product_name_label, themed_window.product_meta_label):
            foreground = label.palette().color(label.foregroundRole()).name()
            background = (
                themed_window.nav_identity.palette().color(QPalette.ColorRole.Window).name()
            )
            assert foreground == "#000000"
            assert _contrast_ratio(foreground, background) >= 7.0
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
    window.details.setCurrentWidget(window.raw_view)
    window.show()
    qtbot.waitUntil(lambda: window.raw_view.isVisible(), timeout=3000)  # type: ignore[attr-defined]

    palette = window.raw_view.palette()
    text = palette.color(QPalette.ColorRole.Text).name()
    base = palette.color(QPalette.ColorRole.Base).name()
    assert _contrast_ratio(text, base) >= 4.5
    window.close()


def test_selected_session_summary_tracks_existing_row_and_preserves_raw_widgets(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    original_raw = window.raw_view
    original_diagnostics = window.diagnostics_list
    apply_main_window_theme(window)
    window._append_observation(_observation())
    window.resize(1320, 820)
    window.raw_diagnostics_toggle.setChecked(True)
    window.result_table.selectRow(0)
    window.details.setCurrentIndex(0)
    window.show()

    protocol = window.findChild(QLabel, "detailProtocol")
    assert protocol is not None
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: protocol.text() == "TCP (6)" and window.details.minimumWidth() >= 340,
        timeout=3000,
    )

    assert window.details.widget(1) is original_raw
    assert window.details.widget(2) is original_diagnostics
    assert window.raw_view.toPlainText() == "sanitized raw row"
    assert window.result_splitter.orientation() == Qt.Orientation.Horizontal
    assert window.result_table.viewport().height() >= 40
    assert protocol.wordWrap()
    assert "─" not in protocol.text()
    assert "▶" not in protocol.text()

    endpoint_values = window.findChildren(QLabel, "detailEndpointValue")
    assert [label.text() for label in endpoint_values] == [
        "192.0.2.10:50000",
        "198.51.100.20:443",
    ]
    assert all(label.wordWrap() for label in endpoint_values)
    assert all(
        label.width() >= label.fontMetrics().horizontalAdvance(label.text())
        for label in endpoint_values
    )

    fact_values: dict[str, QLabel] = {}
    for frame in window.findChildren(QFrame, "detailFact"):
        caption = frame.findChild(QLabel, "detailFactLabel")
        value = frame.findChild(QLabel, "detailFactValue")
        assert caption is not None
        assert value is not None
        assert value.wordWrap()
        assert (
            value.width() >= value.fontMetrics().horizontalAdvance(value.text())
            or value.height() >= value.sizeHint().height()
        )
        fact_values[caption.text()] = value
    assert fact_values["STATUS"].text() == "현재 관측됨"
    assert fact_values["CONTROLLER"].text() == "MD-01"
    assert fact_values["FLAGS"].text() == "D"
    assert fact_values["LAST SEEN"].text() == window.result_table.item(0, 12).text()
    assert fact_values["PACKETS"].text() == "10"
    assert fact_values["BYTES"].text() == "2,048"
    assert fact_values["AGE"].text() == "18"
    assert fact_values["CPU"].text() == "1"

    metric_values: dict[str, str] = {}
    for frame in window.findChildren(QFrame, "metricCard"):
        caption = frame.findChild(QLabel, "metricLabel")
        value = frame.findChild(QLabel, "metricValue")
        assert caption is not None
        assert value is not None
        metric_values[caption.text()] = value.text()
    assert metric_values == {
        "ACTIVE FLOWS": "1",
        "VISIBLE ROWS": "1",
        "CHANGED FLOWS": "0",
        "CONTROLLERS": "1",
    }

    status_item = window.result_table.item(0, 14)
    assert status_item.foreground().style() == Qt.BrushStyle.NoBrush
    assert window.result_table.item(0, 13).foreground().color().name() == "#e05c65"
    assert window.result_table.item(0, 15).foreground().color().name() == "#e05c65"

    window.details.setCurrentWidget(original_raw)
    assert window.raw_view.toPlainText() == "sanitized raw row"
    window.resize(1080, 680)
    window.advanced_toggle_button.setChecked(True)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.result_splitter.orientation() == Qt.Orientation.Horizontal
            and window.result_table.viewport().height() >= 40
        ),
        timeout=3000,
    )
    window.close()


def test_compact_advanced_layout_keeps_selected_session_details_scrollable(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    apply_main_window_theme(window)
    window._append_observation(_observation())
    window.resize(window.minimumSize())
    window.advanced_toggle_button.setChecked(True)
    window.raw_diagnostics_toggle.setChecked(True)
    window.result_table.selectRow(0)
    window.details.setCurrentIndex(0)
    window.show()

    scroll = window.findChild(QScrollArea, "sessionDetailScroll")
    assert scroll is not None
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: scroll.isVisible() and scroll.verticalScrollBar().maximum() > 0,
        timeout=3000,
    )

    assert window.result_splitter.orientation() == Qt.Orientation.Horizontal
    assert window.result_table.viewport().height() >= 40
    assert window.details.width() >= 300
    assert scroll.viewport().height() > 0
    assert scroll.widget() is not None
    assert scroll.widget().height() > scroll.viewport().height()
    window.close()
