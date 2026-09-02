from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QBoxLayout,
    QDialog,
    QFileDialog,
    QFrame,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import SessionObservation
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.developer_inspector import DeveloperInspectorController
from aruba_session_tracker.ui.main_window import _ResultFilterDialog
from aruba_session_tracker.ui.startup import StartupWindow
from aruba_session_tracker.ui.theme import (
    _uses_high_contrast_palette,
    apply_application_popup_theme,
    apply_main_window_theme,
    build_popup_stylesheet,
    build_stylesheet,
)


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
    assert "네트워크 세션 분석 콘솔" in window.product_meta_label.text()

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
    assert window.details.tabText(0) == "세션 요약"
    assert window.details.tabText(1) == "장비 원문"
    assert window.details.tabText(2) == "진단 이벤트"
    session_detail_page = window.findChild(QWidget, "sessionDetailPage")
    assert session_detail_page is not None
    assert window.details.minimumWidth() >= 380
    assert window.details.tabBar().minimumWidth() >= 380
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


def test_application_popup_theme_covers_owned_transient_surfaces(
    qtbot: object,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    original_stylesheet = application.styleSheet()
    original_font = application.font()
    surfaces: list[QWidget] = []
    try:
        apply_application_popup_theme(application)
        assert application.property("popupThemeContrast") == "normal"

        message = QMessageBox()
        message.setText(
            "조회 결과를 안전하게 저장하지 못했습니다. 저장소 권한과 보안 상태를 확인하십시오."
        )
        message.setInformativeText(f"{'긴-한글-파일명-' * 12}보고서.html")
        message.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        message.setDefaultButton(QMessageBox.StandardButton.No)
        surfaces.append(message)

        generic_dialog = QDialog()
        generic_layout = QVBoxLayout(generic_dialog)
        generic_layout.addWidget(QLabel("별도 상세 창 문구", generic_dialog))
        generic_layout.addWidget(QLineEdit("필드 문구", generic_dialog))
        generic_layout.addWidget(QPushButton("확인", generic_dialog))
        surfaces.append(generic_dialog)

        menu = QMenu()
        menu.addAction("출발지 IP 필터")
        surfaces.append(menu)

        fallback_file_dialog = QFileDialog()
        fallback_file_dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        surfaces.append(fallback_file_dialog)

        startup = StartupWindow()
        startup.setProperty("popupSurface", "startup")
        surfaces.append(startup)

        for surface in surfaces:
            qtbot.addWidget(surface)  # type: ignore[attr-defined]
            surface.show()
        QApplication.processEvents()

        for surface in surfaces:
            palette = surface.palette()
            background = palette.color(QPalette.ColorRole.Window).name()
            foreground = palette.color(QPalette.ColorRole.WindowText).name()
            assert background == "#152331"
            assert foreground == "#e8eff6"
            assert _contrast_ratio(foreground, background) >= 7.0

        body_label = message.findChild(QLabel, "qt_msgbox_label")
        information_label = message.findChild(QLabel, "qt_msgbox_informativelabel")
        assert body_label is not None and body_label.isVisible()
        assert information_label is not None and information_label.isVisible()
        assert body_label.minimumWidth() >= 320
        assert information_label.minimumWidth() >= 320
        assert information_label.text().endswith("보고서.html")

        no_button = message.button(QMessageBox.StandardButton.No)
        assert no_button is not None and no_button.isDefault()
        button_palette = no_button.palette()
        assert (
            _contrast_ratio(
                button_palette.color(QPalette.ColorRole.ButtonText).name(),
                button_palette.color(QPalette.ColorRole.Button).name(),
            )
            >= 4.5
        )

        file_name_edit = fallback_file_dialog.findChild(QLineEdit, "fileNameEdit")
        assert file_name_edit is not None
        field_palette = file_name_edit.palette()
        assert (
            _contrast_ratio(
                field_palette.color(QPalette.ColorRole.Text).name(),
                field_palette.color(QPalette.ColorRole.Base).name(),
            )
            >= 7.0
        )

        popup_stylesheet = build_popup_stylesheet()
        assert "QMessageBox" in popup_stylesheet
        assert "QDialog" in popup_stylesheet
        assert "QFileDialog" in popup_stylesheet
        assert "QMenu" in popup_stylesheet
        assert "QToolTip" in popup_stylesheet
        assert "DontUseNativeDialog" not in popup_stylesheet
        assert _contrast_ratio("#42B7C8", "#152331") >= 3.0
        assert _contrast_ratio("#66859D", "#1C2E3F") >= 3.0
    finally:
        for surface in surfaces:
            surface.close()
        QApplication.processEvents()
        application.setStyleSheet(original_stylesheet)
        application.setFont(original_font)


@pytest.mark.parametrize(
    (
        "window",
        "window_text",
        "base",
        "text",
        "button",
        "button_text",
        "highlight",
        "highlighted_text",
    ),
    (
        ("#000000", "#ffffff", "#000000", "#ffffff", "#000000", "#ffffff", "#ffff00", "#000000"),
        ("#ffffff", "#000000", "#ffffff", "#000000", "#ffffff", "#000000", "#000000", "#ffffff"),
    ),
)
def test_application_popup_theme_uses_native_roles_for_high_contrast(
    qtbot: object,
    window: str,
    window_text: str,
    base: str,
    text: str,
    button: str,
    button_text: str,
    highlight: str,
    highlighted_text: str,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    original_palette = application.palette()
    original_stylesheet = application.styleSheet()
    original_font = application.font()
    palette = QPalette(original_palette)
    palette.setColor(QPalette.ColorRole.Window, QColor(window))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(window_text))
    palette.setColor(QPalette.ColorRole.Base, QColor(base))
    palette.setColor(QPalette.ColorRole.Text, QColor(text))
    palette.setColor(QPalette.ColorRole.Button, QColor(button))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(button_text))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(highlight))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(highlighted_text))
    application.setPalette(palette)
    surfaces: list[QWidget] = []
    try:
        apply_application_popup_theme(application)
        assert application.property("popupThemeContrast") == "high"
        assert "palette(window-text)" in application.styleSheet()

        popup = QMessageBox()
        surfaces.append(popup)
        qtbot.addWidget(popup)  # type: ignore[attr-defined]
        popup.setText("고대비 팝업 문구")
        popup.setStandardButtons(QMessageBox.StandardButton.Ok)
        popup.show()

        fallback_file_dialog = QFileDialog()
        surfaces.append(fallback_file_dialog)
        qtbot.addWidget(fallback_file_dialog)  # type: ignore[attr-defined]
        fallback_file_dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        fallback_file_dialog.show()

        generic_dialog = QDialog()
        QVBoxLayout(generic_dialog).addWidget(QPushButton("확인", generic_dialog))
        surfaces.append(generic_dialog)
        qtbot.addWidget(generic_dialog)  # type: ignore[attr-defined]
        generic_dialog.show()

        menu = QMenu()
        menu.addAction("필터")
        surfaces.append(menu)
        qtbot.addWidget(menu)  # type: ignore[attr-defined]
        menu.show()

        startup = StartupWindow()
        startup.setProperty("popupSurface", "startup")
        surfaces.append(startup)
        qtbot.addWidget(startup)  # type: ignore[attr-defined]
        startup.show()
        QApplication.processEvents()

        for surface in surfaces:
            surface_palette = surface.palette()
            actual_background = surface_palette.color(QPalette.ColorRole.Window).name()
            actual_foreground = surface_palette.color(QPalette.ColorRole.WindowText).name()
            assert actual_background == window
            assert actual_foreground == window_text
            assert _contrast_ratio(actual_foreground, actual_background) >= 7.0

        file_name_edit = fallback_file_dialog.findChild(QLineEdit, "fileNameEdit")
        assert file_name_edit is not None
        field_palette = file_name_edit.palette()
        assert field_palette.color(QPalette.ColorRole.Base).name() == base
        assert field_palette.color(QPalette.ColorRole.Text).name() == text

        ok_button = popup.button(QMessageBox.StandardButton.Ok)
        assert ok_button is not None
        button_palette = ok_button.palette()
        assert button_palette.color(QPalette.ColorRole.Button).name() == button
        assert button_palette.color(QPalette.ColorRole.ButtonText).name() == button_text
    finally:
        for surface in surfaces:
            surface.close()
        QApplication.processEvents()
        application.setStyleSheet(original_stylesheet)
        application.setFont(original_font)
        application.setPalette(original_palette)


def test_high_contrast_detection_accepts_button_text_at_aa_threshold() -> None:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#767676"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#ffff00"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#000000"))

    button_ratio = _contrast_ratio("#ffffff", "#767676")
    assert 4.5 <= button_ratio < 7.0
    assert _uses_high_contrast_palette(palette)


def test_high_contrast_detection_rejects_invisible_focus_color() -> None:
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#000000"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))

    assert not _uses_high_contrast_palette(palette)


def test_popup_theme_preserves_default_button_and_escape_semantics(
    qtbot: object,
) -> None:
    application = QApplication.instance()
    assert isinstance(application, QApplication)
    original_stylesheet = application.styleSheet()
    original_font = application.font()
    approval = QMessageBox(
        QMessageBox.Icon.Question,
        "조회 승인",
        "승인하지 않으면 안전하게 취소됩니다.",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
    )
    filter_owner = QWidget()
    filter_dialog = _ResultFilterDialog(
        filter_owner,
        title="출발지 IP",
        values=(("192.0.2.10", "192.0.2.10"),),
        selected=set(),
        filter_active=False,
    )
    try:
        apply_application_popup_theme(application)
        qtbot.addWidget(approval)  # type: ignore[attr-defined]
        qtbot.addWidget(filter_owner)  # type: ignore[attr-defined]
        approval.setDefaultButton(QMessageBox.StandardButton.No)
        approval.show()
        QApplication.processEvents()

        assert approval.defaultButton() is approval.button(QMessageBox.StandardButton.No)
        qtbot.keyClick(approval, Qt.Key.Key_Escape)  # type: ignore[attr-defined]
        qtbot.waitUntil(lambda: not approval.isVisible(), timeout=3000)  # type: ignore[attr-defined]
        assert approval.result() == QMessageBox.StandardButton.No.value

        filter_dialog.show()
        QApplication.processEvents()
        qtbot.keyClick(filter_dialog, Qt.Key.Key_Escape)  # type: ignore[attr-defined]
        qtbot.waitUntil(lambda: not filter_dialog.isVisible(), timeout=3000)  # type: ignore[attr-defined]
        assert filter_dialog.result() == QDialog.DialogCode.Rejected.value
    finally:
        approval.close()
        filter_dialog.close()
        QApplication.processEvents()
        application.setStyleSheet(original_stylesheet)
        application.setFont(original_font)


def test_export_completion_popup_remains_readable_inside_themed_main_window(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    apply_main_window_theme(window)
    window.show()
    inspected: list[bool] = []

    def inspect_and_close() -> None:
        dialog = window.findChild(QMessageBox, "exportCompletionDialog")
        assert dialog is not None and dialog.isVisible()
        background = dialog.palette().color(QPalette.ColorRole.Window).name()
        body = dialog.findChild(QLabel, "qt_msgbox_label")
        information = dialog.findChild(QLabel, "qt_msgbox_informativelabel")
        assert body is not None and body.text() == "HTML 보고서를 저장했습니다."
        assert information is not None and information.text().endswith("보고서.html")
        foreground = body.palette().color(body.foregroundRole()).name()
        assert _contrast_ratio(foreground, background) >= 7.0
        confirm = next(
            button for button in dialog.findChildren(QPushButton) if button.text() == "확인"
        )
        inspected.append(True)
        confirm.click()

    QTimer.singleShot(0, inspect_and_close)
    window._show_export_completion(
        "HTML 보고서",
        tmp_path / f"{'긴-한글-파일명-' * 12}보고서.html",
    )

    assert inspected == [True]
    window.close()


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
    assert window.details.minimumWidth() >= 380
    assert window.details.minimumHeight() == 0
    assert window.result_splitter.widget(0).width() >= 380

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
            and window.details.minimumWidth() >= 380
        ),
        timeout=3000,
    )
    assert window.advanced_panel.isVisible()
    assert window.details.isVisible()
    assert window.results_title_label.isHidden()
    assert window.result_status_guide.isHidden()
    assert window.context_label.isHidden()
    assert "장비 장애나 통신 성공 판정이 아닙니다" in window.result_table.accessibleDescription()
    assert window.context_label.text() in window.result_table.accessibleDescription()
    assert window.details.minimumWidth() >= 380
    assert window.details.minimumHeight() == 0
    assert window.result_splitter.widget(0).width() >= 380
    assert window.result_table.viewport().height() >= 40
    metric_values = window.findChildren(QLabel, "metricValue")
    for value in metric_values:
        value.setText("2,000")
    window.resize(1081, 680)
    window.resize(1080, 680)
    metric_labels = window.findChildren(QLabel, "metricLabel")
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            len(metric_values) == 4
            and len(metric_labels) == 4
            and all(value.width() >= value.sizeHint().width() for value in metric_values)
            and all(
                label.isVisible()
                and label.parentWidget().rect().contains(label.geometry())
                and label.width() >= label.sizeHint().width()
                and label.height() >= label.sizeHint().height()
                for label in metric_labels
            )
        ),
        timeout=3000,
    )
    assert len(metric_values) == 4
    assert len(metric_labels) == 4
    assert all(value.text() == "2,000" for value in metric_values)
    assert all(value.width() >= value.sizeHint().width() for value in metric_values)
    assert all(label.isVisible() for label in metric_labels)
    assert all(label.parentWidget().rect().contains(label.geometry()) for label in metric_labels)
    assert all(label.width() >= label.sizeHint().width() for label in metric_labels)
    assert all(label.height() >= label.sizeHint().height() for label in metric_labels)
    detail_tab_bar = window.details.tabBar()
    assert detail_tab_bar.minimumWidth() >= 380

    def detail_tabs_fit() -> bool:
        return (
            detail_tab_bar.width() >= 380
            and window.details.rect().contains(detail_tab_bar.geometry())
            and all(
                (rect := detail_tab_bar.tabRect(index)).width()
                >= detail_tab_bar.fontMetrics().horizontalAdvance(window.details.tabText(index))
                + 12
                and detail_tab_bar.rect().contains(rect)
                for index in range(window.details.count())
            )
        )

    for current_index in range(window.details.count()):
        window.details.setCurrentIndex(current_index)
        qtbot.waitUntil(detail_tabs_fit, timeout=3000)  # type: ignore[attr-defined]
        assert detail_tabs_fit()
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


def test_light_high_contrast_covers_inspector_and_result_filter_surfaces(
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
    inspector: DeveloperInspectorController | None = None
    filter_dialog: _ResultFilterDialog | None = None
    try:
        store = SessionStore(
            tmp_path / "tracker.db",
            tmp_path / "raw",
            tmp_path / "exports",
        )
        store.initialize()
        inspector = DeveloperInspectorController(application, "v0.6.0")
        window = MainWindow(
            ConfigRepository(tmp_path / "config.json"),
            store,
            _Executor(),
            developer_inspector=inspector,
        )
        qtbot.addWidget(window)  # type: ignore[attr-defined]
        qtbot.waitUntil(  # type: ignore[attr-defined]
            lambda: not window._history_task_running,
            timeout=3000,
        )
        apply_main_window_theme(window)
        window.show()
        qtbot.keyClick(window, Qt.Key.Key_F12)  # type: ignore[attr-defined]

        bar = window.findChild(QFrame, "developerInspectorBar")
        assert bar is not None
        qtbot.waitUntil(bar.isVisible, timeout=3000)  # type: ignore[attr-defined]
        detail = inspector.show_element_detail(inspector.catalog[0], window)
        catalog = inspector.show_catalog(window)
        assert detail is not None
        assert catalog is not None
        filter_dialog = _ResultFilterDialog(
            window,
            title="목적지 포트",
            values=((22, "22(SSH)"), (443, "443(HTTPS)")),
            selected=set(),
            filter_active=False,
        )
        qtbot.addWidget(filter_dialog)  # type: ignore[attr-defined]
        filter_dialog.show()
        QApplication.processEvents()

        for surface in (bar, detail, catalog, filter_dialog):
            surface_palette = surface.palette()
            background = surface_palette.color(QPalette.ColorRole.Window).name()
            foreground = surface_palette.color(QPalette.ColorRole.WindowText).name()
            assert background == "#ffffff"
            assert foreground == "#000000"
            assert _contrast_ratio(foreground, background) >= 7.0

        for label, surface in (
            (bar.mode_label, bar),
            (detail.intro_label, detail),
            (catalog.guide_label, catalog),
        ):
            foreground = label.palette().color(label.foregroundRole()).name()
            background = surface.palette().color(QPalette.ColorRole.Window).name()
            assert _contrast_ratio(foreground, background) >= 7.0

        for control in (
            detail.name_value,
            detail.purpose_value,
            detail.request_preview,
            catalog.element_list,
            filter_dialog.search_edit,
            filter_dialog.values_list,
        ):
            control_palette = control.palette()
            background = control_palette.color(QPalette.ColorRole.Base).name()
            foreground = control_palette.color(QPalette.ColorRole.Text).name()
            assert _contrast_ratio(foreground, background) >= 7.0
    finally:
        if filter_dialog is not None:
            filter_dialog.close()
        if inspector is not None:
            inspector.close()
        if window is not None:
            window.close()
        QApplication.processEvents()
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
        lambda: protocol.text() == "TCP (6)" and window.details.minimumWidth() >= 380,
        timeout=3000,
    )

    assert window.details.widget(1) is original_raw
    assert window.details.widget(2) is original_diagnostics
    assert window.raw_view.toPlainText() == "sanitized raw row"
    assert window.result_splitter.orientation() == Qt.Orientation.Horizontal
    assert window.result_table.viewport().height() >= 40
    assert (
        window.result_table.viewport().visibleRegion().boundingRect().height()
        >= window.result_table.verticalHeader().defaultSectionSize()
    )
    assert protocol.wordWrap()
    assert "─" not in protocol.text()
    assert "▶" not in protocol.text()

    endpoint_values = window.findChildren(QLabel, "detailEndpointValue")
    assert [label.text() for label in endpoint_values] == [
        "192.0.2.10:50000",
        "198.51.100.20:443(HTTPS)",
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
    assert fact_values["관측 상태"].text() == "현재 관측됨"
    assert fact_values["관측 MD"].text() == "MD-01"
    assert fact_values["장비 Flags"].text() == "D"
    assert fact_values["마지막 확인"].text() == window.result_table.item(0, 12).text()
    assert fact_values["패킷"].text() == "10"
    assert fact_values["바이트"].text() == "2,048"
    assert fact_values["세션 경과"].text() == "18"
    assert fact_values["CPU ID"].text() == "1"

    metric_values: dict[str, str] = {}
    for frame in window.findChildren(QFrame, "metricCard"):
        caption = frame.findChild(QLabel, "metricLabel")
        value = frame.findChild(QLabel, "metricValue")
        assert caption is not None
        assert value is not None
        metric_values[caption.text()] = value.text()
    assert metric_values == {
        "현재 관측 흐름": "1",
        "결과표 표시 행": "1",
        "신규·변경 흐름": "0",
        "관측 MD": "1",
    }

    status_item = window.result_table.item(0, 14)
    assert status_item.foreground().style() == Qt.BrushStyle.NoBrush
    assert window.result_table.item(0, 13).foreground().color().name() == "#e05c65"
    assert window.result_table.item(0, 15).text() == ""

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
    window.show()
    window.advanced_toggle_button.setChecked(True)
    window.raw_diagnostics_toggle.setChecked(True)
    window.result_table.selectRow(0)
    window.details.setCurrentIndex(0)
    window.resize(window.minimumSize())

    scroll = window.findChild(QScrollArea, "sessionDetailScroll")
    assert scroll is not None
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: scroll.isVisible() and scroll.verticalScrollBar().maximum() > 0,
        timeout=3000,
    )
    metric_labels = window.findChildren(QLabel, "metricLabel")
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.results_title_label.isHidden()
            and window.result_status_guide.isHidden()
            and window.context_label.isHidden()
            and len(metric_labels) == 4
            and all(label.isVisible() for label in metric_labels)
            and all(
                label.parentWidget().rect().contains(label.geometry())
                and label.width() >= label.sizeHint().width()
                and label.height() >= label.sizeHint().height()
                for label in metric_labels
            )
        ),
        timeout=3000,
    )

    assert window.result_splitter.orientation() == Qt.Orientation.Horizontal
    assert window.result_table.viewport().height() >= 40
    assert window.details.width() >= 300
    assert scroll.viewport().height() > 0
    assert scroll.widget() is not None
    assert scroll.widget().height() > scroll.viewport().height()
    assert window.results_title_label.isHidden()
    assert window.result_status_guide.isHidden()
    assert window.context_label.isHidden()
    assert len(metric_labels) == 4
    assert all(label.isVisible() for label in metric_labels)
    assert all(label.parentWidget().rect().contains(label.geometry()) for label in metric_labels)
    assert all(label.width() >= label.sizeHint().width() for label in metric_labels)
    assert all(label.height() >= label.sizeHint().height() for label in metric_labels)

    window.resize(1080, 820)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.results_title_label.isVisible()
            and window.result_status_guide.isVisible()
            and window.context_label.isVisible()
        ),
        timeout=3000,
    )
    window.resize(window.minimumSize())
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window.results_title_label.isHidden(),
        timeout=3000,
    )
    window.raw_diagnostics_toggle.setChecked(False)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.results_title_label.isVisible()
            and window.result_status_guide.isVisible()
            and window.context_label.isVisible()
        ),
        timeout=3000,
    )
    window.raw_diagnostics_toggle.setChecked(True)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: window.results_title_label.isHidden(),
        timeout=3000,
    )
    window.advanced_toggle_button.setChecked(False)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: (
            window.results_title_label.isVisible()
            and window.result_status_guide.isVisible()
            and window.context_label.isVisible()
            and all(
                isinstance(label.parentWidget().layout(), QBoxLayout)
                and label.parentWidget().layout().direction() == QBoxLayout.Direction.TopToBottom
                for label in metric_labels
            )
        ),
        timeout=3000,
    )
    window.close()


def test_result_accessibility_tracks_consecutive_empty_query_contexts(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = _build_window(qtbot, tmp_path)
    apply_main_window_theme(window)

    window._display_outcome(
        QueryOutcome(
            used_mm="MM-A",
            controllers=("MD-A",),
            authoritative=True,
        )
    )
    first_description = window.result_table.accessibleDescription()
    assert "MM-A" in first_description
    assert "MD-A" in first_description
    assert "장비 장애나 통신 성공 판정이 아닙니다" in first_description

    window._display_outcome(
        QueryOutcome(
            used_mm="MM-B",
            controllers=("MD-B",),
            authoritative=True,
        )
    )
    second_description = window.result_table.accessibleDescription()
    assert "MM-B" in second_description
    assert "MD-B" in second_description
    assert "MM-A" not in second_description
    assert "MD-A" not in second_description
    window.close()
