"""Visual system for the Aruba Session Tracker Qt interface.

The operational widgets and their stable Developer Inspector identifiers live in
``main_window.py``. This module deliberately limits itself to presentation and
non-destructive usability settings so the network, storage, and Inspector
contracts remain unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QPalette
from PySide6.QtWidgets import QApplication, QGroupBox, QLayout, QTableWidget, QWidget

if TYPE_CHECKING:
    from aruba_session_tracker.ui.main_window import MainWindow


_DEFAULT_FONT_FAMILY = "Malgun Gothic"
_DEFAULT_FONT_SIZE = 9


def apply_main_window_theme(window: MainWindow) -> None:
    """Apply the operations-console theme without changing widget contracts."""

    window.setObjectName("mainWindow")
    application = QApplication.instance()
    palette = application.palette() if isinstance(application, QApplication) else window.palette()
    window.setProperty(
        "themeContrast",
        "high" if _uses_high_contrast_palette(palette) else "normal",
    )
    _configure_layout_density(window)
    _configure_component_roles(window)
    _configure_tables(window)
    _configure_guidance(window)

    font = QFont(_DEFAULT_FONT_FAMILY, _DEFAULT_FONT_SIZE)
    window.setFont(font)
    if isinstance(application, QApplication):
        application.setFont(font)

    # MainWindow applies a legacy local stylesheet during construction. Set the
    # complete theme last so one source of truth controls all presentation.
    window.setStyleSheet(build_stylesheet())


def build_stylesheet() -> str:
    """Return the self-contained QSS used by the desktop application."""

    return """
    /* Aruba Session Tracker — enterprise network operations console */
    QMainWindow#mainWindow {
        background-color: #EEF3F8;
        color: #102A43;
    }

    QMainWindow#mainWindow QWidget {
        color: #102A43;
        selection-background-color: #CDE6FA;
        selection-color: #08243B;
    }

    /* Primary navigation: quiet tabs with a strong active-state underline. */
    QTabWidget#mainTabs::pane {
        background-color: #EEF3F8;
        border: 0;
        top: -1px;
    }

    QTabWidget#mainTabs QTabBar {
        background-color: #E4EBF2;
    }

    QTabWidget#mainTabs QTabBar::tab {
        min-height: 38px;
        padding: 0 20px;
        margin: 0;
        color: #52667A;
        background-color: #E4EBF2;
        border: 0;
        border-bottom: 3px solid transparent;
    }

    QTabWidget#mainTabs QTabBar::tab:selected {
        color: #0B4F82;
        background-color: #F7FAFC;
        border-bottom: 3px solid #1976B9;
        font-weight: 700;
    }

    QTabWidget#mainTabs QTabBar::tab:hover:!selected {
        color: #173A57;
        background-color: #EDF3F8;
    }

    QTabWidget#mainTabs QTabBar::tab:focus {
        border: 2px solid #1976B9;
        border-bottom: 3px solid #1976B9;
    }

    /* Progressive detail panel remains visually subordinate to the main table. */
    QTabWidget#detailsTabs::pane {
        background-color: #0F1C29;
        border: 1px solid #25394C;
        border-radius: 8px;
        top: -1px;
    }

    QTabWidget#detailsTabs QTabBar::tab {
        min-height: 31px;
        padding: 0 14px;
        color: #B7C7D8;
        background-color: #172736;
        border: 1px solid #2A3F53;
        border-bottom: 0;
    }

    QTabWidget#detailsTabs QTabBar::tab:selected {
        color: #FFFFFF;
        background-color: #0F1C29;
        border-color: #38536D;
        font-weight: 700;
    }

    QFrame#setupGuide {
        color: #17324D;
        background-color: #E6F2FC;
        border: 1px solid #9EC4E4;
        border-left: 4px solid #1976B9;
        border-radius: 8px;
    }

    /* Operational cards. Dynamic panelRole values are presentation-only. */
    QGroupBox {
        margin-top: 13px;
        padding: 19px 14px 14px 14px;
        color: #17324D;
        background-color: #FFFFFF;
        border: 1px solid #CCD8E4;
        border-radius: 9px;
        font-weight: 700;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 12px;
        padding: 0 7px;
        color: #17324D;
        background-color: #FFFFFF;
    }

    QGroupBox[panelRole="query"] {
        border-left: 4px solid #1976B9;
    }

    QGroupBox[panelRole="credentials"] {
        background-color: #F9FBFD;
        border-color: #D8E2EC;
    }

    QGroupBox[panelRole="advanced"] {
        background-color: #FAFCFE;
        border-style: dashed;
        border-color: #B9C9D8;
    }

    QGroupBox[panelRole="controller"] {
        border-left: 4px solid #4B7F9E;
    }

    QGroupBox[panelRole="timing"] {
        border-left: 4px solid #6D7F90;
    }

    QLabel {
        background-color: transparent;
    }

    QLabel#contextSummary {
        min-height: 32px;
        padding: 4px 11px;
        color: #123A58;
        background-color: #EAF3FA;
        border: 1px solid #B9D2E6;
        border-radius: 7px;
        font-weight: 600;
    }

    QLabel#stateLabel {
        min-height: 28px;
        padding: 2px 13px;
        color: #0A527E;
        background-color: #DDF0FC;
        border: 1px solid #8FC2E2;
        border-radius: 14px;
        font-weight: 700;
    }

    QLabel#privacyNotice {
        padding: 9px 11px;
        color: #5E4A18;
        background-color: #FFF8E7;
        border: 1px solid #E5C86E;
        border-left: 4px solid #C69214;
        border-radius: 7px;
    }

    QLineEdit,
    QSpinBox {
        min-height: 34px;
        padding: 0 10px;
        color: #102A43;
        background-color: #FFFFFF;
        border: 1px solid #A9BBCB;
        border-radius: 7px;
    }

    QLineEdit:hover,
    QSpinBox:hover {
        border-color: #718CA4;
        background-color: #FCFDFE;
    }

    QLineEdit:focus,
    QSpinBox:focus {
        border: 2px solid #1976B9;
        padding-left: 9px;
        padding-right: 9px;
        background-color: #FFFFFF;
    }

    QLineEdit:disabled,
    QSpinBox:disabled {
        color: #7D8B99;
        background-color: #EDF1F5;
        border-color: #D4DEE7;
    }

    QCheckBox {
        min-height: 30px;
        spacing: 8px;
        color: #263B50;
    }

    QCheckBox::indicator {
        width: 16px;
        height: 16px;
    }

    QPushButton {
        min-height: 34px;
        padding: 0 15px;
        color: #17324D;
        background-color: #FFFFFF;
        border: 1px solid #A7B8C8;
        border-radius: 7px;
        font-weight: 600;
    }

    QPushButton:hover {
        background-color: #F2F7FB;
        border-color: #6987A2;
    }

    QPushButton:pressed {
        background-color: #E1EBF3;
        border-color: #4E6E88;
    }

    QPushButton:focus {
        border: 2px solid #1976B9;
    }

    QPushButton:disabled {
        color: #8996A3;
        background-color: #E9EEF3;
        border-color: #D3DCE5;
    }

    QPushButton[buttonRole="primary"] {
        color: #FFFFFF;
        background-color: #0B5F9A;
        border-color: #0B5F9A;
        font-weight: 700;
    }

    QPushButton[buttonRole="primary"]:hover {
        background-color: #084F82;
        border-color: #084F82;
    }

    QPushButton[buttonRole="primary"]:pressed {
        background-color: #063E67;
        border-color: #063E67;
    }

    QPushButton[buttonRole="secondary"] {
        color: #0B4F82;
        background-color: #E9F3FB;
        border-color: #9CBFDA;
    }

    QPushButton[buttonRole="secondary"]:hover {
        background-color: #DCECF8;
        border-color: #6F9FC4;
    }

    QPushButton[buttonRole="tertiary"] {
        min-height: 30px;
        color: #0B4F82;
        background-color: transparent;
        border-color: transparent;
        padding-left: 9px;
        padding-right: 9px;
    }

    QPushButton[buttonRole="tertiary"]:hover,
    QPushButton[buttonRole="tertiary"]:checked {
        background-color: #E7F1F9;
        border-color: #A8C7DE;
    }

    QPushButton[buttonRole="danger"] {
        color: #9B1C1C;
        background-color: #FFF5F5;
        border-color: #E2A8A8;
    }

    QPushButton[buttonRole="danger"]:hover {
        color: #FFFFFF;
        background-color: #B42318;
        border-color: #B42318;
    }

    QPushButton[buttonRole="dangerStrong"] {
        color: #FFFFFF;
        background-color: #B42318;
        border-color: #B42318;
        font-weight: 700;
    }

    QPushButton[buttonRole="dangerStrong"]:hover {
        background-color: #8F1C14;
        border-color: #8F1C14;
    }

    /* Data grid is the visual center of gravity. */
    QTableWidget {
        color: #172A3D;
        background-color: #FFFFFF;
        alternate-background-color: #F7FAFC;
        border: 1px solid #C6D3DF;
        border-radius: 8px;
        gridline-color: #E6EDF3;
        outline: 0;
    }

    QTableWidget::item {
        min-height: 29px;
        padding: 5px 8px;
        border-bottom: 1px solid #E7EDF3;
    }

    QTableWidget::item:selected {
        color: #08243B;
        background-color: #CDE6FA;
    }

    QTableWidget::item:focus {
        border: 1px solid #1976B9;
    }

    QHeaderView::section {
        min-height: 34px;
        padding: 5px 8px;
        color: #294359;
        background-color: #E7EEF4;
        border: 0;
        border-right: 1px solid #CBD7E2;
        border-bottom: 1px solid #AABBCB;
        font-weight: 700;
    }

    QAbstractScrollArea::corner {
        background-color: #E7EEF4;
        border: 0;
    }

    QScrollBar:vertical {
        width: 11px;
        margin: 0;
        background-color: #EEF3F7;
    }

    QScrollBar::handle:vertical {
        min-height: 28px;
        margin: 2px;
        background-color: #AABAC8;
        border-radius: 4px;
    }

    QScrollBar::handle:vertical:hover {
        background-color: #7F95A8;
    }

    QScrollBar:horizontal {
        height: 11px;
        margin: 0;
        background-color: #EEF3F7;
    }

    QScrollBar::handle:horizontal {
        min-width: 28px;
        margin: 2px;
        background-color: #AABAC8;
        border-radius: 4px;
    }

    QScrollBar::handle:horizontal:hover {
        background-color: #7F95A8;
    }

    QScrollBar::add-line,
    QScrollBar::sub-line {
        width: 0;
        height: 0;
        border: 0;
        background: transparent;
    }

    QPlainTextEdit#rawConsole {
        color: #DDE8F2;
        background-color: #0F1C29;
        border: 0;
        border-radius: 7px;
        padding: 10px;
        font-family: Consolas;
        selection-background-color: #28557D;
        selection-color: #FFFFFF;
    }

    QListWidget#diagnosticsList {
        color: #1E3347;
        background-color: #FFFFFF;
        border: 0;
        border-radius: 7px;
        outline: 0;
    }

    QListWidget#diagnosticsList::item {
        min-height: 29px;
        padding: 5px 9px;
        border-bottom: 1px solid #E4EBF1;
    }

    QListWidget#diagnosticsList::item:selected {
        color: #08243B;
        background-color: #CDE6FA;
    }

    QSplitter::handle {
        background-color: #D4DEE7;
    }

    QSplitter::handle:horizontal {
        width: 7px;
        margin: 2px 1px;
    }

    QSplitter::handle:hover {
        background-color: #86AFCF;
    }

    QStatusBar {
        min-height: 26px;
        color: #425A70;
        background-color: #E2EAF1;
        border-top: 1px solid #C2CFDA;
    }

    QStatusBar::item {
        border: 0;
    }

    QToolTip {
        color: #FFFFFF;
        background-color: #172A3D;
        border: 1px solid #4A637A;
        padding: 5px 7px;
    }

    /* Native-palette fallback for Windows high-contrast startup. */
    QMainWindow#mainWindow[themeContrast="high"] {
        color: palette(window-text);
        background-color: palette(window);
    }

    QMainWindow#mainWindow[themeContrast="high"] QWidget {
        color: palette(window-text);
        selection-background-color: palette(highlight);
        selection-color: palette(highlighted-text);
    }

    QMainWindow#mainWindow[themeContrast="high"] QFrame#setupGuide,
    QMainWindow#mainWindow[themeContrast="high"] QGroupBox,
    QMainWindow#mainWindow[themeContrast="high"] QGroupBox::title,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#contextSummary,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#stateLabel,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#privacyNotice,
    QMainWindow#mainWindow[themeContrast="high"] QTabWidget#mainTabs::pane,
    QMainWindow#mainWindow[themeContrast="high"] QTabWidget#detailsTabs::pane {
        color: palette(window-text);
        background-color: palette(window);
        border-color: palette(mid);
    }

    QMainWindow#mainWindow[themeContrast="high"] QLineEdit,
    QMainWindow#mainWindow[themeContrast="high"] QSpinBox,
    QMainWindow#mainWindow[themeContrast="high"] QTableWidget,
    QMainWindow#mainWindow[themeContrast="high"] QListWidget,
    QMainWindow#mainWindow[themeContrast="high"] QPlainTextEdit#rawConsole {
        color: palette(text);
        background-color: palette(base);
        alternate-background-color: palette(base);
        border-color: palette(mid);
        selection-background-color: palette(highlight);
        selection-color: palette(highlighted-text);
    }

    QMainWindow#mainWindow[themeContrast="high"] QTableWidget::item,
    QMainWindow#mainWindow[themeContrast="high"] QListWidget::item {
        border-color: palette(mid);
    }

    QMainWindow#mainWindow[themeContrast="high"] QHeaderView::section,
    QMainWindow#mainWindow[themeContrast="high"] QTabBar::tab,
    QMainWindow#mainWindow[themeContrast="high"] QStatusBar {
        color: palette(window-text);
        background-color: palette(window);
        border-color: palette(mid);
    }

    QMainWindow#mainWindow[themeContrast="high"] QTabBar::tab:selected,
    QMainWindow#mainWindow[themeContrast="high"] QTableWidget::item:selected,
    QMainWindow#mainWindow[themeContrast="high"] QListWidget::item:selected {
        color: palette(highlighted-text);
        background-color: palette(highlight);
    }

    QMainWindow#mainWindow[themeContrast="high"] QPushButton,
    QMainWindow#mainWindow[themeContrast="high"] QPushButton[buttonRole="primary"],
    QMainWindow#mainWindow[themeContrast="high"] QPushButton[buttonRole="secondary"],
    QMainWindow#mainWindow[themeContrast="high"] QPushButton[buttonRole="tertiary"],
    QMainWindow#mainWindow[themeContrast="high"] QPushButton[buttonRole="danger"],
    QMainWindow#mainWindow[themeContrast="high"] QPushButton[buttonRole="dangerStrong"] {
        color: palette(button-text);
        background-color: palette(button);
        border: 2px solid palette(highlight);
    }

    QMainWindow#mainWindow[themeContrast="high"] QPushButton:focus,
    QMainWindow#mainWindow[themeContrast="high"] QLineEdit:focus,
    QMainWindow#mainWindow[themeContrast="high"] QSpinBox:focus,
    QMainWindow#mainWindow[themeContrast="high"] QTabBar::tab:focus {
        border: 2px solid palette(highlight);
    }
    """


def _configure_layout_density(window: MainWindow) -> None:
    for page in (window.query_page, window.settings_page, window.history_page):
        _set_layout(page.layout(), margins=(18, 16, 18, 18), spacing=12)

    for group in (
        window.connection_group,
        window.query_group,
        window.advanced_panel,
        window.mm_group,
        window.md_group,
        window.timing_group,
    ):
        _configure_group_layout(group)

    window.tabs.setObjectName("mainTabs")
    window.tabs.setDocumentMode(True)
    window.tabs.setElideMode(Qt.TextElideMode.ElideRight)
    window.details.setObjectName("detailsTabs")
    window.details.setDocumentMode(True)
    window.details.setMinimumWidth(320)


def _configure_group_layout(group: QGroupBox) -> None:
    _set_layout(group.layout(), margins=(14, 19, 14, 14), spacing=10)


def _set_layout(
    layout: QLayout | None,
    *,
    margins: tuple[int, int, int, int],
    spacing: int,
) -> None:
    if layout is None:
        return
    layout.setContentsMargins(*margins)
    layout.setSpacing(spacing)


def _configure_component_roles(window: MainWindow) -> None:
    _set_role(window.open_settings_button, "primary")
    _set_role(window.monitor_button, "primary")
    _set_role(window.query_button, "secondary")
    _set_role(window.advanced_toggle_button, "tertiary")
    _set_role(window.stop_button, "dangerStrong")
    _set_role(window.save_config_button, "primary")
    _set_role(window.refresh_history_button, "secondary")
    _set_role(window.export_button, "secondary")
    _set_role(window.html_export_button, "secondary")
    _set_role(window.delete_button, "danger")
    _set_role(window.delete_all_button, "dangerStrong")

    _set_panel_role(window.connection_group, "credentials")
    _set_panel_role(window.query_group, "query")
    _set_panel_role(window.advanced_panel, "advanced")
    _set_panel_role(window.mm_group, "controller")
    _set_panel_role(window.md_group, "controller")
    _set_panel_role(window.timing_group, "timing")

    window.context_label.setObjectName("contextSummary")
    window.state_label.setObjectName("stateLabel")
    window.settings_privacy_notice.setObjectName("privacyNotice")
    window.history_privacy_notice.setObjectName("privacyNotice")
    window.raw_view.setObjectName("rawConsole")
    window.diagnostics_list.setObjectName("diagnosticsList")


def _set_role(widget: QWidget, role: str) -> None:
    widget.setProperty("buttonRole", role)


def _set_panel_role(widget: QWidget, role: str) -> None:
    widget.setProperty("panelRole", role)


def _configure_tables(window: MainWindow) -> None:
    tables: tuple[QTableWidget, ...] = (
        window.result_table,
        window.md_table,
        window.history_table,
    )
    for table in tables:
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setCornerButtonEnabled(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(32)
        table.horizontalHeader().setHighlightSections(False)
        table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )


def _uses_high_contrast_palette(palette: QPalette) -> bool:
    role_pairs = (
        (QPalette.ColorRole.Window, QPalette.ColorRole.WindowText),
        (QPalette.ColorRole.Base, QPalette.ColorRole.Text),
        (QPalette.ColorRole.Highlight, QPalette.ColorRole.HighlightedText),
    )
    return all(
        _contrast_ratio(palette.color(background), palette.color(foreground)) >= 7.0
        for background, foreground in role_pairs
    )


def _contrast_ratio(first: QColor, second: QColor) -> float:
    lighter, darker = sorted(
        (_relative_luminance(first), _relative_luminance(second)),
        reverse=True,
    )
    return (lighter + 0.05) / (darker + 0.05)


def _relative_luminance(color: QColor) -> float:
    channels = (color.redF(), color.greenF(), color.blueF())
    linear = tuple(
        channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    )
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _configure_guidance(window: MainWindow) -> None:
    window.username_edit.setPlaceholderText("SSH 사용자 이름")
    window.source_ip_edit.setPlaceholderText("예: 192.0.2.10")
    window.destination_ip_edit.setPlaceholderText("예: 203.0.113.20")
    window.source_port_edit.setPlaceholderText("0-65535")
    window.destination_port_edit.setPlaceholderText("0-65535")
    window.mm_primary_host.setPlaceholderText("Primary MM IPv4")
    window.mm_standby_host.setPlaceholderText("Standby MM IPv4")


__all__ = ["apply_main_window_theme", "build_stylesheet"]
