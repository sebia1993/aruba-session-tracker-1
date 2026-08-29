"""Visual system for the Aruba Session Tracker Qt interface.

The operational widgets and their stable Developer Inspector identifiers live in
``main_window.py``.  This module deliberately limits itself to presentation and
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

    # MainWindow applies a legacy local stylesheet during construction.  Set the
    # complete theme last so one source of truth controls all presentation.
    window.setStyleSheet(build_stylesheet())


def build_stylesheet() -> str:
    """Return the self-contained QSS used by the desktop application."""

    return """
    /* Aruba Session Tracker — dense enterprise operations console */
    QMainWindow#mainWindow {
        background-color: #F3F6F9;
        color: #0F172A;
    }

    QMainWindow#mainWindow QWidget {
        color: #0F172A;
        selection-background-color: #CFE4FA;
        selection-color: #0B253F;
    }

    QTabWidget#mainTabs::pane {
        background-color: #F3F6F9;
        border: 0;
        top: -1px;
    }

    QTabWidget#mainTabs QTabBar::tab {
        min-height: 34px;
        padding: 0 18px;
        margin: 0 2px 0 0;
        color: #475569;
        background-color: #E8EDF3;
        border: 1px solid #CBD5E1;
        border-bottom: 0;
        border-top-left-radius: 7px;
        border-top-right-radius: 7px;
    }

    QTabWidget#mainTabs QTabBar::tab:selected {
        color: #0B4F82;
        background-color: #F3F6F9;
        border-color: #9FB3C8;
        font-weight: 700;
    }

    QTabWidget#mainTabs QTabBar::tab:hover:!selected {
        color: #163A59;
        background-color: #F8FAFC;
    }

    QTabWidget#mainTabs QTabBar::tab:focus {
        border: 2px solid #1976B9;
    }

    QTabWidget#detailsTabs::pane {
        background-color: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 7px;
        top: -1px;
    }

    QTabWidget#detailsTabs QTabBar::tab {
        min-height: 30px;
        padding: 0 13px;
        color: #52657A;
        background-color: #E8EDF3;
        border: 1px solid #CBD5E1;
        border-bottom: 0;
    }

    QTabWidget#detailsTabs QTabBar::tab:selected {
        color: #0B4F82;
        background-color: #FFFFFF;
        font-weight: 700;
    }

    QFrame#setupGuide {
        color: #17324D;
        background-color: #EAF2FA;
        border: 1px solid #9DBBD5;
        border-radius: 7px;
    }

    QGroupBox {
        margin-top: 12px;
        padding: 18px 14px 14px 14px;
        color: #17324D;
        background-color: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 8px;
        font-weight: 700;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 12px;
        padding: 0 6px;
        color: #17324D;
        background-color: #FFFFFF;
    }

    QLabel {
        background-color: transparent;
    }

    QLabel#contextSummary {
        min-height: 30px;
        padding: 3px 10px;
        color: #17324D;
        background-color: #EAF2FA;
        border: 1px solid #BED2E6;
        border-radius: 6px;
        font-weight: 600;
    }

    QLabel#stateLabel {
        min-height: 26px;
        padding: 2px 12px;
        color: #0B4F82;
        background-color: #DCECFB;
        border: 1px solid #9EC5E8;
        border-radius: 13px;
        font-weight: 700;
    }

    QLabel#privacyNotice {
        padding: 8px 10px;
        color: #5E4A18;
        background-color: #FFF8E7;
        border: 1px solid #E7C978;
        border-radius: 6px;
    }

    QLineEdit,
    QSpinBox {
        min-height: 32px;
        padding: 0 9px;
        color: #0F172A;
        background-color: #FFFFFF;
        border: 1px solid #AEBCCA;
        border-radius: 6px;
    }

    QLineEdit:hover,
    QSpinBox:hover {
        border-color: #7F96AB;
    }

    QLineEdit:focus,
    QSpinBox:focus {
        border: 2px solid #1976B9;
        padding-left: 8px;
        padding-right: 8px;
    }

    QLineEdit:disabled,
    QSpinBox:disabled {
        color: #7A8998;
        background-color: #EEF2F6;
        border-color: #D5DEE7;
    }

    QCheckBox {
        min-height: 30px;
        spacing: 8px;
        color: #263B50;
    }

    QPushButton {
        min-height: 32px;
        padding: 0 14px;
        color: #17324D;
        background-color: #FFFFFF;
        border: 1px solid #A9B8C7;
        border-radius: 6px;
        font-weight: 600;
    }

    QPushButton:hover {
        background-color: #F3F7FB;
        border-color: #6F8CA6;
    }

    QPushButton:pressed {
        background-color: #E3ECF5;
        border-color: #526F89;
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
        background-color: #EAF2FA;
        border-color: #9DBBD5;
    }

    QPushButton[buttonRole="secondary"]:hover {
        background-color: #DCEAF7;
        border-color: #6F9FC4;
    }

    QPushButton[buttonRole="tertiary"] {
        color: #0B4F82;
        background-color: transparent;
        border-color: transparent;
        padding-left: 8px;
        padding-right: 8px;
    }

    QPushButton[buttonRole="tertiary"]:hover,
    QPushButton[buttonRole="tertiary"]:checked {
        background-color: #EAF2FA;
        border-color: #9DBBD5;
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

    QTableWidget {
        color: #172A3D;
        background-color: #FFFFFF;
        alternate-background-color: #F6F9FC;
        border: 1px solid #C4D0DC;
        border-radius: 7px;
        gridline-color: #E2E8F0;
        outline: 0;
    }

    QTableWidget::item {
        min-height: 27px;
        padding: 4px 7px;
        border-bottom: 1px solid #E7EDF3;
    }

    QTableWidget::item:selected {
        color: #0B253F;
        background-color: #CFE4FA;
    }

    QTableWidget::item:focus {
        border: 1px solid #1976B9;
    }

    QHeaderView::section {
        min-height: 32px;
        padding: 4px 7px;
        color: #263B50;
        background-color: #E8EEF4;
        border: 0;
        border-right: 1px solid #CBD5E1;
        border-bottom: 1px solid #AEBCCA;
        font-weight: 700;
    }

    QPlainTextEdit#rawConsole {
        color: #DCE7F2;
        background-color: #111C27;
        border: 0;
        border-radius: 6px;
        padding: 8px;
        font-family: Consolas;
        selection-background-color: #28557D;
        selection-color: #FFFFFF;
    }

    QListWidget#diagnosticsList {
        color: #1E3347;
        background-color: #FFFFFF;
        border: 0;
        border-radius: 6px;
        outline: 0;
    }

    QListWidget#diagnosticsList::item {
        min-height: 28px;
        padding: 4px 8px;
        border-bottom: 1px solid #E7EDF3;
    }

    QListWidget#diagnosticsList::item:selected {
        color: #0B253F;
        background-color: #CFE4FA;
    }

    QSplitter::handle {
        background-color: #D8E1EA;
    }

    QSplitter::handle:horizontal {
        width: 6px;
        margin: 2px 1px;
    }

    QSplitter::handle:hover {
        background-color: #8FB5D4;
    }

    QStatusBar {
        color: #40566B;
        background-color: #E8EEF4;
        border-top: 1px solid #C4D0DC;
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
        _set_layout(page.layout(), margins=(18, 14, 18, 18), spacing=12)

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


def _configure_group_layout(group: QGroupBox) -> None:
    _set_layout(group.layout(), margins=(14, 18, 14, 14), spacing=10)


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

    window.context_label.setObjectName("contextSummary")
    window.state_label.setObjectName("stateLabel")
    window.settings_privacy_notice.setObjectName("privacyNotice")
    window.history_privacy_notice.setObjectName("privacyNotice")
    window.raw_view.setObjectName("rawConsole")
    window.diagnostics_list.setObjectName("diagnosticsList")


def _set_role(widget: QWidget, role: str) -> None:
    widget.setProperty("buttonRole", role)


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
        table.verticalHeader().setDefaultSectionSize(30)
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
