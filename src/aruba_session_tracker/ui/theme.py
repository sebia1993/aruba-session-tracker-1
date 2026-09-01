"""Approved Dark NOC Console visual system for the Qt desktop interface.

Operational widgets and their stable Developer Inspector identifiers remain in
``main_window.py``.  This module changes presentation only and installs local,
derived status/summary widgets through :mod:`noc_console`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QGroupBox,
    QLayout,
    QSizePolicy,
    QTableWidget,
    QWidget,
)

from aruba_session_tracker.ui.noc_console import install_dark_noc_console

if TYPE_CHECKING:
    from aruba_session_tracker.ui.main_window import MainWindow


_DEFAULT_FONT_FAMILY = "Malgun Gothic"
_DEFAULT_FONT_SIZE = 9
_HEADER_HEIGHT = 66


def apply_main_window_theme(window: MainWindow) -> None:
    """Apply the approved dark NOC presentation without replacing controls."""

    window.setObjectName("mainWindow")
    application = QApplication.instance()
    palette = application.palette() if isinstance(application, QApplication) else window.palette()
    window.setProperty(
        "themeContrast",
        "high" if _uses_high_contrast_palette(palette) else "normal",
    )
    if window.property("themeContrast") == "high":
        _clear_explicit_result_foregrounds(window)

    _configure_layout_density(window)
    _configure_component_roles(window)
    _configure_tables(window)
    _configure_guidance(window)
    controller = install_dark_noc_console(window)

    font = QFont(_DEFAULT_FONT_FAMILY, _DEFAULT_FONT_SIZE)
    window.setFont(font)
    if isinstance(application, QApplication):
        application.setFont(font)

    # MainWindow applies a minimal construction stylesheet. This complete local
    # stylesheet remains the single presentation source after startup.
    window.setStyleSheet(build_stylesheet())
    window.result_table.ensurePolished()
    result_table_chrome_height = (
        window.result_table.horizontalHeader().sizeHint().height()
        + window.result_table.horizontalScrollBar().sizeHint().height()
        + (2 * window.result_table.frameWidth())
    )
    window.result_table.setMinimumHeight(50 + result_table_chrome_height)
    window.nav_identity.setFixedHeight(_HEADER_HEIGHT)
    window.nav_identity.updateGeometry()
    controller.schedule_refresh()
    controller.schedule_layout()


def build_stylesheet() -> str:
    """Return a self-contained QSS implementation of Dark NOC Console V1."""

    return """
    /* Aruba Session Tracker — Dark NOC Console V1 */
    QMainWindow#mainWindow {
        background-color: #101720;
        color: #E8EFF6;
    }

    QMainWindow#mainWindow QWidget {
        color: #E8EFF6;
        selection-background-color: #294D6A;
        selection-color: #FFFFFF;
    }

    QMainWindow#mainWindow QWidget#qt_scrollarea_viewport,
    QMainWindow#mainWindow QWidget#centralWidget {
        background-color: #101720;
    }

    /* Reused product identity becomes the compact operational header. */
    QFrame#nocHeader {
        background-color: #0A1118;
        border: 0;
        border-bottom: 1px solid #2D4154;
    }

    QFrame#productIdentity {
        background-color: transparent;
        border: 0;
    }

    QFrame#nocHeader QLabel#productName {
        color: #FFFFFF;
        background-color: transparent;
        font-size: 11pt;
        font-weight: 800;
        letter-spacing: 1px;
    }

    QFrame#nocHeader QLabel#productMeta {
        color: #91A5B8;
        background-color: transparent;
        font-size: 8pt;
        font-weight: 600;
        letter-spacing: .5px;
    }

    QFrame#headerChip {
        min-width: 72px;
        background-color: #16212D;
        border: 1px solid #2D4154;
        border-radius: 6px;
    }

    QFrame#headerChip[chipRole="success"] {
        border-color: #245E48;
        background-color: #132A24;
    }

    QFrame#headerChip[chipRole="info"] {
        border-color: #2F5E75;
        background-color: #152934;
    }

    QLabel#headerChipLabel {
        color: #748A9E;
        font-size: 7pt;
        font-weight: 800;
        letter-spacing: .7px;
    }

    QLabel#headerChipValue {
        color: #D8E4EE;
        font-size: 8pt;
        font-weight: 700;
    }

    /* Existing QTabWidget/QTabBar retained as compact horizontal navigation. */
    QTabWidget#mainTabs {
        background-color: #101720;
    }

    QTabWidget#mainTabs::pane {
        background-color: #101720;
        border: 0;
        top: -1px;
    }

    QTabBar#mainNavigationTabs {
        background-color: #0D141C;
        border-bottom: 1px solid #2D4154;
    }

    QTabBar#mainNavigationTabs::tab {
        width: 176px;
        min-height: 40px;
        padding: 0 16px;
        margin: 0;
        color: #91A5B8;
        background-color: #0D141C;
        border: 2px solid transparent;
        border-bottom: 3px solid transparent;
        font-weight: 650;
    }

    QTabBar#mainNavigationTabs::tab:selected {
        color: #FFFFFF;
        background-color: #1C2937;
        border-bottom: 3px solid #2F80ED;
        font-weight: 800;
    }

    QTabBar#mainNavigationTabs::tab:hover:!selected {
        color: #E8EFF6;
        background-color: #16212D;
    }

    QTabBar#mainNavigationTabs::tab:focus {
        border: 2px solid #42B7C8;
        border-bottom: 3px solid #42B7C8;
    }

    /* Pages and engineering surfaces. */
    QGroupBox {
        margin-top: 12px;
        padding: 16px 12px 11px 12px;
        color: #DCE8F2;
        background-color: #16212D;
        border: 1px solid #2D4154;
        border-radius: 8px;
        font-weight: 750;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 12px;
        padding: 0 7px;
        color: #BFD0DE;
        background-color: #16212D;
        font-size: 9pt;
        font-weight: 800;
    }

    QGroupBox[panelRole="query"] {
        border-left: 3px solid #2F80ED;
    }

    QGroupBox[panelRole="credentials"] {
        background-color: #141F2A;
        border-color: #293B4C;
    }

    QGroupBox[panelRole="credentials"]::title {
        background-color: #141F2A;
    }

    QGroupBox[panelRole="advanced"] {
        background-color: #121C26;
        border-style: dashed;
        border-color: #3B556C;
    }

    QGroupBox[panelRole="advanced"]::title {
        background-color: #121C26;
    }

    QGroupBox[panelRole="controller"] {
        border-left: 3px solid #42B7C8;
    }

    QGroupBox[panelRole="timing"] {
        border-left: 3px solid #71869A;
    }

    QFrame#setupGuide {
        color: #C9E8F0;
        background-color: #132832;
        border: 1px solid #2F5B68;
        border-left: 3px solid #42B7C8;
        border-radius: 7px;
    }

    QFrame#flowEndpointCard {
        min-height: 76px;
        background-color: #1C2937;
        border: 1px solid #344B60;
        border-radius: 7px;
    }

    QFrame#flowEndpointCard[endpointRole="source"] {
        border-top: 3px solid #2F80ED;
    }

    QFrame#flowEndpointCard[endpointRole="destination"] {
        border-top: 3px solid #42B7C8;
    }

    QLabel#flowEyebrow {
        color: #7F96AA;
        font-size: 8pt;
        font-weight: 800;
        letter-spacing: 1px;
    }

    QLabel#flowFieldLabel {
        color: #D8E4EE;
        font-size: 9pt;
        font-weight: 700;
    }

    QFrame#flowDirectionPanel {
        min-width: 118px;
        background-color: transparent;
        border: 0;
    }

    QLabel#flowDirectionCaption {
        color: #748A9E;
        font-size: 8pt;
        font-weight: 700;
    }

    QLabel#flowDirectionLabel {
        min-height: 27px;
        padding: 1px 10px;
        color: #BEEAF0;
        background-color: #16303A;
        border: 1px solid #326474;
        border-radius: 13px;
        font-weight: 750;
    }

    QLabel#flowDirectionLabel[directionRole="forward"] {
        color: #C1CED9;
        background-color: #22303D;
        border-color: #3B4E5F;
    }

    QFrame#queryActionBar,
    QFrame#historyToolbar {
        background-color: #121C26;
        border: 1px solid #2D4154;
        border-radius: 7px;
    }

    QFrame#resultsHeader {
        background-color: transparent;
        border: 0;
    }

    QLabel#sectionTitle {
        color: #E8EFF6;
        font-size: 11pt;
        font-weight: 800;
    }

    QLabel#sectionHint,
    QLabel#stateCaption {
        color: #91A5B8;
        font-size: 8pt;
    }

    QLabel#stateCaption {
        font-weight: 700;
    }

    QLabel#contextSummary {
        min-height: 30px;
        padding: 4px 10px;
        color: #B8CEDD;
        background-color: #142431;
        border: 1px solid #2C465A;
        border-radius: 6px;
        font-weight: 600;
    }

    QLabel#stateLabel {
        min-height: 28px;
        padding: 2px 12px;
        color: #B8C6D2;
        background-color: #22303D;
        border: 1px solid #405466;
        border-radius: 14px;
        font-weight: 800;
    }

    QLabel#stateLabel[stateRole="active"] {
        color: #B9DCF8;
        background-color: #183653;
        border-color: #35688E;
    }

    QLabel#stateLabel[stateRole="success"] {
        color: #C2F0D9;
        background-color: #163629;
        border-color: #2B7553;
    }

    QLabel#stateLabel[stateRole="warning"] {
        color: #F6D89C;
        background-color: #3A2D18;
        border-color: #80612B;
    }

    QLabel#stateLabel[stateRole="danger"] {
        color: #F7C0C5;
        background-color: #3B2026;
        border-color: #88424A;
    }

    QLabel#emptyState {
        min-height: 34px;
        padding: 8px 12px;
        color: #91A5B8;
        background-color: #121C26;
        border: 1px dashed #3B556C;
        border-radius: 7px;
    }

    QLabel#storageStatus {
        min-height: 24px;
        padding: 4px 9px;
        color: #B9CBD8;
        background-color: #14232F;
        border-left: 3px solid #42B7C8;
        border-radius: 4px;
    }

    QLabel#toolbarSectionLabel {
        min-height: 28px;
        padding: 0 3px 0 9px;
        color: #7F96AA;
        font-size: 8pt;
        font-weight: 800;
    }

    QLabel#privacyNotice {
        padding: 9px 11px;
        color: #E7D3A4;
        background-color: #302817;
        border: 1px solid #6F5B2A;
        border-left: 3px solid #E4A83C;
        border-radius: 7px;
    }

    QLabel {
        background-color: transparent;
    }

    /* Derived KPI strip. */
    QFrame#metricStrip {
        background-color: transparent;
        border: 0;
    }

    QFrame#metricCard {
        min-height: 42px;
        background-color: #16212D;
        border: 1px solid #2D4154;
        border-radius: 7px;
    }

    QFrame#metricCard[metricRole="active"] {
        border-top: 2px solid #2DBE78;
    }

    QFrame#metricCard[metricRole="changes"] {
        border-top: 2px solid #E4A83C;
    }

    QFrame#metricCard[metricRole="controllers"] {
        border-top: 2px solid #42B7C8;
    }

    QLabel#metricValue {
        color: #FFFFFF;
        font-size: 16pt;
        font-weight: 850;
    }

    QLabel#metricLabel {
        color: #7F96AA;
        font-size: 7pt;
        font-weight: 800;
        letter-spacing: .8px;
    }

    /* Input controls. */
    QLineEdit,
    QSpinBox {
        min-height: 32px;
        padding: 0 10px;
        color: #E8EFF6;
        background-color: #0F1A24;
        border: 1px solid #3B5266;
        border-radius: 6px;
        selection-background-color: #29597E;
        selection-color: #FFFFFF;
    }

    QLineEdit:hover,
    QSpinBox:hover {
        border-color: #55748D;
        background-color: #111E29;
    }

    QLineEdit:focus,
    QSpinBox:focus {
        border: 2px solid #2F80ED;
        padding-left: 9px;
        padding-right: 9px;
        background-color: #101D28;
    }

    QLineEdit:disabled,
    QSpinBox:disabled {
        color: #677B8D;
        background-color: #17212A;
        border-color: #293844;
    }

    QCheckBox {
        min-height: 30px;
        spacing: 8px;
        color: #C7D4DF;
    }

    QCheckBox::indicator {
        width: 16px;
        height: 16px;
    }

    QPushButton {
        min-height: 32px;
        padding: 0 15px;
        color: #D8E4EE;
        background-color: #1C2937;
        border: 1px solid #3B556C;
        border-radius: 6px;
        font-weight: 650;
    }

    QPushButton:hover {
        color: #FFFFFF;
        background-color: #223243;
        border-color: #55748D;
    }

    QPushButton:pressed {
        background-color: #182532;
        border-color: #2F80ED;
    }

    QPushButton:focus {
        border: 2px solid #42B7C8;
    }

    QPushButton:disabled {
        color: #617485;
        background-color: #17212A;
        border-color: #293844;
    }

    QPushButton[buttonRole="primary"] {
        color: #FFFFFF;
        background-color: #1769C2;
        border-color: #2F80ED;
        font-weight: 800;
    }

    QPushButton[buttonRole="primary"]:hover {
        background-color: #1F78D1;
        border-color: #5A9BEF;
    }

    QPushButton[buttonRole="primary"]:pressed {
        background-color: #12549D;
    }

    QPushButton[buttonRole="secondary"] {
        color: #C7E0F4;
        background-color: #183149;
        border-color: #356489;
    }

    QPushButton[buttonRole="secondary"]:hover {
        background-color: #1C3C59;
        border-color: #4B7EA4;
    }

    QPushButton[buttonRole="tertiary"] {
        min-height: 30px;
        color: #90CAF4;
        background-color: transparent;
        border-color: transparent;
        padding-left: 9px;
        padding-right: 9px;
    }

    QPushButton[buttonRole="tertiary"]:hover,
    QPushButton[buttonRole="tertiary"]:checked {
        background-color: #172B3C;
        border-color: #31516A;
    }

    QPushButton[buttonRole="danger"] {
        color: #F4B8BD;
        background-color: #2D1D22;
        border-color: #714049;
    }

    QPushButton[buttonRole="danger"]:hover {
        color: #FFFFFF;
        background-color: #A83F49;
        border-color: #E05C65;
    }

    QPushButton[buttonRole="dangerStrong"] {
        color: #FFFFFF;
        background-color: #A23B45;
        border-color: #E05C65;
        font-weight: 800;
    }

    QPushButton[buttonRole="dangerStrong"]:hover {
        background-color: #BF4853;
    }

    QPushButton[buttonRole="primary"]:disabled,
    QPushButton[buttonRole="secondary"]:disabled,
    QPushButton[buttonRole="tertiary"]:disabled,
    QPushButton[buttonRole="danger"]:disabled,
    QPushButton[buttonRole="dangerStrong"]:disabled {
        color: #617485;
        background-color: #17212A;
        border-color: #293844;
        font-weight: 600;
    }

    QPushButton[buttonRole="primary"]:focus,
    QPushButton[buttonRole="dangerStrong"]:focus {
        border: 3px solid #42B7C8;
        padding-left: 12px;
        padding-right: 12px;
    }

    /* Dense operational data grids. */
    QTableWidget {
        color: #DCE6EF;
        background-color: #111A23;
        alternate-background-color: #151F2A;
        border: 1px solid #2D4154;
        border-radius: 7px;
        gridline-color: #22313E;
        outline: 0;
        selection-background-color: #274A66;
        selection-color: #FFFFFF;
    }

    QTableWidget::item {
        min-height: 27px;
        padding: 4px 8px;
        border-bottom: 1px solid #202E3A;
    }

    QTableWidget::item:selected {
        color: #FFFFFF;
        background-color: #294D6A;
    }

    QTableWidget::item:focus {
        border: 1px solid #42B7C8;
    }

    QTableWidget:focus,
    QListWidget:focus,
    QPlainTextEdit:focus {
        border: 2px solid #42B7C8;
    }

    QCheckBox:focus {
        border: 2px solid #42B7C8;
        border-radius: 4px;
    }

    QHeaderView::section {
        min-height: 32px;
        padding: 4px 8px;
        color: #BFD0DE;
        background-color: #1C2937;
        border: 0;
        border-right: 1px solid #2D4154;
        border-bottom: 1px solid #3B556C;
        font-size: 8pt;
        font-weight: 800;
    }

    QAbstractScrollArea::corner {
        background-color: #16212D;
        border: 0;
    }

    QScrollBar:vertical {
        width: 12px;
        margin: 0;
        background-color: #101720;
    }

    QScrollBar::handle:vertical {
        min-height: 28px;
        margin: 2px;
        background-color: #4D667A;
        border-radius: 4px;
    }

    QScrollBar::handle:vertical:hover {
        background-color: #65849C;
    }

    QScrollBar:horizontal {
        height: 12px;
        margin: 0;
        background-color: #101720;
    }

    QScrollBar::handle:horizontal {
        min-width: 28px;
        margin: 2px;
        background-color: #4D667A;
        border-radius: 4px;
    }

    QScrollBar::handle:horizontal:hover {
        background-color: #65849C;
    }

    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {
        height: 12px;
        background-color: #1C2937;
        border: 1px solid #3B556C;
    }

    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 12px;
        background-color: #1C2937;
        border: 1px solid #3B556C;
    }

    /* Investigation detail area. */
    QTabWidget#detailsTabs::pane {
        background-color: #0A1118;
        border: 1px solid #2D4154;
        border-radius: 7px;
        top: -1px;
    }

    QTabBar#detailsNavigationTabs::tab {
        min-height: 31px;
        padding: 0 14px;
        color: #91A5B8;
        background-color: #16212D;
        border: 1px solid #2D4154;
        border-bottom: 0;
        font-size: 8pt;
    }

    QTabBar#detailsNavigationTabs::tab:selected {
        color: #FFFFFF;
        background-color: #0A1118;
        border-color: #3B556C;
        font-weight: 800;
    }

    QWidget#sessionDetailPage,
    QScrollArea#sessionDetailScroll,
    QWidget#sessionDetailContent {
        background-color: #0A1118;
        border: 0;
    }

    QLabel#detailEyebrow {
        color: #42B7C8;
        font-size: 8pt;
        font-weight: 850;
        letter-spacing: .8px;
    }

    QLabel#detailHint {
        color: #748A9E;
        font-size: 8pt;
    }

    QFrame#sessionFlowCard {
        background-color: #101A24;
        border: 1px solid #2D4154;
        border-radius: 7px;
    }

    QFrame#detailEndpoint {
        background-color: transparent;
        border: 0;
    }

    QLabel#detailEndpointLabel,
    QLabel#detailFactLabel {
        color: #70879B;
        font-size: 7pt;
        font-weight: 850;
        letter-spacing: .7px;
    }

    QLabel#detailEndpointValue {
        color: #E8EFF6;
        font-size: 8pt;
        font-weight: 750;
    }

    QLabel#detailProtocol {
        min-width: 48px;
        max-width: 60px;
        color: #7DD5E0;
        font-size: 8pt;
        font-weight: 800;
    }

    QFrame#detailFacts {
        background-color: transparent;
        border: 0;
    }

    QFrame#detailFact {
        min-height: 44px;
        background-color: #101A24;
        border: 1px solid #263A4B;
        border-radius: 6px;
    }

    QLabel#detailFactValue {
        color: #D8E4EE;
        font-size: 8pt;
        font-weight: 700;
    }

    QMainWindow#mainWindow QPlainTextEdit#rawConsole {
        color: #C8D6E2;
        background-color: #0A1118;
        border: 0;
        border-radius: 6px;
        padding: 10px;
        font-family: Consolas;
        selection-background-color: #28557D;
        selection-color: #FFFFFF;
    }

    QMainWindow#mainWindow QListWidget#diagnosticsList {
        color: #D8E4EE;
        background-color: #0D161F;
        border: 0;
        border-radius: 6px;
        outline: 0;
    }

    QListWidget#diagnosticsList::item {
        min-height: 29px;
        padding: 5px 9px;
        border-bottom: 1px solid #22313E;
    }

    QListWidget#diagnosticsList::item:selected {
        color: #FFFFFF;
        background-color: #294D6A;
    }

    QSplitter::handle {
        background-color: #22313E;
    }

    QSplitter::handle:horizontal {
        width: 7px;
        margin: 2px 1px;
    }

    QSplitter::handle:vertical {
        height: 7px;
        margin: 1px 2px;
    }

    QSplitter::handle:hover {
        background-color: #3B607A;
    }

    QStatusBar {
        min-height: 25px;
        color: #91A5B8;
        background-color: #0A1118;
        border-top: 1px solid #2D4154;
    }

    QStatusBar::item {
        border: 0;
    }

    QToolTip {
        color: #FFFFFF;
        background-color: #1C2937;
        border: 1px solid #55748D;
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

    QMainWindow#mainWindow[themeContrast="high"] QFrame#nocHeader QLabel#productName,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#nocHeader QLabel#productMeta {
        color: palette(window-text);
    }

    QMainWindow#mainWindow[themeContrast="high"] QFrame#nocHeader,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#headerChip,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#setupGuide,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#flowEndpointCard,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#queryActionBar,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#historyToolbar,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#metricCard,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#sessionFlowCard,
    QMainWindow#mainWindow[themeContrast="high"] QFrame#detailFact,
    QMainWindow#mainWindow[themeContrast="high"] QGroupBox,
    QMainWindow#mainWindow[themeContrast="high"] QGroupBox::title,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#contextSummary,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#stateLabel,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#privacyNotice,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#emptyState,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#storageStatus,
    QMainWindow#mainWindow[themeContrast="high"] QLabel#flowDirectionLabel,
    QMainWindow#mainWindow[themeContrast="high"] QTabWidget#mainTabs::pane,
    QMainWindow#mainWindow[themeContrast="high"] QTabWidget#detailsTabs::pane {
        color: palette(window-text);
        background-color: palette(window);
        border-color: palette(mid);
    }

    QMainWindow#mainWindow[themeContrast="high"] QTabWidget#mainTabs,
    QMainWindow#mainWindow[themeContrast="high"] QTabBar#mainNavigationTabs {
        background-color: palette(window);
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

    QMainWindow#mainWindow[themeContrast="high"] QScrollBar:vertical,
    QMainWindow#mainWindow[themeContrast="high"] QScrollBar:horizontal {
        background-color: palette(window);
    }

    QMainWindow#mainWindow[themeContrast="high"] QScrollBar::handle:vertical,
    QMainWindow#mainWindow[themeContrast="high"] QScrollBar::handle:horizontal {
        background-color: palette(highlight);
        border: 1px solid palette(window-text);
    }

    QMainWindow#mainWindow[themeContrast="high"] QScrollBar::add-line,
    QMainWindow#mainWindow[themeContrast="high"] QScrollBar::sub-line {
        background-color: palette(button);
        border: 1px solid palette(highlight);
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
    QMainWindow#mainWindow[themeContrast="high"] QCheckBox:focus,
    QMainWindow#mainWindow[themeContrast="high"] QTableWidget:focus,
    QMainWindow#mainWindow[themeContrast="high"] QListWidget:focus,
    QMainWindow#mainWindow[themeContrast="high"] QPlainTextEdit:focus,
    QMainWindow#mainWindow[themeContrast="high"] QTabBar::tab:focus {
        border: 2px solid palette(highlight);
    }
    """


def _configure_layout_density(window: MainWindow) -> None:
    for page in (window.query_page, window.settings_page, window.history_page):
        _set_layout(page.layout(), margins=(14, 10, 14, 14), spacing=8)

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
    window.tabs.tabBar().setObjectName("mainNavigationTabs")
    window.tabs.setDocumentMode(True)
    window.tabs.setElideMode(Qt.TextElideMode.ElideNone)
    window.details.setObjectName("detailsTabs")
    window.details.tabBar().setObjectName("detailsNavigationTabs")
    window.details.setDocumentMode(True)
    window.details.setMinimumWidth(0)
    window.details.setMinimumHeight(180)
    window.advanced_panel.setSizePolicy(
        QSizePolicy.Policy.Preferred,
        QSizePolicy.Policy.Fixed,
    )


def _configure_group_layout(group: QGroupBox) -> None:
    _set_layout(group.layout(), margins=(12, 16, 12, 10), spacing=8)


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
        table.verticalHeader().setDefaultSectionSize(30)
        table.horizontalHeader().setHighlightSections(False)
        table.horizontalHeader().setDefaultAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        )

    # Presentation-only visual order: state and protocol first, then the flow.
    result_header = window.result_table.horizontalHeader()
    desired_logical_order = (14, 1, 2, 3, 4, 5, 0, 12, 13, 15, 6, 7, 8, 9, 10, 11)
    for visual_index, logical_index in enumerate(desired_logical_order):
        current = result_header.visualIndex(logical_index)
        if current != visual_index:
            result_header.moveSection(current, visual_index)


def _clear_explicit_result_foregrounds(window: MainWindow) -> None:
    """Let the native high-contrast palette own all result-cell text colors."""

    for row in range(window.result_table.rowCount()):
        for column in (13, 14, 15):
            item = window.result_table.item(row, column)
            if item is not None:
                item.setForeground(QBrush())


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
