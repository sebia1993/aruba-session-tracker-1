"""Presentation-only Dark NOC Console composition for the Qt desktop UI.

This module deliberately reuses the operational widgets built by ``MainWindow``.
It adds only local presentation widgets, rearranges existing containers, and
derives every displayed metric from UI state that already exists in memory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QObject, QPointF, QRectF, QSize, Qt, QTimer
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProxyStyle,
    QStyle,
    QStyleOption,
    QStyleOptionTab,
    QTabBar,
    QTableWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aruba_session_tracker.ui.main_window import MainWindow


_DASH = "—"
_SIDE_DETAIL_BREAKPOINT = 1200


class _HorizontalRailTabStyle(QProxyStyle):
    """Keep labels horizontal while the existing QTabBar is on the west side."""

    def sizeFromContents(
        self,
        content_type: QStyle.ContentsType,
        option: QStyleOption,
        size: QSize,
        widget: QWidget | None = None,
    ) -> QSize:
        calculated = super().sizeFromContents(content_type, option, size, widget)
        if content_type == QStyle.ContentsType.CT_TabBarTab:
            return QSize(184, max(52, calculated.height()))
        return calculated

    def drawControl(
        self,
        element: QStyle.ControlElement,
        option: QStyleOption,
        painter: QPainter,
        widget: QWidget | None = None,
    ) -> None:
        if (
            element == QStyle.ControlElement.CE_TabBarTabLabel
            and isinstance(option, QStyleOptionTab)
        ):
            horizontal = QStyleOptionTab(option)
            horizontal.shape = QTabBar.Shape.RoundedNorth
            super().drawControl(element, horizontal, painter, widget)
            return
        super().drawControl(element, option, painter, widget)


class _NocConsoleController(QObject):
    """Synchronize presentation-only cards with existing operational widgets."""

    def __init__(self, window: MainWindow) -> None:
        super().__init__(window)
        self._window = window
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.timeout.connect(self.refresh)
        self._layout_timer = QTimer(self)
        self._layout_timer.setSingleShot(True)
        self._layout_timer.timeout.connect(self._apply_detail_orientation)
        self._metric_values: dict[str, QLabel] = {}
        self._detail_values: dict[str, QLabel] = {}
        self._header_values: dict[str, QLabel] = {}

        self._install_shell()
        self._install_metrics()
        self._install_detail_summary()
        self._connect_existing_state()
        window.installEventFilter(self)
        self.schedule_refresh()
        self.schedule_layout()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self._window and event.type() == QEvent.Type.Resize:
            self.schedule_layout()
        return super().eventFilter(watched, event)

    def schedule_refresh(self, *_args: object) -> None:
        if not self._refresh_timer.isActive():
            self._refresh_timer.start(0)

    def schedule_layout(self, *_args: object) -> None:
        if not self._layout_timer.isActive():
            self._layout_timer.start(0)

    def refresh(self) -> None:
        self._refresh_header()
        self._refresh_metrics()
        self._refresh_detail()
        self._refresh_status_cells()

    def _install_shell(self) -> None:
        window = self._window
        window.tabs.setTabPosition(QTabWidget.TabPosition.West)
        window.tabs.setUsesScrollButtons(False)
        window.tabs.tabBar().setExpanding(False)
        window.tabs.tabBar().setDrawBase(False)
        window.tabs.tabBar().setIconSize(QSize(18, 18))

        tab_style = _HorizontalRailTabStyle()
        tab_style.setParent(window.tabs.tabBar())
        window.tabs.tabBar().setStyle(tab_style)
        window._dark_noc_tab_style = tab_style  # type: ignore[attr-defined]

        for index, icon_name in enumerate(("query", "settings", "history")):
            window.tabs.setTabIcon(index, _navigation_icon(icon_name))

        # Reuse the existing identity frame instead of creating a second product
        # header. Reparenting removes it from the QTabWidget corner safely.
        window.nav_identity.setParent(window.central_root)
        window.nav_identity.setObjectName("nocHeader")
        header_layout = window.nav_identity.layout()
        if header_layout is None:
            header_layout = QHBoxLayout(window.nav_identity)
        while header_layout.count():
            item = header_layout.takeAt(0)
            if item is not None and item.widget() is not None:
                item.widget().setParent(window.nav_identity)
        header_layout.setContentsMargins(18, 9, 18, 9)
        header_layout.setSpacing(10)

        title_block = QFrame(window.nav_identity)
        title_block.setObjectName("productIdentity")
        title_layout = QVBoxLayout(title_block)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(0)
        window.product_name_label.setParent(title_block)
        window.product_meta_label.setParent(title_block)
        window.product_name_label.setObjectName("productName")
        window.product_meta_label.setObjectName("productMeta")
        window.product_meta_label.setText(
            f"NETWORK SESSION INVESTIGATION CONSOLE · v{_version_text(window)}"
        )
        title_layout.addWidget(window.product_name_label)
        title_layout.addWidget(window.product_meta_label)
        header_layout.addWidget(title_block)
        header_layout.addStretch(1)

        for key, label, value, role in (
            ("mm", "MM", "설정 0/2", "neutral"),
            ("md", "MD", "설정 0/4", "neutral"),
            ("poll", "POLL", _DASH, "info"),
            ("last", "LAST SEEN", _DASH, "neutral"),
        ):
            chip = _header_chip(label, value, role, window.nav_identity)
            header_layout.addWidget(chip)
            value_label = chip.findChild(QLabel, "headerChipValue")
            if value_label is not None:
                self._header_values[key] = value_label

        local_chip = _header_chip("MODE", "LOCAL · READ ONLY", "success", window.nav_identity)
        header_layout.addWidget(local_chip)

        window.state_label.setParent(window.nav_identity)
        window.state_label.setObjectName("stateLabel")
        window.state_label.setMinimumWidth(82)
        window.state_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header_layout.addWidget(window.state_label)
        window.state_caption.setVisible(False)

        window.nav_identity.setFixedHeight(66)
        window.central_layout.insertWidget(0, window.nav_identity)

    def _install_metrics(self) -> None:
        window = self._window
        result_layout = window.result_table.parentWidget().layout()
        if result_layout is None:
            return
        strip = QFrame(window.result_table.parentWidget())
        strip.setObjectName("metricStrip")
        strip_layout = QHBoxLayout(strip)
        strip_layout.setContentsMargins(0, 0, 0, 0)
        strip_layout.setSpacing(8)

        definitions = (
            ("active", "ACTIVE FLOWS"),
            ("rows", "VISIBLE ROWS"),
            ("changes", "CHANGED FLOWS"),
            ("controllers", "CONTROLLERS"),
        )
        for key, label in definitions:
            card = QFrame(strip)
            card.setObjectName("metricCard")
            card.setProperty("metricRole", key)
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(12, 8, 12, 8)
            card_layout.setSpacing(0)
            value_label = QLabel("0", card)
            value_label.setObjectName("metricValue")
            caption = QLabel(label, card)
            caption.setObjectName("metricLabel")
            card_layout.addWidget(value_label)
            card_layout.addWidget(caption)
            strip_layout.addWidget(card, 1)
            self._metric_values[key] = value_label

        insertion_index = result_layout.indexOf(window.result_empty_label)
        if insertion_index < 0:
            insertion_index = result_layout.indexOf(window.result_table)
        result_layout.insertWidget(max(0, insertion_index), strip)
        window.metric_strip = strip  # type: ignore[attr-defined]

    def _install_detail_summary(self) -> None:
        window = self._window
        page = QWidget(window.details)
        page.setObjectName("sessionDetailPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(10)

        heading_row = QHBoxLayout()
        heading = QLabel("SELECTED SESSION", page)
        heading.setObjectName("detailEyebrow")
        self._detail_values["hint"] = QLabel(
            "세션 행을 선택하면 조사 요약을 표시합니다.", page
        )
        self._detail_values["hint"].setObjectName("detailHint")
        heading_row.addWidget(heading)
        heading_row.addStretch(1)
        heading_row.addWidget(self._detail_values["hint"])
        layout.addLayout(heading_row)

        flow = QFrame(page)
        flow.setObjectName("sessionFlowCard")
        flow_layout = QHBoxLayout(flow)
        flow_layout.setContentsMargins(14, 12, 14, 12)
        flow_layout.setSpacing(12)

        source_block = _detail_endpoint("SOURCE", page)
        destination_block = _detail_endpoint("DESTINATION", page)
        source_value = source_block.findChild(QLabel, "detailEndpointValue")
        destination_value = destination_block.findChild(QLabel, "detailEndpointValue")
        if source_value is not None:
            self._detail_values["source"] = source_value
        if destination_value is not None:
            self._detail_values["destination"] = destination_value

        protocol = QLabel(_DASH, page)
        protocol.setObjectName("detailProtocol")
        protocol.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._detail_values["protocol"] = protocol

        flow_layout.addWidget(source_block, 1)
        flow_layout.addWidget(protocol)
        flow_layout.addWidget(destination_block, 1)
        layout.addWidget(flow)

        facts = QFrame(page)
        facts.setObjectName("detailFacts")
        facts_layout = QGridLayout(facts)
        facts_layout.setContentsMargins(0, 0, 0, 0)
        facts_layout.setHorizontalSpacing(8)
        facts_layout.setVerticalSpacing(8)
        fields = (
            ("status", "STATUS"),
            ("controller", "CONTROLLER"),
            ("flags", "FLAGS"),
            ("last_seen", "LAST SEEN"),
            ("packets", "PACKETS"),
            ("bytes", "BYTES"),
            ("age", "AGE"),
            ("cpu", "CPU"),
        )
        for index, (key, label) in enumerate(fields):
            fact = QFrame(facts)
            fact.setObjectName("detailFact")
            fact_layout = QVBoxLayout(fact)
            fact_layout.setContentsMargins(10, 7, 10, 7)
            fact_layout.setSpacing(1)
            caption = QLabel(label, fact)
            caption.setObjectName("detailFactLabel")
            value = QLabel(_DASH, fact)
            value.setObjectName("detailFactValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            fact_layout.addWidget(caption)
            fact_layout.addWidget(value)
            facts_layout.addWidget(fact, index // 4, index % 4)
            self._detail_values[key] = value
        layout.addWidget(facts)
        layout.addStretch(1)

        window.details.insertTab(0, page, "DETAILS")
        window.details.setTabText(1, "RAW CLI")
        window.details.setTabText(2, "DIAGNOSTICS")
        window.details.setAccessibleDescription(
            "선택 세션 요약, Raw CLI와 진단 이벤트를 전환합니다."
        )
        window.session_detail_page = page  # type: ignore[attr-defined]

    def _connect_existing_state(self) -> None:
        window = self._window
        model = window.result_table.model()
        model.rowsInserted.connect(self.schedule_refresh)
        model.rowsRemoved.connect(self.schedule_refresh)
        model.modelReset.connect(self.schedule_refresh)
        model.dataChanged.connect(self.schedule_refresh)
        window.result_table.itemSelectionChanged.connect(self.schedule_refresh)
        window.session_interval.valueChanged.connect(self.schedule_refresh)
        window.mm_primary_host.textChanged.connect(self.schedule_refresh)
        window.mm_standby_host.textChanged.connect(self.schedule_refresh)
        window.mm_primary_enabled.toggled.connect(self.schedule_refresh)
        window.mm_standby_enabled.toggled.connect(self.schedule_refresh)
        window.md_table.itemChanged.connect(self.schedule_refresh)
        window.raw_diagnostics_toggle.toggled.connect(self.schedule_layout)
        window.advanced_toggle_button.toggled.connect(self.schedule_layout)
        window.tabs.currentChanged.connect(self.schedule_layout)

    def _apply_detail_orientation(self) -> None:
        window = self._window
        use_side_panel = window.width() >= _SIDE_DETAIL_BREAKPOINT
        orientation = (
            Qt.Orientation.Horizontal if use_side_panel else Qt.Orientation.Vertical
        )
        window.result_splitter.setOrientation(orientation)
        if use_side_panel:
            window.details.setMinimumWidth(340)
            window.details.setMinimumHeight(0)
            available = max(window.result_splitter.width(), 720)
            window.result_splitter.setSizes([max(380, available - 360), 360])
        else:
            window.details.setMinimumWidth(0)
            window.details.setMinimumHeight(190)
            available = max(window.result_splitter.height(), 360)
            window.result_splitter.setSizes([max(150, available - 210), 210])

    def _refresh_header(self) -> None:
        window = self._window
        mm_total = 2
        mm_configured = sum(
            1
            for enabled, host in (
                (window.mm_primary_enabled, window.mm_primary_host),
                (window.mm_standby_enabled, window.mm_standby_host),
            )
            if enabled.isChecked() and bool(host.text().strip())
        )
        md_total = window.md_table.rowCount()
        md_configured = 0
        for row in range(md_total):
            enabled = window.md_table.item(row, 0)
            host = window.md_table.item(row, 2)
            if (
                enabled is not None
                and enabled.checkState() == Qt.CheckState.Checked
                and host is not None
                and bool(host.text().strip())
            ):
                md_configured += 1
        self._set_header("mm", f"설정 {mm_configured}/{mm_total}")
        self._set_header("md", f"설정 {md_configured}/{md_total}")
        self._set_header("poll", f"{window.session_interval.value()}s")

        latest_values: list[str] = []
        for row in range(window.result_table.rowCount()):
            item = window.result_table.item(row, 12)
            if item is not None and item.text().strip() not in ("", "-"):
                latest_values.append(item.text().strip())
        self._set_header("last", max(latest_values) if latest_values else _DASH)

    def _refresh_metrics(self) -> None:
        table = self._window.result_table
        active_flows: set[tuple[str, str, str, str, str]] = set()
        changed_flows: set[tuple[str, str, str, str, str]] = set()
        controllers: set[str] = set()
        for row in range(table.rowCount()):
            controller = _item_text(table, row, 0)
            protocol = _item_text(table, row, 1)
            source_ip = _item_text(table, row, 2)
            source_port = _item_text(table, row, 3)
            destination_ip = _item_text(table, row, 4)
            destination_port = _item_text(table, row, 5)
            status = _item_text(table, row, 14)
            flow = (protocol, source_ip, source_port, destination_ip, destination_port)
            if controller not in ("", "-"):
                controllers.add(controller)
            if not _status_is_inactive(status):
                active_flows.add(flow)
            if any(
                marker in status
                for marker in ("처음 관측", "관측 MD 변경", "여러 MD", "Flags 변경")
            ):
                changed_flows.add(flow)
        self._set_metric("active", len(active_flows))
        self._set_metric("rows", table.rowCount())
        self._set_metric("changes", len(changed_flows))
        self._set_metric("controllers", len(controllers))

    def _refresh_detail(self) -> None:
        table = self._window.result_table
        row = table.currentRow()
        if row < 0:
            self._set_detail("hint", "세션 행을 선택하면 조사 요약을 표시합니다.")
            for key in (
                "source",
                "destination",
                "protocol",
                "status",
                "controller",
                "flags",
                "last_seen",
                "packets",
                "bytes",
                "age",
                "cpu",
            ):
                self._set_detail(key, _DASH)
            return

        source = _join_endpoint(_item_text(table, row, 2), _item_text(table, row, 3))
        destination = _join_endpoint(_item_text(table, row, 4), _item_text(table, row, 5))
        protocol = _item_text(table, row, 1) or _DASH
        self._set_detail("hint", f"결과 행 {row + 1:,}")
        self._set_detail("source", source)
        self._set_detail("destination", destination)
        self._set_detail("protocol", f"── {protocol} ──▶")
        self._set_detail("status", _item_text(table, row, 14) or _DASH)
        self._set_detail("controller", _item_text(table, row, 0) or _DASH)
        self._set_detail("flags", _item_text(table, row, 13) or _DASH)
        self._set_detail("last_seen", _item_text(table, row, 12) or _DASH)
        self._set_detail("packets", _item_text(table, row, 6) or _DASH)
        self._set_detail("bytes", _item_text(table, row, 7) or _DASH)
        self._set_detail("age", _item_text(table, row, 10) or _DASH)
        self._set_detail("cpu", _item_text(table, row, 11) or _DASH)

    def _refresh_status_cells(self) -> None:
        if self._window.property("themeContrast") == "high":
            return
        table = self._window.result_table
        for row in range(table.rowCount()):
            status_item = table.item(row, 14)
            if status_item is None:
                continue
            status = status_item.text()
            if "종료" in status:
                color = QColor("#E05C65")
            elif "미관측" in status or "신뢰 불가" in status:
                color = QColor("#E4A83C")
            else:
                color = QColor("#2DBE78")
            status_item.setForeground(color)

    def _set_metric(self, key: str, value: int) -> None:
        label = self._metric_values.get(key)
        if label is not None:
            label.setText(f"{value:,}")

    def _set_detail(self, key: str, value: str) -> None:
        label = self._detail_values.get(key)
        if label is not None:
            label.setText(value)

    def _set_header(self, key: str, value: str) -> None:
        label = self._header_values.get(key)
        if label is not None:
            label.setText(value)


def install_dark_noc_console(window: MainWindow) -> _NocConsoleController:
    """Install the approved presentation once and return its controller."""

    existing = getattr(window, "_dark_noc_console_controller", None)
    if isinstance(existing, _NocConsoleController):
        existing.schedule_refresh()
        existing.schedule_layout()
        return existing
    controller = _NocConsoleController(window)
    window._dark_noc_console_controller = controller  # type: ignore[attr-defined]
    window.setProperty("darkNocConsoleInstalled", True)
    return controller


def _header_chip(label: str, value: str, role: str, parent: QWidget) -> QFrame:
    chip = QFrame(parent)
    chip.setObjectName("headerChip")
    chip.setProperty("chipRole", role)
    layout = QVBoxLayout(chip)
    layout.setContentsMargins(9, 4, 9, 4)
    layout.setSpacing(0)
    caption = QLabel(label, chip)
    caption.setObjectName("headerChipLabel")
    value_label = QLabel(value, chip)
    value_label.setObjectName("headerChipValue")
    value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    layout.addWidget(caption)
    layout.addWidget(value_label)
    return chip


def _detail_endpoint(label: str, parent: QWidget) -> QFrame:
    block = QFrame(parent)
    block.setObjectName("detailEndpoint")
    layout = QVBoxLayout(block)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(2)
    caption = QLabel(label, block)
    caption.setObjectName("detailEndpointLabel")
    value = QLabel(_DASH, block)
    value.setObjectName("detailEndpointValue")
    value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    value.setWordWrap(True)
    layout.addWidget(caption)
    layout.addWidget(value)
    return block


def _navigation_icon(name: str) -> QIcon:
    pixmap = QPixmap(22, 22)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(QColor("#B9C9D8"), 1.7)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    if name == "query":
        painter.drawEllipse(QRectF(3.5, 3.5, 10.5, 10.5))
        painter.drawLine(QPointF(12.2, 12.2), QPointF(18.3, 18.3))
        painter.drawLine(QPointF(5.8, 17.5), QPointF(10.0, 17.5))
    elif name == "settings":
        painter.drawRoundedRect(QRectF(3.0, 4.0, 16.0, 14.0), 2.0, 2.0)
        painter.drawLine(QPointF(6.0, 8.0), QPointF(16.0, 8.0))
        painter.drawLine(QPointF(6.0, 12.0), QPointF(16.0, 12.0))
        painter.drawLine(QPointF(6.0, 16.0), QPointF(13.0, 16.0))
    else:
        painter.drawEllipse(QRectF(3.0, 3.0, 16.0, 16.0))
        painter.drawLine(QPointF(11.0, 6.0), QPointF(11.0, 11.0))
        painter.drawLine(QPointF(11.0, 11.0), QPointF(15.0, 13.0))
    painter.end()
    return QIcon(pixmap)


def _item_text(table: QTableWidget, row: int, column: int) -> str:
    item = table.item(row, column)
    return item.text().strip() if item is not None else ""


def _join_endpoint(address: str, port: str) -> str:
    if not address:
        return _DASH
    if not port or port == "-":
        return address
    return f"{address}:{port}"


def _status_is_inactive(status: str) -> bool:
    return "종료" in status or "미관측" in status or "신뢰 불가" in status


def _version_text(window: object) -> str:
    title_getter = getattr(window, "windowTitle", None)
    title = str(title_getter()) if callable(title_getter) else ""
    return title.rsplit(" ", 1)[-1] if " " in title else title or "—"


__all__ = ["install_dark_noc_console"]