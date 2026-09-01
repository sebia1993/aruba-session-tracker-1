"""Presentation-only Dark NOC Console composition for the Qt desktop UI.

This module deliberately reuses the operational widgets built by ``MainWindow``.
It adds only local presentation widgets, rearranges existing containers, and
derives every displayed metric from UI state that already exists in memory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QEvent, QObject, Qt, QTimer
from PySide6.QtWidgets import (
    QBoxLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QTableWidget,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from aruba_session_tracker.ui.main_window import MainWindow


_DASH = "—"
_SIDE_DETAIL_BREAKPOINT = 1200
_COMPACT_DETAIL_HEIGHT = 760
_DETAIL_MIN_WIDTH = 340
_RESULT_MIN_WIDTH = 380


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
        self._metric_layouts: list[QBoxLayout] = []
        self._metric_pairs: list[tuple[QLabel, QLabel]] = []
        self._detail_values: dict[str, QLabel] = {}
        self._header_values: dict[str, QLabel] = {}
        self._result_layout: QBoxLayout | None = None
        self._result_layout_margins = (0, 0, 0, 0)
        self._result_layout_spacing = 0

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
        self._refresh_accessibility_context()
        self.schedule_layout()

    def _install_shell(self) -> None:
        window = self._window
        window.tabs.setTabPosition(QTabWidget.TabPosition.North)
        window.tabs.setUsesScrollButtons(False)
        window.tabs.tabBar().setExpanding(False)
        window.tabs.tabBar().setDrawBase(False)
        # Reuse the existing identity frame instead of creating a second product
        # header. Explicitly release the registered corner before reparenting it.
        # Qt accepts a null widget to release the corner; PySide's stub omits it.
        window.tabs.setCornerWidget(None, Qt.Corner.TopRightCorner)  # type: ignore[arg-type]
        window.nav_identity.setParent(window.central_root)
        window.nav_identity.setVisible(True)
        window.nav_identity.setObjectName("nocHeader")
        existing_layout = window.nav_identity.layout()
        if isinstance(existing_layout, QBoxLayout):
            header_layout = existing_layout
        else:
            header_layout = QHBoxLayout(window.nav_identity)
        while header_layout.count():
            item = header_layout.takeAt(0)
            if item is None:
                continue
            child = item.widget()
            if child is not None:
                child.setParent(window.nav_identity)
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
        result_parent = window.result_table.parentWidget()
        if result_parent is None:
            return
        result_layout = result_parent.layout()
        if not isinstance(result_layout, QBoxLayout):
            return
        self._result_layout = result_layout
        margins = result_layout.contentsMargins()
        self._result_layout_margins = (
            margins.left(),
            margins.top(),
            margins.right(),
            margins.bottom(),
        )
        self._result_layout_spacing = result_layout.spacing()
        strip = QFrame(result_parent)
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
            self._metric_layouts.append(card_layout)
            self._metric_pairs.append((value_label, caption))

        insertion_index = result_layout.indexOf(window.result_empty_label)
        if insertion_index < 0:
            insertion_index = result_layout.indexOf(window.result_table)
        result_layout.insertWidget(max(0, insertion_index), strip)

    def _install_detail_summary(self) -> None:
        window = self._window
        page = QWidget(window.details)
        page.setObjectName("sessionDetailPage")
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        scroll = QScrollArea(page)
        scroll.setObjectName("sessionDetailScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget(scroll)
        content.setObjectName("sessionDetailContent")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(8)

        heading_row = QVBoxLayout()
        heading_row.setSpacing(2)
        heading = QLabel("SELECTED SESSION", page)
        heading.setObjectName("detailEyebrow")
        self._detail_values["hint"] = QLabel("세션 행을 선택하면 조사 요약을 표시합니다.", page)
        self._detail_values["hint"].setObjectName("detailHint")
        self._detail_values["hint"].setWordWrap(True)
        heading_row.addWidget(heading)
        heading_row.addWidget(self._detail_values["hint"])
        layout.addLayout(heading_row)

        flow = QFrame(page)
        flow.setObjectName("sessionFlowCard")
        flow_layout = QGridLayout(flow)
        flow_layout.setContentsMargins(9, 8, 9, 8)
        flow_layout.setHorizontalSpacing(8)
        flow_layout.setVerticalSpacing(4)

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
        protocol.setWordWrap(True)
        self._detail_values["protocol"] = protocol

        flow_layout.addWidget(source_block, 0, 0)
        flow_layout.addWidget(destination_block, 0, 1)
        flow_layout.addWidget(
            protocol,
            1,
            0,
            1,
            2,
            Qt.AlignmentFlag.AlignHCenter,
        )
        flow_layout.setColumnStretch(0, 1)
        flow_layout.setColumnStretch(1, 1)
        layout.addWidget(flow)

        facts = QFrame(page)
        facts.setObjectName("detailFacts")
        facts_layout = QGridLayout(facts)
        facts_layout.setContentsMargins(0, 0, 0, 0)
        facts_layout.setHorizontalSpacing(8)
        facts_layout.setVerticalSpacing(6)
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
            fact_layout.setContentsMargins(9, 5, 9, 5)
            fact_layout.setSpacing(1)
            caption = QLabel(label, fact)
            caption.setObjectName("detailFactLabel")
            value = QLabel(_DASH, fact)
            value.setObjectName("detailFactValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            fact_layout.addWidget(caption)
            fact_layout.addWidget(value)
            facts_layout.addWidget(fact, index // 2, index % 2)
            self._detail_values[key] = value
        layout.addWidget(facts)
        layout.addStretch(1)
        scroll.setWidget(content)
        page_layout.addWidget(scroll)

        window.details.insertTab(0, page, "DETAILS")
        window.details.setTabText(1, "RAW CLI")
        window.details.setTabText(2, "DIAGNOSTICS")
        window.details.setUsesScrollButtons(False)
        window.details.tabBar().setExpanding(True)
        window.details.setAccessibleDescription(
            "선택 세션 요약, Raw CLI와 진단 이벤트를 전환합니다."
        )

    def _connect_existing_state(self) -> None:
        window = self._window
        model = window.result_table.model()
        if model is not None:
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
        condensed_results = (
            window.height() < _COMPACT_DETAIL_HEIGHT
            and window.advanced_toggle_button.isChecked()
            and window.raw_diagnostics_toggle.isChecked()
        )
        for widget in (
            window.results_title_label,
            window.result_status_guide,
            window.context_label,
        ):
            widget.setVisible(not condensed_results)
        if self._result_layout is not None:
            margins = (0, 0, 0, 0) if condensed_results else self._result_layout_margins
            self._result_layout.setContentsMargins(*margins)
            self._result_layout.setSpacing(4 if condensed_results else self._result_layout_spacing)
        for layout in self._metric_layouts:
            layout.setDirection(QBoxLayout.Direction.TopToBottom)
            layout.setContentsMargins(*(6, 1, 6, 1) if condensed_results else (12, 8, 12, 8))
            layout.setSpacing(0)
        for value, caption in self._metric_pairs:
            value.setMinimumWidth(value.sizeHint().width() if condensed_results else 0)
            caption.setMinimumWidth(caption.sizeHint().width() if condensed_results else 0)
        self._refresh_accessibility_context()

        use_side_panel = (
            window.width() >= _SIDE_DETAIL_BREAKPOINT
            or window.height() < _COMPACT_DETAIL_HEIGHT
            or window.advanced_toggle_button.isChecked()
        )
        orientation = Qt.Orientation.Horizontal if use_side_panel else Qt.Orientation.Vertical
        window.result_splitter.setOrientation(orientation)
        if use_side_panel:
            available = max(window.result_splitter.width(), 720)
            tab_bar = window.details.tabBar()
            tab_bar.ensurePolished()
            rendered_tab_width = max(
                (tab_bar.tabRect(index).right() + 1 for index in range(tab_bar.count())),
                default=0,
            )
            # On Windows the selected/native-styled tab can render wider than
            # QTabBar.sizeHint() after a vertical-to-horizontal transition.
            tab_width = max(
                tab_bar.sizeHint().width(),
                tab_bar.minimumSizeHint().width(),
                rendered_tab_width,
            )
            detail_width = min(
                max(_DETAIL_MIN_WIDTH, tab_width),
                max(_DETAIL_MIN_WIDTH, available - _RESULT_MIN_WIDTH),
            )
            window.details.setMinimumWidth(detail_width)
            window.details.setMinimumHeight(0)
            window.result_splitter.setSizes(
                [max(_RESULT_MIN_WIDTH, available - detail_width), detail_width]
            )
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

    def _refresh_accessibility_context(self) -> None:
        self._window._sync_result_accessibility_context()

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
        self._set_detail("protocol", protocol)
        self._set_detail("status", _item_text(table, row, 14) or _DASH)
        self._set_detail("controller", _item_text(table, row, 0) or _DASH)
        self._set_detail("flags", _item_text(table, row, 13) or _DASH)
        self._set_detail("last_seen", _item_text(table, row, 12) or _DASH)
        self._set_detail("packets", _item_text(table, row, 6) or _DASH)
        self._set_detail("bytes", _item_text(table, row, 7) or _DASH)
        self._set_detail("age", _item_text(table, row, 10) or _DASH)
        self._set_detail("cpu", _item_text(table, row, 11) or _DASH)

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

    existing = window.findChild(_NocConsoleController, "darkNocConsoleController")
    if existing is not None:
        existing.schedule_refresh()
        existing.schedule_layout()
        return existing
    controller = _NocConsoleController(window)
    controller.setObjectName("darkNocConsoleController")
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
    value.setMinimumWidth(0)
    value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    value.setWordWrap(True)
    layout.addWidget(caption)
    layout.addWidget(value)
    return block


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


def _version_text(window: QWidget) -> str:
    title = window.windowTitle()
    return title.rsplit(" ", 1)[-1] if " " in title else title or "—"


__all__ = ["install_dark_noc_console"]
