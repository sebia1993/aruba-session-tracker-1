"""Process-local F12 UI inspector built around fixed, non-runtime metadata.

The inspector intentionally has no configuration, command-line, environment,
registry, or storage integration.  A new controller always starts disabled and
an unmodified F12 key press is its only activation path.
"""

from __future__ import annotations

import re
import weakref
from collections import OrderedDict
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from time import monotonic
from typing import Any, ClassVar, cast

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, Qt, Signal, Slot
from PySide6.QtGui import QColor, QCursor, QKeyEvent, QMouseEvent, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

_STABLE_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*\Z")
_VERSION_PATTERN = re.compile(r"v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z")


def _static_field(value: str, field_name: str, *, maximum: int = 500) -> str:
    """Validate a hard-coded catalog field without rewriting it."""

    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty and trimmed")
    if len(value) > maximum:
        raise ValueError(f"{field_name} is too long")
    if not value.isprintable():
        raise ValueError(f"{field_name} must be a single printable line")
    return value


def _repository_relative_source(value: str) -> str:
    source = _static_field(value, "source_path", maximum=260)
    if "\\" in source or ":" in source:
        raise ValueError("source_path must use repository-relative POSIX separators")
    posix_path = PurePosixPath(source)
    windows_path = PureWindowsPath(source)
    if (
        source != posix_path.as_posix()
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or any(part in {"", ".", ".."} for part in posix_path.parts)
    ):
        raise ValueError("source_path must be a repository-relative path")
    return source


def _application_version(value: str) -> str:
    version = _static_field(value, "app_version", maximum=64)
    if not _VERSION_PATTERN.fullmatch(version):
        raise ValueError("app_version must be a static dotted version string")
    return version


@dataclass(frozen=True, slots=True)
class UiElementMetadata:
    """Fixed metadata for one user-visible UI element."""

    name_ko: str
    stable_id: str
    screen_path: str
    source_path: str
    purpose: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "name_ko", _static_field(self.name_ko, "name_ko"))
        stable_id = _static_field(self.stable_id, "stable_id", maximum=128)
        if not _STABLE_ID_PATTERN.fullmatch(stable_id):
            raise ValueError("stable_id must use uppercase ASCII words separated by hyphens")
        object.__setattr__(self, "stable_id", stable_id)
        object.__setattr__(
            self,
            "screen_path",
            _static_field(self.screen_path, "screen_path"),
        )
        object.__setattr__(
            self,
            "source_path",
            _repository_relative_source(self.source_path),
        )
        object.__setattr__(self, "purpose", _static_field(self.purpose, "purpose"))


def build_static_request_text(metadata: UiElementMetadata, app_version: str) -> str:
    """Build a sanitized handoff template from fixed metadata only."""

    if not isinstance(metadata, UiElementMetadata):
        raise TypeError("metadata must be UiElementMetadata")
    version = _application_version(app_version)
    return (
        f"프로그램 버전: {version}\n"
        f"화면 위치: {metadata.screen_path}\n"
        f"요소 이름: {metadata.name_ko}\n"
        f"UI 식별자: {metadata.stable_id}\n"
        f"소스 위치: {metadata.source_path}\n"
        f"용도: {metadata.purpose}\n\n"
        "현재 현상:\n"
        "원하는 변경:\n"
    )


class DeveloperInspectorBar(QFrame):
    """Host bar that is visible only while the inspector is enabled."""

    def __init__(
        self,
        controller: DeveloperInspectorController,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._controller = controller
        self.setProperty("uiInspectorInternal", True)
        self.setObjectName("developerInspectorBar")
        self.setFrameShape(QFrame.Shape.StyledPanel)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)
        self.mode_label = QLabel("화면 개선 도우미", self)
        self.mode_label.setObjectName("developerInspectorModeLabel")
        self.mode_label.setAccessibleName("화면 개선 도우미 상태")
        layout.addWidget(self.mode_label)
        layout.addStretch(1)

        self.select_button = QPushButton("화면에서 선택", self)
        self.select_button.setAccessibleName("화면에서 요소 선택 또는 선택 취소")
        self.select_button.setAccessibleDescription(
            "화면 요소를 선택하는 안전한 식별 모드를 시작하거나 취소합니다."
        )
        self.catalog_button = QPushButton("목록에서 찾기", self)
        self.catalog_button.setAccessibleName("화면 요소 목록에서 찾기")
        self.catalog_button.setAccessibleDescription(
            "등록된 화면 요소를 화면 위치별 목록으로 엽니다."
        )
        self.exit_button = QPushButton("도우미 닫기", self)
        self.exit_button.setAccessibleName("화면 개선 도우미 닫기")
        self.exit_button.setAccessibleDescription("F12 화면 개선 도우미를 종료합니다.")
        layout.addWidget(self.select_button)
        layout.addWidget(self.catalog_button)
        layout.addWidget(self.exit_button)

        self.select_button.clicked.connect(self._toggle_selection)
        self.catalog_button.clicked.connect(lambda: controller.show_catalog(self.window()))
        self.exit_button.clicked.connect(controller.deactivate)
        QWidget.setTabOrder(self.select_button, self.catalog_button)
        QWidget.setTabOrder(self.catalog_button, self.exit_button)
        controller.enabled_changed.connect(self._sync_enabled)
        controller.selection_mode_changed.connect(self._sync_selection_mode)
        self._sync_selection_mode(False)
        self._sync_enabled(controller.enabled)

    def _sync_enabled(self, enabled: bool) -> None:
        self.setVisible(enabled)

    def _sync_selection_mode(self, selecting: bool) -> None:
        self.mode_label.setText(
            "화면 개선 도우미 · 확인할 요소를 클릭하세요. "
            "선택용 클릭은 실제 기능을 실행하지 않습니다. "
            "선택할 대상이 없으면 우클릭 또는 Esc로 선택을 취소할 수 있습니다."
            if selecting
            else "화면 개선 도우미"
        )
        self.select_button.setText("선택 취소" if selecting else "화면에서 선택")

    def _toggle_selection(self) -> None:
        if self._controller.selection_mode:
            self._controller.cancel_selection()
        else:
            self._controller.begin_selection()


class DeveloperInspectorDetailDialog(QDialog):
    """Nonmodal view of fixed catalog metadata and sanitized request text."""

    def __init__(self, app_version: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("uiInspectorInternal", True)
        self.setObjectName("developerInspectorDetailDialog")
        self._app_version = _application_version(app_version)
        self._metadata: UiElementMetadata | None = None
        self.setWindowTitle("화면 개선 도우미")
        self.setModal(False)
        self.resize(580, 390)

        root = QVBoxLayout(self)
        self.intro_label = QLabel(
            "이 정보는 화면 개선 요청을 정확히 전달할 때 사용합니다. "
            "현재 입력값, 비밀번호, 장비 데이터는 포함되지 않습니다.",
            self,
        )
        self.intro_label.setWordWrap(True)
        root.addWidget(self.intro_label)

        summary_form = QFormLayout()
        self.name_value = self._read_only_line()
        self.screen_value = self._read_only_line()
        self.purpose_value = QTextEdit(self)
        self.purpose_value.setReadOnly(True)
        self.purpose_value.setAcceptRichText(False)
        self.purpose_value.setMaximumHeight(90)
        summary_form.addRow("선택한 항목", self.name_value)
        summary_form.addRow("어디에 있나요?", self.screen_value)
        summary_form.addRow("무엇을 하나요?", self.purpose_value)
        root.addLayout(summary_form)

        self.technical_toggle = QPushButton("기술 정보 보기", self)
        self.technical_toggle.setCheckable(True)
        self.technical_toggle.setAccessibleName("기술 정보 펼치기 또는 접기")
        self.technical_toggle.setAccessibleDescription(
            "프로그램 버전, UI 식별자, 관련 코드 위치를 표시하거나 숨깁니다."
        )
        self.technical_toggle.toggled.connect(self._sync_technical_visibility)
        root.addWidget(self.technical_toggle)
        self.technical_widget = QWidget(self)
        technical_form = QFormLayout(self.technical_widget)
        technical_form.setContentsMargins(0, 0, 0, 0)
        self.version_value = self._read_only_line()
        self.id_value = self._read_only_line()
        self.source_value = self._read_only_line()
        technical_form.addRow("프로그램 버전", self.version_value)
        technical_form.addRow("UI 식별자", self.id_value)
        technical_form.addRow("관련 코드 위치", self.source_value)
        self.technical_widget.setVisible(False)
        root.addWidget(self.technical_widget)

        request_title = QLabel("개선 요청 정보", self)
        request_title.setObjectName("inspectorSectionTitle")
        root.addWidget(request_title)
        self.request_help = QLabel(
            "정보를 복사한 뒤 채팅이나 이슈에 붙여넣고 '현재 현상'과 "
            "'원하는 변경'을 작성하세요. 자동으로 전송되지 않습니다.",
            self,
        )
        self.request_help.setWordWrap(True)
        root.addWidget(self.request_help)

        self.preview_toggle = QPushButton("복사할 정보 미리보기", self)
        self.preview_toggle.setCheckable(True)
        self.preview_toggle.setAccessibleName("복사할 정보 미리보기 펼치기 또는 접기")
        self.preview_toggle.setAccessibleDescription(
            "클립보드에 복사될 정적 개선 요청 정보를 표시하거나 숨깁니다."
        )
        self.preview_toggle.toggled.connect(self._sync_preview_visibility)
        root.addWidget(self.preview_toggle)

        self.request_preview = QTextEdit(self)
        self.request_preview.setReadOnly(True)
        self.request_preview.setAcceptRichText(False)
        self.request_preview.setAccessibleName("복사할 개선 요청 정보 미리보기")
        self.request_preview.setAccessibleDescription(
            "현재 입력값이나 장비 데이터를 포함하지 않는 읽기 전용 정적 문구입니다."
        )
        self.request_preview.setVisible(False)
        root.addWidget(self.request_preview)

        buttons = QDialogButtonBox(self)
        self.copy_button = buttons.addButton(
            "개선 요청 정보 복사",
            QDialogButtonBox.ButtonRole.ActionRole,
        )
        self.copy_button.setAccessibleName("개선 요청 정보 클립보드에 복사")
        self.copy_button.setAccessibleDescription(
            "정적 화면 요소 정보만 클립보드에 복사하며 자동 전송하지 않습니다."
        )
        self.close_button = buttons.addButton(QDialogButtonBox.StandardButton.Close)
        self.close_button.setText("닫기")
        self.close_button.setAccessibleName("화면 요소 정보 닫기")
        self.copy_button.clicked.connect(self.copy_request)
        self.close_button.clicked.connect(self.hide)
        root.addWidget(buttons)
        self.copy_status = QLabel("", self)
        self.copy_status.setAccessibleName("복사 상태")
        self.copy_status.setWordWrap(True)
        root.addWidget(self.copy_status)
        QWidget.setTabOrder(self.technical_toggle, self.preview_toggle)
        QWidget.setTabOrder(self.preview_toggle, self.copy_button)
        QWidget.setTabOrder(self.copy_button, self.close_button)

    def _read_only_line(self) -> QLineEdit:
        line = QLineEdit(self)
        line.setReadOnly(True)
        return line

    @property
    def metadata(self) -> UiElementMetadata | None:
        return self._metadata

    def set_metadata(self, metadata: UiElementMetadata) -> None:
        self._metadata = metadata
        self.name_value.setText(metadata.name_ko)
        self.version_value.setText(self._app_version)
        self.id_value.setText(metadata.stable_id)
        self.screen_value.setText(metadata.screen_path)
        self.source_value.setText(metadata.source_path)
        self.purpose_value.setPlainText(metadata.purpose)
        self.request_preview.setPlainText(build_static_request_text(metadata, self._app_version))
        self.copy_status.clear()

    @Slot(bool)
    def _sync_technical_visibility(self, visible: bool) -> None:
        self.technical_widget.setVisible(visible)
        self.technical_toggle.setText("기술 정보 숨기기" if visible else "기술 정보 보기")

    @Slot(bool)
    def _sync_preview_visibility(self, visible: bool) -> None:
        self.request_preview.setVisible(visible)
        self.preview_toggle.setText("복사할 정보 숨기기" if visible else "복사할 정보 미리보기")

    def copy_request(self) -> str:
        metadata = self._metadata
        if metadata is None:
            return ""
        text = build_static_request_text(metadata, self._app_version)
        QApplication.clipboard().setText(text)
        self.copy_status.setText("클립보드에 복사했습니다. 외부로 자동 전송되지는 않습니다.")
        return text


class DeveloperInspectorCatalogDialog(QDialog):
    """Nonmodal catalog containing fixed metadata only."""

    metadata_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("uiInspectorInternal", True)
        self.setObjectName("developerInspectorCatalogDialog")
        self.setWindowTitle("화면 개선 도우미 - 목록")
        self.setModal(False)
        self.resize(590, 420)
        self._metadata_by_id: dict[str, UiElementMetadata] = {}

        root = QVBoxLayout(self)
        self.guide_label = QLabel(
            "확인할 항목을 선택하세요. 현재 입력값이나 장비 정보는 표시되지 않습니다.",
            self,
        )
        self.guide_label.setWordWrap(True)
        root.addWidget(self.guide_label)
        self.element_list = QListWidget(self)
        self.element_list.setAccessibleName("화면 요소 목록")
        self.element_list.setAccessibleDescription("화면 위치별로 묶인 정적 요소 이름 목록입니다.")
        self.element_list.itemDoubleClicked.connect(self._request_item)
        root.addWidget(self.element_list)

        buttons = QDialogButtonBox(self)
        self.details_button = buttons.addButton(
            "선택한 요소 보기",
            QDialogButtonBox.ButtonRole.ActionRole,
        )
        self.details_button.setAccessibleName("선택한 화면 요소 정보 보기")
        self.details_button.setAccessibleDescription(
            "목록에서 선택한 요소의 용도와 개선 요청 정보를 엽니다."
        )
        self.close_button = buttons.addButton(QDialogButtonBox.StandardButton.Close)
        self.close_button.setText("닫기")
        self.close_button.setAccessibleName("화면 요소 목록 닫기")
        self.details_button.clicked.connect(self._request_current)
        self.close_button.clicked.connect(self.hide)
        root.addWidget(buttons)
        QWidget.setTabOrder(self.element_list, self.details_button)
        QWidget.setTabOrder(self.details_button, self.close_button)

    def set_catalog(self, metadata_items: Iterable[UiElementMetadata]) -> None:
        selected_id: str | None = None
        current_item = self.element_list.currentItem()
        if current_item is not None:
            selected_value = current_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(selected_value, str):
                selected_id = selected_value
        self.element_list.clear()
        self._metadata_by_id.clear()
        grouped: OrderedDict[str, list[UiElementMetadata]] = OrderedDict()
        for metadata in metadata_items:
            grouped.setdefault(metadata.screen_path, []).append(metadata)
        first_selectable: QListWidgetItem | None = None
        for screen_path, group in grouped.items():
            group_name = screen_path.rsplit(" > ", maxsplit=1)[-1]
            if group_name == "공통":
                group_name = "공통 화면"
            header = QListWidgetItem(f"── {group_name} ──", self.element_list)
            header.setFlags(Qt.ItemFlag.NoItemFlags)
            for metadata in group:
                self._metadata_by_id[metadata.stable_id] = metadata
                item = QListWidgetItem(metadata.name_ko, self.element_list)
                item.setData(Qt.ItemDataRole.UserRole, metadata.stable_id)
                if first_selectable is None:
                    first_selectable = item
                if metadata.stable_id == selected_id:
                    self.element_list.setCurrentItem(item)
        if self.element_list.currentRow() < 0 and first_selectable is not None:
            self.element_list.setCurrentItem(first_selectable)

    def _request_current(self) -> None:
        item = self.element_list.currentItem()
        if item is not None:
            self._request_item(item)

    def _request_item(self, item: QListWidgetItem) -> None:
        metadata = self._metadata_by_id.get(item.data(Qt.ItemDataRole.UserRole))
        if metadata is not None:
            self.metadata_requested.emit(metadata)


class _SelectionOutline(QWidget):
    """Mouse-transparent outline positioned over the current registered hit."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setProperty("uiInspectorInternal", True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.hide()

    def show_for_widget(self, widget: QWidget) -> None:
        parent = self.parentWidget()
        if parent is None:
            return
        top_left = widget.mapTo(parent, QPoint(0, 0))
        self.setGeometry(QRect(top_left, widget.size()))
        self.show()
        self.raise_()
        self.update()

    def paintEvent(self, event: Any) -> None:
        del event
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(QPen(QColor("#05080B"), 4))
            painter.drawRect(self.rect().adjusted(1, 1, -2, -2))
            painter.setPen(QPen(QColor("#F7FBFF"), 2))
            painter.drawRect(self.rect().adjusted(5, 5, -6, -6))
        finally:
            painter.end()


@dataclass(frozen=True, slots=True)
class _RegisteredTarget:
    reference: weakref.ReferenceType[QWidget]
    metadata: UiElementMetadata


@dataclass(frozen=True, slots=True)
class _Hit:
    metadata: UiElementMetadata
    widget: QWidget


class DeveloperInspectorController(QObject):
    """Application-wide developer inspector with an F12-only activation gate."""

    enabled_changed = Signal(bool)
    selection_mode_changed = Signal(bool)
    element_selected = Signal(object)

    _HOVER_EVENTS: ClassVar[frozenset[QEvent.Type]] = frozenset(
        {
            QEvent.Type.Enter,
            QEvent.Type.HoverEnter,
            QEvent.Type.HoverMove,
            QEvent.Type.MouseMove,
        }
    )
    _LEAVE_EVENTS: ClassVar[frozenset[QEvent.Type]] = frozenset(
        {
            QEvent.Type.Leave,
            QEvent.Type.HoverLeave,
        }
    )
    _MOUSE_EVENTS: ClassVar[frozenset[QEvent.Type]] = frozenset(
        {
            QEvent.Type.MouseButtonPress,
            QEvent.Type.MouseButtonRelease,
            QEvent.Type.MouseButtonDblClick,
        }
    )

    def __init__(
        self,
        app: QApplication,
        app_version: str,
        parent: QObject | None = None,
    ) -> None:
        if not isinstance(app, QApplication):
            raise TypeError("app must be QApplication")
        super().__init__(parent)
        self._app = app
        self._app_version = _application_version(app_version)
        self._enabled = False
        self._selection_mode = False
        self._closed = False
        self._catalog: OrderedDict[str, UiElementMetadata] = OrderedDict()
        self._targets: dict[int, _RegisteredTarget] = {}
        self._bars: list[weakref.ReferenceType[DeveloperInspectorBar]] = []
        self._tracking_states: dict[
            int,
            tuple[weakref.ReferenceType[QWidget], bool, bool],
        ] = {}
        self._suppressed_mouse_buttons: set[Qt.MouseButton] = set()
        self._post_selection_guard: (
            tuple[
                weakref.ReferenceType[QObject],
                Qt.MouseButton,
                float,
            ]
            | None
        ) = None
        self._suppress_escape_release = False
        self._suppress_context_menu_until = 0.0
        self._hovered_metadata: UiElementMetadata | None = None
        self._outline: _SelectionOutline | None = None
        self._detail_dialog: DeveloperInspectorDetailDialog | None = None
        self._catalog_dialog: DeveloperInspectorCatalogDialog | None = None
        self._app.installEventFilter(self)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def selection_mode(self) -> bool:
        return self._selection_mode

    @property
    def hovered_metadata(self) -> UiElementMetadata | None:
        return self._hovered_metadata

    @property
    def catalog(self) -> tuple[UiElementMetadata, ...]:
        return tuple(self._catalog.values())

    @property
    def detail_dialog(self) -> DeveloperInspectorDetailDialog | None:
        return self._detail_dialog

    @property
    def catalog_dialog(self) -> DeveloperInspectorCatalogDialog | None:
        return self._catalog_dialog

    def register_widget(self, widget: QWidget, metadata: UiElementMetadata) -> None:
        if not isinstance(widget, QWidget):
            raise TypeError("widget must be QWidget")
        self._register_metadata(metadata)
        key = id(widget)
        existing_target = self._targets.get(key)
        if existing_target is not None:
            existing_widget = existing_target.reference()
            if existing_widget is widget and existing_target.metadata != metadata:
                raise ValueError("widget is already registered with different metadata")
        widget_reference = weakref.ref(widget)
        self._targets[key] = _RegisteredTarget(widget_reference, metadata)
        widget.setProperty("uiInspectorId", metadata.stable_id)
        controller_reference = weakref.ref(self)

        def remove_destroyed_target(*_args: object, target_key: int = key) -> None:
            controller = controller_reference()
            if controller is None:
                return
            registered = controller._targets.get(target_key)
            if registered is not None and registered.reference is widget_reference:
                controller._targets.pop(target_key, None)

        widget.destroyed.connect(remove_destroyed_target)
        if self._selection_mode:
            self._enable_tracking_tree(widget)

    def register_catalog_item(self, metadata: UiElementMetadata) -> None:
        """Register a static virtual entry that is available from the catalog."""

        self._register_metadata(metadata)

    def _register_metadata(self, metadata: UiElementMetadata) -> None:
        if not isinstance(metadata, UiElementMetadata):
            raise TypeError("metadata must be UiElementMetadata")
        existing = self._catalog.get(metadata.stable_id)
        if existing is not None and existing != metadata:
            raise ValueError(f"stable_id {metadata.stable_id!r} already has different metadata")
        self._catalog.setdefault(metadata.stable_id, metadata)

    def attach_host_layout(
        self,
        host: QWidget,
        layout: QVBoxLayout,
    ) -> DeveloperInspectorBar:
        if not isinstance(host, QWidget):
            raise TypeError("host must be QWidget")
        if not isinstance(layout, QVBoxLayout):
            raise TypeError("layout must be QVBoxLayout")
        self._bars = [reference for reference in self._bars if reference() is not None]
        bar = DeveloperInspectorBar(self, host)
        layout.insertWidget(0, bar)
        self._bars.append(weakref.ref(bar))
        return bar

    def begin_selection(self) -> bool:
        """Enter element selection only after F12 enabled the inspector."""

        if not self._enabled or self._selection_mode:
            return False
        self._hide_dialog(self._detail_dialog)
        self._hide_dialog(self._catalog_dialog)
        self._selection_mode = True
        self._hovered_metadata = None
        self._enable_registered_mouse_tracking()
        QApplication.setOverrideCursor(Qt.CursorShape.CrossCursor)
        self.selection_mode_changed.emit(True)
        return True

    def cancel_selection(self) -> bool:
        if not self._selection_mode:
            return False
        self._selection_mode = False
        self._hovered_metadata = None
        self._hide_outline()
        self._restore_mouse_tracking()
        QApplication.restoreOverrideCursor()
        self.selection_mode_changed.emit(False)
        return True

    def deactivate(self) -> None:
        """Disable the inspector; this method never activates it."""

        self.cancel_selection()
        self._hide_outline()
        self._hide_dialog(self._detail_dialog)
        self._hide_dialog(self._catalog_dialog)
        if not self._enabled:
            return
        self._enabled = False
        self.enabled_changed.emit(False)

    @staticmethod
    def _hide_dialog(dialog: QDialog | None) -> None:
        if dialog is None:
            return
        with suppress(RuntimeError):
            dialog.hide()

    def show_catalog(
        self,
        owner: QWidget | None = None,
    ) -> DeveloperInspectorCatalogDialog | None:
        if not self._enabled:
            return None
        owner = self._dialog_owner(owner)
        if not self._dialog_matches_owner(self._catalog_dialog, owner):
            if self._catalog_dialog is not None:
                self._dispose_dialog(self._catalog_dialog)
            self._catalog_dialog = DeveloperInspectorCatalogDialog(owner)
            self._catalog_dialog.metadata_requested.connect(
                lambda metadata, target_owner=owner: self.show_element_detail(
                    metadata,
                    target_owner,
                )
            )
            self._clear_dialog_reference_on_destroy(
                self._catalog_dialog,
                "_catalog_dialog",
            )
        dialog = self._catalog_dialog
        if dialog is None:  # pragma: no cover - guarded by construction above
            raise RuntimeError("catalog dialog could not be created")
        dialog.set_catalog(self.catalog)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        return dialog

    def show_element_detail(
        self,
        metadata: UiElementMetadata,
        owner: QWidget | None = None,
    ) -> DeveloperInspectorDetailDialog | None:
        if not self._enabled:
            return None
        if self._catalog.get(metadata.stable_id) != metadata:
            raise ValueError("metadata is not registered in this inspector catalog")
        owner = self._dialog_owner(owner)
        if not self._dialog_matches_owner(self._detail_dialog, owner):
            if self._detail_dialog is not None:
                self._dispose_dialog(self._detail_dialog)
            self._detail_dialog = DeveloperInspectorDetailDialog(self._app_version, owner)
            self._clear_dialog_reference_on_destroy(
                self._detail_dialog,
                "_detail_dialog",
            )
        dialog = self._detail_dialog
        if dialog is None:  # pragma: no cover - guarded by construction above
            raise RuntimeError("detail dialog could not be created")
        dialog.set_metadata(metadata)
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        return dialog

    def _dialog_owner(self, owner: QWidget | None) -> QWidget | None:
        if owner is not None and not self._is_inspector_internal(owner):
            return owner.window()
        modal = self._app.activeModalWidget()
        if modal is not None and not self._is_inspector_internal(modal):
            return modal.window()
        active = self._app.activeWindow()
        if active is not None and not self._is_inspector_internal(active):
            return active.window()
        return None

    @staticmethod
    def _dialog_matches_owner(dialog: QDialog | None, owner: QWidget | None) -> bool:
        if dialog is None:
            return False
        try:
            return dialog.parentWidget() is owner
        except RuntimeError:
            return False

    @staticmethod
    def _dispose_dialog(dialog: QDialog) -> None:
        try:
            dialog.hide()
            dialog.deleteLater()
        except RuntimeError:
            pass

    def _clear_dialog_reference_on_destroy(
        self,
        dialog: QDialog,
        attribute_name: str,
    ) -> None:
        controller_reference = weakref.ref(self)
        dialog_reference = weakref.ref(dialog)

        def clear_reference(*_args: object) -> None:
            controller = controller_reference()
            if controller is None:
                return
            if getattr(controller, attribute_name, None) is dialog_reference():
                setattr(controller, attribute_name, None)

        dialog.destroyed.connect(clear_reference)

    def request_text(self, metadata: UiElementMetadata) -> str:
        if self._catalog.get(metadata.stable_id) != metadata:
            raise ValueError("metadata is not registered in this inspector catalog")
        return build_static_request_text(metadata, self._app_version)

    def close(self) -> None:
        """Remove the app filter and release all process-local UI state."""

        if self._closed:
            return
        self._closed = True
        with suppress(RuntimeError):
            self._app.removeEventFilter(self)
        self.deactivate()
        outline = self._outline
        self._outline = None
        if outline is not None:
            try:
                outline.hide()
                outline.deleteLater()
            except RuntimeError:
                pass
        if self._detail_dialog is not None:
            self._dispose_dialog(self._detail_dialog)
        if self._catalog_dialog is not None:
            self._dispose_dialog(self._catalog_dialog)
        self._detail_dialog = None
        self._catalog_dialog = None
        self._suppressed_mouse_buttons.clear()
        self._post_selection_guard = None
        self._suppress_context_menu_until = 0.0
        self._bars.clear()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if getattr(self, "_closed", True):
            return False
        event_type = event.type()

        if (
            self._selection_mode
            and event_type in {QEvent.Type.Show, QEvent.Type.ShowToParent}
            and isinstance(watched, QDialog)
            and not self._is_inspector_internal(watched)
            and (watched.isModal() or watched.windowModality() != Qt.WindowModality.NonModal)
        ):
            # Safety confirmations and file dialogs must remain operable.  This
            # changes only the transient selection state, not the F12 mode.
            self.cancel_selection()

        if (
            event_type == QEvent.Type.Close
            and isinstance(watched, QWidget)
            and watched.isWindow()
            and not self._is_inspector_internal(watched)
        ):
            for dialog in (self._detail_dialog, self._catalog_dialog):
                if self._dialog_matches_owner(dialog, watched):
                    self._hide_dialog(dialog)

        if event_type in {
            QEvent.Type.ShortcutOverride,
            QEvent.Type.KeyPress,
            QEvent.Type.KeyRelease,
        } and isinstance(event, QKeyEvent):
            if self._is_plain_f12(event):
                event.accept()
                if event_type == QEvent.Type.KeyPress and not event.isAutoRepeat():
                    self._set_enabled_from_f12(not self._enabled)
                return True

            if self._selection_mode and event.key() == Qt.Key.Key_Escape:
                event.accept()
                if event_type == QEvent.Type.KeyPress and not event.isAutoRepeat():
                    self._suppress_escape_release = True
                    self.cancel_selection()
                return True

            if (
                self._suppress_escape_release
                and event.key() == Qt.Key.Key_Escape
                and event_type == QEvent.Type.KeyRelease
            ):
                self._suppress_escape_release = False
                event.accept()
                return True

            if self._selection_mode and not self._is_inspector_internal(watched):
                # Selection is identification-only.  Consume every operational
                # key event so Space/Enter, mnemonics, and widget-specific keys
                # cannot invoke the focused control while the crosshair is
                # active.  F12 and Escape are handled above, and inspector-owned
                # controls remain keyboard-operable.
                event.accept()
                return True

        if (
            self._selection_mode
            and event_type == QEvent.Type.Shortcut
            and not self._is_inspector_internal(watched)
        ):
            event.accept()
            return True

        if event_type in self._MOUSE_EVENTS and isinstance(event, QMouseEvent):
            if self._is_inspector_internal(watched):
                return False
            button = event.button()
            self._expire_post_selection_guard()
            if event_type == QEvent.Type.MouseButtonPress:
                # A consumed press may lose its release after ownership changes.
                # Never let that stale state swallow the next genuine click.
                self._suppressed_mouse_buttons.discard(button)
                self._post_selection_guard = None
                self._suppress_context_menu_until = 0.0
            if (
                event_type == QEvent.Type.MouseButtonRelease
                and button in self._suppressed_mouse_buttons
            ):
                self._suppressed_mouse_buttons.discard(button)
                if button == Qt.MouseButton.RightButton:
                    # Windows normally raises ContextMenu after release. Refresh
                    # the bounded guard here so a deliberate long press cannot
                    # escape the selection-only interaction boundary.
                    self._suppress_context_menu_until = monotonic() + 0.5
                event.accept()
                return True
            if event_type == QEvent.Type.MouseButtonDblClick and self._post_selection_matches(
                watched, button
            ):
                self._post_selection_guard = None
                self._suppressed_mouse_buttons.add(button)
                event.accept()
                return True
            if self._selection_mode:
                event.accept()
                if event_type in {
                    QEvent.Type.MouseButtonPress,
                    QEvent.Type.MouseButtonDblClick,
                }:
                    self._suppressed_mouse_buttons.add(button)
                    if button == Qt.MouseButton.LeftButton:
                        hit = self._hit_for_event(watched, event)
                        if hit is not None:
                            self._select_hit(hit)
                            self._arm_post_selection_guard(watched, button)
                    elif (
                        button == Qt.MouseButton.RightButton
                        and event_type == QEvent.Type.MouseButtonPress
                    ):
                        # Right-click is the explicit selection-cancel gesture.
                        # The registered top-level window covers visually blank
                        # areas, so hit-testing for ``None`` would make the
                        # advertised cancellation path unreachable there.
                        self._suppress_context_menu_until = monotonic() + 0.5
                        self.cancel_selection()
                return True
            if (
                event_type == QEvent.Type.MouseButtonDblClick
                and button in self._suppressed_mouse_buttons
            ):
                event.accept()
                return True

        if event_type == QEvent.Type.ContextMenu and not self._is_inspector_internal(watched):
            if monotonic() <= self._suppress_context_menu_until:
                event.accept()
                return True
            if self._selection_mode:
                event.accept()
                self._suppress_context_menu_until = monotonic() + 0.5
                self.cancel_selection()
                return True

        if (
            self._selection_mode
            and event_type in self._LEAVE_EVENTS
            and not self._is_inspector_internal(watched)
        ):
            self._show_hit(None)

        if (
            self._selection_mode
            and event_type in self._HOVER_EVENTS
            and not self._is_inspector_internal(watched)
        ):
            self._show_hit(self._hit_for_event(watched, event))

        return super().eventFilter(watched, event)

    @staticmethod
    def _is_inspector_internal(watched: QObject) -> bool:
        current: QObject | None = watched
        while current is not None:
            try:
                if bool(current.property("uiInspectorInternal")):
                    return True
            except RuntimeError:
                return False
            current = current.parent()
        return False

    def _arm_post_selection_guard(
        self,
        watched: QObject,
        button: Qt.MouseButton,
    ) -> None:
        self._post_selection_guard = (
            weakref.ref(watched),
            button,
            monotonic() + (self._app.doubleClickInterval() / 1000.0),
        )

    def _expire_post_selection_guard(self) -> None:
        guard = self._post_selection_guard
        if guard is not None and monotonic() > guard[2]:
            self._post_selection_guard = None

    def _post_selection_matches(
        self,
        watched: QObject,
        button: Qt.MouseButton,
    ) -> bool:
        guard = self._post_selection_guard
        if guard is None:
            return False
        return guard[0]() is watched and guard[1] == button

    @staticmethod
    def _is_plain_f12(event: QKeyEvent) -> bool:
        return event.key() == Qt.Key.Key_F12 and event.modifiers() == Qt.KeyboardModifier.NoModifier

    def _set_enabled_from_f12(self, enabled: bool) -> None:
        if enabled == self._enabled:
            return
        if not enabled:
            self.deactivate()
            return
        self._enabled = True
        self.enabled_changed.emit(True)

    def _target_metadata(self, target: QWidget) -> UiElementMetadata | None:
        registered = self._targets.get(id(target))
        if registered is None or registered.reference() is not target:
            return None
        return registered.metadata

    def _hit_for_event(self, watched: QObject, event: QEvent) -> _Hit | None:
        global_position = self._global_position(event)
        widget = self._app.widgetAt(global_position) if global_position is not None else None
        if widget is None and isinstance(watched, QWidget):
            widget = watched
        if widget is None or self._is_inspector_internal(widget):
            return None

        current: QWidget | None = widget
        while current is not None:
            metadata = self._target_metadata(current)
            if metadata is not None:
                return _Hit(metadata, current)
            current = current.parentWidget()
        return None

    @staticmethod
    def _global_position(event: QEvent) -> QPoint | None:
        global_position = getattr(event, "globalPosition", None)
        if callable(global_position):
            return cast(QPoint, global_position().toPoint())
        context_position = getattr(event, "globalPos", None)
        if callable(context_position):
            return cast(QPoint, context_position())
        if event.type() in {
            QEvent.Type.Enter,
            QEvent.Type.HoverEnter,
            QEvent.Type.HoverMove,
        }:
            return QCursor.pos()
        return None

    def _show_hit(self, hit: _Hit | None) -> None:
        if hit is None:
            self._hovered_metadata = None
            self._hide_outline()
            return
        self._hovered_metadata = hit.metadata
        self._outline_for(hit.widget.window()).show_for_widget(hit.widget)

    def _outline_for(self, window: QWidget) -> _SelectionOutline:
        outline = self._outline
        if outline is not None:
            try:
                if outline.parentWidget() is window:
                    return outline
                outline.hide()
                outline.deleteLater()
            except RuntimeError:
                pass

        outline = _SelectionOutline(window)
        self._outline = outline
        controller_reference = weakref.ref(self)
        outline_reference = weakref.ref(outline)

        def forget_outline(*_args: object) -> None:
            controller = controller_reference()
            if controller is not None and controller._outline is outline_reference():
                controller._outline = None

        outline.destroyed.connect(forget_outline)
        return outline

    def _hide_outline(self) -> None:
        outline = self._outline
        if outline is None:
            return
        try:
            outline.hide()
        except RuntimeError:
            self._outline = None

    def _select_hit(self, hit: _Hit) -> None:
        metadata = hit.metadata
        self.cancel_selection()
        self.element_selected.emit(metadata)
        self.show_element_detail(metadata, hit.widget.window())

    def _enable_registered_mouse_tracking(self) -> None:
        for registered in tuple(self._targets.values()):
            target = registered.reference()
            if target is not None:
                self._enable_tracking_tree(target)

    def _enable_tracking_tree(self, root: QWidget) -> None:
        for widget in (root, *root.findChildren(QWidget)):
            if self._is_inspector_internal(widget):
                continue
            key = id(widget)
            if key in self._tracking_states:
                continue
            self._tracking_states[key] = (
                weakref.ref(widget),
                widget.hasMouseTracking(),
                widget.testAttribute(Qt.WidgetAttribute.WA_Hover),
            )
            widget.setMouseTracking(True)
            widget.setAttribute(Qt.WidgetAttribute.WA_Hover, True)

    def _restore_mouse_tracking(self) -> None:
        states = tuple(self._tracking_states.values())
        self._tracking_states.clear()
        for reference, had_mouse_tracking, had_hover in states:
            widget = reference()
            if widget is None:
                continue
            try:
                widget.setMouseTracking(had_mouse_tracking)
                widget.setAttribute(Qt.WidgetAttribute.WA_Hover, had_hover)
            except RuntimeError:
                continue


__all__ = [
    "DeveloperInspectorBar",
    "DeveloperInspectorCatalogDialog",
    "DeveloperInspectorController",
    "DeveloperInspectorDetailDialog",
    "UiElementMetadata",
    "build_static_request_text",
]
