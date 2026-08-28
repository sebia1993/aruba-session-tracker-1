from __future__ import annotations

import os
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QAction, QContextMenuEvent, QKeyEvent, QKeySequence, QMouseEvent
from PySide6.QtTest import QSignalSpy, QTest
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from aruba_session_tracker.ui.developer_inspector import (
    DeveloperInspectorController,
    UiElementMetadata,
    build_static_request_text,
)


def _app() -> QApplication:
    application = QApplication.instance()
    return application if isinstance(application, QApplication) else QApplication([])


def _metadata(
    stable_id: str = "MAIN-QUERY-RUN",
    *,
    name: str = "현재 조회 버튼",
    screen: str = "메인 화면 > 세션 조회 > 실행",
    source: str = "src/aruba_session_tracker/ui/main_window.py",
    purpose: str = "입력한 조건으로 읽기 전용 세션 조회를 시작합니다.",
) -> UiElementMetadata:
    return UiElementMetadata(name, stable_id, screen, source, purpose)


@pytest.fixture
def inspector(qtbot: Any) -> DeveloperInspectorController:
    del qtbot
    controller = DeveloperInspectorController(_app(), "v0.3.0")
    yield controller
    controller.close()
    _app().processEvents()


def test_metadata_is_frozen_and_rejects_non_static_fields() -> None:
    metadata = _metadata()
    assert metadata.stable_id == "MAIN-QUERY-RUN"

    with pytest.raises(FrozenInstanceError):
        metadata.stable_id = "MAIN-QUERY-STOP"  # type: ignore[misc]
    with pytest.raises(ValueError, match="uppercase ASCII"):
        _metadata("main-query-run")
    with pytest.raises(ValueError, match="repository-relative"):
        _metadata(source="D:/private/main_window.py")
    with pytest.raises(ValueError, match="repository-relative"):
        _metadata(source="file:///C:/private/main_window.py")
    with pytest.raises(ValueError, match="repository-relative"):
        _metadata(source="src//aruba_session_tracker/ui/main_window.py")
    with pytest.raises(ValueError, match="repository-relative"):
        _metadata(source="src/../main_window.py")
    with pytest.raises(ValueError, match="single printable line"):
        _metadata(name="현재 조회\n192.0.2.10")
    with pytest.raises(ValueError, match="static dotted version"):
        build_static_request_text(metadata, "runtime-version")


def test_catalog_supports_virtual_entries_and_rejects_redefinitions(
    inspector: DeveloperInspectorController,
) -> None:
    widget = QWidget()
    direct = _metadata()
    virtual = _metadata(
        "MAIN-QUERY-RESULT-TABLE-SELECTION",
        name="결과표 선택 행",
        purpose="결과표에서 선택된 행을 나타내는 정적 가상 항목입니다.",
    )
    inspector.register_widget(widget, direct)
    inspector.register_catalog_item(virtual)
    inspector.register_catalog_item(virtual)

    assert inspector.catalog == (direct, virtual)
    assert widget.property("uiInspectorId") == direct.stable_id
    assert widget.objectName() == ""

    with pytest.raises(ValueError, match="different metadata"):
        inspector.register_catalog_item(_metadata(name="충돌하는 이름"))
    with pytest.raises(ValueError, match="different metadata"):
        inspector.register_widget(widget, virtual)
    with pytest.raises(TypeError, match="widget must be QWidget"):
        inspector.register_widget(QObject(), direct)  # type: ignore[arg-type]
    widget.close()


def test_plain_f12_is_the_only_enable_path_and_every_controller_starts_off(
    qtbot: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = _app()
    monkeypatch.setenv("ARUBA_UI_INSPECTOR", "1")
    host = QWidget()
    qtbot.addWidget(host)
    layout = QVBoxLayout(host)
    controller = DeveloperInspectorController(app, "v0.3.0")
    bar = controller.attach_host_layout(host, layout)
    f12_action = QAction(host)
    f12_action.setShortcut(QKeySequence("F12"))
    host.addAction(f12_action)
    action_spy = QSignalSpy(f12_action.triggered)
    host.show()
    app.processEvents()

    try:
        assert controller.enabled is False
        assert bar.isVisible() is False
        assert controller.begin_selection() is False
        assert controller.show_catalog() is None
        assert not hasattr(controller, "activate")
        assert not hasattr(controller, "enable")
        assert not hasattr(controller, "toggle")

        QTest.keyClick(host, Qt.Key.Key_F11)
        QTest.keyClick(
            host,
            Qt.Key.Key_F12,
            Qt.KeyboardModifier.ControlModifier,
        )
        QTest.keyClick(
            host,
            Qt.Key.Key_F12,
            Qt.KeyboardModifier.ShiftModifier,
        )
        QTest.keyClick(
            host,
            Qt.Key.Key_F12,
            Qt.KeyboardModifier.AltModifier,
        )
        QApplication.sendEvent(
            host,
            QKeyEvent(
                QEvent.Type.KeyPress,
                Qt.Key.Key_F12,
                Qt.KeyboardModifier.NoModifier,
                "",
                True,
                2,
            ),
        )
        assert controller.enabled is False

        QTest.keyClick(host, Qt.Key.Key_F12)
        app.processEvents()
        assert controller.enabled is True
        assert bar.isVisible() is True
        assert action_spy.count() == 0

        QTest.keyClick(host, Qt.Key.Key_F12)
        app.processEvents()
        assert controller.enabled is False
        assert bar.isVisible() is False
    finally:
        controller.close()

    replacement = DeveloperInspectorController(app, "v0.3.0")
    try:
        assert replacement.enabled is False
    finally:
        replacement.close()


def test_selection_climbs_to_registered_parent_and_consumes_the_click(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    app = _app()
    host = QWidget()
    qtbot.addWidget(host)
    root = QVBoxLayout(host)
    registered_parent = QWidget(host)
    child_layout = QVBoxLayout(registered_parent)
    runtime_button = QPushButton("password=secret 192.0.2.10", registered_parent)
    child_layout.addWidget(runtime_button)
    root.addWidget(registered_parent)
    metadata = _metadata()
    inspector.register_widget(registered_parent, metadata)
    selected_spy = QSignalSpy(inspector.element_selected)
    clicked_spy = QSignalSpy(runtime_button.clicked)
    pressed_spy = QSignalSpy(runtime_button.pressed)
    host.show()
    app.processEvents()

    QTest.keyClick(runtime_button, Qt.Key.Key_F12)
    assert inspector.begin_selection()
    QTest.mouseMove(runtime_button, runtime_button.rect().center())
    app.processEvents()
    assert inspector.hovered_metadata == metadata
    assert inspector._outline is not None
    assert inspector._outline.isVisible()

    QApplication.sendEvent(runtime_button, QEvent(QEvent.Type.Leave))
    app.processEvents()
    assert inspector.hovered_metadata is None
    assert inspector._outline is not None
    assert inspector._outline.isVisible() is False

    QTest.mouseClick(runtime_button, Qt.MouseButton.LeftButton)
    app.processEvents()
    assert selected_spy.count() == 1
    assert selected_spy.at(0)[0] == metadata
    assert pressed_spy.count() == 0
    assert clicked_spy.count() == 0
    assert inspector.selection_mode is False
    assert inspector.detail_dialog is not None
    assert inspector.detail_dialog.metadata == metadata

    QTest.mouseClick(runtime_button, Qt.MouseButton.LeftButton)
    assert clicked_spy.count() == 1


def test_double_click_tail_and_missing_release_do_not_leak_actions(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    app = _app()
    host = QWidget()
    qtbot.addWidget(host)
    layout = QVBoxLayout(host)
    selected = QPushButton("선택 대상", host)
    normal = QPushButton("다음 정상 동작", host)
    layout.addWidget(selected)
    layout.addWidget(normal)
    inspector.register_widget(selected, _metadata("MAIN-DOUBLE-CLICK-TARGET"))
    selected_clicked = QSignalSpy(selected.clicked)
    normal_clicked = QSignalSpy(normal.clicked)
    element_selected = QSignalSpy(inspector.element_selected)
    host.show()
    app.processEvents()
    point = selected.rect().center()
    global_point = selected.mapToGlobal(point)

    QTest.keyClick(selected, Qt.Key.Key_F12)
    assert inspector.begin_selection()
    for event_type, buttons in (
        (QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton),
        (QEvent.Type.MouseButtonRelease, Qt.MouseButton.NoButton),
        (QEvent.Type.MouseButtonDblClick, Qt.MouseButton.LeftButton),
        (QEvent.Type.MouseButtonRelease, Qt.MouseButton.NoButton),
    ):
        QApplication.sendEvent(
            selected,
            QMouseEvent(
                event_type,
                point,
                global_point,
                Qt.MouseButton.LeftButton,
                buttons,
                Qt.KeyboardModifier.NoModifier,
            ),
        )

    assert element_selected.count() == 1
    assert selected_clicked.count() == 0
    assert selected.isDown() is False
    assert not inspector._suppressed_mouse_buttons

    assert inspector.begin_selection()
    QApplication.sendEvent(
        selected,
        QMouseEvent(
            QEvent.Type.MouseButtonPress,
            point,
            global_point,
            Qt.MouseButton.LeftButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        ),
    )
    assert inspector.selection_mode is False
    QTest.mouseClick(normal, Qt.MouseButton.LeftButton)
    assert normal_clicked.count() == 1


def test_escape_only_cancels_selection_and_restores_tracking_and_cursor(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    app = _app()
    host = QWidget()
    qtbot.addWidget(host)
    child = QPushButton("실제 동작", host)
    layout = QVBoxLayout(host)
    layout.addWidget(child)
    inspector.register_widget(host, _metadata("MAIN-WINDOW"))
    clicked = QSignalSpy(child.clicked)
    host.show()
    app.processEvents()
    baseline_tracking = child.hasMouseTracking()
    baseline_hover = child.testAttribute(Qt.WidgetAttribute.WA_Hover)
    baseline_cursor = QApplication.overrideCursor()

    QTest.keyClick(child, Qt.Key.Key_F12)
    assert inspector.begin_selection()
    assert child.hasMouseTracking()
    assert child.testAttribute(Qt.WidgetAttribute.WA_Hover)
    assert QApplication.overrideCursor() is not None
    assert QApplication.overrideCursor().shape() == Qt.CursorShape.CrossCursor

    QTest.keyClick(child, Qt.Key.Key_Escape)
    assert inspector.selection_mode is False
    assert inspector.enabled is True
    assert child.hasMouseTracking() is baseline_tracking
    assert child.testAttribute(Qt.WidgetAttribute.WA_Hover) is baseline_hover
    if baseline_cursor is None:
        assert QApplication.overrideCursor() is None
    else:
        assert QApplication.overrideCursor() is not None
        assert QApplication.overrideCursor().shape() == baseline_cursor.shape()
    assert clicked.count() == 0

    QTest.mouseClick(child, Qt.MouseButton.LeftButton)
    assert clicked.count() == 1


def test_context_menu_is_blocked_and_inspector_widgets_are_excluded(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    app = _app()
    host = QWidget()
    qtbot.addWidget(host)
    layout = QVBoxLayout(host)
    button = QPushButton("원래 컨텍스트 메뉴", host)
    button.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    layout.addWidget(button)
    inspector.register_widget(host, _metadata("MAIN-WINDOW"))
    bar = inspector.attach_host_layout(host, layout)
    context_spy = QSignalSpy(button.customContextMenuRequested)
    host.show()
    app.processEvents()

    QTest.keyClick(button, Qt.Key.Key_F12)
    assert inspector.begin_selection()
    event = QContextMenuEvent(
        QContextMenuEvent.Reason.Mouse,
        button.rect().center(),
        button.mapToGlobal(button.rect().center()),
    )
    QApplication.sendEvent(button, event)
    app.processEvents()
    assert event.isAccepted()
    assert context_spy.count() == 0
    assert inspector.selection_mode is True

    QTest.mouseMove(bar.select_button, bar.select_button.rect().center())
    app.processEvents()
    assert inspector.hovered_metadata is None
    assert bar.select_button.isCheckable() is False
    QTest.mouseClick(bar.select_button, Qt.MouseButton.LeftButton)
    assert inspector.selection_mode is True
    assert bar.select_button.text() == "선택 중 (Esc로 취소)"

    QTest.mouseClick(bar.exit_button, Qt.MouseButton.LeftButton)
    assert inspector.selection_mode is False
    assert inspector.enabled is False


def test_non_inspector_modal_cancels_selection_but_keeps_f12_mode_usable(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    app = _app()
    host = QWidget()
    qtbot.addWidget(host)
    target = QPushButton("선택 대상", host)
    inspector.register_widget(target, _metadata())
    host.show()
    app.processEvents()

    QTest.keyClick(target, Qt.Key.Key_F12)
    assert inspector.begin_selection()

    modal = QDialog(host)
    qtbot.addWidget(modal)
    modal.setModal(True)
    modal_button = QPushButton("안전 확인", modal)
    QVBoxLayout(modal).addWidget(modal_button)
    clicked = QSignalSpy(modal_button.clicked)
    modal.show()
    app.processEvents()

    assert inspector.selection_mode is False
    assert inspector.enabled is True
    QTest.mouseClick(modal_button, Qt.MouseButton.LeftButton)
    assert clicked.count() == 1

    # Inspector-owned nonmodal dialogs never trigger the safety cancellation.
    assert inspector.begin_selection()
    catalog = inspector.show_catalog(host)
    assert catalog is not None
    app.processEvents()
    assert inspector.selection_mode is True
    inspector.cancel_selection()


def test_request_and_clipboard_use_only_registered_static_metadata(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    app = _app()
    runtime_widget = QPushButton("password=do-not-copy 192.0.2.33 customer-controller")
    qtbot.addWidget(runtime_widget)
    metadata = _metadata(
        "MAIN-SETTINGS-SAVE",
        name="장비 설정 저장 버튼",
        screen="메인 화면 > 장비 설정",
        purpose="장비 주소와 조회 주기를 로컬 설정 파일에 저장합니다.",
    )
    inspector.register_widget(runtime_widget, metadata)
    expected = (
        "프로그램 버전: v0.3.0\n"
        "화면 위치: 메인 화면 > 장비 설정\n"
        "요소 이름: 장비 설정 저장 버튼\n"
        "UI 식별자: MAIN-SETTINGS-SAVE\n"
        "소스 위치: src/aruba_session_tracker/ui/main_window.py\n"
        "용도: 장비 주소와 조회 주기를 로컬 설정 파일에 저장합니다.\n\n"
        "현재 현상:\n"
        "원하는 변경:\n"
    )

    assert inspector.request_text(metadata) == expected
    assert build_static_request_text(metadata, "v0.3.0") == expected
    assert "password" not in expected
    assert "192.0.2.33" not in expected
    assert "customer-controller" not in expected

    runtime_widget.show()
    app.processEvents()
    QTest.keyClick(runtime_widget, Qt.Key.Key_F12)
    dialog = inspector.show_element_detail(metadata)
    assert dialog is not None
    dialog.request_preview.setPlainText("runtime-secret-must-not-be-copied")
    copied = dialog.copy_request()
    assert copied == expected
    assert QApplication.clipboard().text() == expected
    assert "runtime-secret" not in copied


def test_catalog_dialog_can_open_virtual_entry_details(
    qtbot: Any,
    inspector: DeveloperInspectorController,
) -> None:
    host = QWidget()
    qtbot.addWidget(host)
    virtual = _metadata(
        "MAIN-HISTORY-RUN-TABLE-SELECTION",
        name="기록표 선택 실행",
        screen="메인 화면 > 기록 및 내보내기 > 실행 기록표",
        purpose="기록표에서 선택한 실행을 나타내는 정적 가상 항목입니다.",
    )
    inspector.register_catalog_item(virtual)
    host.show()
    _app().processEvents()
    QTest.keyClick(host, Qt.Key.Key_F12)

    catalog = inspector.show_catalog(host)
    assert catalog is not None
    assert catalog.element_list.count() == 1
    QTest.mouseClick(catalog.details_button, Qt.MouseButton.LeftButton)
    _app().processEvents()
    detail = inspector.detail_dialog
    assert detail is not None
    assert detail.metadata == virtual
    assert detail.parentWidget() is host

    host.close()
    _app().processEvents()
    assert not detail.isVisible()
    assert not catalog.isVisible()


def test_close_is_idempotent_and_restores_transient_state(
    qtbot: Any,
) -> None:
    app = _app()
    host = QWidget()
    qtbot.addWidget(host)
    child = QPushButton("대상", host)
    controller = DeveloperInspectorController(app, "v0.3.0")
    controller.register_widget(child, _metadata())
    original_tracking = child.hasMouseTracking()
    host.show()
    app.processEvents()
    QTest.keyClick(child, Qt.Key.Key_F12)
    assert controller.begin_selection()

    controller.close()
    controller.close()
    assert controller.enabled is False
    assert controller.selection_mode is False
    assert child.hasMouseTracking() is original_tracking
    QTest.keyClick(child, Qt.Key.Key_F12)
    assert controller.enabled is False
