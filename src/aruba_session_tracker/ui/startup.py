"""Small responsive startup surface and background initialization runner."""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable

from PySide6.QtCore import QObject, Qt, QTimer, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget


class StartupWindow(QWidget):
    """Show bounded, non-technical progress while local storage is checked."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Aruba Session Tracker 시작")
        self.setFixedSize(420, 130)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        self.message = QLabel("로컬 저장소를 안전하게 확인하고 있습니다.")
        self.message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.message.setWordWrap(True)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        layout.addWidget(self.message)
        layout.addWidget(self.progress)

    def closeEvent(self, event: QCloseEvent) -> None:
        """Keep the bounded startup loop visible until it settles or times out."""

        self.message.setText("시작 상태를 확인 중입니다. 최대 30초 안에 자동으로 끝납니다.")
        event.ignore()


class StartupCoordinator(QObject):
    ready = Signal(object)
    failed = Signal(str)
    _worker_completed = Signal(int, bool, object)

    def __init__(
        self,
        parent: QObject | None = None,
        *,
        grace_milliseconds: int = 30_000,
    ) -> None:
        super().__init__(parent)
        if type(grace_milliseconds) is not int or grace_milliseconds < 1:
            raise ValueError("grace_milliseconds must be a positive integer")
        self._started = False
        self._generation = 0
        self._active_generation: int | None = None
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(grace_milliseconds)
        self._timer.timeout.connect(self._grace_expired)
        self._worker_completed.connect(self._completed)

    def start(self, operation: Callable[[], object]) -> None:
        if self._started:
            raise RuntimeError("startup initialization already started")
        self._started = True
        self._generation += 1
        generation = self._generation
        self._active_generation = generation
        self._timer.start()
        thread = threading.Thread(
            target=_run_startup_operation,
            args=(operation, weakref.ref(self), generation),
            name="aruba-session-startup",
            daemon=True,
        )
        thread.start()

    @Slot(int, bool, object)
    def _completed(self, generation: int, succeeded: bool, result: object) -> None:
        if self._active_generation != generation:
            return
        self._active_generation = None
        self._timer.stop()
        if succeeded:
            self.ready.emit(result)
        else:
            self.failed.emit(str(result))

    @Slot()
    def _grace_expired(self) -> None:
        if self._active_generation is None:
            return
        self._active_generation = None
        self.failed.emit("StartupGraceTimeout")


def _run_startup_operation(
    operation: Callable[[], object],
    owner: weakref.ReferenceType[StartupCoordinator],
    generation: int,
) -> None:
    try:
        result = operation()
        succeeded = True
    except Exception as exc:
        result = type(exc).__name__
        succeeded = False
    coordinator = owner()
    if coordinator is None:
        return
    try:
        coordinator._worker_completed.emit(generation, succeeded, result)
    except RuntimeError:
        return


__all__ = ["StartupCoordinator", "StartupWindow"]
