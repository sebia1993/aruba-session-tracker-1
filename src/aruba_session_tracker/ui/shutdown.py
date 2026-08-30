"""Asynchronous, idempotent stop/finalization coordination for the GUI."""

from __future__ import annotations

import threading
import weakref
from collections.abc import Callable

from PySide6.QtCore import QObject, QTimer, Signal, Slot

_DEFAULT_GRACE_MILLISECONDS = 15_000


class ShutdownCoordinator(QObject):
    """Run recoverable finalization without blocking Qt's GUI thread.

    The worker is deliberately a daemon thread. A storage transaction is never
    killed or interrupted by this class; after the grace period the UI is merely
    allowed to close and the existing startup recovery owns any unfinished run.
    Late worker completion is ignored by generation.
    """

    stage_changed = Signal(str)
    settled = Signal(bool, str)
    _worker_completed = Signal(int, bool, str)

    def __init__(
        self,
        operation: Callable[[], None],
        parent: QObject | None = None,
        *,
        grace_milliseconds: int = _DEFAULT_GRACE_MILLISECONDS,
    ) -> None:
        super().__init__(parent)
        if type(grace_milliseconds) is not int or grace_milliseconds < 1:
            raise ValueError("grace_milliseconds must be a positive integer")
        self._operation = operation
        self._generation = 0
        self._active_generation: int | None = None
        self._requested = False
        self._restart_required = False
        self._grace_timer = QTimer(self)
        self._grace_timer.setSingleShot(True)
        self._grace_timer.setInterval(grace_milliseconds)
        self._grace_timer.timeout.connect(self._grace_expired)
        self._worker_completed.connect(self._complete)

    @property
    def active(self) -> bool:
        return self._active_generation is not None

    @property
    def restart_required(self) -> bool:
        return self._restart_required

    def request(self) -> bool:
        """Start finalization once; repeated requests while active are no-ops."""

        if self._requested:
            return False
        self._requested = True
        self._generation += 1
        generation = self._generation
        self._active_generation = generation
        self.stage_changed.emit("종료 기록 정리 중")
        self._grace_timer.start()
        thread = threading.Thread(
            target=_run_operation,
            args=(self._operation, weakref.ref(self), generation),
            name="aruba-session-shutdown",
            daemon=True,
        )
        thread.start()
        return True

    def reset(self) -> None:
        """Arm the coordinator for a later independent monitoring lifecycle."""

        if self.active:
            raise RuntimeError("cannot reset active shutdown coordination")
        if self._restart_required:
            raise RuntimeError("application restart is required after incomplete finalization")
        self._requested = False

    @Slot(int, bool, str)
    def _complete(self, generation: int, succeeded: bool, exception_type: str) -> None:
        if not self._finish(generation):
            return
        if succeeded:
            self.stage_changed.emit("종료 정리 완료")
            self.settled.emit(True, "")
            return
        self._restart_required = True
        self.stage_changed.emit("종료 기록 확인 필요")
        self.settled.emit(False, exception_type)

    @Slot()
    def _grace_expired(self) -> None:
        generation = self._active_generation
        if generation is None or not self._finish(generation):
            return
        self._restart_required = True
        self.stage_changed.emit("종료 정리를 다음 실행에서 복구합니다")
        self.settled.emit(False, "ShutdownGraceTimeout")

    def _finish(self, generation: int) -> bool:
        if self._active_generation != generation:
            return False
        self._active_generation = None
        self._grace_timer.stop()
        return True


def _run_operation(
    operation: Callable[[], None],
    owner: weakref.ReferenceType[ShutdownCoordinator],
    generation: int,
) -> None:
    try:
        operation()
    except BaseException as exc:
        succeeded = False
        exception_type = type(exc).__name__
    else:
        succeeded = True
        exception_type = ""
    coordinator = owner()
    if coordinator is None:
        return
    try:
        coordinator._worker_completed.emit(generation, succeeded, exception_type)
    except RuntimeError:
        # The Qt object may already have been destroyed after a grace timeout.
        return


__all__ = ["ShutdownCoordinator"]
