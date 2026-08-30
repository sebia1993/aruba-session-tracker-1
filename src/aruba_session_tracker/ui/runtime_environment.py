"""Testable sleep/resume and network-environment discontinuity signals."""

from __future__ import annotations

from collections.abc import Callable
from time import monotonic

from PySide6.QtCore import QObject, QTimer, Signal, Slot

try:
    from PySide6.QtNetwork import QNetworkInformation
except ImportError:  # pragma: no cover - QtNetwork is part of the supported bundle
    QNetworkInformation = None  # type: ignore[assignment,misc]


class RuntimeEnvironmentMonitor(QObject):
    """Emit sanitized reasons when polling assumptions may have become stale."""

    discontinuity = Signal(str)

    def __init__(
        self,
        parent: QObject | None = None,
        *,
        clock: Callable[[], float] = monotonic,
        sample_interval_ms: int = 5_000,
        resume_gap_seconds: float = 15.0,
    ) -> None:
        super().__init__(parent)
        self._clock = clock
        self._resume_gap_seconds = resume_gap_seconds
        self._last_sample = clock()
        self._timer = QTimer(self)
        self._timer.setInterval(sample_interval_ms)
        self._timer.timeout.connect(self.sample_now)
        self._network_debounce = QTimer(self)
        self._network_debounce.setSingleShot(True)
        self._network_debounce.setInterval(500)
        self._network_debounce.timeout.connect(self.notify_adapter_change)
        self._network_information: object | None = None
        self._attach_network_information()
        self._timer.start()

    @Slot()
    def sample_now(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last_sample)
        self._last_sample = now
        if elapsed >= self._resume_gap_seconds:
            self.notify_resume()

    @Slot()
    def notify_resume(self) -> None:
        self.discontinuity.emit("SYSTEM_RESUMED")

    @Slot()
    def notify_adapter_change(self) -> None:
        self.discontinuity.emit("NETWORK_CHANGED")

    @Slot()
    def _queue_network_change(self, *_args: object) -> None:
        self._network_debounce.start()

    def _attach_network_information(self) -> None:
        if QNetworkInformation is None:
            return
        try:
            QNetworkInformation.loadDefaultBackend()
            information = QNetworkInformation.instance()
        except RuntimeError:
            return
        if information is None:
            return
        self._network_information = information
        information.reachabilityChanged.connect(self._queue_network_change)
        information.transportMediumChanged.connect(self._queue_network_change)


__all__ = ["RuntimeEnvironmentMonitor"]
