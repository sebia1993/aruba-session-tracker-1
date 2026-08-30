from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from shiboken6 import delete as delete_qt_object

from aruba_session_tracker.collectors.ssh import CollectorError
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.ui.main_window import MainWindow, _StorageTask
from aruba_session_tracker.ui.runtime_environment import RuntimeEnvironmentMonitor
from aruba_session_tracker.ui.shutdown import ShutdownCoordinator
from aruba_session_tracker.ui.startup import StartupCoordinator, StartupWindow


class _EmptyStore:
    @property
    def pending_external_recovery_count(self) -> int:
        return 0

    def retry_pending_external_recoveries(self) -> int:
        return 0

    def list_runs(self, *, limit: int = 100) -> tuple[object, ...]:
        del limit
        return ()


class _EnvironmentExecutor:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.invalidations = 0
        self.stop_calls = 0

    def execute(self, *_args: object, **kwargs: object) -> object:
        token = kwargs["cancel_token"]
        self.started.set()
        if not token.wait(3):
            raise TimeoutError("fixture cancellation was not received")
        raise CollectorError(ErrorCode.CANCELLED, "fixture cancelled")

    def stop_monitor(self) -> None:
        self.stop_calls += 1

    def invalidate_monitor_location(self) -> None:
        self.invalidations += 1


class _BlockedStopExecutor:
    def __init__(self) -> None:
        self.execute_calls = 0
        self.release = threading.Event()

    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        self.execute_calls += 1
        return QueryOutcome(authoritative=True)

    def stop_monitor(self) -> None:
        self.release.wait(3)


def _configure_valid_query(window: MainWindow) -> None:
    window.mm_primary_host.setText("192.0.2.1")
    window.mm_standby_host.setText("192.0.2.2")
    window.md_table.item(0, 2).setText("198.51.100.21")
    for row in range(1, 4):
        window.md_table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
    window.username_edit.setText("operator")
    window.password_edit.setText("session-only")
    window.source_ip_edit.setText("192.0.2.10")
    window.destination_ip_edit.setText("203.0.113.20")


def test_shutdown_coordinator_is_idempotent_and_runs_off_gui_thread(qtbot: object) -> None:
    caller_thread = threading.get_ident()
    worker_threads: list[int] = []
    settled: list[tuple[bool, str]] = []
    coordinator = ShutdownCoordinator(lambda: worker_threads.append(threading.get_ident()))
    coordinator.settled.connect(lambda ok, code: settled.append((ok, code)))

    assert coordinator.request()
    assert not coordinator.request()
    qtbot.waitUntil(lambda: settled == [(True, "")], timeout=3_000)  # type: ignore[attr-defined]
    assert worker_threads and worker_threads[0] != caller_thread

    coordinator.reset()
    assert coordinator.request()
    qtbot.waitUntil(lambda: len(settled) == 2, timeout=3_000)  # type: ignore[attr-defined]
    assert settled == [(True, ""), (True, "")]


def test_shutdown_grace_timeout_settles_once_without_killing_transaction(qtbot: object) -> None:
    release = threading.Event()
    settled: list[tuple[bool, str]] = []
    coordinator = ShutdownCoordinator(
        lambda: release.wait(3),
        grace_milliseconds=30,
    )
    coordinator.settled.connect(lambda ok, code: settled.append((ok, code)))

    assert coordinator.request()
    qtbot.waitUntil(lambda: bool(settled), timeout=3_000)  # type: ignore[attr-defined]
    assert settled == [(False, "ShutdownGraceTimeout")]
    assert not coordinator.active
    assert coordinator.restart_required

    with pytest.raises(RuntimeError, match="restart"):
        coordinator.reset()

    release.set()
    qtbot.wait(100)  # type: ignore[attr-defined]
    assert settled == [(False, "ShutdownGraceTimeout")]


def test_deferred_close_callback_is_bound_to_window_lifetime(
    qtbot: object,
    tmp_path: Path,
) -> None:
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        _EnvironmentExecutor(),  # type: ignore[arg-type]
    )
    qtbot.waitUntil(lambda: not window._history_task_running, timeout=3_000)  # type: ignore[attr-defined]
    window._close_when_idle = True

    window._close_if_idle()
    delete_qt_object(window)
    application = QApplication.instance()
    assert application is not None
    application.processEvents()


def test_storage_worker_ignores_late_signal_after_qt_teardown() -> None:
    task = _StorageTask(1, "fixture", lambda _cancel, _progress: object())
    delete_qt_object(task.signals)

    task.run()


def test_stop_timeout_blocks_new_monitoring_until_restart(qtbot: object, tmp_path: Path) -> None:
    executor = _BlockedStopExecutor()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        executor,  # type: ignore[arg-type]
        shutdown_grace_milliseconds=30,
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)
    window._start_monitoring()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3_000)  # type: ignore[attr-defined]
    assert executor.execute_calls == 1

    window._stop_work()
    qtbot.waitUntil(lambda: window._shutdown.restart_required, timeout=3_000)  # type: ignore[attr-defined]
    assert not window.query_button.isEnabled()
    assert not window.monitor_button.isEnabled()
    assert window.state_label.text() == "확인 필요"

    window._start_monitoring()
    assert executor.execute_calls == 1
    assert not window._monitoring

    executor.release.set()
    window.close()


def test_blocked_finalizer_cannot_hold_the_gui_process_open(tmp_path: Path) -> None:
    script = textwrap.dedent(
        f"""
        import threading
        from pathlib import Path
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from aruba_session_tracker.config import ConfigRepository
        from aruba_session_tracker.ui.main_window import MainWindow

        class EmptyStore:
            pending_external_recovery_count = 0
            def retry_pending_external_recoveries(self):
                return 0
            def list_runs(self, *, limit=100):
                return ()

        class BlockedExecutor:
            def execute(self, *args, **kwargs):
                raise AssertionError("query must not run")
            def stop_monitor(self):
                threading.Event().wait()

        app = QApplication([])
        window = MainWindow(
            ConfigRepository(Path({str(tmp_path / "config.json")!r})),
            EmptyStore(),
            BlockedExecutor(),
            shutdown_grace_milliseconds=50,
        )
        window.show()
        QTimer.singleShot(0, window.close)
        exit_code = app.exec()
        print(f"BLOCKED_SHUTDOWN_EXIT={{exit_code}} CLEAN={{window.clean_shutdown_completed}}")
        """
    )
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["PYTHONPATH"] = str(Path.cwd() / "src")

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert "BLOCKED_SHUTDOWN_EXIT=0 CLEAN=False" in completed.stdout


def test_blocked_storage_reader_cannot_hold_the_gui_process_open(tmp_path: Path) -> None:
    script = textwrap.dedent(
        f"""
        import threading
        from pathlib import Path
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from aruba_session_tracker.config import ConfigRepository
        from aruba_session_tracker.ui.main_window import MainWindow

        class BlockedStore:
            pending_external_recovery_count = 0
            def retry_pending_external_recoveries(self):
                return 0
            def list_runs(self, *, limit=100):
                threading.Event().wait()

        class Executor:
            def execute(self, *args, **kwargs):
                raise AssertionError("query must not run")
            def stop_monitor(self):
                return None

        app = QApplication([])
        window = MainWindow(
            ConfigRepository(Path({str(tmp_path / "blocked-config.json")!r})),
            BlockedStore(),
            Executor(),
            shutdown_grace_milliseconds=50,
            close_grace_milliseconds=50,
        )
        window.show()
        QTimer.singleShot(0, window.close)
        exit_code = app.exec()
        print(f"BLOCKED_STORAGE_EXIT={{exit_code}} CLEAN={{window.clean_shutdown_completed}}")
        """
    )
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["PYTHONPATH"] = str(Path.cwd() / "src")

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert "BLOCKED_STORAGE_EXIT=0 CLEAN=False" in completed.stdout


def test_blocked_startup_worker_has_finite_nested_loop_and_process_exit() -> None:
    script = textwrap.dedent(
        """
        import threading
        from PySide6.QtCore import QEventLoop
        from PySide6.QtWidgets import QApplication
        from aruba_session_tracker.ui.startup import StartupCoordinator

        app = QApplication([])
        loop = QEventLoop()
        coordinator = StartupCoordinator(grace_milliseconds=50)
        failures = []
        coordinator.failed.connect(lambda code: (failures.append(code), loop.quit()))
        coordinator.start(lambda: threading.Event().wait())
        loop.exec()
        print(f"BLOCKED_STARTUP_EXIT={failures}")
        """
    )
    environment = os.environ.copy()
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["PYTHONPATH"] = str(Path.cwd() / "src")

    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        env=environment,
    )

    assert completed.returncode == 0, completed.stderr
    assert "BLOCKED_STARTUP_EXIT=['StartupGraceTimeout']" in completed.stdout


def test_startup_window_close_is_ignored_with_bounded_wait_message(qtbot: object) -> None:
    window = StartupWindow()
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()

    assert window.close() is False
    assert window.isVisible()
    assert window.message.text() == "시작 상태를 확인 중입니다. 최대 30초 안에 자동으로 끝납니다."
    window.hide()


@pytest.mark.parametrize("grace_milliseconds", (0, -1, True))
def test_startup_coordinator_rejects_invalid_grace(grace_milliseconds: object) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        StartupCoordinator(grace_milliseconds=grace_milliseconds)  # type: ignore[arg-type]


def test_startup_coordinator_is_one_shot_and_ignores_stale_completion(qtbot: object) -> None:
    coordinator = StartupCoordinator(grace_milliseconds=10_000)
    ready: list[object] = []
    coordinator.ready.connect(ready.append)

    coordinator.start(lambda: "ready")
    with pytest.raises(RuntimeError, match="already started"):
        coordinator.start(lambda: "duplicate")
    coordinator._completed(-1, True, "stale")

    qtbot.waitUntil(lambda: ready == ["ready"], timeout=3_000)  # type: ignore[attr-defined]


def test_startup_grace_expiry_handles_idle_and_active_generations(qtbot: object) -> None:
    release = threading.Event()
    failures: list[str] = []
    coordinator = StartupCoordinator(grace_milliseconds=10_000)
    coordinator.failed.connect(failures.append)

    coordinator._grace_expired()
    assert failures == []

    coordinator.start(lambda: release.wait(3))
    coordinator._grace_expired()
    qtbot.waitUntil(lambda: failures == ["StartupGraceTimeout"], timeout=1_000)  # type: ignore[attr-defined]
    release.set()


def test_storage_reconciliation_runs_after_window_start_off_gui_thread(
    qtbot: object,
    tmp_path: Path,
) -> None:
    gui_thread = threading.get_ident()

    class _ReconcileStore(_EmptyStore):
        def __init__(self) -> None:
            self.reconciled = threading.Event()
            self.worker_thread: int | None = None

        def reconcile_storage_health(
            self,
            *,
            cancel_check: object = None,
            progress: object = None,
        ) -> object:
            del cancel_check, progress
            self.worker_thread = threading.get_ident()
            self.reconciled.set()
            return object()

    store = _ReconcileStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _EnvironmentExecutor(),  # type: ignore[arg-type]
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()

    assert store.reconciled.wait(timeout=3)
    qtbot.waitUntil(  # type: ignore[attr-defined]
        lambda: not window._storage_reconciliation_pending,
        timeout=3_000,
    )
    assert store.worker_thread is not None
    assert store.worker_thread != gui_thread

    window.close()


def test_window_close_cancels_background_storage_reconciliation(
    qtbot: object,
    tmp_path: Path,
) -> None:
    class _CancellableReconcileStore(_EmptyStore):
        def __init__(self) -> None:
            self.started = threading.Event()
            self.cancel_observed = threading.Event()

        def reconcile_storage_health(
            self,
            *,
            cancel_check: Callable[[], bool],
            progress: Callable[[str, int, int | None], None],
        ) -> object:
            del progress
            self.started.set()
            while not cancel_check():
                self.cancel_observed.wait(0.01)
            self.cancel_observed.set()
            return object()

    store = _CancellableReconcileStore()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        store,  # type: ignore[arg-type]
        _EnvironmentExecutor(),  # type: ignore[arg-type]
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    window.show()
    assert store.started.wait(timeout=3)

    window.close()

    assert store.cancel_observed.wait(timeout=3)
    qtbot.waitUntil(lambda: not window.isVisible(), timeout=3_000)  # type: ignore[attr-defined]


def test_runtime_environment_detects_monotonic_resume_gap(qtbot: object) -> None:
    now = [10.0]
    monitor = RuntimeEnvironmentMonitor(
        clock=lambda: now[0],
        sample_interval_ms=100_000,
        resume_gap_seconds=15.0,
    )
    reasons: list[str] = []
    monitor.discontinuity.connect(reasons.append)

    now[0] = 20.0
    monitor.sample_now()
    assert reasons == []
    now[0] = 40.0
    monitor.sample_now()
    qtbot.waitUntil(lambda: reasons == ["SYSTEM_RESUMED"], timeout=1_000)  # type: ignore[attr-defined]


def test_resume_cancels_stale_poll_and_forces_location_refresh_without_false_close(
    qtbot: object,
    tmp_path: Path,
) -> None:
    executor = _EnvironmentExecutor()
    window = MainWindow(
        ConfigRepository(tmp_path / "config.json"),
        _EmptyStore(),  # type: ignore[arg-type]
        executor,  # type: ignore[arg-type]
    )
    qtbot.addWidget(window)  # type: ignore[attr-defined]
    _configure_valid_query(window)

    window._start_monitoring()
    assert executor.started.wait(timeout=3)
    window._runtime_environment.notify_resume()
    qtbot.waitUntil(lambda: not window._query_running, timeout=3_000)  # type: ignore[attr-defined]

    assert executor.invalidations == 1
    assert window._monitoring
    assert window.state_label.text() == "재시도 중"
    assert window.result_table.rowCount() == 0
    assert "종료 확인" not in window.context_label.text()
    assert window._monitor_timer.isActive()

    window._stop_work()
    qtbot.waitUntil(lambda: not window._shutdown.active, timeout=3_000)  # type: ignore[attr-defined]
    window.close()
