from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import re
import sys
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QEvent, QEventLoop, Qt, QTimer
from PySide6.QtGui import QKeyEvent
from PySide6.QtNetwork import QSslSocket
from PySide6.QtWidgets import QApplication, QMessageBox

from aruba_session_tracker import __version__
from aruba_session_tracker.collectors import CancellationToken
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import (
    AppConfig,
    Credentials,
    DeviceTarget,
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.observability import CrashJournal, ExceptionHookManager
from aruba_session_tracker.paths import AppPaths, UnsafeManagedPath
from aruba_session_tracker.runtime import RuntimeExecutor
from aruba_session_tracker.single_instance import SingleInstanceGuard
from aruba_session_tracker.storage import SessionStore, StorageError
from aruba_session_tracker.ui import DeveloperInspectorController, MainWindow
from aruba_session_tracker.ui.startup import StartupCoordinator, StartupWindow
from aruba_session_tracker.ui.theme import apply_main_window_theme


@dataclass(frozen=True, slots=True)
class _RuntimeBundle:
    repository: ConfigRepository
    store: SessionStore
    executor: RuntimeExecutor
    journal: CrashJournal


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="ArubaSessionTracker")
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--gui-smoke-test", action="store_true")
    parser.add_argument("--report-smoke-test", type=Path)
    parser.add_argument("--tls-backend-smoke", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--loopback-ssh-smoke",
        choices=("success", "auth-failure"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--loopback-ssh-port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--loopback-ssh-fingerprint", help=argparse.SUPPRESS)
    parser.add_argument("--version", action="store_true")
    options = parser.parse_args(arguments)
    if options.version:
        print(__version__)
        return 0
    if options.smoke_test:
        print(f"ARUBA_SESSION_TRACKER_SMOKE_OK {__version__}")
        return 0
    if options.report_smoke_test is not None:
        return _report_smoke_test(options.report_smoke_test)
    if options.tls_backend_smoke:
        return _tls_backend_smoke()
    if options.loopback_ssh_smoke is not None:
        if options.loopback_ssh_port is None or options.loopback_ssh_fingerprint is None:
            parser.error("loopback SSH smoke requires port and fingerprint")
        return _loopback_runtime_smoke(
            options.loopback_ssh_port,
            options.loopback_ssh_fingerprint,
            options.loopback_ssh_smoke,
        )

    existing = QApplication.instance()
    application = (
        existing if isinstance(existing, QApplication) else QApplication([sys.argv[0], *arguments])
    )
    application.setApplicationName("Aruba Session Tracker")
    application.setApplicationVersion(__version__)
    paths = AppPaths.default()
    instance_guard = SingleInstanceGuard(str(paths.root))
    try:
        acquired = instance_guard.acquire()
    except OSError as exc:
        QMessageBox.critical(
            None,
            "Aruba Session Tracker 시작 실패",
            "프로그램 실행 상태를 확인할 수 없습니다. LocalAppData 권한을 "
            f"확인하십시오.\n\n오류 유형: {type(exc).__name__}",
        )
        return 1
    if not acquired:
        QMessageBox.information(
            None,
            "Aruba Session Tracker",
            "Aruba Session Tracker가 이미 실행 중입니다.",
        )
        return 0

    startup_window = StartupWindow()
    startup = StartupCoordinator(application)
    startup_loop = QEventLoop()
    startup_result: list[_RuntimeBundle] = []
    startup_failure: list[str] = []

    def startup_ready(result: object) -> None:
        if isinstance(result, _RuntimeBundle):
            startup_result.append(result)
        else:
            startup_failure.append("InvalidStartupResult")
        startup_loop.quit()

    def startup_failed(exception_type: str) -> None:
        startup_failure.append(exception_type)
        startup_loop.quit()

    startup.ready.connect(startup_ready)
    startup.failed.connect(startup_failed)
    startup_window.show()
    startup.start(lambda: _initialize_runtime(paths))
    startup_loop.exec()
    startup_window.hide()
    if not startup_result:
        exception_type = startup_failure[0] if startup_failure else "StartupInitializationError"
        QMessageBox.critical(
            None,
            "Aruba Session Tracker 시작 실패",
            "로컬 저장소를 초기화할 수 없습니다. 디스크 공간과 LocalAppData 권한을 "
            f"확인하십시오.\n\n오류 유형: {exception_type}",
        )
        instance_guard.release()
        return 1

    bundle = startup_result[0]
    hook_manager = ExceptionHookManager(bundle.journal)
    try:
        previous_unclean = bundle.journal.start_session()
        hook_manager.install()
    except (OSError, UnsafeManagedPath, ValueError) as exc:
        QMessageBox.critical(
            None,
            "Aruba Session Tracker 시작 실패",
            "로컬 실행 상태 기록을 안전하게 준비할 수 없습니다. LocalAppData 권한을 "
            f"확인하십시오.\n\n오류 유형: {type(exc).__name__}",
        )
        instance_guard.release()
        return 1

    developer_inspector: DeveloperInspectorController | None = None
    window: MainWindow | None = None
    exit_code = 1
    try:
        developer_inspector = DeveloperInspectorController(
            application,
            f"v{__version__}",
            parent=application,
        )
        window = MainWindow(
            bundle.repository,
            bundle.store,
            bundle.executor,
            developer_inspector=developer_inspector,
        )
        apply_main_window_theme(window)
        window.show()
        if previous_unclean:
            window.statusBar().showMessage(
                "이전 실행이 정상적으로 끝나지 않았습니다. 로컬 기록 복구를 완료했습니다.",
                15_000,
            )
        if options.gui_smoke_test:
            QTimer.singleShot(
                300,
                lambda: _run_gui_smoke_test(application, window, developer_inspector),
            )
        exit_code = application.exec()
    except BaseException as exc:
        # The process hooks must be restored in ``finally``.  Record this
        # boundary explicitly first so a MainWindow/application failure is not
        # reduced to a generic incomplete-shutdown marker.
        with suppress(OSError, UnsafeManagedPath):
            bundle.journal.record(
                "UNHANDLED_EXCEPTION",
                type(exc).__name__,
                stage="MAIN_THREAD",
            )
        raise
    finally:
        if developer_inspector is not None:
            developer_inspector.close()
        hook_manager.restore()
        ui_clean = bool(
            (window is not None and window.clean_shutdown_completed)
            or (options.gui_smoke_test and exit_code == 0)
        )
        storage_closed = ui_clean
        if ui_clean:
            try:
                bundle.store.close()
            except StorageError:
                storage_closed = False
        # A grace-timeout path must never wait on a worker-held store lock.
        # The exiting process releases those handles and startup recovery marks
        # unfinished DB runs safely on the next launch.
        clean_shutdown = ui_clean and storage_closed
        with suppress(OSError, UnsafeManagedPath):
            if clean_shutdown:
                bundle.journal.mark_clean_exit()
            else:
                bundle.journal.record(
                    "CONTROLLED_SHUTDOWN_INCOMPLETE",
                    "RecoveryRequired",
                    stage="SHUTDOWN",
                )
        instance_guard.release()
    if options.gui_smoke_test and exit_code == 0:
        print(f"ARUBA_SESSION_TRACKER_GUI_SMOKE_OK {__version__}")
    return exit_code


def _tls_backend_smoke() -> int:
    available = tuple(str(value).casefold() for value in QSslSocket.availableBackends())
    active = str(QSslSocket.activeBackend()).casefold()
    if "schannel" not in available or "openssl" in available or active != "schannel":
        print(
            "ARUBA_SESSION_TRACKER_TLS_BACKEND_FAILED "
            f"active={active or '-'} available={','.join(available) or '-'}",
            file=sys.stderr,
        )
        return 1
    print("ARUBA_SESSION_TRACKER_TLS_BACKEND_OK active=schannel")
    return 0


def _initialize_runtime(paths: AppPaths) -> _RuntimeBundle:
    paths.ensure()
    repository = ConfigRepository(paths.config)
    store = SessionStore(paths.database, paths.raw, paths.exports)
    store.initialize()
    executor = RuntimeExecutor(paths, store)
    journal = CrashJournal(
        paths.root / "diagnostics" / "crash-journal.jsonl",
        managed_root=paths.root,
    )
    return _RuntimeBundle(repository, store, executor, journal)


def _run_gui_smoke_test(
    application: QApplication,
    window: MainWindow,
    developer_inspector: DeveloperInspectorController,
) -> None:
    try:
        if developer_inspector.enabled:
            raise RuntimeError("developer inspector started enabled")
        _send_plain_f12(application, window)
        if not developer_inspector.enabled:
            raise RuntimeError("developer inspector did not enable")
        _send_plain_f12(application, window)
        if developer_inspector.enabled:
            raise RuntimeError("developer inspector did not disable")
    except Exception as exc:
        print(
            f"ARUBA_SESSION_TRACKER_GUI_SMOKE_FAILED {type(exc).__name__}",
            file=sys.stderr,
        )
        application.exit(1)
        return
    application.quit()


def _send_plain_f12(application: QApplication, window: MainWindow) -> None:
    for event_type in (QEvent.Type.KeyPress, QEvent.Type.KeyRelease):
        event = QKeyEvent(
            event_type,
            Qt.Key.Key_F12,
            Qt.KeyboardModifier.NoModifier,
        )
        application.sendEvent(window, event)


def _report_smoke_test(destination: Path) -> int:
    observed_at = datetime(2026, 8, 28, 9, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory(prefix="aruba-session-report-smoke-") as temporary:
        root = Path(temporary)
        store = SessionStore(root / "tracker.db", root / "raw", root / "exports")
        store.initialize()
        run_id = store.start_run(
            QueryRequest("192.0.2.10", "203.0.113.20", 53000, 443),
            started_at=observed_at,
        )
        run_finished = False
        try:
            observation = SessionObservation(
                controller_name="한국어-MD",
                controller_host="198.51.100.21",
                protocol=6,
                source_ip="192.0.2.10",
                destination_ip="203.0.113.20",
                source_port=53000,
                destination_port=443,
                packets=12,
                bytes_count=2048,
                flags="DY",
                cpu_id=1,
                observed_at=observed_at,
            )
            store.record_query(
                run_id,
                (observation,),
                raw_text="PACKAGE-RAW-CANARY",
                controller_name=observation.controller_name,
                captured_at=observed_at,
            )
            store.record_diagnostic(
                DiagnosticEvent(
                    stage="report-smoke",
                    code=ErrorCode.PARSE_PARTIAL,
                    message="PACKAGE-DIAGNOSTIC-CANARY",
                    occurred_at=observed_at,
                ),
                run_id=run_id,
            )
            store.finish_run(run_id, ended_at=observed_at)
            run_finished = True
            written = store.export_run_html(run_id, destination)
        finally:
            if not run_finished:
                # A failed package self-test must not leave a Windows lease
                # handle open and hide the original failure during temp cleanup.
                with suppress(StorageError):
                    store.finish_run(run_id, status="FAILED")
            with suppress(StorageError):
                store.close()
    text = written.read_text(encoding="utf-8")
    required = (
        "세션 추적 결과",
        "결과 찾기",
        "최신 세션 결과",
        "전체 추적 이력",
        "조회 출발지",
        "출발지 IP·포트",
        "목적지 IP·포트",
        "KST",
        "한국어-MD",
        'id="result-filter"',
        'id="filter-ip"',
        'id="filter-protocol"',
        'id="filter-port"',
        'class="report-row"',
        'class="flow-panel"',
        'class="summary-stats"',
        'class="protocol-cell"',
        "script-src 'sha256-",
    )
    forbidden = (
        "PACKAGE-RAW-CANARY",
        "PACKAGE-DIAGNOSTIC-CANARY",
        "PARSE_PARTIAL",
        "report-smoke",
        "Troubleshooting",
        "CLI와 Quick Reference",
        "세션별 수치 변화",
        "패킷",
        "바이트",
        "XMLHttpRequest",
        "WebSocket",
        "navigator.clipboard",
        "localStorage",
        "sessionStorage",
        "eval(",
    )
    section_positions = tuple(
        text.find(marker) for marker in ("결과 찾기", "최신 세션 결과", "전체 추적 이력")
    )
    history_markers = (
        '<details class="history-toggle">',
        '<div class="details-body" id="observation-history-body">',
        ".history-toggle + .details-body { display:block !important; }",
    )
    if (
        "<!doctype html>" not in text.casefold()
        or any(marker not in text for marker in required)
        or any(marker in text for marker in forbidden)
        or section_positions != tuple(sorted(section_positions))
        or any(marker not in text for marker in history_markers)
        or not _report_filter_script_is_hash_authorized(text)
        or "<details open" in text
        or "https://" in text.casefold()
        or "http://" in text.casefold()
    ):
        print("ARUBA_SESSION_TRACKER_REPORT_SMOKE_FAILED", file=sys.stderr)
        return 1
    print(f"ARUBA_SESSION_TRACKER_REPORT_SMOKE_OK {__version__}")
    return 0


def _report_filter_script_is_hash_authorized(text: str) -> bool:
    scripts = re.findall(r"<script>(.*?)</script>", text, flags=re.IGNORECASE | re.DOTALL)
    if len(scripts) != 1:
        return False
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode("utf-8")).digest()).decode("ascii")
    return f"script-src 'sha256-{digest}'" in text


def _loopback_runtime_smoke(port: int, fingerprint: str, mode: str) -> int:
    """Exercise the real SSH/runtime/storage path against a loopback-only fixture."""

    if (
        type(port) is not int
        or not 1 <= port <= 65535
        or re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) is None
        or mode not in {"success", "auth-failure"}
    ):
        print("ARUBA_SESSION_TRACKER_LOOPBACK_SSH_SMOKE_FAILED InvalidArguments", file=sys.stderr)
        return 2
    username = "fixture-operator"
    accepted_password = username[::-1]
    password = accepted_password if mode == "success" else f"{accepted_password}-invalid"
    try:
        with tempfile.TemporaryDirectory(prefix="aruba-session-loopback-smoke-") as temporary:
            root = Path(temporary)
            paths = AppPaths(
                root=root,
                config=root / "config.json",
                known_hosts=root / "known_hosts",
                database=root / "tracker.db",
                raw=root / "raw",
                exports=root / "exports",
            )
            paths.ensure()
            store = SessionStore(paths.database, paths.raw, paths.exports)
            store.initialize()
            executor = RuntimeExecutor(paths, store)
            loopback = "127.0.0.1"
            config = AppConfig(
                mm_primary=DeviceTarget("loopback-mm", loopback, port),
                mm_standby=DeviceTarget("loopback-standby", loopback, port, enabled=False),
                managed_devices=(DeviceTarget("loopback-md", loopback, port),),
            )
            request = QueryRequest("192.0.2.10", "203.0.113.20", 54321, 443, False)
            outcome = executor.execute(
                config,
                request,
                Credentials(username, password),
                monitoring=False,
                cancel_token=CancellationToken(),
                host_key_approval=lambda _target, info: hmac.compare_digest(
                    info.sha256_fingerprint,
                    fingerprint,
                ),
                full_scan_approval=lambda *_args: False,
            )
            codes = {
                getattr(getattr(event, "code", None), "value", None)
                for event in getattr(outcome, "diagnostics", ())
            }
            observations = tuple(getattr(outcome, "observations", ()))
            runs = store.list_runs(limit=10)
            stored_observation_count = runs[0].get("observation_count") if runs else None
            if mode == "success":
                checks = {
                    "Authoritative": bool(getattr(outcome, "authoritative", False)),
                    "ObservationCount": len(observations) == 1,
                    "Protocol": bool(observations) and observations[0].protocol == 6,
                    "SourcePort": bool(observations) and observations[0].source_port == 54321,
                    "DestinationPort": bool(observations)
                    and observations[0].destination_port == 443,
                    "RunStored": bool(runs),
                    "ObservationStored": type(stored_observation_count) is int
                    and stored_observation_count == 1,
                }
            else:
                checks = {
                    "AuthFailed": ErrorCode.AUTH_FAILED.value in codes,
                    "NoObservations": not observations,
                    "RunStored": bool(runs),
                }
            failed_checks = tuple(name for name, passed in checks.items() if not passed)
            if failed_checks:
                print(
                    "ARUBA_SESSION_TRACKER_LOOPBACK_SSH_SMOKE_FAILED "
                    f"Invariant_{'_'.join(failed_checks)}",
                    file=sys.stderr,
                )
                return 1
    except Exception as exc:
        print(
            f"ARUBA_SESSION_TRACKER_LOOPBACK_SSH_SMOKE_FAILED {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    print(f"ARUBA_SESSION_TRACKER_LOOPBACK_SSH_{mode.upper().replace('-', '_')}_OK {__version__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
