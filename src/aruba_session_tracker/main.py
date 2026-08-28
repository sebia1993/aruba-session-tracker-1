from __future__ import annotations

import argparse
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from aruba_session_tracker import __version__
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import (
    DiagnosticEvent,
    ErrorCode,
    QueryRequest,
    SessionObservation,
)
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.runtime import RuntimeExecutor
from aruba_session_tracker.storage import SessionStore, StorageError
from aruba_session_tracker.ui import MainWindow


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="ArubaSessionTracker")
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--gui-smoke-test", action="store_true")
    parser.add_argument("--report-smoke-test", type=Path)
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

    existing = QApplication.instance()
    application = (
        existing if isinstance(existing, QApplication) else QApplication([sys.argv[0], *arguments])
    )
    application.setApplicationName("Aruba Session Tracker")
    application.setApplicationVersion(__version__)
    try:
        paths = AppPaths.default()
        paths.ensure()
        repository = ConfigRepository(paths.config)
        store = SessionStore(paths.database, paths.raw, paths.exports)
        store.initialize()
        executor = RuntimeExecutor(paths, store)
    except (OSError, StorageError) as exc:
        QMessageBox.critical(
            None,
            "Aruba Session Tracker 시작 실패",
            "로컬 저장소를 초기화할 수 없습니다. 디스크 공간과 LocalAppData 권한을 "
            f"확인하십시오.\n\n오류 유형: {type(exc).__name__}",
        )
        return 1

    window = MainWindow(repository, store, executor)
    window.show()
    if options.gui_smoke_test:
        QTimer.singleShot(300, application.quit)
    exit_code = application.exec()
    if options.gui_smoke_test and exit_code == 0:
        print(f"ARUBA_SESSION_TRACKER_GUI_SMOKE_OK {__version__}")
    return exit_code


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
            raw_text="synthetic fixture only",
            controller_name=observation.controller_name,
            captured_at=observed_at,
        )
        store.record_diagnostic(
            DiagnosticEvent(
                stage="report-smoke",
                code=ErrorCode.PARSE_PARTIAL,
                message="합성 데이터 보고서 생성 검증",
                occurred_at=observed_at,
            ),
            run_id=run_id,
        )
        store.finish_run(run_id, ended_at=observed_at)
        written = store.export_run_html(run_id, destination)
    text = written.read_text(encoding="utf-8")
    if (
        "<!doctype html>" not in text.casefold()
        or "한국어-MD" not in text
        or "https://" in text.casefold()
        or "http://" in text.casefold()
    ):
        print("ARUBA_SESSION_TRACKER_REPORT_SMOKE_FAILED", file=sys.stderr)
        return 1
    print(f"ARUBA_SESSION_TRACKER_REPORT_SMOKE_OK {__version__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
