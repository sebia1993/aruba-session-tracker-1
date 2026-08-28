from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMessageBox

from aruba_session_tracker import __version__
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.runtime import RuntimeExecutor
from aruba_session_tracker.storage import SessionStore, StorageError
from aruba_session_tracker.ui import MainWindow


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="ArubaSessionTracker")
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--gui-smoke-test", action="store_true")
    parser.add_argument("--version", action="store_true")
    options = parser.parse_args(arguments)
    if options.version:
        print(__version__)
        return 0
    if options.smoke_test:
        print(f"ARUBA_SESSION_TRACKER_SMOKE_OK {__version__}")
        return 0

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


if __name__ == "__main__":
    raise SystemExit(main())
