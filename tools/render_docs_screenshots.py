"""Capture real Qt widgets and the real HTML renderer with synthetic data only.

No RuntimeExecutor, saved user config, credential provider or SSH connection is used.
The output directory receives PNGs and provenance JSON only; the temporary database,
Raw fixture and HTML report are removed after rendering.
"""

# ruff: noqa: S603, S607
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
if sys.platform == "win32":
    os.environ.setdefault("QT_QPA_FONTDIR", str(Path(os.environ["WINDIR"]) / "Fonts"))
os.environ.setdefault("QT_SCALE_FACTOR", "1")

from PySide6 import __version__ as qt_version
from PySide6.QtGui import QFont, QFontDatabase, QFontMetrics, QImage
from PySide6.QtWidgets import QApplication, QLabel

from aruba_session_tracker import __version__
from aruba_session_tracker.config import ConfigRepository
from aruba_session_tracker.models import AppConfig, DeviceTarget, QueryRequest, SessionObservation
from aruba_session_tracker.services import QueryOutcome
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.ui import MainWindow
from aruba_session_tracker.ui.theme import apply_application_popup_theme, apply_main_window_theme

STAMP = datetime(2026, 9, 8, 0, 0, tzinfo=UTC)


class OfflineExecutor:
    def execute(self, *_args: object, **_kwargs: object) -> QueryOutcome:
        raise AssertionError("Documentation captures must not execute a query")

    def stop_monitor(self) -> None:
        return None


def deny_connection(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("Network connections are forbidden in documentation captures")


def drain(app: QApplication, predicate: object = None) -> None:
    deadline = time.monotonic() + 8
    while True:
        app.processEvents()
        if predicate is None or predicate():
            break
        if time.monotonic() > deadline:
            raise RuntimeError("Qt fixture work did not settle within 8 seconds")
        time.sleep(0.01)
    # Text/model callbacks schedule subsequent layout requests. Drain those too,
    # so captures cannot retain a chip width measured for its previous empty text.
    for _ in range(6):
        app.processEvents()
        time.sleep(0.01)


def observations() -> tuple[SessionObservation, ...]:
    return tuple(
        SessionObservation(
            controller_name="DEMO-MD-01",
            controller_host="198.51.100.21",
            protocol=protocol,
            source_ip="192.0.2.101",
            destination_ip=f"203.0.113.{50 + index}",
            source_port=50000 + index,
            destination_port=port,
            packets=10 + index,
            bytes_count=2048 + index * 128,
            flags="DY",
            cpu_id=1,
            raw_line="SYNTHETIC DOCUMENTATION ROW",
            observed_at=STAMP + timedelta(seconds=index * 5),
        )
        for index, (protocol, port) in enumerate(((6, 443), (17, 53), (6, 8443), (6, 443)))
    )


def capture(widget: object, destination: Path, app: QApplication) -> None:
    drain(app)
    if not widget.grab().save(str(destination), "PNG"):
        raise RuntimeError("Could not save Qt screenshot")


def edge_executable() -> Path:
    for key in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA"):
        candidate = Path(os.environ.get(key, "")) / "Microsoft/Edge/Application/msedge.exe"
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("Microsoft Edge on Windows is required for --include-report")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-report", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication([])
    if sys.platform == "win32":
        font_path = Path(os.environ["WINDIR"]) / "Fonts" / "malgun.ttf"
        font_id = QFontDatabase.addApplicationFont(str(font_path))
        if font_id < 0:
            raise RuntimeError("Windows Malgun Gothic could not be loaded")
        family = QFontDatabase.applicationFontFamilies(font_id)[0]
    else:
        family = "Apple SD Gothic Neo"
    app.setFont(QFont(family, 10))
    if not all(QFontMetrics(app.font()).inFontUcs4(ord(char)) for char in "가A1"):
        raise RuntimeError("Documentation font lacks required Korean/Latin glyphs")
    apply_application_popup_theme(app)
    names = ["session-settings.png", "session-query.png", "session-history.png"]
    with tempfile.TemporaryDirectory(prefix="session-docs-") as temporary:
        root = Path(temporary).resolve()
        store = SessionStore(root / "tracker.db", root / "raw", root / "exports")
        store.initialize()
        config = ConfigRepository(root / "config.json")
        config.save(
            AppConfig(
                mm_primary=DeviceTarget("DEMO-MM-Primary", "192.0.2.1"),
                mm_standby=DeviceTarget("DEMO-MM-Standby", "192.0.2.2"),
                managed_devices=(DeviceTarget("DEMO-MD-01", "198.51.100.21"),),
            )
        )
        rows = observations()
        request = QueryRequest("192.0.2.101", "", None, None)
        # Each displayed row is a synthetic observation of this source address.
        run_id = store.start_run(request, started_at=STAMP)
        store.record_query(
            run_id,
            rows,
            raw_text="SYNTHETIC DOCUMENTATION ROWS",
            controller_name="DEMO-MD-01",
            captured_at=STAMP,
        )
        store.finish_run(run_id, ended_at=STAMP + timedelta(minutes=1))
        report = store.export_run_html(run_id, root / "synthetic-report.html")
        with (
            patch.object(socket.socket, "connect", deny_connection),
            patch.object(socket.socket, "connect_ex", deny_connection),
            patch.object(socket, "create_connection", deny_connection),
        ):
            window = MainWindow(config, store, OfflineExecutor())
            apply_main_window_theme(window)
            window.resize(1680, 1080)
            window.show()
            drain(app, lambda: not window._history_task_running)
            window.tabs.setCurrentWidget(window.settings_page)
            capture(window, output / names[0], app)
            window.tabs.setCurrentWidget(window.query_page)
            window.source_ip_edit.setText("192.0.2.101")
            window.source_port_edit.clear()
            window._display_outcome(
                QueryOutcome(
                    observations=rows,
                    used_mm="DEMO-MM-Primary",
                    controllers=("DEMO-MD-01",),
                    authoritative=True,
                )
            )
            # The display fixture bypasses _start_query, so seed the same run
            # timing fields from the synthetic stored run before capturing.
            window._run_started_at = STAMP
            window._run_started_monotonic = time.monotonic() - 60
            window._refresh_elapsed_labels()
            window.result_table.selectRow(0)
            window.raw_diagnostics_toggle.setChecked(True)
            window.details.setCurrentIndex(0)
            drain(app)
            for label in window.nav_identity.findChildren(QLabel, "headerChipValue"):
                if label.width() < label.fontMetrics().horizontalAdvance(label.text()):
                    raise RuntimeError("Header text is clipped after fixture layout settled")
            if "2026-09-08 09:00:00 KST" not in window.elapsed_label.text():
                raise RuntimeError("Synthetic query start time was not rendered")
            if window.elapsed_label.height() < window.elapsed_label.fontMetrics().height():
                raise RuntimeError("Query timing text is vertically clipped")
            capture(window, output / names[1], app)
            window.tabs.setCurrentWidget(window.history_page)
            drain(app, lambda: not window._history_task_running)
            window.history_table.selectRow(0)
            capture(window, output / names[2], app)
            window.close()
            drain(app, lambda: window.clean_shutdown_completed)
        store.close()
        if args.include_report:
            names.append("session-report.png")
            command = [
                str(edge_executable()),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--hide-scrollbars",
                "--window-size=1440,1800",
                "--virtual-time-budget=1500",
                f"--user-data-dir={root / 'edge-profile'}",
                f"--screenshot={output / names[-1]}",
                report.as_uri(),
            ]
            subprocess.run(command, check=True, timeout=45, capture_output=True)
    files = []
    for name in names:
        path = output / name
        picture = QImage(str(path))
        if picture.isNull() or picture.width() < 1080 or picture.height() < 680:
            raise RuntimeError(f"Invalid screenshot: {name}")
        files.append(
            {
                "name": name,
                "width": picture.width(),
                "height": picture.height(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    metadata = {
        "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "app_version": __version__,
        "python": platform.python_version(),
        "qt": qt_version,
        "os": platform.platform(),
        "scale_factor": os.environ["QT_SCALE_FACTOR"],
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
        "synthetic": True,
        "method": "MainWindow + injected QueryOutcome + temporary SessionStore; actual HTML export",
        "limitations": "No SSH, live collection, physical desktop or full query verification",
        "files": files,
    }
    (output / "capture-metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(metadata, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
