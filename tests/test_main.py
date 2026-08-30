from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import aruba_session_tracker.main as main_module
from aruba_session_tracker.config import ConfigError
from aruba_session_tracker.main import main
from aruba_session_tracker.paths import AppPaths, UnsafeManagedPath
from aruba_session_tracker.storage import StorageError


@pytest.mark.parametrize(
    ("argument", "output_prefix"),
    (
        ("--version", "0."),
        ("--smoke-test", "ARUBA_SESSION_TRACKER_SMOKE_OK"),
    ),
)
def test_cli_metadata_modes_exit_without_starting_gui(
    argument: str,
    output_prefix: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([argument]) == 0
    assert capsys.readouterr().out.startswith(output_prefix)


def test_loopback_smoke_requires_all_private_fixture_arguments() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--loopback-ssh-smoke", "success"])

    assert caught.value.code == 2


@pytest.mark.parametrize("guard_mode", ("already-running", "guard-error"))
def test_single_instance_guard_failures_are_bounded_and_sanitized(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guard_mode: str,
) -> None:
    del qtbot
    root = tmp_path / "app"
    paths = AppPaths(
        root=root,
        config=root / "config.json",
        known_hosts=root / "known_hosts",
        database=root / "tracker.db",
        raw=root / "raw",
        exports=root / "exports",
    )
    shown: list[tuple[str, str]] = []

    class _Guard:
        def __init__(self, _identity: str) -> None:
            pass

        def acquire(self) -> bool:
            if guard_mode == "guard-error":
                raise OSError("GUARD_SECRET_CANARY")
            return False

        def release(self) -> None:
            raise AssertionError("unacquired guard must not be released")

    monkeypatch.setattr(main_module.AppPaths, "default", lambda: paths)
    monkeypatch.setattr(main_module, "SingleInstanceGuard", _Guard)
    monkeypatch.setattr(
        main_module.QMessageBox,
        "information",
        lambda _parent, title, message: shown.append((title, message)),
    )
    monkeypatch.setattr(
        main_module.QMessageBox,
        "critical",
        lambda _parent, title, message: shown.append((title, message)),
    )

    expected = 1 if guard_mode == "guard-error" else 0
    assert main([]) == expected
    assert shown
    assert "GUARD_SECRET_CANARY" not in repr(shown)


class _SmokeApplication:
    def __init__(self) -> None:
        self.exit_codes: list[int] = []
        self.quit_calls = 0

    def exit(self, code: int) -> None:
        self.exit_codes.append(code)

    def quit(self) -> None:
        self.quit_calls += 1


@pytest.mark.parametrize(
    ("initially_enabled", "toggle_mode", "expected_sends"),
    (
        (True, "toggle", 0),
        (False, "ignore", 1),
        (False, "enable-only", 2),
    ),
)
def test_gui_smoke_failures_exit_nonzero_for_each_inspector_invariant(
    initially_enabled: bool,
    toggle_mode: str,
    expected_sends: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    application = _SmokeApplication()
    inspector = SimpleNamespace(enabled=initially_enabled)
    sends = 0

    def send_plain_f12(_application: object, _window: object) -> None:
        nonlocal sends
        sends += 1
        if toggle_mode == "toggle":
            inspector.enabled = not inspector.enabled
        elif toggle_mode == "enable-only":
            inspector.enabled = True

    monkeypatch.setattr(main_module, "_send_plain_f12", send_plain_f12)

    main_module._run_gui_smoke_test(  # type: ignore[arg-type]
        application,
        object(),
        inspector,
    )

    assert sends == expected_sends
    assert application.exit_codes == [1]
    assert application.quit_calls == 0
    assert "ARUBA_SESSION_TRACKER_GUI_SMOKE_FAILED RuntimeError" in capsys.readouterr().err


def test_gui_smoke_success_toggles_inspector_off_and_quits(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    application = _SmokeApplication()
    inspector = SimpleNamespace(enabled=False)

    def toggle_inspector(_application: object, _window: object) -> None:
        inspector.enabled = not inspector.enabled

    monkeypatch.setattr(main_module, "_send_plain_f12", toggle_inspector)

    main_module._run_gui_smoke_test(  # type: ignore[arg-type]
        application,
        object(),
        inspector,
    )

    assert inspector.enabled is False
    assert application.exit_codes == []
    assert application.quit_calls == 1
    assert capsys.readouterr().err == ""


def test_report_smoke_writes_standalone_html_to_korean_path(tmp_path: Path) -> None:
    destination = tmp_path / "한국어 결과" / "세션 보고서.html"

    assert main(["--report-smoke-test", str(destination)]) == 0

    text = destination.read_text(encoding="utf-8")
    assert "<!doctype html>" in text.casefold()
    assert "한국어-MD" in text
    assert "최신 세션 결과" in text
    assert "전체 추적 이력" in text
    assert "KST" in text
    assert "PACKAGE-RAW-CANARY" not in text
    assert "PACKAGE-DIAGNOSTIC-CANARY" not in text
    assert "PARSE_PARTIAL" not in text
    assert "report-smoke" not in text
    assert "세션별 수치 변화" not in text
    assert "패킷" not in text
    assert "바이트" not in text
    assert text.index("최신 세션 결과") < text.index("전체 추적 이력")
    assert "<details>" in text
    assert "<details open" not in text
    assert "https://" not in text.casefold()
    assert "http://" not in text.casefold()


@pytest.mark.parametrize(
    "error", [StorageError("storage"), ConfigError("config"), UnsafeManagedPath("path")]
)
def test_startup_storage_failure_is_visible_and_returns_nonzero(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    del qtbot
    root = tmp_path / "app"
    paths = AppPaths(
        root=root,
        config=root / "config.json",
        known_hosts=root / "known_hosts",
        database=root / "tracker.db",
        raw=root / "raw",
        exports=root / "exports",
    )
    shown: list[tuple[str, str]] = []

    def fail_initialize(_self: object) -> None:
        raise error

    monkeypatch.setattr("aruba_session_tracker.main.AppPaths.default", lambda: paths)
    monkeypatch.setattr(
        "aruba_session_tracker.main.SessionStore.initialize",
        fail_initialize,
    )
    monkeypatch.setattr(
        "aruba_session_tracker.main.QMessageBox.critical",
        lambda _parent, title, message: shown.append((title, message)),
    )

    assert main([]) == 1
    assert shown and "시작 실패" in shown[0][0]
    assert str(error) not in shown[0][1]


def test_main_window_failure_is_sanitized_and_journaled_before_hook_restore(
    qtbot: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del qtbot
    root = tmp_path / "app"
    paths = AppPaths(
        root=root,
        config=root / "config.json",
        known_hosts=root / "known_hosts",
        database=root / "tracker.db",
        raw=root / "raw",
        exports=root / "exports",
    )
    records: list[tuple[str, str, str]] = []

    class _Journal:
        def start_session(self) -> bool:
            return False

        def record(self, event: str, exception_type: object, *, stage: str) -> str:
            records.append((event, str(exception_type), stage))
            return "sanitized-incident"

        def mark_clean_exit(self) -> None:
            raise AssertionError("failed startup must not be marked clean")

    def fail_main_window(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("MAIN_WINDOW_SECRET_CANARY")

    monkeypatch.setattr(main_module.AppPaths, "default", lambda: paths)
    monkeypatch.setattr(main_module, "CrashJournal", lambda *_args, **_kwargs: _Journal())
    monkeypatch.setattr(main_module, "MainWindow", fail_main_window)

    with pytest.raises(RuntimeError, match="MAIN_WINDOW_SECRET_CANARY"):
        main([])

    assert records == [
        ("UNHANDLED_EXCEPTION", "RuntimeError", "MAIN_THREAD"),
        ("CONTROLLED_SHUTDOWN_INCOMPLETE", "RecoveryRequired", "SHUTDOWN"),
    ]
    assert "MAIN_WINDOW_SECRET_CANARY" not in repr(records)
