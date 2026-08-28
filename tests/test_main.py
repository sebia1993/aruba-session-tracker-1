from __future__ import annotations

from pathlib import Path

import pytest

from aruba_session_tracker.main import main
from aruba_session_tracker.paths import AppPaths
from aruba_session_tracker.storage import StorageError


def test_startup_storage_failure_is_visible_and_returns_nonzero(
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
    shown: list[tuple[str, str]] = []

    def fail_initialize(_self: object) -> None:
        raise StorageError("sensitive path detail")

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
    assert "sensitive path detail" not in shown[0][1]
