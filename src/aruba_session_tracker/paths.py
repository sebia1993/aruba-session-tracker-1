from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppPaths:
    root: Path
    config: Path
    known_hosts: Path
    database: Path
    raw: Path
    exports: Path

    @classmethod
    def default(cls) -> AppPaths:
        local_app_data = os.environ.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
        root = base / "ArubaSessionTracker"
        return cls(
            root=root,
            config=root / "config.json",
            known_hosts=root / "known_hosts",
            database=root / "tracker.db",
            raw=root / "raw",
            exports=root / "exports",
        )

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        self.exports.mkdir(parents=True, exist_ok=True)
