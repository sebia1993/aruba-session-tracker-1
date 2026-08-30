from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path


class UnsafeManagedPath(RuntimeError):
    """A managed application path is a link, reparse point, or changed root."""


@dataclass(frozen=True, slots=True)
class DirectoryIdentity:
    device: int
    inode: int


def reject_link_or_reparse(path: Path) -> os.stat_result:
    """Inspect *path* itself without following links and reject Windows junctions."""

    info = os.lstat(path)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = int(getattr(info, "st_file_attributes", 0))
    if stat.S_ISLNK(info.st_mode) or (reparse_flag and attributes & reparse_flag):
        raise UnsafeManagedPath(
            "관리 경로에 symbolic link 또는 reparse point를 사용할 수 없습니다."
        )
    return info


def ensure_managed_directory(path: Path | str) -> tuple[Path, DirectoryIdentity]:
    """Create a managed directory without resolving through a reparse point."""

    absolute = Path(os.path.abspath(Path(path)))
    if os.path.lexists(absolute):
        info = reject_link_or_reparse(absolute)
        if not stat.S_ISDIR(info.st_mode):
            raise UnsafeManagedPath("관리 경로가 디렉터리가 아닙니다.")
    else:
        absolute.mkdir(parents=True, exist_ok=False)
        info = reject_link_or_reparse(absolute)
        if not stat.S_ISDIR(info.st_mode):  # pragma: no cover - defensive filesystem race
            raise UnsafeManagedPath("생성된 관리 경로가 디렉터리가 아닙니다.")
    return absolute, DirectoryIdentity(int(info.st_dev), int(info.st_ino))


def verify_managed_directory(path: Path, expected: DirectoryIdentity) -> None:
    """Fail closed when a managed directory has been replaced since initialization."""

    try:
        info = reject_link_or_reparse(path)
    except FileNotFoundError as error:
        raise UnsafeManagedPath("관리 경로가 실행 중 사라졌습니다.") from error
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeManagedPath("관리 경로가 실행 중 디렉터리가 아닌 항목으로 바뀌었습니다.")
    current = DirectoryIdentity(int(info.st_dev), int(info.st_ino))
    if current != expected:
        raise UnsafeManagedPath("관리 경로가 실행 중 다른 디렉터리로 바뀌었습니다.")


def reject_managed_file_link(path: Path) -> None:
    """Reject an existing managed file unless it is regular, single-link and non-reparse."""

    if not os.path.lexists(path):
        return
    info = reject_link_or_reparse(path)
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeManagedPath("관리 파일 경로가 일반 파일이 아닙니다.")
    if int(getattr(info, "st_nlink", 1)) != 1:
        raise UnsafeManagedPath("관리 파일 경로에 hard link를 사용할 수 없습니다.")


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
        root, root_identity = ensure_managed_directory(self.root)
        for managed_file in (self.config, self.known_hosts, self.database):
            verify_managed_directory(root, root_identity)
            reject_managed_file_link(Path(os.path.abspath(managed_file)))
        for directory in (self.raw, self.exports):
            absolute = Path(os.path.abspath(directory))
            if absolute.parent == Path(os.path.abspath(self.root)):
                verify_managed_directory(root, root_identity)
            ensure_managed_directory(absolute)
