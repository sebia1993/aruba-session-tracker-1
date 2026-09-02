"""Per-run UTF-8 raw output storage with path-containment checks."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from aruba_session_tracker.paths import (
    DirectoryIdentity,
    UnsafeManagedPath,
    ensure_managed_directory,
    reject_link_or_reparse,
    verify_managed_directory,
)
from aruba_session_tracker.storage.durable_io import (
    replace_with_retry,
    retry_windows_file_operation,
)

_SAFE_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class UnsafeStoragePath(ValueError):
    """A managed path escapes its configured application root."""


@dataclass(frozen=True, slots=True)
class RawArtifact:
    relative_path: str
    sha256: str
    byte_size: int


class RawOutputStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(os.path.abspath(Path(root)))
        self._identity: DirectoryIdentity | None = None
        self._identity_lock = threading.Lock()

    def initialize(self) -> DirectoryIdentity:
        with self._identity_lock:
            try:
                if self._identity is None:
                    self.root, self._identity = ensure_managed_directory(self.root)
                else:
                    verify_managed_directory(self.root, self._identity)
            except UnsafeManagedPath as error:
                raise UnsafeStoragePath(str(error)) from error
            return self._identity

    def verify(self) -> None:
        identity = self._identity
        if identity is None:
            self.initialize()
            return
        try:
            verify_managed_directory(self.root, identity)
        except UnsafeManagedPath as error:
            raise UnsafeStoragePath(str(error)) from error

    def write(
        self,
        run_id: str,
        *,
        kind: str,
        controller_name: str,
        content: str,
        captured_at: datetime | None = None,
    ) -> RawArtifact:
        """Atomically write one captured response below the run directory."""

        run_segment = safe_segment(run_id, "run_id")
        kind_segment = filename_segment(kind, "kind")
        controller_segment = filename_segment(controller_name, "controller_name")
        captured_utc = _as_utc(captured_at)
        timestamp = captured_utc.strftime("%Y%m%dT%H%M%S.%fZ")
        filename = f"{timestamp}_{kind_segment}_{controller_segment}_{uuid4().hex[:8]}.txt"

        self.verify()
        relative_directory = (
            Path(run_segment) / captured_utc.strftime("%Y%m%d") / captured_utc.strftime("%H")
        )
        directory = self.root
        relative_parent = Path()
        for part in relative_directory.parts:
            relative_parent /= part
            directory = contained_path(self.root, relative_parent)
            with suppress(FileExistsError):
                directory.mkdir(parents=False, exist_ok=True)
            try:
                info = reject_link_or_reparse(directory)
            except UnsafeManagedPath as error:
                raise UnsafeStoragePath(str(error)) from error
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafeStoragePath("Raw 실행 경로가 디렉터리가 아닙니다.")
        self.verify()
        relative = relative_directory / filename
        path = contained_path(self.root, relative)
        data = content.encode("utf-8")

        try:
            temporary_parent = reject_link_or_reparse(directory)
        except UnsafeManagedPath as error:
            raise UnsafeStoragePath(str(error)) from error

        def create_temporary() -> tuple[int, str]:
            try:
                current_parent = reject_link_or_reparse(directory)
            except UnsafeManagedPath as error:
                raise UnsafeStoragePath(str(error)) from error
            if (int(current_parent.st_dev), int(current_parent.st_ino)) != (
                int(temporary_parent.st_dev),
                int(temporary_parent.st_ino),
            ):
                raise UnsafeStoragePath("Raw 임시 파일의 상위 경로가 준비 이후 변경되었습니다.")
            return tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=directory)

        descriptor, temporary_name = retry_windows_file_operation(create_temporary)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            replace_with_retry(
                temporary_path,
                path,
                replace=os.replace,
                expected_sha256=hashlib.sha256(data).hexdigest(),
                expected_size=len(data),
            )
        finally:
            temporary_path.unlink(missing_ok=True)

        return RawArtifact(
            relative_path=relative.as_posix(),
            sha256=hashlib.sha256(data).hexdigest(),
            byte_size=len(data),
        )

    def remove(self, relative_path: str) -> None:
        self.verify()
        path = contained_path(self.root, Path(relative_path))
        if path.exists():
            if not path.is_file():
                raise UnsafeStoragePath("관리 대상 Raw 경로가 일반 파일이 아닙니다.")
            path.unlink()
        _remove_empty_parents(path.parent, self.root)


def safe_segment(value: str, label: str) -> str:
    if _SAFE_SEGMENT.fullmatch(value) is None or value in {".", ".."}:
        raise UnsafeStoragePath(f"{label}에 안전하지 않은 경로 문자가 있습니다.")
    return value


def filename_segment(value: str, label: str) -> str:
    """Return a stable ASCII filename segment while preserving Unicode metadata."""

    stripped = value.strip()
    if not stripped:
        raise UnsafeStoragePath(f"{label}은 비어 있을 수 없습니다.")
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", stripped).strip("._-")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    prefix = normalized[:48] or ("controller" if label == "controller_name" else "value")
    return f"{prefix}-{digest}"


def contained_path(root: Path, relative: Path) -> Path:
    if relative.is_absolute():
        raise UnsafeStoragePath("절대 경로는 관리 상대 경로로 사용할 수 없습니다.")
    if os.path.lexists(root):
        try:
            reject_link_or_reparse(root)
        except UnsafeManagedPath as error:
            raise UnsafeStoragePath(str(error)) from error
    root_resolved = root.resolve(strict=False)
    candidate = (root / relative).resolve(strict=False)
    if candidate == root_resolved or not candidate.is_relative_to(root_resolved):
        raise UnsafeStoragePath("관리 경로가 애플리케이션 저장소 밖을 가리킵니다.")
    return candidate


def _remove_empty_parents(start: Path, stop: Path) -> None:
    stop_resolved = stop.resolve(strict=False)
    current = start.resolve(strict=False)
    while current != stop_resolved and current.is_relative_to(stop_resolved):
        try:
            current.rmdir()
        except (FileNotFoundError, OSError):
            break
        current = current.parent


def _as_utc(value: datetime | None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None:
        raise ValueError("시간 값에는 timezone 정보가 필요합니다.")
    return result.astimezone(UTC)
