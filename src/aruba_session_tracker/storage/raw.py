"""Per-run UTF-8 raw output storage with path-containment checks."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

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
        self.root = Path(root)

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
        kind_segment = _filename_segment(kind, "kind")
        controller_segment = _filename_segment(controller_name, "controller_name")
        timestamp = _as_utc(captured_at).strftime("%Y%m%dT%H%M%S.%fZ")
        filename = f"{timestamp}_{kind_segment}_{controller_segment}_{uuid4().hex[:8]}.txt"

        self.root.mkdir(parents=True, exist_ok=True)
        run_directory = contained_path(self.root, Path(run_segment))
        run_directory.mkdir(parents=False, exist_ok=True)
        path = contained_path(self.root, Path(run_segment) / filename)
        data = content.encode("utf-8")

        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{filename}.", suffix=".tmp", dir=run_directory
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, path)
        finally:
            temporary_path.unlink(missing_ok=True)

        relative = path.relative_to(self.root).as_posix()
        return RawArtifact(
            relative_path=relative,
            sha256=hashlib.sha256(data).hexdigest(),
            byte_size=len(data),
        )

    def remove(self, relative_path: str) -> None:
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


def _filename_segment(value: str, label: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._-")
    if not normalized:
        raise UnsafeStoragePath(f"{label}은 비어 있을 수 없습니다.")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{normalized[:48]}-{digest}"


def contained_path(root: Path, relative: Path) -> Path:
    if relative.is_absolute():
        raise UnsafeStoragePath("절대 경로는 관리 상대 경로로 사용할 수 없습니다.")
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
