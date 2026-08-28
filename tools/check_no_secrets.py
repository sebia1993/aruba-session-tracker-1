"""Fail when source control candidates contain private material or runtime data."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".release-venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
}
_SCAN_CHUNK_BYTES = 1024 * 1024
_SCAN_OVERLAP_BYTES = 256
_PRIVATE_SUFFIXES = {
    ".csv",
    ".db",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".ppk",
    ".sqlite",
    ".sqlite3",
}
_SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bghp_[A-Za-z0-9]{30,}\b"),
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
)


def _candidate_files(repository: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
        cwd=repository,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        names = [name for name in result.stdout.decode("utf-8").split("\0") if name]
        return [repository / name for name in names]
    return [path for path in repository.rglob("*") if path.is_file()]


def _content_problem(path: Path) -> str | None:
    tail = b""
    first = True
    with path.open("rb") as stream:
        while chunk := stream.read(_SCAN_CHUNK_BYTES):
            if first:
                first = False
                if chunk.startswith(b"SQLite format 3\x00"):
                    return "SQLite database content"
                # PEM keys and access tokens are text. Compiled dependencies
                # legitimately embed parser marker strings, so avoid treating
                # NUL-bearing binaries as captured secret documents.
                if b"\x00" in chunk[:8192]:
                    return None
            combined = tail + chunk
            if any(pattern.search(combined) for pattern in _SECRET_PATTERNS):
                return "private material pattern"
            tail = combined[-_SCAN_OVERLAP_BYTES:]
    return None


def check(repository: Path) -> list[str]:
    problems: list[str] = []
    for path in _candidate_files(repository):
        try:
            relative = path.relative_to(repository)
        except ValueError:
            problems.append("file escapes repository root")
            continue
        if any(part in _IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            problems.append(f"symbolic link is not allowed: {relative.as_posix()}")
            continue
        if not path.is_file():
            problems.append(f"candidate is not a regular file: {relative.as_posix()}")
            continue
        lower_name = path.name.casefold()
        lower_parts = {part.casefold() for part in relative.parts[:-1]}
        if lower_name in {"config.json", "known_hosts", ".env"}:
            problems.append(f"runtime/private file is not allowed: {relative.as_posix()}")
        if path.suffix.casefold() in _PRIVATE_SUFFIXES or lower_name.endswith(
            ("-journal", "-shm", "-wal")
        ):
            problems.append(f"private/runtime data file is not allowed: {relative.as_posix()}")
        if lower_parts & {"raw", "exports"}:
            problems.append(f"captured/exported data is not allowed: {relative.as_posix()}")
        content_problem = _content_problem(path)
        if content_problem is not None:
            problems.append(f"{content_problem} found: {relative.as_posix()}")
    return problems


def main() -> int:
    problems = check(Path.cwd())
    if problems:
        for problem in problems:
            print(f"secret-check: {problem}", file=sys.stderr)
        return 1
    print("Secret/runtime-data check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
