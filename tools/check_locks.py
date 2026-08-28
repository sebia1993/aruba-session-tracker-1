"""Validate direct pins and the three hash-locked Windows dependency sets."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;\\]+)")
_HASH = re.compile(r"--hash=sha256:[0-9a-f]{64}\b")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _direct_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r "):
            pins.update(_direct_pins(path.parent / line[3:].strip()))
            continue
        match = _PIN.match(line)
        if match is None:
            raise ValueError(f"{path.name}: direct requirement is not exactly pinned: {line}")
        pins[_normalize(match.group(1))] = match.group(2)
    return pins


def _locked_pins(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    if "--only-binary=:all:" not in text or "--require-hashes" not in text:
        raise ValueError(f"{path.name}: binary-only/hash enforcement directives are missing")
    logical_lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or (line.startswith("--") and not pending):
            continue
        continued = line.endswith("\\")
        pending += (line[:-1] if continued else line) + " "
        if not continued:
            logical_lines.append(pending.strip())
            pending = ""
    if pending:
        raise ValueError(f"{path.name}: unterminated continued requirement")

    pins: dict[str, str] = {}
    for line in logical_lines:
        match = _PIN.match(line)
        if match is None or _HASH.search(line) is None:
            raise ValueError(f"{path.name}: every locked requirement needs a SHA-256 hash")
        name = _normalize(match.group(1))
        if name in pins:
            raise ValueError(f"{path.name}: duplicate locked package: {name}")
        pins[name] = match.group(2)
    if not pins:
        raise ValueError(f"{path.name}: lock is empty")
    return pins


def _require_subset(label: str, expected: dict[str, str], actual: dict[str, str]) -> None:
    for name, version in sorted(expected.items()):
        if actual.get(name) != version:
            raise ValueError(
                f"{label}: expected {name}=={version}, found {actual.get(name, 'missing')}"
            )


def check(repository: Path) -> None:
    pyproject = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    project_pins: dict[str, str] = {}
    for requirement in pyproject["project"]["dependencies"]:
        match = _PIN.fullmatch(requirement)
        if match is None:
            raise ValueError(f"pyproject runtime dependency is not exactly pinned: {requirement}")
        project_pins[_normalize(match.group(1))] = match.group(2)

    runtime_direct = _direct_pins(repository / "requirements.txt")
    if project_pins != runtime_direct:
        raise ValueError("pyproject runtime pins and requirements.txt differ")

    runtime_lock = _locked_pins(repository / "requirements-runtime.lock")
    build_lock = _locked_pins(repository / "requirements-build.lock")
    dev_lock = _locked_pins(repository / "requirements-dev.lock")
    dev_direct = _direct_pins(repository / "requirements-dev.txt")
    build_system = {
        _normalize(match.group(1)): match.group(2)
        for requirement in pyproject["build-system"]["requires"]
        if (match := _PIN.fullmatch(requirement)) is not None
    }

    _require_subset("runtime lock", runtime_direct, runtime_lock)
    _require_subset("build lock runtime", runtime_lock, build_lock)
    _require_subset("build lock build-system", build_system, build_lock)
    _require_subset(
        "build lock PyInstaller", {"pyinstaller": dev_direct["pyinstaller"]}, build_lock
    )
    _require_subset("build lock pip", {"pip": "26.2.1"}, build_lock)
    _require_subset("development lock direct", dev_direct, dev_lock)
    _require_subset("development lock build", build_lock, dev_lock)


def main() -> int:
    try:
        check(Path.cwd())
    except (KeyError, OSError, ValueError) as error:
        print(f"lock-check: {error}", file=sys.stderr)
        return 1
    print("Dependency lock synchronization passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
