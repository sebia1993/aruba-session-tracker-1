"""Require synchronized package, project, changelog, and release versions."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

_VERSION = re.compile(r"\d+\.\d+\.\d+\Z")


class VersionError(ValueError):
    pass


def versions(repository: Path) -> dict[str, str]:
    pyproject = tomllib.loads((repository / "pyproject.toml").read_text(encoding="utf-8"))
    project_version = str(pyproject["project"]["version"])

    package_text = (repository / "src/aruba_session_tracker/__init__.py").read_text(
        encoding="utf-8"
    )
    package_match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', package_text, re.M)
    if package_match is None:
        raise VersionError("src/aruba_session_tracker/__init__.py has no __version__")

    changelog_text = (repository / "CHANGELOG.md").read_text(encoding="utf-8")
    changelog_match = re.search(r"^##\s+(\d+\.\d+\.\d+)\b", changelog_text, re.M)
    if changelog_match is None:
        raise VersionError("CHANGELOG.md has no version heading")
    build_text = (repository / "build_windows.ps1").read_text(encoding="utf-8")
    build_match = re.search(r'\[string\]\$Version\s*=\s*"([^"]+)"', build_text)
    if build_match is None:
        raise VersionError("build_windows.ps1 has no default Version")
    return {
        "pyproject": project_version,
        "package": package_match.group(1),
        "changelog": changelog_match.group(1),
        "build": build_match.group(1),
    }


def check_version(
    repository: Path,
    *,
    expected: str | None = None,
    tag: str | None = None,
) -> str:
    if tag is not None:
        if re.fullmatch(r"v\d+\.\d+\.\d+", tag) is None:
            raise VersionError("release tag must use vMAJOR.MINOR.PATCH")
        tag_version = tag[1:]
        if expected is not None and expected != tag_version:
            raise VersionError("--expected and --tag versions disagree")
        expected = tag_version
    if expected is not None and _VERSION.fullmatch(expected) is None:
        raise VersionError("expected version must use MAJOR.MINOR.PATCH")

    found = versions(repository)
    distinct = set(found.values())
    if len(distinct) != 1:
        details = ", ".join(f"{label}={value}" for label, value in found.items())
        raise VersionError(f"version sources are not synchronized: {details}")
    actual = distinct.pop()
    if expected is not None and actual != expected:
        raise VersionError(f"repository version {actual} does not match expected {expected}")
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected")
    parser.add_argument("--tag")
    args = parser.parse_args()
    version = check_version(Path.cwd(), expected=args.expected, tag=args.tag)
    print(f"Version synchronization passed: {version}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, VersionError) as error:
        print(f"version-check: {error}", file=sys.stderr)
        sys.exit(1)
