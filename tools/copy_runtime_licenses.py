"""Copy license evidence from every locked runtime wheel into the bundle."""

from __future__ import annotations

import argparse
import importlib.metadata
import re
import shutil
import sys
from pathlib import Path

_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)")
_LICENSE_TOKENS = ("license", "copying", "notice", "authors")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _locked_packages(path: Path) -> tuple[tuple[str, str], ...]:
    packages: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _REQUIREMENT.match(line.strip())
        if match is not None:
            packages.append((match.group(1), match.group(2)))
    if not packages:
        raise ValueError("runtime lock contains no packages")
    return tuple(packages)


def copy_runtime_licenses(
    lock_path: Path,
    destination: Path,
    extra_packages: tuple[str, ...] = (),
) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    packages = list(_locked_packages(lock_path))
    for requirement in extra_packages:
        match = _REQUIREMENT.fullmatch(requirement)
        if match is None:
            raise ValueError(f"extra package is not exactly pinned: {requirement}")
        packages.append((match.group(1), match.group(2)))
    if len({_normalize(name) for name, _version in packages}) != len(packages):
        raise ValueError("license package list contains a duplicate")

    for locked_name, locked_version in packages:
        distribution = importlib.metadata.distribution(locked_name)
        if distribution.version != locked_version:
            raise ValueError(
                f"installed {locked_name} version {distribution.version} "
                f"does not match lock {locked_version}"
            )
        package_destination = destination / _normalize(locked_name)
        package_destination.mkdir()
        base = Path(distribution.locate_file("")).resolve(strict=True)
        copied = 0
        for relative in distribution.files or ():
            name = Path(str(relative)).name.casefold()
            if not any(token in name for token in _LICENSE_TOKENS):
                continue
            source = Path(distribution.locate_file(relative)).resolve(strict=True)
            if not source.is_relative_to(base) or not source.is_file() or source.is_symlink():
                raise ValueError(f"unsafe license source for {locked_name}: {relative}")
            if source.stat().st_size > 1024 * 1024:
                raise ValueError(f"unexpectedly large license source for {locked_name}: {relative}")
            output_name = "__".join(Path(str(relative)).parts[-3:])
            shutil.copyfile(source, package_destination / output_name)
            copied += 1

        metadata = distribution.metadata
        license_value = metadata.get("License-Expression") or metadata.get("License") or "UNKNOWN"
        home_page = metadata.get("Home-page") or metadata.get("Project-URL") or "UNKNOWN"
        summary = (
            f"Package: {distribution.metadata.get('Name', locked_name)}\n"
            f"Version: {distribution.version}\n"
            f"Declared-License: {license_value}\n"
            f"Project: {home_page}\n"
            f"Wheel-License-Files-Copied: {copied}\n"
        )
        (package_destination / "PACKAGE-METADATA.txt").write_text(
            summary, encoding="utf-8", newline="\n"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--extra-package", action="append", default=[])
    args = parser.parse_args()
    try:
        copy_runtime_licenses(args.lock, args.destination, tuple(args.extra_package))
    except (OSError, ValueError, importlib.metadata.PackageNotFoundError) as error:
        print(f"license-copy: {error}", file=sys.stderr)
        return 1
    print(f"Runtime license evidence copied: {args.destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
