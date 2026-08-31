"""Copy license evidence from every locked runtime wheel into the bundle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s\\]+)")
_LICENSE_TOKENS = ("license", "copying", "notice", "authors")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class _LicenseFallback:
    package: str
    version: str
    source: Path
    source_url: str
    sha256: str


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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _license_fallbacks(path: Path | None) -> dict[str, _LicenseFallback]:
    if path is None:
        return {}
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    raw_fallbacks = document.get("license_fallbacks", [])
    if not isinstance(raw_fallbacks, list):
        raise ValueError("component manifest license_fallbacks must be an array")
    manifest_root = path.parent.resolve(strict=True)
    result: dict[str, _LicenseFallback] = {}
    for raw in raw_fallbacks:
        if not isinstance(raw, dict):
            raise ValueError("component manifest license fallback is invalid")
        package = raw.get("package")
        version = raw.get("version")
        source_file = raw.get("source_file")
        source_url = raw.get("source_url")
        expected_hash = raw.get("sha256")
        if not all(
            isinstance(value, str) and value
            for value in (package, version, source_file, source_url, expected_hash)
        ):
            raise ValueError("component manifest license fallback fields are incomplete")
        assert isinstance(package, str)
        assert isinstance(version, str)
        assert isinstance(source_file, str)
        assert isinstance(source_url, str)
        assert isinstance(expected_hash, str)
        normalized = _normalize(package)
        if normalized in result:
            raise ValueError(f"duplicate license fallback: {normalized}")
        if (
            Path(source_file).is_absolute()
            or ".." in Path(source_file).parts
            or not source_url.startswith("https://")
            or _SHA256.fullmatch(expected_hash) is None
        ):
            raise ValueError(f"unsafe license fallback: {normalized}")
        source = (manifest_root / source_file).resolve(strict=True)
        if (
            not source.is_relative_to(manifest_root)
            or not source.is_file()
            or source.is_symlink()
            or source.stat().st_size > 1024 * 1024
            or _sha256(source) != expected_hash
        ):
            raise ValueError(f"license fallback source differs from contract: {normalized}")
        result[normalized] = _LicenseFallback(
            normalized,
            version,
            source,
            source_url,
            expected_hash,
        )
    return result


def copy_runtime_licenses(
    lock_path: Path,
    destination: Path,
    extra_packages: tuple[str, ...] = (),
    component_manifest: Path | None = None,
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
    fallbacks = _license_fallbacks(component_manifest)
    package_versions = {_normalize(name): version for name, version in packages}
    unknown_fallbacks = sorted(fallbacks.keys() - package_versions.keys())
    if unknown_fallbacks:
        raise ValueError(f"license fallback package is not locked: {unknown_fallbacks[0]}")
    for name, fallback in fallbacks.items():
        if package_versions[name] != fallback.version:
            raise ValueError(f"license fallback version differs from lock: {name}")

    for locked_name, locked_version in packages:
        distribution = importlib.metadata.distribution(locked_name)
        if distribution.version != locked_version:
            raise ValueError(
                f"installed {locked_name} version {distribution.version} "
                f"does not match lock {locked_version}"
            )
        package_destination = destination / _normalize(locked_name)
        package_destination.mkdir()
        base = Path(str(distribution.locate_file(""))).resolve(strict=True)
        copied = 0
        for relative in distribution.files or ():
            name = Path(str(relative)).name.casefold()
            if not any(token in name for token in _LICENSE_TOKENS):
                continue
            source = Path(str(distribution.locate_file(relative))).resolve(strict=True)
            if not source.is_relative_to(base) or not source.is_file() or source.is_symlink():
                raise ValueError(f"unsafe license source for {locked_name}: {relative}")
            if source.stat().st_size > 1024 * 1024:
                raise ValueError(f"unexpectedly large license source for {locked_name}: {relative}")
            output_name = "__".join(Path(str(relative)).parts[-3:])
            output = package_destination / output_name
            if output.exists():
                raise ValueError(
                    f"duplicate license evidence output for {locked_name}: {output_name}"
                )
            shutil.copyfile(source, output)
            copied += 1

        supplemental = 0
        package_fallback = fallbacks.get(_normalize(locked_name))
        if package_fallback is not None:
            output_name = f"SUPPLEMENTAL__{package_fallback.source.name}"
            output = package_destination / output_name
            if output.exists():
                raise ValueError(
                    f"duplicate supplemental license output for {locked_name}: {output_name}"
                )
            shutil.copyfile(package_fallback.source, output)
            if _sha256(output) != package_fallback.sha256:
                raise ValueError(f"copied license fallback hash differs: {locked_name}")
            supplemental = 1
        if copied + supplemental == 0:
            raise ValueError(f"locked package has no license or notice evidence: {locked_name}")

        metadata = distribution.metadata
        license_value = metadata.get("License-Expression") or metadata.get("License") or "UNKNOWN"
        home_page = metadata.get("Home-page") or metadata.get("Project-URL") or "UNKNOWN"
        summary = (
            f"Package: {distribution.metadata.get('Name', locked_name)}\n"
            f"Version: {distribution.version}\n"
            f"Declared-License: {license_value}\n"
            f"Project: {home_page}\n"
            f"Wheel-License-Files-Copied: {copied}\n"
            f"Supplemental-License-Files-Copied: {supplemental}\n"
            f"License-Evidence-Files-Copied: {copied + supplemental}\n"
        )
        (package_destination / "PACKAGE-METADATA.txt").write_text(
            summary, encoding="utf-8", newline="\n"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--extra-package", action="append", default=[])
    parser.add_argument("--component-manifest", type=Path)
    args = parser.parse_args()
    try:
        copy_runtime_licenses(
            args.lock,
            args.destination,
            tuple(args.extra_package),
            args.component_manifest,
        )
    except (
        OSError,
        ValueError,
        tomllib.TOMLDecodeError,
        importlib.metadata.PackageNotFoundError,
    ) as error:
        print(f"license-copy: {error}", file=sys.stderr)
        return 1
    print(f"Runtime license evidence copied: {args.destination}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
