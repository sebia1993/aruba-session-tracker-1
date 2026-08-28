"""Bind the CycloneDX root component to the locked direct runtime packages."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import tomllib
from pathlib import Path

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;]+)$")


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def finalize(sbom_path: Path, pyproject_path: Path) -> None:
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component"), dict):
        raise ValueError("SBOM root component is missing")
    root_ref = metadata["component"].get("bom-ref")
    if not isinstance(root_ref, str) or not root_ref:
        raise ValueError("SBOM root component has no bom-ref")

    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    direct_names: set[str] = set()
    for requirement in pyproject["project"]["dependencies"]:
        match = _PIN.fullmatch(requirement)
        if match is None:
            raise ValueError(f"runtime dependency is not exactly pinned: {requirement}")
        direct_names.add(_normalize(match.group(1)))

    components = document.get("components")
    if not isinstance(components, list):
        raise ValueError("SBOM components are missing")
    refs_by_name = {
        _normalize(name): reference
        for component in components
        if isinstance(component, dict)
        and isinstance((name := component.get("name")), str)
        and isinstance((reference := component.get("bom-ref")), str)
    }
    missing = sorted(direct_names - refs_by_name.keys())
    if missing:
        raise ValueError(f"SBOM is missing direct runtime components: {', '.join(missing)}")

    dependencies = document.setdefault("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("SBOM dependencies must be an array")
    dependencies[:] = [
        item for item in dependencies if not isinstance(item, dict) or item.get("ref") != root_ref
    ]
    dependencies.append(
        {
            "ref": root_ref,
            "dependsOn": sorted(refs_by_name[name] for name in direct_names),
        }
    )
    dependencies.sort(key=lambda item: str(item.get("ref", "")) if isinstance(item, dict) else "")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{sbom_path.name}.", suffix=".tmp", dir=sbom_path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, sbom_path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    args = parser.parse_args()
    try:
        finalize(args.sbom, args.pyproject)
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"sbom-finalize: {error}", file=sys.stderr)
        return 1
    print(f"SBOM root dependency graph finalized: {args.sbom.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
