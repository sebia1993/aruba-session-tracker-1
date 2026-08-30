"""Bind locked packages and verified native bundle components into CycloneDX."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import sys
import tempfile
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

try:
    from tools.component_manifest import (
        canonical_bundle_paths,
        native_bundle_paths,
        paths_matching_patterns,
        safe_bundle_path,
        select_component_paths,
    )
except ModuleNotFoundError:
    from component_manifest import (  # type: ignore[no-redef, import-not-found]
        canonical_bundle_paths,
        native_bundle_paths,
        paths_matching_patterns,
        safe_bundle_path,
        select_component_paths,
    )

_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;]+)$")
_LOCK_PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)==([^\s;]+)")
_COMPONENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]*$")
_ALLOWED_TYPES = {"application", "framework", "library"}


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).casefold()


def _write_json_atomic(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _strings(value: object, *, field: str, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"component manifest {field} must be an array of strings")
    result = tuple(value)
    if not allow_empty and not result:
        raise ValueError(f"component manifest {field} must not be empty")
    return result


def _template(value: str, versions: dict[str, str]) -> str:
    try:
        rendered = value.format_map(versions)
    except KeyError as error:
        raise ValueError(f"unknown component manifest placeholder: {error.args[0]}") from error
    if "{" in rendered or "}" in rendered:
        raise ValueError(f"unresolved component manifest template: {value}")
    return rendered


def _safe_relative(value: str, *, field: str) -> PurePosixPath:
    return safe_bundle_path(value, field=field)


def _bundle_file(bundle_root: Path, relative: PurePosixPath) -> Path:
    path = bundle_root.joinpath(*relative.parts)
    resolved_root = bundle_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file() or path.is_symlink():
        raise ValueError(f"unsafe native component file: {relative.as_posix()}")
    return resolved


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _inventory_sha256(entries: list[dict[str, str]]) -> str:
    return hashlib.sha256(
        json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _all_bundle_files(bundle_root: Path) -> dict[str, Path]:
    paths: dict[str, Path] = {}
    for candidate in bundle_root.rglob("*"):
        if candidate.is_symlink():
            raise ValueError(f"bundle must not contain symbolic links: {candidate}")
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(bundle_root).as_posix()
        paths[relative] = _bundle_file(bundle_root, _safe_relative(relative, field="bundle path"))
    canonical_bundle_paths(paths)
    return paths


def _locked_versions(path: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    pending = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or (line.startswith("--") and not pending):
            continue
        continued = line.endswith("\\")
        pending += (line[:-1] if continued else line) + " "
        if continued:
            continue
        match = _LOCK_PIN.match(pending.strip())
        pending = ""
        if match is None:
            raise ValueError("runtime lock has an unpinned component")
        name = _normalize(match.group(1))
        if name in versions:
            raise ValueError(f"runtime lock has duplicate component: {name}")
        versions[name] = match.group(2)
    if pending or not versions:
        raise ValueError("runtime lock is incomplete")
    return versions


def _runtime_template_versions(runtime_lock: Path, qt_version: str) -> dict[str, str]:
    locked = _locked_versions(runtime_lock)
    pyside = locked.get("pyside6-essentials")
    shiboken = locked.get("shiboken6")
    installed_pyside = importlib.metadata.version("PySide6-Essentials")
    installed_shiboken = importlib.metadata.version("shiboken6")
    if (
        pyside is None
        or shiboken is None
        or pyside != shiboken
        or pyside != qt_version
        or installed_pyside != pyside
        or installed_shiboken != shiboken
    ):
        raise ValueError("installed and locked PySide6/Shiboken versions must match Qt exactly")
    versions = {f"{name.replace('-', '_')}_version": version for name, version in locked.items()}
    versions["qt_version"] = qt_version
    return versions


def _load_component_manifest(path: Path) -> dict[str, Any]:
    document = tomllib.loads(path.read_text(encoding="utf-8"))
    if document.get("schema_version") != 1:
        raise ValueError("component manifest schema_version must be 1")
    if document.get("resolved_manifest") != "THIRD_PARTY_COMPONENTS.json":
        raise ValueError("component manifest resolved_manifest is not canonical")
    policy = document.get("policy")
    components = document.get("components")
    if not isinstance(policy, dict) or not isinstance(components, list) or not components:
        raise ValueError("component manifest policy or components are missing")
    return document


def resolve_component_manifest(
    manifest_path: Path,
    bundle_root: Path,
    *,
    versions: dict[str, str],
) -> dict[str, object]:
    """Resolve templates/globs and bind every declared component to bundle hashes."""

    document = _load_component_manifest(manifest_path)
    policy = document["policy"]
    assert isinstance(policy, dict)
    bundle_files = _all_bundle_files(bundle_root)
    all_paths = set(bundle_files)
    required = _strings(
        policy.get("required_bundle_files"), field="policy.required_bundle_files", allow_empty=True
    )
    forbidden_globs = _strings(
        policy.get("forbidden_bundle_globs"),
        field="policy.forbidden_bundle_globs",
        allow_empty=True,
    )
    indexed = canonical_bundle_paths(all_paths)
    for value in required:
        relative = _safe_relative(value, field="required_bundle_files").as_posix()
        if relative.casefold() not in indexed:
            raise ValueError(f"required native bundle file is missing: {value}")
    forbidden_present = sorted(paths_matching_patterns(all_paths, forbidden_globs))
    if forbidden_present:
        raise ValueError(f"forbidden native bundle file is present: {forbidden_present[0]}")

    raw_fallbacks = document.get("license_fallbacks", [])
    if not isinstance(raw_fallbacks, list):
        raise ValueError("component manifest license_fallbacks must be an array")
    resolved_fallbacks: list[dict[str, str]] = []
    fallback_packages: set[str] = set()
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
        normalized_package = _normalize(package)
        if normalized_package in fallback_packages:
            raise ValueError(f"duplicate license fallback: {normalized_package}")
        fallback_packages.add(normalized_package)
        if (
            not source_url.startswith("https://")
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
        ):
            raise ValueError(f"license fallback contract is invalid: {normalized_package}")
        source_name = _safe_relative(source_file, field="license_fallbacks.source_file").name
        bundle_path = f"licenses/{normalized_package}/SUPPLEMENTAL__{source_name}"
        evidence_path = bundle_files.get(bundle_path)
        if evidence_path is None or _sha256(evidence_path) != expected_hash:
            raise ValueError(f"license fallback evidence differs: {normalized_package}")
        resolved_fallbacks.append(
            {
                "bundle_path": bundle_path,
                "package": normalized_package,
                "sha256": expected_hash,
                "source_url": source_url,
                "version": version,
            }
        )

    raw_components = document["components"]
    assert isinstance(raw_components, list)
    ids: set[str] = set()
    assigned_files: set[str] = set()
    resolved_components: list[dict[str, object]] = []
    for raw in raw_components:
        if not isinstance(raw, dict):
            raise ValueError("component manifest entries must be tables")
        component_id = raw.get("id")
        name = raw.get("name")
        component_type = raw.get("type")
        raw_version = raw.get("version")
        optional = raw.get("optional", False)
        if not isinstance(component_id, str) or _COMPONENT_ID.fullmatch(component_id) is None:
            raise ValueError("component manifest id is invalid")
        if component_id in ids:
            raise ValueError(f"duplicate component manifest id: {component_id}")
        ids.add(component_id)
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"component manifest name is missing: {component_id}")
        if component_type not in _ALLOWED_TYPES:
            raise ValueError(f"component manifest type is invalid: {component_id}")
        if not isinstance(optional, bool):
            raise ValueError(f"component manifest optional flag is invalid: {component_id}")
        if not isinstance(raw_version, str):
            raise ValueError(f"component manifest version is missing: {component_id}")
        version = _template(raw_version, versions)
        if _VERSION.fullmatch(version) is None:
            raise ValueError(f"component manifest version is invalid: {component_id}")

        license_id = raw.get("license_id")
        license_name = raw.get("license_name")
        if (isinstance(license_id, str)) == (isinstance(license_name, str)):
            raise ValueError(f"component must declare exactly one license field: {component_id}")
        license_files = _strings(raw.get("license_files"), field=f"{component_id}.license_files")
        resolved_license_files: list[dict[str, str]] = []
        for value in license_files:
            rendered = _template(value, versions)
            license_relative = _safe_relative(rendered, field=f"{component_id}.license_files")
            license_path = _bundle_file(bundle_root, license_relative)
            resolved_license_files.append(
                {"path": license_relative.as_posix(), "sha256": _sha256(license_path)}
            )

        source_urls = tuple(
            _template(value, versions)
            for value in _strings(raw.get("source_urls"), field=f"{component_id}.source_urls")
        )
        if any(not value.startswith("https://") for value in source_urls):
            raise ValueError(f"component source URL is not HTTPS: {component_id}")

        exact_files = tuple(
            _template(value, versions)
            for value in _strings(
                raw.get("files", []), field=f"{component_id}.files", allow_empty=True
            )
        )
        globs = tuple(
            _template(value, versions)
            for value in _strings(
                raw.get("globs", []), field=f"{component_id}.globs", allow_empty=True
            )
        )
        exclude_globs = tuple(
            _template(value, versions)
            for value in _strings(
                raw.get("exclude_globs", []),
                field=f"{component_id}.exclude_globs",
                allow_empty=True,
            )
        )
        selected_names = select_component_paths(
            all_paths,
            files=exact_files,
            globs=globs,
            exclude_globs=exclude_globs,
            field=component_id,
        )
        if not selected_names:
            if optional:
                continue
            raise ValueError(f"component manifest matched no bundle files: {component_id}")
        overlap = sorted(assigned_files & selected_names)
        if overlap:
            raise ValueError(f"native bundle file belongs to multiple components: {overlap[0]}")
        assigned_files.update(selected_names)

        file_entries = [
            {"path": relative, "sha256": _sha256(bundle_files[relative])}
            for relative in sorted(selected_names)
        ]
        resolved_components.append(
            {
                "bom_ref": f"native:{component_id}@{version}",
                "files": file_entries,
                "id": component_id,
                "inventory_sha256": _inventory_sha256(file_entries),
                "license_files": resolved_license_files,
                "license_id": license_id if isinstance(license_id, str) else None,
                "license_name": license_name if isinstance(license_name, str) else None,
                "name": name,
                "source_urls": list(source_urls),
                "type": component_type,
                "version": version,
            }
        )

    unassigned_native = sorted(native_bundle_paths(all_paths) - assigned_files)
    if unassigned_native:
        raise ValueError(
            f"native bundle file is not assigned to a component: {unassigned_native[0]}"
        )

    evidence_paths = sorted(
        value
        for value in all_paths
        if value.startswith("licenses/")
        or value in {"OPEN_SOURCE_SOURCE_OFFER.txt", "THIRD_PARTY_NOTICES.txt"}
    )
    license_evidence = [
        {"path": relative, "sha256": _sha256(bundle_files[relative])} for relative in evidence_paths
    ]
    if not license_evidence:
        raise ValueError("bundle contains no license evidence")

    return {
        "components": resolved_components,
        "license_evidence": license_evidence,
        "license_evidence_inventory_sha256": _inventory_sha256(license_evidence),
        "license_fallbacks": resolved_fallbacks,
        "policy": {
            "forbidden_bundle_globs": list(forbidden_globs),
            "required_bundle_files": list(required),
        },
        "schema_version": 1,
    }


def _cyclonedx_component(component: dict[str, object]) -> dict[str, object]:
    license_id = component.get("license_id")
    license_name = component.get("license_name")
    license_value = {"id": license_id} if isinstance(license_id, str) else {"name": license_name}
    source_urls = component["source_urls"]
    license_files = component["license_files"]
    assert isinstance(source_urls, list)
    assert isinstance(license_files, list)
    license_references = []
    for evidence in license_files:
        assert isinstance(evidence, dict)
        path = evidence["path"]
        digest = evidence["sha256"]
        assert isinstance(path, str) and isinstance(digest, str)
        license_references.append(
            {
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "type": "license",
                "url": f"urn:aruba-session-tracker:bundle:{quote(path, safe='')}",
            }
        )
    return {
        "bom-ref": component["bom_ref"],
        "externalReferences": [
            *({"type": "distribution", "url": source_url} for source_url in source_urls),
            *license_references,
        ],
        "licenses": [{"license": license_value}],
        "name": component["name"],
        "properties": [
            {"name": "aruba-session-tracker:component-id", "value": component["id"]},
            {
                "name": "aruba-session-tracker:inventory-sha256",
                "value": component["inventory_sha256"],
            },
            {
                "name": "aruba-session-tracker:resolved-manifest",
                "value": "THIRD_PARTY_COMPONENTS.json",
            },
        ],
        "type": component["type"],
        "version": component["version"],
    }


def finalize(
    sbom_path: Path,
    pyproject_path: Path,
    component_manifest_path: Path,
    bundle_root: Path,
    resolved_manifest_path: Path,
    *,
    versions: dict[str, str],
) -> None:
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

    resolved_manifest = resolve_component_manifest(
        component_manifest_path, bundle_root, versions=versions
    )
    native_components = resolved_manifest["components"]
    assert isinstance(native_components, list)
    native_refs: list[str] = []
    for native in native_components:
        assert isinstance(native, dict)
        native_ref = native["bom_ref"]
        if not isinstance(native_ref, str) or any(
            isinstance(component, dict) and component.get("bom-ref") == native_ref
            for component in components
        ):
            raise ValueError(f"duplicate native SBOM reference: {native_ref}")
        native_refs.append(native_ref)
        components.append(_cyclonedx_component(native))
    components.sort(key=lambda item: str(item.get("bom-ref", "")) if isinstance(item, dict) else "")

    dependencies = document.setdefault("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValueError("SBOM dependencies must be an array")
    dependencies[:] = [
        item
        for item in dependencies
        if not isinstance(item, dict) or item.get("ref") not in {root_ref, *native_refs}
    ]
    dependencies.extend({"ref": native_ref, "dependsOn": []} for native_ref in native_refs)
    dependencies.append(
        {
            "ref": root_ref,
            "dependsOn": sorted([*(refs_by_name[name] for name in direct_names), *native_refs]),
        }
    )
    dependencies.sort(key=lambda item: str(item.get("ref", "")) if isinstance(item, dict) else "")

    evidence_inventory = resolved_manifest.get("license_evidence_inventory_sha256")
    if not isinstance(evidence_inventory, str):
        raise ValueError("resolved license evidence inventory hash is missing")
    root_properties = metadata["component"].setdefault("properties", [])
    if not isinstance(root_properties, list):
        raise ValueError("SBOM root component properties must be an array")
    root_properties[:] = [
        item
        for item in root_properties
        if not isinstance(item, dict)
        or item.get("name")
        not in {
            "aruba-session-tracker:license-evidence-inventory-sha256",
            "aruba-session-tracker:resolved-manifest",
        }
    ]
    root_properties.extend(
        [
            {
                "name": "aruba-session-tracker:license-evidence-inventory-sha256",
                "value": evidence_inventory,
            },
            {
                "name": "aruba-session-tracker:resolved-manifest",
                "value": "THIRD_PARTY_COMPONENTS.json",
            },
        ]
    )
    root_properties.sort(
        key=lambda item: str(item.get("name", "")) if isinstance(item, dict) else ""
    )

    expected_resolved = _load_component_manifest(component_manifest_path)["resolved_manifest"]
    if (
        resolved_manifest_path.name != expected_resolved
        or resolved_manifest_path.parent != bundle_root
    ):
        raise ValueError("resolved component manifest output path is not canonical")
    _write_json_atomic(resolved_manifest_path, resolved_manifest)
    _write_json_atomic(sbom_path, document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--pyproject", type=Path, required=True)
    parser.add_argument("--component-manifest", type=Path, required=True)
    parser.add_argument("--bundle-root", type=Path, required=True)
    parser.add_argument("--resolved-manifest", type=Path, required=True)
    parser.add_argument("--runtime-lock", type=Path, required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--openssl-version", required=True)
    parser.add_argument("--cryptography-openssl-version", required=True)
    parser.add_argument("--libyaml-version", required=True)
    parser.add_argument("--pyinstaller-version", required=True)
    parser.add_argument("--qt-version", required=True)
    parser.add_argument("--sqlite-version", required=True)
    args = parser.parse_args()
    versions = {
        "cryptography_openssl_version": args.cryptography_openssl_version,
        "libyaml_version": args.libyaml_version,
        "openssl_version": args.openssl_version,
        "pyinstaller_version": args.pyinstaller_version,
        "python_version": args.python_version,
        "sqlite_version": args.sqlite_version,
    }
    try:
        versions.update(_runtime_template_versions(args.runtime_lock, args.qt_version))
        if any(_VERSION.fullmatch(value) is None for value in versions.values()):
            raise ValueError("native component version argument is invalid")
        finalize(
            args.sbom,
            args.pyproject,
            args.component_manifest,
            args.bundle_root,
            args.resolved_manifest,
            versions=versions,
        )
    except (
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        importlib.metadata.PackageNotFoundError,
    ) as error:
        print(f"sbom-finalize: {error}", file=sys.stderr)
        return 1
    print(f"SBOM package/native dependency graph finalized: {args.sbom.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
