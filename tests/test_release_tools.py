from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import tomllib
import zipfile
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

from tools.check_coverage_policy import (
    CRITICAL_BRANCH_FLOORS,
    CoveragePolicyError,
    check_coverage_policy,
)
from tools.check_no_secrets import check
from tools.check_packaging_environment import INJECTION_VARIABLES
from tools.check_remote_release import ExpectedAsset, RemoteReleaseError, verify_release
from tools.check_version import VersionError
from tools.component_manifest import bundle_pattern_matches, native_bundle_paths
from tools.continuous_release_state import (
    Action,
    AssetEvidence,
    ContinuousReleaseStateError,
    DesiredRelease,
    DurableState,
    ReleaseSelection,
    ReleaseSnapshot,
    Stage,
    classify_asset_names,
    next_action,
    parse_state,
    render_body,
    select_release_candidates,
    snapshot_from_document,
    validate_legacy_files,
    verify_rollback,
)
from tools.copy_runtime_licenses import copy_runtime_licenses
from tools.finalize_sbom import finalize, resolve_component_manifest
from tools.release_notes import build_release_notes
from tools.verify_release import (
    ReleaseVerificationError,
    _packaged_environment,
    _safe_member,
    _verify_native_components,
    _verify_packaged_report_text,
    _verify_source_offer,
)


def test_secret_check_scans_extensionless_private_key(tmp_path: Path) -> None:
    marker = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"
    (tmp_path / "identity").write_bytes(marker + b"\nnot-a-real-key\n")

    assert check(tmp_path) == ["private material pattern found: identity"]


def test_secret_check_rejects_private_and_sqlite_sidecar_suffixes(tmp_path: Path) -> None:
    (tmp_path / "capture.csv").write_text("source,destination\n", encoding="utf-8")
    (tmp_path / "session-report.html").write_text("<!doctype html>", encoding="utf-8")
    (tmp_path / "session.db-wal").write_bytes(b"runtime state")
    (tmp_path / "client.pem").write_bytes(b"certificate material")

    problems = check(tmp_path)

    assert "private/runtime data file is not allowed: capture.csv" in problems
    assert "private/runtime data file is not allowed: client.pem" in problems
    assert "private/runtime data file is not allowed: session-report.html" in problems
    assert "private/runtime data file is not allowed: session.db-wal" in problems


def test_release_verifier_rejects_generated_html_report() -> None:
    with pytest.raises(ReleaseVerificationError, match="private/runtime suffix"):
        _safe_member(zipfile.ZipInfo("ArubaSessionTracker/session-report.html"))


@pytest.mark.parametrize(
    "member",
    (
        "ArubaSessionTracker/_internal/qopensslbackend.dll.",
        "ArubaSessionTracker/_internal/QOPENSSLBackend.DLL ",
        "ArubaSessionTracker/_internal/NUL.dll",
        "ArubaSessionTracker/_internal/native.dll:stream",
    ),
)
def test_release_verifier_rejects_windows_path_aliases(member: str) -> None:
    with pytest.raises(ReleaseVerificationError, match="unsafe Windows path alias"):
        _safe_member(zipfile.ZipInfo(member))


def test_packaged_smoke_environment_excludes_development_python(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    monkeypatch.setenv("PATH", r"C:\Python313;C:\Windows\System32")
    monkeypatch.setenv("PYTHONHOME", r"C:\Python313")
    monkeypatch.setenv("VIRTUAL_ENV", r"D:\repo\.venv")
    monkeypatch.setenv("QT_PLUGIN_PATH", r"D:\host-qt\plugins")
    monkeypatch.setenv("QML2_IMPORT_PATH", r"D:\host-qt\qml")

    environment = _packaged_environment()

    assert environment["PATH"] == r"C:\Windows\System32;C:\Windows"
    assert not (set(INJECTION_VARIABLES) & environment.keys())


def _write_component_fixture(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    bundle = tmp_path / "ArubaSessionTracker"
    (bundle / "licenses").mkdir(parents=True)
    (bundle / "native").mkdir()
    (bundle / "licenses" / "fixture.txt").write_text("fixture license\n", encoding="utf-8")
    (bundle / "native" / "required.dat").write_bytes(b"required")
    (bundle / "native" / "runtime.dll").write_bytes(b"native fixture bytes")
    manifest = tmp_path / "third_party_components.toml"
    manifest.write_text(
        """schema_version = 1
resolved_manifest = "THIRD_PARTY_COMPONENTS.json"

[policy]
required_bundle_files = ["native/required.dat"]
forbidden_bundle_globs = ["**/forbidden.dll", "**/qopensslbackend.dll"]

[[components]]
id = "fixture-runtime"
name = "Fixture runtime"
type = "library"
version = "{python_version}"
license_name = "Fixture license"
license_files = ["licenses/fixture.txt"]
source_urls = ["https://example.invalid/source/{python_version}"]
files = ["native/runtime.dll"]
""",
        encoding="utf-8",
    )
    versions = {
        "cryptography_openssl_version": "4.0.2",
        "libyaml_version": "0.2.5",
        "openssl_version": "3.0.15",
        "pyinstaller_version": "6.22.2",
        "python_version": "3.13.1",
        "qt_version": "6.11.0",
        "sqlite_version": "3.45.3",
    }
    return bundle, manifest, versions


def test_native_component_manifest_hashes_exact_files_and_fails_on_forbidden(
    tmp_path: Path,
) -> None:
    bundle, manifest, versions = _write_component_fixture(tmp_path)

    resolved = resolve_component_manifest(manifest, bundle, versions=versions)

    components = resolved["components"]
    assert isinstance(components, list)
    component = components[0]
    assert isinstance(component, dict)
    expected = hashlib.sha256(b"native fixture bytes").hexdigest()
    assert component["files"] == [{"path": "native/runtime.dll", "sha256": expected}]
    (bundle / "native" / "rogue.PYD").write_bytes(b"unassigned native")
    with pytest.raises(ValueError, match="not assigned to a component"):
        resolve_component_manifest(manifest, bundle, versions=versions)
    (bundle / "native" / "rogue.PYD").unlink()
    (bundle / "native" / "forbidden.dll").write_bytes(b"host PATH contamination")
    with pytest.raises(ValueError, match="forbidden native bundle file"):
        resolve_component_manifest(manifest, bundle, versions=versions)
    (bundle / "native" / "forbidden.dll").unlink()
    (bundle / "native" / "QOpenSSLBackend.DLL").write_bytes(b"case variant")
    with pytest.raises(ValueError, match="forbidden native bundle file"):
        resolve_component_manifest(manifest, bundle, versions=versions)


def test_optional_native_component_is_omitted_or_fully_inventoried(tmp_path: Path) -> None:
    bundle, manifest, versions = _write_component_fixture(tmp_path)
    manifest.write_text(
        manifest.read_text(encoding="utf-8")
        + """

[[components]]
id = "optional-runtime"
name = "Optional runtime"
type = "library"
version = "{python_version}"
optional = true
license_name = "Fixture license"
license_files = ["licenses/fixture.txt"]
source_urls = ["https://example.invalid/optional/{python_version}"]
globs = ["native/optional/**/*.dll"]
""",
        encoding="utf-8",
    )

    absent = resolve_component_manifest(manifest, bundle, versions=versions)
    assert [component["id"] for component in absent["components"]] == ["fixture-runtime"]

    optional = bundle / "native" / "optional" / "nested" / "runtime.DLL"
    optional.parent.mkdir(parents=True)
    optional.write_bytes(b"optional native")
    present = resolve_component_manifest(manifest, bundle, versions=versions)
    component = next(
        component for component in present["components"] if component["id"] == "optional-runtime"
    )
    assert [entry["path"] for entry in component["files"]] == ["native/optional/nested/runtime.DLL"]


def test_shared_native_glob_semantics_are_case_insensitive_and_recursive() -> None:
    cryptography = "_internal/cryptography/hazmat/bindings/_rust.PYD"
    qopenssl = "_INTERNAL/PySide6/plugins/tls/QOpenSSLBackend.DLL"

    assert bundle_pattern_matches(cryptography, "_internal/cryptography/hazmat/bindings/*.pyd")
    assert bundle_pattern_matches(qopenssl, "**/qopensslbackend.dll")
    assert bundle_pattern_matches("qopensslbackend.dll", "**/qopensslbackend.dll")
    assert bundle_pattern_matches(
        "_internal/PySide6/plugins/nested/backend/qfixture.dll",
        "_internal/PySide6/plugins/**/*.dll",
    )
    assert bundle_pattern_matches(
        "_internal/PySide6/plugins/qfixture.dll",
        "_internal/PySide6/plugins/**/*.dll",
    )
    assert native_bundle_paths(
        {cryptography, "ArubaSessionTracker.ExE", "licenses/LICENSE.txt"}
    ) == {cryptography, "ArubaSessionTracker.ExE"}


def test_repository_component_contract_uses_complete_casefold_policy() -> None:
    contract = tomllib.loads(Path("third_party_components.toml").read_text(encoding="utf-8"))
    policy = contract["policy"]
    components = {component["id"]: component for component in contract["components"]}

    assert "forbidden_bundle_files" not in policy
    assert {
        "**/qopensslbackend.dll",
        "**/libcrypto-3-x64.dll",
        "**/libssl-3-x64.dll",
        "**/api-ms-win-*.dll",
        "**/ucrtbase.dll",
        "**/opengl32sw.dll",
    }.issubset(policy["forbidden_bundle_globs"])
    assert components["qt-for-python-runtime"]["version"] == "{qt_version}"
    assert components["cryptography-native-extension"]["files"] == [
        "_internal/cryptography/hazmat/bindings/_rust.pyd"
    ]
    assert components["cryptography-native-extension"]["version"] == (
        "{cryptography_version}+openssl.{cryptography_openssl_version}"
    )
    assert (
        "licenses/openssl/NOTICE.txt"
        in components["cryptography-native-extension"]["license_files"]
    )
    assert components["pynacl-native-extension"]["version"] == (
        "{pynacl_version}+libsodium.1.0.20-stable"
    )
    assert (
        "licenses__licenses__LICENSE.libsodium.txt"
        in components["pynacl-native-extension"]["license_files"][1]
    )
    assert components["pyyaml-native-extension"]["version"] == (
        "{pyyaml_version}+libyaml.{libyaml_version}"
    )
    for component in components.values():
        assert not any(
            PurePosixPath(pattern).suffix.casefold() in {".dll", ".exe", ".pyd"}
            for pattern in component.get("globs", [])
        )
    exact_native_paths = {
        path.casefold()
        for component in components.values()
        for path in component.get("files", [])
        if PurePosixPath(path).suffix.casefold() in {".dll", ".exe", ".pyd"}
    }
    assert {
        "_internal/rogue.pyd",
        "_internal/pyside6/plugins/rogue/evil.dll",
        "_internal/pyside6/plugins/tls/qopensslbackend-copy.dll",
    }.isdisjoint(exact_native_paths)
    assert components["sqlite-runtime"]["source_urls"] == [
        "https://www.sqlite.org/src/tarball/sqlite.tar.gz?r=version-{sqlite_version}",
        "https://www.sqlite.org/copyright.html",
    ]
    notices = Path("THIRD_PARTY_NOTICES.txt").read_text(encoding="utf-8")
    assert "SQLite is dedicated to the public domain" in notices
    assert "microsoft-vc-runtime" in notices
    assert components["microsoft-vc-runtime"]["license_files"] == ["licenses/cpython/LICENSE.txt"]
    assert contract["license_fallbacks"] == [
        {
            "package": "pyserial",
            "version": "3.5",
            "source_file": "licenses/pyserial-BSD-3-Clause.txt",
            "source_url": "https://raw.githubusercontent.com/pyserial/pyserial/v3.5/LICENSE.txt",
            "sha256": "f91cb9813de6a5b142b8f7f2dede630b5134160aedaeaf55f4d6a7e2593ca3f3",
        }
    ]


def test_finalize_sbom_links_native_component_and_writes_resolved_manifest(
    tmp_path: Path,
) -> None:
    bundle, manifest, versions = _write_component_fixture(tmp_path)
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"bom-ref": "pkg:pypi/demo@1.0", "name": "demo", "version": "1.0"}],
                "dependencies": [
                    {"ref": "pkg:pypi/demo@1.0", "dependsOn": []},
                ],
                "metadata": {
                    "component": {
                        "bom-ref": "app:fixture",
                        "name": "fixture",
                        "version": "0.5.4",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "fixture"\nversion = "0.5.4"\ndependencies = ["demo==1.0"]\n',
        encoding="utf-8",
    )
    resolved_path = bundle / "THIRD_PARTY_COMPONENTS.json"

    finalize(
        sbom,
        pyproject,
        manifest,
        bundle,
        resolved_path,
        versions=versions,
    )

    document = json.loads(sbom.read_text(encoding="utf-8"))
    native_ref = "native:fixture-runtime@3.13.1"
    assert any(component.get("bom-ref") == native_ref for component in document["components"])
    root = next(item for item in document["dependencies"] if item["ref"] == "app:fixture")
    assert root["dependsOn"] == [native_ref, "pkg:pypi/demo@1.0"]
    assert json.loads(resolved_path.read_text(encoding="utf-8"))["schema_version"] == 1


def _write_locked_components(path: Path, components: tuple[tuple[str, str], ...]) -> None:
    path.write_text(
        "".join(
            f"{name}=={version} --hash=sha256:{index:064x}\n"
            for index, (name, version) in enumerate(components, start=1)
        ),
        encoding="utf-8",
    )


def test_native_release_verifier_detects_file_changed_after_sbom_finalization(
    tmp_path: Path,
) -> None:
    bundle, manifest, versions = _write_component_fixture(tmp_path)
    (bundle / "licenses" / "cpython").mkdir()
    (bundle / "licenses" / "openssl").mkdir()
    (bundle / "licenses" / "cpython" / "LICENSE.txt").write_text(
        "PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2\n", encoding="utf-8"
    )
    (bundle / "licenses" / "openssl" / "LICENSE.txt").write_text(
        "Apache License\nVersion 2.0\n", encoding="utf-8"
    )
    (bundle / "licenses" / "openssl" / "NOTICE.txt").write_text(
        "Copyright The OpenSSL Project Authors\n", encoding="utf-8"
    )
    offer_text = Path("OPEN_SOURCE_SOURCE_OFFER.txt").read_text(encoding="utf-8")
    (bundle / "OPEN_SOURCE_SOURCE_OFFER.txt").write_bytes(offer_text.encode("utf-8"))
    (tmp_path / "OPEN_SOURCE_SOURCE_OFFER.txt").write_bytes(offer_text.encode("utf-8"))
    runtime_lock = tmp_path / "runtime.lock"
    build_lock = tmp_path / "build.lock"
    _write_locked_components(
        runtime_lock,
        (
            ("Paramiko", "5.0.0"),
            ("PySide6-Essentials", "6.11.0"),
            ("shiboken6", "6.11.0"),
        ),
    )
    _write_locked_components(build_lock, (("PyInstaller", "6.22.2"),))
    for package, version in (
        ("paramiko", "5.0.0"),
        ("pyside6-essentials", "6.11.0"),
        ("shiboken6", "6.11.0"),
    ):
        package_root = bundle / "licenses" / package
        package_root.mkdir()
        (package_root / "LICENSE.txt").write_text("fixture license\n", encoding="utf-8")
        (package_root / "PACKAGE-METADATA.txt").write_text(
            f"Package: {package}\n"
            f"Version: {version}\n"
            "Declared-License: Fixture\n"
            "Project: https://example.invalid\n"
            "Wheel-License-Files-Copied: 1\n"
            "Supplemental-License-Files-Copied: 0\n"
            "License-Evidence-Files-Copied: 1\n",
            encoding="utf-8",
        )
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"bom-ref": "pkg:pypi/demo@1.0", "name": "demo", "version": "1.0"}],
                "dependencies": [{"ref": "pkg:pypi/demo@1.0", "dependsOn": []}],
                "metadata": {
                    "component": {
                        "bom-ref": "app:fixture",
                        "name": "fixture",
                        "version": "0.5.4",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "fixture"\nversion = "0.5.4"\ndependencies = ["demo==1.0"]\n',
        encoding="utf-8",
    )
    finalize(
        sbom,
        pyproject,
        manifest,
        bundle,
        bundle / "THIRD_PARTY_COMPONENTS.json",
        versions=versions,
    )
    archive_path = tmp_path / "bundle.zip"

    def write_archive() -> None:
        with zipfile.ZipFile(archive_path, "w") as output:
            for path in sorted(item for item in bundle.rglob("*") if item.is_file()):
                output.write(path, f"ArubaSessionTracker/{path.relative_to(bundle).as_posix()}")

    def verify_archive(sbom_document: dict[str, object] | None = None) -> None:
        with zipfile.ZipFile(archive_path) as archive:
            files = {_safe_member(info): info for info in archive.infolist() if not info.is_dir()}
            relative_names = {PurePosixPath(*member.parts[1:]).as_posix() for member in files}
            _verify_native_components(
                archive=archive,
                files=files,
                relative_names=relative_names,
                sbom_document=(
                    json.loads(sbom.read_text(encoding="utf-8"))
                    if sbom_document is None
                    else sbom_document
                ),
                build_info={
                    "cryptographyOpenssl": "4.0.2",
                    "libyaml": "0.2.5",
                    "openssl": "3.0.15",
                    "pyinstaller": "6.22.2",
                    "python": "3.13.1",
                    "qt": "6.11.0",
                    "sqlite": "3.45.3",
                },
                component_manifest_path=manifest,
                runtime_lock=runtime_lock,
                build_lock=build_lock,
            )

    write_archive()
    verify_archive()
    altered_sbom = json.loads(sbom.read_text(encoding="utf-8"))
    native_component = next(
        item
        for item in altered_sbom["components"]
        if item.get("bom-ref") == "native:fixture-runtime@3.13.1"
    )
    native_component["externalReferences"] = []
    with pytest.raises(ReleaseVerificationError, match="source references differ"):
        verify_archive(altered_sbom)
    (bundle / "native" / "rogue.DLL").write_bytes(b"rogue after finalization")
    write_archive()
    with pytest.raises(ReleaseVerificationError, match="not assigned to a component"):
        verify_archive()
    (bundle / "native" / "rogue.DLL").unlink()
    (bundle / "native" / "runtime.dll").write_bytes(b"changed after finalization")
    write_archive()
    with pytest.raises(ReleaseVerificationError, match="file hash differs"):
        verify_archive()


def test_lgpl_source_offer_names_exact_locked_versions_and_request_route() -> None:
    offer = Path("OPEN_SOURCE_SOURCE_OFFER.txt").read_text(encoding="utf-8")
    runtime_components = {
        "paramiko": ("5.0.0", set()),
        "pyside6-essentials": ("6.11.0", set()),
        "shiboken6": ("6.11.0", set()),
    }

    _verify_source_offer(offer, runtime_components)

    with pytest.raises(ReleaseVerificationError, match="source offer"):
        _verify_source_offer(
            offer.replace("at least three years", "temporarily"), runtime_components
        )
    with pytest.raises(ReleaseVerificationError, match="reviewed repository text"):
        _verify_source_offer(
            offer + "\nThis offer is not available for at least three years.\n",
            runtime_components,
            canonical_text=offer,
        )


def test_pyserial_zero_wheel_license_requires_hashed_explicit_fallback(tmp_path: Path) -> None:
    lock = tmp_path / "runtime.lock"
    lock.write_text("pyserial==3.5\n", encoding="utf-8")

    with pytest.raises(ValueError, match="no license or notice evidence"):
        copy_runtime_licenses(lock, tmp_path / "without-fallback")

    destination = tmp_path / "with-fallback"
    copy_runtime_licenses(
        lock,
        destination,
        component_manifest=Path("third_party_components.toml"),
    )
    fallback = destination / "pyserial" / "SUPPLEMENTAL__pyserial-BSD-3-Clause.txt"
    assert fallback.stat().st_size == 1885
    assert hashlib.sha256(fallback.read_bytes()).hexdigest() == (
        "f91cb9813de6a5b142b8f7f2dede630b5134160aedaeaf55f4d6a7e2593ca3f3"
    )
    metadata = (destination / "pyserial" / "PACKAGE-METADATA.txt").read_text(encoding="utf-8")
    assert "Wheel-License-Files-Copied: 0" in metadata
    assert "Supplemental-License-Files-Copied: 1" in metadata
    assert "License-Evidence-Files-Copied: 1" in metadata


def test_packaging_environment_probe_observes_actual_child_environment() -> None:
    checker = Path("tools/check_packaging_environment.py").resolve()
    allowed = str(Path(sys.executable).resolve().parent)
    clean_environment = os.environ.copy()
    clean_environment["PATH"] = allowed
    for name in INJECTION_VARIABLES:
        clean_environment.pop(name, None)
    arguments = [sys.executable, str(checker), "--allowed-path", allowed]

    clean = subprocess.run(  # noqa: S603
        arguments,
        check=False,
        capture_output=True,
        env=clean_environment,
        timeout=30,
    )
    assert clean.returncode == 0
    assert b"PACKAGING_CHILD_ENVIRONMENT_ISOLATED" in clean.stdout

    polluted_environment = clean_environment.copy()
    polluted_environment["PYTHONPATH"] = str(Path.cwd())
    polluted = subprocess.run(  # noqa: S603
        arguments,
        check=False,
        capture_output=True,
        env=polluted_environment,
        timeout=30,
    )
    assert polluted.returncode == 1
    assert b"PYTHONPATH" in polluted.stderr


def test_windows_packaging_isolates_host_path_and_verifies_native_contract() -> None:
    build = Path("build_windows.ps1").read_text(encoding="utf-8")
    publish = Path("tools/verify_publish_assets.ps1").read_text(encoding="utf-8")

    assert "$packagingPathBefore = $env:PATH" in build
    assert "$env:PATH = [string]::Join" in build
    assert "$env:PATH = $packagingPathBefore" in build
    assert "tools/check_packaging_environment.py" in build
    for name in INJECTION_VARIABLES:
        assert f'"{name}"' in build
    sanitization_index = build.index("$packagingEnvironmentBefore = @{}")
    first_python_index = build.index("Invoke-Checked $PythonPath")
    outer_restore_index = build.rindex("foreach ($environmentName in $packagingInjectionNames)")
    assert sanitization_index < first_python_index
    assert build.index("tools/copy_runtime_licenses.py") < outer_restore_index
    assert build.index("tools/finalize_sbom.py") < outer_restore_index
    assert '"libcrypto-3-x64.dll", "libssl-3-x64.dll"' in build
    assert "qopensslbackend.dll" in build
    assert "qschannelbackend.dll" in build
    assert "opengl32sw.dll" in build
    assert '"--runtime-lock"' in build
    assert '"--qt-version"' in build
    assert '"--sqlite-version"' in build
    assert '"--cryptography-openssl-version"' in build
    assert '"--libyaml-version"' in build
    assert '"--component-manifest"' in build
    assert '"--component-manifest"' in build
    assert '"--build-lock"' in build
    assert "--component-manifest third_party_components.toml" in publish
    assert "--build-lock requirements-build.lock" in publish


def test_packaged_report_verifier_requires_printable_history_structure() -> None:
    script = "document.documentElement.dataset.filterReady = 'true';"
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    csp = f"default-src 'none'; script-src 'sha256-{digest}'"
    report = f"""<!doctype html>
    <meta http-equiv="Content-Security-Policy" content="{csp}">
    세션 추적 결과 KST 한국어-MD
    <div class="flow-panel">조회 출발지</div>
    <dl class="summary-stats"></dl>
    결과 찾기
    <section id="result-filter"></section>
    <input id="filter-ip"><select id="filter-protocol"></select><input id="filter-port">
    최신 세션 결과
    <table><thead><tr><th>출발지 IP·포트</th><th>목적지 IP·포트</th></tr></thead>
    <tbody><tr class="report-row"><td class="protocol-cell">TCP</td></tr></tbody></table>
    전체 추적 이력
    <details class="history-toggle"></details>
    <div class="details-body" id="observation-history-body"></div>
    <style>.history-toggle + .details-body {{ display:block !important; }}</style>
    <script>{script}</script>
    """

    _verify_packaged_report_text(report)

    with pytest.raises(ReleaseVerificationError, match="standalone and complete"):
        _verify_packaged_report_text(
            report.replace('<details class="history-toggle">', "<details>")
        )
    with pytest.raises(ReleaseVerificationError, match="standalone and complete"):
        _verify_packaged_report_text(
            report.replace("script-src 'sha256-", "script-src 'sha256-broken-", 1)
        )
    with pytest.raises(ReleaseVerificationError, match="standalone and complete"):
        _verify_packaged_report_text(f"{report}<script>extra</script>")


def test_secret_check_detects_sqlite_magic_without_database_suffix(tmp_path: Path) -> None:
    (tmp_path / "history").write_bytes(b"SQLite format 3\x00" + bytes(3 * 1024 * 1024))

    assert check(tmp_path) == ["SQLite database content found: history"]


def test_secret_check_does_not_treat_binary_parser_marker_as_a_key(tmp_path: Path) -> None:
    marker = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"
    (tmp_path / "library.bin").write_bytes(b"MZ\x00" + bytes(8192) + marker)

    assert check(tmp_path) == []


def _write_coverage_xml(
    destination: Path,
    *,
    global_line_rate: float = 0.90,
    branch_rate: float = 0.80,
) -> None:
    classes = "".join(
        f'<class filename="{filename}" branch-rate="{branch_rate}" />'
        for filename in CRITICAL_BRANCH_FLOORS
    )
    destination.write_text(
        f'<coverage line-rate="{global_line_rate}"><packages><package><classes>'
        f"{classes}</classes></package></packages></coverage>",
        encoding="utf-8",
    )


def test_coverage_policy_accepts_global_and_critical_module_floors(tmp_path: Path) -> None:
    report = tmp_path / "coverage.xml"
    _write_coverage_xml(report)

    check_coverage_policy(report)


def test_coverage_policy_rejects_hidden_critical_branch_gap(tmp_path: Path) -> None:
    report = tmp_path / "coverage.xml"
    _write_coverage_xml(report, branch_rate=0.64)

    with pytest.raises(CoveragePolicyError, match=r"main\.py: branch coverage"):
        check_coverage_policy(report)


def test_coverage_policy_rejects_global_line_regression(tmp_path: Path) -> None:
    report = tmp_path / "coverage.xml"
    _write_coverage_xml(report, global_line_rate=0.82)

    with pytest.raises(CoveragePolicyError, match="global line coverage"):
        check_coverage_policy(report)


def _release_document(asset: Path) -> dict[str, object]:
    expected = ExpectedAsset(asset.name, asset)
    return {
        "tag_name": "v0.3.1",
        "target_commitish": "a" * 40,
        "draft": True,
        "prerelease": True,
        "body": "notes\n<!-- owned -->",
        "assets": [
            {
                "name": asset.name,
                "state": "uploaded",
                "size": expected.size,
                "digest": expected.digest,
            }
        ],
    }


def test_remote_release_verifies_github_digest_and_state(tmp_path: Path) -> None:
    asset = tmp_path / "package.zip"
    asset.write_bytes(b"verified package")

    verify_release(
        _release_document(asset),
        expected_tag="v0.3.1",
        expected_commit="a" * 40,
        expected_draft=True,
        expected_prerelease=True,
        expected_assets=(ExpectedAsset(asset.name, asset),),
        required_marker="<!-- owned -->",
    )


def test_remote_release_rejects_digest_mismatch(tmp_path: Path) -> None:
    asset = tmp_path / "package.zip"
    asset.write_bytes(b"verified package")
    document = _release_document(asset)
    document["assets"][0]["digest"] = "sha256:" + "0" * 64  # type: ignore[index]

    with pytest.raises(RemoteReleaseError, match="digest differs"):
        verify_release(
            document,
            expected_tag="v0.3.1",
            expected_commit="a" * 40,
            expected_draft=True,
            expected_prerelease=True,
            expected_assets=(ExpectedAsset(asset.name, asset),),
        )


def test_versioned_release_can_delegate_target_proof_to_annotated_tag_gate(
    tmp_path: Path,
) -> None:
    asset = tmp_path / "package.zip"
    asset.write_bytes(b"verified package")
    document = _release_document(asset)
    document["target_commitish"] = "main"

    verify_release(
        document,
        expected_tag="v0.3.1",
        expected_commit="a" * 40,
        expected_draft=True,
        expected_prerelease=True,
        expected_assets=(ExpectedAsset(asset.name, asset),),
        verify_target=False,
    )


def test_remote_release_rejects_extra_public_asset(tmp_path: Path) -> None:
    asset = tmp_path / "package.zip"
    asset.write_bytes(b"verified package")
    document = _release_document(asset)
    document["assets"].append(  # type: ignore[union-attr]
        {
            "name": "unexpected.txt",
            "state": "uploaded",
            "size": 1,
            "digest": "sha256:" + "0" * 64,
        }
    )

    with pytest.raises(RemoteReleaseError, match="exact expected asset set"):
        verify_release(
            document,
            expected_tag="v0.3.1",
            expected_commit="a" * 40,
            expected_draft=True,
            expected_prerelease=True,
            expected_assets=(ExpectedAsset(asset.name, asset),),
        )


def test_release_notes_embed_verified_single_zip_download_contract(tmp_path: Path) -> None:
    archive = tmp_path / "ArubaSessionTracker_v0.4.0_windows_x64.zip"
    archive.write_bytes(b"verified windows bundle")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sidecar = tmp_path / f"{archive.name}.sha256"
    sidecar.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")

    notes = build_release_notes("# 검토된 릴리스\n", archive, sidecar)

    assert f"SHA-256: `{digest}`" in notes
    assert f"Windows 11 x64 실행 파일: `{archive.name}`" in notes
    assert "ArubaSessionTracker/sbom.cdx.json" in notes
    assert "ArubaSessionTracker/THIRD_PARTY_COMPONENTS.json" in notes
    assert "ArubaSessionTracker/OPEN_SOURCE_SOURCE_OFFER.txt" in notes
    assert "Source code (zip)" in notes


def test_release_notes_reject_mismatched_zip_sidecar(tmp_path: Path) -> None:
    archive = tmp_path / "ArubaSessionTracker_v0.4.0_windows_x64.zip"
    archive.write_bytes(b"verified windows bundle")
    sidecar = tmp_path / f"{archive.name}.sha256"
    sidecar.write_text(f"{'0' * 64}  {archive.name}\n", encoding="utf-8")

    with pytest.raises(VersionError, match="does not match"):
        build_release_notes("# 검토된 릴리스\n", archive, sidecar)


def _desired_release() -> DesiredRelease:
    return DesiredRelease(
        commit="a" * 40,
        zip_name="ArubaSessionTracker_v0.4.0_windows_x64.zip",
        sha256="b" * 64,
        size=1234,
    )


def _durable_body(stage: Stage, desired: DesiredRelease | None = None) -> str:
    target = desired or _desired_release()
    notes = f"# Continuous\n\n- SHA-256: `{target.sha256}`\n"
    return render_body(notes, DurableState(stage, target))


def _desired_asset(desired: DesiredRelease) -> tuple[AssetEvidence, ...]:
    return (
        AssetEvidence(
            desired.zip_name,
            desired.size,
            f"sha256:{desired.sha256}",
        ),
    )


def _continuous_candidate(
    release_id: int,
    *,
    published_at: str | None = None,
    assets: list[dict[str, object]] | None = None,
    body: str | None = None,
) -> dict[str, object]:
    return {
        "id": release_id,
        "draft": True,
        "prerelease": True,
        "name": "Aruba Session Tracker continuous",
        "body": body or _durable_body(Stage.STAGING),
        "target_commitish": "a" * 40,
        "tag_name": "continuous",
        "published_at": published_at,
        "assets": assets or [],
    }


def _legacy_candidate_assets() -> list[dict[str, object]]:
    archive = "ArubaSessionTracker_v0.3.1_windows_x64.zip"
    return [
        {"name": archive, "size": 10, "digest": f"sha256:{'c' * 64}"},
        {"name": f"{archive}.sha256", "size": 109, "digest": f"sha256:{'d' * 64}"},
        {
            "name": "ArubaSessionTracker_v0.3.1_sbom.cdx.json",
            "size": 200,
            "digest": f"sha256:{'e' * 64}",
        },
    ]


def test_continuous_release_selection_recovers_real_duplicate_draft_shape() -> None:
    candidates = [
        _continuous_candidate(
            378408554,
            published_at="2026-08-29T00:00:00Z",
            assets=_legacy_candidate_assets(),
        ),
        _continuous_candidate(378942556),
        _continuous_candidate(378942581),
    ]

    selection = select_release_candidates(candidates)

    assert selection == ReleaseSelection(
        keeper_id=378408554,
        cleanup_ids=(378942556, 378942581),
    )


def test_continuous_release_selection_fails_closed_on_nonempty_duplicate() -> None:
    candidates = [
        _continuous_candidate(
            10,
            published_at="2026-08-29T00:00:00Z",
            assets=_legacy_candidate_assets(),
        ),
        _continuous_candidate(
            11,
            assets=[
                {
                    "name": "ArubaSessionTracker_v0.4.0_windows_x64.zip",
                    "size": 1234,
                    "digest": f"sha256:{'b' * 64}",
                }
            ],
        ),
    ]

    with pytest.raises(ContinuousReleaseStateError, match="empty unpublished draft"):
        select_release_candidates(candidates)


def test_continuous_release_selection_fails_closed_on_foreign_duplicate() -> None:
    candidates = [
        _continuous_candidate(
            10,
            published_at="2026-08-29T00:00:00Z",
            assets=_legacy_candidate_assets(),
        ),
        _continuous_candidate(11, body="not owned"),
    ]

    with pytest.raises(ContinuousReleaseStateError, match="not workflow-owned"):
        select_release_candidates(candidates)


def test_continuous_release_selection_cleans_owned_starter_upload() -> None:
    candidate = _continuous_candidate(
        10,
        published_at="2026-08-29T00:00:00Z",
        assets=[
            {
                "id": 901,
                "name": "ArubaSessionTracker_v0.4.0_windows_x64.zip",
                "state": "starter",
                "size": 0,
                "digest": None,
            }
        ],
    )

    selection = select_release_candidates([candidate])

    assert selection == ReleaseSelection(
        keeper_id=10,
        cleanup_ids=(),
        cleanup_asset_ids=(901,),
    )


def test_continuous_release_selection_rejects_starter_with_foreign_name() -> None:
    candidate = _continuous_candidate(
        10,
        assets=[
            {
                "id": 901,
                "name": "unowned.bin",
                "state": "starter",
                "size": 0,
                "digest": None,
            }
        ],
    )

    with pytest.raises(ContinuousReleaseStateError, match="not a disposable owned"):
        select_release_candidates([candidate])


def test_continuous_release_selection_requires_durable_marker_for_duplicate() -> None:
    old_commit = "c" * 40
    candidates = [
        _continuous_candidate(
            10,
            published_at="2026-08-29T00:00:00Z",
            assets=_legacy_candidate_assets(),
        ),
        _continuous_candidate(
            11,
            body=(f"# legacy draft\n\n<!-- aruba-session-tracker-continuous:{old_commit} -->\n"),
        ),
    ]

    with pytest.raises(ContinuousReleaseStateError, match="no durable state marker"):
        select_release_candidates(candidates)


def test_continuous_durable_marker_round_trips_exact_desired_state() -> None:
    desired = _desired_release()

    body = _durable_body(Stage.ASSETS_VERIFIED, desired)
    parsed = parse_state(body)

    assert parsed == DurableState(Stage.ASSETS_VERIFIED, desired)
    assert body.count("<!-- aruba-session-tracker-continuous:") == 1
    assert body.count("<!-- aruba-session-tracker-continuous-state:") == 1


@pytest.mark.parametrize(
    ("old", "new"),
    ((r'"schema":1', r'"schema":true'), (r'"size":1234', r'"size":true')),
)
def test_continuous_durable_marker_rejects_boolean_integer_fields(
    old: str,
    new: str,
) -> None:
    body = _durable_body(Stage.STAGING).replace(old, new)

    with pytest.raises(ContinuousReleaseStateError, match="marker"):
        parse_state(body)


def test_continuous_legacy_trio_requires_one_common_version() -> None:
    with pytest.raises(ContinuousReleaseStateError, match="same-version trio"):
        classify_asset_names(
            (
                "ArubaSessionTracker_v0.4.0_windows_x64.zip",
                "ArubaSessionTracker_v0.3.1_windows_x64.zip.sha256",
                "ArubaSessionTracker_v0.4.0_sbom.cdx.json",
            )
        )


def test_continuous_legacy_sidecar_must_match_zip(tmp_path: Path) -> None:
    archive = tmp_path / "ArubaSessionTracker_v0.3.1_windows_x64.zip"
    archive.write_bytes(b"legacy verified bytes")
    sidecar = tmp_path / f"{archive.name}.sha256"
    sbom = tmp_path / "ArubaSessionTracker_v0.3.1_sbom.cdx.json"
    sbom.write_text('{"bomFormat":"CycloneDX"}', encoding="utf-8")
    sidecar.write_text(
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
        encoding="utf-8",
    )

    validate_legacy_files(archive, sidecar, sbom)
    sidecar.write_text(f"{'0' * 64}  {archive.name}\n", encoding="utf-8")

    with pytest.raises(ContinuousReleaseStateError, match="does not match"):
        validate_legacy_files(archive, sidecar, sbom)

    sidecar.write_text(
        f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
        encoding="utf-8",
    )
    sbom.write_text("[]", encoding="utf-8")
    with pytest.raises(ContinuousReleaseStateError, match="CycloneDX"):
        validate_legacy_files(archive, sidecar, sbom)


def test_continuous_snapshot_rejects_coerced_remote_metadata() -> None:
    document: dict[str, object] = {
        "draft": True,
        "prerelease": True,
        "name": "continuous",
        "body": "owned",
        "target_commitish": "a" * 40,
        "tag_name": "continuous",
        "assets": [
            {
                "name": "ArubaSessionTracker_v0.4.0_windows_x64.zip",
                "size": True,
                "digest": f"sha256:{'b' * 64}",
            }
        ],
    }

    with pytest.raises(ContinuousReleaseStateError, match="asset metadata"):
        snapshot_from_document(document, tag_commit="a" * 40)


def _apply_reconcile_action(
    snapshot: ReleaseSnapshot | None,
    action: Action,
    desired: DesiredRelease,
) -> ReleaseSnapshot:
    if action is Action.CREATE_DRAFT:
        return ReleaseSnapshot(
            draft=True,
            prerelease=True,
            title="Aruba Session Tracker continuous",
            body=_durable_body(Stage.STAGING, desired),
            target_commitish=desired.commit,
            tag_commit=None,
            assets=(),
        )
    assert snapshot is not None
    if action in {Action.HIDE_AND_MARK_STAGING, Action.MARK_STAGING}:
        return replace(
            snapshot,
            draft=True,
            body=_durable_body(Stage.STAGING, desired),
            target_commitish=desired.commit,
        )
    if action is Action.REPLACE_ASSETS:
        return replace(snapshot, assets=_desired_asset(desired))
    if action is Action.MARK_ASSETS_VERIFIED:
        return replace(snapshot, body=_durable_body(Stage.ASSETS_VERIFIED, desired))
    if action is Action.ALIGN_TAG:
        return replace(
            snapshot,
            tag_commit=desired.commit,
            target_commitish=desired.commit,
        )
    if action is Action.MARK_READY:
        return replace(snapshot, body=_durable_body(Stage.READY, desired))
    if action is Action.PUBLISH:
        return replace(snapshot, draft=False)
    raise AssertionError(f"not a mutating reconcile action: {action}")


def _converge_after_every_mutation_restart(
    initial: ReleaseSnapshot | None,
    desired: DesiredRelease,
) -> tuple[ReleaseSnapshot, tuple[Action, ...]]:
    snapshot = initial
    actions: list[Action] = []
    legacy_validated = False
    authenticated = False
    public_verified = False
    for _ in range(30):
        action = next_action(
            snapshot,
            desired,
            legacy_validated=legacy_validated,
            authenticated=authenticated,
            public_verified=public_verified,
        )
        actions.append(action)
        if action is Action.DONE:
            assert snapshot is not None
            return snapshot, tuple(actions)
        if action is Action.VALIDATE_LEGACY:
            legacy_validated = True
            continue
        if action is Action.VERIFY_DRAFT_DOWNLOAD:
            authenticated = True
            continue
        if action is Action.VERIFY_PUBLIC:
            public_verified = True
            continue
        snapshot = _apply_reconcile_action(snapshot, action, desired)
        # Simulate a worker being killed immediately after every durable
        # mutation. Only release/tag state survives into the resumed run.
        legacy_validated = False
        authenticated = False
        public_verified = False
    raise AssertionError("continuous reconciliation did not converge")


@pytest.mark.parametrize("source_contract", ["legacy_trio", "single_zip", "absent"])
def test_continuous_reconciliation_converges_after_every_interruption_boundary(
    source_contract: str,
) -> None:
    desired = _desired_release()
    if source_contract == "absent":
        initial = None
    else:
        old_commit = "c" * 40
        old_zip = "ArubaSessionTracker_v0.3.1_windows_x64.zip"
        assets = (AssetEvidence(old_zip, 10, f"sha256:{'d' * 64}"),)
        if source_contract == "legacy_trio":
            assets = (
                *assets,
                AssetEvidence(f"{old_zip}.sha256", 100, f"sha256:{'e' * 64}"),
                AssetEvidence(
                    "ArubaSessionTracker_v0.3.1_sbom.cdx.json",
                    200,
                    f"sha256:{'f' * 64}",
                ),
            )
        initial = ReleaseSnapshot(
            draft=False,
            prerelease=True,
            title="Prior continuous title",
            body=f"prior body\n<!-- aruba-session-tracker-continuous:{old_commit} -->\n",
            target_commitish=old_commit,
            tag_commit=old_commit,
            assets=assets,
        )

    final, actions = _converge_after_every_mutation_restart(initial, desired)

    assert final.draft is False
    assert final.tag_commit == desired.commit
    assert final.assets == _desired_asset(desired)
    assert parse_state(final.body) == DurableState(Stage.READY, desired)
    assert actions[-2:] == (Action.VERIFY_PUBLIC, Action.DONE)
    assert Action.ALIGN_TAG in actions
    if source_contract == "legacy_trio":
        assert Action.VALIDATE_LEGACY in actions


def test_continuous_reconciliation_recovers_partial_asset_replacement() -> None:
    desired = _desired_release()
    partial = ReleaseSnapshot(
        draft=True,
        prerelease=True,
        title="Aruba Session Tracker continuous",
        body=_durable_body(Stage.STAGING, desired),
        target_commitish=desired.commit,
        tag_commit="c" * 40,
        assets=(
            AssetEvidence(
                "ArubaSessionTracker_v0.3.1_windows_x64.zip",
                10,
                f"sha256:{'d' * 64}",
            ),
        ),
    )

    assert next_action(partial, desired) is Action.REPLACE_ASSETS
    final, actions = _converge_after_every_mutation_restart(partial, desired)
    assert final.assets == _desired_asset(desired)
    assert Action.REPLACE_ASSETS in actions


def test_continuous_rollback_verification_includes_exact_body_and_metadata() -> None:
    expected = ReleaseSnapshot(
        draft=False,
        prerelease=True,
        title="Exact prior title",
        body="exact prior body without an added newline",
        target_commitish="c" * 40,
        tag_commit="c" * 40,
        assets=(AssetEvidence("prior.zip", 7, f"sha256:{'d' * 64}"),),
    )

    verify_rollback(expected, expected)

    corruptions = (
        replace(expected, draft=True),
        replace(expected, prerelease=False),
        replace(expected, title=f"{expected.title} changed"),
        replace(expected, body=f"{expected.body}\n"),
        replace(expected, target_commitish="e" * 40),
        replace(expected, tag_commit="f" * 40),
        replace(expected, tag_name="not-continuous"),
        replace(
            expected,
            assets=(AssetEvidence("prior.zip", 8, f"sha256:{'d' * 64}"),),
        ),
    )
    for actual in corruptions:
        with pytest.raises(ContinuousReleaseStateError, match="exact prior state"):
            verify_rollback(actual, expected)


def test_versioned_workflow_verifies_draft_and_public_download_before_done() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "$assetPaths = @($zip)" in workflow
    assert "$assetPaths = @($zip, $sha, $sbom)" not in workflow
    assert "Release notes do not contain the verified public ZIP SHA-256." in workflow
    assert "--draft `" in workflow
    assert "tools/check_remote_release.py" in workflow
    assert "--state draft `" in workflow
    assert "--state published `" in workflow
    assert "Invoke-WebRequest -Uri $remote[0].browser_download_url" in workflow
    assert "Versioned release is already published; this workflow will not mutate it." in workflow
    publish_job = workflow[workflow.index("  publish:") :]
    dependency_install = publish_job.index(
        "python -m pip install --no-input -r requirements-runtime.lock"
    )
    package_verification = publish_job.index("./tools/verify_publish_assets.ps1")
    assert dependency_install < package_verification
    assert "Publish verification dependency check failed." in publish_job
    assert workflow.count("Assert-VersionedTagProvenance") == 4
    assert workflow.count("Assert-MainAtExpected") == 3
    assert "# Re-peel the annotated tag immediately before making the draft public." in workflow
    publish_index = workflow.index("gh release edit $env:RELEASE_TAG")
    final_main_index = workflow.rfind("Assert-MainAtExpected", 0, publish_index)
    final_tag_index = workflow.rfind("Assert-VersionedTagProvenance", 0, publish_index)
    assert final_main_index > final_tag_index > workflow.index("# Re-peel the annotated tag")


def test_versioned_workflow_requires_parallel_exact_tag_soak_before_publish() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    build_start = workflow.index("  build:")
    soak_start = workflow.index("  release-soak:")
    publish_start = workflow.index("  publish:")
    build_job = workflow[build_start:soak_start]
    soak_job = workflow[soak_start:publish_start]
    publish_job = workflow[publish_start:]

    assert "timeout-minutes: 60" in build_job
    assert 'ARUBA_SOAK_POLLS: "20000"' not in build_job
    assert "timeout-minutes: 120" in soak_job
    assert "permissions:\n      contents: read" in soak_job
    assert 'ARUBA_SOAK_POLLS: "20000"' in soak_job
    environment = soak_job.index('ARUBA_SOAK_POLLS: "20000"')
    exact_tag_gate = soak_job.index("python tools/check_release_ref.py")
    version_gate = soak_job.index("python tools/check_version.py --tag $env:RELEASE_TAG")
    dependencies = soak_job.index("python -m pip install --no-input -r requirements-dev.lock")
    soak = soak_job.index("python -m pytest -m soak -q --junitxml=artifacts/release-soak.xml")
    retained_result = soak_job.index("- name: Retain non-sensitive release soak result")
    assert environment < exact_tag_gate < version_gate < dependencies < soak < retained_result
    assert "if: always()" in soak_job[retained_result:]
    assert "if-no-files-found: warn" in soak_job[retained_result:]
    assert "needs:\n      - build\n      - release-soak" in publish_job


def test_continuous_workflow_delegates_to_durable_reconciler() -> None:
    workflow = Path(".github/workflows/continuous.yml").read_text(encoding="utf-8")

    assert "timeout-minutes: 30" in workflow
    assert "./tools/publish_continuous.ps1" in workflow
    assert "-ExpectedCommit $env:EXPECTED_COMMIT" in workflow
    assert "GH_TOKEN: ${{ github.token }}" in workflow
    assert "gh release" not in workflow
    publish_job = workflow[workflow.index("  publish:") :]
    dependency_install = publish_job.index(
        "python -m pip install --no-input -r requirements-runtime.lock"
    )
    package_verification = publish_job.index("./tools/publish_continuous.ps1")
    assert dependency_install < package_verification
    assert "Continuous publish verification dependency check failed." in publish_job


def test_continuous_reconciler_persists_stages_and_uses_release_ids() -> None:
    script = Path("tools/publish_continuous.ps1").read_text(encoding="utf-8")

    assert 'Write-StageBody "staging"' in script
    assert 'Write-StageBody "assets_verified"' in script
    assert 'Write-StageBody "ready"' in script
    assert "tools/continuous_release_state.py action" not in script
    assert '"tools/continuous_release_state.py", "action"' in script
    assert "tools/continuous_release_state.py validate-legacy" in script
    assert "tools/continuous_release_state.py select-release" in script
    assert '"repos/$Repository/releases?per_page=100&page=$page"' in script
    assert '"repos/$Repository/releases/$ReleaseId"' in script
    assert '"https://uploads.github.com/repos/' in script
    assert '"--hostname", "uploads.github.com"' not in script
    assert "Save-ReleaseAsset" in script
    assert "cleanup_asset_ids" in script
    assert '"release", "upload"' not in script
    assert '"release", "download"' not in script
    assert '"release", "edit"' not in script
    assert "Restore-RollbackState" not in script
    assert "durable forward state" in script
    assert "releases/$duplicateId" in script
    catch_case = script[script.index("catch {") : script.rindex("throw $primaryError")]
    assert "Set-ReleaseDraftState" in catch_case
    assert "Write-Warning" in catch_case


def test_continuous_reconciler_rechecks_main_tag_and_exact_single_zip() -> None:
    script = Path("tools/publish_continuous.ps1").read_text(encoding="utf-8")

    publish_case = script[script.index('"publish" {') : script.index('"verify_public" {')]
    assert "Assert-MainStillExpected" in publish_case
    assert "Assert-ContinuousTagAt $ExpectedCommit" in publish_case
    assert 'Assert-RemoteContract $release "draft"' in publish_case
    contract_index = publish_case.index('Assert-RemoteContract $release "draft"')
    tag_index = publish_case.index("Assert-ContinuousTagAt $ExpectedCommit", contract_index)
    main_index = publish_case.index("Assert-MainStillExpected", tag_index)
    mutation_index = publish_case.index("Set-ReleaseMetadata", main_index)
    assert contract_index < tag_index < main_index < mutation_index
    public_case = script[script.index('"verify_public" {') : script.index('"done" {')]
    assert public_case.count("Assert-ContinuousTagAt $ExpectedCommit") == 2
    assert "publishedByTag.id -ne [int64]$release.id" in public_case
    assert 'Assert-RemoteContract $release "published"' in public_case
    assert "-Public" in public_case
    assert "The public continuous ZIP differs from the verified input." in public_case


def test_nightly_workflow_runs_fixture_only_scaled_soak() -> None:
    workflow = Path(".github/workflows/nightly.yml").read_text(encoding="utf-8")

    assert 'ARUBA_SOAK_POLLS: "20000"' in workflow
    assert "python -m pytest -m soak" in workflow
    assert "QT_QPA_PLATFORM: offscreen" in workflow
    assert "github.token" not in workflow


def test_soak_worker_timeouts_allow_hosted_variance_without_extending_20k_cap() -> None:
    expected = "timeout=min(3_200, max(900, math.ceil(polls * 0.16)))"
    for path in ("tests/test_end_to_end_soak.py", "tests/test_storage_soak.py"):
        source = Path(path).read_text(encoding="utf-8")
        assert expected in source
        assert "max(500, math.ceil(polls * 0.16))" not in source

    guidance = Path("AGENTS.md").read_text(encoding="utf-8")
    assert "between 900 and 3,200 seconds" in guidance
