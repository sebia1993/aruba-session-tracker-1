from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from tools.check_coverage_policy import CoveragePolicyError, check_coverage_policy
from tools.check_no_secrets import check
from tools.check_remote_release import ExpectedAsset, RemoteReleaseError, verify_release
from tools.verify_release import ReleaseVerificationError, _safe_member


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
        for filename in (
            "src/aruba_session_tracker/main.py",
            "src/aruba_session_tracker/runtime.py",
            "src/aruba_session_tracker/collectors/ssh.py",
            "src/aruba_session_tracker/services/monitoring.py",
            "src/aruba_session_tracker/services/tracker.py",
            "src/aruba_session_tracker/storage/session_store.py",
            "src/aruba_session_tracker/ui/main_window.py",
        )
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


def test_versioned_workflow_verifies_draft_and_public_download_before_done() -> None:
    workflow = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "--draft `" in workflow
    assert "tools/check_remote_release.py" in workflow
    assert "--state draft `" in workflow
    assert "--state published `" in workflow
    assert "Invoke-WebRequest -Uri $remote[0].browser_download_url" in workflow
    assert "Versioned release is already published; this workflow will not mutate it." in workflow
    assert workflow.count("Assert-VersionedTagProvenance") == 4
    assert "# Re-peel the annotated tag immediately before making the draft public." in workflow


def test_continuous_workflow_hides_candidates_and_keeps_verified_rollback() -> None:
    workflow = Path(".github/workflows/continuous.yml").read_text(encoding="utf-8")

    assert "$newReleaseVerified = $false" in workflow
    hide_index = workflow.index("# Hide the published release before deleting stale temporaries")
    candidate_upload_index = workflow.index("& gh release upload continuous @candidatePaths")
    previous_cleanup_index = workflow.index('throw "Could not remove a prior continuous asset."')
    final_contract_index = workflow.index('throw "Final continuous release contract failed."')
    verified_index = workflow.index("$newReleaseVerified = $true")

    assert hide_index < candidate_upload_index
    assert candidate_upload_index < previous_cleanup_index
    assert previous_cleanup_index < final_contract_index < verified_index
    assert "Continuous update failed and rollback also failed" in workflow
    assert "candidate[0].digest" in workflow
    assert "A public continuous download differs" in workflow
    assert "tools/check_remote_release.py" in workflow
    assert "aruba-session-tracker-continuous:" in workflow
    assert "Could not recover a temporary continuous asset from a prior run." in workflow
    assert "temporaryAssetPattern" in workflow
    assert "continuous-rollback" in workflow
    assert "Could not restore prior continuous assets." in workflow
    assert "unexpectedDraftAssets" in workflow
    assert workflow.count("--required-marker $marker") == 4


def test_continuous_workflow_uses_exact_tag_lookup_and_fail_closed_drafts() -> None:
    workflow = Path(".github/workflows/continuous.yml").read_text(encoding="utf-8")

    assert "releases/tags/continuous" in workflow
    assert "releases?per_page=100" not in workflow
    assert "reservedDraftAssets" not in workflow
    assert '-X DELETE "repos/$env:GITHUB_REPOSITORY/releases/$' not in workflow
    marker_gate_index = workflow.index(
        'throw "The existing continuous draft is not owned by this workflow."'
    )
    draft_cleanup_index = workflow.index("$unexpectedDraftAssets = @(")
    assert marker_gate_index < draft_cleanup_index


def test_continuous_workflow_rechecks_tag_around_publish() -> None:
    workflow = Path(".github/workflows/continuous.yml").read_text(encoding="utf-8")

    assert "function Assert-ContinuousTagAt" in workflow
    assert "# Re-resolve immediately before publish" in workflow
    assert workflow.count("Assert-ContinuousTagAt $env:EXPECTED_COMMIT") >= 4
    assert "Assert-ContinuousTagAt $oldCommit" in workflow
