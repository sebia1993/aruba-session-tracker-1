"""Verify a GitHub release document against local immutable assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class RemoteReleaseError(ValueError):
    """Raised when remote release metadata does not match local evidence."""


@dataclass(frozen=True, slots=True)
class ExpectedAsset:
    name: str
    path: Path

    @property
    def size(self) -> int:
        return self.path.stat().st_size

    @property
    def digest(self) -> str:
        hasher = hashlib.sha256()
        with self.path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(chunk)
        return f"sha256:{hasher.hexdigest()}"


def parse_asset(value: str) -> ExpectedAsset:
    if "=" not in value:
        raise RemoteReleaseError("--asset must use REMOTE_NAME=LOCAL_PATH")
    name, raw_path = value.split("=", 1)
    if not name or Path(name).name != name:
        raise RemoteReleaseError("remote asset name must be a plain file name")
    path = Path(raw_path)
    if not path.is_file():
        raise RemoteReleaseError(f"local asset is missing: {path}")
    return ExpectedAsset(name=name, path=path)


def verify_release(
    document: dict[str, Any],
    *,
    expected_tag: str,
    expected_commit: str,
    expected_draft: bool,
    expected_prerelease: bool,
    expected_assets: tuple[ExpectedAsset, ...],
    allow_extra_assets: bool = False,
    required_marker: str | None = None,
    verify_target: bool = True,
) -> None:
    if document.get("tag_name") != expected_tag:
        raise RemoteReleaseError("release tag does not match")
    target = str(document.get("target_commitish", ""))
    if verify_target and target.lower() != expected_commit.lower():
        raise RemoteReleaseError("release target commit does not match")
    if document.get("draft") is not expected_draft:
        raise RemoteReleaseError("release draft state does not match")
    if document.get("prerelease") is not expected_prerelease:
        raise RemoteReleaseError("release prerelease state does not match")
    if required_marker is not None and required_marker not in str(document.get("body", "")):
        raise RemoteReleaseError("release workflow ownership marker is missing")

    raw_assets = document.get("assets")
    if not isinstance(raw_assets, list):
        raise RemoteReleaseError("release assets are missing")
    names = [str(item.get("name", "")) for item in raw_assets if isinstance(item, dict)]
    if len(names) != len(set(names)):
        raise RemoteReleaseError("release contains duplicate asset names")
    if not allow_extra_assets and set(names) != {item.name for item in expected_assets}:
        raise RemoteReleaseError("release does not contain the exact expected asset set")

    by_name = {str(item.get("name", "")): item for item in raw_assets if isinstance(item, dict)}
    for expected in expected_assets:
        actual = by_name.get(expected.name)
        if actual is None:
            raise RemoteReleaseError(f"release asset is missing: {expected.name}")
        if actual.get("state") != "uploaded":
            raise RemoteReleaseError(f"release asset is not uploaded: {expected.name}")
        if int(actual.get("size", -1)) != expected.size:
            raise RemoteReleaseError(f"release asset size differs: {expected.name}")
        digest = str(actual.get("digest", "")).lower()
        if digest != expected.digest:
            raise RemoteReleaseError(f"release asset digest differs: {expected.name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--state", choices=("draft", "published"), required=True)
    parser.add_argument("--asset", action="append", default=[])
    parser.add_argument("--allow-extra-assets", action="store_true")
    parser.add_argument("--required-marker")
    parser.add_argument("--skip-target-check", action="store_true")
    args = parser.parse_args()
    try:
        document = json.loads(args.release_json.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        raise RemoteReleaseError(f"release JSON could not be read: {exc}") from exc
    assets = tuple(parse_asset(item) for item in args.asset)
    if not assets:
        raise RemoteReleaseError("at least one --asset is required")
    verify_release(
        document,
        expected_tag=args.tag,
        expected_commit=args.expected_commit,
        expected_draft=args.state == "draft",
        expected_prerelease=True,
        expected_assets=assets,
        allow_extra_assets=args.allow_extra_assets,
        required_marker=args.required_marker,
        verify_target=not args.skip_target_check,
    )
    print("Remote release metadata and asset digests passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RemoteReleaseError) as error:
        print(f"remote-release: {error}", file=sys.stderr)
        sys.exit(1)
