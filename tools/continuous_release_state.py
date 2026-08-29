"""Pure continuous-release reconciliation and durable marker helpers."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

PRODUCT = "ArubaSessionTracker"
OWNER_PATTERN = re.compile(r"<!-- aruba-session-tracker-continuous:(?P<commit>[0-9a-fA-F]{40}) -->")
STATE_PATTERN = re.compile(
    r"<!-- aruba-session-tracker-continuous-state:(?P<payload>\{[^\r\n]*\}) -->"
)
ZIP_PATTERN = re.compile(rf"^{PRODUCT}_v(?P<version>\d+\.\d+\.\d+)_windows_x64\.zip$")
CANONICAL_ASSET_PATTERN = re.compile(
    rf"^{PRODUCT}_v\d+\.\d+\.\d+_"
    r"(?:windows_x64\.zip(?:\.sha256)?|sbom\.cdx\.json)$"
)
TEMPORARY_ASSET_PATTERN = re.compile(
    rf"^(?:previous-\d+|candidate-[0-9a-fA-F]{{12}})--{PRODUCT}_v"
    r"\d+\.\d+\.\d+_(?:windows_x64\.zip(?:\.sha256)?|sbom\.cdx\.json)$"
)


class ContinuousReleaseStateError(ValueError):
    """Raised when a moving release cannot be reconciled without guessing."""


class Stage(StrEnum):
    STAGING = "staging"
    ASSETS_VERIFIED = "assets_verified"
    READY = "ready"


class Action(StrEnum):
    CREATE_DRAFT = "create_draft"
    VALIDATE_LEGACY = "validate_legacy"
    HIDE_AND_MARK_STAGING = "hide_and_mark_staging"
    MARK_STAGING = "mark_staging"
    REPLACE_ASSETS = "replace_assets"
    VERIFY_DRAFT_DOWNLOAD = "verify_draft_download"
    MARK_ASSETS_VERIFIED = "mark_assets_verified"
    ALIGN_TAG = "align_tag"
    MARK_READY = "mark_ready"
    PUBLISH = "publish"
    VERIFY_PUBLIC = "verify_public"
    DONE = "done"


@dataclass(frozen=True, slots=True)
class DesiredRelease:
    commit: str
    zip_name: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.commit, str):
            raise ContinuousReleaseStateError("continuous commit must be text")
        if not isinstance(self.zip_name, str):
            raise ContinuousReleaseStateError("continuous ZIP name must be text")
        if not isinstance(self.sha256, str):
            raise ContinuousReleaseStateError("continuous ZIP digest must be text")
        if type(self.size) is not int:
            raise ContinuousReleaseStateError("continuous ZIP size must be an integer")
        if re.fullmatch(r"[0-9a-fA-F]{40}", self.commit) is None:
            raise ContinuousReleaseStateError("continuous commit is not a full Git SHA")
        if ZIP_PATTERN.fullmatch(self.zip_name) is None:
            raise ContinuousReleaseStateError("continuous ZIP name is not canonical")
        if re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256) is None:
            raise ContinuousReleaseStateError("continuous ZIP digest is not SHA-256")
        if self.size <= 0:
            raise ContinuousReleaseStateError("continuous ZIP size must be positive")


@dataclass(frozen=True, slots=True)
class DurableState:
    stage: Stage
    desired: DesiredRelease


@dataclass(frozen=True, slots=True)
class AssetEvidence:
    name: str
    size: int
    digest: str


@dataclass(frozen=True, slots=True)
class ReleaseSnapshot:
    draft: bool
    prerelease: bool
    title: str
    body: str
    target_commitish: str
    tag_commit: str | None
    assets: tuple[AssetEvidence, ...]
    tag_name: str = "continuous"


@dataclass(frozen=True, slots=True)
class ReleaseSelection:
    keeper_id: int
    cleanup_ids: tuple[int, ...]
    cleanup_asset_ids: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class AssetContract:
    kind: str
    version: str
    zip_name: str
    sidecar_name: str | None = None
    sbom_name: str | None = None


def render_body(notes: str, state: DurableState) -> str:
    """Return release notes with exactly one ownership and durable-state marker."""

    cleaned = OWNER_PATTERN.sub("", notes)
    cleaned = STATE_PATTERN.sub("", cleaned).rstrip()
    desired = state.desired
    required_digest_line = f"SHA-256: `{desired.sha256.lower()}`"
    if required_digest_line not in cleaned:
        raise ContinuousReleaseStateError(
            "release notes do not contain the exact verified public ZIP SHA-256 line"
        )
    payload = json.dumps(
        {
            "commit": desired.commit.lower(),
            "schema": 1,
            "sha256": desired.sha256.lower(),
            "size": desired.size,
            "stage": state.stage.value,
            "zip": desired.zip_name,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    owner = f"<!-- aruba-session-tracker-continuous:{desired.commit.lower()} -->"
    marker = f"<!-- aruba-session-tracker-continuous-state:{payload} -->"
    return f"{cleaned}\n\n{owner}\n{marker}\n"


def parse_state(body: str) -> DurableState | None:
    matches = tuple(STATE_PATTERN.finditer(body))
    if not matches:
        return None
    if len(matches) != 1:
        raise ContinuousReleaseStateError("continuous release has duplicate durable markers")
    try:
        payload = json.loads(matches[0].group("payload"))
    except json.JSONDecodeError as exc:
        raise ContinuousReleaseStateError("continuous durable marker is invalid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "commit",
        "schema",
        "sha256",
        "size",
        "stage",
        "zip",
    }:
        raise ContinuousReleaseStateError("continuous durable marker has an invalid schema")
    if type(payload["schema"]) is not int or payload["schema"] != 1:
        raise ContinuousReleaseStateError("continuous durable marker schema is unsupported")
    if (
        not all(isinstance(payload[field], str) for field in ("commit", "sha256", "stage", "zip"))
        or type(payload["size"]) is not int
    ):
        raise ContinuousReleaseStateError("continuous durable marker values are invalid")
    try:
        stage = Stage(payload["stage"])
        desired = DesiredRelease(
            commit=payload["commit"],
            zip_name=payload["zip"],
            sha256=payload["sha256"],
            size=payload["size"],
        )
    except (TypeError, ValueError) as exc:
        raise ContinuousReleaseStateError("continuous durable marker values are invalid") from exc
    owner_matches = tuple(OWNER_PATTERN.finditer(body))
    owner_matches_state = (
        len(owner_matches) == 1
        and owner_matches[0].group("commit").casefold() == desired.commit.casefold()
    )
    if not owner_matches_state:
        raise ContinuousReleaseStateError(
            "continuous ownership marker does not match the durable commit"
        )
    return DurableState(stage=stage, desired=desired)


def has_legacy_ownership(body: str) -> bool:
    return len(tuple(OWNER_PATTERN.finditer(body))) == 1


def classify_asset_names(names: tuple[str, ...]) -> AssetContract:
    """Accept only one canonical ZIP or a same-version legacy trio."""

    if len(names) != len(set(names)):
        raise ContinuousReleaseStateError("continuous release has duplicate asset names")
    if len(names) == 1:
        match = ZIP_PATTERN.fullmatch(names[0])
        if match is None:
            raise ContinuousReleaseStateError(
                "continuous release does not contain one canonical ZIP"
            )
        return AssetContract("single_zip", match.group("version"), names[0])
    if len(names) == 3:
        zip_names = tuple(name for name in names if ZIP_PATTERN.fullmatch(name))
        if len(zip_names) != 1:
            raise ContinuousReleaseStateError("legacy continuous release has no unique ZIP")
        zip_name = zip_names[0]
        version = ZIP_PATTERN.fullmatch(zip_name).group("version")  # type: ignore[union-attr]
        sidecar_name = f"{zip_name}.sha256"
        sbom_name = f"{PRODUCT}_v{version}_sbom.cdx.json"
        if set(names) != {zip_name, sidecar_name, sbom_name}:
            raise ContinuousReleaseStateError(
                "legacy continuous assets do not form one same-version trio"
            )
        return AssetContract("legacy_trio", version, zip_name, sidecar_name, sbom_name)
    raise ContinuousReleaseStateError(
        "continuous release must contain one ZIP or the same-version legacy trio"
    )


def validate_owned_asset_names(names: tuple[str, ...], *, draft: bool) -> None:
    """Reject deletion of any asset not owned by the continuous workflow."""

    if not draft:
        classify_asset_names(names)
        return
    for name in names:
        if (
            CANONICAL_ASSET_PATTERN.fullmatch(name) is None
            and TEMPORARY_ASSET_PATTERN.fullmatch(name) is None
        ):
            raise ContinuousReleaseStateError(
                f"workflow-owned draft contains an unexpected asset: {name}"
            )


def validate_legacy_files(zip_path: Path, sidecar_path: Path, sbom_path: Path) -> None:
    contract = classify_asset_names((zip_path.name, sidecar_path.name, sbom_path.name))
    if contract.kind != "legacy_trio":
        raise ContinuousReleaseStateError("legacy validation requires the exact legacy trio")
    text = sidecar_path.read_text(encoding="utf-8")
    sidecar_pattern = re.compile(
        rf"\A(?P<digest>[0-9a-fA-F]{{64}})  {re.escape(zip_path.name)}\r?\n?\Z"
    )
    match = sidecar_pattern.fullmatch(text)
    actual = _sha256(zip_path)
    if match is None or match.group("digest").casefold() != actual:
        raise ContinuousReleaseStateError("legacy sidecar does not match the legacy ZIP")
    try:
        document = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContinuousReleaseStateError("legacy SBOM is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise ContinuousReleaseStateError("legacy SBOM is not CycloneDX")


def snapshot_from_document(document: dict[str, Any], *, tag_commit: str | None) -> ReleaseSnapshot:
    if type(document.get("draft")) is not bool or type(document.get("prerelease")) is not bool:
        raise ContinuousReleaseStateError("continuous release state metadata is malformed")
    text_fields = ("name", "body", "target_commitish", "tag_name")
    if not all(isinstance(document.get(field), str) for field in text_fields):
        raise ContinuousReleaseStateError("continuous release text metadata is malformed")
    if tag_commit is not None and re.fullmatch(r"[0-9a-fA-F]{40}", tag_commit) is None:
        raise ContinuousReleaseStateError("continuous tag commit is not a full Git SHA")
    raw_assets = document.get("assets")
    if not isinstance(raw_assets, list):
        raise ContinuousReleaseStateError("continuous release assets are missing")
    assets: list[AssetEvidence] = []
    for item in raw_assets:
        if not isinstance(item, dict):
            raise ContinuousReleaseStateError("continuous release asset metadata is malformed")
        name = item.get("name")
        size = item.get("size")
        raw_digest = item.get("digest")
        if (
            not isinstance(name, str)
            or type(size) is not int
            or size <= 0
            or not isinstance(raw_digest, str)
        ):
            raise ContinuousReleaseStateError("continuous release asset metadata is malformed")
        digest = raw_digest.casefold()
        if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise ContinuousReleaseStateError("continuous release asset digest is unavailable")
        assets.append(AssetEvidence(name=name, size=size, digest=digest))
    return ReleaseSnapshot(
        draft=document["draft"],
        prerelease=document["prerelease"],
        title=document["name"],
        body=document["body"],
        target_commitish=document["target_commitish"],
        tag_commit=tag_commit,
        assets=tuple(assets),
        tag_name=document["tag_name"],
    )


def select_release_candidates(documents: list[dict[str, Any]]) -> ReleaseSelection:
    """Choose one owned continuous release and only disposable empty duplicates."""

    if not documents:
        raise ContinuousReleaseStateError("continuous release candidates are empty")
    candidates: list[tuple[int, ReleaseSnapshot, str | None]] = []
    cleanup_asset_ids: list[int] = []
    seen_ids: set[int] = set()
    for document in documents:
        if not isinstance(document, dict):
            raise ContinuousReleaseStateError("continuous release candidate is not an object")
        release_id = document.get("id")
        published_at = document.get("published_at")
        if type(release_id) is not int or release_id <= 0 or release_id in seen_ids:
            raise ContinuousReleaseStateError("continuous release id is invalid or duplicated")
        if published_at is not None and (
            not isinstance(published_at, str) or not published_at.strip()
        ):
            raise ContinuousReleaseStateError("continuous published timestamp is malformed")
        seen_ids.add(release_id)
        if not isinstance(document.get("body"), str) or not has_legacy_ownership(document["body"]):
            raise ContinuousReleaseStateError("continuous release candidate is not workflow-owned")
        raw_assets = document.get("assets")
        if not isinstance(raw_assets, list):
            raise ContinuousReleaseStateError("continuous release assets are missing")
        retained_assets: list[dict[str, Any]] = []
        for asset in raw_assets:
            if not isinstance(asset, dict):
                raise ContinuousReleaseStateError("continuous release asset metadata is malformed")
            if asset.get("state") != "starter":
                retained_assets.append(asset)
                continue
            name = asset.get("name")
            asset_id = asset.get("id")
            if (
                document.get("draft") is not True
                or not isinstance(name, str)
                or (
                    CANONICAL_ASSET_PATTERN.fullmatch(name) is None
                    and TEMPORARY_ASSET_PATTERN.fullmatch(name) is None
                )
                or type(asset_id) is not int
                or asset_id <= 0
                or asset.get("size") != 0
                or asset.get("digest") is not None
            ):
                raise ContinuousReleaseStateError(
                    "starter asset is not a disposable owned draft upload"
                )
            cleanup_asset_ids.append(asset_id)
        sanitized = {**document, "assets": retained_assets}
        snapshot = snapshot_from_document(sanitized, tag_commit=None)
        if snapshot.tag_name != "continuous" or not snapshot.prerelease:
            raise ContinuousReleaseStateError("continuous release candidate is not a prerelease")
        validate_owned_asset_names(
            tuple(asset.name for asset in snapshot.assets),
            draft=snapshot.draft,
        )
        candidates.append((release_id, snapshot, published_at))

    published = tuple(item for item in candidates if not item[1].draft)
    if len(published) > 1:
        raise ContinuousReleaseStateError("multiple published continuous releases exist")
    if published:
        keeper = published[0]
    else:
        historical = tuple(item for item in candidates if item[2] is not None)
        if len(historical) > 1:
            raise ContinuousReleaseStateError(
                "multiple previously published continuous drafts exist"
            )
        if historical:
            keeper = historical[0]
        else:
            non_empty = tuple(item for item in candidates if item[1].assets)
            if len(non_empty) > 1:
                raise ContinuousReleaseStateError("multiple non-empty continuous drafts exist")
            keeper = non_empty[0] if non_empty else min(candidates, key=lambda item: item[0])

    cleanup: list[int] = []
    for release_id, snapshot, published_at in candidates:
        if release_id == keeper[0]:
            continue
        if not snapshot.draft or snapshot.assets or published_at is not None:
            raise ContinuousReleaseStateError(
                "duplicate continuous release is not an empty unpublished draft"
            )
        if parse_state(snapshot.body) is None:
            raise ContinuousReleaseStateError(
                "duplicate continuous draft has no durable state marker"
            )
        cleanup.append(release_id)
    if len(cleanup_asset_ids) != len(set(cleanup_asset_ids)):
        raise ContinuousReleaseStateError("starter asset id is duplicated")
    return ReleaseSelection(
        keeper_id=keeper[0],
        cleanup_ids=tuple(sorted(cleanup)),
        cleanup_asset_ids=tuple(sorted(cleanup_asset_ids)),
    )


def next_action(
    snapshot: ReleaseSnapshot | None,
    desired: DesiredRelease,
    *,
    legacy_validated: bool = False,
    authenticated: bool = False,
    public_verified: bool = False,
) -> Action:
    """Return the next idempotent action for a forward-only reconciliation."""

    if snapshot is None:
        return Action.CREATE_DRAFT
    if not snapshot.prerelease:
        raise ContinuousReleaseStateError("continuous release is not a prerelease")
    if snapshot.tag_name != "continuous":
        raise ContinuousReleaseStateError("continuous release has an unexpected tag name")
    if not has_legacy_ownership(snapshot.body):
        raise ContinuousReleaseStateError("continuous release is not workflow-owned")
    state = parse_state(snapshot.body)
    names = tuple(asset.name for asset in snapshot.assets)
    validate_owned_asset_names(names, draft=snapshot.draft)
    exact_asset = _has_exact_asset(snapshot.assets, desired)
    tag_matches = snapshot.tag_commit is not None and _same(snapshot.tag_commit, desired.commit)
    target_matches = _same(snapshot.target_commitish, desired.commit)

    if not snapshot.draft:
        contract = classify_asset_names(names)
        if state is not None and state.stage is Stage.READY:
            if not _same_desired(state.desired, _desired_from_snapshot(state, snapshot)):
                raise ContinuousReleaseStateError(
                    "published ready marker does not match its public ZIP"
                )
            if snapshot.tag_commit is None or not _same(snapshot.tag_commit, state.desired.commit):
                raise ContinuousReleaseStateError(
                    "published ready marker does not match the continuous tag"
                )
            if not _same(snapshot.target_commitish, state.desired.commit):
                raise ContinuousReleaseStateError(
                    "published ready marker does not match the release target"
                )
        if state is not None and state.stage is not Stage.READY:
            return Action.HIDE_AND_MARK_STAGING
        already_desired = (
            state is not None
            and _same_desired(state.desired, desired)
            and exact_asset
            and tag_matches
        )
        if already_desired:
            return Action.DONE if public_verified else Action.VERIFY_PUBLIC
        if contract.kind == "legacy_trio" and not legacy_validated:
            return Action.VALIDATE_LEGACY
        return Action.HIDE_AND_MARK_STAGING

    if state is None or not _same_desired(state.desired, desired):
        return Action.MARK_STAGING
    if not target_matches:
        return Action.MARK_STAGING
    if state.stage is Stage.STAGING:
        if not exact_asset:
            return Action.REPLACE_ASSETS
        return Action.MARK_ASSETS_VERIFIED if authenticated else Action.VERIFY_DRAFT_DOWNLOAD
    if not exact_asset:
        return Action.MARK_STAGING
    if state.stage is Stage.ASSETS_VERIFIED:
        return Action.MARK_READY if tag_matches else Action.ALIGN_TAG
    if not tag_matches:
        return Action.ALIGN_TAG
    return Action.PUBLISH


def verify_rollback(actual: ReleaseSnapshot, expected: ReleaseSnapshot) -> None:
    """Verify the observable release contract restored by same-run rollback."""

    if actual != expected:
        raise ContinuousReleaseStateError(
            "restored continuous release is not the exact prior state"
        )


def _desired_from_snapshot(state: DurableState, snapshot: ReleaseSnapshot) -> DesiredRelease:
    match = tuple(asset for asset in snapshot.assets if asset.name == state.desired.zip_name)
    if len(match) != 1:
        raise ContinuousReleaseStateError("published ready ZIP is missing")
    digest = match[0].digest.removeprefix("sha256:")
    return DesiredRelease(state.desired.commit, match[0].name, digest, match[0].size)


def _has_exact_asset(assets: tuple[AssetEvidence, ...], desired: DesiredRelease) -> bool:
    return assets == (
        AssetEvidence(desired.zip_name, desired.size, f"sha256:{desired.sha256.casefold()}"),
    )


def _same(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()


def _same_desired(left: DesiredRelease, right: DesiredRelease) -> bool:
    return (
        _same(left.commit, right.commit)
        and left.zip_name == right.zip_name
        and _same(left.sha256, right.sha256)
        and left.size == right.size
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _desired_from_args(args: argparse.Namespace) -> DesiredRelease:
    return DesiredRelease(args.commit, args.zip_name, args.sha256, args.size)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    body = subparsers.add_parser("body")
    body.add_argument("--notes", type=Path, required=True)
    body.add_argument("--output", type=Path, required=True)
    body.add_argument("--stage", choices=tuple(Stage), required=True)
    _add_desired_arguments(body)

    legacy = subparsers.add_parser("validate-legacy")
    legacy.add_argument("--zip", type=Path, required=True)
    legacy.add_argument("--sha256-file", type=Path, required=True)
    legacy.add_argument("--sbom", type=Path, required=True)

    select = subparsers.add_parser("select-release")
    select.add_argument("--releases-json", type=Path, required=True)

    action = subparsers.add_parser("action")
    action.add_argument("--release-json", type=Path)
    action.add_argument("--tag-commit")
    action.add_argument("--legacy-validated", action="store_true")
    action.add_argument("--authenticated", action="store_true")
    action.add_argument("--public-verified", action="store_true")
    _add_desired_arguments(action)

    args = parser.parse_args()
    if args.command == "body":
        desired = _desired_from_args(args)
        state = DurableState(Stage(args.stage), desired)
        rendered = render_body(args.notes.read_text(encoding="utf-8"), state)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
        return 0
    if args.command == "validate-legacy":
        validate_legacy_files(args.zip, args.sha256_file, args.sbom)
        return 0
    if args.command == "select-release":
        document = json.loads(args.releases_json.read_text(encoding="utf-8-sig"))
        if not isinstance(document, list) or not all(isinstance(item, dict) for item in document):
            raise ContinuousReleaseStateError("release candidate JSON is not an object list")
        selection = select_release_candidates(document)
        print(
            json.dumps(
                {
                    "cleanup_asset_ids": selection.cleanup_asset_ids,
                    "cleanup_ids": selection.cleanup_ids,
                    "keeper_id": selection.keeper_id,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    desired = _desired_from_args(args)
    snapshot = None
    if args.release_json is not None:
        document = json.loads(args.release_json.read_text(encoding="utf-8-sig"))
        if document is not None:
            if not isinstance(document, dict):
                raise ContinuousReleaseStateError("release JSON is not an object")
            snapshot = snapshot_from_document(document, tag_commit=args.tag_commit)
    print(
        next_action(
            snapshot,
            desired,
            legacy_validated=args.legacy_validated,
            authenticated=args.authenticated,
            public_verified=args.public_verified,
        ).value
    )
    return 0


def _add_desired_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--commit", required=True)
    parser.add_argument("--zip-name", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--size", type=int, required=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ContinuousReleaseStateError, OSError, json.JSONDecodeError) as exc:
        print(f"continuous-release-state: {exc}", file=sys.stderr)
        sys.exit(1)
