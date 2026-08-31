"""Build reviewed release notes with an exact public ZIP digest."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

if __package__:
    from .check_version import VersionError, check_version
else:
    from check_version import VersionError, check_version


_SIDECAR_PATTERN = re.compile(r"(?P<digest>[0-9a-fA-F]{64})  (?P<name>[^\r\n]+)\r?\n?\Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_release_notes(reviewed: str, zip_path: Path, sidecar_path: Path) -> str:
    """Append the single-download contract after verifying the ZIP sidecar."""

    match = _SIDECAR_PATTERN.fullmatch(sidecar_path.read_text(encoding="utf-8"))
    if match is None or match.group("name") != zip_path.name:
        raise VersionError("release ZIP SHA-256 sidecar has an invalid format or file name")
    actual_digest = _sha256(zip_path)
    if match.group("digest").lower() != actual_digest:
        raise VersionError("release ZIP does not match its SHA-256 sidecar")
    download_block = (
        "## 다운로드 및 무결성\n\n"
        f"- Windows 11 x64 실행 파일: `{zip_path.name}`\n"
        f"- SHA-256: `{actual_digest}`\n"
        "- SBOM: ZIP 내부 `ArubaSessionTracker/sbom.cdx.json`\n"
        "- Native 파일 해시 목록: ZIP 내부 "
        "`ArubaSessionTracker/THIRD_PARTY_COMPONENTS.json`\n"
        "- LGPL 대응 소스 요청·재빌드 안내: ZIP 내부 "
        "`ArubaSessionTracker/OPEN_SOURCE_SOURCE_OFFER.txt`\n"
        "- GitHub의 `Source code (zip)`과 `Source code (tar.gz)`는 자동 생성된 "
        "소스 스냅샷이며 실행 프로그램이 아닙니다.\n"
    )
    return f"{reviewed.rstrip()}\n\n{download_block}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--sha256", type=Path, required=True)
    args = parser.parse_args()
    repository = Path.cwd()
    check_version(repository, expected=args.version)
    source = repository / f"release-notes-v{args.version}.md"
    if not source.is_file():
        raise VersionError(f"reviewed release notes are missing: {source.name}")
    text = source.read_text(encoding="utf-8")
    if "TODO" in text or "[입력" in text:
        raise VersionError("release notes contain an unfinished placeholder")
    if not args.zip.is_file() or not args.sha256.is_file():
        raise VersionError("release ZIP and SHA-256 sidecar are required")
    text = build_release_notes(text, args.zip, args.sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8", newline="\n")
    print(f"Release notes generated: {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, VersionError) as error:
        print(f"release-notes: {error}", file=sys.stderr)
        sys.exit(1)
