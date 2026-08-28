"""Verify a remote annotated tag against checkout, event SHA, and current main."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


class ReleaseRefError(ValueError):
    pass


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(  # noqa: S603
        ["git", *arguments],  # noqa: S607
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        operation = arguments[0] if arguments else "unknown"
        raise ReleaseRefError(f"Git {operation} operation failed")
    return result.stdout.strip()


def _commit(repository: Path, revision: str, label: str) -> str:
    try:
        return _git(repository, "rev-parse", "--verify", f"{revision}^{{commit}}")
    except ReleaseRefError as error:
        raise ReleaseRefError(f"could not resolve {label}") from error


def verify_release_ref(tag: str, event_sha: str, repository: Path) -> str:
    if re.fullmatch(r"v\d+\.\d+\.\d+", tag) is None:
        raise ReleaseRefError("release tag must use vMAJOR.MINOR.PATCH")
    if re.fullmatch(r"[0-9a-fA-F]{40}", event_sha) is None:
        raise ReleaseRefError("event SHA must be a full hexadecimal commit")

    tag_ref = f"refs/release-verify/tags/{tag}"
    main_ref = "refs/release-verify/heads/main"
    _git(
        repository,
        "fetch",
        "--force",
        "--no-tags",
        "origin",
        f"+refs/tags/{tag}:{tag_ref}",
        f"+refs/heads/main:{main_ref}",
    )
    if _git(repository, "cat-file", "-t", tag_ref) != "tag":
        raise ReleaseRefError("release tag must be an annotated Git tag")

    commits = {
        "remote tag": _commit(repository, tag_ref, "remote tag"),
        "checkout HEAD": _commit(repository, "HEAD", "checkout HEAD"),
        "event SHA": _commit(repository, event_sha, "event SHA"),
        "remote main": _commit(repository, main_ref, "remote main"),
    }
    if len(set(commits.values())) != 1:
        details = ", ".join(f"{label}={commit[:12]}" for label, commit in commits.items())
        raise ReleaseRefError(f"release refs do not resolve to one commit: {details}")
    return commits["remote tag"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--event-sha", required=True)
    args = parser.parse_args()
    commit = verify_release_ref(args.tag, args.event_sha, Path.cwd())
    print(f"Release ref gate passed: {args.tag} -> {commit}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ReleaseRefError) as error:
        print(f"release-ref-check: {error}", file=sys.stderr)
        sys.exit(1)
