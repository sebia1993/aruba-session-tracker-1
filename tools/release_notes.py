"""Copy the reviewed release notes for an exact synchronized version."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from check_version import VersionError, check_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repository = Path.cwd()
    check_version(repository, expected=args.version)
    source = repository / f"release-notes-v{args.version}.md"
    if not source.is_file():
        raise VersionError(f"reviewed release notes are missing: {source.name}")
    text = source.read_text(encoding="utf-8")
    if "TODO" in text or "[입력" in text:
        raise VersionError("release notes contain an unfinished placeholder")
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
