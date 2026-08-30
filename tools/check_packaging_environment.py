"""Fail if a PyInstaller child can see build-host injection variables."""

from __future__ import annotations

import argparse
import os
import sys

INJECTION_VARIABLES = (
    "CONDA_PREFIX",
    "PYTHONHOME",
    "PYTHONPATH",
    "QML2_IMPORT_PATH",
    "QT_PLUGIN_PATH",
    "QT_QPA_PLATFORM_PLUGIN_PATH",
    "VIRTUAL_ENV",
)


def _normalized_path(value: str) -> str:
    return os.path.normcase(os.path.abspath(value)).casefold()


def check_environment(allowed_paths: tuple[str, ...]) -> tuple[str, ...]:
    problems = [name for name in INJECTION_VARIABLES if name in os.environ]
    allowed = {_normalized_path(value) for value in allowed_paths}
    actual = {
        _normalized_path(value) for value in os.environ.get("PATH", "").split(os.pathsep) if value
    }
    unexpected = sorted(actual - allowed)
    if unexpected:
        problems.append(f"PATH:{unexpected[0]}")
    if not actual or not actual.issubset(allowed):
        return tuple(problems)
    return tuple(problems)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowed-path", action="append", required=True)
    args = parser.parse_args()
    problems = check_environment(tuple(args.allowed_path))
    if problems:
        print(f"packaging-environment: host injection is visible: {problems[0]}", file=sys.stderr)
        return 1
    print("PACKAGING_CHILD_ENVIRONMENT_ISOLATED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
