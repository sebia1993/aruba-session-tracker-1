"""Enforce coverage floors for lifecycle-critical modules.

The global project percentage can hide untested shutdown and cancellation
branches.  This checker consumes coverage.py's Cobertura XML after pytest and
applies explicit per-module branch floors without adding another dependency.
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


class CoveragePolicyError(ValueError):
    """Raised when the coverage report does not satisfy the release policy."""


GLOBAL_LINE_FLOOR = 0.83
CRITICAL_BRANCH_FLOORS = {
    "src/aruba_session_tracker/analysis/catalog.py": 0.65,
    "src/aruba_session_tracker/analysis/offline.py": 0.65,
    "src/aruba_session_tracker/analysis/summary.py": 0.65,
    "src/aruba_session_tracker/analysis/tos.py": 0.65,
    "src/aruba_session_tracker/main.py": 0.65,
    "src/aruba_session_tracker/observability.py": 0.65,
    "src/aruba_session_tracker/runtime.py": 0.65,
    "src/aruba_session_tracker/single_instance.py": 0.65,
    "src/aruba_session_tracker/collectors/ssh.py": 0.65,
    "src/aruba_session_tracker/offline/io.py": 0.65,
    "src/aruba_session_tracker/offline/parser.py": 0.65,
    "src/aruba_session_tracker/parsers/global_users.py": 0.65,
    "src/aruba_session_tracker/services/monitoring.py": 0.65,
    "src/aruba_session_tracker/services/tracker.py": 0.65,
    "src/aruba_session_tracker/storage/html_report.py": 0.65,
    "src/aruba_session_tracker/storage/html_report_presentation.py": 0.65,
    "src/aruba_session_tracker/storage/durable_io.py": 0.65,
    "src/aruba_session_tracker/storage/session_store.py": 0.65,
    "src/aruba_session_tracker/ui/main_window.py": 0.65,
    "src/aruba_session_tracker/ui/runtime_environment.py": 0.65,
    "src/aruba_session_tracker/ui/shutdown.py": 0.65,
    "src/aruba_session_tracker/ui/startup.py": 0.65,
}


def check_coverage_policy(report: Path) -> None:
    try:
        root = ET.parse(report).getroot()  # noqa: S314 - trusted local coverage.py output
    except (ET.ParseError, OSError) as exc:
        raise CoveragePolicyError(f"coverage XML could not be read: {exc}") from exc

    try:
        global_line_rate = float(root.attrib["line-rate"])
    except (KeyError, ValueError) as exc:
        raise CoveragePolicyError("coverage XML has no valid global line-rate") from exc
    if global_line_rate < GLOBAL_LINE_FLOOR:
        raise CoveragePolicyError(
            f"global line coverage {global_line_rate:.2%} is below {GLOBAL_LINE_FLOOR:.0%}"
        )

    classes = {
        node.attrib.get("filename", "").replace("\\", "/"): node
        for node in root.findall("./packages/package/classes/class")
    }
    failures: list[str] = []
    for filename, floor in CRITICAL_BRANCH_FLOORS.items():
        node = classes.get(filename)
        if node is None:
            failures.append(f"{filename}: missing from coverage XML")
            continue
        try:
            branch_rate = float(node.attrib["branch-rate"])
        except (KeyError, ValueError):
            failures.append(f"{filename}: invalid branch-rate")
            continue
        if branch_rate < floor:
            failures.append(f"{filename}: branch coverage {branch_rate:.2%} is below {floor:.0%}")
    if failures:
        raise CoveragePolicyError("; ".join(failures))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    check_coverage_policy(args.report)
    print("Lifecycle coverage policy passed.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CoveragePolicyError as error:
        print(f"coverage-policy: {error}", file=sys.stderr)
        sys.exit(1)
