from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = tuple(sorted((ROOT / ".github" / "workflows").glob("*.yml")))
APPROVED_ACTIONS = {
    "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7.0.1"),
    "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7.0.0"),
    "actions/upload-artifact": ("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", "v7.0.1"),
    "actions/download-artifact": ("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", "v8.0.1"),
}
ACTION_LINE = re.compile(
    r"^\s*uses:\s+(?P<name>actions/[a-z-]+)@(?P<sha>[0-9a-f]{40})\s+#\s+(?P<tag>v\d+\.\d+\.\d+)\s*$"
)


def test_first_party_actions_are_immutable_and_node24_compatible() -> None:
    seen: set[str] = set()
    for workflow in WORKFLOWS:
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if "uses: actions/" not in line:
                continue
            match = ACTION_LINE.match(line)
            assert match is not None, f"unversioned or unlabelled action in {workflow.name}: {line}"
            name = match.group("name")
            assert name in APPROVED_ACTIONS, f"unreviewed first-party action: {name}"
            assert (match.group("sha"), match.group("tag")) == APPROVED_ACTIONS[name]
            seen.add(name)

    assert seen == set(APPROVED_ACTIONS)
