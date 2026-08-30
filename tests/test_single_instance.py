from __future__ import annotations

import os
from uuid import uuid4

import pytest

from aruba_session_tracker.single_instance import SingleInstanceGuard


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex test")
def test_single_instance_guard_blocks_duplicate_and_releases_deterministically() -> None:
    identity = f"ArubaSessionTracker-test-{uuid4().hex}"
    first = SingleInstanceGuard(identity)
    duplicate = SingleInstanceGuard(identity)

    assert first.acquire()
    assert first.acquire()
    assert not duplicate.acquire()
    duplicate.release()
    first.release()
    first.release()

    assert duplicate.acquire()
    duplicate.release()
