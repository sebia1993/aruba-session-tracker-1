"""Neutral Raw persistence sizing and bundle serialization contract."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol

MAX_PERSISTED_RAW_BYTES = 32 * 1024 * 1024
RAW_BUNDLE_MAGIC = b"ARUBA_SESSION_TRACKER_RAW_BUNDLE_V1\n"


class RawSnapshotLike(Protocol):
    @property
    def device_name(self) -> str: ...

    @property
    def command(self) -> str: ...

    @property
    def output(self) -> str: ...

    @property
    def observed_at(self) -> datetime: ...

    @property
    def observation_keys(self) -> tuple[str, ...] | None: ...


def raw_bundle_prefix(snapshot_count: int) -> bytes:
    if snapshot_count < 2:
        raise ValueError("Raw poll bundle requires at least two snapshots.")
    return (
        RAW_BUNDLE_MAGIC
        + json.dumps(
            {"snapshot_count": snapshot_count},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def raw_bundle_section_parts(
    snapshot: RawSnapshotLike,
    index: int,
    observation_keys: Sequence[str],
) -> tuple[bytes, bytes, bytes, bytes]:
    output = snapshot.output.encode("utf-8")
    metadata = {
        "command": snapshot.command,
        "device_name": snapshot.device_name,
        "index": index,
        "observation_keys": list(observation_keys),
        "observed_at": _iso_utc(snapshot.observed_at),
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_utf8_bytes": len(output),
    }
    return (
        f"--- BEGIN SNAPSHOT {index} ---\n".encode(),
        json.dumps(
            metadata,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n",
        output,
        f"\n--- END SNAPSHOT {index} ---\n".encode(),
    )


def persisted_raw_size(
    snapshots: Sequence[RawSnapshotLike],
    *,
    observation_keys_by_snapshot: Sequence[Sequence[str]] | None = None,
) -> int:
    """Return the exact bytes SessionStore would persist for these snapshots."""

    if observation_keys_by_snapshot is not None and len(observation_keys_by_snapshot) != len(
        snapshots
    ):
        raise ValueError("snapshot and observation-key counts differ")
    if not snapshots:
        return 0
    if len(snapshots) == 1:
        return len(snapshots[0].output.encode("utf-8"))
    total = len(raw_bundle_prefix(len(snapshots)))
    for index, snapshot in enumerate(snapshots, start=1):
        keys = (
            observation_keys_by_snapshot[index - 1]
            if observation_keys_by_snapshot is not None
            else snapshot.observation_keys or ()
        )
        total += sum(len(part) for part in raw_bundle_section_parts(snapshot, index, keys))
    return total


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("시간 값에는 timezone 정보가 필요합니다.")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
