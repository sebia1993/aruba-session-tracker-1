"""Apply the one-time Dark NOC Console payload on the design branch."""

from __future__ import annotations

import base64
import hashlib
import json
import lzma
from pathlib import Path

_EXPECTED_SHA256 = "c63d6b673a17b7718c2610d64655b2ac96fc4889a82038f285dd61ba4cb73e2a"


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    payload_dir = root / "tools" / ".dark_noc_payload"
    parts = sorted(payload_dir.glob("part*.txt"))
    if not parts:
        raise RuntimeError("Dark NOC payload parts are missing.")
    encoded = "".join(part.read_text(encoding="ascii").strip() for part in parts)
    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    if digest != _EXPECTED_SHA256:
        raise RuntimeError(f"Dark NOC payload integrity mismatch: {digest}")
    packed = base64.b64decode(encoded, validate=True)
    manifest = json.loads(lzma.decompress(packed).decode("utf-8"))
    if not isinstance(manifest, dict):
        raise TypeError("Dark NOC payload manifest is not a mapping.")
    for relative_path, encoded_content in manifest.items():
        if not isinstance(relative_path, str) or not isinstance(encoded_content, str):
            raise TypeError("Dark NOC payload contains an invalid entry.")
        destination = (root / relative_path).resolve()
        destination.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(base64.b64decode(encoded_content, validate=True))
        print(f"Applied {relative_path}")


if __name__ == "__main__":
    main()
