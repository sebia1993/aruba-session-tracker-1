from __future__ import annotations

from pathlib import Path

from tools.check_no_secrets import check


def test_secret_check_scans_extensionless_private_key(tmp_path: Path) -> None:
    marker = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"
    (tmp_path / "identity").write_bytes(marker + b"\nnot-a-real-key\n")

    assert check(tmp_path) == ["private material pattern found: identity"]


def test_secret_check_rejects_private_and_sqlite_sidecar_suffixes(tmp_path: Path) -> None:
    (tmp_path / "capture.csv").write_text("source,destination\n", encoding="utf-8")
    (tmp_path / "session.db-wal").write_bytes(b"runtime state")
    (tmp_path / "client.pem").write_bytes(b"certificate material")

    problems = check(tmp_path)

    assert "private/runtime data file is not allowed: capture.csv" in problems
    assert "private/runtime data file is not allowed: client.pem" in problems
    assert "private/runtime data file is not allowed: session.db-wal" in problems


def test_secret_check_detects_sqlite_magic_without_database_suffix(tmp_path: Path) -> None:
    (tmp_path / "history").write_bytes(b"SQLite format 3\x00" + bytes(3 * 1024 * 1024))

    assert check(tmp_path) == ["SQLite database content found: history"]


def test_secret_check_does_not_treat_binary_parser_marker_as_a_key(tmp_path: Path) -> None:
    marker = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----"
    (tmp_path / "library.bin").write_bytes(b"MZ\x00" + bytes(8192) + marker)

    assert check(tmp_path) == []
