from __future__ import annotations

from pathlib import Path

import pytest

from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.offline import (
    OfflineParseLimits,
    parse_offline_tech_support_file,
)
from aruba_session_tracker.parsers import ParseError

FIXTURE = Path(__file__).parent / "fixtures" / "offline_tech_support_valid.txt"


def test_korean_path_file_is_read_locally_without_storing_its_path(tmp_path: Path) -> None:
    source = tmp_path / "장애 자료" / "기술지원 로그.txt"
    source.parent.mkdir()
    source.write_bytes(b"\xef\xbb\xbf" + FIXTURE.read_bytes())

    result = parse_offline_tech_support_file(source)

    assert len(result.sessions) == 2
    assert not hasattr(result, "source_path")
    assert str(source) not in repr(result)


def test_file_reader_rejects_invalid_utf8_without_echoing_path_or_bytes(tmp_path: Path) -> None:
    source = tmp_path / "secret-device-name.log"
    source.write_bytes(b"\xff\xfePRIVATE-CONTENT")

    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support_file(source)

    message = str(caught.value)
    assert "secret-device-name" not in message
    assert "PRIVATE-CONTENT" not in message
    assert "UTF-8" in message
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_file_reader_enforces_byte_limit_before_parsing(tmp_path: Path) -> None:
    source = tmp_path / "bounded.log"
    source.write_bytes(FIXTURE.read_bytes())

    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support_file(
            source,
            limits=OfflineParseLimits(max_text_bytes=100),
        )

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_file_reader_supports_cooperative_cancellation(tmp_path: Path) -> None:
    source = tmp_path / "cancel.log"
    source.write_bytes(FIXTURE.read_bytes())

    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support_file(source, is_cancelled=lambda: True)

    assert caught.value.code is ErrorCode.CANCELLED
    assert str(source) not in str(caught.value)


def test_file_reader_validates_public_arguments(tmp_path: Path) -> None:
    with pytest.raises(TypeError):
        parse_offline_tech_support_file(123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        parse_offline_tech_support_file(tmp_path / "missing.log", is_cancelled=True)  # type: ignore[arg-type]


def test_missing_file_error_is_sanitized(tmp_path: Path) -> None:
    source = tmp_path / "sensitive-hostname.log"

    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support_file(source)

    assert "sensitive-hostname" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
