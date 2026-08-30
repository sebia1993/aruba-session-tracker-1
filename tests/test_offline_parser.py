from __future__ import annotations

import re
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.offline import (
    DATAPATH_INTERNAL_COMMAND,
    OfflineEnrichment,
    OfflineEnrichmentStatus,
    OfflineParseLimits,
    OfflineStationRecord,
    OfflineUserRecord,
    extract_exact_command_block,
    parse_offline_tech_support,
)
from aruba_session_tracker.parsers import ParseError

FIXTURES = Path(__file__).parent / "fixtures"
UNSPECIFIED_TEST_IP = "0.0.0.0"  # noqa: S104 - parser data, never a bind address


def fixture() -> str:
    return (FIXTURES / "offline_tech_support_valid.txt").read_text(encoding="utf-8")


def _datapath_only(*, include_count: bool = True) -> str:
    lines = fixture().splitlines()
    end = lines.index("show user-table verbose")
    selected = lines[:end]
    if not include_count:
        selected.remove("Entries: 2")
    return "\n".join(selected)


def _replace_datapath_field(text: str, row_prefix: str, column: int, value: str) -> str:
    lines = text.splitlines()
    separator_index = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("----------------- ---------------")
    )
    boundaries = [
        (match.start(), match.end()) for match in re.finditer(r"-+", lines[separator_index])
    ]
    start, end = boundaries[column]
    if len(value) > end - start:
        raise ValueError("replacement does not fit fixture column")
    row_index = next(index for index, line in enumerate(lines) if line.startswith(row_prefix))
    row = lines[row_index].ljust(end)
    lines[row_index] = f"{row[:start]}{value.ljust(end - start)}{row[end:]}".rstrip()
    return "\n".join(lines)


def _user_row(ip_address: str, mac_address: str, name: str, role: str) -> str:
    return f"{ip_address:<15} {mac_address:<17} {name:<12} {role:<10}".rstrip()


def _station_row(mac_address: str, name: str, role: str) -> str:
    return f"{mac_address:<17} {name:<12} {role:<10}".rstrip()


def test_offline_parser_maps_valid_ipv4_rows_without_controller_identity() -> None:
    result = parse_offline_tech_support(fixture())

    assert len(result.sessions) == 2
    first = result.sessions[0]
    assert first.source_ip == "192.0.2.10"
    assert first.destination_ip == "198.51.100.20"
    assert first.protocol == 6
    assert first.source_port == 54321
    assert first.destination_port == 443
    assert first.tunnel_age == 10
    assert first.packets == 16
    assert first.bytes_count == 2048
    assert first.application_id == "https (443)"
    assert first.webcc_id == "Not-Classified (0)"
    assert first.cpu_id == 1
    assert first.session_key == "6|192.0.2.10|198.51.100.20|54321|443"
    assert not hasattr(first, "controller_host")
    assert not hasattr(first, "raw_line")


def test_offline_parser_returns_records_and_compatible_membership() -> None:
    result = parse_offline_tech_support(fixture())

    assert result.enrichment.user_table_status is OfflineEnrichmentStatus.VALIDATED
    assert result.enrichment.station_table_status is OfflineEnrichmentStatus.VALIDATED
    assert result.enrichment.user_ips == frozenset({"192.0.2.10"})
    assert result.enrichment.user_macs == frozenset({"00:00:5e:00:53:01"})
    assert result.enrichment.station_macs == frozenset({"00:00:5e:00:53:02"})
    assert result.enrichment.user_records == (
        OfflineUserRecord(
            ip_address="192.0.2.10",
            mac_address="00:00:5e:00:53:01",
            name="sample-user",
            role="employee",
        ),
    )
    assert result.enrichment.station_records == (
        OfflineStationRecord(
            mac_address="00:00:5e:00:53:02",
            name="sample-ap",
            role="station",
        ),
    )
    assert "sample-user" not in repr(result)
    assert "sample-ap" not in repr(result)


def test_offline_models_are_immutable_and_hide_sensitive_repr() -> None:
    result = parse_offline_tech_support(fixture())

    with pytest.raises(FrozenInstanceError):
        result.sessions[0].source_ip = "203.0.113.1"  # type: ignore[misc]
    assert "192.0.2.10" not in repr(result.sessions[0])
    with pytest.raises(FrozenInstanceError):
        result.enrichment.user_records[0].name = "changed"  # type: ignore[misc]
    for sensitive_value in (
        "192.0.2.10",
        "00:00:5e:00:53:01",
        "sample-user",
        "employee",
        "00:00:5e:00:53:02",
        "sample-ap",
        "station",
    ):
        assert sensitive_value not in repr(result.enrichment)
        assert sensitive_value not in repr(result.enrichment.user_records[0])
        assert sensitive_value not in repr(result.enrichment.station_records[0])


def test_legacy_enrichment_fields_and_positional_statuses_remain_compatible() -> None:
    enrichment = OfflineEnrichment(
        frozenset({"192.0.2.10"}),
        frozenset({"00:00:5e:00:53:01"}),
        frozenset({"00:00:5e:00:53:02"}),
        OfflineEnrichmentStatus.VALIDATED,
        OfflineEnrichmentStatus.UNAVAILABLE,
    )

    assert enrichment.user_ips == frozenset({"192.0.2.10"})
    assert enrichment.user_macs == frozenset({"00:00:5e:00:53:01"})
    assert enrichment.station_macs == frozenset({"00:00:5e:00:53:02"})
    assert enrichment.user_table_status is OfflineEnrichmentStatus.VALIDATED
    assert enrichment.station_table_status is OfflineEnrichmentStatus.UNAVAILABLE
    assert enrichment.user_records == ()
    assert enrichment.station_records == ()


def test_enrichment_records_preserve_row_relationships_and_order() -> None:
    original_user = _user_row("192.0.2.10", "00:00:5e:00:53:01", "sample-user", "employee")
    second_user = _user_row(UNSPECIFIED_TEST_IP, "00:00:5e:00:53:01", "second-user", "guest")
    original_station = _station_row("00:00:5e:00:53:02", "sample-ap", "station")
    second_station = _station_row("00:00:5e:00:53:02", "backup-ap", "standby")
    text = (
        fixture()
        .replace(original_user, f"{original_user}\n{second_user}", 1)
        .replace("User Entries: 1/1", "User Entries: 2/2", 1)
        .replace(original_station, f"{original_station}\n{second_station}", 1)
        .replace("Station Entries: 1", "Station Entries: 2", 1)
    )

    enrichment = parse_offline_tech_support(text).enrichment

    assert enrichment.user_records == (
        OfflineUserRecord(
            ip_address="192.0.2.10",
            mac_address="00:00:5e:00:53:01",
            name="sample-user",
            role="employee",
        ),
        OfflineUserRecord(
            ip_address=UNSPECIFIED_TEST_IP,
            mac_address="00:00:5e:00:53:01",
            name="second-user",
            role="guest",
        ),
    )
    assert enrichment.station_records == (
        OfflineStationRecord(
            mac_address="00:00:5e:00:53:02",
            name="sample-ap",
            role="station",
        ),
        OfflineStationRecord(
            mac_address="00:00:5e:00:53:02",
            name="backup-ap",
            role="standby",
        ),
    )
    assert enrichment.user_ips == frozenset({"192.0.2.10"})
    assert enrichment.user_macs == frozenset({"00:00:5e:00:53:01"})
    assert enrichment.station_macs == frozenset({"00:00:5e:00:53:02"})


@pytest.mark.parametrize(
    ("old_row", "unsafe_row", "records_attribute"),
    [
        (
            _user_row("192.0.2.10", "00:00:5e:00:53:01", "sample-user", "employee"),
            _user_row("192.0.2.10", "00:00:5e:00:53:01", "<b>bad</b>", "employee"),
            "user_records",
        ),
        (
            _station_row("00:00:5e:00:53:02", "sample-ap", "station"),
            _station_row("00:00:5e:00:53:02", "<b>bad</b>", "station"),
            "station_records",
        ),
    ],
)
def test_optional_enrichment_html_like_fields_fail_closed(
    old_row: str, unsafe_row: str, records_attribute: str
) -> None:
    enrichment = parse_offline_tech_support(fixture().replace(old_row, unsafe_row, 1)).enrichment

    assert getattr(enrichment, records_attribute) == ()
    if records_attribute == "user_records":
        assert enrichment.user_table_status is OfflineEnrichmentStatus.UNAVAILABLE
        assert enrichment.user_ips == frozenset()
        assert enrichment.user_macs == frozenset()
    else:
        assert enrichment.station_table_status is OfflineEnrichmentStatus.UNAVAILABLE
        assert enrichment.station_macs == frozenset()


def test_exact_command_extraction_accepts_crlf_and_safe_aruba_prompt() -> None:
    text = (
        fixture()
        .replace(
            DATAPATH_INTERNAL_COMMAND,
            f"(document-host) [node] #{DATAPATH_INTERNAL_COMMAND}",
            1,
        )
        .replace("\n", "\r\n")
    )

    block = extract_exact_command_block(text, DATAPATH_INTERNAL_COMMAND)

    assert block.command == DATAPATH_INTERNAL_COMMAND
    assert block.terminated_by_command is True
    assert block.lines[0] == "Datapath Session Table Entries"


def test_lf_and_crlf_inputs_produce_identical_results() -> None:
    lf_result = parse_offline_tech_support(fixture())
    crlf_result = parse_offline_tech_support(fixture().replace("\n", "\r\n"))
    assert crlf_result == lf_result


def test_exact_command_extraction_requires_one_exact_echo() -> None:
    with pytest.raises(ParseError, match="not found"):
        extract_exact_command_block(
            fixture().replace(
                DATAPATH_INTERNAL_COMMAND,
                f"{DATAPATH_INTERNAL_COMMAND} extra",
                1,
            ),
            DATAPATH_INTERNAL_COMMAND,
        )

    with pytest.raises(ParseError, match="duplicated"):
        extract_exact_command_block(f"{fixture()}\n{fixture()}", DATAPATH_INTERNAL_COMMAND)


def test_offline_parser_rejects_missing_or_duplicate_required_block() -> None:
    with pytest.raises(ParseError, match="not found"):
        parse_offline_tech_support("show clock\n12:00:00")
    with pytest.raises(ParseError, match="duplicated"):
        parse_offline_tech_support(f"{fixture()}\n{fixture()}")


@pytest.mark.parametrize(
    "mutated",
    [
        lambda value: value.replace("Source IP or MAC", "Source Address  ", 1),
        lambda value: value.replace("CPU ID", "CPU-ID", 1),
        lambda value: value.replace(
            "----------------- ---------------",
            "----------------- --             ",
            1,
        ),
    ],
)
def test_offline_parser_rejects_unsupported_or_incomplete_header(mutated: object) -> None:
    text = mutated(fixture())  # type: ignore[operator]
    with pytest.raises(ParseError, match="header"):
        parse_offline_tech_support(text)


def test_offline_parser_rejects_truncated_fixed_width_row() -> None:
    lines = fixture().splitlines()
    row_index = next(index for index, line in enumerate(lines) if line.startswith("192.0.2.10"))
    lines[row_index] = lines[row_index][:100]

    with pytest.raises(ParseError, match=r"incomplete|malformed"):
        parse_offline_tech_support("\n".join(lines))


def test_offline_parser_rejects_count_mismatch_and_unterminated_eof() -> None:
    with pytest.raises(ParseError, match="row count"):
        parse_offline_tech_support(fixture().replace("Entries: 2", "Entries: 3", 1))
    with pytest.raises(ParseError, match="completion marker"):
        parse_offline_tech_support(_datapath_only(include_count=False))


def test_offline_parser_accepts_counted_final_block_at_eof() -> None:
    result = parse_offline_tech_support(_datapath_only())
    assert len(result.sessions) == 2
    assert result.enrichment.user_table_status is OfflineEnrichmentStatus.NOT_PRESENT
    assert result.enrichment.station_table_status is OfflineEnrichmentStatus.NOT_PRESENT


def test_offline_parser_accepts_empty_counted_table() -> None:
    lines = _datapath_only().splitlines()
    lines = [line for line in lines if not line.startswith(("192.0.2.10", "198.51.100.20"))]
    text = "\n".join(lines).replace("Entries: 2", "Entries: 0")
    assert parse_offline_tech_support(text).sessions == ()


def test_offline_parser_accepts_safe_final_prompt_as_completion() -> None:
    text = f"{_datapath_only(include_count=False)}\n(document-host) [node] #"
    assert len(parse_offline_tech_support(text).sessions) == 2


def test_offline_parser_rejects_duplicate_marker_or_data_after_completion() -> None:
    with pytest.raises(ParseError, match="duplicated"):
        parse_offline_tech_support(_datapath_only().replace("Entries: 2", "Entries: 2\nEntries: 2"))
    with pytest.raises(ParseError, match="after completion"):
        parse_offline_tech_support(f"{_datapath_only()}\nuntrusted trailing data")


def test_offline_parser_rejects_l2_and_invalid_required_fields() -> None:
    mac_row = _replace_datapath_field(fixture(), "192.0.2.10", 0, "00:00:5e:00:53:01")
    with pytest.raises(ParseError, match="endpoint type"):
        parse_offline_tech_support(mac_row)

    bad_counter = _replace_datapath_field(fixture(), "192.0.2.10", 5, "invalid")
    with pytest.raises(ParseError, match="malformed"):
        parse_offline_tech_support(bad_counter)

    missing_destination = _replace_datapath_field(fixture(), "192.0.2.10", 9, "")
    with pytest.raises(ParseError, match="malformed"):
        parse_offline_tech_support(missing_destination)


def test_offline_parser_rejects_html_in_opaque_datapath_field() -> None:
    text = _replace_datapath_field(fixture(), "192.0.2.10", 36, "<script>bad</script>")
    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support(text)
    assert "<script>" not in str(caught.value)


def test_optional_unverified_table_is_not_used_for_enrichment() -> None:
    text = fixture().replace(
        "IP              MAC               Name",
        "Ix              MAC               Name",
        1,
    )

    result = parse_offline_tech_support(text)

    assert result.enrichment.user_table_status is OfflineEnrichmentStatus.UNAVAILABLE
    assert result.enrichment.user_ips == frozenset()
    assert result.enrichment.user_macs == frozenset()
    assert result.enrichment.station_table_status is OfflineEnrichmentStatus.VALIDATED


def test_unverified_station_table_is_not_used_for_enrichment() -> None:
    before_station, station = fixture().split("show station-table", 1)
    text = f"{before_station}show station-table{
        station.replace(
            'MAC               Name         Role',
            'MxC               Name         Role',
            1,
        )
    }"
    result = parse_offline_tech_support(text)
    assert result.enrichment.station_table_status is OfflineEnrichmentStatus.UNAVAILABLE
    assert result.enrichment.station_macs == frozenset()


def test_optional_count_mismatch_is_unavailable_not_partially_trusted() -> None:
    user_mismatch = parse_offline_tech_support(
        fixture().replace("User Entries: 1/1", "User Entries: 2/2")
    )
    assert user_mismatch.enrichment.user_table_status is OfflineEnrichmentStatus.UNAVAILABLE
    assert user_mismatch.enrichment.user_ips == frozenset()

    station_mismatch = parse_offline_tech_support(
        fixture().replace("Station Entries: 1", "Station Entries: 2")
    )
    assert station_mismatch.enrichment.station_table_status is OfflineEnrichmentStatus.UNAVAILABLE
    assert station_mismatch.enrichment.station_macs == frozenset()


def test_required_block_needs_its_own_trusted_completion_marker() -> None:
    truncated_lines = [
        line
        for line in fixture().splitlines()
        if not line.startswith("198.51.100.20") and line != "Entries: 2"
    ]

    with pytest.raises(ParseError, match="trusted completion"):
        parse_offline_tech_support("\n".join(truncated_lines))


@pytest.mark.parametrize(
    ("marker", "extra"),
    [
        (
            "User Entries: 1/1",
            "203.0.113.10    00:00:5e:00:53:03 second-user  employee",
        ),
        ("User Entries: 1/1", "User Entries: 1/1"),
        ("Station Entries: 1", "00:00:5e:00:53:03 second-ap station"),
        ("Station Entries: 1", "Station Entries: 1"),
    ],
)
def test_optional_enrichment_rejects_content_after_completion(marker: str, extra: str) -> None:
    result = parse_offline_tech_support(fixture().replace(marker, f"{marker}\n{extra}", 1))

    if marker.startswith("User"):
        assert result.enrichment.user_table_status is OfflineEnrichmentStatus.UNAVAILABLE
        assert result.enrichment.user_ips == frozenset()
        assert result.enrichment.user_records == ()
    else:
        assert result.enrichment.station_table_status is OfflineEnrichmentStatus.UNAVAILABLE
        assert result.enrichment.station_macs == frozenset()
        assert result.enrichment.station_records == ()


def test_duplicate_optional_block_is_unavailable_without_guessing() -> None:
    user_block = fixture().split("show user-table verbose", 1)[1].split("show station-table", 1)[0]
    text = fixture().replace(
        "show station-table",
        f"show user-table verbose{user_block}show station-table",
        1,
    )

    result = parse_offline_tech_support(text)

    assert result.enrichment.user_table_status is OfflineEnrichmentStatus.UNAVAILABLE
    assert result.enrichment.user_ips == frozenset()


def test_html_like_row_and_control_text_fail_with_sanitized_messages() -> None:
    html_text = fixture().replace("192.0.2.10", "<script>x ", 1)
    with pytest.raises(ParseError) as html_error:
        parse_offline_tech_support(html_text)
    assert "<script>" not in str(html_error.value)
    assert "192.0.2.10" not in str(html_error.value)

    with pytest.raises(ParseError) as control_error:
        parse_offline_tech_support(f"{fixture()}\x00secret-value")
    assert "secret-value" not in str(control_error.value)
    assert "control characters" in str(control_error.value)


def test_malformed_endpoint_error_does_not_echo_row_or_address() -> None:
    text = fixture().replace("192.0.2.10", "not-an-ip ", 1)
    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support(text)
    assert "not-an-ip" not in str(caught.value)
    assert "198.51.100.20" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_offline_input_and_session_limits_fail_before_unbounded_growth() -> None:
    with pytest.raises(ParseError) as text_error:
        parse_offline_tech_support(
            fixture(),
            limits=OfflineParseLimits(max_text_bytes=100),
        )
    assert text_error.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED

    with pytest.raises(ParseError) as line_error:
        parse_offline_tech_support(
            fixture(),
            limits=OfflineParseLimits(max_line_characters=100),
        )
    assert line_error.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED

    with pytest.raises(ParseError) as session_error:
        parse_offline_tech_support(
            fixture(),
            limits=OfflineParseLimits(max_sessions=1),
        )
    assert session_error.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED

    with pytest.raises(ParseError) as line_count_error:
        parse_offline_tech_support(
            "\n" * 10,
            limits=OfflineParseLimits(max_lines=10),
        )
    assert line_count_error.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "marker",
    ("Entries: 2", "User Entries: 1/1", "Station Entries: 1"),
)
def test_attacker_sized_declared_counts_are_bounded_without_integer_conversion(
    marker: str,
) -> None:
    prefix = marker.split(":", 1)[0]
    replacement = f"{prefix}: {'9' * 5_000}"
    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support(fixture().replace(marker, replacement, 1))
    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_utf8_byte_limit_and_invalid_encoding_are_sanitized() -> None:
    with pytest.raises(ParseError) as byte_error:
        parse_offline_tech_support(
            "가" * 40,
            limits=OfflineParseLimits(max_text_bytes=100),
        )
    assert byte_error.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED

    with pytest.raises(ParseError, match="encoding") as encoding_error:
        parse_offline_tech_support("\ud800")
    assert encoding_error.value.__cause__ is None
    assert encoding_error.value.__context__ is None

    with pytest.raises(TypeError, match="must be text"):
        parse_offline_tech_support(b"not text")  # type: ignore[arg-type]


def test_optional_enrichment_limit_is_a_hard_failure() -> None:
    row = "192.0.2.10      00:00:5e:00:53:01 sample-user  employee"
    extra = "203.0.113.10    00:00:5e:00:53:03 second-user  employee"
    text = (
        fixture().replace(row, f"{row}\n{extra}").replace("User Entries: 1/1", "User Entries: 2/2")
    )

    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support(
            text,
            limits=OfflineParseLimits(max_enrichment_records=1),
        )
    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    ("kwargs", "error_type"),
    [
        ({"max_text_bytes": 0}, ValueError),
        ({"max_lines": 0}, ValueError),
        ({"max_line_characters": True}, TypeError),
        ({"max_sessions": 0}, ValueError),
        ({"max_enrichment_records": 0}, ValueError),
    ],
)
def test_offline_limits_validate_types_and_ranges(
    kwargs: dict[str, object], error_type: type[Exception]
) -> None:
    with pytest.raises(error_type):
        OfflineParseLimits(**kwargs)  # type: ignore[arg-type]


def test_unsupported_public_command_is_rejected_without_echoing_it() -> None:
    with pytest.raises(ValueError) as caught:
        extract_exact_command_block(fixture(), "show running-config")
    assert "running-config" not in str(caught.value)


def test_offline_parser_can_be_cancelled_after_input_validation_starts() -> None:
    checks = 0

    def cancel_during_parse() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 4

    with pytest.raises(ParseError) as caught:
        parse_offline_tech_support(fixture(), is_cancelled=cancel_during_parse)

    assert caught.value.code is ErrorCode.CANCELLED
    assert checks >= 4


def test_offline_parser_rejects_non_callable_cancellation_probe() -> None:
    with pytest.raises(TypeError):
        parse_offline_tech_support(fixture(), is_cancelled=True)  # type: ignore[arg-type]
