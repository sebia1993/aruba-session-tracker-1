from __future__ import annotations

from pathlib import Path

import pytest

from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.parsers import (
    FLAG_DEFINITIONS,
    FlagSeverity,
    GlobalUserStatus,
    ParseError,
    interpret_flags,
    overall_flag_severity,
    parse_datapath_sessions,
    parse_global_user_table,
    parse_show_switches,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_global_user_parser_returns_one_current_switch() -> None:
    result = parse_global_user_table(fixture("global_user_one.txt"), client_ip="192.0.2.10")
    assert result.status is GlobalUserStatus.FOUND
    assert result.current_switch == "198.51.100.11"
    assert result.current_switches == ("198.51.100.11",)
    assert result.row_count == 1


def test_datapath_parser_enforces_observation_capacity_before_append() -> None:
    with pytest.raises(ParseError) as caught:
        parse_datapath_sessions(
            fixture("datapath_sessions.txt"),
            controller_name="MD-1",
            controller_host="198.51.100.11",
            max_observations=1,
        )

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_datapath_zero_capacity_precedes_malformed_ipv4_row_validation() -> None:
    output = fixture("datapath_empty.txt").replace(
        "Entries: 0",
        "192.0.2.10 malformed\n(md-document-01)^*[mynode]#",
    )

    with pytest.raises(ParseError) as caught:
        parse_datapath_sessions(
            output,
            controller_name="MD-1",
            controller_host="198.51.100.11",
            max_observations=0,
        )

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


@pytest.mark.parametrize(
    "over_limit_row",
    [
        # A repeated key must not downgrade the capacity failure to a partial parse.
        "192.0.2.10        203.0.113.20    6    54321 443   0/0  0    0   12  "
        "local       0    10      2048  FCI   1",
        # Field validation beyond the basic row shape also comes after the capacity gate.
        "192.0.2.10        203.0.113.20    6    54321 443   bad  0    0   12  "
        "local       0    10      2048  FCI   1",
    ],
)
def test_datapath_capacity_precedes_duplicate_and_field_validation(
    over_limit_row: str,
) -> None:
    lines = fixture("datapath_sessions.txt").splitlines()
    first_row_index = next(
        index for index, line in enumerate(lines) if line.startswith("192.0.2.10")
    )
    output = "\n".join([*lines[: first_row_index + 1], over_limit_row, "Entries: 2"])

    with pytest.raises(ParseError) as caught:
        parse_datapath_sessions(
            output,
            controller_name="MD-1",
            controller_host="198.51.100.11",
            max_observations=1,
        )

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_global_user_parser_distinguishes_zero_rows() -> None:
    result = parse_global_user_table(fixture("global_user_empty.txt"), client_ip="192.0.2.99")
    assert result.status is GlobalUserStatus.NOT_FOUND
    assert result.current_switch is None
    assert result.current_switches == ()
    assert result.row_count == 0


def test_global_user_parser_distinguishes_multiple_switches() -> None:
    result = parse_global_user_table(fixture("global_user_multiple.txt"), client_ip="192.0.2.44")
    assert result.status is GlobalUserStatus.AMBIGUOUS
    assert result.current_switch is None
    assert result.current_switches == ("198.51.100.11", "198.51.100.12")
    assert result.row_count == 2


def test_global_user_duplicate_rows_on_one_switch_are_not_ambiguous() -> None:
    output = fixture("global_user_one.txt").replace(
        "Total entries = 1",
        "192.0.2.10      00:00:5e:00:53:02  second-user    "
        "198.51.100.11  employee     dot1x  ap-doc-02\n"
        "Total entries = 2",
    )
    result = parse_global_user_table(output, client_ip="192.0.2.10")
    assert result.status is GlobalUserStatus.FOUND
    assert result.current_switches == ("198.51.100.11",)
    assert result.row_count == 2


def test_global_user_parser_rejects_declared_but_missing_row() -> None:
    with pytest.raises(ParseError, match="row count mismatch"):
        parse_global_user_table(fixture("global_user_truncated.txt"), client_ip="192.0.2.10")


def test_global_user_parser_rejects_duplicate_or_trailing_completion_data() -> None:
    duplicate = fixture("global_user_one.txt") + "\nTotal entries = 1\n"
    with pytest.raises(ParseError, match="duplicated"):
        parse_global_user_table(duplicate, client_ip="192.0.2.10")

    trailing = fixture("global_user_one.txt") + "\nUNTRUSTED TRAILING DATA\n"
    with pytest.raises(ParseError, match="data after completion"):
        parse_global_user_table(trailing, client_ip="192.0.2.10")


def test_global_user_parser_accepts_one_trusted_prompt_after_completion() -> None:
    output = fixture("global_user_one.txt") + "\n(mm-primary)^*[mynode]#\n"

    result = parse_global_user_table(output, client_ip="192.0.2.10")

    assert result.status is GlobalUserStatus.FOUND
    assert result.current_switch == "198.51.100.11"


def test_global_user_parser_enforces_row_capacity_before_completion_marker() -> None:
    source = fixture("global_user_one.txt")
    lines = source.splitlines()
    row = next(line for line in lines if line.startswith("192.0.2.10"))
    marker_index = next(
        index for index, line in enumerate(lines) if line.startswith("Total entries")
    )
    output = "\n".join(
        (
            *lines[:marker_index],
            *(row for _ in range(20_001)),
            "Total entries = 20001",
        )
    )

    with pytest.raises(ParseError) as caught:
        parse_global_user_table(output, client_ip="192.0.2.10")

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_global_user_parser_rejects_invalid_current_switch() -> None:
    output = fixture("global_user_one.txt").replace("198.51.100.11", "not-an-address")
    with pytest.raises(ParseError, match="Current switch"):
        parse_global_user_table(output, client_ip="192.0.2.10")


@pytest.mark.parametrize(
    ("parser", "kwargs"),
    [
        (parse_global_user_table, {"client_ip": "192.0.2.10"}),
        (parse_show_switches, {}),
        (
            parse_datapath_sessions,
            {"controller_name": "md-document-01", "controller_host": "198.51.100.11"},
        ),
    ],
)
def test_all_table_parsers_reject_cli_errors(parser: object, kwargs: dict[str, str]) -> None:
    with pytest.raises(ParseError, match="rejected"):
        parser(fixture("command_rejected.txt"), **kwargs)  # type: ignore[operator]


@pytest.mark.parametrize(
    "output",
    [
        "Permission denied",
        "% Insufficient privileges",
        "Authorization failed",
        "Error: Access denied",
        "Command authorization failed.",
        "Command not allowed",
    ],
)
@pytest.mark.parametrize(
    ("parser", "kwargs"),
    [
        (parse_global_user_table, {"client_ip": "192.0.2.10"}),
        (parse_show_switches, {}),
        (
            parse_datapath_sessions,
            {"controller_name": "md-document-01", "controller_host": "198.51.100.11"},
        ),
    ],
)
def test_all_table_parsers_classify_permission_errors_as_command_rejected(
    parser: object,
    kwargs: dict[str, str],
    output: str,
) -> None:
    with pytest.raises(ParseError) as caught:
        parser(output, **kwargs)  # type: ignore[operator]

    assert caught.value.code is ErrorCode.COMMAND_REJECTED


def test_show_switches_parser_returns_only_managed_devices() -> None:
    rows = parse_show_switches(fixture("show_switches.txt"))
    assert [(row.ip_address, row.name) for row in rows] == [
        ("198.51.100.11", "md-document-01"),
        ("198.51.100.12", "md-document-02"),
    ]
    assert rows[0].device_type == "MD"
    assert rows[0].model == "Aruba7240XM"
    assert rows[0].version == "8.10.0.10_89128"
    assert rows[0].status == "up"


def test_show_switches_debug_variant_is_supported() -> None:
    rows = parse_show_switches(fixture("show_switches_debug.txt"))
    assert len(rows) == 1
    assert rows[0].ip_address == "198.51.100.11"
    assert rows[0].name == "md-document-01"
    assert rows[0].model == "Aruba7240XM"
    assert rows[0].version == "8.10.0.10_89128"


def test_show_switches_parser_rejects_incomplete_table() -> None:
    output = fixture("show_switches.txt").replace("Total Switches:3", "")
    with pytest.raises(ParseError, match="incomplete"):
        parse_show_switches(output)


def test_show_switches_parser_rejects_row_count_mismatch() -> None:
    output = fixture("show_switches.txt").replace("Total Switches:3", "Total Switches:4")
    with pytest.raises(ParseError, match="row count mismatch"):
        parse_show_switches(output)


def test_datapath_parser_maps_standard_rows_to_models() -> None:
    rows = parse_datapath_sessions(
        fixture("datapath_sessions.txt"),
        controller_name="md-document-01",
        controller_host="198.51.100.11",
    )
    assert len(rows) == 3
    first = rows[0]
    assert first.controller_name == "md-document-01"
    assert first.controller_host == "198.51.100.11"
    assert first.source_ip == "192.0.2.10"
    assert first.destination_ip == "203.0.113.20"
    assert first.protocol == 6
    assert first.source_port == 54321
    assert first.destination_port == 443
    assert first.counter == "0/0"
    assert first.priority == 0
    assert first.tos == 0
    assert first.age == 12
    assert first.destination == "local"
    assert first.tunnel_age == 0
    assert first.packets == 10
    assert first.bytes_count == 2048
    assert first.flags == "FCI"
    assert first.cpu_id == 1
    assert first.raw_line.strip().startswith("192.0.2.10")
    assert rows[1].tunnel_age == int("f4cb", 16)
    assert rows[1].flags == "Y"
    assert rows[2].flags == ""
    assert rows[2].cpu_id == 6


@pytest.mark.parametrize(
    "duplicate_row",
    [
        # The same flow with different flags and CPU ownership is still ambiguous.
        "192.0.2.10 203.0.113.20 6 54321 443 0/0 0 0 12 local 0 10 2048 Y 2",
        # Counters are observations of one key, not distinct sessions.
        "192.0.2.10 203.0.113.20 6 54321 443 1/2 0 0 13 local 0 11 4096 FCI 1",
        # Even byte-for-byte equivalent session data must not be silently collapsed.
        "192.0.2.10        203.0.113.20    6    54321 443   0/0  0    0   12  "
        "local       0    10      2048  FCI   1",
    ],
)
def test_datapath_parser_rejects_duplicate_session_keys(duplicate_row: str) -> None:
    output = fixture("datapath_sessions.txt").replace(
        "Entries: 3",
        f"{duplicate_row}\nEntries: 4",
    )

    with pytest.raises(ParseError, match="duplicate session key"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_accepts_tabs_and_spacing_variation() -> None:
    rows = parse_datapath_sessions(
        fixture("datapath_whitespace.txt"),
        controller_name="md-document-01",
        controller_host="198.51.100.11",
    )
    assert len(rows) == 1
    assert rows[0].source_port == 4500
    assert rows[0].destination == "tunnel 10"
    assert rows[0].tunnel_age == int("efee", 16)
    assert rows[0].flags == "FC"


def test_datapath_empty_table_is_not_a_parse_failure() -> None:
    rows = parse_datapath_sessions(
        fixture("datapath_empty.txt"),
        controller_name="md-document-01",
        controller_host="198.51.100.11",
    )
    assert rows == ()


def test_datapath_parser_rejects_truncated_row() -> None:
    with pytest.raises(ParseError, match="Truncated"):
        parse_datapath_sessions(
            fixture("datapath_truncated.txt"),
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_rejects_declared_but_missing_row() -> None:
    output = fixture("datapath_sessions.txt").replace(
        "192.0.2.10        198.51.100.53   17   53000 53    1/2  0    40  "
        "1   local       19   2       144         6\n",
        "",
    )
    with pytest.raises(ParseError, match="row count mismatch"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


@pytest.mark.parametrize(
    "output",
    [
        fixture("datapath_empty.txt").replace("Entries: 0", ""),
        fixture("datapath_sessions.txt").rsplit("Entries:", 1)[0],
        fixture("datapath_empty.txt").replace("Entries: 0", "Entries:\n0"),
    ],
)
def test_datapath_parser_rejects_output_without_completion_marker(output: str) -> None:
    with pytest.raises(ParseError, match="completion marker"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


@pytest.mark.parametrize(
    "output",
    [
        fixture("datapath_empty.txt") + "\nEntries: 0\n",
        fixture("datapath_empty.txt") + "\nUNTRUSTED TRAILING DATA\n",
        fixture("datapath_empty.txt").replace(
            "Entries: 0",
            "(md-document-01)#\n(md-document-01)#",
        ),
    ],
)
def test_datapath_parser_rejects_duplicate_or_trailing_completion_data(output: str) -> None:
    with pytest.raises(ParseError, match=r"completion marker|data after completion"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_bounds_declared_count_before_integer_conversion() -> None:
    output = fixture("datapath_empty.txt").replace("Entries: 0", f"Entries: {'9' * 5_000}")

    with pytest.raises(ParseError) as caught:
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED


def test_datapath_parser_accepts_one_trusted_prompt_after_count() -> None:
    output = fixture("datapath_sessions.txt") + "\n(md-document-01)^*[mynode]#\n"

    rows = parse_datapath_sessions(
        output,
        controller_name="md-document-01",
        controller_host="198.51.100.11",
    )

    assert len(rows) == 3


def test_datapath_parser_rejects_trusted_prompt_before_count() -> None:
    output = fixture("datapath_sessions.txt").replace(
        "Entries: 3",
        "(md-document-01)^*[mynode]#\nEntries: 3",
    )

    with pytest.raises(ParseError, match="prompt appears before"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


@pytest.mark.parametrize(
    "completion",
    [
        "Entries: 0",
        "(md-document-01)^*[mynode]#",
    ],
)
def test_datapath_parser_rejects_unrecognized_data_before_completion(
    completion: str,
) -> None:
    output = fixture("datapath_empty.txt").replace(
        "Entries: 0",
        f"UNTRUSTED INTERRUPT\n{completion}",
    )

    with pytest.raises(ParseError, match="unrecognized data line"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_table_start_accepts_safe_horizontal_spacing() -> None:
    output = fixture("datapath_empty.txt").replace(
        "Datapath Session Table Entries",
        "\tDatapath\tSession   Table\tEntries  ",
    )

    assert (
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )
        == ()
    )


def test_datapath_header_must_follow_exact_table_start() -> None:
    source = fixture("datapath_empty.txt")
    header = next(line for line in source.splitlines() if line.startswith("Source IP or MAC"))
    output = f"{header}\n" + source.replace(f"{header}\n", "", 1)

    with pytest.raises(ParseError, match="required column header"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_legend_continuation_requires_flags_start() -> None:
    output = fixture("datapath_empty.txt").replace(
        "------------------------------",
        "------------------------------\n       W - untrusted standalone text",
        1,
    )

    with pytest.raises(ParseError, match="unrecognized data before its header"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_rejects_long_malformed_flag_legend_without_regex_backtracking() -> None:
    malformed_legend = "Flags:" + ("A - +," * 5_000) + "A -"
    output = fixture("datapath_empty.txt").replace(
        "------------------------------",
        f"------------------------------\n{malformed_legend}",
        1,
    )

    with pytest.raises(ParseError, match="unrecognized data before its header"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_column_separator_must_follow_header_inside_table_region() -> None:
    source = fixture("datapath_empty.txt")
    separator = next(
        line for line in source.splitlines() if line.startswith("---------------- ----------------")
    )
    output = f"{separator}\n" + source.replace(f"{separator}\n", "", 1)

    with pytest.raises(ParseError, match="validated column separator"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_table_start_rejects_embedded_phrase() -> None:
    output = fixture("datapath_empty.txt").replace(
        "Datapath Session Table Entries",
        "NOTICE: Datapath Session Table Entries will follow",
    )

    with pytest.raises(ParseError, match="incomplete or unrecognized"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


@pytest.mark.parametrize(
    "prompt",
    [
        "(md-document-01) #",
        "(md-document-01)^[mynode]#",
        "(md-document-01)*[mynode]#",
        "(md-document-01)^*[mynode]#",
        "(md-document-01) ^[mynode] #",
        "(md-document-01) ^ [mynode] #",
        "(md-document-01) *#",
        "(md-document-01) * [mynode] #",
        "md-document-01#",
    ],
)
def test_datapath_parser_accepts_safe_prompt_as_completion_marker(prompt: str) -> None:
    output = fixture("datapath_empty.txt").replace("Entries: 0", prompt)
    assert (
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )
        == ()
    )


@pytest.mark.parametrize(
    "prompt",
    [
        "(md-document-01) ![mynode] #",
        "^[mynode] #",
        "(md-document-01) **#",
        "(md-document-01) *^[mynode] #",
        "(md-document-01) [mynode] (config) #",
        "(md-document-01) ^[mynode] # trailing",
    ],
)
def test_datapath_parser_rejects_untrusted_prompt_variants(prompt: str) -> None:
    output = fixture("datapath_empty.txt").replace("Entries: 0", prompt)

    with pytest.raises(ParseError, match="completion marker"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_rejects_unverified_next_hop_schema() -> None:
    output = fixture("datapath_sessions.txt").replace(
        "Bytes Flags CPU ID",
        "Bytes NhlIdx NhIdx NhlNhVer Flags CPU ID",
    )
    with pytest.raises(ParseError, match="unsupported next-hop"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


@pytest.mark.parametrize(
    "bad_row",
    [
        "192.0.2.10 not-an-ip 6 54321 443 0/0 0 0 12 local 0 10 2048 F 1",
        "192.0.2.10 203.0.113.20 999 54321 443 0/0 0 0 12 local 0 10 2048 F 1",
        "192.0.2.10 203.0.113.20 6 65536 443 0/0 0 0 12 local 0 10 2048 F 1",
        "192.0.2.10 203.0.113.20 6 54321 443 invalid 0 0 12 local 0 10 2048 F 1",
        "192.0.2.10 203.0.113.20 6 54321 443 0/0 0 0 -1 local 0 10 2048 F 1",
        "192.0.2.10 203.0.113.20 6 54321 443 0/0 0 0 12 local 0 10 2048 F 1 extra",
    ],
)
def test_datapath_parser_fails_closed_on_malformed_rows(bad_row: str) -> None:
    output = fixture("datapath_empty.txt").replace("Entries: 0", bad_row)
    with pytest.raises(ParseError):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_rejects_mac_row() -> None:
    output = fixture("datapath_empty.txt").replace(
        "Entries: 0",
        "00:00:5e:00:53:01 203.0.113.20 6 0 443 0/0 0 0 1 local 0 1 64 C 1",
    )
    with pytest.raises(ParseError, match="MAC-address"):
        parse_datapath_sessions(
            output,
            controller_name="md-document-01",
            controller_host="198.51.100.11",
        )


def test_datapath_parser_validates_controller_identity() -> None:
    with pytest.raises(ValueError, match="controller_name"):
        parse_datapath_sessions(
            fixture("datapath_empty.txt"),
            controller_name=" ",
            controller_host="198.51.100.11",
        )
    with pytest.raises(ValueError, match="controller_host"):
        parse_datapath_sessions(
            fixture("datapath_empty.txt"),
            controller_name="md-document-01",
            controller_host="not-an-ip",
        )


def test_flag_mapping_is_complete_and_case_sensitive() -> None:
    expected = set("FSNDRYHPTCMVQuIUEGrhAiJXxBOLo")
    assert set(FLAG_DEFINITIONS) == expected
    assert FLAG_DEFINITIONS["R"].description == "redirect"
    assert FLAG_DEFINITIONS["r"].description == "route nexthop"
    assert FLAG_DEFINITIONS["O"].description == "OpenFlow"
    assert FLAG_DEFINITIONS["o"].description == "OpenFlow config revision mismatched"


def test_flag_severity_distinguishes_deny_no_syn_redirect_and_unknown() -> None:
    interpreted = interpret_flags("DYR?")
    assert [item.severity for item in interpreted] == [
        FlagSeverity.CRITICAL,
        FlagSeverity.WARNING,
        FlagSeverity.NOTICE,
        FlagSeverity.CHECK,
    ]
    assert [item.is_known for item in interpreted] == [True, True, True, False]
    assert interpreted[-1].description.startswith("unknown flag")
    assert interpreted[-1].label_ko == "알 수 없는 플래그(확인 필요)"
    assert overall_flag_severity("DYR") is FlagSeverity.CRITICAL
    assert overall_flag_severity("DYR").value == "CRITICAL"
    assert overall_flag_severity("D?") is FlagSeverity.CRITICAL
    assert overall_flag_severity("?") is FlagSeverity.CHECK
    assert overall_flag_severity("") is FlagSeverity.NORMAL


def test_flag_interpreter_ignores_visual_empty_markers_only() -> None:
    assert interpret_flags(" - \t") == ()
