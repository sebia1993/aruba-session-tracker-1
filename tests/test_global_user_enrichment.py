from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from aruba_session_tracker.models import ErrorCode
from aruba_session_tracker.parsers.common import ParseError
from aruba_session_tracker.parsers.global_users import (
    GlobalUserEntry,
    GlobalUserStatus,
    parse_global_user_table,
)

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_matching_entry_exposes_normalized_fixed_width_context() -> None:
    result = parse_global_user_table(fixture("global_user_one.txt"), client_ip="192.0.2.10")

    assert result.entries == (
        GlobalUserEntry(
            client_ip="192.0.2.10",
            mac_address="00:00:5e:00:53:01",
            user_name="test-user",
            current_switch="198.51.100.11",
            role="employee",
            auth_method="dot1x",
            ap_name="ap-doc-01",
        ),
    )


def test_entry_is_immutable_and_repr_does_not_expose_context_values() -> None:
    entry = parse_global_user_table(fixture("global_user_one.txt"), client_ip="192.0.2.10").entries[
        0
    ]

    with pytest.raises(FrozenInstanceError):
        entry.user_name = "changed"  # type: ignore[misc]

    rendered = repr(entry)
    assert rendered == "GlobalUserEntry()"
    for secret in (
        entry.client_ip,
        entry.mac_address,
        entry.user_name,
        entry.current_switch,
        entry.role,
        entry.auth_method,
        entry.ap_name,
    ):
        assert secret not in rendered


def test_blank_name_does_not_shift_later_fixed_width_columns() -> None:
    output = fixture("global_user_one.txt").replace("test-user", "         ")

    entry = parse_global_user_table(output, client_ip="192.0.2.10").entries[0]

    assert entry.user_name == ""
    assert entry.current_switch == "198.51.100.11"
    assert entry.role == "employee"
    assert entry.auth_method == "dot1x"
    assert entry.ap_name == "ap-doc-01"


def test_mac_is_validated_and_normalized_without_changing_lookup_status() -> None:
    output = fixture("global_user_one.txt").replace("00:00:5e:00:53:01", "AA-BB-CC-DD-EE-FF")

    result = parse_global_user_table(output, client_ip="192.0.2.10")

    assert result.status is GlobalUserStatus.FOUND
    assert result.current_switch == "198.51.100.11"
    assert result.entries[0].mac_address == "aa:bb:cc:dd:ee:ff"


def test_multiple_rows_are_preserved_while_switch_ambiguity_remains() -> None:
    result = parse_global_user_table(fixture("global_user_multiple.txt"), client_ip="192.0.2.44")

    assert result.status is GlobalUserStatus.AMBIGUOUS
    assert result.current_switch is None
    assert [entry.current_switch for entry in result.entries] == [
        "198.51.100.11",
        "198.51.100.12",
    ]
    assert [entry.ap_name for entry in result.entries] == ["ap-doc-01", "ap-doc-02"]


def test_duplicate_rows_on_one_switch_are_preserved_without_status_change() -> None:
    output = fixture("global_user_one.txt").replace(
        "Total entries = 1",
        "192.0.2.10      00:00:5e:00:53:02                 "
        "198.51.100.11  employee     mac    ap-doc-02\n"
        "Total entries = 2",
    )

    result = parse_global_user_table(output, client_ip="192.0.2.10")

    assert result.status is GlobalUserStatus.FOUND
    assert result.current_switch == "198.51.100.11"
    assert len(result.entries) == 2
    assert result.entries[1].user_name == ""


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("00:00:5e:00:53:01", "not-a-valid-mac  ", "MAC"),
        ("192.0.2.10", "not-an-ip ", "row IP"),
        ("198.51.100.11", "not-a-switch ", "Current switch"),
    ],
)
def test_malformed_identity_fields_fail_closed(old: str, new: str, message: str) -> None:
    output = fixture("global_user_one.txt").replace(old, new)

    with pytest.raises(ParseError, match=message):
        parse_global_user_table(output, client_ip="192.0.2.10")


def test_malformed_identity_is_not_retained_in_exception_chain() -> None:
    output = fixture("global_user_one.txt").replace("192.0.2.10", "sensitive-ip")

    with pytest.raises(ParseError) as caught:
        parse_global_user_table(output, client_ip="192.0.2.10")

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_attacker_sized_total_is_a_sanitized_output_limit_error() -> None:
    output = fixture("global_user_one.txt").replace(
        "Total entries = 1", f"Total entries = {'9' * 5_000}"
    )

    with pytest.raises(ParseError) as caught:
        parse_global_user_table(output, client_ip="192.0.2.10")

    assert caught.value.code is ErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_incomplete_optional_column_geometry_fails_closed() -> None:
    output = fixture("global_user_one.txt").replace("   AP name", "          ")

    with pytest.raises(ParseError, match="optional column geometry"):
        parse_global_user_table(output, client_ip="192.0.2.10")


def test_misordered_optional_column_geometry_fails_closed() -> None:
    output = fixture("global_user_one.txt").replace(
        "Role         Auth   AP name", "Auth   Role         AP name"
    )

    with pytest.raises(ParseError, match="conflicting optional column geometry"):
        parse_global_user_table(output, client_ip="192.0.2.10")


def test_truncated_declared_row_fails_closed_instead_of_becoming_not_found() -> None:
    output = fixture("global_user_one.txt").replace(
        "192.0.2.10      00:00:5e:00:53:01  test-user      198.51.100.11  "
        "employee     dot1x  ap-doc-01",
        "192.0.2.10",
    )

    with pytest.raises(ParseError, match="MAC"):
        parse_global_user_table(output, client_ip="192.0.2.10")


def test_legacy_header_without_optional_columns_remains_supported() -> None:
    header = "IP              MAC                Name              Current switch    Role"
    labels = ("IP", "MAC", "Name", "Current switch", "Role")
    starts = {label: header.index(label) for label in labels}
    row = [" "] * (len(header) + 16)
    for label, value in (
        ("IP", "192.0.2.10"),
        ("MAC", "00:11:22:33:44:55"),
        ("Name", "fixture"),
        ("Current switch", "198.51.100.11"),
        ("Role", "authenticated"),
    ):
        start = starts[label]
        row[start : start + len(value)] = value
    output = f"{header}\n{'-' * len(header)}\n{''.join(row).rstrip()}\nTotal entries = 1\n"

    result = parse_global_user_table(output, client_ip="192.0.2.10")

    assert result.status is GlobalUserStatus.FOUND
    assert result.current_switch == "198.51.100.11"
    assert result.entries[0].auth_method == ""
    assert result.entries[0].ap_name == ""


def test_columns_after_ap_name_are_not_folded_into_the_ap_value() -> None:
    output = (
        fixture("global_user_one.txt")
        .replace(
            "Role         Auth   AP name",
            "Role         Auth   AP name       Roaming Essid",
        )
        .replace(
            "employee     dot1x  ap-doc-01",
            "employee     dot1x  ap-doc-01     No      corp-wifi",
        )
    )

    entry = parse_global_user_table(output, client_ip="192.0.2.10").entries[0]

    assert entry.ap_name == "ap-doc-01"
