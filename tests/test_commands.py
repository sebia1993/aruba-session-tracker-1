from __future__ import annotations

from ipaddress import IPv4Address

import pytest

from aruba_session_tracker.commands import (
    NO_PAGING_COMMAND,
    build_datapath_session_command,
    build_global_user_command,
    build_no_paging_command,
    normalize_ipv4,
)


def test_global_user_command_is_exact_and_quoted() -> None:
    assert build_global_user_command("192.0.2.10") == 'show global-user-table list ip "192.0.2.10"'


def test_datapath_command_is_exact_and_filtered() -> None:
    assert (
        build_datapath_session_command("203.0.113.9") == "show datapath session table 203.0.113.9"
    )


def test_no_paging_command_is_exact() -> None:
    assert NO_PAGING_COMMAND == "no paging"
    assert build_no_paging_command() == "no paging"


def test_ipv4_address_object_is_accepted() -> None:
    address = IPv4Address("198.51.100.7")
    assert normalize_ipv4(address) == "198.51.100.7"
    assert build_global_user_command(address).endswith('"198.51.100.7"')


@pytest.mark.parametrize(
    "payload",
    [
        "192.0.2.10; show running-config",
        '192.0.2.10" or role admin',
        "192.0.2.10\nshow switches",
        "192.0.2.10 | include secret",
        "192.0.2.10 && reboot",
        "192.0.2.10 ",
        " 192.0.2.10",
        "192.0.2.010",
        "2001:db8::10",
        "controller.example",
        "",
    ],
)
def test_cli_injection_and_non_ipv4_inputs_are_rejected(payload: str) -> None:
    with pytest.raises(ValueError):
        build_global_user_command(payload)
    with pytest.raises(ValueError):
        build_datapath_session_command(payload)


@pytest.mark.parametrize("payload", [3232235777, b"192.0.2.10", None, True])
def test_non_text_operands_are_rejected(payload: object) -> None:
    with pytest.raises(TypeError):
        normalize_ipv4(payload)  # type: ignore[arg-type]
