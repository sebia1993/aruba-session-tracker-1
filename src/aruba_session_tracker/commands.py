"""Fail-closed command builders for the read-only Aruba CLI surface."""

from __future__ import annotations

from ipaddress import IPv4Address

NO_PAGING_COMMAND = "no paging"


def normalize_ipv4(value: str | IPv4Address) -> str:
    """Return a canonical IPv4 string or raise ``ValueError``.

    Accepting only ``str`` and ``IPv4Address`` keeps integer and bytes-like
    values from accidentally becoming valid CLI operands.
    """

    if not isinstance(value, (str, IPv4Address)):
        raise TypeError("IPv4 address must be text or IPv4Address.")
    return str(IPv4Address(value))


def build_global_user_command(client_ip: str | IPv4Address) -> str:
    """Build the only supported Mobility Conductor user-location query."""

    return f'show global-user-table list ip "{normalize_ipv4(client_ip)}"'


def build_datapath_session_command(client_ip: str | IPv4Address) -> str:
    """Build the only supported managed-device datapath session query."""

    return f"show datapath session table {normalize_ipv4(client_ip)}"


def build_no_paging_command() -> str:
    """Return the session-scoped paging command used before a filtered query."""

    return NO_PAGING_COMMAND
