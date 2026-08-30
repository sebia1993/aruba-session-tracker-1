"""Small, deterministic protocol and service-name catalogues.

The application intentionally ships a conservative static subset instead of
consulting the operating system or a network service.  That keeps labels
stable in offline Windows packages.  Unknown values remain numeric rather
than being guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class ProtocolDefinition:
    """One Internet Protocol Number entry used by the analysis layer."""

    number: int
    keyword: str
    description: str


_PROTOCOL_DEFINITIONS = {
    0: ProtocolDefinition(0, "HOPOPT", "IPv6 Hop-by-Hop Option"),
    1: ProtocolDefinition(1, "ICMP", "Internet Control Message"),
    2: ProtocolDefinition(2, "IGMP", "Internet Group Management"),
    4: ProtocolDefinition(4, "IPv4", "IPv4 encapsulation"),
    6: ProtocolDefinition(6, "TCP", "Transmission Control"),
    8: ProtocolDefinition(8, "EGP", "Exterior Gateway Protocol"),
    17: ProtocolDefinition(17, "UDP", "User Datagram"),
    41: ProtocolDefinition(41, "IPv6", "IPv6 encapsulation"),
    43: ProtocolDefinition(43, "IPv6-Route", "Routing Header for IPv6"),
    44: ProtocolDefinition(44, "IPv6-Frag", "Fragment Header for IPv6"),
    46: ProtocolDefinition(46, "RSVP", "Reservation Protocol"),
    47: ProtocolDefinition(47, "GRE", "Generic Routing Encapsulation"),
    50: ProtocolDefinition(50, "ESP", "Encapsulating Security Payload"),
    51: ProtocolDefinition(51, "AH", "Authentication Header"),
    58: ProtocolDefinition(58, "IPv6-ICMP", "ICMP for IPv6"),
    59: ProtocolDefinition(59, "IPv6-NoNxt", "No Next Header for IPv6"),
    60: ProtocolDefinition(60, "IPv6-Opts", "Destination Options for IPv6"),
    89: ProtocolDefinition(89, "OSPF", "Open Shortest Path First"),
    103: ProtocolDefinition(103, "PIM", "Protocol Independent Multicast"),
    112: ProtocolDefinition(112, "VRRP", "Virtual Router Redundancy Protocol"),
    115: ProtocolDefinition(115, "L2TP", "Layer Two Tunneling Protocol"),
    132: ProtocolDefinition(132, "SCTP", "Stream Control Transmission Protocol"),
    136: ProtocolDefinition(136, "UDPLite", "UDP-Lite"),
    137: ProtocolDefinition(137, "MPLS-in-IP", "MPLS-in-IP"),
}

PROTOCOL_DEFINITIONS = MappingProxyType(_PROTOCOL_DEFINITIONS)


@dataclass(frozen=True, slots=True)
class ServiceDefinition:
    """A representative service whose transport protocol is significant."""

    protocol: int
    port: int
    label: str


_SERVICE_DEFINITIONS = {
    # TCP services.
    (6, 20): ServiceDefinition(6, 20, "FTP data"),
    (6, 21): ServiceDefinition(6, 21, "FTP"),
    (6, 22): ServiceDefinition(6, 22, "SSH"),
    (6, 23): ServiceDefinition(6, 23, "Telnet"),
    (6, 25): ServiceDefinition(6, 25, "SMTP"),
    (6, 53): ServiceDefinition(6, 53, "DNS"),
    (6, 80): ServiceDefinition(6, 80, "HTTP"),
    (6, 110): ServiceDefinition(6, 110, "POP3"),
    (6, 143): ServiceDefinition(6, 143, "IMAP"),
    (6, 389): ServiceDefinition(6, 389, "LDAP"),
    (6, 443): ServiceDefinition(6, 443, "HTTPS"),
    (6, 445): ServiceDefinition(6, 445, "SMB"),
    (6, 465): ServiceDefinition(6, 465, "SMTPS"),
    (6, 587): ServiceDefinition(6, 587, "SMTP submission"),
    (6, 636): ServiceDefinition(6, 636, "LDAPS"),
    (6, 993): ServiceDefinition(6, 993, "IMAPS"),
    (6, 995): ServiceDefinition(6, 995, "POP3S"),
    (6, 3389): ServiceDefinition(6, 3389, "RDP"),
    # UDP services.  Entries are separate so a same-number TCP port is never
    # labelled solely because its UDP counterpart is familiar.
    (17, 53): ServiceDefinition(17, 53, "DNS"),
    (17, 67): ServiceDefinition(17, 67, "DHCP server"),
    (17, 68): ServiceDefinition(17, 68, "DHCP client"),
    (17, 69): ServiceDefinition(17, 69, "TFTP"),
    (17, 123): ServiceDefinition(17, 123, "NTP"),
    (17, 137): ServiceDefinition(17, 137, "NetBIOS name"),
    (17, 138): ServiceDefinition(17, 138, "NetBIOS datagram"),
    (17, 161): ServiceDefinition(17, 161, "SNMP"),
    (17, 162): ServiceDefinition(17, 162, "SNMP trap"),
    (17, 500): ServiceDefinition(17, 500, "IKE"),
    (17, 514): ServiceDefinition(17, 514, "Syslog"),
    (17, 520): ServiceDefinition(17, 520, "RIP"),
    (17, 1701): ServiceDefinition(17, 1701, "L2TP"),
    (17, 1812): ServiceDefinition(17, 1812, "RADIUS authentication"),
    (17, 1813): ServiceDefinition(17, 1813, "RADIUS accounting"),
    (17, 4500): ServiceDefinition(17, 4500, "IPsec NAT-T"),
    (17, 4789): ServiceDefinition(17, 4789, "VXLAN"),
}

SERVICE_DEFINITIONS = MappingProxyType(_SERVICE_DEFINITIONS)


def protocol_definition(number: int) -> ProtocolDefinition | None:
    """Return a known static definition, leaving unknown numbers unclassified."""

    _validate_protocol(number)
    return PROTOCOL_DEFINITIONS.get(number)


def protocol_label(number: int) -> str:
    """Return a stable label that always retains the on-device numeric value."""

    definition = protocol_definition(number)
    if definition is None:
        return f"Protocol {number}"
    return f"{definition.keyword} ({number})"


def service_definition(protocol: int, port: int) -> ServiceDefinition | None:
    """Return a service only when both protocol and port match the catalogue."""

    _validate_protocol(protocol)
    _validate_port(port)
    return SERVICE_DEFINITIONS.get((protocol, port))


def service_label(protocol: int, port: int) -> str:
    """Return ``NAME (port)`` for a known pair, otherwise the numeric port."""

    definition = service_definition(protocol, port)
    if definition is None:
        return str(port)
    return f"{definition.label} ({port})"


def _validate_protocol(number: int) -> None:
    if type(number) is not int:
        raise TypeError("Protocol number must be an integer.")
    if not 0 <= number <= 255:
        raise ValueError("Protocol number must be in the 0..255 range.")


def _validate_port(port: int) -> None:
    if type(port) is not int:
        raise TypeError("Port must be an integer.")
    if not 0 <= port <= 65535:
        raise ValueError("Port must be in the 0..65535 range.")
