"""Synthetic CLI transport only; production code builds and parses all queries."""

from contextlib import AbstractContextManager
from ipaddress import IPv4Address

from aruba_session_tracker.collectors import CollectorError
from aruba_session_tracker.commands import build_datapath_session_command, build_global_user_command
from aruba_session_tracker.models import AppConfig, DeviceTarget, ErrorCode

CONFIG = AppConfig(
    DeviceTarget("DEMO-MM-PRIMARY", "192.0.2.1"),
    DeviceTarget("DEMO-MM-STANDBY", "192.0.2.2"),
    tuple(DeviceTarget(f"DEMO-MD-{n:02}", f"192.0.2.{100 + n}") for n in range(1, 5)),
    location_interval_seconds=10,
)
STAGES = (
    "초기 관측",
    "Counter / Flags change",
    "Controller overlap",
    "Controller move",
    "Collection failure",
    "MISS 1",
    "Parsing failure",
    "MISS 2 + MM refresh",
    "MISS 3 / CLOSED",
    "Re-observed",
)
GLOBAL_HEADER = "IP              MAC                Name              Current switch    Role"
DATAPATH_HEADER = (
    "Datapath Session Table Entries\n------------------------------\n"
    "Source IP or MAC Destination IP Prot SPort DPort Cntr Prio ToS Age Destination TAge Packets Bytes Flags CPU ID\n"
    "---------------- ---------------- ---- ----- ----- ---- ---- --- --- ----------- ---- ------- ----- ----- ------\n"
)


def inventory():
    return [
        {
            "Client": f"198.51.100.{n}",
            "Destination": f"203.0.113.{20 + n % 3}",
            "Home MD": f"DEMO-MD-{n % 4 + 1:02}",
            "TCP": 443,
            "UDP": 53,
        }
        for n in range(10, 22)
    ]


def home(ip):
    return f"192.0.2.{101 + int(ip.rsplit('.', 1)[1]) % 4}"


def global_output(ip, switch):
    row = [" "] * 100
    for label, value in [
        ("IP", ip),
        ("MAC", "02:00:00:00:00:10"),
        ("Name", "demo"),
        ("Current switch", switch or ""),
        ("Role", "demo-role"),
    ]:
        start = GLOBAL_HEADER.index(label)
        row[start : start + len(value)] = value
    return (
        GLOBAL_HEADER
        + "\n"
        + "-" * len(GLOBAL_HEADER)
        + "\n"
        + ("".join(row).rstrip() + "\nTotal entries = 1\n" if switch else "Total entries = 0\n")
    )


class FixtureConnection(AbstractContextManager):
    def __init__(self, factory, target):
        self.factory, self.target = factory, target

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def close(self):
        pass

    def send_command(self, command, *, read_timeout):
        del read_timeout
        f = self.factory
        f.trace.append({"Device": self.target.name, "Command": command})
        if command == "no paging":
            return ""
        if command.startswith("show global-user-table list ip "):
            ip = str(IPv4Address(command.rsplit(" ", 1)[1].strip('"')))
            if command != build_global_user_command(ip):
                raise ValueError("Non-canonical query")
            exists = ip in {x["Client"] for x in inventory()} | {
                x["Destination"] for x in inventory()
            }
            owner = home(ip)
            if f.tick >= 2:
                owner = f.moved(owner)
            return global_output(ip, owner if exists else None)
        ip = str(IPv4Address(command.rsplit(" ", 1)[1]))
        if command != build_datapath_session_command(ip):
            raise ValueError("Filtered query required")
        if f.mode == "timeout" or (f.mode == "timeline" and f.tick == 4):
            raise CollectorError(
                ErrorCode.MD_UNREACHABLE, "Synthetic timeout", retryable_network=True
            )
        if f.mode == "parse" or (f.mode == "timeline" and f.tick == 6):
            return "truncated synthetic CLI"
        lines = []
        if not (f.mode == "timeline" and f.tick in (5, 7, 8)):
            for client in inventory():
                src, dst = client["Client"], client["Destination"]
                owners = {home(src)} if f.tick < 2 else {f.moved(home(src))}
                if f.tick == 2:
                    owners.add(home(src))
                if self.target.host not in owners or ip not in (src, dst):
                    continue
                n = int(src.rsplit(".", 1)[1])
                for source, dest, proto, sport, dport in (
                    (src, dst, 6, 40000 + n, 443),
                    (dst, src, 6, 443, 40000 + n),
                    (src, dst, 17, 50000 + n, 53),
                ):
                    flags = "SY" if f.tick == 0 else "F"
                    lines.append(
                        f"{source} {dest} {proto} {sport} {dport} 0/0 0 0 10 0 0 {5 + f.tick} {100 + f.tick * 20} {flags} 0"
                    )
        return DATAPATH_HEADER + "\n".join(lines) + f"\nEntries: {len(lines)}\n"


class FixtureFactory:
    def __init__(self):
        self.tick = 0
        self.mode = "timeline"
        self.trace = []

    @staticmethod
    def moved(owner):
        return f"192.0.2.{101 + (int(owner.rsplit('.', 1)[1]) - 100) % 4}"

    def connect(self, target, credentials, *, host_key_approval, cancel_token, deadline):
        del credentials, host_key_approval
        cancel_token.raise_if_cancelled()
        deadline.raise_if_expired()
        if target not in (CONFIG.mm_primary, CONFIG.mm_standby, *CONFIG.managed_devices):
            raise ValueError("Unknown demo target")
        return FixtureConnection(self, target)
