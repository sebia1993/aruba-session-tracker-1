"""Official AOS 8 datapath-session flag interpretations.

The symbols are case-sensitive.  Descriptions follow the HPE Aruba Networking
AOS 8 CLI reference for ``show datapath session``.  Severity is an application
triage hint, not a claim that the controller is unhealthy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


class FlagSeverity(StrEnum):
    NORMAL = "NORMAL"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    CHECK = "CHECK"


_SEVERITY_RANK = {
    FlagSeverity.NORMAL: 0,
    FlagSeverity.NOTICE: 1,
    FlagSeverity.CHECK: 2,
    FlagSeverity.WARNING: 3,
    FlagSeverity.CRITICAL: 4,
}


@dataclass(frozen=True, slots=True)
class FlagDefinition:
    symbol: str
    description: str
    label_ko: str
    severity: FlagSeverity = FlagSeverity.NORMAL


@dataclass(frozen=True, slots=True)
class InterpretedFlag:
    symbol: str
    description: str
    label_ko: str
    severity: FlagSeverity
    is_known: bool


_FLAG_DEFINITIONS = {
    "F": FlagDefinition("F", "fast age", "빠른 만료"),
    "S": FlagDefinition("S", "source NAT", "소스 NAT"),
    "N": FlagDefinition("N", "destination NAT", "대상 NAT"),
    "D": FlagDefinition("D", "deny", "차단", FlagSeverity.CRITICAL),
    "R": FlagDefinition("R", "redirect", "리디렉션", FlagSeverity.NOTICE),
    "Y": FlagDefinition("Y", "no SYN", "SYN 없음", FlagSeverity.WARNING),
    "H": FlagDefinition("H", "high priority", "높은 우선순위"),
    "P": FlagDefinition("P", "set priority", "우선순위 설정"),
    "T": FlagDefinition("T", "set ToS", "ToS 설정"),
    "C": FlagDefinition("C", "client", "클라이언트"),
    "M": FlagDefinition("M", "mirror", "미러"),
    "V": FlagDefinition("V", "VoIP", "VoIP"),
    "Q": FlagDefinition("Q", "Real-Time Quality analysis", "실시간 품질 분석"),
    "u": FlagDefinition("u", "upstream Real-Time Quality analysis", "업스트림 실시간 품질 분석"),
    "I": FlagDefinition("I", "deep inspect", "심층 검사"),
    "U": FlagDefinition("U", "locally destined", "로컬 목적지"),
    "E": FlagDefinition("E", "media deep inspect", "미디어 심층 검사"),
    "G": FlagDefinition("G", "media signal", "미디어 신호"),
    "r": FlagDefinition("r", "route nexthop", "라우트 넥스트홉"),
    "h": FlagDefinition("h", "high value", "중요 세션"),
    "A": FlagDefinition("A", "application firewall inspect", "애플리케이션 방화벽 검사"),
    "i": FlagDefinition("i", "session classified on first packet", "첫 패킷에서 분류"),
    "J": FlagDefinition("J", "SD-WAN default probe fallback", "SD-WAN 기본 프로브 대체 통계"),
    "X": FlagDefinition("X", "SD-WAN exception", "SD-WAN 예외"),
    "x": FlagDefinition("x", "translation", "변환"),
    "B": FlagDefinition("B", "permanent", "영구"),
    "O": FlagDefinition("O", "OpenFlow", "OpenFlow"),
    "L": FlagDefinition("L", "log", "로그"),
    "o": FlagDefinition("o", "OpenFlow config revision mismatched", "OpenFlow 구성 리비전 불일치"),
}

FLAG_DEFINITIONS = MappingProxyType(_FLAG_DEFINITIONS)


def interpret_flags(flags: str) -> tuple[InterpretedFlag, ...]:
    """Interpret every case-sensitive flag without silently dropping unknowns."""

    if not isinstance(flags, str):
        raise TypeError("Flags must be text.")
    interpreted: list[InterpretedFlag] = []
    for symbol in flags:
        if symbol.isspace() or symbol == "-":
            continue
        definition = FLAG_DEFINITIONS.get(symbol)
        if definition is None:
            interpreted.append(
                InterpretedFlag(
                    symbol=symbol,
                    description="unknown flag; check the device CLI reference",
                    label_ko="알 수 없는 플래그(확인 필요)",
                    severity=FlagSeverity.CHECK,
                    is_known=False,
                )
            )
        else:
            interpreted.append(
                InterpretedFlag(
                    symbol=symbol,
                    description=definition.description,
                    label_ko=definition.label_ko,
                    severity=definition.severity,
                    is_known=True,
                )
            )
    return tuple(interpreted)


def overall_flag_severity(flags: str) -> FlagSeverity:
    """Return the most actionable severity without hiding known warning flags."""

    interpreted = interpret_flags(flags)
    return max(
        (item.severity for item in interpreted),
        key=_SEVERITY_RANK.__getitem__,
        default=FlagSeverity.NORMAL,
    )
