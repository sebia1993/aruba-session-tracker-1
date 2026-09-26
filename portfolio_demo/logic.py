"""Offline public fixture transport; reuse the production AOS parsers and flags."""

import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from aruba_session_tracker.parsers import (  # noqa: E402 - standalone demo source bootstrap
    ParseError,
    overall_flag_severity,
    parse_datapath_sessions,
    parse_global_user_table,
)

DATA = ROOT / "portfolio_demo" / "demo_data"
SCENARIOS = {
    "sessions": "세션 존재",
    "empty": "세션 없음 · 정상 수집",
    "collection_failed": "CLI 수집 실패",
    "parse_failed": "Parsing 실패",
}
CLIENTS = {
    "192.0.2.10": "00:00:5e:00:53:01",
    "192.0.2.20": "00:00:5e:00:53:02",
    "192.0.2.30": "00:00:5e:00:53:03",
}


def run_demo(scenario: str, client: str):
    if scenario not in SCENARIOS or client not in CLIENTS:
        raise ValueError("공개 샘플 Client IP 또는 MAC만 입력하세요.")

    def read(name):
        return (
            (DATA / name)
            .read_text(encoding="utf-8")
            .replace("192.0.2.10", client)
            .replace(CLIENTS["192.0.2.10"], CLIENTS[client])
        )

    raw = {"show global-user-table": read("global_user_one.txt")}
    lookup = parse_global_user_table(raw["show global-user-table"], client_ip=client)
    context = [asdict(e) for e in lookup.entries]
    trace = ["MM global-user-table 파싱 완료", f"관련 MD 식별: {lookup.current_switch}"]
    result = {
        "client": client,
        "context": context,
        "trace": trace,
        "raw": raw,
        "rows": [],
        "authoritative": False,
    }
    if scenario == "collection_failed":
        result.update(
            status="Unknown / Collection Error",
            reason="합성 MD Timeout: 세션 종료로 판단하지 않습니다.",
        )
        raw["show datapath session table"] = "[수집 실패 · 출력 없음]"
        return result
    filename = {
        "sessions": "datapath_sessions.txt",
        "empty": "datapath_empty.txt",
        "parse_failed": "datapath_truncated.txt",
    }[scenario]
    raw["show datapath session table"] = read(filename)
    try:
        observations = parse_datapath_sessions(
            raw["show datapath session table"],
            controller_name="DEMO-MD",
            controller_host=lookup.current_switch,
        )
    except ParseError:
        result.update(
            status="Unknown / Parsing Error",
            reason="불완전 CLI: 세션 0개 또는 종료로 판단하지 않습니다.",
        )
        return result
    result["rows"] = [
        {
            "Source": s.source_ip,
            "Destination": s.destination_ip,
            "Protocol": {6: "TCP", 17: "UDP"}.get(s.protocol, str(s.protocol)),
            "Source Port": s.source_port,
            "Port": s.destination_port,
            "Flags": s.flags,
            "Flag Severity": overall_flag_severity(s.flags).value,
            "Controller": s.controller_host,
            "State": "관측됨",
        }
        for s in observations
    ]
    trace.append("MD datapath 파싱 완료")
    result.update(
        authoritative=True,
        status="Active Sessions" if observations else "No Active Session",
        reason=(
            "정상 수집 및 완전한 CLI 파싱 결과입니다. Flags로 TCP 연결 상태를 단정하지 않습니다."
        ),
    )
    return result
