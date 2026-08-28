# ruff: noqa: E501
"""Deterministic, offline HTML5 result reports for one stored run."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from html import escape
from pathlib import Path

from aruba_session_tracker.parsers.flags import interpret_flags, overall_flag_severity

ReportRow = dict[str, object]

HTML_OBSERVATION_LIMIT = 2_000
HTML_LIFECYCLE_LIMIT = 1_000
HTML_CONTROLLER_LIMIT = 500
HTML_DIAGNOSTIC_LIMIT = 500
HTML_RAW_FILE_LIMIT = 500

_IPV4_TEXT = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_CREDENTIAL_TEXT = re.compile(
    r"(?i)\b(username|user|password|passwd|secret|token)\s*[:=]\s*([^\s,;]+)"
)
_DETAIL_KEYS = {
    "miss_count": "MISS 횟수",
    "previous_flags": "이전 Flags",
    "packet_delta": "Packet 변화",
    "byte_delta": "Byte 변화",
}
_TROUBLESHOOTING = {
    "AUTH_FAILED": "계정과 읽기 권한을 확인하십시오. 인증 실패는 Standby 자동 우회 조건이 아닙니다.",
    "COMMAND_REJECTED": "허용된 필터형 명령인지와 AOS 버전의 명령 구문을 확인하십시오.",
    "COMMAND_VARIANT_UNVERIFIED": "전체 세션 조회로 전환하지 말고 장비 버전별 필터 구문을 확인하십시오.",
    "CLIENT_NOT_FOUND_ON_MM": "MM 사용자 위치와 대상 IP를 확인하십시오. 빈 결과를 장애로 단정하지 마십시오.",
    "CURRENT_SWITCH_AMBIGUOUS": "MM 출력의 Current switch 후보가 하나인지 확인하십시오.",
    "CURRENT_SWITCH_UNMAPPED": "Current switch 이름과 등록된 MD 이름의 매핑을 확인하십시오.",
    "HOST_KEY_CHANGED": "연결을 중단하고 승인된 경로로 장비 SSH 지문 변경 사유를 확인하십시오.",
    "HOST_KEY_UNKNOWN": "장비와 지문을 별도 경로로 확인한 뒤 프로그램에서 명시적으로 승인하십시오.",
    "MD_UNREACHABLE": "MD 경로, TCP/22, 시간 초과와 점검 창을 확인하십시오.",
    "MM_UNREACHABLE": "MM 경로, TCP/22와 시간 초과를 확인하십시오. 장비 다운의 증거는 아닙니다.",
    "OUTPUT_LIMIT_EXCEEDED": "필터가 실제로 적용됐는지 확인하고 전체 출력으로 우회하지 마십시오.",
    "PARSE_PARTIAL": "Raw TXT를 로컬에서 검토하고 미해석 값을 임의로 보완하지 마십시오.",
    "PROMPT_PARSE_FAILED": "배너, 프롬프트와 paging 동작을 확인하십시오.",
    "SESSION_NOT_FOUND": "조회 시각과 방향·포트 조건을 확인하십시오. 세션 종료로 단정하지 마십시오.",
    "CANCELLED": "사용자 취소 또는 중지 시각을 확인하십시오.",
}


@dataclass(frozen=True, slots=True)
class RunReportSnapshot:
    """Stable database snapshot used to render one report."""

    run: ReportRow
    controllers: tuple[str, ...]
    mm_controllers: tuple[str, ...]
    md_controllers: tuple[str, ...]
    observations: tuple[ReportRow, ...]
    observation_total: int
    unique_session_total: int
    lifecycle_events: tuple[ReportRow, ...]
    lifecycle_total: int
    lifecycle_counts: tuple[tuple[str, int], ...]
    controller_events: tuple[ReportRow, ...]
    controller_total: int
    diagnostics: tuple[ReportRow, ...]
    diagnostic_total: int
    raw_files: tuple[ReportRow, ...]
    raw_file_total: int
    raw_byte_total: int


def render_html_report(snapshot: RunReportSnapshot) -> str:
    """Return a standalone HTML5 report with no external resource dependency."""

    run = snapshot.run
    status = str(run.get("status") or "확인 필요")
    source_ip = run.get("source_ip")
    destination_ip = run.get("destination_ip")
    controllers = snapshot.controllers
    mm_controllers = snapshot.mm_controllers
    md_controllers = snapshot.md_controllers
    severity_counts = {name: 0 for name in ("NORMAL", "NOTICE", "CHECK", "WARNING", "CRITICAL")}
    for row in snapshot.observations:
        severity_counts[overall_flag_severity(str(row.get("flags") or "")).value] += 1

    observation_rows = "".join(_observation_row(row) for row in snapshot.observations)
    lifecycle_rows = "".join(_lifecycle_row(row) for row in snapshot.lifecycle_events)
    controller_rows = "".join(_controller_row(row) for row in snapshot.controller_events)
    diagnostic_rows = "".join(_diagnostic_row(row) for row in snapshot.diagnostics)
    raw_rows = "".join(_raw_row(row) for row in snapshot.raw_files)
    lifecycle_badges = (
        "".join(
            f'<span class="badge neutral">{_e(name)} {_e(count)}</span>'
            for name, count in snapshot.lifecycle_counts
        )
        or '<span class="muted">기록 없음</span>'
    )
    troubleshooting = _troubleshooting_cards(snapshot.diagnostics)
    status_note = _status_note(status)
    query_direction = "양방향" if bool(run.get("bidirectional")) else "단방향"

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Aruba Session Tracker 결과 보고서</title>
  <style>
    :root {{ color-scheme: light; --navy:#102a43; --blue:#1769aa; --ink:#243b53;
      --muted:#627d98; --line:#d9e2ec; --paper:#fff; --bg:#f3f6f9;
      --ok:#147d64; --notice:#805ad5; --warn:#b7791f; --danger:#c53030; }}
    * {{ box-sizing:border-box; }}
    html {{ scroll-behavior:smooth; }}
    body {{ margin:0; overflow-x:hidden; background:var(--bg); color:var(--ink); font-family:system-ui,
      -apple-system,"Segoe UI","Malgun Gothic",sans-serif; line-height:1.55; }}
    a {{ color:var(--blue); }} a:focus-visible, summary:focus-visible {{ outline:3px solid #63b3ed; }}
    .hero {{ color:#fff; background:linear-gradient(130deg,#102a43,#1769aa); padding:34px 28px; }}
    .hero-inner {{ max-width:1440px; min-width:0; margin:auto; overflow-wrap:anywhere; }} .hero h1 {{ margin:8px 0; font-size:clamp(1.8rem,4vw,3rem); }}
    .run-meta {{ display:flex; flex-wrap:wrap; gap:.35rem; align-items:center; }} .run-id {{ min-width:0; max-width:100%; overflow-wrap:anywhere; }}
    .eyebrow {{ letter-spacing:.08em; font-weight:700; text-transform:uppercase; opacity:.85; }}
    .layout {{ max-width:1440px; margin:0 auto; display:grid; grid-template-columns:230px minmax(0,1fr); gap:22px; padding:22px; }}
    nav {{ position:sticky; top:16px; align-self:start; min-width:0; max-width:100%; background:var(--paper); border:1px solid var(--line); border-radius:14px; padding:14px; box-shadow:0 8px 24px #102a4312; }}
    nav strong {{ display:block; margin-bottom:8px; }} nav a {{ display:block; padding:7px 8px; border-radius:7px; text-decoration:none; }} nav a:hover {{ background:#ebf8ff; }}
    main {{ min-width:0; max-width:100%; }} section {{ min-width:0; max-width:100%; scroll-margin-top:14px; background:var(--paper); border:1px solid var(--line); border-radius:14px; padding:22px; margin-bottom:18px; box-shadow:0 8px 24px #102a430d; }}
    h2 {{ color:var(--navy); margin-top:0; }} h3 {{ color:var(--navy); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }}
    .card {{ border:1px solid var(--line); border-radius:11px; padding:15px; background:#fbfdff; min-width:0; }}
    .metric {{ font-size:1.7rem; font-weight:750; color:var(--navy); overflow-wrap:anywhere; }}
    .label {{ color:var(--muted); font-size:.88rem; }}
    .badge {{ display:inline-block; border-radius:999px; padding:3px 9px; margin:2px; font-size:.78rem; font-weight:700; background:#e6fffa; color:var(--ok); }}
    .badge.notice {{ background:#faf5ff; color:var(--notice); }} .badge.check,.badge.warning {{ background:#fffaf0; color:var(--warn); }}
    .badge.critical {{ background:#fff5f5; color:var(--danger); }} .badge.neutral {{ background:#edf2f7; color:#486581; }}
    .info,.warning {{ border-left:5px solid var(--blue); background:#ebf8ff; padding:14px 16px; border-radius:8px; margin:12px 0; }}
    .warning {{ border-left-color:var(--warn); background:#fffaf0; }}
    .flow {{ display:grid; grid-template-columns:repeat(7,minmax(90px,1fr)); align-items:center; gap:8px; text-align:center; }}
    .node {{ border:1px solid #9fb3c8; border-radius:10px; padding:14px 8px; background:#f8fbff; font-weight:700; }} .arrow {{ color:var(--blue); font-size:1.5rem; }}
    .table-wrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:10px; }} .table-wrap:focus-visible {{ outline:3px solid #63b3ed; outline-offset:2px; }}
    table {{ width:100%; min-width:760px; border-collapse:collapse; font-size:.88rem; }}
    th,td {{ padding:9px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }} th {{ background:#f0f4f8; color:var(--navy); position:sticky; top:0; }}
    tr:last-child td {{ border-bottom:0; }} code,pre {{ font-family:"Cascadia Mono",Consolas,monospace; }}
    .terminal {{ background:#0b1f33; color:#d9e2ec; border-radius:10px; padding:14px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; }}
    details {{ border:1px solid var(--line); border-radius:10px; margin:10px 0; background:#fff; }} summary {{ cursor:pointer; font-weight:700; padding:12px 14px; }} details>div {{ padding:0 14px 14px; }}
    .muted {{ color:var(--muted); }} .truncate-note {{ color:var(--warn); font-weight:650; }} .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
    .footer {{ max-width:1440px; margin:0 auto; padding:0 22px 28px; color:var(--muted); }}
    @media (max-width:850px) {{ .layout {{ grid-template-columns:minmax(0,1fr); padding:12px; }} nav {{ position:static; display:flex; gap:4px; overflow-x:auto; white-space:nowrap; }} nav strong {{ display:none; }} nav a {{ display:inline-block; }} section {{ padding:16px; }} .flow {{ grid-template-columns:1fr; }} .arrow {{ transform:rotate(90deg); }} }}
    @media (max-width:600px) {{ .hero {{ padding:26px 18px; }} .hero h1 {{ word-break:keep-all; overflow-wrap:break-word; }} .grid {{ grid-template-columns:minmax(0,1fr); }} .metric {{ font-size:1.45rem; }} }}
    @page {{ size:A4 landscape; margin:10mm; }}
    @media print {{ body {{ background:#fff; color:#000; }} .hero {{ background:#fff; color:#000; padding:12px 0; }} .layout {{ display:block; padding:0; }} nav {{ display:none; }} section {{ box-shadow:none; border:1px solid #bbb; break-inside:auto; margin-bottom:10px; }} details,.card,tr {{ break-inside:avoid; }} details>div {{ display:block; }} .table-wrap {{ overflow:visible; border:0; }} table {{ min-width:0; font-size:7.5pt; }} thead {{ display:table-header-group; }} th,td {{ padding:4px; overflow-wrap:anywhere; }} th {{ position:static; }} .footer {{ padding:0; }} }}
    @media (prefers-reduced-motion:reduce) {{ html {{ scroll-behavior:auto; }} }}
  </style>
</head>
<body>
  <header class="hero"><div class="hero-inner">
    <div class="eyebrow">Network Engineering Result Report</div>
    <h1>Aruba Session Tracker 결과 보고서</h1>
    <div class="run-meta"><span class="run-id">Run ID: {_e(run.get("id"))}</span><span>· 상태: {_status_badge(status)}</span></div>
  </div></header>
  <div class="layout">
    <nav aria-label="문서 목차"><strong>목차</strong>
      <a href="#summary">Executive Summary</a><a href="#environment">환경·조회 조건</a>
      <a href="#flow">조회 흐름</a><a href="#sessions">세션 결과</a>
      <a href="#lifecycle">수명주기</a><a href="#diagnostics">진단·검증</a>
      <a href="#evidence">수집 증거</a><a href="#troubleshooting">Troubleshooting</a>
      <a href="#quick-reference">Quick Reference</a><a href="#warnings">Warning</a>
    </nav>
    <main>
      <section id="summary"><h2>Executive Summary</h2>
        <div class="grid">
          {_metric("실행 상태", status)}{_metric("전체 관측 행", snapshot.observation_total)}
          {_metric("고유 세션 키", snapshot.unique_session_total)}{_metric("수명주기 이벤트", snapshot.lifecycle_total)}
          {_metric("Controller", len(controllers))}{_metric("진단 이벤트", snapshot.diagnostic_total)}
        </div>
        <div class="info"><strong>판독 기준</strong><br>{_e(status_note)} 수집 성공이나 빈 결과만으로 장비 정상·장애 또는 세션 종료를 단정하지 않습니다.</div>
        {_time_range_warning(run)}
      </section>
      <section id="environment"><h2>환경정보와 조회 조건</h2>
        <div class="grid">
          {_kv("Vendor", "HPE Aruba Networking")}{_kv("장비 지원 기준", "Aruba 7240XM")}
          {_kv("OS 지원 기준", "AOS 8.10.0.10_89128")}{_kv("실제 장비 모델/펌웨어", "미수집 / 확인 필요")}
          {_kv("Source", source_ip)}{_kv("Destination", destination_ip)}
          {_kv("SPort", run.get("source_port"))}{_kv("DPort", run.get("destination_port"))}
          {_kv("방향", query_direction)}{_kv("시작(UTC)", run.get("started_at"))}
          {_kv("종료(UTC)", run.get("ended_at"))}{_kv("관측 Controller", ", ".join(controllers) or "확인 필요")}
        </div>
        <div class="warning"><strong>확인 필요</strong><br>VLAN, SSID, Role, ACL, 인터페이스와 물리 토폴로지는 이 실행 기록에 저장되지 않았으므로 보고서가 추측하지 않습니다.</div>
      </section>
      <section id="flow"><h2>프로그램 조회 흐름</h2>
        <div class="flow" role="img" aria-label="Source와 Destination을 MM에서 확인하고 관련 MD의 datapath 세션을 조회한 뒤 로컬에 저장하는 흐름">
          <div class="node">Source / Destination</div><div class="arrow">→</div>
          <div class="node">MM 위치 확인<br><span class="muted">{_e(", ".join(mm_controllers) or "기록 확인 필요")}</span></div><div class="arrow">→</div>
          <div class="node">관련 MD 조회<br><span class="muted">{_e(", ".join(md_controllers) or "기록 확인 필요")}</span></div><div class="arrow">→</div>
          <div class="node">SQLite / Raw / Report</div>
        </div>
        <p>Source MD를 우선 조회하고 조건에 따라 Destination MD를 추가 확인합니다. 두 IP 모두 MM에 없을 때의 활성 MD 순차 조회는 사용자 승인이 필요합니다. 이 그림은 물리 네트워크 토폴로지가 아니라 프로그램의 읽기 전용 처리 순서입니다.</p>
      </section>
      <section id="sessions"><h2>세션 결과와 Flags</h2>
        <p>{_severity_badges(severity_counts)}</p>
        {_truncation("최신 고유 세션", len(snapshot.observations), snapshot.unique_session_total)}
        <div class="table-wrap" role="region" aria-label="최신 고유 세션 표" tabindex="0"><table><caption class="sr-only">최신 고유 세션</caption><thead><tr><th scope="col">마지막 관측</th><th scope="col">Controller</th><th scope="col">Protocol</th><th scope="col">Source</th><th scope="col">Destination</th><th scope="col">Packets</th><th scope="col">Bytes</th><th scope="col">Age</th><th scope="col">Flags 해석</th><th scope="col">CPU</th></tr></thead><tbody>{observation_rows or _empty_row(10, "관측된 세션이 없습니다.")}</tbody></table></div>
      </section>
      <section id="lifecycle"><h2>수명주기와 Controller 전환</h2>
        <p>{lifecycle_badges}</p>
        {_truncation("수명주기 이벤트", len(snapshot.lifecycle_events), snapshot.lifecycle_total)}
        <div class="table-wrap" role="region" aria-label="수명주기 이벤트 표" tabindex="0"><table><caption class="sr-only">수명주기 이벤트</caption><thead><tr><th scope="col">시각</th><th scope="col">이벤트</th><th scope="col">인스턴스</th><th scope="col">Controller</th><th scope="col">세부 정보</th></tr></thead><tbody>{lifecycle_rows or _empty_row(5, "수명주기 이벤트가 없습니다.")}</tbody></table></div>
        <h3>Controller 변경</h3>{_truncation("Controller 전환", len(snapshot.controller_events), snapshot.controller_total)}
        <div class="table-wrap" role="region" aria-label="Controller 전환 표" tabindex="0"><table><caption class="sr-only">Controller 전환</caption><thead><tr><th scope="col">시각</th><th scope="col">이전</th><th scope="col">현재</th><th scope="col">사유</th></tr></thead><tbody>{controller_rows or _empty_row(4, "Controller 전환 기록이 없습니다.")}</tbody></table></div>
      </section>
      <section id="diagnostics"><h2>확인 및 검증 결과</h2>
        <p>진단 메시지는 저장 시 비식별 처리되고 보고서 생성 시 다시 마스킹됩니다. 오류 코드는 점검 단서이며 장비 장애의 확정 증거가 아닙니다.</p>
        {_truncation("진단 이벤트", len(snapshot.diagnostics), snapshot.diagnostic_total)}
        <div class="table-wrap" role="region" aria-label="진단 이벤트 표" tabindex="0"><table><caption class="sr-only">진단 이벤트</caption><thead><tr><th scope="col">시각</th><th scope="col">단계</th><th scope="col">코드</th><th scope="col">메시지</th></tr></thead><tbody>{diagnostic_rows or _empty_row(4, "기록된 진단 이벤트가 없습니다.")}</tbody></table></div>
      </section>
      <section id="evidence"><h2>수집 증거</h2>
        <div class="grid">{_metric("Raw 파일", snapshot.raw_file_total)}{_metric("Raw 전체 크기", _format_bytes(snapshot.raw_byte_total))}</div>
        <p>Raw CLI 본문과 파일 경로는 보고서에 포함하지 않습니다. 아래 DB ID, 메타데이터와 저장 당시 SHA-256 기록을 사용해 SQLite의 Raw 파일 레코드와 대조하십시오.</p>
        {_truncation("Raw 파일", len(snapshot.raw_files), snapshot.raw_file_total)}
        <div class="table-wrap" role="region" aria-label="Raw 수집 증거 표" tabindex="0"><table><caption class="sr-only">Raw 수집 증거</caption><thead><tr><th scope="col">DB ID</th><th scope="col">수집 시각</th><th scope="col">종류</th><th scope="col">Controller</th><th scope="col">크기</th><th scope="col">SHA-256</th></tr></thead><tbody>{raw_rows or _empty_row(6, "Raw 파일 기록이 없습니다.")}</tbody></table></div>
      </section>
      <section id="troubleshooting"><h2>Troubleshooting</h2>{troubleshooting}</section>
      <section id="quick-reference"><h2>CLI와 Quick Reference</h2>
        <div class="warning">아래는 프로그램에서 허용하는 읽기 전용 명령 형식입니다. 이 보고서는 각 명령이 실제로 실행됐다고 추정하지 않으며, 무필터 전체 세션 조회로 전환하지 않습니다.</div>
        {_command_card(f'show global-user-table list ip "{source_ip or "<IPv4>"}"', "MM에서 대상 IP의 Current switch 위치 확인", "단일 Current switch 또는 명시적인 빈 결과")}
        {_command_card("no paging", "현재 SSH 세션의 paging 비활성화", "필터형 출력이 중간에서 잘리지 않도록 준비")}
        {_command_card(f"show datapath session table {source_ip or '<IPv4>'}", "관련 MD에서 대상 IP의 필터형 datapath 세션 조회", "헤더·세션 행·Entries footer가 완전한 제한 출력")}
        <div class="grid">{_kv("MM 기록", ", ".join(mm_controllers) or "확인 필요")}{_kv("MD 기록", ", ".join(md_controllers) or "확인 필요")}{_kv("전체 행 데이터", "CSV / SQLite")}{_kv("Raw 원문", "%LOCALAPPDATA%\\ArubaSessionTracker\\raw")}</div>
      </section>
      <section id="warnings"><h2>Warning / 주의사항</h2>
        <div class="warning"><strong>민감정보</strong><br>이 파일에는 내부 IP, 장비명과 세션 메타데이터가 포함될 수 있습니다. 외부 공유 전 HTML 원문을 검토하고 필요한 값을 제거하십시오.</div>
        <div class="warning"><strong>증거 경계</strong><br>보고서는 저장된 실행 결과를 정리할 뿐 실제 장비 호환성, 네트워크 정상 상태, 세션 종료, 코드 서명 또는 현장 검증을 증명하지 않습니다.</div>
        <div class="info"><strong>오프라인 문서</strong><br>외부 CSS, JavaScript, 이미지, 웹폰트와 CDN을 사용하지 않습니다. Raw CLI 본문과 자격증명도 포함하지 않습니다.</div>
      </section>
    </main>
  </div>
  <footer class="footer">보고서 기준 시각: {_e(run.get("ended_at") or run.get("started_at"))} · Aruba Session Tracker · 실행 스냅샷 기반</footer>
</body>
</html>
"""


def write_html_report_atomic(destination: Path | str, snapshot: RunReportSnapshot) -> Path:
    """Atomically write one deterministic UTF-8 report."""

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(render_html_report(snapshot))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return path


def _e(value: object) -> str:
    if value is None or value == "":
        return "확인 필요"
    return escape(str(value), quote=True)


def _metric(label: str, value: object) -> str:
    return f'<div class="card"><div class="label">{_e(label)}</div><div class="metric">{_e(value)}</div></div>'


def _kv(label: str, value: object) -> str:
    return (
        f'<div class="card"><div class="label">{_e(label)}</div><strong>{_e(value)}</strong></div>'
    )


def _status_badge(status: str) -> str:
    if status in {"FAILED", "INTERRUPTED", "PARTIAL"}:
        kind = "warning"
    elif status == "COMPLETED":
        kind = ""
    else:
        kind = "neutral"
    return f'<span class="badge {kind}">{_e(status)}</span>'


def _status_note(status: str) -> str:
    return {
        "COMPLETED": "수집 절차가 완료됐습니다. 이는 장비 정상 판정이 아닙니다.",
        "STOPPED": "모니터링이 중지됐습니다. 사용자 요청에 따른 정상 중지일 수 있습니다.",
        "PARTIAL": "일부 결과만 신뢰할 수 있으므로 진단 코드와 Raw 증거를 함께 확인하십시오.",
        "FAILED": "수집이 완료되지 않았습니다. 빈 결과를 세션 부재로 해석하지 마십시오.",
        "INTERRUPTED": "이전 실행이 정상 종료 기록 없이 중단됐습니다.",
        "RESTARTED": "모니터 조건 변경으로 실행이 교체됐습니다.",
    }.get(status, "상태 의미를 확인하십시오.")


def _severity_badges(counts: dict[str, int]) -> str:
    return " ".join(
        f'<span class="badge {name.casefold()}">{name} {_e(count)}</span>'
        for name, count in counts.items()
    )


def _observation_row(row: ReportRow) -> str:
    flags = str(row.get("flags") or "")
    interpreted = interpret_flags(flags)
    flag_text = (
        ", ".join(f"{item.symbol}: {item.label_ko} [{item.severity.value}]" for item in interpreted)
        or "Flags 없음"
    )
    return (
        "<tr>"
        f'<td>{_e(row.get("observed_at"))}</td><td>{_e(row.get("controller_name"))}<br><span class="muted">{_e(row.get("controller_host"))}</span></td>'
        f"<td>{_e(_protocol(row.get('protocol')))}</td><td>{_e(row.get('source_ip'))}:{_e(row.get('source_port'))}</td>"
        f"<td>{_e(row.get('destination_ip'))}:{_e(row.get('destination_port'))}</td><td>{_e(row.get('packets'))}</td>"
        f"<td>{_e(row.get('bytes_count'))}</td><td>{_e(row.get('age'))}</td><td>{_e(flags or '-')}<br>{_e(flag_text)}</td><td>{_e(row.get('cpu_id'))}</td>"
        "</tr>"
    )


def _lifecycle_row(row: ReportRow) -> str:
    return (
        "<tr>"
        f"<td>{_e(row.get('occurred_at'))}</td><td>{_e(row.get('event_type'))}</td>"
        f"<td>{_e(row.get('instance_id'))}</td><td>{_e(row.get('controller_name'))}</td>"
        f"<td>{_e(_details(row.get('details_json')))}</td></tr>"
    )


def _controller_row(row: ReportRow) -> str:
    return (
        "<tr>"
        f"<td>{_e(row.get('occurred_at'))}</td><td>{_e(row.get('previous_controller'))}</td>"
        f"<td>{_e(row.get('current_controller'))}</td><td>{_e(row.get('reason'))}</td></tr>"
    )


def _diagnostic_row(row: ReportRow) -> str:
    return (
        "<tr>"
        f"<td>{_e(row.get('occurred_at'))}</td><td>{_e(_redact(row.get('stage')))}</td>"
        f"<td>{_e(row.get('code') or '확인 필요')}</td><td>{_e(_redact(row.get('message')))}</td></tr>"
    )


def _raw_row(row: ReportRow) -> str:
    return (
        "<tr>"
        f"<td>{_e(row.get('id'))}</td><td>{_e(row.get('captured_at'))}</td><td>{_e(row.get('kind'))}</td>"
        f"<td>{_e(row.get('controller_name'))}</td><td>{_e(_format_bytes(_int(row.get('byte_size'))))}</td>"
        f"<td><code>{_e(row.get('sha256'))}</code></td></tr>"
    )


def _time_range_warning(run: ReportRow) -> str:
    started = run.get("started_at")
    ended = run.get("ended_at")
    if not isinstance(started, str) or not isinstance(ended, str):
        return ""
    try:
        started_at = datetime.fromisoformat(started.replace("Z", "+00:00"))
        ended_at = datetime.fromisoformat(ended.replace("Z", "+00:00"))
        reversed_range = ended_at < started_at
    except (TypeError, ValueError):
        return ""
    if not reversed_range:
        return ""
    return (
        '<div class="warning"><strong>시간 범위 확인 필요</strong><br>'
        "종료 시각이 시작 시각보다 빠릅니다. 저장 시각과 시스템 시계를 확인하십시오.</div>"
    )


def _details(value: object) -> str:
    if not isinstance(value, str):
        return "확인 필요"
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return "확인 필요"
    if not isinstance(parsed, dict):
        return "확인 필요"
    parts = [f"{label}: {parsed[key]}" for key, label in _DETAIL_KEYS.items() if key in parsed]
    return ", ".join(parts) or "추가 세부정보 없음"


def _redact(value: object) -> str:
    text = str(value or "")
    text = _IPV4_TEXT.sub("<IPv4>", text)
    return _CREDENTIAL_TEXT.sub(lambda match: f"{match.group(1)}=<REDACTED>", text)


def _troubleshooting_cards(rows: tuple[ReportRow, ...]) -> str:
    codes = sorted({str(row.get("code")) for row in rows if row.get("code")})
    if not codes:
        return '<div class="info">발생한 오류 코드가 없습니다. 빈 결과 자체는 정상 판정이 아닙니다.</div>'
    return "".join(
        f"<details open><summary>{_e(code)}</summary><div>{_e(_TROUBLESHOOTING.get(code, '수집 단계와 비식별 메시지를 확인하고 임의로 원인을 단정하지 마십시오.'))}</div></details>"
        for code in codes
    )


def _command_card(command: str, purpose: str, expected: str) -> str:
    return (
        '<div class="card"><div class="label">명령어</div>'
        f'<pre class="terminal">{_e(command)}</pre><strong>목적</strong><p>{_e(purpose)}</p>'
        f"<strong>예상 결과</strong><p>{_e(expected)}</p></div>"
    )


def _truncation(label: str, displayed: int, total: int) -> str:
    if displayed >= total:
        return f'<p class="muted">{_e(label)} 전체 {_e(total)}건 표시</p>'
    return (
        f'<p class="truncate-note">{_e(label)} 전체 {_e(total)}건 중 최근 {_e(displayed)}건 표시. '
        "전체 데이터는 CSV 또는 SQLite를 확인하십시오.</p>"
    )


def _empty_row(columns: int, message: str) -> str:
    return f'<tr><td colspan="{columns}" class="muted">{_e(message)}</td></tr>'


def _protocol(value: object) -> str:
    number = _int(value)
    return {6: "6 / TCP", 17: "17 / UDP"}.get(number, str(number))


def _int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _format_bytes(value: int) -> str:
    size = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"
