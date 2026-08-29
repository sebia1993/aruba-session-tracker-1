# ruff: noqa: E501
"""Deterministic, offline HTML5 result reports for one stored run."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from html import escape
from pathlib import Path

from aruba_session_tracker.analysis import protocol_label

ReportRow = dict[str, object]
FlowKey = tuple[str, str, str, str, str]

_KST = timezone(timedelta(hours=9), "KST")
_LATEST_SESSION_LIMIT = 50
_CONFIRMED_EVENTS = {
    "STARTED",
    "OPENED",  # Older databases and imported fixtures may use this legacy name.
    "OBSERVED",
    "CONTROLLER_CHANGED",
    "FLAGS_CHANGED",
    "COUNTERS_CHANGED",
}
_RUN_STATUS_KO = {
    "RUNNING": "수집 중",
    "COMPLETED": "수집 완료",
    "STOPPED": "수집 중지",
    "PARTIAL": "일부 수집",
    "FAILED": "수집 실패",
    "INTERRUPTED": "수집 중단",
    "RESTARTED": "조건 변경 종료",
    "CANCELLED": "사용자 취소",
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
    observation_history: tuple[ReportRow, ...] = ()


def render_html_report(snapshot: RunReportSnapshot) -> str:
    """Return a concise standalone HTML5 report containing tracked results only."""

    run = snapshot.run
    history = snapshot.observation_history or snapshot.observations
    flow_groups = _group_observations(history)
    flow_statuses, session_statuses = _lifecycle_statuses(snapshot.lifecycle_events)
    latest_groups = flow_groups[:_LATEST_SESSION_LIMIT]

    latest_rows = "".join(
        _observation_row(
            rows[-1],
            _status_for(rows[-1], flow_statuses, session_statuses),
        )
        for _flow, rows in latest_groups
    )
    change_rows = "".join(_change_row(rows) for _flow, rows in flow_groups)
    history_rows = "".join(_observation_row(row, "관측됨") for row in history)

    logical_session_total = len(flow_groups)
    displayed_latest = len(latest_groups)
    latest_note = (
        f"고유 세션 {_format_integer(logical_session_total)}개를 모두 표시합니다."
        if displayed_latest >= logical_session_total
        else (
            f"고유 세션 {_format_integer(logical_session_total)}개 중 마지막 확인 시각을 기준으로 "
            f"최근 {_format_integer(displayed_latest)}개를 표시합니다."
        )
    )
    query_direction = "양방향" if bool(run.get("bidirectional")) else "단방향"
    run_status = _RUN_STATUS_KO.get(str(run.get("status") or "").upper(), "상태 확인 필요")

    return f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Aruba Session Tracker 추적 결과</title>
  <style>
    :root {{ color-scheme:light; --navy:#17324d; --blue:#1769aa; --ink:#243b53;
      --muted:#627d98; --line:#d9e2ec; --paper:#fff; --bg:#f3f6f9;
      --ok:#147d64; --warn:#9c6615; --closed:#9b2c2c; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; overflow-x:hidden; background:var(--bg); color:var(--ink);
      font-family:system-ui,-apple-system,"Segoe UI","Malgun Gothic",sans-serif; line-height:1.5; }}
    .header {{ background:var(--navy); color:#fff; padding:22px; }}
    .header-inner,.content,.footer {{ width:min(1240px,calc(100% - 32px)); margin:0 auto; }}
    h1 {{ margin:0; font-size:clamp(1.55rem,3vw,2.25rem); }}
    .subtitle {{ margin:.35rem 0 0; color:#d9e8f5; }}
    .content {{ padding:18px 0; }}
    section,.result-summary {{ min-width:0; background:var(--paper); border:1px solid var(--line);
      border-radius:12px; padding:20px; margin-bottom:16px; box-shadow:0 5px 18px #102a430d; }}
    h2 {{ margin:0 0 6px; color:var(--navy); font-size:1.25rem; }}
    .section-note {{ margin:0 0 14px; color:var(--muted); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:10px; }}
    .card {{ min-width:0; border:1px solid var(--line); border-radius:9px; padding:12px; background:#fbfdff; }}
    .label {{ color:var(--muted); font-size:.82rem; }}
    .value {{ display:block; margin-top:3px; font-weight:700; overflow-wrap:anywhere; }}
    .table-wrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:9px; }}
    .table-wrap:focus-visible,summary:focus-visible {{ outline:3px solid #63b3ed; outline-offset:2px; }}
    table {{ width:100%; min-width:800px; border-collapse:collapse; font-size:.88rem; }}
    .changes table {{ min-width:1050px; }}
    th,td {{ padding:9px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ background:#f0f4f8; color:var(--navy); position:sticky; top:0; white-space:nowrap; }}
    tr:last-child td {{ border-bottom:0; }}
    .badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:.78rem;
      font-weight:700; background:#e6fffa; color:var(--ok); white-space:nowrap; }}
    .badge.missed {{ background:#fffaf0; color:var(--warn); }}
    .badge.closed {{ background:#fff5f5; color:var(--closed); }}
    .badge.observed {{ background:#edf2f7; color:#486581; }}
    .delta {{ color:var(--muted); font-size:.82rem; white-space:nowrap; }}
    details {{ border:0; }}
    summary {{ cursor:pointer; color:var(--blue); font-weight:700; padding:6px 0 13px; }}
    .details-body {{ padding-top:2px; }}
    .muted {{ color:var(--muted); }}
    .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden;
      clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
    .footer {{ padding:0 0 24px; color:var(--muted); font-size:.82rem; }}
    @media (max-width:850px) {{
      .header-inner,.content,.footer {{ width:min(100% - 20px,1240px); }}
      section,.result-summary {{ padding:14px; }}
      .grid {{ grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); }}
    }}
    @media (max-width:520px) {{ .grid {{ grid-template-columns:1fr; }} .header {{ padding:18px 10px; }} }}
    @page {{ size:A4 landscape; margin:10mm; }}
    @media print {{
      body {{ background:#fff; color:#000; }} .header {{ background:#fff; color:#000; padding:0 0 10px; }}
      .subtitle {{ color:#333; }} .header-inner,.content,.footer {{ width:100%; }} .content {{ padding:0; }}
      section,.result-summary {{ box-shadow:none; border:1px solid #bbb; padding:10px; margin-bottom:8px; }}
      details:not([open]) > .details-body {{ display:block !important; }} summary {{ color:#000; }}
      .table-wrap {{ overflow:visible; border:0; }} table,.changes table {{ min-width:0; font-size:7.5pt; }}
      thead {{ display:table-header-group; }} th {{ position:static; }} th,td {{ padding:4px; overflow-wrap:anywhere; }}
      .card,tr {{ break-inside:avoid; }}
    }}
  </style>
</head>
<body>
  <header class="header"><div class="header-inner">
    <h1>세션 추적 결과</h1>
    <p class="subtitle">저장된 세션 값을 조회 실행별로 정리한 보고서입니다.</p>
  </div></header>
  <main class="content">
    <div class="result-summary" aria-label="조회 결과 정보">
      <div class="grid">
        {_card("추적 시작", _format_kst(run.get("started_at")))}
        {_card("추적 종료", _format_kst(run.get("ended_at")))}
        {_card("출발지 IP", run.get("source_ip"))}
        {_card("출발지 포트", run.get("source_port"))}
        {_card("목적지 IP", run.get("destination_ip"))}
        {_card("목적지 포트", run.get("destination_port"))}
        {_card("검색 방향", query_direction)}
        {_card("전체 관측", f"{_format_integer(snapshot.observation_total)}건")}
        {_card("고유 세션", f"{_format_integer(logical_session_total)}개")}
        {_card("수집 상태", run_status)}
      </div>
    </div>

    <section id="latest-sessions">
      <h2>최신 세션 결과</h2>
      <p class="section-note">{_e(latest_note)}</p>
      <div class="table-wrap" role="region" aria-label="최신 세션 결과 표" tabindex="0"><table>
        <caption class="sr-only">최신 세션 결과</caption>
        <thead><tr><th scope="col">마지막 확인 시각</th><th scope="col">장비명</th><th scope="col">프로토콜</th><th scope="col">출발지 IP:포트</th><th scope="col">목적지 IP:포트</th><th scope="col">추적 상태</th></tr></thead>
        <tbody>{latest_rows or _empty_row(6, "관측된 세션이 없습니다.")}</tbody>
      </table></div>
    </section>

    <section id="session-changes" class="changes">
      <h2>세션별 수치 변화</h2>
      <p class="section-note">각 세션의 처음 값과 마지막 값을 그대로 비교합니다.</p>
      <div class="table-wrap" role="region" aria-label="세션별 수치 변화 표" tabindex="0"><table>
        <caption class="sr-only">세션별 수치 변화</caption>
        <thead><tr><th scope="col">세션</th><th scope="col">처음 확인</th><th scope="col">마지막 확인</th><th scope="col">패킷</th><th scope="col">바이트</th><th scope="col">장비 변화</th></tr></thead>
        <tbody>{change_rows or _empty_row(6, "비교할 세션이 없습니다.")}</tbody>
      </table></div>
    </section>

    <section id="observation-history">
      <h2>전체 추적 이력</h2>
      <details>
        <summary>전체 추적 이력 {_format_integer(snapshot.observation_total)}건 보기</summary>
        <div class="details-body">
          <p class="section-note">저장된 관측 결과를 시간순으로 모두 표시합니다.</p>
          <div class="table-wrap" role="region" aria-label="전체 추적 이력 표" tabindex="0"><table>
            <caption class="sr-only">전체 추적 이력</caption>
            <thead><tr><th scope="col">확인 시각</th><th scope="col">장비명</th><th scope="col">프로토콜</th><th scope="col">출발지 IP:포트</th><th scope="col">목적지 IP:포트</th><th scope="col">추적 상태</th></tr></thead>
            <tbody>{history_rows or _empty_row(6, "저장된 관측 이력이 없습니다.")}</tbody>
          </table></div>
        </div>
      </details>
    </section>
  </main>
  <footer class="footer">Aruba Session Tracker 결과 보고서</footer>
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


def _card(label: str, value: object) -> str:
    return (
        f'<div class="card"><div class="label">{_e(label)}</div>'
        f'<span class="value">{_e(value)}</span></div>'
    )


def _group_observations(
    rows: tuple[ReportRow, ...],
) -> tuple[tuple[FlowKey, tuple[ReportRow, ...]], ...]:
    grouped: dict[FlowKey, list[tuple[int, ReportRow]]] = {}
    for index, row in enumerate(rows):
        grouped.setdefault(_flow_key(row), []).append((index, row))

    ordered: list[tuple[FlowKey, tuple[ReportRow, ...]]] = []
    for flow, indexed_rows in grouped.items():
        sorted_rows = tuple(
            row
            for _index, row in sorted(
                indexed_rows,
                key=lambda item: (_datetime_sort_value(item[1].get("observed_at")), item[0]),
            )
        )
        ordered.append((flow, sorted_rows))
    ordered.sort(
        key=lambda item: (_datetime_sort_value(item[1][-1].get("observed_at")), item[0]),
        reverse=True,
    )
    return tuple(ordered)


def _lifecycle_statuses(
    rows: tuple[ReportRow, ...],
) -> tuple[dict[FlowKey, str], dict[str, str]]:
    flow_statuses: dict[FlowKey, tuple[tuple[datetime, int], str]] = {}
    session_statuses: dict[str, tuple[tuple[datetime, int], str]] = {}
    for index, row in enumerate(rows):
        status = _lifecycle_status(row.get("event_type"))
        rank = (_datetime_sort_value(row.get("occurred_at")), -index)
        session_key = str(row.get("session_key") or "")
        if session_key:
            current_session = session_statuses.get(session_key)
            if current_session is None or rank > current_session[0]:
                session_statuses[session_key] = (rank, status)
        flow = _flow_key_from_session_key(session_key)
        if flow is not None:
            current_flow = flow_statuses.get(flow)
            if current_flow is None or rank > current_flow[0]:
                flow_statuses[flow] = (rank, status)
    return (
        {key: item[1] for key, item in flow_statuses.items()},
        {key: item[1] for key, item in session_statuses.items()},
    )


def _status_for(
    row: ReportRow,
    flow_statuses: dict[FlowKey, str],
    session_statuses: dict[str, str],
) -> str:
    flow_status = flow_statuses.get(_flow_key(row))
    if flow_status is not None:
        return flow_status
    session_key = str(row.get("session_key") or "")
    return session_statuses.get(session_key, "관측됨")


def _lifecycle_status(value: object) -> str:
    event_type = str(value or "").upper()
    if event_type == "CLOSED":
        return "종료 확인"
    if event_type == "MISSED":
        return "잠시 미확인"
    if event_type in _CONFIRMED_EVENTS:
        return "확인됨"
    return "상태 확인 필요"


def _observation_row(row: ReportRow, status: str) -> str:
    return (
        "<tr>"
        f"<td>{_e(_format_kst(row.get('observed_at')))}</td>"
        f"<td>{_e(row.get('controller_name'))}</td>"
        f"<td>{_e(_protocol(row.get('protocol')))}</td>"
        f"<td>{_e(_endpoint(row.get('source_ip'), row.get('source_port')))}</td>"
        f"<td>{_e(_endpoint(row.get('destination_ip'), row.get('destination_port')))}</td>"
        f"<td>{_tracking_badge(status)}</td>"
        "</tr>"
    )


def _change_row(rows: tuple[ReportRow, ...]) -> str:
    first = rows[0]
    last = rows[-1]
    first_packets = _optional_int(first.get("packets"))
    last_packets = _optional_int(last.get("packets"))
    first_bytes = _optional_int(first.get("bytes_count"))
    last_bytes = _optional_int(last.get("bytes_count"))
    return (
        "<tr>"
        f"<td>{_e(_flow_label(first))}</td>"
        f"<td>{_e(_format_kst(first.get('observed_at')))}</td>"
        f"<td>{_e(_format_kst(last.get('observed_at')))}</td>"
        f"<td>{_change_cell(first_packets, last_packets, byte_count=False)}</td>"
        f"<td>{_change_cell(first_bytes, last_bytes, byte_count=True)}</td>"
        f"<td>{_e(_controller_change(first, last))}</td>"
        "</tr>"
    )


def _change_cell(first: int | None, last: int | None, *, byte_count: bool) -> str:
    if byte_count:
        first_text = "-" if first is None else _format_byte_value(first)
        last_text = "-" if last is None else _format_byte_value(last)
    else:
        first_text = "-" if first is None else _format_integer(first)
        last_text = "-" if last is None else _format_integer(last)
    if first is None or last is None:
        delta_text = "계산 불가"
    else:
        delta = last - first
        delta_text = _format_byte_delta(delta) if byte_count else _format_signed_integer(delta)
    return (
        f'<span class="value">{_e(first_text)} → {_e(last_text)}</span>'
        f'<span class="delta">변화 {_e(delta_text)}</span>'
    )


def _tracking_badge(status: str) -> str:
    kind = {
        "잠시 미확인": "missed",
        "종료 확인": "closed",
        "관측됨": "observed",
        "상태 확인 필요": "missed",
    }.get(status, "")
    return f'<span class="badge {kind}">{_e(status)}</span>'


def _flow_key(row: ReportRow) -> FlowKey:
    return (
        _key_part(row.get("protocol")),
        _key_part(row.get("source_ip")),
        _key_part(row.get("destination_ip")),
        _key_part(row.get("source_port")),
        _key_part(row.get("destination_port")),
    )


def _flow_key_from_session_key(value: str) -> FlowKey | None:
    parts = value.split("|")
    if len(parts) != 6:
        return None
    return (parts[1], parts[2], parts[3], parts[4], parts[5])


def _flow_label(row: ReportRow) -> str:
    return (
        f"{_protocol(row.get('protocol'))} · "
        f"{_endpoint(row.get('source_ip'), row.get('source_port'))} → "
        f"{_endpoint(row.get('destination_ip'), row.get('destination_port'))}"
    )


def _controller_change(first: ReportRow, last: ReportRow) -> str:
    first_name = _plain(first.get("controller_name"))
    last_name = _plain(last.get("controller_name"))
    if first_name == last_name:
        return f"{first_name} (변화 없음)"
    return f"{first_name} → {last_name}"


def _endpoint(address: object, port: object) -> str:
    address_text = _plain(address)
    if address_text == "-":
        return "-"
    port_text = _plain(port)
    return address_text if port_text == "-" else f"{address_text}:{port_text}"


def _protocol(value: object) -> str:
    number = _optional_int(value)
    if number is None:
        return _plain(value)
    if not 0 <= number <= 255:
        return str(number)
    return protocol_label(number)


def _format_kst(value: object) -> str:
    parsed = _parse_datetime(value)
    if parsed is None:
        return "-"
    return parsed.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _datetime_sort_value(value: object) -> datetime:
    return _parse_datetime(value) or datetime.min.replace(tzinfo=UTC)


def _format_integer(value: int) -> str:
    return f"{value:,}"


def _format_signed_integer(value: int) -> str:
    if value > 0:
        return f"+{value:,}"
    return f"{value:,}"


def _format_byte_value(value: int) -> str:
    exact = f"{value:,} B"
    scaled = _scaled_bytes(value)
    return exact if scaled is None else f"{exact} ({scaled})"


def _format_byte_delta(value: int) -> str:
    sign = "+" if value > 0 else ""
    exact = f"{sign}{value:,} B"
    scaled = _scaled_bytes(value, signed=True)
    return exact if scaled is None else f"{exact} ({scaled})"


def _scaled_bytes(value: int, *, signed: bool = False) -> str | None:
    magnitude = abs(value)
    if magnitude < 1024:
        return None
    size = float(magnitude)
    unit = "B"
    for candidate in ("KiB", "MiB", "GiB", "TiB"):
        size /= 1024
        unit = candidate
        if size < 1024 or candidate == "TiB":
            break
    prefix = "-" if value < 0 else ("+" if signed and value > 0 else "")
    return f"{prefix}{size:.1f} {unit}"


def _optional_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _key_part(value: object) -> str:
    return "" if value is None else str(value)


def _plain(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _e(value: object) -> str:
    return escape(_plain(value), quote=True)


def _empty_row(columns: int, message: str) -> str:
    return f'<tr><td colspan="{columns}" class="muted">{_e(message)}</td></tr>'
