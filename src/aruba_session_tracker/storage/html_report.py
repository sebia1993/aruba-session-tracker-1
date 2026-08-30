# ruff: noqa: E501
"""Deterministic, offline HTML5 result reports for one stored run."""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from html import escape
from pathlib import Path

from aruba_session_tracker.analysis import protocol_label
from aruba_session_tracker.storage.durable_io import replace_with_retry

ReportRow = dict[str, object]
FlowKey = tuple[str, str, str, str, str]

_KST = timezone(timedelta(hours=9), "KST")
_LATEST_SESSION_LIMIT = 50
_DISTRIBUTION_LIMIT = 5
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

    return "".join(_report_chunks(snapshot))


def _report_chunks(
    snapshot: RunReportSnapshot,
    *,
    observation_history: Iterable[ReportRow] | None = None,
    logical_session_total: int | None = None,
) -> Iterator[str]:
    """Yield one report in bounded chunks.

    ``observation_history`` is used by :class:`SessionStore` to stream a stable
    SQLite cursor directly to the atomic destination. The public renderer keeps
    its historical behavior by deriving both the latest results and the complete
    history from the supplied snapshot.
    """

    run = snapshot.run
    if observation_history is None:
        history: Iterable[ReportRow] = snapshot.observation_history or snapshot.observations
        latest_source = snapshot.observation_history or snapshot.observations
    else:
        history = observation_history
        latest_source = snapshot.observations
    flow_groups = _group_observations(latest_source)
    flow_statuses, session_statuses = _lifecycle_statuses(snapshot.lifecycle_events)
    latest_groups = flow_groups[:_LATEST_SESSION_LIMIT]

    latest_rows = "".join(
        _observation_row(
            rows[-1],
            _status_for(rows[-1], flow_statuses, session_statuses),
        )
        for _flow, rows in latest_groups
    )
    logical_rows = tuple(rows[-1] for _flow, rows in flow_groups)
    logical_statuses = tuple(
        _status_for(row, flow_statuses, session_statuses) for row in logical_rows
    )
    total_sessions = len(flow_groups) if logical_session_total is None else logical_session_total
    displayed_latest = len(latest_groups)
    latest_note = (
        f"고유 세션 {_format_integer(total_sessions)}개를 모두 표시합니다."
        if displayed_latest >= total_sessions
        else (
            f"고유 세션 {_format_integer(total_sessions)}개 중 마지막 확인 시각을 기준으로 "
            f"최근 {_format_integer(displayed_latest)}개를 표시합니다."
        )
    )
    query_direction = "양방향" if bool(run.get("bidirectional")) else "단방향"
    run_status = _RUN_STATUS_KO.get(str(run.get("status") or "").upper(), "상태 확인 필요")
    source_endpoint = _endpoint(run.get("source_ip"), run.get("source_port"))
    destination_endpoint = _endpoint(run.get("destination_ip"), run.get("destination_port"))
    protocol_distribution = _distribution(
        _protocol(row.get("protocol")) for row in logical_rows
    )
    controller_distribution = _distribution(
        _plain(row.get("controller_name")) for row in logical_rows
    )
    status_summary = _status_summary(logical_statuses)

    yield f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Aruba Session Tracker 추적 결과</title>
  <style>
    :root {{ color-scheme:light; --navy:#102f49; --navy-2:#173f60; --blue:#1769aa;
      --blue-soft:#e8f2fb; --ink:#243b53; --muted:#627d98; --line:#d6e0e8;
      --paper:#fff; --bg:#edf3f7; --soft:#f7fafc; --ok:#147d64; --ok-bg:#e6fffa;
      --warn:#9c6615; --warn-bg:#fffaf0; --closed:#9b2c2c; --closed-bg:#fff5f5; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; overflow-x:hidden; background:var(--bg); color:var(--ink);
      font-family:system-ui,-apple-system,"Segoe UI","Malgun Gothic",sans-serif; line-height:1.5; }}
    .header {{ background:var(--navy); color:#fff; padding:26px 0 22px; border-bottom:4px solid #2784c7; }}
    .header-inner,.content,.footer {{ width:min(1240px,calc(100% - 32px)); margin:0 auto; }}
    .eyebrow {{ margin:0 0 4px; color:#9fd0f2; font-size:.72rem; font-weight:800;
      letter-spacing:.14em; text-transform:uppercase; }}
    h1 {{ margin:0; font-size:clamp(1.55rem,3vw,2.25rem); letter-spacing:-.02em; }}
    .subtitle {{ margin:.35rem 0 0; color:#d7e7f4; }}
    .content {{ padding:18px 0; }}
    section,.result-summary {{ min-width:0; background:var(--paper); border:1px solid var(--line);
      border-radius:14px; padding:20px; margin-bottom:16px; box-shadow:0 6px 20px #102a430d; }}
    .result-summary {{ padding:0; overflow:hidden; }}
    .flow-panel {{ display:grid; grid-template-columns:minmax(0,1fr) auto minmax(0,1fr); gap:14px;
      align-items:center; padding:20px; background:#f2f7fb; border-bottom:1px solid var(--line); }}
    .endpoint {{ min-width:0; }}
    .endpoint.destination {{ text-align:right; }}
    .endpoint-label {{ color:var(--muted); font-size:.72rem; font-weight:800; letter-spacing:.08em; }}
    .endpoint-value {{ display:block; margin-top:3px; color:var(--navy); font-size:1.05rem;
      font-weight:800; overflow-wrap:anywhere; }}
    .direction {{ min-width:118px; text-align:center; }}
    .direction-arrow {{ display:block; color:var(--blue); font-size:1.45rem; line-height:1; font-weight:800; }}
    .direction-pill {{ display:inline-block; margin-top:7px; padding:3px 9px; border-radius:999px;
      color:#0b4f82; background:#dcecf8; border:1px solid #9fc6e2; font-size:.75rem; font-weight:800; }}
    .summary-body {{ padding:18px 20px 20px; }}
    .summary-heading {{ display:flex; gap:10px; align-items:center; justify-content:space-between; margin-bottom:12px; }}
    .summary-title {{ color:var(--navy); font-size:.93rem; font-weight:800; }}
    .run-state {{ display:inline-flex; align-items:center; gap:6px; padding:4px 9px; border-radius:999px;
      background:var(--blue-soft); color:#0b4f82; border:1px solid #b8d6eb; font-size:.75rem; font-weight:800; }}
    .run-state::before {{ content:""; width:7px; height:7px; border-radius:50%; background:#2784c7; }}
    h2 {{ margin:0 0 6px; color:var(--navy); font-size:1.25rem; letter-spacing:-.01em; }}
    .section-note {{ margin:0 0 14px; color:var(--muted); }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(145px,1fr)); gap:10px; }}
    .card {{ min-width:0; border:1px solid var(--line); border-radius:10px; padding:12px 13px;
      background:var(--soft); }}
    .label {{ color:var(--muted); font-size:.78rem; font-weight:650; }}
    .value {{ display:block; margin-top:4px; color:#17324d; font-weight:800; overflow-wrap:anywhere; }}
    .insights {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px; margin-top:14px; }}
    .insight-card {{ min-width:0; padding:14px; border:1px solid var(--line); border-radius:10px; background:#fff; }}
    .insight-title {{ margin-bottom:10px; color:var(--navy); font-size:.84rem; font-weight:800; }}
    .distribution {{ display:grid; gap:8px; }}
    .dist-row {{ display:grid; grid-template-columns:minmax(95px,1fr) minmax(100px,2fr) auto;
      gap:10px; align-items:center; font-size:.78rem; }}
    .dist-label {{ min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#334e68; }}
    .dist-count {{ color:var(--muted); font-variant-numeric:tabular-nums; }}
    .bar-track {{ height:7px; overflow:hidden; background:#e8eef3; border-radius:999px; }}
    .bar-fill {{ display:block; height:100%; background:#2d82bd; border-radius:999px; }}
    .empty-insight {{ color:var(--muted); font-size:.8rem; }}
    .status-strip {{ display:flex; flex-wrap:wrap; gap:7px; margin-top:12px; }}
    .status-chip {{ display:inline-flex; align-items:center; gap:5px; padding:4px 8px; border-radius:999px;
      color:#486581; background:#edf2f7; border:1px solid #d7e0e8; font-size:.75rem; font-weight:750; }}
    .status-chip.confirmed {{ color:var(--ok); background:var(--ok-bg); border-color:#ace5d6; }}
    .status-chip.missed {{ color:var(--warn); background:var(--warn-bg); border-color:#ead9ad; }}
    .status-chip.closed {{ color:var(--closed); background:var(--closed-bg); border-color:#edc4c4; }}
    .table-wrap {{ overflow-x:auto; border:1px solid var(--line); border-radius:10px; background:#fff; }}
    .table-wrap:focus-visible,summary:focus-visible {{ outline:3px solid #63b3ed; outline-offset:2px; }}
    table {{ width:100%; min-width:800px; border-collapse:collapse; font-size:.88rem; }}
    th,td {{ padding:10px 11px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
    th {{ background:#edf3f7; color:var(--navy); position:sticky; top:0; white-space:nowrap; font-size:.8rem; }}
    tbody tr:nth-child(even) {{ background:#fbfdff; }}
    tbody tr:hover {{ background:#f2f8fc; }}
    tr:last-child td {{ border-bottom:0; }}
    .badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:.78rem;
      font-weight:800; background:var(--ok-bg); color:var(--ok); white-space:nowrap; }}
    .badge.missed {{ background:var(--warn-bg); color:var(--warn); }}
    .badge.closed {{ background:var(--closed-bg); color:var(--closed); }}
    .badge.observed {{ background:#edf2f7; color:#486581; }}
    details {{ border:0; }}
    summary {{ cursor:pointer; color:var(--blue); font-weight:800; padding:6px 0 13px; }}
    .history-toggle:not([open]) + .details-body {{ display:none; }}
    .history-toggle[open] + .details-body {{ display:block; }}
    .details-body {{ padding-top:2px; }}
    .muted {{ color:var(--muted); }}
    .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden;
      clip:rect(0,0,0,0); white-space:nowrap; border:0; }}
    .footer {{ padding:0 0 24px; color:var(--muted); font-size:.82rem; }}
    @media (max-width:850px) {{
      .header-inner,.content,.footer {{ width:min(100% - 20px,1240px); }}
      section {{ padding:14px; }} .summary-body {{ padding:14px; }}
      .flow-panel {{ grid-template-columns:1fr; gap:10px; padding:16px; }}
      .endpoint.destination {{ text-align:left; }} .direction {{ text-align:left; min-width:0; }}
      .direction-arrow {{ transform:rotate(90deg); transform-origin:left center; margin-left:8px; }}
      .grid {{ grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); }}
      .insights {{ grid-template-columns:1fr; }}
    }}
    @media (max-width:520px) {{
      .grid {{ grid-template-columns:1fr 1fr; }} .header {{ padding:20px 0 18px; }}
      .dist-row {{ grid-template-columns:minmax(85px,1fr) minmax(80px,1.6fr) auto; gap:7px; }}
    }}
    @page {{ size:A4 landscape; margin:10mm; }}
    @media print {{
      body {{ background:#fff; color:#000; }} .header {{ background:#fff; color:#000; padding:0 0 10px; border:0; }}
      .eyebrow,.subtitle {{ color:#333; }} .header-inner,.content,.footer {{ width:100%; }} .content {{ padding:0; }}
      section,.result-summary {{ box-shadow:none; border:1px solid #bbb; padding:10px; margin-bottom:8px; }}
      .result-summary {{ padding:0; }} .flow-panel {{ background:#fff; }} .summary-body {{ padding:10px; }}
      section {{ border:0; border-radius:0; padding:0; }}
      .history-toggle {{ display:none; }} .history-toggle + .details-body {{ display:block !important; }}
      .table-wrap {{ overflow:visible; border:0; }} table {{ min-width:0; font-size:7.5pt; }}
      thead {{ display:table-header-group; }} th {{ position:static; }} th,td {{ padding:4px; overflow-wrap:anywhere; }}
      .card,.insight-card,.flow-panel,tr {{ break-inside:avoid; }}
      tbody tr:nth-child(even),tbody tr:hover {{ background:#fff; }}
    }}
  </style>
</head>
<body>
  <header class="header"><div class="header-inner">
    <p class="eyebrow">Aruba Session Tracker</p>
    <h1>세션 추적 결과</h1>
    <p class="subtitle">저장된 세션 값을 조회 실행별로 정리한 오프라인 결과 보고서입니다.</p>
  </div></header>
  <main class="content">
    <div class="result-summary" aria-label="조회 결과 정보">
      <div class="flow-panel">
        <div class="endpoint">
          <span class="endpoint-label">SOURCE</span>
          <span class="endpoint-value">{_e(source_endpoint)}</span>
        </div>
        <div class="direction" aria-label="검색 방향 {_e(query_direction)}">
          <span class="direction-arrow" aria-hidden="true">→</span>
          <span class="direction-pill">{_e(query_direction)}</span>
        </div>
        <div class="endpoint destination">
          <span class="endpoint-label">DESTINATION</span>
          <span class="endpoint-value">{_e(destination_endpoint)}</span>
        </div>
      </div>
      <div class="summary-body">
        <div class="summary-heading">
          <div class="summary-title">조회 요약</div>
          <div class="run-state">{_e(run_status)}</div>
        </div>
        <div class="grid">
          {_card("추적 시작", _format_kst(run.get("started_at")))}
          {_card("추적 종료", _format_kst(run.get("ended_at")))}
          {_card("출발지 IP", run.get("source_ip"))}
          {_card("출발지 포트", run.get("source_port"))}
          {_card("목적지 IP", run.get("destination_ip"))}
          {_card("목적지 포트", run.get("destination_port"))}
          {_card("검색 방향", query_direction)}
          {_card("전체 관측", f"{_format_integer(snapshot.observation_total)}건")}
          {_card("고유 세션", f"{_format_integer(total_sessions)}개")}
          {_card("수집 상태", run_status)}
        </div>
        <div class="insights" aria-label="세션 분포 요약">
          {_distribution_panel("프로토콜 분포", protocol_distribution)}
          {_distribution_panel("Controller 분포", controller_distribution)}
        </div>
        {_status_strip(status_summary)}
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

    <section id="observation-history">
      <h2>전체 추적 이력</h2>
      <details class="history-toggle">
        <summary aria-controls="observation-history-body">전체 추적 이력 {_format_integer(snapshot.observation_total)}건 보기</summary>
      </details>
      <div class="details-body" id="observation-history-body">
          <p class="section-note">저장된 관측 결과를 시간순으로 모두 표시합니다.</p>
          <div class="table-wrap" role="region" aria-label="전체 추적 이력 표" tabindex="0"><table>
            <caption class="sr-only">전체 추적 이력</caption>
            <thead><tr><th scope="col">확인 시각</th><th scope="col">장비명</th><th scope="col">프로토콜</th><th scope="col">출발지 IP:포트</th><th scope="col">목적지 IP:포트</th><th scope="col">추적 상태</th></tr></thead>
            <tbody>"""
    history_count = 0
    for row in history:
        history_count += 1
        yield _observation_row(row, "관측됨")
    if history_count == 0:
        yield _empty_row(6, "저장된 관측 이력이 없습니다.")
    yield """</tbody>
          </table></div>
      </div>
    </section>
  </main>
  <footer class="footer">Aruba Session Tracker 결과 보고서</footer>
</body>
</html>
"""


def write_html_report_atomic(destination: Path | str, snapshot: RunReportSnapshot) -> Path:
    """Atomically write one deterministic UTF-8 report."""

    return _write_html_chunks_atomic(destination, _report_chunks(snapshot))


def write_html_report_stream_atomic(
    destination: Path | str,
    snapshot: RunReportSnapshot,
    observation_history: Iterable[ReportRow],
    *,
    logical_session_total: int,
) -> Path:
    """Atomically write a report while consuming history rows incrementally."""

    return _write_html_chunks_atomic(
        destination,
        _report_chunks(
            snapshot,
            observation_history=observation_history,
            logical_session_total=logical_session_total,
        ),
    )


def _write_html_chunks_atomic(destination: Path | str, chunks: Iterable[str]) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        byte_size = 0
        with os.fdopen(descriptor, "wb") as stream:
            for chunk in chunks:
                encoded = chunk.encode("utf-8")
                stream.write(encoded)
                digest.update(encoded)
                byte_size += len(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(
            temporary_path,
            path,
            replace=os.replace,
            expected_sha256=digest.hexdigest(),
            expected_size=byte_size,
        )
    finally:
        temporary_path.unlink(missing_ok=True)
    return path


def _card(label: str, value: object) -> str:
    return (
        f'<div class="card"><div class="label">{_e(label)}</div>'
        f'<span class="value">{_e(value)}</span></div>'
    )


def _distribution(values: Iterable[str]) -> tuple[tuple[str, int, int], ...]:
    counts = Counter(value for value in values if value and value != "-")
    total = sum(counts.values())
    if total == 0:
        return ()
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:_DISTRIBUTION_LIMIT]
    return tuple((label, count, max(1, round((count / total) * 100))) for label, count in ordered)


def _distribution_panel(title: str, rows: tuple[tuple[str, int, int], ...]) -> str:
    if rows:
        body = "".join(
            (
                '<div class="dist-row">'
                f'<span class="dist-label" title="{_e(label)}">{_e(label)}</span>'
                '<span class="bar-track" aria-hidden="true">'
                f'<span class="bar-fill" style="width:{percent}%"></span></span>'
                f'<span class="dist-count">{_format_integer(count)}</span>'
                "</div>"
            )
            for label, count, percent in rows
        )
    else:
        body = '<div class="empty-insight">표시할 세션이 없습니다.</div>'
    return (
        '<div class="insight-card">'
        f'<div class="insight-title">{_e(title)}</div>'
        f'<div class="distribution">{body}</div>'
        "</div>"
    )


def _status_summary(statuses: Iterable[str]) -> tuple[tuple[str, int], ...]:
    counts = Counter(statuses)
    ordered = ("확인됨", "잠시 미확인", "종료 확인", "관측됨")
    return tuple((status, counts[status]) for status in ordered if counts[status] > 0)


def _status_strip(statuses: tuple[tuple[str, int], ...]) -> str:
    if not statuses:
        return ""
    chips = "".join(
        (
            f'<span class="status-chip {_status_class(status)}">'
            f'{_e(status)} {_format_integer(count)}</span>'
        )
        for status, count in statuses
    )
    return f'<div class="status-strip" aria-label="추적 상태 요약">{chips}</div>'


def _status_class(status: str) -> str:
    return {
        "확인됨": "confirmed",
        "잠시 미확인": "missed",
        "종료 확인": "closed",
    }.get(status, "observed")


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
        if status is None:
            continue
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


def _lifecycle_status(value: object) -> str | None:
    event_type = str(value or "").upper()
    if event_type == "CLOSED":
        return "종료 확인"
    if event_type == "MISSED":
        return "잠시 미확인"
    if event_type in _CONFIRMED_EVENTS:
        return "확인됨"
    return None


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


def _tracking_badge(status: str) -> str:
    kind = {
        "잠시 미확인": "missed",
        "종료 확인": "closed",
        "관측됨": "observed",
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
