# ruff: noqa: E501
"""Approved light investigation-report presentation over the stable report core.

The original :mod:`html_report` module retains its proven row serialization,
filter script, CSP hash, and atomic streaming writer.  This module composes a
new visual hierarchy from those primitives without widening exported data.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from aruba_session_tracker.analysis import service_label
from aruba_session_tracker.storage import html_report as _base
from aruba_session_tracker.storage.html_report import RunReportSnapshot

ReportRow = dict[str, object]
FrequencyRow = tuple[str, int, int] | tuple[int, int, int, int]
_FREQUENCY_LIMIT = 5


def render_html_report(snapshot: RunReportSnapshot) -> str:
    """Return the approved deterministic standalone HTML report."""

    return "".join(_report_chunks(snapshot))


def write_html_report_atomic(destination: Path | str, snapshot: RunReportSnapshot) -> Path:
    """Atomically write one approved report."""

    return _base._write_html_chunks_atomic(destination, _report_chunks(snapshot))


def write_html_report_stream_atomic(
    destination: Path | str,
    snapshot: RunReportSnapshot,
    observation_history: Iterable[ReportRow],
    *,
    logical_session_total: int,
) -> Path:
    """Atomically stream a complete approved report to the destination."""

    if snapshot.ip_frequency_summary is None or snapshot.protocol_port_frequency_summary is None:
        raise ValueError("streamed HTML reports require precomputed frequency summaries")

    return _base._write_html_chunks_atomic(
        destination,
        _report_chunks(
            snapshot,
            observation_history=observation_history,
            logical_session_total=logical_session_total,
        ),
    )


def _report_chunks(
    snapshot: RunReportSnapshot,
    *,
    observation_history: Iterable[ReportRow] | None = None,
    logical_session_total: int | None = None,
) -> Iterator[str]:
    run = snapshot.run
    if observation_history is None:
        history: Iterable[ReportRow] = snapshot.observation_history or snapshot.observations
        latest_source = snapshot.observation_history or snapshot.observations
    else:
        history = observation_history
        latest_source = snapshot.observations

    flow_groups = _base._group_observations(latest_source)
    flow_statuses, session_statuses = _base._lifecycle_statuses(snapshot.lifecycle_events)
    latest_groups = flow_groups[: _base._LATEST_SESSION_LIMIT]
    latest_rows = "".join(
        _base._observation_row(
            rows[-1],
            _base._status_for(rows[-1], flow_statuses, session_statuses),
        )
        for _flow, rows in latest_groups
    )
    total_sessions = len(flow_groups) if logical_session_total is None else logical_session_total
    displayed_latest = len(latest_groups)
    latest_observations = tuple(rows[-1] for _flow, rows in latest_groups)
    latest_note = (
        f"고유 세션 {_base._format_integer(total_sessions)}개를 모두 표시합니다."
        if displayed_latest >= total_sessions
        else (
            f"고유 세션 {_base._format_integer(total_sessions)}개 중 마지막 확인 시각을 "
            f"기준으로 최근 {_base._format_integer(displayed_latest)}개를 표시합니다."
        )
    )

    query_direction = "양방향" if bool(run.get("bidirectional")) else "단방향"
    direction_symbol = "↔" if bool(run.get("bidirectional")) else "→"
    run_status_code = str(run.get("status") or "").upper()
    run_status = _base._RUN_STATUS_KO.get(run_status_code, "상태 확인 필요")
    run_status_class = _base._RUN_STATUS_CLASS.get(run_status_code, "attention")
    source_endpoint = _base._query_endpoint(
        run.get("source_ip"),
        run.get("source_port"),
        other_address=run.get("destination_ip"),
    )
    destination_endpoint = _base._query_endpoint(
        run.get("destination_ip"),
        run.get("destination_port"),
        other_address=run.get("source_ip"),
    )
    frequency_rows = snapshot.observation_history or snapshot.observations
    ip_frequency_summary = _resolve_ip_frequency_summary(snapshot, frequency_rows)
    protocol_port_frequency_summary = _resolve_protocol_port_frequency_summary(
        snapshot, frequency_rows
    )
    duration = _format_duration(run.get("started_at"), run.get("ended_at"))
    query_target = _display_query_target(run)
    observed_controllers = _observed_controllers(latest_observations)
    observed_controller_text = " · ".join(observed_controllers) if observed_controllers else "—"

    yield f"""<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-{_base._FILTER_SCRIPT_SHA256}'; object-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Aruba Session Tracker 추적 결과</title>
  <style>
    :root {{ color-scheme:light; --navy:#102f49; --navy-2:#163d5c; --canvas:#eef3f7;
      --surface:#ffffff; --surface-muted:#f5f8fb; --surface-strong:#e8eef4;
      --border:#cbd5e1; --border-strong:#aebcca; --text:#0f172a; --text-muted:#475569;
      --primary:#0b5f9a; --primary-hover:#084f82; --focus:#1976b9; --cyan:#23889b;
      --success:#147d64; --warning:#9c6615; --danger:#b42318; --neutral:#486581; }}
    * {{ box-sizing:border-box; }}
    html {{ background:var(--canvas); }}
    body {{ margin:0; overflow-x:hidden; background:var(--canvas); color:var(--text);
      font-family:system-ui,-apple-system,"Segoe UI","Malgun Gothic",sans-serif; line-height:1.5; }}
    .report-header {{ background:var(--navy); color:#fff; border-bottom:4px solid #2b8fc2; }}
    .report-header-inner,.content,.footer {{ width:min(1240px,calc(100% - 32px)); margin:0 auto; }}
    .report-header-inner {{ display:flex; justify-content:space-between; align-items:center;
      gap:20px; padding:18px 0 16px; }}
    .product-name {{ margin:0 0 2px; color:#bcd5e7; font-size:.74rem; font-weight:800;
      letter-spacing:.095em; }}
    h1 {{ margin:0; font-size:clamp(1.42rem,2.4vw,1.85rem); line-height:1.2; }}
    .report-subtitle {{ margin:4px 0 0; color:#d6e4ee; font-size:.86rem; }}
    .content {{ padding:16px 0 18px; }}
    section {{ min-width:0; background:var(--surface); border:1px solid var(--border);
      border-radius:9px; padding:17px; margin-bottom:13px; }}
    h2 {{ margin:0 0 5px; color:var(--text); font-size:1.14rem; }}
    .section-kicker {{ margin:0 0 3px; color:var(--primary); font-size:.72rem;
      font-weight:800; letter-spacing:.085em; }}
    .section-note {{ margin:0 0 12px; color:var(--text-muted); }}
    .run-state {{ display:inline-flex; align-items:center; gap:7px; padding:5px 11px;
      border-radius:999px; background:#edf2f7; color:var(--neutral); border:1px solid #cbd5e1;
      font-size:.79rem; font-weight:800; white-space:nowrap; }}
    .run-state::before {{ content:""; width:8px; height:8px; border-radius:50%;
      background:currentColor; }}
    .run-state.completed {{ background:#e6fffa; color:var(--success); border-color:#9ae6d3; }}
    .run-state.running {{ background:#e8f2fb; color:var(--primary); border-color:#b8d6eb; }}
    .run-state.attention {{ background:#fff8e7; color:var(--warning); border-color:#e7c978; }}
    .run-state.failed {{ background:#fff1f0; color:var(--danger); border-color:#f3b6b0; }}

    .report-hero {{ padding:0; overflow:hidden; }}
    .hero-grid {{ display:grid; grid-template-columns:minmax(0,1.4fr) minmax(280px,.6fr); }}
    .hero-main {{ padding:19px; }}
    .hero-side {{ padding:19px; background:#f7fafc; border-left:1px solid var(--border); }}
    .hero-title-row {{ display:flex; align-items:flex-start; justify-content:space-between;
      gap:18px; margin-bottom:15px; }}
    .summary-title {{ margin:0; font-size:1.15rem; }}
    .flow-panel {{ display:grid; grid-template-columns:minmax(0,1fr) auto minmax(0,1fr);
      gap:14px; align-items:center; padding:14px; background:#f8fafc;
      border:1px solid var(--border); border-radius:8px; }}
    .endpoint {{ min-width:0; }}
    .endpoint.destination {{ text-align:right; }}
    .endpoint-label {{ color:var(--text-muted); font-size:.75rem; font-weight:750; }}
    .endpoint-value {{ display:block; margin-top:3px; color:#17324d; font-size:1rem;
      font-weight:800; overflow-wrap:anywhere; }}
    .direction {{ min-width:94px; text-align:center; }}
    .direction-arrow {{ display:block; color:var(--primary); font-size:1.4rem;
      line-height:1; font-weight:800; }}
    .direction-pill {{ display:inline-block; margin-top:7px; padding:3px 9px;
      border-radius:999px; color:#0b4f82; background:#e8f2fb;
      border:1px solid #b8d6eb; font-size:.75rem; font-weight:800; }}
    .summary-stats {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:8px;
      margin:12px 0 0; }}
    .summary-stat {{ min-width:0; padding:10px 11px; background:#f8fafc;
      border:1px solid var(--border); border-radius:7px; }}
    .summary-stat dt {{ color:var(--text-muted); font-size:.74rem; font-weight:700; }}
    .summary-stat dd {{ margin:3px 0 0; color:#17324d; font-weight:850; overflow-wrap:anywhere; }}
    .run-facts {{ display:grid; gap:0; margin:0; }}
    .run-fact {{ display:grid; grid-template-columns:94px minmax(0,1fr); gap:10px;
      padding:9px 0; border-bottom:1px solid #dde6ee; }}
    .run-fact:last-child {{ border-bottom:0; }}
    .run-fact dt {{ color:var(--text-muted); font-size:.76rem; font-weight:750; }}
    .run-fact dd {{ margin:0; color:#17324d; font-size:.84rem; font-weight:750;
      overflow-wrap:anywhere; }}
    .collection-grid {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:9px;
      margin:11px 0 0; }}
    .collection-fact {{ min-width:0; padding:10px 11px; border:1px solid var(--border);
      border-radius:7px; background:#f8fafc; }}
    .collection-fact dt {{ color:var(--text-muted); font-size:.74rem; font-weight:700; }}
    .collection-fact dd {{ margin:3px 0 0; color:#17324d; font-weight:800;
      overflow-wrap:anywhere; }}

    .frequency-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:13px;
      margin-top:12px; }}
    .frequency-card {{ min-width:0; padding:14px; border:1px solid var(--border);
      border-radius:8px; background:#f8fafc; }}
    .frequency-card h3 {{ margin:0 0 10px; color:var(--text); font-size:1.02rem; }}
    .frequency-list {{ display:grid; gap:11px; margin:0; padding:0; list-style:none;
      counter-reset:frequency-rank; }}
    .frequency-item {{ min-width:0; counter-increment:frequency-rank; }}
    .frequency-heading {{ display:flex; justify-content:space-between; gap:10px; align-items:baseline; }}
    .frequency-label {{ min-width:0; color:#17324d; font-size:.86rem; font-weight:800;
      overflow-wrap:anywhere; }}
    .frequency-label::before {{ content:counter(frequency-rank) ". "; color:var(--text-muted);
      font-weight:700; }}
    .frequency-count {{ margin-top:2px; color:var(--text-muted); font-size:.76rem;
      font-variant-numeric:tabular-nums; }}
    .frequency-bar {{ display:flex; width:100%; height:10px; margin-top:5px; overflow:hidden;
      border:1px solid #aebcca; border-radius:999px; background:#e8eef4; }}
    .frequency-source {{ display:block; height:100%; background:#0b5f9a; }}
    .frequency-destination {{ display:block; height:100%; background:#d46b2f; }}
    .frequency-legend {{ display:flex; flex-wrap:wrap; gap:12px; margin:11px 0 0; padding:0;
      list-style:none; color:var(--text-muted); font-size:.76rem; }}
    .frequency-legend li {{ display:inline-flex; align-items:center; gap:5px; }}
    .frequency-swatch {{ width:11px; height:11px; border-radius:2px; border:1px solid #789; }}
    .frequency-swatch.source {{ background:#0b5f9a; }}
    .frequency-swatch.destination {{ background:#d46b2f; }}

    .filter-panel[hidden] {{ display:none !important; }}
    .filter-panel {{ position:relative; background:#f8fafc; border-color:#b9c9d8; }}
    .filter-heading {{ margin:0 0 10px; color:var(--text); font-size:1.16rem;
      font-weight:750; }}
    .filter-grid {{ display:grid; grid-template-columns:minmax(190px,1fr) minmax(150px,.65fr)
      minmax(160px,.75fr) auto; gap:10px; align-items:end; }}
    .filter-field {{ position:relative; min-width:0; }}
    .filter-field label {{ display:block; margin-bottom:5px; color:var(--text);
      font-size:.84rem; font-weight:700; }}
    .filter-input,.filter-select {{ width:100%; min-height:40px; border:1px solid #9fb3c8;
      border-radius:7px; padding:8px 10px; background:#fff; color:var(--text); font:inherit; }}
    .filter-input:focus-visible,.filter-select:focus-visible,.filter-reset:focus-visible,
    .suggestion-list [role="option"]:focus-visible {{ outline:3px solid var(--focus);
      outline-offset:2px; }}
    .suggestion-list {{ position:absolute; z-index:20; left:0; right:0; top:calc(100% + 4px);
      max-height:260px; overflow-y:auto; margin:0; padding:4px; list-style:none; background:#fff;
      border:1px solid #9fb3c8; border-radius:8px; box-shadow:0 9px 24px #102a4326;
      touch-action:pan-y; }}
    .suggestion-list[hidden] {{ display:none !important; }}
    .suggestion-list [role="option"] {{ display:flex; justify-content:space-between; gap:12px;
      padding:8px 9px; border-radius:5px; cursor:pointer; }}
    .suggestion-list [role="option"][aria-selected="true"],
    .suggestion-list [role="option"]:hover {{ background:#e8f3fb; color:#17324d; }}
    .suggestion-value {{ min-width:0; overflow-wrap:anywhere; font-weight:650; }}
    .suggestion-direction {{ flex:0 0 auto; color:var(--text-muted); font-size:.78rem; }}
    .filter-reset {{ min-height:40px; border:1px solid #9fb3c8; border-radius:7px;
      padding:8px 14px; background:#fff; color:var(--primary); font:inherit; font-weight:700;
      cursor:pointer; white-space:nowrap; }}
    .filter-reset:hover {{ background:#f0f7fc; }}
    .filter-help {{ margin:9px 0 0; color:var(--text-muted); font-size:.82rem; }}
    .filter-meta {{ margin-top:9px; }}
    .section-heading-row {{ display:flex; align-items:baseline; justify-content:space-between;
      gap:12px; margin-bottom:5px; }}
    .section-heading-row h2 {{ margin:0; }}
    .filter-count {{ display:inline-block; border-radius:999px; padding:3px 9px;
      background:#edf2f7; color:var(--neutral); font-size:.78rem; font-weight:700; }}
    .filter-status {{ min-height:1.5em; margin:0; color:var(--text-muted); font-size:.82rem; }}
    .print-filter-summary {{ display:none; }}
    .print-filter-summary[hidden] {{ display:none !important; }}
    tr[hidden],.filter-empty-row[hidden] {{ display:none !important; }}

    .table-wrap {{ overflow-x:auto; border:1px solid var(--border); border-radius:7px;
      background:#fff; }}
    .table-wrap:focus-visible,summary:focus-visible {{ outline:3px solid var(--focus);
      outline-offset:2px; }}
    table {{ width:100%; min-width:900px; border-collapse:collapse; font-size:.87rem; }}
    th,td {{ padding:9px 10px; border-bottom:1px solid var(--border); text-align:left;
      vertical-align:top; }}
    th {{ background:var(--surface-strong); color:#17324d; position:sticky; top:0;
      white-space:nowrap; font-size:.79rem; }}
    tbody tr:nth-child(even) {{ background:#fbfdff; }}
    tbody tr:hover {{ background:#f2f8fc; }}
    tr:last-child td {{ border-bottom:0; }}
    .protocol-cell,.endpoint-cell,.time-cell {{ white-space:nowrap;
      font-variant-numeric:tabular-nums; }}
    .protocol-cell,.endpoint-cell {{ color:#17324d; font-weight:700; }}
    .time-cell,.device-cell {{ color:var(--text-muted); }}
    .device-cell {{ max-width:240px; overflow-wrap:anywhere; }}
    .badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:.78rem;
      font-weight:700; background:#e6fffa; color:var(--success);
      border:1px solid #9ae6d3; white-space:nowrap; }}
    .badge.missed {{ background:#fff8e7; color:var(--warning); border-color:#e7c978; }}
    .badge.closed {{ background:#fff1f0; color:var(--danger); border-color:#f3b6b0; }}
    .badge.observed {{ background:#edf2f7; color:var(--neutral); border-color:#cbd5e1; }}
    details {{ border:0; }}
    summary {{ cursor:pointer; color:var(--primary); font-weight:700; padding:9px 11px;
      border:1px solid var(--border); border-radius:7px; background:#f8fafc; }}
    summary:hover {{ color:var(--primary-hover); background:#f0f7fc; }}
    .history-toggle:not([open]) + .details-body {{ display:none; }}
    .history-toggle[open] + .details-body {{ display:block; }}
    .details-body {{ padding-top:2px; }}
    .muted {{ color:var(--text-muted); text-align:center; padding:24px 12px; }}
    .footer {{ padding:0 0 20px; color:var(--text-muted); font-size:.8rem; }}
    .privacy-note {{ padding-top:7px; border-top:1px solid #cad6df; }}
    .sr-only {{ position:absolute; width:1px; height:1px; padding:0; margin:-1px;
      overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }}

    @media (max-width:1000px) {{
      .hero-grid {{ grid-template-columns:1fr; }}
      .hero-side {{ border-left:0; border-top:1px solid var(--border); }}
    }}
    @media (max-width:850px) {{
      .report-header-inner,.content,.footer {{ width:min(100% - 20px,1240px); }}
      section {{ padding:14px; }}
      .summary-stats {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
      .filter-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
      .frequency-grid {{ grid-template-columns:1fr; }}
      .collection-grid {{ grid-template-columns:1fr; }}
    }}
    @media (max-width:720px) {{
      .report-header-inner {{ align-items:flex-start; }}
      .flow-panel {{ grid-template-columns:1fr; gap:9px; padding:12px; }}
      .endpoint.destination {{ text-align:left; }}
      .direction {{ text-align:left; min-width:0; }}
      .direction-arrow {{ transform:rotate(90deg); transform-origin:left center;
        margin-left:8px; }}
    }}
    @media (max-width:520px) {{
      .report-header-inner {{ display:block; }}
      .run-state {{ margin-top:9px; }}
      .hero-title-row {{ display:block; }}
      .hero-title-row .run-state {{ margin-top:9px; }}
      .filter-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
      .filter-field:first-child,.filter-reset {{ grid-column:1 / -1; }}
      .filter-reset {{ width:100%; }}
    }}
    @media (max-width:360px) {{
      .summary-stats,.filter-grid {{ grid-template-columns:1fr; }}
    }}
    @media (forced-colors:active) {{
      .report-header {{ border-bottom-color:Highlight; }}
      .run-state,.direction-pill,.summary-stat,.flow-panel,.hero-side,.frequency-card,
      .frequency-bar,.frequency-swatch,
      .filter-input,.filter-select,.filter-reset,.filter-count,.suggestion-list,
      .table-wrap,.badge,summary {{ border:1px solid CanvasText; forced-color-adjust:auto; }}
      .run-state::before,.frequency-source,.frequency-swatch.source {{ background:Highlight; }}
      .frequency-destination,.frequency-swatch.destination {{ background:LinkText; }}
      .filter-input:focus-visible,.filter-select:focus-visible,.filter-reset:focus-visible,
      .suggestion-list [role="option"]:focus-visible,.table-wrap:focus-visible,
      summary:focus-visible {{ outline-color:Highlight; }}
    }}
    @page {{ size:A4 landscape; margin:10mm; }}
    @media print {{
      body {{ background:#fff; color:#000; }}
      .report-header {{ background:#fff; color:#000; padding:0 0 10px; border:0; }}
      .product-name,.report-subtitle {{ color:#333; }}
      .report-header-inner,.content,.footer {{ width:100%; }}
      .report-header-inner {{ padding:0; }}
      .content {{ padding:0; }}
      section {{ border:0; border-radius:0; padding:0; margin-bottom:8px; }}
      .hero-grid,.frequency-grid {{ grid-template-columns:1fr 1fr; }}
      .hero-side {{ border:0; }}
      .flow-panel {{ grid-template-columns:minmax(0,1fr) auto minmax(0,1fr);
        gap:14px; background:#fff; }}
      .endpoint.destination {{ text-align:right; }}
      .direction {{ min-width:94px; text-align:center; }}
      .direction-arrow {{ transform:none; margin-left:0; }}
      .history-toggle {{ display:none; }} .history-toggle + .details-body {{ display:block !important; }}
      .filter-panel {{ display:none !important; }}
      .print-filter-summary {{ display:block; margin:0 0 10px; padding:7px 9px;
        border:1px solid #bbb; font-size:8.5pt; }}
      .table-wrap {{ overflow:visible; border:0; }}
      table {{ min-width:0; font-size:7.5pt; }}
      thead {{ display:table-header-group; }}
      th {{ position:static; }}
      th,td {{ padding:4px; overflow-wrap:anywhere; }}
      .muted {{ padding:8px 4px; }}
      .summary-stats,.flow-panel,.frequency-card,.frequency-item,.collection-fact,tr {{ break-inside:avoid; }}
      .frequency-source,.frequency-destination {{ print-color-adjust:exact; }}
      tbody tr:nth-child(even),tbody tr:hover {{ background:#fff; }}
    }}
  </style>
</head>
<body>
  <header class="report-header"><div class="report-header-inner">
    <div>
      <p class="product-name">ARUBA SESSION TRACKER</p>
      <h1>세션 추적 결과</h1>
      <p class="report-subtitle">Network Session Investigation Report</p>
    </div>
    <div class="run-state {_base._e(run_status_class)}">{_base._e(run_status)}</div>
  </div></header>

  <main class="content">
    <section class="report-hero" aria-labelledby="query-summary-title">
      <div class="hero-grid">
        <div class="hero-main">
          <div class="hero-title-row">
            <div>
              <p class="section-kicker">INVESTIGATION SCOPE</p>
              <h2 id="query-summary-title" class="summary-title">조회 요약</h2>
            </div>
          </div>
          <div class="flow-panel">
            <div class="endpoint">
              <span class="endpoint-label">조회 출발지</span>
              <span class="endpoint-value">{_base._e(source_endpoint)}</span>
            </div>
            <div class="direction" aria-label="{_base._e(query_direction)} 검색">
              <span class="direction-arrow" aria-hidden="true">{_base._e(direction_symbol)}</span>
              <span class="direction-pill">{_base._e(query_direction)}</span>
            </div>
            <div class="endpoint destination">
              <span class="endpoint-label">조회 목적지</span>
              <span class="endpoint-value">{_base._e(destination_endpoint)}</span>
            </div>
          </div>
          <dl class="summary-stats">
            {_base._summary_stat("추적 시작", _base._format_kst(run.get("started_at")))}
            {_base._summary_stat("추적 종료", _base._format_kst(run.get("ended_at")))}
            {_base._summary_stat("전체 관측", f"{_base._format_integer(snapshot.observation_total)}건")}
            {_base._summary_stat("고유 세션", f"{_base._format_integer(total_sessions)}개")}
          </dl>
        </div>
        <aside class="hero-side" aria-label="보고서 기준">
          <p class="section-kicker">REPORT BASIS</p>
          <dl class="run-facts">
            {_run_fact("조회 대상", query_target)}
            {_run_fact("추적 시간", duration)}
            {_run_fact("최신 표시", f"{_base._format_integer(displayed_latest)}/{_base._format_integer(total_sessions)}개")}
            {_run_fact("전체 이력", f"{_base._format_integer(snapshot.observation_total)}건")}
          </dl>
        </aside>
      </div>
    </section>

    <section id="observation-frequency" aria-labelledby="observation-frequency-title">
      <p class="section-kicker">FULL-HISTORY FREQUENCY</p>
      <h2 id="observation-frequency-title">전체 이력 관측 빈도 TOP 5</h2>
      <p class="section-note">저장된 전체 관측 {_base._format_integer(snapshot.observation_total)}건의 각 행에서 출발지와 목적지를 각각 1회로 집계합니다. IP는 빈 값을, 포트·프로토콜은 0번 포트를 제외합니다. 관측 횟수이며 트래픽 양·전송량·원인을 의미하지 않고, 아래 결과 필터와도 연동되지 않습니다.</p>
      <ul class="frequency-legend" aria-label="막대 색상 안내">
        <li><span class="frequency-swatch source" aria-hidden="true"></span>출발지</li>
        <li><span class="frequency-swatch destination" aria-hidden="true"></span>목적지</li>
      </ul>
      <div class="frequency-grid">
        <article class="frequency-card" aria-labelledby="ip-frequency-title">
          <h3 id="ip-frequency-title">IP별 관측 횟수 TOP 5</h3>
          {_frequency_chart_markup(ip_frequency_summary, _ip_frequency_label, "집계할 IP가 없습니다.")}
        </article>
        <article class="frequency-card" aria-labelledby="protocol-port-frequency-title">
          <h3 id="protocol-port-frequency-title">포트·프로토콜별 관측 횟수 TOP 5</h3>
          {_frequency_chart_markup(protocol_port_frequency_summary, _protocol_port_frequency_label, "집계할 프로토콜·포트가 없습니다.")}
        </article>
      </div>
    </section>

    <section id="result-filter" class="filter-panel js-only" aria-labelledby="result-filter-title" hidden>
      <h2 id="result-filter-title" class="filter-heading">결과 찾기</h2>
      <div class="filter-grid">
        <div class="filter-field">
          <label for="filter-ip">IP 검색</label>
          <input id="filter-ip" class="filter-input" type="text" role="combobox"
            autocomplete="off" spellcheck="false" aria-autocomplete="list"
            aria-controls="filter-ip-list" aria-expanded="false"
            aria-describedby="filter-help filter-status">
          <div id="filter-ip-list" class="suggestion-list" role="listbox"
            aria-label="IP 추천값" hidden></div>
        </div>
        <div class="filter-field">
          <label for="filter-protocol">프로토콜</label>
          <select id="filter-protocol" class="filter-select" aria-label="프로토콜"
            aria-describedby="filter-status">
            <option value="">전체</option>
          </select>
        </div>
        <div class="filter-field">
          <label for="filter-port">포트 검색</label>
          <input id="filter-port" class="filter-input" type="text" role="combobox"
            autocomplete="off" spellcheck="false" aria-autocomplete="list"
            aria-controls="filter-port-list" aria-expanded="false"
            aria-describedby="filter-help filter-status">
          <div id="filter-port-list" class="suggestion-list" role="listbox"
            aria-label="포트 추천값" hidden></div>
        </div>
        <button id="filter-reset" class="filter-reset" type="button">전체 초기화</button>
      </div>
      <p id="filter-help" class="filter-help">한 글자 이상 입력하면 최대 12개의 완성값을 추천합니다. 방향키와 Enter 또는 마우스로 선택할 수 있습니다.</p>
      <div class="filter-meta">
        <p id="filter-status" class="filter-status" role="status" aria-live="polite"></p>
      </div>
    </section>
    <p id="print-filter-summary" class="print-filter-summary" hidden></p>

    <section id="latest-sessions">
      <div class="section-heading-row">
        <div>
          <p class="section-kicker">LATEST LOGICAL SESSIONS</p>
          <h2>최신 세션 결과</h2>
        </div>
        <span id="latest-filter-count" class="filter-count" aria-live="polite">최신 {_base._format_integer(displayed_latest)}/{_base._format_integer(displayed_latest)}건</span>
      </div>
      <p id="latest-result-note" class="section-note">{_base._e(latest_note)}</p>
      <div class="table-wrap" role="region" aria-label="최신 세션 결과 표" tabindex="0"><table>
        <caption class="sr-only">최신 세션 결과</caption>
        <thead><tr><th scope="col">프로토콜</th><th scope="col">출발지 IP·포트</th><th scope="col">목적지 IP·포트</th><th scope="col">추적 상태</th><th scope="col">마지막 확인</th><th scope="col">장비</th></tr></thead>
        <tbody id="latest-results-body">{latest_rows or _base._empty_row(6, "관측된 세션이 없습니다.")}
          <tr id="latest-filter-empty" class="filter-empty-row" hidden><td colspan="6" class="muted">선택한 필터와 일치하는 세션이 없습니다.</td></tr>
        </tbody>
      </table></div>
    </section>

    <section id="collection-information" aria-labelledby="collection-information-title">
      <p class="section-kicker">COLLECTION INFORMATION</p>
      <h2 id="collection-information-title">수집 정보</h2>
      <p class="section-note">최신 세션 결과에 실제로 기록된 장비 이름만 표시하며 장비 도달성이나 상태를 의미하지 않습니다.</p>
      <dl class="collection-grid">
        {_collection_fact("최근 세션 관측 장비", observed_controller_text)}
        {_collection_fact("최신 세션 표시 범위", f"{_base._format_integer(displayed_latest)}/{_base._format_integer(total_sessions)}개")}
        {_collection_fact("저장된 전체 관측", f"{_base._format_integer(snapshot.observation_total)}건")}
      </dl>
    </section>

    <section id="observation-history">
      <div class="section-heading-row">
        <div>
          <p class="section-kicker">COMPLETE OBSERVATION HISTORY</p>
          <h2>전체 추적 이력</h2>
        </div>
        <span id="history-filter-count" class="filter-count" aria-live="polite">전체 {_base._format_integer(snapshot.observation_total)}/{_base._format_integer(snapshot.observation_total)}건</span>
      </div>
      <details class="history-toggle">
        <summary id="history-filter-summary" aria-controls="observation-history-body">전체 추적 이력 {_base._format_integer(snapshot.observation_total)}/{_base._format_integer(snapshot.observation_total)}건 보기</summary>
      </details>
      <div class="details-body" id="observation-history-body">
        <p class="section-note">저장된 관측 결과를 시간순으로 모두 표시합니다.</p>
        <div class="table-wrap" role="region" aria-label="전체 추적 이력 표" tabindex="0"><table>
          <caption class="sr-only">전체 추적 이력</caption>
          <thead><tr><th scope="col">프로토콜</th><th scope="col">출발지 IP·포트</th><th scope="col">목적지 IP·포트</th><th scope="col">추적 상태</th><th scope="col">확인 시각</th><th scope="col">장비</th></tr></thead>
          <tbody id="history-results-body">"""
    history_count = 0
    for row in history:
        history_count += 1
        yield _base._observation_row(row, "관측됨")
    if history_count == 0:
        yield _base._empty_row(6, "저장된 관측 이력이 없습니다.")
    yield """<tr id="history-filter-empty" class="filter-empty-row" hidden><td colspan="6" class="muted">선택한 필터와 일치하는 세션이 없습니다.</td></tr>
          </tbody>
        </table></div>
      </div>
    </section>
  </main>
  <footer class="footer">
    <div class="privacy-note">Aruba Session Tracker 결과 보고서 · 로컬 저장 결과만 표시하며 Raw CLI와 진단 내부정보는 포함하지 않습니다.</div>
  </footer>
  <script>"""
    yield _base._FILTER_SCRIPT
    yield """</script>
</body>
</html>
"""


def _resolve_ip_frequency_summary(
    snapshot: RunReportSnapshot,
    rows: Iterable[ReportRow],
) -> tuple[tuple[str, int, int], ...]:
    summary = snapshot.ip_frequency_summary
    if summary is None:
        return _top_ip_frequencies(rows)
    return _normalize_ip_frequencies(summary)


def _resolve_protocol_port_frequency_summary(
    snapshot: RunReportSnapshot,
    rows: Iterable[ReportRow],
) -> tuple[tuple[int, int, int, int], ...]:
    summary = snapshot.protocol_port_frequency_summary
    if summary is None:
        return _top_protocol_port_frequencies(rows)
    return _normalize_protocol_port_frequencies(summary)


def _top_ip_frequencies(rows: Iterable[ReportRow]) -> tuple[tuple[str, int, int], ...]:
    counts: dict[str, list[int]] = {}
    for row in rows:
        source = _frequency_ip(row.get("source_ip"))
        destination = _frequency_ip(row.get("destination_ip"))
        if source:
            counts.setdefault(source, [0, 0])[0] += 1
        if destination:
            counts.setdefault(destination, [0, 0])[1] += 1
    return _normalize_ip_frequencies(
        (address, direction_counts[0], direction_counts[1])
        for address, direction_counts in counts.items()
    )


def _top_protocol_port_frequencies(
    rows: Iterable[ReportRow],
) -> tuple[tuple[int, int, int, int], ...]:
    counts: dict[tuple[int, int], list[int]] = {}
    for row in rows:
        protocol = _base._optional_int(row.get("protocol"))
        if protocol is None or not 0 <= protocol <= 255:
            continue
        for direction_index, field in enumerate(("source_port", "destination_port")):
            port = _base._optional_int(row.get(field))
            if port is None or not 1 <= port <= 65535:
                continue
            counts.setdefault((protocol, port), [0, 0])[direction_index] += 1
    return _normalize_protocol_port_frequencies(
        (protocol, port, direction_counts[0], direction_counts[1])
        for (protocol, port), direction_counts in counts.items()
    )


def _normalize_ip_frequencies(
    rows: Iterable[tuple[str, int, int]],
) -> tuple[tuple[str, int, int], ...]:
    combined: dict[str, list[int]] = {}
    for address, source_count, destination_count in rows:
        clean_address = _frequency_ip(address)
        source = max(0, int(source_count))
        destination = max(0, int(destination_count))
        if not clean_address or source + destination == 0:
            continue
        target = combined.setdefault(clean_address, [0, 0])
        target[0] += source
        target[1] += destination
    ordered = sorted(
        (
            (address, direction_counts[0], direction_counts[1])
            for address, direction_counts in combined.items()
        ),
        key=lambda item: (-(item[1] + item[2]), item[0]),
    )
    return tuple(ordered[:_FREQUENCY_LIMIT])


def _normalize_protocol_port_frequencies(
    rows: Iterable[tuple[int, int, int, int]],
) -> tuple[tuple[int, int, int, int], ...]:
    combined: dict[tuple[int, int], list[int]] = {}
    for protocol_value, port_value, source_count, destination_count in rows:
        protocol = _base._optional_int(protocol_value)
        port = _base._optional_int(port_value)
        source = max(0, int(source_count))
        destination = max(0, int(destination_count))
        if (
            protocol is None
            or port is None
            or not 0 <= protocol <= 255
            or not 1 <= port <= 65535
            or source + destination == 0
        ):
            continue
        target = combined.setdefault((protocol, port), [0, 0])
        target[0] += source
        target[1] += destination
    ordered = sorted(
        (
            (protocol, port, direction_counts[0], direction_counts[1])
            for (protocol, port), direction_counts in combined.items()
        ),
        key=lambda item: (-(item[2] + item[3]), item[0], item[1]),
    )
    return tuple(ordered[:_FREQUENCY_LIMIT])


def _frequency_ip(value: object) -> str:
    return "" if value is None else str(value).strip()


def _frequency_chart_markup(
    rows: tuple[FrequencyRow, ...],
    labeler: Callable[[FrequencyRow], str],
    empty_message: str,
) -> str:
    if not rows:
        return f'<p class="muted">{_base._e(empty_message)}</p>'
    maximum = max(row[-2] + row[-1] for row in rows)
    items: list[str] = []
    for row in rows:
        source_count = row[-2]
        destination_count = row[-1]
        total = source_count + destination_count
        source_width = source_count / maximum * 100.0
        destination_width = destination_count / maximum * 100.0
        label = labeler(row)
        items.append(
            '<li class="frequency-item">'
            '<div class="frequency-heading">'
            f'<span class="frequency-label">{_base._e(label)}</span>'
            "</div>"
            f'<div class="frequency-count">총 {_base._format_integer(total)}회 · '
            f"출발지 {_base._format_integer(source_count)}회 · "
            f"목적지 {_base._format_integer(destination_count)}회</div>"
            '<div class="frequency-bar" aria-hidden="true">'
            f'<span class="frequency-source" style="width:{source_width:.4f}%"></span>'
            f'<span class="frequency-destination" style="width:{destination_width:.4f}%"></span>'
            "</div></li>"
        )
    return '<ol class="frequency-list" role="list">' + "".join(items) + "</ol>"


def _ip_frequency_label(row: FrequencyRow) -> str:
    return str(row[0])


def _protocol_port_frequency_label(row: FrequencyRow) -> str:
    protocol = int(row[0])
    port = int(row[1])
    return f"{_base._protocol(protocol)} · {service_label(protocol, port)}"


def _format_duration(started_at: object, ended_at: object) -> str:
    started = _base._parse_datetime(started_at)
    ended = _base._parse_datetime(ended_at)
    if started is None or ended is None or ended < started:
        return "-"
    total_seconds = int((ended - started).total_seconds())
    days, remaining = divmod(total_seconds, 86_400)
    hours, remaining = divmod(remaining, 3_600)
    minutes, seconds = divmod(remaining, 60)
    if days:
        return f"{days}일 {hours}시간 {minutes}분 {seconds}초"
    if hours:
        return f"{hours}시간 {minutes}분 {seconds}초"
    return f"{minutes}분 {seconds}초"


def _display_query_target(run: ReportRow) -> str:
    source = _frequency_ip(run.get("source_ip"))
    destination = _frequency_ip(run.get("destination_ip"))
    if source and destination:
        return f"{source} → {destination}"
    if source:
        return f"출발지: {source}"
    if destination:
        return f"목적지: {destination}"
    return "조회 대상 없음"


def _observed_controllers(rows: tuple[ReportRow, ...]) -> tuple[str, ...]:
    values = {value for row in rows if (value := _base._plain(row.get("controller_name"))) != "-"}
    return tuple(sorted(values, key=lambda value: (value.casefold(), value)))


def _run_fact(label: str, value: object) -> str:
    return f'<div class="run-fact"><dt>{_base._e(label)}</dt><dd>{_base._e(value)}</dd></div>'


def _collection_fact(label: str, value: object) -> str:
    return (
        f'<div class="collection-fact"><dt>{_base._e(label)}</dt><dd>{_base._e(value)}</dd></div>'
    )


__all__ = [
    "render_html_report",
    "write_html_report_atomic",
    "write_html_report_stream_atomic",
]
