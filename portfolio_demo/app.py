from __future__ import annotations

import sys
from dataclasses import asdict
from html import escape
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aruba_session_tracker.parsers.flags import interpret_flags
from portfolio_demo.execution_trace import render_trace
from portfolio_demo.fixture_transport import CONFIG
from portfolio_demo.guided_flow import GuidedSlot, begin
from portfolio_demo.runtime import DemoRuntime, QueryRequest
from portfolio_demo.scenario_runner import SCENARIOS, ScenarioRunner
from portfolio_demo.scenario_view import render_communication, render_timeline

st.set_page_config(
    page_title="Aruba Session Tracker · Public Web Edition",
    page_icon="📡",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1540px;
        padding-top: 1.15rem;
        padding-bottom: 3rem;
    }
    .product-shell {
        border: 1px solid rgba(120, 145, 175, .24);
        border-radius: 14px;
        background: rgba(15, 23, 35, .58);
        padding: 12px 16px;
        margin-bottom: .55rem;
    }
    .product-name {
        font-size: 1.4rem;
        font-weight: 850;
        letter-spacing: .02em;
    }
    .product-meta {
        color: #8797aa;
        font-size: .8rem;
        margin-top: .15rem;
    }
    .header-chip {
        border: 1px solid rgba(120, 145, 175, .24);
        border-radius: 9px;
        padding: 7px 9px;
        min-height: 54px;
        background: rgba(17, 26, 39, .55);
    }
    .header-chip-label {
        font-size: .68rem;
        color: #8191a5;
        font-weight: 750;
    }
    .header-chip-value {
        font-size: .86rem;
        font-weight: 800;
        margin-top: .15rem;
    }
    .query-box {
        border: 1px solid rgba(120, 145, 175, .23);
        border-radius: 11px;
        padding: 12px 14px;
        background: rgba(18, 27, 41, .46);
    }
    .flow-card {
        border: 1px solid rgba(120, 145, 175, .23);
        border-radius: 11px;
        padding: 10px 12px;
        background: rgba(18, 27, 41, .52);
        min-height: 82px;
    }
    .flow-label {
        color: #8495a9;
        font-size: .7rem;
        font-weight: 800;
    }
    .flow-value {
        font-size: .95rem;
        font-weight: 800;
        margin-top: .22rem;
    }
    .demo-pill {
        display: inline-block;
        border: 1px solid #38506d;
        border-radius: 999px;
        padding: .16rem .5rem;
        margin-right: .3rem;
        color: #afc8ee;
        font-size: .66rem;
        font-weight: 800;
    }
    [data-testid="stMetricValue"] {
        white-space: normal; overflow-wrap: anywhere; font-size: clamp(1rem, 2.2vw, 2rem);
    }
    .header-chip-value {overflow-wrap: anywhere;}
    .noc-hero {
        position: relative;
        overflow: hidden;
        border: 1px solid rgba(91, 143, 193, .38);
        border-radius: 16px;
        background:
            linear-gradient(135deg, rgba(10, 18, 29, .98), rgba(16, 31, 48, .94)),
            radial-gradient(circle at 88% 8%, rgba(61, 137, 205, .18), transparent 34%);
        padding: 18px 20px 16px;
        margin-bottom: .7rem;
        box-shadow: 0 14px 36px rgba(0, 0, 0, .18);
    }
    .noc-hero::after {
        content: "";
        position: absolute;
        inset: 0;
        pointer-events: none;
        background-image:
            linear-gradient(rgba(120, 160, 205, .035) 1px, transparent 1px),
            linear-gradient(90deg, rgba(120, 160, 205, .035) 1px, transparent 1px);
        background-size: 28px 28px;
    }
    .noc-hero-top {
        position: relative;
        z-index: 1;
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        align-items: flex-start;
    }
    .noc-eyebrow {
        font-size: .69rem;
        letter-spacing: .16em;
        font-weight: 850;
        color: #7db8ee;
        margin-bottom: .35rem;
    }
    .noc-title {
        font-size: clamp(1.55rem, 3vw, 2.2rem);
        line-height: 1.05;
        font-weight: 900;
        letter-spacing: .025em;
    }
    .noc-subtitle {
        margin-top: .45rem;
        color: #9aadc2;
        font-size: .82rem;
        font-weight: 650;
    }
    .noc-badges {
        display: flex;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: .4rem;
    }
    .noc-badge {
        border: 1px solid rgba(126, 178, 224, .38);
        border-radius: 999px;
        padding: .24rem .58rem;
        font-size: .66rem;
        font-weight: 850;
        letter-spacing: .045em;
        color: #c7def5;
        background: rgba(30, 57, 82, .46);
        white-space: nowrap;
    }
    .noc-hero-summary {
        position: relative;
        z-index: 1;
        margin-top: 1rem;
        padding-top: .85rem;
        border-top: 1px solid rgba(130, 160, 190, .18);
        color: #d9e3ed;
        font-size: .92rem;
    }
    .noc-status-strip {
        display: grid;
        grid-template-columns: 1.15fr repeat(5, 1fr);
        gap: 1px;
        border: 1px solid rgba(107, 139, 171, .3);
        border-radius: 12px;
        overflow: hidden;
        margin: .55rem 0 1rem;
        background: rgba(91, 118, 145, .18);
    }
    .noc-status-item {
        min-width: 0;
        background: rgba(13, 22, 34, .86);
        padding: .62rem .72rem;
    }
    .noc-status-label {
        display: block;
        color: #7f91a4;
        font-size: .62rem;
        letter-spacing: .08em;
        font-weight: 800;
        text-transform: uppercase;
    }
    .noc-status-value {
        display: block;
        margin-top: .18rem;
        font-size: .79rem;
        font-weight: 850;
        overflow-wrap: anywhere;
    }
    .noc-status-main {
        display: flex;
        align-items: center;
        gap: .48rem;
    }
    .noc-dot {
        width: .52rem;
        height: .52rem;
        border-radius: 50%;
        flex: 0 0 auto;
        box-shadow: 0 0 0 4px rgba(117, 153, 188, .08);
    }
    .noc-dot-ok { background: #55c993; box-shadow: 0 0 0 4px rgba(85, 201, 147, .12); }
    .noc-dot-warn { background: #e0b35c; box-shadow: 0 0 0 4px rgba(224, 179, 92, .12); }
    .noc-dot-idle { background: #7e91a5; }
    .review-brief {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .75rem;
        margin: .35rem 0 1rem;
    }
    .review-card {
        border: 1px solid rgba(111, 146, 181, .28);
        border-radius: 13px;
        background: linear-gradient(180deg, rgba(22, 34, 49, .72), rgba(15, 24, 36, .62));
        padding: .95rem 1rem;
        min-height: 132px;
    }
    .review-card-kicker {
        font-size: .66rem;
        color: #76afe3;
        letter-spacing: .12em;
        font-weight: 850;
        margin-bottom: .38rem;
    }
    .review-card-title {
        font-weight: 900;
        font-size: 1rem;
        margin-bottom: .4rem;
    }
    .review-card p {
        margin: 0;
        line-height: 1.55;
        color: #c9d5e1;
        font-size: .86rem;
    }
    .runbook-heading {
        border-left: 3px solid #589bd6;
        padding-left: .75rem;
        margin: .9rem 0 .55rem;
    }
    .runbook-heading .kicker {
        font-size: .64rem;
        letter-spacing: .12em;
        color: #7f9bb6;
        font-weight: 850;
    }
    .runbook-heading .title {
        margin-top: .12rem;
        font-size: 1.03rem;
        font-weight: 900;
    }
    .topology-shell {
        border: 1px solid rgba(91, 139, 184, .34);
        border-radius: 15px;
        background: linear-gradient(180deg, rgba(14, 24, 37, .92), rgba(12, 19, 30, .86));
        padding: 1rem;
        margin: .7rem 0 1rem;
        box-shadow: inset 0 1px 0 rgba(255,255,255,.025);
    }
    .topology-head {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: .8rem;
        margin-bottom: .9rem;
    }
    .topology-kicker {
        color: #7f9bb6;
        font-size: .64rem;
        letter-spacing: .12em;
        font-weight: 850;
    }
    .topology-title {
        font-weight: 900;
        font-size: 1.05rem;
        margin-top: .1rem;
    }
    .topology-state {
        border-radius: 999px;
        padding: .27rem .58rem;
        font-size: .67rem;
        font-weight: 900;
        letter-spacing: .04em;
        border: 1px solid rgba(91, 182, 140, .45);
        color: #9ee0bd;
        background: rgba(35, 96, 65, .24);
    }
    .topology-state.warn {
        border-color: rgba(211, 166, 73, .45);
        color: #e7c882;
        background: rgba(107, 75, 24, .24);
    }
    .topology-path {
        display: grid;
        grid-template-columns: minmax(150px, 1fr) 52px minmax(150px, 1fr) 52px minmax(150px, 1fr);
        gap: .55rem;
        align-items: stretch;
    }
    .topology-node {
        border: 1px solid rgba(118, 151, 185, .28);
        border-radius: 12px;
        background: rgba(21, 34, 50, .82);
        padding: .8rem .85rem;
        min-height: 92px;
    }
    .topology-node.client { border-top: 2px solid #60a6df; }
    .topology-node.mm { border-top: 2px solid #8399d8; }
    .topology-node.md { border-top: 2px solid #5fc09a; }
    .topology-node-kind {
        color: #7f91a6;
        font-size: .61rem;
        letter-spacing: .095em;
        font-weight: 850;
    }
    .topology-node-value {
        font-weight: 900;
        font-size: .96rem;
        margin-top: .34rem;
        overflow-wrap: anywhere;
    }
    .topology-node-meta {
        color: #91a3b6;
        font-size: .72rem;
        margin-top: .26rem;
    }
    .topology-link {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        color: #77a9d3;
        font-weight: 900;
        font-size: 1.2rem;
    }
    .topology-link small {
        margin-top: .2rem;
        color: #6f8194;
        font-size: .55rem;
        line-height: 1.15;
        text-align: center;
        font-weight: 750;
    }
    .peer-section {
        border-top: 1px solid rgba(110, 142, 174, .2);
        margin-top: .9rem;
        padding-top: .85rem;
    }
    .peer-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .55rem;
        margin-top: .55rem;
    }
    .peer-card {
        border: 1px solid rgba(109, 141, 174, .26);
        border-radius: 10px;
        background: rgba(18, 29, 43, .76);
        padding: .7rem .76rem;
    }
    .peer-card .proto {
        display: inline-block;
        font-size: .62rem;
        font-weight: 900;
        border: 1px solid rgba(104, 154, 201, .38);
        border-radius: 999px;
        padding: .12rem .38rem;
        color: #a8cbea;
        margin-bottom: .38rem;
    }
    .peer-card .peer {
        font-size: .85rem;
        font-weight: 850;
        overflow-wrap: anywhere;
    }
    .peer-card .meta {
        margin-top: .28rem;
        color: #8295a8;
        font-size: .68rem;
    }
    .topology-foot {
        margin-top: .7rem;
        color: #76899d;
        font-size: .7rem;
    }
    @media(max-width:900px) {
        .noc-status-strip {grid-template-columns: repeat(3, 1fr);}
        .topology-path {grid-template-columns: 1fr; gap:.35rem;}
        .topology-link {min-height:32px; transform:rotate(90deg);}
        .topology-link small {display:none;}
        .peer-grid {grid-template-columns:1fr;}
    }
    @media(max-width:700px) {
        .noc-hero-top {flex-direction:column;}
        .noc-badges {justify-content:flex-start;}
        .review-brief {grid-template-columns:1fr;}
        .noc-status-strip {grid-template-columns:repeat(2, 1fr);}
    }
    </style>
    """,
    unsafe_allow_html=True,
)

if "runtime" not in st.session_state:
    st.session_state.runtime = DemoRuntime()
if "session_demo_mode" not in st.session_state:
    st.session_state.session_demo_mode = "timeline"

r = st.session_state.runtime


def operating_state() -> str:
    if r.outcome is None:
        return "대기"
    if r.outcome.authoritative:
        return "정상"
    if r.result is not None and r.result.retry_after_seconds:
        return "재시도 중"
    return "확인 필요"


def latest_seen() -> str:
    rows = r.rows() if r.outcome else []
    values = [
        str(row.get("Last Seen", "")).strip()
        for row in rows
        if str(row.get("Last Seen", "")).strip()
    ]
    if values:
        return max(values)
    if r.poll_count:
        return f"Poll {r.poll_count}"
    return "—"


def render_header() -> None:
    st.markdown(
        """
        <section class="noc-hero">
          <div class="noc-hero-top">
            <div>
              <div class="noc-eyebrow">ENTERPRISE WLAN · SESSION INVESTIGATION</div>
              <div class="noc-title">ARUBA SESSION TRACKER</div>
              <div class="noc-subtitle">
                Wireless Client → Mobility Conductor → Managed Device → Datapath Session
              </div>
            </div>
            <div class="noc-badges">
              <span class="noc-badge">READ ONLY</span>
              <span class="noc-badge">PUBLIC DEMO</span>
              <span class="noc-badge">SYNTHETIC TRANSPORT</span>
            </div>
          </div>
          <div class="noc-hero-summary">
            단말 IP 하나에서 출발해 위치를 찾고, 담당 Controller를 식별한 뒤
            실제 통신 세션과 상태 변화를 추적하는 Enterprise WLAN 장애 조사 콘솔입니다.
          </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def render_reviewer_summary() -> None:
    st.markdown(
        """
        <section class="review-brief" aria-label="비전공 검토자를 위한 프로젝트 설명">
          <article class="review-card">
            <div class="review-card-kicker">WHY THIS EXISTS</div>
            <div class="review-card-title">프로젝트 목적</div>
            <p>
              특정 기기의 IP 주소 하나를 시작점으로 어느 무선 장비에 연결되어 있고,
              현재 어떤 대상과 통신하는지를 자동으로 따라갑니다.
              사람이 여러 장비에 접속해 순서대로 확인하던 장애 조사 절차를 하나로 묶습니다.
            </p>
          </article>
          <article class="review-card">
            <div class="review-card-kicker">WHAT TO WATCH</div>
            <div class="review-card-title">이 데모에서 보여주는 것</div>
            <p>
              단말 IP → 위치 확인 → 담당 Controller 선택 → 통신 세션 조회 →
              통신 상대와 상태 변화까지 한 번의 실행으로 보여줍니다.
              수집 실패를 통신 종료로 오판하지 않는 과정도 함께 확인할 수 있습니다.
            </p>
          </article>
        </section>
        """,
        unsafe_allow_html=True,
    )


def render_status_chips() -> None:
    state = operating_state()
    dot_class = (
        "noc-dot-ok"
        if state == "정상"
        else "noc-dot-warn"
        if state != "대기"
        else "noc-dot-idle"
    )
    values = (
        ("SYSTEM", state),
        ("MM", "2 / 2"),
        ("MD", f"{len(CONFIG.managed_devices)} / {len(CONFIG.managed_devices)}"),
        ("POLL", f"{CONFIG.session_interval_seconds}s"),
        ("LAST CHECK", latest_seen()),
        ("MODE", "READ ONLY"),
    )
    items = []
    for index, (label, value) in enumerate(values):
        if index == 0:
            value_html = (
                '<span class="noc-status-main">'
                f'<span class="noc-dot {dot_class}"></span>'
                f"<span>{escape(str(value))}</span>"
                "</span>"
            )
        else:
            value_html = escape(str(value))
        items.append(
            '<div class="noc-status-item">'
            f'<span class="noc-status-label">{escape(label)}</span>'
            f'<span class="noc-status-value">{value_html}</span>'
            "</div>"
        )
    st.markdown(
        '<section class="noc-status-strip" aria-label="NOC 상태">'
        + "".join(items)
        + "</section>",
        unsafe_allow_html=True,
    )


def demo_reset() -> None:
    st.session_state.pop("scenario_runner", None)
    st.session_state.runtime = DemoRuntime()
    st.rerun()


def render_sidebar() -> None:
    st.subheader("Public Demo")
    st.caption("Desktop App의 UI/작업 흐름을 Web으로 옮긴 버전입니다.")
    if st.button("샘플 현재 조회", type="primary", use_container_width=True):
        st.session_state.pop("scenario_runner", None)
        demo = DemoRuntime()
        demo.execution.on_change = lambda: render_trace(demo.execution, trace_slot)
        demo.start(
            QueryRequest("198.51.100.10", ""),
            monitor=False,
            mode="normal",
        )
        st.session_state.runtime = demo
        st.rerun()
    if st.button("Demo Reset", use_container_width=True):
        demo_reset()
    st.divider()
    with st.expander("Demo Fault / Timeline", expanded=False):
        st.session_state.session_demo_mode = st.selectbox(
            "다음 수집 조건",
            ["timeline", "normal", "timeout", "parse"],
            format_func=lambda value: {
                "timeline": "운영 타임라인",
                "normal": "정상 수집",
                "timeout": "CLI 수집 실패",
                "parse": "Parsing 실패",
            }[value],
        )
        st.caption(
            "실제 Desktop App의 운영 기능이 아니라 공개 데모에서 "
            "상태 전이를 재현하기 위한 입력입니다."
        )


def build_query_request(
    source: str,
    destination: str,
    source_port: str,
    destination_port: str,
    bidirectional: bool,
) -> QueryRequest:
    return QueryRequest(
        source,
        destination,
        int(source_port) if source_port.strip() else None,
        int(destination_port) if destination_port.strip() else None,
        bidirectional,
    )


def run_query(request: QueryRequest, *, monitor: bool) -> None:
    st.session_state.pop("scenario_runner", None)
    r.start(
        request,
        monitor=monitor,
        mode=st.session_state.session_demo_mode,
    )


def render_query_page() -> None:
    st.subheader("세션 조회")

    with st.container(border=True):
        st.markdown("**조회할 세션 흐름 · IP 하나 이상 입력**")
        endpoints = st.columns([1, 0.25, 1])
        source = endpoints[0].text_input(
            "출발지 IP",
            value="198.51.100.10",
            disabled=r.running,
            placeholder="예: 198.51.100.10",
        )
        endpoints[1].markdown(
            '<div style="text-align:center;padding-top:2rem;font-size:1.2rem">⇄</div>',
            unsafe_allow_html=True,
        )
        destination = endpoints[2].text_input(
            "목적지 IP",
            value="",
            disabled=r.running,
            placeholder="선택 입력",
        )
        bidirectional = st.checkbox(
            "양방향 조회",
            value=True,
            disabled=r.running,
        )

        with st.expander("고급 조건 보기", expanded=False):
            advanced = st.columns(2)
            source_port = advanced[0].text_input(
                "출발지 포트 (선택)",
                disabled=r.running,
            )
            destination_port = advanced[1].text_input(
                "목적지 포트 (선택)",
                disabled=r.running,
            )

        controls = st.columns([1.35, 1, 1, 3])
        start = controls[0].button(
            "지속 모니터링 시작",
            disabled=r.running,
            use_container_width=True,
        )
        once = controls[1].button(
            "현재 조회",
            disabled=r.running,
            type="primary",
            use_container_width=True,
        )
        stop = controls[2].button(
            "중지",
            disabled=not r.running,
            use_container_width=True,
        )
        controls[3].caption(
            "필터 조건이 장비에서 거부되어도 전체 datapath table 조회로 자동 전환하지 않습니다."
        )

        if stop:
            r.stop()
            st.rerun()

        if once or start:
            try:
                request = build_query_request(
                    source,
                    destination,
                    source_port,
                    destination_port,
                    bidirectional,
                )
                with st.status(
                    "입력 검증 → MM 위치 확인 → 관련 MD 선택 → datapath Parser",
                    expanded=False,
                ):
                    run_query(request, monitor=start)
                st.rerun()
            except (TypeError, ValueError) as exc:
                st.error(str(exc))

        if r.running:
            playback = st.columns([1, 4])
            if playback[0].button("다음 Poll", use_container_width=True):
                try:
                    st.session_state.pop("scenario_runner", None)
                    r.poll(st.session_state.session_demo_mode)
                    st.rerun()
                except ValueError as exc:
                    st.warning(str(exc))
            playback[1].caption(
                "Desktop App에서는 설정한 주기로 자동 수집합니다. "
                "Public Demo는 외부 연결 없이 다음 Poll을 수동 재생합니다."
            )

    with st.container(border=True):
        st.markdown("**로그인 정보 · 이번 실행에만 사용**")
        c = st.columns(3)
        c[0].text_input(
            "SSH 사용자 이름",
            value="Public Demo에서는 입력하지 않습니다",
            disabled=True,
        )
        c[1].text_input(
            "SSH 암호",
            value="synthetic-only",
            type="password",
            disabled=True,
        )
        c[2].text_input(
            "Enable 암호 (선택)",
            value="",
            type="password",
            disabled=True,
        )
        st.caption(
            "실제 Desktop App에서는 실행 세션 메모리에서만 사용합니다. "
            "Public Web Edition은 외부 SSH를 완전히 비활성화합니다."
        )

    state_row = st.columns([1, 2, 2])
    state_row[0].metric("실행 상태", operating_state())
    state_row[1].caption(
        "MM/MD: "
        + (
            f"{r.outcome.used_mm or '확인 불가'} → {', '.join(r.outcome.controllers) or '없음'}"
            if r.outcome
            else "아직 조회하지 않음"
        )
    )
    state_row[2].caption(f"시작 시각: {r.started or '-'} · Poll {r.poll_count}")


def result_rows() -> list[dict[str, object]]:
    return r.rows() if r.outcome else []


def render_run_evidence() -> None:
    if r.events:
        with st.expander("Lifecycle Events", expanded=False):
            st.dataframe(r.events[-30:], hide_index=True, width="stretch")
    if r.outcome:
        with st.expander("수집 진단 · 전체 Raw", expanded=False):
            st.json([asdict(item) for item in r.outcome.diagnostics])
            st.caption(f"현재 단계: {r.stage}")
            st.dataframe(r.trace, hide_index=True, width="stretch")
            for snapshot in r.outcome.raw_snapshots:
                st.caption(f"{snapshot.device_name} · {snapshot.command}")
                st.code(snapshot.output, language="text")


def render_result_console() -> None:
    st.markdown("### 세션 조회 결과")
    st.caption(
        "수집 실패는 세션 종료로 해석하지 않습니다. 현재 조회가 불완전하면 기존 상태를 유지합니다."
    )

    rows = result_rows()
    authoritative = r.outcome is not None and r.outcome.authoritative
    observations = r.outcome.observations if authoritative else []
    changed = len(r.result.events) if r.result and authoritative else 0
    metrics = st.columns(4)
    metrics[0].metric("현재 관측 흐름", len(observations) if authoritative else "확인 불가")
    displayed_count = metrics[1].empty()
    metrics[2].metric("이번 Poll 이벤트", changed if authoritative else "확인 불가")
    metrics[3].metric(
        "관측 MD",
        len({item.controller_name for item in observations}) if authoritative else "확인 불가",
    )
    st.caption(f"추적 중인 세션: {len(rows)} · 수집 실패 시 이전 관측을 유지합니다.")
    with st.expander("Diagnostics / 전체 Raw", expanded=False):
        render_run_evidence()

    if r.outcome and not r.outcome.authoritative:
        st.warning(
            "현재 수집은 완전하지 않습니다. 세션 없음/종료로 "
            "단정하지 않고 "
            "확인 필요 상태로 유지합니다."
        )

    if not rows:
        displayed_count.metric("결과표 표시 행", 0)
        st.info(
            "현재 표시할 추적 행이 없습니다. 대표 시나리오 또는 고급 "
            "직접 조회를 실행할 수 있습니다."
        )
        return

    filters = st.columns(4)
    search = filters[0].text_input("결과 검색", placeholder="IP / Port", key="result_search")
    protocol = filters[1].selectbox("Protocol", ["All", "TCP", "UDP"], key="result_protocol")
    controller = filters[2].selectbox(
        "Controller",
        ["All", *(device.name for device in CONFIG.managed_devices)],
        key="result_controller",
    )
    lifecycle = filters[3].selectbox(
        "Lifecycle",
        ["All", "OBSERVED", "MISSED"],
        key="result_lifecycle",
    )

    filtered = [
        row
        for row in rows
        if (protocol == "All" or row.get("protocol") == {"TCP": 6, "UDP": 17}.get(protocol))
        and (controller == "All" or row.get("controller_name") == controller)
        and (lifecycle == "All" or row.get("State") == lifecycle)
        and search.casefold()
        in " ".join(
            str(row.get(key, ""))
            for key in (
                "source_ip",
                "source_port",
                "destination_ip",
                "destination_port",
            )
        ).casefold()
    ]

    displayed_count.metric("결과표 표시 행", len(filtered))

    display_columns = (
        "controller_name",
        "protocol",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "packets",
        "bytes_count",
        "age",
        "cpu_id",
        "Last Seen",
        "flags",
        "State",
    )
    table_rows = [{key: row.get(key, "") for key in display_columns} for row in filtered]
    st.dataframe(table_rows, hide_index=True, width="stretch")

    if not filtered:
        st.caption("필터 조건에 맞는 행이 없습니다.")
        return

    selected = st.selectbox(
        "선택한 세션",
        range(len(filtered)),
        format_func=lambda index: (
            f"{filtered[index].get('source_ip')}:"
            f"{filtered[index].get('source_port')} → "
            f"{filtered[index].get('destination_ip')}:"
            f"{filtered[index].get('destination_port')} · "
            f"{filtered[index].get('controller_name')}"
        ),
    )
    row = filtered[selected]

    with st.expander("고급 결과 상세 / Raw / Diagnostics", expanded=False):
        summary, raw, diagnostics = st.tabs(["세션 요약", "선택 행 Raw", "진단 이벤트"])

        with summary:
            st.markdown("#### 선택한 세션")
            flow = st.columns([2, 1, 2])
            flow[0].markdown(
                '<div class="flow-card">'
                '<div class="flow-label">출발지</div>'
                f'<div class="flow-value">{row.get("source_ip")}:'
                f"{row.get('source_port')}</div>"
                "</div>",
                unsafe_allow_html=True,
            )
            flow[1].markdown(
                '<div class="flow-card">'
                '<div class="flow-label">Protocol / MD</div>'
                f'<div class="flow-value">{row.get("protocol")}<br>'
                f"{row.get('controller_name')}</div>"
                "</div>",
                unsafe_allow_html=True,
            )
            flow[2].markdown(
                '<div class="flow-card">'
                '<div class="flow-label">목적지</div>'
                f'<div class="flow-value">{row.get("destination_ip")}:'
                f"{row.get('destination_port')}</div>"
                "</div>",
                unsafe_allow_html=True,
            )

            facts = st.columns(6)
            facts[0].metric("상태", row.get("State", "—"))
            facts[1].metric("Flags", row.get("flags", "—"))
            facts[2].metric("Packets", row.get("packets", "—"))
            facts[3].metric("Bytes", row.get("bytes_count", "—"))
            facts[4].metric("Age", row.get("age", "—"))
            facts[5].metric("CPU", row.get("cpu_id", "—"))

            with st.expander("Flags 해석", expanded=False):
                st.json([asdict(flag) for flag in interpret_flags(str(row.get("flags", "")))])

        with raw:
            raw_line = row.get("raw_line")
            if raw_line:
                st.code(str(raw_line), language="text")
            elif r.outcome:
                for snapshot in r.outcome.raw_snapshots:
                    with st.expander(
                        f"{snapshot.device_name} · {snapshot.command}",
                        expanded=False,
                    ):
                        st.code(snapshot.output, language="text")
            else:
                st.caption("원본 출력이 없습니다.")

        with diagnostics:
            if r.outcome:
                st.json([asdict(item) for item in r.outcome.diagnostics])
                st.caption(f"현재 단계: {r.stage}")
                st.dataframe(r.trace, hide_index=True, width="stretch")
            else:
                st.caption("진단 이벤트가 없습니다.")


def render_settings_page() -> None:
    st.subheader("장비 설정")

    with st.container(border=True):
        st.markdown("**Mobility Conductor (MM)**")
        rows = [
            {
                "구분": "Primary",
                "표시 이름": CONFIG.mm_primary.name,
                "IPv4": CONFIG.mm_primary.host,
                "SSH 포트": CONFIG.mm_primary.port,
                "사용": True,
            },
            {
                "구분": "Standby",
                "표시 이름": CONFIG.mm_standby.name,
                "IPv4": CONFIG.mm_standby.host,
                "SSH 포트": CONFIG.mm_standby.port,
                "사용": True,
            },
        ]
        st.dataframe(rows, hide_index=True, width="stretch")

    with st.container(border=True):
        st.markdown("**Managed Device (MD, 7240XM)**")
        st.dataframe(
            [
                {
                    "사용": True,
                    "표시 이름": device.name,
                    "IPv4": device.host,
                    "SSH 포트": device.port,
                }
                for device in CONFIG.managed_devices
            ],
            hide_index=True,
            width="stretch",
        )

    with st.container(border=True):
        st.markdown("**모니터링 판정 기준**")
        cols = st.columns(3)
        cols[0].metric("세션 조회 주기", f"{CONFIG.session_interval_seconds}s")
        cols[1].metric(
            "위치 갱신 주기",
            f"{CONFIG.location_interval_seconds}s",
        )
        cols[2].metric(
            "종료 확정 MISS",
            CONFIG.close_after_misses,
        )

    st.button("장비 설정 저장", disabled=True)
    st.caption(
        "Public Web Edition에서는 Demo 장비 설정을 "
        "변경하거나 자격 증명을 저장하지 않습니다. "
        "실제 Desktop App에서는 설정과 로컬 저장 경계를 사용합니다."
    )


def render_history_page() -> None:
    st.subheader("기록 및 내보내기")

    st.caption(
        "CSV와 HTML은 현재 실행 전체를 내보냅니다. 아래 기록 선택은 실행 요약 삭제에만 사용합니다."
    )
    actions = st.columns(5)
    actions[0].button("새로고침", disabled=True, use_container_width=True)

    if r.outcome:
        actions[1].download_button(
            "CSV 내보내기",
            r.csv(),
            "session-history.csv",
            "text/csv",
            use_container_width=True,
        )
        actions[2].download_button(
            "HTML 보고서",
            r.html(),
            "session-report.html",
            "text/html",
            use_container_width=True,
        )
    else:
        actions[1].button("CSV 내보내기", disabled=True, use_container_width=True)
        actions[2].button("HTML 보고서", disabled=True, use_container_width=True)

    selected_index = None
    if r.history:
        selected_index = st.selectbox(
            "기록 선택",
            range(len(r.history)),
            format_func=lambda index: (
                f"{r.history[index].get('Started', '')} · {r.history[index].get('Status', '')}"
            ),
        )

    if (
        actions[3].button(
            "선택 삭제",
            disabled=selected_index is None,
            use_container_width=True,
        )
        and selected_index is not None
    ):
        del r.history[selected_index]
        st.rerun()

    if actions[4].button(
        "전체 기록 삭제",
        disabled=not r.history,
        use_container_width=True,
    ):
        r.history.clear()
        st.rerun()

    st.caption("내보내기 · 현재 Public Demo 세션 안의 비식별 관측만 포함합니다.")
    if r.history:
        st.dataframe(r.history, hide_index=True, width="stretch")
    else:
        st.info("저장된 Demo 실행 기록이 없습니다.")


def start_scenario(key):
    global r
    begin()
    runner = ScenarioRunner()
    st.session_state.scenario_runner = runner
    for widget_key in ("result_search", "result_protocol", "result_controller", "result_lifecycle"):
        st.session_state.pop(widget_key, None)

    def update(current):
        render_timeline(current, timeline_slot)
        render_trace(current.runtime.execution, trace_slot)

    try:
        runner.play(key, update)
    except Exception as exc:
        st.error(f"시나리오 실행을 완료하지 못했습니다: {exc}")
    r = runner.runtime
    st.session_state.runtime = r
    st.session_state.trace_poll = max(0, len(runner.run.snapshots) - 1) if runner.run else 0


render_header()
render_status_chips()
render_reviewer_summary()
scenario_controls = st.container()
timeline_slot = GuidedSlot(
    st.empty(), lambda: getattr(st.session_state.get("scenario_runner"), "run", None)
)
communication_area = st.container()
with st.expander("실제 처리 기록 / Execution Trace", expanded=False):
    trace_selector = st.container()
    trace_slot = st.empty()
with scenario_controls:
    st.markdown(
        '<div class="runbook-heading">'
        '<div class="kicker">INVESTIGATION RUNBOOK</div>'
        '<div class="title">대표 조사 시나리오를 실행해 실제 분석 흐름을 확인하세요.</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    chosen = None
    if st.button("대표 통신 추적 실행", type="primary", use_container_width=True):
        chosen = "normal"
    cols = st.columns(3)
    for column, (key, label) in zip(cols, SCENARIOS.items(), strict=True):
        if column.button(label, use_container_width=True):
            chosen = key
    if chosen:
        start_scenario(chosen)

runner = st.session_state.get("scenario_runner")
with communication_area:
    render_communication(r, st)
render_timeline(runner, timeline_slot)
r.execution.on_change = lambda: render_trace(r.execution, trace_slot)
if runner and runner.run and runner.run.snapshots:
    with trace_selector:
        trace_index = st.selectbox(
            "Poll별 Execution Trace",
            range(len(runner.run.snapshots)),
            format_func=lambda i: (
                f"Poll #{runner.run.snapshots[i].poll} · {runner.run.snapshots[i].title}"
            ),
            key="trace_poll",
        )
        st.caption(
            "Trace는 선택한 Poll의 기록입니다. 통신 흐름과 아래 결과표는 마지막 Poll을 표시합니다."
        )
    render_trace(runner.run.snapshots[trace_index].trace, trace_slot)
    if runner.run.error:
        st.error(runner.run.error)
else:
    render_trace(r.execution, trace_slot)

query_page, settings_page, history_page = st.tabs(["세션 조회", "장비 설정", "기록 및 내보내기"])
with query_page:
    render_result_console()
    with st.expander("고급 직접 조회", expanded=False):
        render_query_page()
        render_sidebar()
with settings_page:
    render_settings_page()
with history_page:
    render_history_page()

st.caption(
    "Public Web Edition · QueryRequest / TrackerService / production Parser / "
    "MonitorEngine 재사용 · 실제 SSH/known_hosts/자격 증명 입력 없음"
)
st.link_button("GitHub Source", "https://github.com/sebia1993/aruba-session-tracker-1")
r.execution.on_change = None
