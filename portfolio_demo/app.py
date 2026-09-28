import sys
from dataclasses import asdict
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aruba_session_tracker.parsers.flags import interpret_flags
from portfolio_demo.fixture_transport import CONFIG, inventory
from portfolio_demo.runtime import DemoRuntime, QueryRequest

st.set_page_config(
    page_title="Session NOC Console · Public Demo",
    page_icon="📡",
    layout="wide",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.5rem; padding-bottom: 3rem; max-width: 1500px;}
    .product-kicker {
        font-size:.78rem; letter-spacing:.08em; font-weight:800;
        color:#7da7ff; margin-bottom:.25rem;
    }
    .product-title {font-size:2.15rem; line-height:1.1; font-weight:800; margin:0;}
    .product-sub {color:#8a98aa; margin-top:.45rem; margin-bottom:1rem;}
    .demo-badge {
        display:inline-block; border:1px solid #31445f; border-radius:999px;
        padding:.22rem .62rem; font-size:.72rem; font-weight:750;
        color:#afc8ee; background:#101927; margin-right:.35rem;
    }
    .path-card {border:1px solid rgba(120,145,175,.25); border-radius:12px; padding:.75rem .9rem;
                background:rgba(18,27,41,.55); min-height:78px;}
    .path-title {font-size:.74rem; color:#8da2bb; font-weight:700; margin-bottom:.2rem;}
    .path-value {font-size:.98rem; font-weight:760;}
    </style>
    """,
    unsafe_allow_html=True,
)

if "runtime" not in st.session_state:
    st.session_state.runtime = DemoRuntime()
r = st.session_state.runtime


def render_header() -> None:
    st.markdown(
        '<div class="product-kicker">ARUBA SESSION OPERATIONS</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="product-title">Session Tracker</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="product-sub">단말 위치를 MM에서 확인하고 관련 MD의 datapath session을 '
        "추적·기록합니다.</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        '<span class="demo-badge">PUBLIC DEMO</span>'
        '<span class="demo-badge">SYNTHETIC TRANSPORT</span>'
        '<span class="demo-badge">READ ONLY</span>',
        unsafe_allow_html=True,
    )


def render_sidebar() -> None:
    with st.sidebar:
        st.subheader("Demo Network")
        st.caption("계정 입력과 실제 SSH 연결은 비활성화되어 있습니다.")
        st.write(f"**MM**  {CONFIG.mm_primary.name} / {CONFIG.mm_standby.name}")
        st.write(f"**MD**  {len(CONFIG.managed_devices)} Controllers")
        st.write(f"**Session Poll**  {CONFIG.session_interval_seconds}s")
        st.write(f"**Location Refresh**  {CONFIG.location_interval_seconds}s")
        st.divider()
        if st.button("Demo Reset", use_container_width=True):
            st.session_state.runtime = DemoRuntime()
            st.rerun()


def render_query_bar() -> tuple[bool, bool, str]:
    st.subheader("세션 조회")
    c = st.columns(2)
    source = c[0].text_input(
        "출발지 IP",
        "198.51.100.10",
        disabled=r.running,
        placeholder="예: 198.51.100.10",
    )
    destination = c[1].text_input(
        "목적지 IP",
        "",
        disabled=r.running,
        placeholder="선택 입력",
    )

    c = st.columns([1, 1, 1, 1.4])
    sport = c[0].text_input("Source Port (선택)", disabled=r.running)
    dport = c[1].text_input("Destination Port (선택)", disabled=r.running)
    bidirectional = c[2].checkbox("양방향 조회", True, disabled=r.running)
    c[3].caption("IP 하나만 입력해도 현재 위치와 관련 MD를 찾아 제한된 필터형 CLI만 조회합니다.")

    mode = "timeline"
    with st.expander("Demo controls · 장애/수집 실패 재현", expanded=False):
        st.caption(
            "운영 화면의 기본 흐름과 분리된 검증용 제어입니다. "
            "기본 사용자는 정상 조회/모니터링만 사용하면 됩니다."
        )
        mode = st.selectbox(
            "다음 수집 조건",
            ["timeline", "normal", "timeout", "parse"],
            format_func=lambda v: {
                "timeline": "운영 타임라인",
                "normal": "정상 수집",
                "timeout": "CLI 수집 실패",
                "parse": "Parsing 실패",
            }[v],
        )

    c = st.columns([1.1, 1.25, 1, 1, 3])
    once = c[0].button("현재 조회", disabled=r.running, type="primary", use_container_width=True)
    start = c[1].button("지속 모니터링 시작", disabled=r.running, use_container_width=True)
    next_poll = c[2].button("다음 Poll", disabled=not r.running, use_container_width=True)
    stop = c[3].button("중지", disabled=not r.running, use_container_width=True)
    c[4].caption(
        "지속 모니터링은 백그라운드 연결을 만들지 않습니다. "
        "`다음 Poll`로 가상 시간을 진행해 lifecycle 변화를 재현합니다."
    )
    if stop:
        r.stop()
        st.rerun()

    if once or start or next_poll:
        try:
            with st.status(
                "QueryRequest 검증 → MM 위치 확인 → MD 필터형 명령 → Parser",
                expanded=False,
            ):
                if next_poll:
                    r.poll(mode)
                else:
                    request = QueryRequest(
                        source,
                        destination,
                        int(sport) if sport.strip() else None,
                        int(dport) if dport.strip() else None,
                        bidirectional,
                    )
                    r.start(request, monitor=start, mode=mode)
            st.rerun()
        except (ValueError, TypeError) as exc:
            st.error(str(exc))

    return once, start, mode


def operator_status() -> str:
    if not r.outcome:
        return "대기"
    if r.outcome.authoritative:
        return "정상"
    if r.result and r.result.retry_after_seconds:
        return "재시도 중"
    return "확인 필요"


def render_metrics() -> None:
    c = st.columns(5)
    c[0].metric("운영 상태", operator_status())
    if not r.outcome:
        c[1].metric("Active Sessions", "-")
        c[2].metric("관측 MD", "-")
        c[3].metric("Last Poll", "0")
        c[4].metric("Lifecycle Events", "0")
        return

    c[1].metric(
        "Active Sessions",
        len(r.result.active_sessions)
        if r.result
        else (len(r.outcome.observations) if r.outcome.authoritative else "확인 불가"),
    )
    c[2].metric("관측 MD", len(r.outcome.controllers))
    c[3].metric("Last Poll", r.poll_count)
    c[4].metric("Lifecycle Events", len(r.events))


def render_query_path() -> None:
    if not r.outcome:
        return
    o = r.outcome
    src = asdict(o.source_location) if o.source_location else {}
    dst = asdict(o.destination_location) if o.destination_location else {}
    src_value = (
        src.get("controller_name") or src.get("controller") or src.get("switch") or "확인 불가"
    )
    dst_value = (
        dst.get("controller_name") or dst.get("controller") or dst.get("switch") or "선택 없음"
    )
    md_value = ", ".join(o.controllers) or "없음"

    a, b, c = st.columns(3)
    a.markdown(
        f'<div class="path-card"><div class="path-title">SOURCE LOCATION</div>'
        f'<div class="path-value">{src_value}</div></div>',
        unsafe_allow_html=True,
    )
    b.markdown(
        f'<div class="path-card"><div class="path-title">DESTINATION LOCATION</div>'
        f'<div class="path-value">{dst_value}</div></div>',
        unsafe_allow_html=True,
    )
    c.markdown(
        f'<div class="path-card"><div class="path-title">QUERIED MD</div>'
        f'<div class="path-value">{md_value}</div></div>',
        unsafe_allow_html=True,
    )


def filtered_rows():
    c = st.columns(4)
    text = c[0].text_input("IP / Port 검색")
    protocol = c[1].selectbox("Protocol", ["All", "TCP", "UDP"])
    controller = c[2].selectbox(
        "Controller",
        ["All", *(d.name for d in CONFIG.managed_devices)],
    )
    state = c[3].selectbox("Lifecycle", ["All", "OBSERVED", "MISSED"])
    return [
        row
        for row in r.rows()
        if (protocol == "All" or row["protocol"] == {"TCP": 6, "UDP": 17}.get(protocol))
        and (controller == "All" or row["controller_name"] == controller)
        and (state == "All" or row["State"] == state)
        and text
        in " ".join(
            str(row[k]) for k in ("source_ip", "destination_ip", "source_port", "destination_port")
        )
    ]


def render_sessions() -> None:
    st.subheader("현재 세션")
    if not r.outcome:
        st.info("출발지 또는 목적지 IP를 입력하고 `현재 조회`를 실행하세요.")
        st.caption("Demo 예시: 198.51.100.10")
        st.dataframe(inventory(), hide_index=True, width="stretch")
        return

    o = r.outcome
    if not o.authoritative:
        st.warning(
            "수집 불완전 / Unknown · 세션 없음이나 종료로 판단하지 않습니다. "
            "기존 추적 상태를 유지합니다."
        )
    elif not o.observations:
        st.info("현재 관측 0개 · 기존 세션은 MISS 횟수와 CLOSED 이벤트를 별도로 확인하세요.")

    render_query_path()
    rows = filtered_rows()
    st.dataframe(
        [{k: v for k, v in row.items() if k != "raw_line"} for row in rows],
        hide_index=True,
        width="stretch",
    )

    if rows:
        selected = st.selectbox(
            "선택 세션 상세",
            range(len(rows)),
            format_func=lambda i: (
                f"{rows[i]['source_ip']}:{rows[i]['source_port']} → "
                f"{rows[i]['destination_ip']}:{rows[i]['destination_port']} · "
                f"{rows[i]['controller_name']}"
            ),
        )
        row = rows[selected]
        st.subheader("선택한 세션")
        a, b, c = st.columns(3)
        a.markdown(
            f'<div class="path-card"><div class="path-title">SOURCE</div>'
            f'<div class="path-value">{row["source_ip"]}:{row["source_port"]}</div></div>',
            unsafe_allow_html=True,
        )
        b.markdown(
            f'<div class="path-card"><div class="path-title">CONTROLLER / PROTOCOL</div>'
            f'<div class="path-value">{row["controller_name"]} · {row["protocol"]}</div></div>',
            unsafe_allow_html=True,
        )
        c.markdown(
            f'<div class="path-card"><div class="path-title">DESTINATION</div>'
            f'<div class="path-value">{row["destination_ip"]}:'
            f"{row['destination_port']}</div></div>",
            unsafe_allow_html=True,
        )
        with st.expander("세션 상세 / Flags", expanded=False):
            st.json(row)
            st.json([asdict(flag) for flag in interpret_flags(row["flags"])])

    if r.events:
        st.subheader("Lifecycle Events")
        st.dataframe(r.events, hide_index=True, width="stretch")


def render_diagnostics() -> None:
    st.subheader("Diagnostics / Evidence")
    if not r.outcome:
        st.info("조회 후 실제 production parser로 처리한 경로와 Raw CLI가 표시됩니다.")
        return
    st.caption(f"Stage: {r.stage}")
    st.dataframe(r.trace, hide_index=True, width="stretch")
    st.dataframe(r.factory.trace, hide_index=True, width="stretch")
    with st.expander("진단 이벤트", expanded=False):
        st.json([asdict(d) for d in r.outcome.diagnostics])
    with st.expander("Raw CLI", expanded=False):
        for n, raw in enumerate(r.outcome.raw_snapshots):
            st.markdown(f"**{n + 1}. {raw.device_name} · {raw.command}**")
            st.code(raw.output, language="text")


def render_history() -> None:
    st.subheader("이력 / Export")
    if not r.history:
        st.info("조회 이력이 아직 없습니다.")
        return
    st.dataframe(r.history, hide_index=True, width="stretch")
    st.caption("최근 20회 Run 요약. Export는 마지막 Run의 전체 관측이며 표 필터와 독립적입니다.")
    if r.outcome:
        st.download_button("CSV Export", r.csv(), "session-v2.csv", "text/csv")
        st.download_button("HTML Report", r.html(), "session-v2.html", "text/html")


render_header()
render_sidebar()
render_query_bar()
render_metrics()

sessions, diagnostics, history = st.tabs(["세션 Console", "Advanced Diagnostics", "이력 / Export"])
with sessions:
    render_sessions()
with diagnostics:
    render_diagnostics()
with history:
    render_history()

with st.expander("Architecture", expanded=False):
    st.write(
        "QueryRequest → TrackerService → SSHCollector allowlist → "
        "FixtureFactory → production Parser → QueryOutcome → MonitorEngine"
    )
    st.caption(
        "Public Demo는 등록된 문서용 Demo 장비의 필터형 명령만 처리하며 "
        "SQLite, known_hosts, 자격 증명 입력이나 실제 네트워크 연결을 사용하지 않습니다."
    )
st.link_button(
    "GitHub Source",
    "https://github.com/sebia1993/aruba-session-tracker-1",
)
