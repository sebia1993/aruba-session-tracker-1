from __future__ import annotations

import sys
from dataclasses import asdict
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aruba_session_tracker.parsers.flags import interpret_flags
from portfolio_demo.execution_trace import render_trace
from portfolio_demo.fixture_transport import CONFIG
from portfolio_demo.runtime import DemoRuntime, QueryRequest

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
    left, right = st.columns([4.4, 1.6])
    with left:
        st.markdown(
            '<div class="product-shell">'
            '<div class="product-name">ARUBA SESSION TRACKER</div>'
            '<div class="product-meta">네트워크 세션 분석 콘솔 · Public Web Edition · '
            "로컬/읽기 전용 설계</div>"
            "</div>",
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            '<div style="padding-top:.6rem;text-align:right">'
            '<span class="demo-pill">PUBLIC DEMO</span>'
            '<span class="demo-pill">SYNTHETIC TRANSPORT</span>'
            "</div>",
            unsafe_allow_html=True,
        )

    chips = st.columns(6)
    values = (
        ("MM", "설정 2/2"),
        (
            "MD",
            f"설정 {len(CONFIG.managed_devices)}/{len(CONFIG.managed_devices)}",
        ),
        ("조회 주기", f"{CONFIG.session_interval_seconds}s"),
        ("최근 확인", latest_seen()),
        ("실행 모드", "Web Demo · 읽기 전용"),
        ("실행 상태", operating_state()),
    )
    for col, (label, value) in zip(chips, values, strict=True):
        col.markdown(
            '<div class="header-chip">'
            f'<div class="header-chip-label">{label}</div>'
            f'<div class="header-chip-value">{value}</div>'
            "</div>",
            unsafe_allow_html=True,
        )

    st.info(
        "단말 IP를 기준으로 MM에서 위치를 찾고 관련 MD에서 필터형 datapath session을 조회합니다. "
        "Public Demo에서는 실제 장비 접속 대신 비식별 합성 Transport만 사용합니다."
    )


def render_reviewer_summary() -> None:
    st.markdown("### 이 프로젝트는 무엇을 해결하나요?")
    left, right = st.columns(2)
    with left, st.container(border=True):
        st.markdown("**프로젝트 목적**")
        st.write(
            "특정 단말의 IP 주소 하나를 출발점으로, 그 단말이 어느 무선 장비에 연결되어 있고 "
            "현재 어떤 서버나 서비스와 통신하고 있는지를 자동으로 따라가는 도구입니다."
        )
        st.caption(
            "쉽게 말해: '이 기기가 지금 어디를 통해 어디와 통신하고 있는지'를 자동으로 추적합니다."
        )
    with right, st.container(border=True):
        st.markdown("**이 데모에서 보여주는 것**")
        st.write(
            "단말 IP 확인 → 단말 위치 찾기 → 담당 Controller 선택 → 실제 통신 세션 조회 → "
            "통신 흐름과 변화 확인까지를 한 번의 실행으로 보여줍니다."
        )
        st.caption(
            "해커톤 관점: 여러 단계로 나뉜 장애 조사 절차를 하나의 자동 추적 흐름으로 연결합니다."
        )


def demo_reset() -> None:
    st.session_state.runtime = DemoRuntime()
    st.rerun()


def render_sidebar() -> None:
    with st.sidebar:
        st.subheader("Public Demo")
        st.caption("Desktop App의 UI/작업 흐름을 Web으로 옮긴 버전입니다.")
        if st.button("샘플 현재 조회", type="primary", use_container_width=True):
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
        with st.expander("수집 진단 · 전체 Raw", expanded=not r.outcome.authoritative):
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
    render_run_evidence()

    if r.outcome and not r.outcome.authoritative:
        st.warning(
            "현재 수집은 완전하지 않습니다. 세션 없음/종료로 단정하지 않고 "
            "확인 필요 상태로 유지합니다."
        )

    if not rows:
        displayed_count.metric("결과표 표시 행", 0)
        st.info(
            "조회 결과가 없습니다. 위 조건으로 조회하거나 Sidebar의 샘플 현재 조회를 사용하세요."
        )
        return

    filters = st.columns(4)
    search = filters[0].text_input("결과 검색", placeholder="IP / Port")
    protocol = filters[1].selectbox("Protocol", ["All", "TCP", "UDP"])
    controller = filters[2].selectbox(
        "Controller",
        ["All", *(device.name for device in CONFIG.managed_devices)],
    )
    lifecycle = filters[3].selectbox(
        "Lifecycle",
        ["All", "OBSERVED", "MISSED"],
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
        "Public Web Edition에서는 Demo 장비 설정을 변경하거나 자격 증명을 저장하지 않습니다. "
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


render_header()
render_reviewer_summary()

query_page, settings_page, history_page = st.tabs(["세션 조회", "장비 설정", "기록 및 내보내기"])
with query_page:
    query_area = st.container()
    trace_slot = st.empty()
    r.execution.on_change = lambda: render_trace(r.execution, trace_slot)
    render_trace(r.execution, trace_slot)
    with query_area:
        render_query_page()
    render_result_console()
with settings_page:
    render_settings_page()
with history_page:
    render_history_page()
render_sidebar()

st.caption(
    "Public Web Edition · QueryRequest / TrackerService / production Parser / "
    "MonitorEngine 재사용 · 실제 SSH/known_hosts/자격 증명 입력 없음"
)
st.link_button(
    "GitHub Source",
    "https://github.com/sebia1993/aruba-session-tracker-1",
)

# Bind UI notifications only for the active Streamlit script run.
r.execution.on_change = None
