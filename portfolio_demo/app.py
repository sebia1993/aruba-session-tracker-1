from dataclasses import asdict
from pathlib import Path
import sys
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from portfolio_demo.runtime import DemoRuntime, QueryRequest
from portfolio_demo.fixture_transport import CONFIG, inventory
from aruba_session_tracker.parsers.flags import interpret_flags

st.set_page_config(page_title="Session NOC Console · Public Demo v2", page_icon="📡", layout="wide")
if "runtime" not in st.session_state:
    st.session_state.runtime = DemoRuntime()
r = st.session_state.runtime
st.title("Session 추적 Console")
st.caption("조회 조건 → MM 위치 확인 → 관련 MD → 현재 조회 / 지속 모니터링 → 이력과 Export")
with st.sidebar:
    st.success("실제 SSH 비활성 · 합성 Transport")
    st.caption(
        "계정 입력 없이 문서용 가상 네트워크를 조회합니다. 임의의 유효 IPv4 조건도 검증하며 가상망에 없으면 진단 결과를 표시합니다."
    )
    if st.button("Demo Reset"):
        st.session_state.runtime = DemoRuntime()
        st.rerun()
settings, query, evidence, history = st.tabs(
    ["장비 설정", "세션 조회", "Raw / Diagnostics", "이력 / Export"]
)
with settings:
    st.subheader("Demo Network")
    st.dataframe(
        [d.to_dict() for d in (CONFIG.mm_primary, CONFIG.mm_standby, *CONFIG.managed_devices)],
        hide_index=True,
    )
    st.write(
        f"세션 주기 {CONFIG.session_interval_seconds}초 · 위치 확인 {CONFIG.location_interval_seconds}초 · Close after {CONFIG.close_after_misses} misses"
    )
    st.dataframe(inventory(), hide_index=True)
    st.caption(
        "지속 모니터링은 다음 Poll로 가상 시간을 진행합니다. 서버 백그라운드 스레드를 만들지 않습니다."
    )
with query:
    c = st.columns(2)
    source = c[0].text_input("출발지 IP", "198.51.100.10", disabled=r.running)
    destination = c[1].text_input("목적지 IP", "", disabled=r.running)
    c = st.columns(3)
    sport = c[0].text_input("Source Port (선택)", disabled=r.running)
    dport = c[1].text_input("Destination Port (선택)", disabled=r.running)
    bidirectional = c[2].checkbox("양방향 조회", True, disabled=r.running)
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
    c = st.columns(4)
    once = c[0].button("현재 조회", disabled=r.running, type="primary")
    start = c[1].button("지속 모니터링 시작", disabled=r.running)
    next_poll = c[2].button("다음 Poll", disabled=not r.running)
    if c[3].button("중지", disabled=not r.running):
        r.stop()
        st.rerun()
    if once or start or next_poll:
        try:
            with st.status("QueryRequest 검증 → MM 위치 → MD 필터형 명령 → Parser", expanded=False):
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
    if r.outcome:
        o = r.outcome
        operator = (
            "정상"
            if o.authoritative
            else ("재시도 중" if r.result and r.result.retry_after_seconds else "확인 필요")
        )
        c = st.columns(5)
        c[0].metric("운영 상태", operator)
        c[1].metric(
            "Active Sessions",
            len(r.result.active_sessions)
            if r.result
            else (len(o.observations) if o.authoritative else "확인 불가"),
        )
        c[2].metric("Authoritative", str(o.authoritative))
        c[3].metric("Last Poll", r.poll_count)
        c[4].metric("현재 관측", len(o.observations) if o.authoritative else "확인 불가")
        st.write(
            f"Used MM: {o.used_mm or '확인 불가'} · Controllers: {', '.join(o.controllers) or '없음'}"
        )
        st.caption(f"실행 조건: {asdict(r.request)} · Stage: {r.stage}")
        if not o.authoritative:
            st.warning(
                "수집 불완전 / Unknown · 세션 없음이나 종료로 판단하지 않습니다. 기존 추적 상태를 유지합니다."
            )
        elif not o.observations:
            st.info("현재 관측 0개 · 기존 세션은 MISS 횟수와 CLOSED 이벤트를 별도로 확인하세요.")
        if r.result:
            st.caption(
                f"MM refresh: {r.result.refreshed_location} · Retry: {r.result.retry_after_seconds}초 · 연속 MISS: {r.result.consecutive_misses}"
            )
        st.json(
            {
                "Source location": asdict(o.source_location) if o.source_location else None,
                "Destination location": asdict(o.destination_location)
                if o.destination_location
                else None,
            }
        )
        c = st.columns(4)
        text = c[0].text_input("IP / Port 검색")
        protocol = c[1].selectbox("Protocol", ["All", "TCP", "UDP"])
        controller = c[2].selectbox(
            "Controller", ["All", *(d.name for d in CONFIG.managed_devices)]
        )
        state = c[3].selectbox("Lifecycle", ["All", "OBSERVED", "MISSED"])
        rows = [
            row
            for row in r.rows()
            if (protocol == "All" or row["protocol"] == {"TCP": 6, "UDP": 17}.get(protocol))
            and (controller == "All" or row["controller_name"] == controller)
            and (state == "All" or row["State"] == state)
            and text
            in " ".join(
                str(row[k])
                for k in ("source_ip", "destination_ip", "source_port", "destination_port")
            )
        ]
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
                    f"{rows[i]['source_ip']}:{rows[i]['source_port']} → {rows[i]['destination_ip']}:{rows[i]['destination_port']} · {rows[i]['controller_name']}"
                ),
            )
            st.json(rows[selected])
            st.json([asdict(flag) for flag in interpret_flags(rows[selected]["flags"])])
        st.subheader("Lifecycle Events · CLOSED / Controller 이동 포함")
        st.dataframe(r.events, hide_index=True)
    else:
        st.info("출발지 또는 목적지 조건으로 현재 조회하거나 지속 모니터링을 시작하세요.")
with evidence:
    st.subheader("조회 경로")
    st.dataframe(r.trace, hide_index=True)
    st.dataframe(r.factory.trace, hide_index=True)
    if r.outcome:
        st.subheader("진단 이벤트")
        st.json([asdict(d) for d in r.outcome.diagnostics])
        for n, raw in enumerate(r.outcome.raw_snapshots):
            with st.expander(f"{n + 1}. {raw.device_name} · {raw.command}"):
                st.code(raw.output, language="text")
with history:
    st.dataframe(r.history, hide_index=True, width="stretch")
    st.caption(
        "최근 20회 Run 요약. 아래 Export는 마지막 Run의 전체 관측이며 표 필터와 독립적입니다. Reset 시 모두 지웁니다."
    )
    if r.outcome:
        st.download_button("CSV Export", r.csv(), "session-v2.csv", "text/csv")
        st.download_button("HTML Report", r.html(), "session-v2.html", "text/html")
with st.expander("Architecture"):
    st.write(
        "QueryRequest → TrackerService → SSHCollector allowlist → FixtureFactory → production Parser → QueryOutcome → MonitorEngine"
    )
    st.caption(
        "SQLite와 known_hosts를 사용하지 않습니다. 합성 transport는 등록된 Demo 장비의 필터형 명령만 처리합니다."
    )
st.link_button(
    "GitHub Source",
    "https://github.com/sebia1993/aruba-session-tracker-1/tree/codex/public-demo-v2",
)
