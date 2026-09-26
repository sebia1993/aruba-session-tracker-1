import csv
import io
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from portfolio_demo.logic import CLIENTS, SCENARIOS, run_demo

st.set_page_config(page_title="Session Tracker · Public Demo", page_icon="📡", layout="wide")
st.title("Aruba Session Tracker")
st.caption("Client → Mobility Conductor → 관련 MD → datapath session 분석")
st.info(
    "공개 Demo Mode · 원 프로젝트의 Global User / Datapath Parser와 Flags 분석을 사용합니다. "
    "입력은 공개 샘플 조회에만 사용되며 외부 장비에 연결하지 않습니다."
)
with st.sidebar:
    st.subheader("Demo Mode")
    st.success("실제 장비 연결: 비활성")
    st.write("분석: 원 프로젝트 Python 코드")
    st.caption(
        "수집 실패는 세션 종료가 아닙니다. "
        "VLAN과 TCP 상태는 이 CLI에서 관측되지 않아 추정하지 않습니다."
    )
scenario = st.selectbox("체험 시나리오", list(SCENARIOS), format_func=SCENARIOS.get)
if "client" not in st.session_state:
    st.session_state.client = "192.0.2.10"
for col, ip in zip(st.columns(3), CLIENTS, strict=True):
    if col.button(f"Sample {ip}"):
        st.session_state.client = ip
client_input = st.text_input("Client IP 또는 MAC Address", key="client")
if st.button("분석 실행", type="primary", width="stretch"):
    client = next(
        (ip for ip, mac in CLIENTS.items() if client_input.strip().lower() in (ip, mac)), ""
    )
    try:
        result = run_demo(scenario, client)
        st.session_state.result = (scenario, result)
        history = st.session_state.get("history", [])
        history.append(
            {
                "Run": history[-1]["Run"] + 1 if history else 1,
                "Client": client,
                "Scenario": SCENARIOS[scenario],
                "Status": result["status"],
                "Session Count": len(result["rows"]) if result["authoritative"] else None,
            }
        )
        st.session_state.history = history[-50:]
    except ValueError as exc:
        st.session_state.pop("result", None)
        st.error(str(exc))
if "result" in st.session_state:
    selected, result = st.session_state.result
    st.subheader(f"결과 · {SCENARIOS[selected]} · {result['client']}")
    if selected != scenario or client_input.strip().lower() not in (
        result["client"],
        CLIENTS[result["client"]],
    ):
        st.info("입력이 변경되었습니다. 분석 실행을 눌러 새 결과를 확인하세요.")
    (st.success if result["authoritative"] else st.warning)(result["status"])
    st.write(result["reason"])
    st.metric("Session Count", len(result["rows"]) if result["authoritative"] else "확인 불가")
    st.dataframe(result["context"], hide_index=True, width="stretch")
    st.caption("VLAN: 관측 정보 없음 · 세션 State는 현재 CLI 관측 여부를 의미합니다.")
    search = st.text_input("Search Filter · IP / Protocol / Port")
    rows = [
        r for r in result["rows"] if search.casefold() in " ".join(map(str, r.values())).casefold()
    ]
    if result["authoritative"]:
        st.caption(f"표시 {len(rows)} / 관측 {len(result['rows'])}")
    else:
        st.caption("수집 불완전 · 세션 개수 확인 불가")
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    if result["rows"]:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(result["rows"][0]))
        writer.writeheader()
        writer.writerows(result["rows"])
        st.download_button("CSV Export · 전체 관측", buf.getvalue(), "session-demo.csv", "text/csv")
    with st.expander("조회 경로 / Raw CLI", expanded=False):
        st.write(result["trace"])
        for command, body in result["raw"].items():
            st.markdown(f"**{command}**")
            st.code(body, language="text")
    st.download_button(
        "Raw TXT 다운로드",
        "\n\n".join(f"{k}\n{v}" for k, v in result["raw"].items()),
        "session-demo.txt",
    )
if "history" in st.session_state:
    with st.expander("Session History · 현재 브라우저 세션의 최근 50회"):
        st.dataframe(st.session_state.history, hide_index=True)
with st.expander("Architecture / How It Works"):
    st.write(
        "Sample Client → parse_global_user_table → Current Switch → "
        "parse_datapath_sessions → Flags 분석"
    )
    st.caption(
        "합성 수집 계층만 사용합니다. "
        "SSH·SQLite 영속 저장·실제 세션 수명주기 검증은 이 공개 체험판의 범위가 아닙니다."
    )
st.link_button("GitHub Source", "https://github.com/sebia1993/aruba-session-tracker-1")
