"""Mobile-safe presentation of retained real execution evidence.

The backend Runtime executes at full speed. This module only replays the already
recorded ExecutionTrace in the Streamlit DOM so reviewers can see the sequence.
No JavaScript is required.
"""

from uuid import uuid4
import html

import streamlit as st


STEP_DELAY_SECONDS = 0.62


def begin():
    st.session_state.guided_run_id = uuid4().hex


def _trace_steps(run):
    return [
        step
        for snapshot in getattr(run, "snapshots", [])
        for step in getattr(snapshot.trace, "steps", [])
    ]


def _rail_html(run):
    steps = _trace_steps(run)
    if not steps:
        return ""
    items = []
    for index, step in enumerate(steps, 1):
        status = html.escape(str(getattr(step, "status", "")))
        label = html.escape(str(getattr(step, "label", f"단계 {index}")))
        delay = (index - 1) * STEP_DELAY_SECONDS
        items.append(
            '<span class="native-rail-step" '
            f'data-status="{status}" style="--step-delay:{delay:.2f}s">'
            f'<span class="native-rail-index">{index}</span>'
            f'<span class="native-rail-label">{label}</span>'
            "</span>"
        )
    return "".join(items)


class GuidedSlot:
    """Drop-in markdown slot for the existing escaped timeline renderer."""

    def __init__(self, slot, get_run):
        self.slot = slot
        self.get_run = get_run

    def empty(self):
        self.slot.empty()

    def markdown(self, body, **_kwargs):
        run = self.get_run()
        phase = (
            "error"
            if getattr(run, "error", "")
            else "result"
            if getattr(run, "completed", False)
            else "running"
        )
        run_id = html.escape(st.session_state.get("guided_run_id", "initial"))
        steps = _trace_steps(run)
        total_steps = max(len(steps), body.count("<article data-guide-step"), 1)
        replay_seconds = max(total_steps * STEP_DELAY_SECONDS, STEP_DELAY_SECONDS)
        finish_delay = replay_seconds + 0.25

        elapsed_values = [
            snapshot.trace.elapsed_ms
            for snapshot in getattr(run, "snapshots", [])
            if snapshot.trace.elapsed_ms is not None
        ]
        elapsed = (
            "측정 중"
            if phase == "running"
            else f"{sum(elapsed_values):.1f} ms"
            if elapsed_values
            else "기록 없음"
        )

        title = {
            "running": "실제 분석 진행 중",
            "result": "실제 분석 완료 · 처리 기록 순차 재생",
            "error": "실행 중단 · 확인 필요",
        }[phase]
        state_label = {
            "running": "● 실제 분석 진행 중",
            "result": "● 실제 처리 완료 · 기록 재생 중",
            "error": "✕ 실행 중단",
        }[phase]

        rail = _rail_html(run)
        shell = f"""
<section
  id="guided-flow"
  class="native-guided-flow"
  data-run="{run_id}"
  data-phase="{phase}"
  style="--replay-duration:{replay_seconds:.2f}s;--finish-delay:{finish_delay:.2f}s"
  aria-label="실행 과정">
<style>
#guided-flow {{
  color:#eaf2f8 !important;
  border:1px solid rgba(89,139,185,.45);
  border-radius:16px;
  padding:1rem;
  margin:.65rem 0 1rem;
  background:linear-gradient(180deg,#142335 0%,#101c2a 100%);
  box-shadow:0 12px 30px rgba(0,0,0,.18), inset 0 1px 0 rgba(255,255,255,.035);
  overflow:hidden;
}}
#guided-flow, #guided-flow * {{
  box-sizing:border-box;
}}
#guided-flow h3,
#guided-flow h4,
#guided-flow p,
#guided-flow b,
#guided-flow span {{
  color:inherit !important;
}}
#guided-flow .native-kicker {{
  color:#7fb3df !important;
  font-size:.66rem;
  letter-spacing:.14em;
  font-weight:900;
  margin-bottom:.22rem;
}}
#guided-flow .native-title {{
  color:#f3f7fb !important;
  font-size:1.08rem;
  font-weight:900;
  margin-bottom:.65rem;
}}
#guided-flow .native-state-row {{
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:.55rem;
  margin-bottom:.65rem;
}}
#guided-flow .native-state {{
  display:inline-flex;
  align-items:center;
  min-height:34px;
  border:1px solid rgba(88,167,226,.58);
  border-radius:999px;
  padding:.28rem .68rem;
  background:rgba(39,94,135,.30);
  color:#d6ecff !important;
  font-weight:900;
}}
#guided-flow .native-runtime {{
  color:#aebdcc !important;
  font-size:.82rem;
}}
#guided-flow .native-progress {{
  height:8px;
  border-radius:999px;
  background:#24384c;
  overflow:hidden;
  margin:.45rem 0 .85rem;
}}
#guided-flow .native-progress > span {{
  display:block;
  width:0;
  height:100%;
  border-radius:999px;
  background:linear-gradient(90deg,#4e9bd8,#69c2e4);
}}
#guided-flow[data-phase="result"] .native-progress > span {{
  animation:nativeProgress var(--replay-duration) linear forwards;
}}
#guided-flow .native-replay-status {{
  color:#bed8ee !important;
}}
#guided-flow .native-complete-status {{
  display:none;
  color:#a8e3c5 !important;
}}
#guided-flow[data-phase="result"] .native-replay-status {{
  animation:nativeHide .01s step-end var(--finish-delay) forwards;
}}
#guided-flow[data-phase="result"] .native-complete-status {{
  display:inline-flex;
  opacity:0;
  animation:nativeShow .01s step-end var(--finish-delay) forwards;
}}
#guided-flow .native-rail {{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(105px,1fr));
  gap:.42rem;
  margin:.55rem 0 .85rem;
}}
#guided-flow .native-rail-step {{
  min-width:0;
  display:flex;
  align-items:center;
  gap:.42rem;
  border:1px solid #344b61;
  border-radius:9px;
  padding:.44rem .5rem;
  background:#172839;
  color:#91a6ba !important;
}}
#guided-flow .native-rail-index {{
  width:1.4rem;
  height:1.4rem;
  flex:0 0 auto;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  border:1px solid #46627b;
  border-radius:50%;
  font-size:.62rem;
  font-weight:900;
}}
#guided-flow .native-rail-label {{
  min-width:0;
  font-size:.65rem;
  line-height:1.2;
  font-weight:800;
  overflow:hidden;
  display:-webkit-box;
  -webkit-line-clamp:2;
  -webkit-box-orient:vertical;
}}
#guided-flow[data-phase="result"] .native-rail-step {{
  opacity:.40;
  animation:nativeRail .24s ease var(--step-delay) forwards;
}}
#guided-flow .scenario-grid {{
  display:block;
}}
#guided-flow article[data-guide-step] {{
  color:#e7eef6 !important;
  border:1px solid #38516a !important;
  border-radius:11px !important;
  background:#17293b !important;
  padding:.85rem !important;
  margin:.5rem 0 !important;
}}
#guided-flow article[data-guide-step] h4 {{
  color:#f4f8fb !important;
  margin:.05rem 0 .38rem !important;
  font-size:.94rem !important;
}}
#guided-flow article[data-guide-step] p {{
  color:#bdcbd8 !important;
  margin:.28rem 0 !important;
  line-height:1.48 !important;
}}
#guided-flow article[data-guide-step] .guide-evidence {{
  color:#8fb5d4 !important;
  font-size:.76rem !important;
}}
#guided-flow[data-phase="result"] article[data-guide-step] {{
  opacity:0;
  transform:translateY(8px);
  animation:nativeStepReveal .30s ease var(--step-delay) forwards;
}}
#guided-flow article[data-status="failure"] {{
  border-color:#a65b61 !important;
}}
#guided-flow article[data-status="warning"] {{
  border-color:#9a7b43 !important;
}}
#guided-flow [data-final-summary] {{
  color:#dce7f0 !important;
  border:1px solid #3a5268 !important;
  background:#142638 !important;
}}
#guided-flow [data-final-summary] p {{
  color:#b9c8d5 !important;
}}
#guided-flow[data-phase="result"] [data-final-summary] {{
  opacity:0;
  animation:nativeShow .20s ease var(--finish-delay) forwards;
}}
#guided-flow section > h3,
#guided-flow section > p {{
  display:none;
}}
@keyframes nativeProgress {{ from {{width:0}} to {{width:100%}} }}
@keyframes nativeStepReveal {{
  from {{opacity:0;transform:translateY(8px)}}
  to {{opacity:1;transform:translateY(0)}}
}}
@keyframes nativeRail {{
  from {{opacity:.40;border-color:#344b61;background:#172839}}
  to {{opacity:1;border-color:#4d8cbc;background:#1b3449;color:#d8ecfb}}
}}
@keyframes nativeShow {{ to {{opacity:1}} }}
@keyframes nativeHide {{ to {{opacity:0;visibility:hidden}} }}
@media(max-width:700px) {{
  #guided-flow {{
    padding:.85rem;
  }}
  #guided-flow .native-rail {{
    grid-template-columns:repeat(2,minmax(0,1fr));
  }}
  #guided-flow article[data-guide-step] {{
    padding:.78rem !important;
  }}
}}
@media(prefers-reduced-motion:reduce) {{
  #guided-flow * {{
    animation:none !important;
    transition:none !important;
  }}
  #guided-flow .native-progress > span {{
    width:100% !important;
  }}
  #guided-flow article[data-guide-step],
  #guided-flow .native-rail-step,
  #guided-flow [data-final-summary] {{
    opacity:1 !important;
    transform:none !important;
  }}
  #guided-flow[data-phase="result"] .native-replay-status {{
    display:none !important;
  }}
  #guided-flow[data-phase="result"] .native-complete-status {{
    display:inline-flex !important;
    opacity:1 !important;
  }}
}}
</style>
<div class="native-kicker">INVESTIGATION EXECUTION</div>
<div class="native-title">{html.escape(title)}</div>
<div class="native-state-row">
  <span class="native-state native-replay-status">{html.escape(state_label)}</span>
  <span class="native-state native-complete-status">✓ 분석 완료</span>
  <span class="native-runtime">실제 Runtime 처리 · <b>{html.escape(elapsed)}</b></span>
</div>
<div class="native-progress"><span></span></div>
<div class="native-rail">{rail}</div>
{body}
</section>
"""
        self.slot.markdown(shell, unsafe_allow_html=True)
