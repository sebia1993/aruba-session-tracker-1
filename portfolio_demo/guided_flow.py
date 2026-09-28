"""Presentation-only navigation of retained execution evidence.

No collection callbacks, network requests, browser storage or generated findings.
Only application-owned scripts execute; timeline values remain HTML-escaped.
"""

from uuid import uuid4
import streamlit as st


def begin():
    st.session_state.guided_run_id = uuid4().hex


_SCRIPT = r"""
<script>
(() => {
 const root = document.getElementById('guided-flow');
 if (!root) return;
 const id = root.dataset.run, phase = root.dataset.phase;
 let state = window.__demoGuide;
 if (!state || state.id !== id) {
   if (state?.cleanup) state.cleanup();
   state = window.__demoGuide = {id, follow:true, selected:null, moved:new Set()};
   const pause = () => {state.follow = false;};
   const key = e => {if (['PageUp','PageDown','ArrowUp','ArrowDown','Home','End'].includes(e.key)) pause();};
   document.addEventListener('wheel',pause,{passive:true});
   document.addEventListener('touchmove',pause,{passive:true});
   document.addEventListener('keydown',key);
   state.cleanup = () => {
     document.removeEventListener('wheel',pause);
     document.removeEventListener('touchmove',pause);
     document.removeEventListener('keydown',key);
   };
 }
 const cards = [...root.querySelectorAll('article')];
 const select = root.querySelector('select');
 const readout = root.querySelector('[data-readout]');
 const result = phase !== 'running';
 const current = cards.findIndex(c => c.textContent.includes('실행 중') || c.textContent.includes('실제 관측 처리 중'));
 const live = current >= 0 ? current : cards.length - 1;
 cards.forEach((card,i) => {
   const opt = document.createElement('option');
   opt.value = i;
   opt.textContent = card.querySelector('h4')?.textContent || `단계 ${i+1}`;
   select.appendChild(opt);
 });
 function paint() {
   const chosen = state.follow ? (result ? -1 : live) : (state.selected ?? (result ? -1 : live));
   cards.forEach((card,i) => {card.hidden = i !== chosen;});
   select.value = String(chosen);
   root.querySelector('[data-steps]').hidden = chosen < 0;
   root.querySelector('[data-back]').disabled = chosen <= 0;
   root.querySelector('[data-next]').disabled = chosen >= cards.length - 1;
   readout.textContent = chosen < 0 ? (phase === 'error' ? '실행이 중단되었습니다. 아래에서 실패와 확인 가능한 범위를 확인하세요.' : '검증 결과가 준비되었습니다. 아래 결론부터 확인하세요.') : `단계 ${chosen+1}/${cards.length} · 저장된 실제 기록`;
   root.querySelector('[data-follow]').textContent = result ? '결과 보기' : '현재 단계 따라가기';
 }
 function move() {
   root.scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth'});
   root.querySelector('h3').focus({preventScroll:true});
 }
 select.addEventListener('change',() => {state.follow=false;state.selected=Number(select.value);paint();});
 root.querySelector('[data-follow]').addEventListener('click',() => {state.follow=true;state.selected=null;paint();move();});
 root.querySelector('[data-replay]').addEventListener('click',() => {state.follow=false;state.selected=cards.length?0:-1;paint();move();});
 root.querySelector('[data-back]').addEventListener('click',() => {state.follow=false;state.selected=Math.max(0,Number(select.value)-1);paint();});
 root.querySelector('[data-next]').addEventListener('click',() => {state.follow=false;state.selected=Math.min(cards.length-1,Number(select.value)+1);paint();});
 paint();
 if (state.follow && !state.moved.has(phase)) {
   state.moved.add(phase);
   requestAnimationFrame(() => {if (root.isConnected && state.follow) move();});
 }
})();
</script>
"""


class GuidedSlot:
    """Drop-in markdown slot for the existing escaped timeline renderers."""

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
        run_id = st.session_state.get("guided_run_id", "initial")
        title = {
            "running": "현재 실행 과정",
            "result": "실행 완료 · 결과 확인",
            "error": "실행 중단 · 확인 필요",
        }[phase]
        with self.slot.container():
            st.html(
                f'''<section id="guided-flow" data-run="{run_id}" data-phase="{phase}" aria-label="안내형 실행 화면" style="scroll-margin-top:70px">
<style>
#guided-flow {{border:1px solid #8886;border-radius:12px;padding:1rem;margin:.5rem 0;overflow-wrap:anywhere}}
#guided-flow h3 {{margin:0 0 .6rem}}
#guided-flow .guide-nav {{display:flex;flex-wrap:wrap;gap:.5rem;margin:.5rem 0}}
#guided-flow button,#guided-flow select {{font:inherit;color:inherit;background:transparent;border:1px solid #8888;border-radius:8px;padding:.5rem;max-width:100%;cursor:pointer}}
#guided-flow select {{flex:1;min-width:160px}}
#guided-flow select option {{color:#111;background:#fff}}
#guided-flow [hidden] {{display:none!important}}
#guided-flow .scenario-grid {{display:block}}
#guided-flow article {{margin:.5rem 0!important}}
#guided-flow section > h3,#guided-flow section > p {{display:none}}
#guided-flow :focus-visible {{outline:3px solid #4f9eff;outline-offset:3px}}
@media(max-width:600px) {{#guided-flow {{padding:.7rem}} #guided-flow select {{width:100%;flex-basis:100%}}}}
</style>
<h3 tabindex="-1">{title}</h3>
<p data-readout role="status" aria-live="polite">실제 실행 기록을 확인합니다.</p>
<div class="guide-nav"><button data-follow type="button">현재 단계 따라가기</button><button data-replay type="button">과정 다시 보기</button></div>
<div class="guide-nav" data-steps><select aria-label="실행 단계 선택"><option value="-1">최종 결과</option></select><button data-back type="button" aria-label="이전 단계">← 이전</button><button data-next type="button" aria-label="다음 단계">다음 →</button></div>
<div>{body}</div></section>'''
                + _SCRIPT,
                unsafe_allow_javascript=True,
            )
