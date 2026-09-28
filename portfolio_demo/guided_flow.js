(() => {
 const root = document.getElementById('guided-flow');
 if (!root) return;
 const id = root.dataset.run, phase = root.dataset.phase;
 let state = window.__demoGuide;
 if (!state || state.id !== id) {
   if (state?.cleanup) state.cleanup();
   state = window.__demoGuide = {id, follow:true, selected:null, moved:new Set()};
   const pause = () => {
     state.follow = false;
     const selected = document.querySelector('#guided-flow select');
     if (selected) state.selected = Number(selected.value);
   };
   const detail = e => {if (e.target.closest('summary, [role="tab"]')) pause();};
   const key = e => {if (['PageUp','PageDown','ArrowUp','ArrowDown','Home','End'].includes(e.key)) pause();};
   document.addEventListener('wheel',pause,{passive:true});
   document.addEventListener('touchmove',pause,{passive:true});
   document.addEventListener('keydown',key);
   document.addEventListener('click',detail);
   state.cleanup = () => {
     document.removeEventListener('wheel',pause);
     document.removeEventListener('touchmove',pause);
     document.removeEventListener('keydown',key);
     document.removeEventListener('click',detail);
   };
 }
 const cards = [...root.querySelectorAll('article')];
 const select = root.querySelector('select');
 const readout = root.querySelector('[data-readout]');
 const result = phase !== 'running';
 const current = cards.findIndex(c => c.textContent.includes('실행 중') || c.textContent.includes('실제 관측 처리 중'));
 const hasPending = cards.some(c => c.textContent.includes('대기 ·'));
 const live = hasPending && current >= 0 ? current : cards.length - 1;
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