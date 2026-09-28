(() => {
 const root = document.getElementById('guided-flow');
 if (!root) return;

 const id = root.dataset.run;
 const phase = root.dataset.phase;
 const elapsed = root.dataset.elapsed;
 const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
 const cards = [...root.querySelectorAll('article[data-guide-step]')];
 const select = root.querySelector('select');
 const readout = root.querySelector('[data-readout]');
 const badge = root.querySelector('[data-state-badge]');
 const progress = root.querySelector('[data-progress]');
 const finalSummary = root.querySelector('[data-final-summary]');
 const rail = root.querySelector('[data-rail]');

 let state = window.__demoGuide;
 const isNewRun = !state || state.id !== id;
 if (isNewRun) {
   if (state?.cleanup) state.cleanup();
   state = window.__demoGuide = {
     id,
     phase,
     follow: true,
     selected: null,
     replaying: phase === 'result' && cards.length > 1 && !reduceMotion,
     replayIndex: 0,
     moved: new Set(),
     timer: null
   };

   const stopReplay = () => {
     if (state.timer) clearTimeout(state.timer);
     state.timer = null;
     state.replaying = false;
   };
   const pause = () => {
     stopReplay();
     state.follow = false;
     const selected = document.querySelector('#guided-flow select');
     if (selected) state.selected = Number(selected.value);
   };
   const detail = e => {if (e.target.closest('summary, [role="tab"]')) pause();};
   const key = e => {
     if (['PageUp','PageDown','ArrowUp','ArrowDown','Home','End'].includes(e.key)) pause();
   };
   document.addEventListener('wheel', pause, {passive:true});
   document.addEventListener('touchmove', pause, {passive:true});
   document.addEventListener('keydown', key);
   document.addEventListener('click', detail);
   state.cleanup = () => {
     stopReplay();
     document.removeEventListener('wheel', pause);
     document.removeEventListener('touchmove', pause);
     document.removeEventListener('keydown', key);
     document.removeEventListener('click', detail);
   };
 } else if (state.phase !== phase) {
   state.phase = phase;
   if (phase === 'result' && cards.length > 1 && !reduceMotion) {
     state.replaying = true;
     state.replayIndex = 0;
     state.selected = null;
   }
 }

 const current = cards.findIndex(c => c.dataset.status === 'running');
 const live = current >= 0 ? current : Math.max(0, cards.length - 1);

 cards.forEach((card, i) => {
   const opt = document.createElement('option');
   opt.value = i;
   opt.textContent = card.querySelector('h4')?.textContent || `단계 ${i + 1}`;
   select.appendChild(opt);

   if (rail) {
     const item = document.createElement('span');
     item.className = 'rail-step';
     item.dataset.railIndex = String(i);
     item.title = opt.textContent;
     const index = document.createElement('span');
     index.className = 'rail-index';
     index.textContent = String(i + 1);
     const label = document.createElement('span');
     label.className = 'rail-label';
     label.textContent = opt.textContent
       .replace(/^Poll #\d+ ·\s*/, '')
       .replace(/^[✓●⚠✕•]\s*/, '');
     item.append(index, label);
     rail.appendChild(item);
   }
 });

 function setProgress(index, final=false) {
   if (!progress) return;
   const ratio = final ? 1 : cards.length ? (index + 1) / cards.length : 0;
   progress.style.width = `${Math.max(0, Math.min(1, ratio)) * 100}%`;
 }

 function paintRail(chosen) {
   if (!rail) return;
   const items = [...rail.querySelectorAll('.rail-step')];
   items.forEach((item, i) => {
     const card = cards[i];
     item.classList.remove('done', 'active', 'failure');
     if (card?.dataset.status === 'failure' || card?.dataset.status === 'warning') {
       item.classList.add('failure');
     }
     if (chosen < 0) {
       if (phase === 'result') item.classList.add('done');
       return;
     }
     if (i < chosen) item.classList.add('done');
     if (i === chosen) item.classList.add('active');
   });
 }

 function paint() {
   let chosen;
   paintRail(chosen);

   if (state.replaying) {
     chosen = state.replayIndex;
   } else if (phase === 'running' && state.follow) {
     chosen = live;
   } else {
     chosen = state.selected ?? -1;
   }

   cards.forEach((card, i) => {card.hidden = i !== chosen;});
   if (finalSummary) finalSummary.hidden = chosen >= 0;
   select.value = String(chosen);
   root.querySelector('[data-steps]').hidden = chosen < 0;
   root.querySelector('[data-back]').disabled = chosen <= 0;
   root.querySelector('[data-next]').disabled = chosen >= cards.length - 1;

   if (state.replaying) {
     badge.textContent = '● 실제 처리 완료 · 기록 재생 중';
     readout.textContent =
       `실제 Runtime 결과를 재생 중입니다 · 단계 ${chosen + 1}/${cards.length}`;
     setProgress(chosen);
   } else if (phase === 'running') {
     badge.textContent = '● 실제 분석 진행 중';
     readout.textContent =
       cards.length ? `실제 분석 진행 중 · 단계 ${live + 1}/${cards.length}` : '실제 분석 시작 중';
     setProgress(live);
   } else if (phase === 'error') {
     badge.textContent = '✕ 실행 중단 · 확인 필요';
     readout.textContent = '실행이 중단되었습니다. 실패 단계와 확인 가능한 범위를 확인하세요.';
     setProgress(Math.max(0, chosen));
   } else if (chosen >= 0) {
     badge.textContent = '✓ 실제 분석 완료 · 기록 확인';
     readout.textContent = `저장된 실제 처리 단계 ${chosen + 1}/${cards.length}`;
     setProgress(chosen);
   } else {
     badge.textContent = '✓ 분석 완료';
     readout.textContent = `실제 Runtime 처리 ${elapsed} · 아래 통신 결과를 확인하세요.`;
     setProgress(cards.length - 1, true);
   }

   root.querySelector('[data-follow]').textContent =
     phase === 'running' ? '현재 단계 따라가기' : '결과 보기';
 }

 function move() {
   root.scrollIntoView({
     block:'start',
     behavior: reduceMotion ? 'instant' : 'smooth'
   });
   root.querySelector('h3').focus({preventScroll:true});
 }

 function scheduleReplay() {
   if (!state.replaying) return;
   if (state.timer) clearTimeout(state.timer);
   state.timer = setTimeout(() => {
     state.timer = null;
     if (!root.isConnected || !state.replaying) return;
     if (state.replayIndex < cards.length - 1) {
       state.replayIndex += 1;
       paint();
       scheduleReplay();
     } else {
       state.replaying = false;
       state.selected = null;
       paint();
     }
   }, 700);
 }

 function startReplay() {
   if (!cards.length) return;
   if (state.timer) clearTimeout(state.timer);
   state.follow = false;
   state.selected = null;
   state.replaying = true;
   state.replayIndex = 0;
   paint();
   move();
   scheduleReplay();
 }

 select.addEventListener('change', () => {
   if (state.timer) clearTimeout(state.timer);
   state.timer = null;
   state.replaying = false;
   state.follow = false;
   state.selected = Number(select.value);
   paint();
 });
 root.querySelector('[data-follow]').addEventListener('click', () => {
   if (state.timer) clearTimeout(state.timer);
   state.timer = null;
   state.replaying = false;
   state.follow = phase === 'running';
   state.selected = null;
   paint();
   move();
 });
 root.querySelector('[data-replay]').addEventListener('click', startReplay);
 root.querySelector('[data-back]').addEventListener('click', () => {
   if (state.timer) clearTimeout(state.timer);
   state.timer = null;
   state.replaying = false;
   state.follow = false;
   state.selected = Math.max(0, Number(select.value) - 1);
   paint();
 });
 root.querySelector('[data-next]').addEventListener('click', () => {
   if (state.timer) clearTimeout(state.timer);
   state.timer = null;
   state.replaying = false;
   state.follow = false;
   state.selected = Math.min(cards.length - 1, Number(select.value) + 1);
   paint();
 });

 paint();
 if (state.replaying) {
   requestAnimationFrame(() => {
     if (root.isConnected) {
       move();
       scheduleReplay();
     }
   });
 } else if (state.follow && !state.moved.has(phase)) {
   state.moved.add(phase);
   requestAnimationFrame(() => {if (root.isConnected && state.follow) move();});
 }
})();
