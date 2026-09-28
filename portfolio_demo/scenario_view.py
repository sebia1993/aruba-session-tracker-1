"""Escaped views of retained real scenario and communication evidence."""

from html import escape

from portfolio_demo.scenario_runner import communication_rows


def _evidence_text(evidence):
    if not evidence:
        return ""
    parts = []
    for key, value in evidence.items():
        if value in (None, "", [], (), {}):
            continue
        parts.append(f"{key}: {value}")
    return " · ".join(parts)


def _step_card(poll, step):
    icon = {"running": "●", "success": "✓", "warning": "⚠", "failure": "✕"}.get(
        step.status, "•"
    )
    timing = "" if step.elapsed_ms is None else f" · {step.elapsed_ms:.1f} ms"
    evidence = _evidence_text(step.evidence)
    evidence_html = (
        f'<p class="guide-evidence">{escape(evidence)}</p>' if evidence else ""
    )
    detail = escape(step.detail or "실제 Runtime 단계 처리")
    return (
        f'<article data-guide-step data-status="{escape(step.status)}" '
        'style="border:1px solid #8885;border-radius:10px;padding:.8rem;'
        'margin:.5rem 0;overflow-wrap:anywhere">'
        f"<h4>Poll #{poll} · {icon} {escape(step.label)}</h4>"
        f"<p>{detail}{timing}</p>"
        f"{evidence_html}</article>"
    )


def render_timeline(runner, slot):
    if not runner or not runner.run:
        slot.empty()
        return

    run = runner.run
    cards = []
    for snap in run.snapshots:
        cards.extend(_step_card(snap.poll, step) for step in snap.trace.steps)

    # During a live poll, expose the current real ExecutionTrace before the
    # immutable snapshot is appended. Completed runs replay the retained copies.
    if not run.completed and not run.error and len(run.snapshots) < run.current_poll:
        cards.extend(
            _step_card(run.current_poll, step) for step in runner.runtime.execution.steps
        )

    state = (
        "시나리오 완료"
        if run.completed
        else "실행 중단"
        if run.error
        else "시나리오 실행 중"
    )
    if run.snapshots:
        last = run.snapshots[-1]
        observed = "확인 불가" if last.observed is None else str(last.observed)
        final_summary = (
            '<div data-final-summary style="border:1px solid #8885;border-radius:10px;'
            'padding:.8rem;margin:.5rem 0">'
            f"<b>{escape(last.title)}</b>"
            f"<p>{escape(last.explanation)}</p>"
            f"<p>관측 행 {observed} · 추적 {last.retained} · "
            f"MISS {last.missed} · CLOSED {last.closed}</p>"
            f"<p>위치 조회 MM: {escape(last.outcome.used_mm or '확인 불가')} · "
            f"조회 대상 MD: {escape(', '.join(last.selected_controllers) or '확인 불가')}</p>"
            "</div>"
        )
    else:
        final_summary = (
            '<div data-final-summary><p>첫 실제 관측 결과를 준비하고 있습니다.</p></div>'
        )

    slot.markdown(
        '<section aria-label="Scenario Timeline"><h3>Scenario Timeline · '
        + escape(run.name)
        + f"</h3><p>{state} · {len(run.snapshots)}/{run.planned_polls} Poll</p>"
        + final_summary
        + '<div class="scenario-grid">'
        + "".join(cards)
        + "</div></section>",
        unsafe_allow_html=True,
    )


def render_communication(runtime, st):
    if not runtime.outcome:
        return
    outcome = runtime.outcome
    controllers = list(
        dict.fromkeys(entry["Device"] for entry in runtime.trace if entry["Stage"] == "MD_QUERY")
    ) or list(outcome.controllers)
    if not outcome.authoritative:
        st.warning(
            "Session 조회가 완료되지 않았습니다. 기존 관측은 "
            "유지하며 세션 종료로 판단하지 않습니다."
        )
        observations = (
            [s.observation for s in runtime.result.active_sessions] if runtime.result else []
        )
        label = "이전 관측 · 현재 통신 여부 확인 불가"
    else:
        observations = outcome.observations
        label = "이번 Poll에서 실제 관측한 통신"
        if observations:
            st.success(
                f"입력한 단말은 {', '.join(outcome.controllers)}에서 확인되었고, "
                f"현재 {len(observations)}개의 통신 세션 관측 행이 확인되었습니다."
            )
        else:
            st.info("단말 위치는 확인됐지만 현재 조건에 맞는 세션은 관측되지 않았습니다.")
    rows = communication_rows(observations)
    items = (
        "".join(
            '<li style="margin:.55rem 0;overflow-wrap:anywhere">'
            f"<b>{escape(row['protocol'])}</b> · {escape(row['source'])} → "
            f"{escape(row['destination'])} <span>({escape(row['controller'])})</span></li>"
            for row in rows
        )
        or "<li>표시할 현재 통신 관측 없음</li>"
    )
    ips = " / ".join(runtime.request.client_ips)
    st.markdown(
        '<section aria-label="Communication Flow" style="border:1px solid #8885;'
        'border-radius:12px;padding:1rem;overflow-wrap:anywhere">'
        "<h3>단말 위치와 통신 흐름</h3>"
        f"<p><b>{escape(ips)}</b> → 위치 조회: <b>{escape(outcome.used_mm or '확인 불가')}</b>"
        f" → 담당 Controller 조회: <b>{escape(', '.join(controllers) or '확인 불가')}</b></p>"
        "<p>MM에서 단말의 위치를 찾고, 해당 MD의 통신 세션을 "
        "읽습니다. 위 화살표는 조회 순서입니다.</p>"
        f"<h4>{label}</h4><ul>{items}</ul>"
        '<p style="font-size:.8rem">각 행은 실제 관측 방향과 포트입니다. '
        "반대 방향 응답도 별도 관측 행이며, 포트 번호만으로 애플리케이션을 "
        "확정하지 않습니다.</p></section>",
        unsafe_allow_html=True,
    )
