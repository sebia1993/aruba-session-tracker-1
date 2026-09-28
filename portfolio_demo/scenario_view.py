"""Escaped views of retained real scenario and communication evidence."""

from html import escape


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
    icon = {"running": "●", "success": "✓", "warning": "⚠", "failure": "✕"}.get(step.status, "•")
    timing = "" if step.elapsed_ms is None else f" · {step.elapsed_ms:.1f} ms"
    evidence = _evidence_text(step.evidence)
    evidence_html = f'<p class="guide-evidence">{escape(evidence)}</p>' if evidence else ""
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
        cards.extend(_step_card(run.current_poll, step) for step in runner.runtime.execution.steps)

    state = "시나리오 완료" if run.completed else "실행 중단" if run.error else "시나리오 실행 중"
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
            "<div data-final-summary><p>첫 실제 관측 결과를 준비하고 있습니다.</p></div>"
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
        observations = (
            [session.observation for session in runtime.result.active_sessions]
            if runtime.result
            else []
        )
        status_text = "UNKNOWN · 수집 확인 필요"
        status_class = "topology-state warn"
        headline = (
            "Session 조회가 완료되지 않았습니다. 이전 관측은 유지하고 "
            "통신 종료로 판단하지 않습니다."
        )
    else:
        observations = outcome.observations
        status_text = "OBSERVED · 현재 관측"
        status_class = "topology-state"
        headline = (
            f"{len(observations)}개의 실제 통신 세션 관측 행을 확인했습니다."
            if observations
            else "단말 위치는 확인됐지만 현재 조건에 맞는 세션은 관측되지 않았습니다."
        )

    client_ips = tuple(runtime.request.client_ips)
    client_ip = " / ".join(client_ips) or "확인 불가"
    used_mm = outcome.used_mm or "확인 불가"
    md_text = ", ".join(controllers) or "확인 불가"

    peer_cards = []
    for index, item in enumerate(observations, 1):
        protocol = {6: "TCP", 17: "UDP"}.get(item.protocol, str(item.protocol))
        if item.source_ip in client_ips:
            direction = "OUTBOUND"
            peer_ip = item.destination_ip
            peer_port = item.destination_port
        elif item.destination_ip in client_ips:
            direction = "INBOUND"
            peer_ip = item.source_ip
            peer_port = item.source_port
        else:
            direction = "OBSERVED"
            peer_ip = item.destination_ip
            peer_port = item.destination_port

        packets = getattr(item, "packets", None)
        bytes_count = getattr(item, "bytes_count", None)
        age = getattr(item, "age", None)
        meta = [
            direction,
            item.controller_name,
            f"Packets {packets}" if packets is not None else "",
            f"Bytes {bytes_count}" if bytes_count is not None else "",
            f"Age {age}" if age not in (None, "") else "",
        ]
        meta_text = " · ".join(part for part in meta if part)

        peer_cards.append(
            '<article class="peer-card">'
            f'<span class="proto">{escape(protocol)} · {escape(str(peer_port))}</span>'
            f'<div class="peer">{escape(str(peer_ip))}:{escape(str(peer_port))}</div>'
            f'<div class="meta">FLOW {index:02d} · {escape(meta_text)}</div>'
            "</article>"
        )

    peer_html = "".join(peer_cards) or (
        '<article class="peer-card">'
        '<span class="proto">NO ACTIVE FLOW</span>'
        '<div class="peer">현재 표시할 통신 관측 없음</div>'
        '<div class="meta">위치 확인 결과와 수집 상태를 먼저 확인하세요.</div>'
        "</article>"
    )

    st.markdown(
        '<section class="topology-shell" data-topology aria-label="WLAN 조사 토폴로지">'
        '<div class="topology-head">'
        "<div>"
        '<div class="topology-kicker">LIVE INVESTIGATION TOPOLOGY</div>'
        '<div class="topology-title">Client → MM → Controller → Communication Peer</div>'
        "</div>"
        f'<span class="{status_class}">{escape(status_text)}</span>'
        "</div>"
        '<div class="topology-path">'
        '<article class="topology-node client">'
        '<div class="topology-node-kind">TARGET · WIRELESS CLIENT</div>'
        f'<div class="topology-node-value">{escape(client_ip)}</div>'
        '<div class="topology-node-meta">조사의 시작점 · 입력 IP</div>'
        "</article>"
        '<div class="topology-link">→<small>LOCATION<br>LOOKUP</small></div>'
        '<article class="topology-node mm">'
        '<div class="topology-node-kind">MOBILITY CONDUCTOR</div>'
        f'<div class="topology-node-value">{escape(used_mm)}</div>'
        '<div class="topology-node-meta">단말이 연결된 Controller 위치 확인</div>'
        "</article>"
        '<div class="topology-link">→<small>FILTERED<br>QUERY</small></div>'
        '<article class="topology-node md">'
        '<div class="topology-node-kind">MANAGED DEVICE · CONTROLLER</div>'
        f'<div class="topology-node-value">{escape(md_text)}</div>'
        '<div class="topology-node-meta">해당 단말의 datapath session 조회</div>'
        "</article>"
        "</div>"
        '<div class="peer-section">'
        '<div class="topology-kicker">OBSERVED COMMUNICATION PEERS</div>'
        f'<div class="topology-node-meta">{escape(headline)}</div>'
        f'<div class="peer-grid">{peer_html}</div>'
        "</div>"
        '<div class="topology-foot">'
        "표시 값은 실제 DemoRuntime의 관측 결과입니다. Public Demo는 비식별 합성 Transport를 "
        "사용하지만 QueryRequest · TrackerService · production Parser · "
        "MonitorEngine 경로를 재사용합니다."
        "</div>"
        "</section>",
        unsafe_allow_html=True,
    )
