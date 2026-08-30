from __future__ import annotations

import base64
import hashlib
import re
from inspect import signature
from pathlib import Path

import pytest

from aruba_session_tracker.storage import (
    RunReportSnapshot,
    html_report,
    render_html_report,
    write_html_report_atomic,
)


def _observation(
    *,
    observed_at: str = "2026-08-28T08:01:00.000Z",
    controller_name: str = "서울-MD-01",
    controller_host: str = "198.51.100.21",
    protocol: int = 6,
    source_ip: str = "192.0.2.100",
    destination_ip: str = "203.0.113.80",
    source_port: int = 53000,
    destination_port: int = 443,
    packets: int | None = 12,
    bytes_count: int | None = 2048,
) -> dict[str, object]:
    return {
        "observed_at": observed_at,
        "controller_name": controller_name,
        "controller_host": controller_host,
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "packets": packets,
        "bytes_count": bytes_count,
        "age": 2,
        "flags": "DY",
        "cpu_id": 1,
        "session_key": (
            f"{controller_host}|{protocol}|{source_ip}|{destination_ip}|"
            f"{source_port}|{destination_port}"
        ),
    }


def _snapshot(
    *,
    run: dict[str, object] | None = None,
    observations: tuple[dict[str, object], ...] | None = None,
    observation_history: tuple[dict[str, object], ...] | None = None,
    lifecycle_events: tuple[dict[str, object], ...] | None = None,
    diagnostics: tuple[dict[str, object], ...] | None = None,
    observation_total: int | None = None,
) -> RunReportSnapshot:
    run_row = (
        run
        if run is not None
        else {
            "id": "run-report-001",
            "started_at": "2026-08-28T08:00:00.000Z",
            "ended_at": "2026-08-28T08:05:00.000Z",
            "source_ip": "192.0.2.100",
            "destination_ip": "203.0.113.80",
            "source_port": 53000,
            "destination_port": 443,
            "bidirectional": 1,
            "status": "COMPLETED",
        }
    )
    observation_rows = observations if observations is not None else (_observation(),)
    history_rows = observation_rows if observation_history is None else observation_history
    default_session_key = str(observation_rows[0]["session_key"]) if observation_rows else ""
    lifecycle_rows = (
        lifecycle_events
        if lifecycle_events is not None
        else (
            (
                {
                    "occurred_at": "2026-08-28T08:01:00.000Z",
                    "session_key": default_session_key,
                    "instance_id": "instance-001",
                    "event_type": "STARTED",
                    "controller_name": "서울-MD-01",
                    "details_json": '{"miss_count": 0}',
                },
            )
            if observation_rows
            else ()
        )
    )
    diagnostic_rows = (
        diagnostics
        if diagnostics is not None
        else (
            {
                "occurred_at": "2026-08-28T08:03:00.000Z",
                "stage": "MD_QUERY",
                "code": "SESSION_NOT_FOUND",
                "message": "보고서에 표시하면 안 되는 진단 메시지",
            },
        )
    )
    raw_rows = (
        {
            "id": 41,
            "captured_at": "2026-08-28T08:00:30.000Z",
            "kind": "mm-location",
            "controller_name": "MM-주장비",
            "sha256": "a" * 64,
            "byte_size": 1024,
            "relative_path": "must-not-be-rendered.txt",
            "raw_text": "RAW-BODY-MUST-NOT-BE-RENDERED",
        },
    )
    return RunReportSnapshot(
        run=run_row,
        controllers=("MM-주장비", "서울-MD-01"),
        mm_controllers=("MM-주장비",),
        md_controllers=("서울-MD-01",),
        observations=observation_rows,
        observation_total=(len(history_rows) if observation_total is None else observation_total),
        unique_session_total=len(observation_rows),
        lifecycle_events=lifecycle_rows,
        lifecycle_total=len(lifecycle_rows),
        lifecycle_counts=(("STARTED", 1),) if lifecycle_rows else (),
        controller_events=(
            {
                "occurred_at": "2026-08-28T08:02:00.000Z",
                "previous_controller": "서울-MD-01",
                "current_controller": "서울-MD-02",
                "reason": "CURRENT_SWITCH_CHANGED",
            },
        ),
        controller_total=1,
        diagnostics=diagnostic_rows,
        diagnostic_total=len(diagnostic_rows),
        raw_files=raw_rows,
        raw_file_total=len(raw_rows),
        raw_byte_total=1024,
        observation_history=history_rows,
    )


def _section(document: str, section_id: str) -> str:
    match = re.search(
        rf'<section id="{re.escape(section_id)}"[^>]*>(?P<body>.*?)</section>',
        document,
        flags=re.DOTALL,
    )
    assert match is not None
    return match.group("body")


def _table_body(section: str) -> str:
    match = re.search(r"<tbody\b[^>]*>(?P<body>.*?)</tbody>", section, flags=re.DOTALL)
    assert match is not None
    return match.group("body")


def _report_rows(markup: str) -> list[str]:
    return re.findall(
        r'<tr\b(?=[^>]*\bclass="[^"]*\breport-row\b)[^>]*>.*?</tr>',
        markup,
        flags=re.DOTALL,
    )


def _element_start_tag(document: str, tag_name: str, element_id: str) -> str:
    match = re.search(
        rf'<{re.escape(tag_name)}\b[^>]*\bid="{re.escape(element_id)}"[^>]*>',
        document,
    )
    assert match is not None
    return match.group(0)


def _inline_scripts(document: str) -> list[str]:
    return re.findall(
        r"<script(?:\s[^>]*)?>(?P<body>.*?)</script>",
        document,
        flags=re.DOTALL | re.IGNORECASE,
    )


def test_report_is_concise_standalone_result_only_html5() -> None:
    document = render_html_report(_snapshot())
    lowered = document.casefold()

    assert document.startswith('<!doctype html>\n<html lang="ko">')
    assert '<meta charset="utf-8">' in lowered
    assert '<meta name="viewport"' in lowered
    assert "Content-Security-Policy" in document
    assert "default-src 'none'" in document
    assert "style-src 'unsafe-inline'" in document
    assert "script-src 'sha256-" in document
    assert "<style>" in lowered
    assert "@media (max-width:850px)" in document
    assert "@page { size:A4 landscape" in document
    assert "@media print" in document
    assert len(_inline_scripts(document)) == 1
    assert "<link" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert not re.search(r"\b(?:src|href)=[\"'](?:https?:)?//", lowered)
    assert "<nav" not in lowered

    headings = ("결과 필터", "최신 세션 결과", "전체 추적 이력")
    positions = [document.index(heading) for heading in headings]
    assert positions == sorted(positions)
    assert document.count("<h2") == 2
    assert re.findall(r'<th scope="col">([^<]+)</th>', _section(document, "latest-sessions")) == [
        "마지막 확인 시각",
        "장비명",
        "프로토콜",
        "출발지 IP:포트",
        "목적지 IP:포트",
        "추적 상태",
    ]
    assert re.findall(
        r'<th scope="col">([^<]+)</th>', _section(document, "observation-history")
    ) == [
        "확인 시각",
        "장비명",
        "프로토콜",
        "출발지 IP:포트",
        "목적지 IP:포트",
        "추적 상태",
    ]
    assert "전체 추적 이력 1/1건 보기</summary>" in document
    assert "<details open" not in document
    assert 'role="region" aria-label="최신 세션 결과 표" tabindex="0"' in document
    assert 'role="region" aria-label="전체 추적 이력 표" tabindex="0"' in document
    assert document.count('<th scope="col">') == 12


def test_filter_uses_one_exactly_hash_authorized_inline_script() -> None:
    document = render_html_report(_snapshot())
    scripts = _inline_scripts(document)
    assert len(scripts) == 1
    script = scripts[0]
    empty_script = _inline_scripts(
        render_html_report(
            _snapshot(
                observations=(),
                observation_history=(),
                lifecycle_events=(),
                observation_total=0,
            )
        )
    )[0]
    assert script == empty_script
    expected_hash = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode(
        "ascii"
    )

    csp = re.search(
        r'<meta http-equiv="Content-Security-Policy" content="(?P<value>[^"]+)">',
        document,
    )
    assert csp is not None
    assert re.findall(r"script-src\s+'sha256-([^']+)'", csp.group("value")) == [expected_hash]
    assert "'unsafe-inline'" not in re.search(
        r"script-src(?P<value>[^;]+)", csp.group("value")
    ).group("value")
    assert not re.search(r"<script\b[^>]+\bsrc=", document, flags=re.IGNORECASE)
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", document, flags=re.IGNORECASE)
    assert "<link" not in document.casefold()
    assert not re.search(r"\b(?:src|href)=[\"'](?:https?:)?//", document, flags=re.IGNORECASE)
    assert "http://" not in document.casefold()
    assert "https://" not in document.casefold()


def test_filter_controls_are_hidden_until_initialized_and_keyboard_accessible() -> None:
    document = render_html_report(_snapshot())
    filter_section = _element_start_tag(document, "section", "result-filter")
    ip_input = _element_start_tag(document, "input", "filter-ip")
    port_input = _element_start_tag(document, "input", "filter-port")
    protocol_select = _element_start_tag(document, "select", "filter-protocol")
    reset_button = _element_start_tag(document, "button", "filter-reset")
    ip_list = _element_start_tag(document, "div", "filter-ip-list")
    port_list = _element_start_tag(document, "div", "filter-port-list")
    filter_status = _element_start_tag(document, "p", "filter-status")

    assert re.search(r"\bclass=\"[^\"]*\bfilter-panel\b", filter_section)
    assert re.search(r"\bclass=\"[^\"]*\bjs-only\b", filter_section)
    assert re.search(r"\shidden(?:\s|>)", filter_section)
    assert re.search(r'<label\b[^>]*\bfor="filter-ip"[^>]*>IP 검색</label>', document)
    assert re.search(r'<label\b[^>]*\bfor="filter-protocol"[^>]*>프로토콜</label>', document)
    assert re.search(r'<label\b[^>]*\bfor="filter-port"[^>]*>포트 검색</label>', document)
    for input_tag, list_id in ((ip_input, "filter-ip-list"), (port_input, "filter-port-list")):
        assert 'role="combobox"' in input_tag
        assert 'aria-autocomplete="list"' in input_tag
        assert f'aria-controls="{list_id}"' in input_tag
        assert 'aria-expanded="false"' in input_tag
        assert 'autocomplete="off"' in input_tag
    assert 'aria-label="프로토콜"' in protocol_select
    assert 'aria-describedby="filter-status"' in protocol_select
    assert '<option value="">전체</option>' in document
    assert 'type="button"' in reset_button
    assert ">전체 초기화</button>" in document
    assert 'role="listbox"' in ip_list
    assert 'role="listbox"' in port_list
    assert 'aria-live="polite"' in filter_status
    assert 'id="latest-filter-count"' in document
    assert 'id="history-filter-count"' in document
    assert 'role="status"' in filter_status
    assert 'aria-live="polite"' in _element_start_tag(document, "span", "latest-filter-count")
    assert 'aria-live="polite"' in _element_start_tag(document, "span", "history-filter-count")
    _element_start_tag(document, "tbody", "latest-results-body")
    _element_start_tag(document, "tbody", "history-results-body")
    _element_start_tag(document, "summary", "history-filter-summary")


def test_filter_rows_have_escaped_exact_match_data_and_print_markers() -> None:
    row = _observation(
        protocol=17,
        source_ip='2001:db8::1" data-breakout="blocked',
        destination_ip="203.0.113.81",
        source_port=5353,
        destination_port=53,
    )
    document = render_html_report(
        _snapshot(
            observations=(row,),
            observation_history=(row,),
            lifecycle_events=(),
        )
    )
    rows = _report_rows(document)

    assert len(rows) == 2
    for rendered_row in rows:
        assert 'data-source-ip="2001:db8::1&quot; data-breakout=&quot;blocked"' in rendered_row
        assert 'data-destination-ip="203.0.113.81"' in rendered_row
        assert 'data-source-port="5353"' in rendered_row
        assert 'data-destination-port="53"' in rendered_row
        assert 'data-protocol="UDP (17)"' in rendered_row
        assert ' data-breakout="blocked"' not in rendered_row
    assert 'id="print-filter-summary"' in document
    assert ".print-filter-summary { display:none; }" in document
    assert re.search(
        r"@media print\s*\{.*?\.print-filter-summary\s*\{\s*display:block",
        document,
        flags=re.DOTALL,
    )


def test_filter_script_contains_bounded_ranked_suggestions_and_no_persistence() -> None:
    script = _inline_scripts(render_html_report(_snapshot()))[0]

    assert re.search(r"(?:const|let)\s+SUGGESTION_LIMIT\s*=\s*12\s*;", script)
    assert ".startsWith(" in script
    assert ".includes(" in script
    assert "localeCompare(" in script or "Intl.Collator" in script
    for label in ("출발지", "목적지", "양쪽", "추천 목록에서 값을 선택하세요"):
        assert label in script
    for key_name in ("ArrowDown", "ArrowUp", "Enter", "Escape"):
        assert key_name in script
    assert 'setAttribute("role", "option")' in script or "setAttribute('role', 'option')" in script
    assert "aria-activedescendant" in script
    assert "aria-selected" in script
    assert 'list.addEventListener("pointerdown"' in script
    assert 'list.addEventListener("click"' in script
    assert 'event.pointerType === "mouse"' in script
    assert "setTimeout(" in script
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "fetch(",
        "XMLHttpRequest",
        "WebSocket",
        "navigator.clipboard",
        "eval(",
    ):
        assert forbidden not in script

    candidate_values = re.search(
        r"const candidateValues = \(kind\) => \{(?P<body>.*?)\n  \};",
        script,
        flags=re.DOTALL,
    )
    assert candidate_values is not None
    assert "historyRecords" not in candidate_values.group("body")
    assert "indexes[kind].values()" in candidate_values.group("body")
    assert "historyRecords.forEach((record, rowId)" in script
    assert "eligibleRowsForOtherFilters" in script
    assert "touch-action:pan-y" in render_html_report(_snapshot())


def test_public_html_report_interfaces_remain_compatible() -> None:
    assert tuple(signature(render_html_report).parameters) == ("snapshot",)
    assert tuple(signature(write_html_report_atomic).parameters) == ("destination", "snapshot")
    assert "observation_history" in RunReportSnapshot.__dataclass_fields__


def test_history_disclosure_keeps_screen_collapsed_but_prints_outside_details() -> None:
    document = render_html_report(_snapshot())
    history = _section(document, "observation-history")

    assert re.search(
        r'<details class="history-toggle">\s*'
        r'<summary\b[^>]*\baria-controls="observation-history-body"[^>]*>.*?</summary>\s*'
        r"</details>\s*"
        r'<div class="details-body" id="observation-history-body">',
        history,
        flags=re.DOTALL,
    )
    details = re.search(
        r'<details class="history-toggle">(?P<body>.*?)</details>',
        history,
        flags=re.DOTALL,
    )
    assert details is not None
    assert '<div class="details-body" id="observation-history-body">' not in details.group("body")
    assert ".history-toggle:not([open]) + .details-body { display:none; }" in document
    assert ".history-toggle[open] + .details-body { display:block; }" in document
    assert (
        ".history-toggle { display:none; } "
        ".history-toggle + .details-body { display:block !important; }"
    ) in document
    assert "section { border:0; border-radius:0; padding:0; }" in document
    assert "details:not([open]) > .details-body" not in document

    for removed_text in (
        "Executive Summary",
        "프로그램 조회 흐름",
        "수명주기와 Controller 전환",
        "Troubleshooting",
        "CLI와 Quick Reference",
        "Warning / 주의사항",
        "SESSION_NOT_FOUND",
        "보고서에 표시하면 안 되는 진단 메시지",
        "RAW-BODY-MUST-NOT-BE-RENDERED",
        "must-not-be-rendered.txt",
        "MM-주장비",
        "DB ID",
        "show datapath session table",
        "세션별 수치 변화",
        "패킷",
        "바이트",
    ):
        assert removed_text not in document


def test_report_renders_kst_with_utc_date_rollover_and_missing_values_as_dash() -> None:
    document = render_html_report(
        _snapshot(
            run={
                "id": "not-rendered",
                "started_at": "2026-08-28T16:00:00.000Z",
                "ended_at": "2026-08-28T16:05:00+00:00",
                "source_ip": None,
                "destination_ip": "",
                "source_port": None,
                "destination_port": "",
                "bidirectional": 0,
                "status": "PARTIAL",
            },
            observations=(),
            observation_history=(),
            lifecycle_events=(),
            observation_total=0,
        )
    )

    assert "2026-08-29 01:00:00 KST" in document
    assert "2026-08-29 01:05:00 KST" in document
    assert "2026-08-28T16:00:00.000Z" not in document
    assert "2026-08-28T16:05:00+00:00" not in document
    assert '<div class="label">수집 상태</div><span class="value">일부 수집</span>' in document
    assert '<div class="label">출발지 IP</div><span class="value">-</span>' in document
    assert '<div class="label">목적지 포트</div><span class="value">-</span>' in document
    assert "PARTIAL" not in document


def test_lifecycle_statuses_are_korean_and_diagnostics_do_not_change_status() -> None:
    rows = tuple(
        _observation(
            destination_port=port,
            source_port=52000 + index,
            controller_host=f"198.51.100.{21 + index}",
        )
        for index, port in enumerate((443, 8443, 9443, 10443))
    )
    lifecycle = (
        {
            "occurred_at": "2026-08-28T08:04:00.000Z",
            "session_key": rows[0]["session_key"],
            "event_type": "CLOSED",
        },
        {
            "occurred_at": "2026-08-28T08:03:00.000Z",
            "session_key": rows[1]["session_key"],
            "event_type": "MISSED",
        },
        {
            "occurred_at": "2026-08-28T08:02:00.000Z",
            "session_key": rows[2]["session_key"],
            "event_type": "STARTED",
        },
    )
    document = render_html_report(
        _snapshot(
            observations=rows,
            observation_history=rows,
            lifecycle_events=lifecycle,
            diagnostics=(
                {
                    "occurred_at": "2026-08-28T08:05:00.000Z",
                    "stage": "MD_QUERY",
                    "code": "MD_UNREACHABLE",
                    "message": "transient communication failure",
                },
            ),
        )
    )
    latest = _section(document, "latest-sessions")

    assert latest.count(">종료 확인<") == 1
    assert latest.count(">잠시 미확인<") == 1
    assert latest.count(">확인됨<") == 1
    assert latest.count(">관측됨<") == 1
    assert set(re.findall(r'<span class="badge[^">]*">([^<]+)</span>', latest)) == {
        "확인됨",
        "잠시 미확인",
        "종료 확인",
        "관측됨",
    }
    history = _section(document, "observation-history")
    assert history.count(">관측됨<") == 4
    assert ">종료 확인<" not in history
    assert ">잠시 미확인<" not in history
    assert "MD_UNREACHABLE" not in document
    assert "transient communication failure" not in document


def test_report_uses_static_protocol_labels_without_guessing_unknown_values() -> None:
    gre = _observation(protocol=47, source_port=0, destination_port=0)
    unknown = _observation(protocol=253, source_port=1, destination_port=1)

    document = render_html_report(
        _snapshot(
            observations=(gre, unknown),
            observation_history=(gre, unknown),
            lifecycle_events=(),
            observation_total=2,
        )
    )

    assert "GRE (47)" in document
    assert "Protocol 253" in document


def test_latest_lifecycle_event_wins_and_equal_times_keep_database_order() -> None:
    observation = _observation()
    reopened = render_html_report(
        _snapshot(
            lifecycle_events=(
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": "STARTED",
                },
                {
                    "occurred_at": "2026-08-28T08:02:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": "CLOSED",
                },
            )
        )
    )
    tied = render_html_report(
        _snapshot(
            lifecycle_events=(
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": "MISSED",
                },
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": "COUNTERS_CHANGED",
                },
            )
        )
    )

    reopened_latest = _section(reopened, "latest-sessions")
    tied_latest = _section(tied, "latest-sessions")
    assert ">확인됨<" in reopened_latest
    assert ">종료 확인<" not in reopened_latest
    assert ">잠시 미확인<" in tied_latest
    assert ">확인됨<" not in tied_latest


def test_unknown_lifecycle_event_falls_back_to_observed() -> None:
    observation = _observation()
    document = render_html_report(
        _snapshot(
            lifecycle_events=(
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": "FUTURE_EVENT",
                },
            )
        )
    )

    latest = _section(document, "latest-sessions")
    assert ">관측됨<" in latest
    assert ">상태 확인 필요<" not in latest


@pytest.mark.parametrize(
    ("recognized_event", "expected_status"),
    (
        ("CLOSED", "종료 확인"),
        ("MISSED", "잠시 미확인"),
        ("STARTED", "확인됨"),
    ),
)
def test_newer_unknown_event_does_not_override_recognized_lifecycle_status(
    recognized_event: str,
    expected_status: str,
) -> None:
    observation = _observation()
    document = render_html_report(
        _snapshot(
            lifecycle_events=(
                {
                    "occurred_at": "2026-08-28T08:04:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": "FUTURE_EVENT",
                },
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": recognized_event,
                },
            )
        )
    )

    latest = _section(document, "latest-sessions")
    assert f">{expected_status}<" in latest
    assert ">상태 확인 필요<" not in latest


@pytest.mark.parametrize(
    "event_type",
    (
        "STARTED",
        "OPENED",
        "OBSERVED",
        "CONTROLLER_CHANGED",
        "FLAGS_CHANGED",
        "COUNTERS_CHANGED",
    ),
)
def test_positive_lifecycle_events_are_presented_as_confirmed(event_type: str) -> None:
    observation = _observation()
    document = render_html_report(
        _snapshot(
            lifecycle_events=(
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": observation["session_key"],
                    "event_type": event_type,
                },
            )
        )
    )

    latest = _section(document, "latest-sessions")
    assert ">확인됨<" in latest


def test_controller_move_is_one_logical_flow_and_latest_result_uses_last_device() -> None:
    first = _observation(
        observed_at="2026-08-28T08:01:00.000Z",
        controller_name="MD-A",
        controller_host="198.51.100.21",
        packets=1_000,
        bytes_count=2_048,
    )
    last = _observation(
        observed_at="2026-08-28T08:03:00.000Z",
        controller_name="MD-B",
        controller_host="198.51.100.22",
        packets=1_250,
        bytes_count=4_096,
    )
    lifecycle = (
        {
            "occurred_at": "2026-08-28T08:03:00.000Z",
            "session_key": last["session_key"],
            "event_type": "CONTROLLER_CHANGED",
        },
        {
            "occurred_at": "2026-08-28T08:01:00.000Z",
            "session_key": first["session_key"],
            "event_type": "STARTED",
        },
    )
    document = render_html_report(
        _snapshot(
            observations=(last, first),
            observation_history=(first, last),
            lifecycle_events=lifecycle,
            observation_total=2,
        )
    )

    latest_rows = _table_body(_section(document, "latest-sessions"))
    history_rows = _table_body(_section(document, "observation-history"))
    assert len(_report_rows(latest_rows)) == 1
    assert len(_report_rows(history_rows)) == 2
    assert '<div class="label">고유 세션</div><span class="value">1개</span>' in document
    assert "MD-B" in latest_rows
    assert "MD-A" not in latest_rows
    assert "MD-A" in history_rows
    assert "MD-B" in history_rows


def test_packet_and_byte_values_are_intentionally_omitted_from_html() -> None:
    first = _observation(packets=987_654_321, bytes_count=123_456_789)
    last = _observation(
        observed_at="2026-08-28T08:02:00.000Z",
        packets=987_654_322,
        bytes_count=123_456_790,
    )
    document = render_html_report(
        _snapshot(
            observations=(last,),
            observation_history=(first, last),
            lifecycle_events=(),
        )
    )

    assert "192.0.2.100:53000" in document
    assert "TCP (6)" in document
    assert "203.0.113.80:443" in document
    for omitted in (
        "세션별 수치 변화",
        "패킷",
        "바이트",
        "987,654,321",
        "987,654,322",
        "123,456,789",
        "123,456,790",
        "987654321",
        "987654322",
        "123456789",
        "123456790",
    ):
        assert omitted not in document


def test_zero_ports_keep_lifecycle_status_and_controller_move_in_one_flow() -> None:
    first = _observation(
        controller_name="MD-A",
        controller_host="198.51.100.21",
        protocol=1,
        source_port=0,
        destination_port=0,
    )
    last = _observation(
        observed_at="2026-08-28T08:02:00.000Z",
        controller_name="MD-B",
        controller_host="198.51.100.22",
        protocol=1,
        source_port=0,
        destination_port=0,
    )
    document = render_html_report(
        _snapshot(
            observations=(last, first),
            observation_history=(first, last),
            lifecycle_events=(
                {
                    "occurred_at": "2026-08-28T08:03:00.000Z",
                    "session_key": last["session_key"],
                    "event_type": "CLOSED",
                },
            ),
        )
    )

    latest = _section(document, "latest-sessions")
    assert len(_report_rows(_table_body(latest))) == 1
    assert ">종료 확인<" in latest
    assert "MD-B" in latest
    assert "ICMP (1)" in latest
    assert "192.0.2.100:0" in latest
    assert "203.0.113.80:0" in latest


@pytest.mark.parametrize(
    ("stored_status", "displayed_status"),
    (("CANCELLED", "사용자 취소"), ("RESTARTED", "조건 변경 종료")),
)
def test_run_status_uses_precise_korean_label(
    stored_status: str,
    displayed_status: str,
) -> None:
    snapshot = _snapshot()
    run = dict(snapshot.run)
    run["status"] = stored_status
    document = render_html_report(
        _snapshot(run=run, observations=(), observation_history=(), lifecycle_events=())
    )

    assert displayed_status in document
    assert stored_status not in document


def test_naive_or_invalid_times_are_not_assumed_to_be_utc() -> None:
    document = render_html_report(
        _snapshot(
            run={
                "started_at": "2026-08-28T08:00:00",
                "ended_at": "not-a-time",
                "source_ip": "192.0.2.100",
                "destination_ip": "203.0.113.80",
                "source_port": 53000,
                "destination_port": 443,
                "bidirectional": 1,
                "status": "COMPLETED",
            },
            observations=(),
            observation_history=(),
            lifecycle_events=(),
        )
    )

    assert document.count('<span class="value">-</span>') >= 2
    assert "2026-08-28 17:00:00 KST" not in document


def test_only_latest_table_is_limited_to_fifty_logical_flows() -> None:
    rows = tuple(
        _observation(
            observed_at=f"2026-08-28T08:{index:02d}:00.000Z",
            source_port=53000 + index,
            destination_port=10000 + index,
        )
        for index in range(55)
    )
    document = render_html_report(
        _snapshot(
            observations=tuple(reversed(rows)),
            observation_history=rows,
            lifecycle_events=(),
            observation_total=55,
        )
    )

    latest = _section(document, "latest-sessions")
    history = _section(document, "observation-history")
    assert len(_report_rows(_table_body(latest))) == 50
    assert len(_report_rows(_table_body(history))) == 55
    assert "고유 세션 55개 중 마지막 확인 시각을 기준으로 최근 50개" in latest
    assert "192.0.2.100:53000" not in _table_body(latest)
    assert "192.0.2.100:53000" in _table_body(history)


def test_full_history_preserves_all_2005_rows_beyond_ui_limit() -> None:
    history = tuple(
        _observation(
            observed_at=f"2026-08-28T08:01:{index % 60:02d}.000Z",
            packets=index,
            bytes_count=index * 128,
        )
        for index in range(2_005)
    )
    document = render_html_report(
        _snapshot(
            observations=(history[-1],),
            observation_history=history,
            lifecycle_events=(),
            observation_total=2_005,
        )
    )
    history_section = _section(document, "observation-history")

    assert len(_report_rows(_table_body(history_section))) == 2_005
    assert "전체 추적 이력 2,005/2,005건 보기" in history_section


def test_report_escapes_result_values_and_excludes_all_internal_evidence() -> None:
    script_payload = '<script data-x="stored">alert(1)</script>'
    attribute_payload = '" autofocus onfocus="alert(2)'
    observation = _observation(controller_name=script_payload)
    snapshot = _snapshot(
        run={
            "id": "SECRET-RUN-ID",
            "started_at": "2026-08-28T08:00:00.000Z",
            "ended_at": "2026-08-28T08:05:00.000Z",
            "source_ip": attribute_payload,
            "destination_ip": "203.0.113.80",
            "source_port": 53000,
            "destination_port": 443,
            "bidirectional": 1,
            "status": "COMPLETED",
        },
        observations=(observation,),
        observation_history=(observation,),
        lifecycle_events=(
            {
                "occurred_at": "2026-08-28T08:01:00.000Z",
                "session_key": observation["session_key"],
                "event_type": "STARTED",
                "instance_id": "SECRET-INSTANCE",
                "details_json": '{"password":"SECRET-LIFECYCLE"}',
            },
        ),
        diagnostics=(
            {
                "occurred_at": "2026-08-28T08:03:00.000Z",
                "stage": "ssh 198.18.0.99",
                "code": "AUTH_FAILED",
                "message": "username=operator password=SECRET-DIAGNOSTIC",
            },
        ),
    )
    document = render_html_report(snapshot)

    assert script_payload not in document
    assert attribute_payload not in document
    assert "&lt;script data-x=&quot;stored&quot;&gt;alert(1)&lt;/script&gt;" in document
    assert "&quot; autofocus onfocus=&quot;alert(2)" in document
    for secret in (
        "SECRET-RUN-ID",
        "SECRET-INSTANCE",
        "SECRET-LIFECYCLE",
        "AUTH_FAILED",
        "SECRET-DIAGNOSTIC",
        "operator",
        "198.18.0.99",
        "RAW-BODY-MUST-NOT-BE-RENDERED",
        "must-not-be-rendered.txt",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "CURRENT_SWITCH_CHANGED",
    ):
        assert secret not in document


def test_empty_result_has_clear_rows_and_no_false_session_state() -> None:
    document = render_html_report(
        _snapshot(
            observations=(),
            observation_history=(),
            lifecycle_events=(),
            diagnostics=(),
            observation_total=0,
        )
    )

    assert "관측된 세션이 없습니다." in document
    assert "저장된 관측 이력이 없습니다." in document
    assert "종료 확인" not in document
    assert "고유 세션 0개를 모두 표시합니다." in document
    assert len(_report_rows(document)) == 0
    assert document.count('class="filter-empty-row" hidden') == 2
    assert document.count("선택한 필터와 일치하는 세션이 없습니다.") == 2


def test_initial_filter_counts_distinguish_latest_limit_from_complete_history() -> None:
    rows = tuple(
        _observation(
            observed_at=f"2026-08-28T08:{index:02d}:00.000Z",
            source_ip=f"192.0.2.{index + 1}",
            destination_ip="203.0.113.80",
            source_port=53000 + index,
            destination_port=443 if index % 2 == 0 else 8443,
        )
        for index in range(55)
    )
    document = render_html_report(
        _snapshot(
            observations=tuple(reversed(rows)),
            observation_history=rows,
            lifecycle_events=(),
            observation_total=55,
        )
    )

    latest_count = re.search(
        r'<span\b[^>]*\bid="latest-filter-count"[^>]*>(?P<value>.*?)</span>',
        document,
        flags=re.DOTALL,
    )
    history_count = re.search(
        r'<span\b[^>]*\bid="history-filter-count"[^>]*>(?P<value>.*?)</span>',
        document,
        flags=re.DOTALL,
    )
    assert latest_count is not None
    assert history_count is not None
    assert latest_count.group("value").strip() == "최신 50/50건"
    assert history_count.group("value").strip() == "전체 55/55건"
    assert "전체 추적 이력 55/55건 보기" in document
    script = _inline_scripts(document)[0]
    latest_visible = "${integerFormat.format(latestVisible)}"
    latest_total = "${integerFormat.format(latestRecords.length)}"
    history_visible = "${integerFormat.format(historyVisible)}"
    history_total = "${integerFormat.format(historyRecords.length)}"
    assert f"최신 {latest_visible}/{latest_total}건" in script
    assert f"전체 {history_visible}/{history_total}건" in script
    assert f"전체 추적 이력 {history_visible}/{history_total}건 보기" in script


def test_render_and_atomic_writes_are_deterministic(tmp_path: Path) -> None:
    snapshot = _snapshot()
    first_render = render_html_report(snapshot)
    second_render = render_html_report(snapshot)
    first_path = tmp_path / "첫 번째 결과.html"
    second_path = tmp_path / "두 번째 결과.html"

    assert first_render == second_render
    assert write_html_report_atomic(first_path, snapshot) == first_path
    assert write_html_report_atomic(second_path, snapshot) == second_path
    assert first_path.read_bytes() == second_path.read_bytes()
    assert first_path.read_text(encoding="utf-8") == first_render
    assert not tuple(tmp_path.glob(".*.tmp"))


def test_atomic_replace_failure_preserves_destination_and_cleans_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "report.html"
    destination.write_text("previous report", encoding="utf-8")

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("replace blocked")

    monkeypatch.setattr(html_report.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace blocked"):
        write_html_report_atomic(destination, _snapshot())

    assert destination.read_text(encoding="utf-8") == "previous report"
    assert not tuple(tmp_path.glob(".report.html.*.tmp"))
