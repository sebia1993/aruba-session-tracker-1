from __future__ import annotations

import re
from pathlib import Path

import pytest

from aruba_session_tracker.storage import (
    RunReportSnapshot,
    html_report,
    render_html_report,
    write_html_report_atomic,
)


def _snapshot(
    *,
    run: dict[str, object] | None = None,
    observations: tuple[dict[str, object], ...] | None = None,
    diagnostics: tuple[dict[str, object], ...] | None = None,
    observation_total: int | None = None,
    unique_session_total: int | None = None,
    lifecycle_total: int | None = None,
    controller_total: int | None = None,
    diagnostic_total: int | None = None,
    raw_file_total: int | None = None,
) -> RunReportSnapshot:
    run_row = run or {
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
    observation_rows = observations or (
        {
            "observed_at": "2026-08-28T08:01:00.000Z",
            "controller_name": "서울-MD-01",
            "controller_host": "198.51.100.21",
            "protocol": 6,
            "source_ip": "192.0.2.100",
            "destination_ip": "203.0.113.80",
            "source_port": 53000,
            "destination_port": 443,
            "packets": 12,
            "bytes_count": 2048,
            "age": 2,
            "flags": "DY",
            "cpu_id": 1,
            "session_key": "stable-session-key",
        },
    )
    lifecycle_rows = (
        {
            "occurred_at": "2026-08-28T08:01:00.000Z",
            "session_key": "stable-session-key",
            "instance_id": "instance-001",
            "event_type": "OPENED",
            "controller_name": "서울-MD-01",
            "details_json": '{"miss_count": 0, "previous_flags": "F"}',
        },
    )
    controller_rows = (
        {
            "occurred_at": "2026-08-28T08:02:00.000Z",
            "previous_controller": "서울-MD-01",
            "current_controller": "서울-MD-02",
            "reason": "CURRENT_SWITCH_CHANGED",
        },
    )
    diagnostic_rows = diagnostics or (
        {
            "occurred_at": "2026-08-28T08:03:00.000Z",
            "stage": "md-query",
            "code": "SESSION_NOT_FOUND",
            "message": "다음 조회에서 다시 확인하십시오.",
        },
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
        {
            "id": 42,
            "captured_at": "2026-08-28T08:01:00.000Z",
            "kind": "session",
            "controller_name": "서울-MD-01",
            "sha256": "b" * 64,
            "byte_size": 2048,
        },
    )
    return RunReportSnapshot(
        run=run_row,
        controllers=("MM-주장비", "서울-MD-01", "서울-MD-02"),
        mm_controllers=("MM-주장비",),
        md_controllers=("서울-MD-01", "서울-MD-02"),
        observations=observation_rows,
        observation_total=(
            len(observation_rows) if observation_total is None else observation_total
        ),
        unique_session_total=(
            len(observation_rows) if unique_session_total is None else unique_session_total
        ),
        lifecycle_events=lifecycle_rows,
        lifecycle_total=(len(lifecycle_rows) if lifecycle_total is None else lifecycle_total),
        lifecycle_counts=(("OPENED", 1),),
        controller_events=controller_rows,
        controller_total=(len(controller_rows) if controller_total is None else controller_total),
        diagnostics=diagnostic_rows,
        diagnostic_total=(len(diagnostic_rows) if diagnostic_total is None else diagnostic_total),
        raw_files=raw_rows,
        raw_file_total=(len(raw_rows) if raw_file_total is None else raw_file_total),
        raw_byte_total=3072,
    )


def test_report_is_standalone_offline_html5_with_korean_sections_and_csp() -> None:
    document = render_html_report(_snapshot())
    lowered = document.casefold()

    assert document.startswith('<!doctype html>\n<html lang="ko">')
    assert '<meta charset="utf-8">' in lowered
    assert '<meta name="viewport"' in lowered
    assert "Content-Security-Policy" in document
    assert "default-src 'none'" in document
    assert "style-src 'unsafe-inline'" in document
    assert "<style>" in lowered
    assert "@media (max-width:850px)" in document
    assert "@page { size:A4 landscape" in document
    assert "@media print" in document
    assert "<script" not in lowered
    assert "<link" not in lowered
    assert "http://" not in lowered
    assert "https://" not in lowered
    assert not re.search(r"\b(?:src|href)=[\"'](?:https?:)?//", lowered)

    for heading in (
        "Executive Summary",
        "환경정보와 조회 조건",
        "프로그램 조회 흐름",
        "세션 결과와 Flags",
        "수명주기와 Controller 전환",
        "확인 및 검증 결과",
        "수집 증거",
        "Troubleshooting",
        "CLI와 Quick Reference",
        "Warning / 주의사항",
    ):
        assert heading in document
    assert "서울-MD-01" in document
    assert '<div class="label">Controller</div><div class="metric">3</div>' in document
    assert "차단" in document
    assert "SYN 없음" in document
    assert '<caption class="sr-only">최신 고유 세션</caption>' in document
    assert '<th scope="col">마지막 관측</th>' in document
    assert 'role="region" aria-label="최신 고유 세션 표" tabindex="0"' in document
    assert "DB ID" in document
    assert ">41<" in document


def test_report_warns_when_the_stored_run_time_range_is_reversed() -> None:
    document = render_html_report(
        _snapshot(
            run={
                "id": "run-reversed-time",
                "started_at": "2026-08-28T09:05:00.000Z",
                "ended_at": "2026-08-28T09:00:00.000Z",
                "source_ip": "192.0.2.100",
                "destination_ip": "203.0.113.80",
                "source_port": 53000,
                "destination_port": 443,
                "bidirectional": 1,
                "status": "COMPLETED",
            }
        )
    )

    assert "시간 범위 확인 필요" in document
    assert "종료 시각이 시작 시각보다 빠릅니다." in document


def test_report_escapes_stored_values_and_remasks_diagnostics() -> None:
    script_payload = '<script data-x="stored">alert(1)</script>'
    attribute_payload = '" autofocus onfocus="alert(2)'
    snapshot = _snapshot(
        run={
            "id": script_payload,
            "started_at": "2026-08-28T08:00:00.000Z",
            "ended_at": "2026-08-28T08:05:00.000Z",
            "source_ip": attribute_payload,
            "destination_ip": "203.0.113.80",
            "source_port": 53000,
            "destination_port": 443,
            "bidirectional": 1,
            "status": "COMPLETED",
        },
        observations=(
            {
                "observed_at": "2026-08-28T08:01:00.000Z",
                "controller_name": script_payload,
                "controller_host": "198.51.100.21",
                "protocol": 6,
                "source_ip": "192.0.2.100",
                "destination_ip": "203.0.113.80",
                "source_port": 53000,
                "destination_port": 443,
                "packets": 12,
                "bytes_count": 2048,
                "age": 2,
                "flags": "DY",
                "cpu_id": 1,
                "session_key": "stable-session-key",
            },
        ),
        diagnostics=(
            {
                "occurred_at": "2026-08-28T08:03:00.000Z",
                "stage": "ssh 198.18.0.99",
                "code": "AUTH_FAILED",
                "message": "username=operator password=not-for-report at 198.18.0.99 "
                + script_payload,
            },
        ),
    )

    document = render_html_report(snapshot)

    assert script_payload not in document
    assert attribute_payload not in document
    assert "&lt;script data-x=&quot;stored&quot;&gt;alert(1)&lt;/script&gt;" in document
    assert "&quot; autofocus onfocus=&quot;alert(2)" in document
    assert "198.18.0.99" not in document
    assert "not-for-report" not in document
    assert "operator" not in document
    assert "username=&lt;REDACTED&gt;" in document
    assert "password=&lt;REDACTED&gt;" in document


def test_report_excludes_raw_body_and_paths_and_marks_truncated_sections() -> None:
    document = render_html_report(
        _snapshot(
            observation_total=9,
            unique_session_total=5,
            lifecycle_total=7,
            controller_total=4,
            diagnostic_total=6,
            raw_file_total=8,
        )
    )

    assert "RAW-BODY-MUST-NOT-BE-RENDERED" not in document
    assert "must-not-be-rendered.txt" not in document
    assert "Raw CLI 본문과 파일 경로는 보고서에 포함하지 않습니다." in document
    assert "최신 고유 세션 전체 5건 중 최근 1건 표시" in document
    assert "수명주기 이벤트 전체 7건 중 최근 1건 표시" in document
    assert "Controller 전환 전체 4건 중 최근 1건 표시" in document
    assert "진단 이벤트 전체 6건 중 최근 1건 표시" in document
    assert "Raw 파일 전체 8건 중 최근 2건 표시" in document
    assert "전체 데이터는 CSV 또는 SQLite를 확인하십시오." in document


def test_render_and_atomic_writes_are_deterministic(tmp_path: Path) -> None:
    snapshot = _snapshot()
    first_render = render_html_report(snapshot)
    second_render = render_html_report(snapshot)
    first_path = tmp_path / "first.html"
    second_path = tmp_path / "second.html"

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
