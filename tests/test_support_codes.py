from __future__ import annotations

import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aruba_session_tracker.models import DiagnosticEvent, ErrorCode, QueryRequest
from aruba_session_tracker.storage import SessionStore
from aruba_session_tracker.support_codes import (
    DIAGNOSTIC_SUPPORT_CODES,
    RESERVED_SUPPORT_CODES,
    UI_FAILURE_SUPPORT_CODES,
    SupportCode,
    UiFailureKey,
    support_code_for,
    support_code_for_ui_failure,
)


def test_support_code_registry_is_fixed_form_immutable_and_respects_ranges() -> None:
    assert support_code_for("unknown", ErrorCode.AUTH_FAILED) is SupportCode.AS00
    assert support_code_for("MD_LOGIN", None) is SupportCode.AS00
    assert support_code_for("MD_LOGIN", "not-a-code") is SupportCode.AS00
    assert support_code_for_ui_failure("not-a-key") is SupportCode.AS00

    assigned = {item.value for item in DIAGNOSTIC_SUPPORT_CODES.values()}
    assigned.update(item.value for item in UI_FAILURE_SUPPORT_CODES.values())
    assigned.add(SupportCode.AS00.value)
    assert all(re.fullmatch(r"AS\d{2}", value) for value in assigned)
    assert not assigned.intersection(RESERVED_SUPPORT_CODES)
    assert {f"AS{number:02d}" for number in range(90, 100)} == RESERVED_SUPPORT_CODES

    for (stage, _error_code), support_code in DIAGNOSTIC_SUPPORT_CODES.items():
        number = int(support_code.value[2:])
        if stage.startswith("MM_"):
            assert 1 <= number <= 19
        elif stage.startswith("MD_"):
            assert 20 <= number <= 59
        elif stage.startswith("MONITOR_"):
            assert 60 <= number <= 69
        else:  # pragma: no cover - a new area must make the policy explicit
            pytest.fail(f"unclassified diagnostic stage: {stage}")

    with pytest.raises(TypeError):
        DIAGNOSTIC_SUPPORT_CODES[("MM_QUERY", "NEW_CODE")] = SupportCode.AS01  # type: ignore[index]


def test_current_diagnostic_pairs_have_stable_codes() -> None:
    expected = {
        ("MM_LOGIN", ErrorCode.AUTH_FAILED): SupportCode.AS01,
        ("MM_QUERY", ErrorCode.AUTH_FAILED): SupportCode.AS01,
        ("MM_QUERY", ErrorCode.MM_UNREACHABLE): SupportCode.AS02,
        ("MM_PARSE", ErrorCode.PARSE_PARTIAL): SupportCode.AS12,
        ("MM_PARSE", ErrorCode.CURRENT_SWITCH_AMBIGUOUS): SupportCode.AS16,
        ("MM_ENABLE", ErrorCode.AUTH_FAILED): SupportCode.AS17,
        ("MD_LOGIN", ErrorCode.AUTH_FAILED): SupportCode.AS20,
        ("MD_QUERY", ErrorCode.AUTH_FAILED): SupportCode.AS20,
        ("MD_ENABLE", ErrorCode.AUTH_FAILED): SupportCode.AS21,
        ("MD_QUERY", ErrorCode.MD_UNREACHABLE): SupportCode.AS22,
        ("MD_PARSE", ErrorCode.PARSE_PARTIAL): SupportCode.AS32,
        ("MD_FILTER", ErrorCode.SESSION_NOT_FOUND): SupportCode.AS36,
        ("MD_ROUTE", ErrorCode.CURRENT_SWITCH_AMBIGUOUS): SupportCode.AS37,
        ("MD_ROUTE", ErrorCode.CURRENT_SWITCH_UNMAPPED): SupportCode.AS38,
        ("MD_SCAN", ErrorCode.CLIENT_NOT_FOUND_ON_MM): SupportCode.AS39,
        ("MONITOR_STATE", ErrorCode.OUTPUT_LIMIT_EXCEEDED): SupportCode.AS60,
        (
            "MONITOR_STATE",
            ErrorCode.DUPLICATE_FLOW_ACROSS_CONTROLLERS,
        ): SupportCode.AS61,
    }
    for pair, expected_code in expected.items():
        assert support_code_for(*pair) is expected_code


def test_ui_failure_keys_are_explicit_and_do_not_parse_messages() -> None:
    assert support_code_for_ui_failure(UiFailureKey.QUERY_AUTH_FAILED) is SupportCode.AS20
    assert support_code_for_ui_failure(UiFailureKey.QUERY_DB_WRITE_FAILED) is SupportCode.AS70
    assert support_code_for_ui_failure(UiFailureKey.QUERY_STORAGE_LOW_SPACE) is SupportCode.AS71
    assert support_code_for_ui_failure(UiFailureKey.HISTORY_READ_FAILED) is SupportCode.AS73
    assert support_code_for_ui_failure(UiFailureKey.EXPORT_CSV_FAILED) is SupportCode.AS74
    assert support_code_for_ui_failure(UiFailureKey.CONFIG_READ_FAILED) is SupportCode.AS84
    assert support_code_for_ui_failure(UiFailureKey.CONFIG_SAVE_FAILED) is SupportCode.AS85
    assert support_code_for_ui_failure("password=secret AUTH_FAILED") is SupportCode.AS00


def test_list_runs_returns_latest_mappable_diagnostic_without_schema_change(
    tmp_path: Path,
) -> None:
    store = SessionStore(tmp_path / "tracker.db", tmp_path / "raw", tmp_path / "exports")
    store.initialize()
    base_time = datetime(2026, 9, 1, 1, 0, tzinfo=UTC)
    empty_run = store.start_run(
        QueryRequest("192.0.2.10", ""),
        run_id="empty-run",
        started_at=base_time,
    )
    mapped_run = store.start_run(
        QueryRequest("", "203.0.113.20"),
        run_id="mapped-run",
        started_at=base_time + timedelta(seconds=1),
    )

    store.record_diagnostic(
        DiagnosticEvent(
            stage="MM_QUERY",
            code=ErrorCode.AUTH_FAILED,
            message="older mapped event",
            occurred_at=base_time + timedelta(seconds=2),
        ),
        run_id=mapped_run,
    )
    tied_time = base_time + timedelta(seconds=3)
    store.record_diagnostic(
        DiagnosticEvent(
            stage="MD_LOGIN",
            code=ErrorCode.AUTH_FAILED,
            message="first tied event",
            occurred_at=tied_time,
        ),
        run_id=mapped_run,
    )
    store.record_diagnostic(
        DiagnosticEvent(
            stage="MD_ENABLE",
            code=ErrorCode.AUTH_FAILED,
            message="second tied event",
            occurred_at=tied_time,
        ),
        run_id=mapped_run,
    )
    store.record_diagnostic(
        DiagnosticEvent(
            stage="FUTURE_STAGE",
            code=ErrorCode.AUTH_FAILED,
            message="newer but unmappable event",
            occurred_at=base_time + timedelta(seconds=4),
        ),
        run_id=mapped_run,
    )

    rows = {str(row["id"]): row for row in store.list_runs()}
    assert rows[mapped_run]["latest_diagnostic_stage"] == "MD_ENABLE"
    assert rows[mapped_run]["latest_diagnostic_code"] == ErrorCode.AUTH_FAILED.value
    assert rows[mapped_run]["latest_support_code"] == SupportCode.AS21.value
    assert rows[empty_run]["latest_diagnostic_stage"] is None
    assert rows[empty_run]["latest_diagnostic_code"] is None
    assert rows[empty_run]["latest_support_code"] is None

    with closing(sqlite3.connect(store.db_path)) as connection:
        run_columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(runs)")}
    assert "latest_diagnostic_stage" not in run_columns
    assert "latest_diagnostic_code" not in run_columns
    assert "latest_support_code" not in run_columns

    store.finish_run(mapped_run)
    store.finish_run(empty_run)
