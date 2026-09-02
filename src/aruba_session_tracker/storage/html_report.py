# ruff: noqa: E501
"""Deterministic, offline HTML5 result reports for one stored run."""

from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from html import escape
from pathlib import Path

from aruba_session_tracker.analysis import protocol_label, service_label
from aruba_session_tracker.storage.durable_io import replace_with_retry

ReportRow = dict[str, object]
FlowKey = tuple[str, str, str, str, str]

_KST = timezone(timedelta(hours=9), "KST")
_LATEST_SESSION_LIMIT = 50
_CONFIRMED_EVENTS = {
    "STARTED",
    "OPENED",  # Older databases and imported fixtures may use this legacy name.
    "OBSERVED",
    "CONTROLLER_CHANGED",
    "FLAGS_CHANGED",
    "COUNTERS_CHANGED",
}
_RUN_STATUS_KO = {
    "RUNNING": "수집 중",
    "COMPLETED": "수집 완료",
    "STOPPED": "수집 중지",
    "PARTIAL": "일부 수집",
    "FAILED": "수집 실패",
    "INTERRUPTED": "수집 중단",
    "RESTARTED": "조건 변경 종료",
    "CANCELLED": "사용자 취소",
}
_RUN_STATUS_CLASS = {
    "RUNNING": "running",
    "COMPLETED": "completed",
    "STOPPED": "attention",
    "PARTIAL": "attention",
    "FAILED": "failed",
    "INTERRUPTED": "attention",
    "RESTARTED": "attention",
    "CANCELLED": "neutral",
}


_FILTER_SCRIPT = r"""(() => {
  "use strict";

  const SUGGESTION_LIMIT = 12;
  const INPUT_DELAY_MS = 120;
  const filterRoot = document.getElementById("result-filter");
  const latestBody = document.getElementById("latest-results-body");
  const historyBody = document.getElementById("history-results-body");
  const protocolSelect = document.getElementById("filter-protocol");
  const resetButton = document.getElementById("filter-reset");
  const filterStatus = document.getElementById("filter-status");
  const latestCount = document.getElementById("latest-filter-count");
  const historyCount = document.getElementById("history-filter-count");
  const latestNote = document.getElementById("latest-result-note");
  const historySummary = document.getElementById("history-filter-summary");
  const printSummary = document.getElementById("print-filter-summary");
  const latestEmpty = document.getElementById("latest-filter-empty");
  const historyEmpty = document.getElementById("history-filter-empty");
  if (!filterRoot || !latestBody || !historyBody || !protocolSelect || !resetButton ||
      !filterStatus || !latestCount || !historyCount || !latestNote || !historySummary || !printSummary ||
      !latestEmpty || !historyEmpty) {
    return;
  }

  const naturalOrder = new Intl.Collator("ko-KR", {numeric: true, sensitivity: "base"});
  const integerFormat = new Intl.NumberFormat("ko-KR");
  const normalize = (value) => String(value || "").trim().toLocaleLowerCase("ko-KR");
  const toRecord = (row) => {
    const record = {
      row,
      sourceIp: row.dataset.sourceIp || "",
      destinationIp: row.dataset.destinationIp || "",
      sourcePort: row.dataset.sourcePort || "",
      destinationPort: row.dataset.destinationPort || "",
      protocol: row.dataset.protocol || ""
    };
    record.sourceIpKey = normalize(record.sourceIp);
    record.destinationIpKey = normalize(record.destinationIp);
    record.sourcePortKey = normalize(record.sourcePort);
    record.destinationPortKey = normalize(record.destinationPort);
    record.protocolKey = normalize(record.protocol);
    return record;
  };

  // The DOM is read once. All later matching uses these small record objects.
  const latestRecords = Array.from(latestBody.querySelectorAll("tr.report-row")).map(toRecord);
  const historyRecords = Array.from(historyBody.querySelectorAll("tr.report-row")).map(toRecord);
  const defaultLatestNote = latestNote.textContent;
  const indexes = {ip: new Map(), port: new Map(), protocol: new Map()};
  const addDirectionalIndex = (kind, key, value, direction, rowId) => {
    const cleanValue = String(value || "").trim();
    if (!key || !cleanValue || cleanValue === "-") return;
    let candidate = indexes[kind].get(key);
    if (!candidate) {
      candidate = {value: cleanValue, sourceRows: [], destinationRows: [], rowSet: null};
      indexes[kind].set(key, candidate);
    }
    candidate[direction === "source" ? "sourceRows" : "destinationRows"].push(rowId);
  };
  const addProtocolIndex = (record, rowId) => {
    if (!record.protocolKey || !record.protocol || record.protocol === "-") return;
    let candidate = indexes.protocol.get(record.protocolKey);
    if (!candidate) {
      candidate = {value: record.protocol, rows: [], rowSet: null};
      indexes.protocol.set(record.protocolKey, candidate);
    }
    candidate.rows.push(rowId);
  };
  historyRecords.forEach((record, rowId) => {
    addDirectionalIndex("ip", record.sourceIpKey, record.sourceIp, "source", rowId);
    addDirectionalIndex("ip", record.destinationIpKey, record.destinationIp, "destination", rowId);
    addDirectionalIndex("port", record.sourcePortKey, record.sourcePort, "source", rowId);
    addDirectionalIndex("port", record.destinationPortKey, record.destinationPort, "destination", rowId);
    addProtocolIndex(record, rowId);
  });
  const state = {ip: "", port: "", protocol: ""};
  const controls = {};
  const candidateCache = {ip: null, port: null};
  const invalidateCandidateCaches = () => {
    candidateCache.ip = null;
    candidateCache.port = null;
  };

  const matchesIp = (record, value) => {
    const key = normalize(value);
    return !key || record.sourceIpKey === key || record.destinationIpKey === key;
  };
  const matchesPort = (record, value) => {
    const key = normalize(value);
    return !key || record.sourcePortKey === key || record.destinationPortKey === key;
  };
  const matchesProtocol = (record, value) => {
    const key = normalize(value);
    return !key || record.protocolKey === key;
  };
  const matchesAll = (record) => (
    matchesIp(record, state.ip) &&
    matchesPort(record, state.port) &&
    matchesProtocol(record, state.protocol)
  );
  const announce = (message) => {
    filterStatus.textContent = message;
  };
  const activeDescription = () => {
    const parts = [];
    if (state.ip) parts.push(`IP ${state.ip}`);
    if (state.protocol) parts.push(`프로토콜 ${state.protocol}`);
    if (state.port) parts.push(`포트 ${state.port}`);
    return parts.length ? parts.join(" · ") : "없음 (전체 결과)";
  };

  const applyFilters = (message) => {
    let latestVisible = 0;
    let historyVisible = 0;
    for (const record of latestRecords) {
      const visible = matchesAll(record);
      record.row.hidden = !visible;
      if (visible) latestVisible += 1;
    }
    for (const record of historyRecords) {
      const visible = matchesAll(record);
      record.row.hidden = !visible;
      if (visible) historyVisible += 1;
    }

    latestEmpty.hidden = latestRecords.length === 0 || latestVisible !== 0;
    historyEmpty.hidden = historyRecords.length === 0 || historyVisible !== 0;
    latestCount.textContent = `최신 ${integerFormat.format(latestVisible)}/${integerFormat.format(latestRecords.length)}건`;
    historyCount.textContent = `전체 ${integerFormat.format(historyVisible)}/${integerFormat.format(historyRecords.length)}건`;
    const hasActiveFilters = Boolean(state.ip || state.port || state.protocol);
    latestNote.textContent = hasActiveFilters
      ? (latestVisible === 0
        ? "선택한 조건과 일치하는 최신 세션이 없습니다."
        : `선택한 조건과 일치하는 최신 세션 ${integerFormat.format(latestVisible)}개를 표시합니다.`)
      : defaultLatestNote;
    historySummary.textContent = `전체 추적 이력 ${integerFormat.format(historyVisible)}/${integerFormat.format(historyRecords.length)}건 보기`;
    printSummary.textContent = `적용 필터: ${activeDescription()} · 최신 ${integerFormat.format(latestVisible)}/${integerFormat.format(latestRecords.length)}건 · 전체 ${integerFormat.format(historyVisible)}/${integerFormat.format(historyRecords.length)}건`;

    let importantResult = "";
    if (historyRecords.length === 0) {
      importantResult = "저장된 관측 이력이 없습니다.";
    } else if (historyVisible === 0) {
      importantResult = "선택한 조건과 일치하는 전체 추적 이력이 없습니다.";
    } else if (latestVisible === 0) {
      importantResult = `전체 이력에는 ${integerFormat.format(historyVisible)}건이 있지만 최신 결과에는 없습니다.`;
    }
    if (message && importantResult) {
      announce(`${message} ${importantResult}`);
    } else if (message) {
      announce(message);
    } else if (importantResult) {
      announce(importantResult);
    } else if (state.ip || state.port || state.protocol) {
      announce(`선택한 조건으로 전체 이력 ${integerFormat.format(historyVisible)}건을 표시합니다.`);
    } else {
      announce("IP나 포트의 일부를 입력하면 실제 보고서 값이 추천됩니다.");
    }
  };

  const directionalRowSet = (candidate) => {
    if (candidate.rowSet === null) {
      candidate.rowSet = new Set([...candidate.sourceRows, ...candidate.destinationRows]);
    }
    return candidate.rowSet;
  };
  const protocolRowSet = (candidate) => {
    if (candidate.rowSet === null) candidate.rowSet = new Set(candidate.rows);
    return candidate.rowSet;
  };
  const eligibleRowsForOtherFilters = (kind) => {
    const rowSets = [];
    if (kind === "ip" && state.port) {
      const port = indexes.port.get(normalize(state.port));
      rowSets.push(port ? directionalRowSet(port) : new Set());
    }
    if (kind === "port" && state.ip) {
      const ip = indexes.ip.get(normalize(state.ip));
      rowSets.push(ip ? directionalRowSet(ip) : new Set());
    }
    if (state.protocol) {
      const protocol = indexes.protocol.get(normalize(state.protocol));
      rowSets.push(protocol ? protocolRowSet(protocol) : new Set());
    }
    if (!rowSets.length) return null;
    rowSets.sort((left, right) => left.size - right.size);
    const remainingRowSets = rowSets.slice(1);
    const eligible = new Set();
    for (const rowId of rowSets[0]) {
      if (remainingRowSets.every((rowSet) => rowSet.has(rowId))) eligible.add(rowId);
    }
    return eligible;
  };
  const hasEligibleRow = (rows, eligibleRows) => (
    eligibleRows === null ? rows.length > 0 : rows.some((rowId) => eligibleRows.has(rowId))
  );
  const candidateValues = (kind) => {
    if (candidateCache[kind] !== null) return candidateCache[kind];
    const eligibleRows = eligibleRowsForOtherFilters(kind);
    const found = [];
    for (const candidate of indexes[kind].values()) {
      const source = hasEligibleRow(candidate.sourceRows, eligibleRows);
      const destination = hasEligibleRow(candidate.destinationRows, eligibleRows);
      if (source || destination) found.push({value: candidate.value, source, destination});
    }
    candidateCache[kind] = found;
    return candidateCache[kind];
  };
  const matchRank = (value, query) => {
    if (value === query) return 0;
    if (value.startsWith(query)) return 1;
    if (value.includes(query)) return 2;
    return 3;
  };
  const suggestionsFor = (kind, query) => {
    const queryKey = normalize(query);
    if (!queryKey) return [];
    const matched = [];
    for (const candidate of candidateValues(kind)) {
      const rank = matchRank(normalize(candidate.value), queryKey);
      if (rank < 3) matched.push({...candidate, rank});
    }
    return matched
      .sort((left, right) => left.rank - right.rank || naturalOrder.compare(left.value, right.value))
      .slice(0, SUGGESTION_LIMIT);
  };
  const directionLabel = (candidate) => {
    if (candidate.source && candidate.destination) return "양쪽";
    return candidate.source ? "출발지" : "목적지";
  };

  const closeSuggestions = (control) => {
    if (control.timer) {
      window.clearTimeout(control.timer);
      control.timer = 0;
    }
    control.list.hidden = true;
    control.input.setAttribute("aria-expanded", "false");
    control.input.removeAttribute("aria-activedescendant");
    control.activeIndex = -1;
    control.pointerInteracting = false;
    control.suggestions = [];
    control.options = [];
    control.list.replaceChildren();
  };
  const closeAllSuggestions = () => {
    for (const control of Object.values(controls)) closeSuggestions(control);
  };
  const setActiveOption = (control, index) => {
    if (!control.options.length) return;
    const bounded = (index + control.options.length) % control.options.length;
    control.activeIndex = bounded;
    control.options.forEach((option, optionIndex) => {
      option.setAttribute("aria-selected", optionIndex === bounded ? "true" : "false");
    });
    const active = control.options[bounded];
    control.input.setAttribute("aria-activedescendant", active.id);
    active.scrollIntoView({block: "nearest"});
  };
  const selectCandidate = (control, value) => {
    state[control.kind] = value;
    invalidateCandidateCaches();
    control.input.value = value;
    control.input.dataset.selectedValue = value;
    closeAllSuggestions();
    applyFilters(`${control.label} ${value} 필터를 적용했습니다.`);
  };
  const renderSuggestions = (control) => {
    if (control.timer) {
      window.clearTimeout(control.timer);
      control.timer = 0;
    }
    const query = control.input.value.trim();
    control.suggestions = suggestionsFor(control.kind, query);
    control.options = [];
    control.activeIndex = -1;
    control.input.removeAttribute("aria-activedescendant");
    const fragment = document.createDocumentFragment();
    control.suggestions.forEach((candidate, index) => {
      const option = document.createElement("div");
      const value = document.createElement("span");
      const direction = document.createElement("span");
      option.id = `${control.kind}-suggestion-${index}`;
      option.setAttribute("role", "option");
      option.setAttribute("aria-selected", "false");
      option.dataset.value = candidate.value;
      value.className = "suggestion-value";
      value.textContent = candidate.value;
      direction.className = "suggestion-direction";
      direction.textContent = directionLabel(candidate);
      option.append(value, direction);
      fragment.appendChild(option);
      control.options.push(option);
    });
    control.list.replaceChildren(fragment);
    if (!query || !control.options.length) {
      closeSuggestions(control);
      if (query) announce(`일치하는 ${control.label} 추천값이 없습니다.`);
      return;
    }
    control.list.hidden = false;
    control.input.setAttribute("aria-expanded", "true");
  };
  const scheduleSuggestions = (control) => {
    if (control.timer) window.clearTimeout(control.timer);
    control.timer = window.setTimeout(() => {
      control.timer = 0;
      renderSuggestions(control);
    }, INPUT_DELAY_MS);
  };

  const makeCombobox = (kind, label) => {
    const input = document.getElementById(`filter-${kind}`);
    const list = document.getElementById(`filter-${kind}-list`);
    if (!input || !list) return null;
    const control = {
      kind, label, input, list, suggestions: [], options: [], activeIndex: -1,
      timer: 0, pointerInteracting: false
    };
    controls[kind] = control;
    input.addEventListener("input", () => {
      // Never let a delayed recommendation from the previous input be selected.
      closeSuggestions(control);
      const selectionChanged = Boolean(state[kind] && input.value !== state[kind]);
      if (selectionChanged) {
        state[kind] = "";
        invalidateCandidateCaches();
        delete input.dataset.selectedValue;
      }
      if (!input.value.trim()) {
        delete input.dataset.selectedValue;
        if (selectionChanged) applyFilters();
        return;
      }
      if (selectionChanged) applyFilters();
      scheduleSuggestions(control);
    });
    input.addEventListener("focus", () => {
      if (input.value.trim()) scheduleSuggestions(control);
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (control.list.hidden || !control.options.length) renderSuggestions(control);
        if (control.options.length) {
          const offset = event.key === "ArrowDown" ? 1 : -1;
          const nextIndex = control.activeIndex < 0
            ? (event.key === "ArrowDown" ? 0 : control.options.length - 1)
            : control.activeIndex + offset;
          setActiveOption(control, nextIndex);
        }
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        if (!control.list.hidden && control.activeIndex >= 0) {
          selectCandidate(control, control.options[control.activeIndex].dataset.value);
          return;
        }
        renderSuggestions(control);
        const queryKey = normalize(input.value);
        const exact = control.suggestions.find((candidate) => normalize(candidate.value) === queryKey);
        if (exact) {
          selectCandidate(control, exact.value);
        } else {
          closeSuggestions(control);
          announce("추천 목록에서 값을 선택하세요.");
        }
        return;
      }
      if (event.key === "Escape") {
        event.preventDefault();
        closeSuggestions(control);
      } else if (event.key === "Tab") {
        closeSuggestions(control);
      }
    });
    input.addEventListener("blur", () => {
      window.setTimeout(() => {
        if (!control.pointerInteracting) closeSuggestions(control);
      }, 0);
    });
    list.addEventListener("pointerdown", (event) => {
      const option = event.target.closest("[role='option']");
      if (!option || !list.contains(option)) return;
      control.pointerInteracting = true;
      if (event.pointerType === "mouse") event.preventDefault();
    });
    list.addEventListener("pointerup", () => {
      control.pointerInteracting = false;
    });
    list.addEventListener("pointercancel", () => {
      control.pointerInteracting = false;
    });
    list.addEventListener("click", (event) => {
      const option = event.target.closest("[role='option']");
      if (!option || !list.contains(option)) return;
      event.preventDefault();
      selectCandidate(control, option.dataset.value);
      input.focus();
    });
    return control;
  };

  makeCombobox("ip", "IP");
  makeCombobox("port", "포트");
  if (!controls.ip || !controls.port) return;
  document.addEventListener("pointerdown", (event) => {
    for (const control of Object.values(controls)) {
      if (event.target !== control.input && !control.list.contains(event.target)) {
        closeSuggestions(control);
      }
    }
  });

  Array.from(indexes.protocol.values())
    .map((candidate) => candidate.value)
    .sort(naturalOrder.compare)
    .forEach((protocol) => {
      const option = document.createElement("option");
      option.value = protocol;
      option.textContent = protocol;
      protocolSelect.appendChild(option);
    });
  protocolSelect.addEventListener("change", () => {
    state.protocol = protocolSelect.value;
    invalidateCandidateCaches();
    closeAllSuggestions();
    applyFilters(state.protocol ? `프로토콜 ${state.protocol} 필터를 적용했습니다.` : "프로토콜 필터를 해제했습니다.");
  });
  const resetFilters = (message) => {
    state.ip = "";
    state.port = "";
    state.protocol = "";
    invalidateCandidateCaches();
    controls.ip.input.value = "";
    controls.port.input.value = "";
    delete controls.ip.input.dataset.selectedValue;
    delete controls.port.input.dataset.selectedValue;
    protocolSelect.value = "";
    closeAllSuggestions();
    applyFilters(message);
  };
  resetButton.addEventListener("click", () => {
    resetFilters("모든 필터를 초기화했습니다.");
  });

  window.addEventListener("pageshow", () => resetFilters());
  resetFilters();
  printSummary.hidden = false;
  filterRoot.hidden = false;
})();"""
_FILTER_SCRIPT_SHA256 = base64.b64encode(
    hashlib.sha256(_FILTER_SCRIPT.encode("utf-8")).digest()
).decode("ascii")


@dataclass(frozen=True, slots=True)
class RunReportSnapshot:
    """Stable database snapshot used to render one report."""

    run: ReportRow
    controllers: tuple[str, ...]
    mm_controllers: tuple[str, ...]
    md_controllers: tuple[str, ...]
    observations: tuple[ReportRow, ...]
    observation_total: int
    unique_session_total: int
    lifecycle_events: tuple[ReportRow, ...]
    lifecycle_total: int
    lifecycle_counts: tuple[tuple[str, int], ...]
    controller_events: tuple[ReportRow, ...]
    controller_total: int
    diagnostics: tuple[ReportRow, ...]
    diagnostic_total: int
    raw_files: tuple[ReportRow, ...]
    raw_file_total: int
    raw_byte_total: int
    observation_history: tuple[ReportRow, ...] = ()
    ip_frequency_summary: tuple[tuple[str, int, int], ...] | None = None
    protocol_port_frequency_summary: tuple[tuple[int, int, int, int], ...] | None = None


def render_html_report(snapshot: RunReportSnapshot) -> str:
    """Return the approved deterministic standalone HTML5 report."""

    # Keep the established public import path while avoiding an import cycle:
    # the presentation module imports this module's proven private helpers.
    from aruba_session_tracker.storage.html_report_presentation import (
        render_html_report as render_presentation,
    )

    return render_presentation(snapshot)


def write_html_report_atomic(destination: Path | str, snapshot: RunReportSnapshot) -> Path:
    """Atomically write one approved deterministic UTF-8 report."""

    from aruba_session_tracker.storage.html_report_presentation import (
        write_html_report_atomic as write_presentation,
    )

    return write_presentation(destination, snapshot)


def write_html_report_stream_atomic(
    destination: Path | str,
    snapshot: RunReportSnapshot,
    observation_history: Iterable[ReportRow],
    *,
    logical_session_total: int,
) -> Path:
    """Write an approved report while consuming history rows incrementally."""

    from aruba_session_tracker.storage.html_report_presentation import (
        write_html_report_stream_atomic as write_presentation_stream,
    )

    return write_presentation_stream(
        destination,
        snapshot,
        observation_history,
        logical_session_total=logical_session_total,
    )


def _write_html_chunks_atomic(destination: Path | str, chunks: Iterable[str]) -> Path:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        digest = hashlib.sha256()
        byte_size = 0
        with os.fdopen(descriptor, "wb") as stream:
            for chunk in chunks:
                encoded = chunk.encode("utf-8")
                stream.write(encoded)
                digest.update(encoded)
                byte_size += len(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(
            temporary_path,
            path,
            replace=os.replace,
            expected_sha256=digest.hexdigest(),
            expected_size=byte_size,
        )
    finally:
        temporary_path.unlink(missing_ok=True)
    return path


def _summary_stat(label: str, value: object) -> str:
    return f'<div class="summary-stat"><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>'


def _group_observations(
    rows: tuple[ReportRow, ...],
) -> tuple[tuple[FlowKey, tuple[ReportRow, ...]], ...]:
    grouped: dict[FlowKey, list[tuple[int, ReportRow]]] = {}
    for index, row in enumerate(rows):
        grouped.setdefault(_flow_key(row), []).append((index, row))

    ordered: list[tuple[FlowKey, tuple[ReportRow, ...]]] = []
    for flow, indexed_rows in grouped.items():
        sorted_rows = tuple(
            row
            for _index, row in sorted(
                indexed_rows,
                key=lambda item: (_datetime_sort_value(item[1].get("observed_at")), item[0]),
            )
        )
        ordered.append((flow, sorted_rows))
    ordered.sort(
        key=lambda item: (_datetime_sort_value(item[1][-1].get("observed_at")), item[0]),
        reverse=True,
    )
    return tuple(ordered)


def _lifecycle_statuses(
    rows: tuple[ReportRow, ...],
) -> tuple[dict[FlowKey, str], dict[str, str]]:
    flow_statuses: dict[FlowKey, tuple[tuple[datetime, int], str]] = {}
    session_statuses: dict[str, tuple[tuple[datetime, int], str]] = {}
    for index, row in enumerate(rows):
        status = _lifecycle_status(row.get("event_type"))
        if status is None:
            continue
        rank = (_datetime_sort_value(row.get("occurred_at")), -index)
        session_key = str(row.get("session_key") or "")
        if session_key:
            current_session = session_statuses.get(session_key)
            if current_session is None or rank > current_session[0]:
                session_statuses[session_key] = (rank, status)
        flow = _flow_key_from_session_key(session_key)
        if flow is not None:
            current_flow = flow_statuses.get(flow)
            if current_flow is None or rank > current_flow[0]:
                flow_statuses[flow] = (rank, status)
    return (
        {key: item[1] for key, item in flow_statuses.items()},
        {key: item[1] for key, item in session_statuses.items()},
    )


def _status_for(
    row: ReportRow,
    flow_statuses: dict[FlowKey, str],
    session_statuses: dict[str, str],
) -> str:
    flow_status = flow_statuses.get(_flow_key(row))
    if flow_status is not None:
        return flow_status
    session_key = str(row.get("session_key") or "")
    return session_statuses.get(session_key, "관측됨")


def _lifecycle_status(value: object) -> str | None:
    event_type = str(value or "").upper()
    if event_type == "CLOSED":
        return "종료 확인"
    if event_type == "MISSED":
        return "잠시 미확인"
    if event_type in _CONFIRMED_EVENTS:
        return "확인됨"
    return None


def _observation_row(row: ReportRow, status: str) -> str:
    protocol = _protocol(row.get("protocol"))
    protocol_number = _optional_int(row.get("protocol"))
    return (
        f'<tr class="report-row" data-source-ip="{_filter_attribute(row.get("source_ip"))}" '
        f'data-destination-ip="{_filter_attribute(row.get("destination_ip"))}" '
        f'data-source-port="{_filter_attribute(row.get("source_port"))}" '
        f'data-destination-port="{_filter_attribute(row.get("destination_port"))}" '
        f'data-protocol="{_filter_attribute(protocol)}">'
        f'<td class="protocol-cell">{_e(protocol)}</td>'
        f'<td class="endpoint-cell">{_e(_endpoint(row.get("source_ip"), row.get("source_port"), protocol=protocol_number))}</td>'
        f'<td class="endpoint-cell">{_e(_endpoint(row.get("destination_ip"), row.get("destination_port"), protocol=protocol_number))}</td>'
        f'<td class="status-cell">{_tracking_badge(status)}</td>'
        f'<td class="time-cell">{_e(_format_kst(row.get("observed_at")))}</td>'
        f'<td class="device-cell">{_e(row.get("controller_name"))}</td>'
        "</tr>"
    )


def _tracking_badge(status: str) -> str:
    kind = {
        "잠시 미확인": "missed",
        "종료 확인": "closed",
        "관측됨": "observed",
    }.get(status, "")
    return f'<span class="badge {kind}">{_e(status)}</span>'


def _flow_key(row: ReportRow) -> FlowKey:
    return (
        _key_part(row.get("protocol")),
        _key_part(row.get("source_ip")),
        _key_part(row.get("destination_ip")),
        _key_part(row.get("source_port")),
        _key_part(row.get("destination_port")),
    )


def _flow_key_from_session_key(value: str) -> FlowKey | None:
    parts = value.split("|")
    if len(parts) != 6:
        return None
    return (parts[1], parts[2], parts[3], parts[4], parts[5])


def _endpoint(address: object, port: object, *, protocol: int | None = None) -> str:
    address_text = _plain(address)
    if address_text == "-":
        return "-"
    port_text = _plain(port)
    if port_text == "-":
        return address_text
    if protocol is not None:
        with suppress(TypeError, ValueError):
            port_text = service_label(protocol, int(port_text))
    if ":" in address_text and not (address_text.startswith("[") and address_text.endswith("]")):
        address_text = f"[{address_text}]"
    return f"{address_text}:{port_text}"


def _query_endpoint(
    address: object,
    port: object,
    *,
    other_address: object,
    protocol: int | None = None,
) -> str:
    if _plain(address) == "-" and _plain(other_address) != "-":
        port_text = _plain(port)
        return "모든 IP" if port_text == "-" else f"모든 IP:{port_text}"
    return _endpoint(address, port, protocol=protocol)


def _protocol(value: object) -> str:
    number = _optional_int(value)
    if number is None:
        return _plain(value)
    if not 0 <= number <= 255:
        return str(number)
    return protocol_label(number)


def _format_kst(value: object) -> str:
    parsed = _parse_datetime(value)
    if parsed is None:
        return "-"
    return parsed.astimezone(_KST).strftime("%Y-%m-%d %H:%M:%S KST")


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _datetime_sort_value(value: object) -> datetime:
    return _parse_datetime(value) or datetime.min.replace(tzinfo=UTC)


def _format_integer(value: int) -> str:
    return f"{value:,}"


def _optional_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _key_part(value: object) -> str:
    return "" if value is None else str(value)


def _plain(value: object) -> str:
    if value is None or value == "":
        return "-"
    return str(value)


def _e(value: object) -> str:
    return escape(_plain(value), quote=True)


def _filter_attribute(value: object) -> str:
    text = _plain(value)
    return "" if text == "-" else escape(text, quote=True)


def _empty_row(columns: int, message: str) -> str:
    return f'<tr><td colspan="{columns}" class="muted">{_e(message)}</td></tr>'
