from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from aruba_session_tracker.storage import RunReportSnapshot, render_html_report

pytestmark = [
    pytest.mark.windows,
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="The packaged HTML report is interaction-tested with Microsoft Edge on Windows.",
    ),
]

_HISTORY_ROW_COUNT = 20_000
_EDGE_TIMEOUT_SECONDS = 55


def _edge_executable() -> Path:
    candidates = [
        Path(os.environ.get("PROGRAMFILES", ""))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", ""))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
        Path(os.environ.get("LOCALAPPDATA", ""))
        / "Microsoft"
        / "Edge"
        / "Application"
        / "msedge.exe",
    ]
    command = shutil.which("msedge.exe")
    if command:
        candidates.append(Path(command))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    pytest.fail(
        "Microsoft Edge is required for the Windows HTML interaction gate, but msedge.exe "
        "was not found in the standard machine, 32-bit Program Files, user, or PATH locations."
    )


def _observation(
    index: int,
    *,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    protocol: int,
) -> dict[str, object]:
    observed_at = datetime(2026, 8, 30, tzinfo=UTC) + timedelta(seconds=index)
    controller = f"가상-MD-{(index % 4) + 1:02d}"
    return {
        "observed_at": observed_at.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "controller_name": controller,
        "controller_host": f"198.51.100.{(index % 4) + 1}",
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "packets": index + 1,
        "bytes_count": (index + 1) * 64,
        "age": index % 60,
        "flags": "DY",
        "cpu_id": index % 8,
        "session_key": (
            f"browser-{index}|{protocol}|{source_ip}|{destination_ip}|"
            f"{source_port}|{destination_port}"
        ),
    }


def _large_snapshot() -> RunReportSnapshot:
    special: dict[int, tuple[str, str, int, int, int]] = {
        # 10.0.0.9 occurs on both sides and port 443 occurs on both sides.
        0: ("10.0.0.9", "203.0.113.9", 55_000, 443, 6),
        1: ("192.0.2.1", "10.0.0.9", 443, 55_001, 17),
        2: ("10.0.0.8", "203.0.113.8", 55_002, 80, 6),
        3: ("192.0.2.7", "10.0.0.7", 55_003, 22, 6),
        # This UDP-only address is old enough to be absent from the latest 50 flows.
        4: ("198.18.0.77", "203.0.113.77", 55_004, 53, 17),
        5: ("192.0.2.12", "203.0.113.12", 55_005, 8443, 6),
        21: ("2001:db8::10", "203.0.113.21", 55_021, 8443, 6),
        22: ("fe80::db8:2", "203.0.113.22", 55_022, 8443, 6),
        23: ("192.0.2.80", "203.0.113.80", 55_023, 8080, 6),
    }
    for offset in range(15):
        special[6 + offset] = (
            f"192.0.2.{120 + offset}",
            f"203.0.113.{120 + offset}",
            55_006 + offset,
            8443,
            6,
        )

    rows: list[dict[str, object]] = []
    for index in range(_HISTORY_ROW_COUNT):
        values = special.get(index)
        if values is None:
            source_ip = f"172.16.{(index // 256) % 256}.{index % 256}"
            destination_ip = f"198.51.100.{(index % 200) + 1}"
            source_port = 10_000 + index
            destination_port = 443 if index % 7 == 0 else (80 if index % 5 == 0 else 8443)
            protocol = 6 if index % 3 else 17
            values = (
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                protocol,
            )
        rows.append(
            _observation(
                index,
                source_ip=values[0],
                destination_ip=values[1],
                source_port=values[2],
                destination_port=values[3],
                protocol=values[4],
            )
        )

    history = tuple(rows)
    return RunReportSnapshot(
        run={
            "id": "browser-filter-sanitized",
            "started_at": "2026-08-30T00:00:00.000Z",
            "ended_at": "2026-08-30T06:00:00.000Z",
            "source_ip": "테스트 데이터",
            "destination_ip": "테스트 데이터",
            "source_port": None,
            "destination_port": None,
            "bidirectional": 1,
            "status": "COMPLETED",
        },
        controllers=("가상-MM-01", "가상-MD-01"),
        mm_controllers=("가상-MM-01",),
        md_controllers=("가상-MD-01",),
        observations=history[-50:],
        observation_total=len(history),
        unique_session_total=len(history),
        lifecycle_events=(),
        lifecycle_total=0,
        lifecycle_counts=(),
        controller_events=(),
        controller_total=0,
        diagnostics=(),
        diagnostic_total=0,
        raw_files=(),
        raw_file_total=0,
        raw_byte_total=0,
        observation_history=history,
    )


def _small_snapshot() -> RunReportSnapshot:
    history = tuple(
        _observation(
            index,
            source_ip=f"192.0.2.{index + 1}",
            destination_ip=f"203.0.113.{index + 1}",
            source_port=50_000 + index,
            destination_port=(80, 443, 8080)[index],
            protocol=(6, 17, 6)[index],
        )
        for index in range(3)
    )
    return RunReportSnapshot(
        run={
            "id": "browser-csp-fallback-sanitized",
            "started_at": "2026-08-30T00:00:00.000Z",
            "ended_at": "2026-08-30T00:01:00.000Z",
            "source_ip": "192.0.2.0/24",
            "destination_ip": "203.0.113.0/24",
            "source_port": None,
            "destination_port": None,
            "bidirectional": 1,
            "status": "COMPLETED",
        },
        controllers=("가상-MD-01",),
        mm_controllers=("가상-MM-01",),
        md_controllers=("가상-MD-01",),
        observations=history,
        observation_total=len(history),
        unique_session_total=len(history),
        lifecycle_events=(),
        lifecycle_total=0,
        lifecycle_counts=(),
        controller_events=(),
        controller_total=0,
        diagnostics=(),
        diagnostic_total=0,
        raw_files=(),
        raw_file_total=0,
        raw_byte_total=0,
        observation_history=history,
    )


_BROWSER_DRIVER = r"""(() => {
  "use strict";

  const finish = (payload) => {
    const result = document.createElement("pre");
    result.id = "browser-test-result";
    result.hidden = true;
    result.textContent = JSON.stringify(payload);
    document.body.appendChild(result);
  };
  const fail = (message) => { throw new Error(message); };
  const check = (condition, message) => { if (!condition) fail(message); };
  const wait = (milliseconds) => new Promise((resolve) => {
    window.setTimeout(resolve, milliseconds);
  });
  const inputValue = (input, value) => {
    input.value = value;
    input.dispatchEvent(new Event("input", {bubbles: true}));
  };
  const key = (input, value) => {
    input.dispatchEvent(new KeyboardEvent(
      "keydown", {key: value, bubbles: true, cancelable: true}
    ));
  };
  const openSuggestions = (input, value) => {
    key(input, "Escape");
    inputValue(input, value);
    key(input, "ArrowDown");
  };
  const options = (list) => Array.from(list.querySelectorAll("[role='option']"));
  const visibleRows = (body) => Array.from(body.querySelectorAll("tr.report-row:not([hidden])"));
  const allRows = (body) => Array.from(body.querySelectorAll("tr.report-row"));
  const recordMatches = (row, ip, protocol, port) => {
    const ipMatch = !ip || row.dataset.sourceIp === ip || row.dataset.destinationIp === ip;
    const protocolMatch = !protocol || row.dataset.protocol === protocol;
    const portMatch = !port || row.dataset.sourcePort === port ||
      row.dataset.destinationPort === port;
    return ipMatch && protocolMatch && portMatch;
  };
  const expectedVisible = (body, ip, protocol, port) => (
    allRows(body).filter((row) => recordMatches(row, ip, protocol, port)).length
  );

  (async () => {
    if (document.readyState !== "complete") {
      await new Promise((resolve) => {
        window.addEventListener("pageshow", resolve, {once: true});
      });
    }
    const startedAt = performance.now();
    const root = document.getElementById("result-filter");
    const ip = document.getElementById("filter-ip");
    const port = document.getElementById("filter-port");
    const protocol = document.getElementById("filter-protocol");
    const reset = document.getElementById("filter-reset");
    const ipList = document.getElementById("filter-ip-list");
    const portList = document.getElementById("filter-port-list");
    const latestBody = document.getElementById("latest-results-body");
    const historyBody = document.getElementById("history-results-body");
    const latestCount = document.getElementById("latest-filter-count");
    const historyCount = document.getElementById("history-filter-count");
    const historySummary = document.getElementById("history-filter-summary");
    const status = document.getElementById("filter-status");
    const printSummary = document.getElementById("print-filter-summary");
    check(root && ip && port && protocol && reset && ipList && portList && latestBody &&
      historyBody && latestCount && historyCount && historySummary && status && printSummary,
      "production filter controls were not initialized");
    check(root.hidden === false, "filter panel stayed hidden after production initialization");
    check(allRows(historyBody).length === 20000, "the 20,000-row history was not preserved");
    check(allRows(latestBody).length === 50, "the latest result limit was not preserved");
    check(protocol.querySelectorAll("option").length === 3,
      "protocol options were not deduplicated");
    check(Array.from(protocol.options).map((item) => item.value).join("|") ===
      "|TCP (6)|UDP (17)",
      "protocol options were not naturally ordered");

    // Ranking is exact, prefix, then contains; the visible list is capped at 12.
    openSuggestions(ip, "192.0.2.1");
    let ipOptions = options(ipList);
    let ipValues = ipOptions.map((item) => item.dataset.value);
    check(ipOptions.length === 12,
      `IP suggestions were not capped at 12: ${ipOptions.length} (${ipValues.join(", ")})`);
    check(ipValues[0] === "192.0.2.1", "exact IP match was not ranked first");
    check(ipValues[1] === "192.0.2.12" && ipValues[2] === "192.0.2.120",
      "prefix IP matches were not naturally sorted");

    openSuggestions(ip, "db8");
    ipValues = options(ipList).map((item) => item.dataset.value);
    check(ipValues.includes("2001:db8::10") && ipValues.includes("fe80::db8:2"),
      "middle-match IPv6 suggestions were not offered");

    // Direction labels merge duplicate source/destination values into one candidate.
    openSuggestions(ip, "10.0.0.");
    ipOptions = options(ipList);
    const directions = new Map(ipOptions.map((item) => [
      item.dataset.value,
      item.querySelector(".suggestion-direction").textContent,
    ]));
    check(directions.get("10.0.0.7") === "목적지", "destination-only IP label was wrong");
    check(directions.get("10.0.0.8") === "출발지", "source-only IP label was wrong");
    check(directions.get("10.0.0.9") === "양쪽", "two-sided IP label was not merged");
    check(ipOptions.filter((item) => item.dataset.value === "10.0.0.9").length === 1,
      "duplicate IP suggestions were rendered");

    // Escape and Tab close the popup without applying a partial value.
    key(ip, "Escape");
    check(ipList.hidden && ip.getAttribute("aria-expanded") === "false",
      "Escape did not close the IP suggestion list");
    openSuggestions(ip, "10.0.0.");
    key(ip, "Tab");
    check(ipList.hidden, "Tab did not close the IP suggestion list");

    // Debouncing must discard old options and render only the newest input query.
    openSuggestions(ip, "10.0.0.");
    const staleOption = options(ipList)[0];
    inputValue(ip, "192.0.2.1");
    inputValue(ip, "db8");
    check(ipList.hidden && options(ipList).length === 0 &&
      !ip.hasAttribute("aria-activedescendant"),
      "input change retained a stale suggestion before the debounce delay");
    await wait(180);
    const debouncedValues = options(ipList).map((item) => item.dataset.value);
    check(!ipList.hidden && debouncedValues.length === 2,
      "180ms debounce did not render the latest query recommendations");
    check(debouncedValues.every((value) => value.toLocaleLowerCase("ko-KR").includes("db8")),
      "debounce rendered a recommendation from an older query");
    check(!ip.hasAttribute("aria-activedescendant") && !ipList.contains(staleOption),
      "debounce retained stale option or ARIA selection state");

    inputValue(ip, "not-present");
    check(ipList.hidden && options(ipList).length === 0 &&
      !ip.hasAttribute("aria-activedescendant"),
      "input change retained a stale suggestion or ARIA selection");
    staleOption.dispatchEvent(new MouseEvent("click", {bubbles: true, cancelable: true}));
    key(ip, "Enter");
    check(!ip.dataset.selectedValue && visibleRows(historyBody).length === 20000,
      "a stale recommendation was applied after the input changed");

    // A complete value can be applied with Enter, without preselecting an option.
    key(ip, "Escape");
    inputValue(ip, "10.0.0.9");
    key(ip, "Enter");
    check(ip.dataset.selectedValue === "10.0.0.9", "exact IP Enter selection failed");
    let expectedHistory = expectedVisible(historyBody, "10.0.0.9", "", "");
    check(visibleRows(historyBody).length === expectedHistory, "exact IP filter count was wrong");

    // A selected IP can be replaced directly by another valid exact value.
    inputValue(ip, "10.0.0.8");
    key(ip, "Enter");
    check(ip.dataset.selectedValue === "10.0.0.8", "direct IP replacement was not applied");
    expectedHistory = expectedVisible(historyBody, "10.0.0.8", "", "");
    check(visibleRows(historyBody).length === expectedHistory,
      "direct IP replacement retained the previous IP condition");
    inputValue(ip, "10.0.0.9");
    key(ip, "Enter");
    check(ip.dataset.selectedValue === "10.0.0.9", "replacement setup did not restore IP");

    protocol.value = "TCP (6)";
    protocol.dispatchEvent(new Event("change", {bubbles: true}));
    openSuggestions(port, "443");
    const port443 = options(portList).find((item) => item.dataset.value === "443");
    check(port443, "exact port recommendation was missing");
    check(port443.querySelector(".suggestion-direction").textContent === "목적지",
      "port direction label ignored the active IP/protocol filters");
    portList.style.height = "24px";
    portList.style.maxHeight = "24px";
    const touchDown = new PointerEvent("pointerdown", {
      bubbles: true, cancelable: true, pointerType: "touch", pointerId: 7,
    });
    const touchMove = new PointerEvent("pointermove", {
      bubbles: true, cancelable: true, pointerType: "touch", pointerId: 7,
    });
    const touchUp = new PointerEvent("pointerup", {
      bubbles: true, cancelable: true, pointerType: "touch", pointerId: 7,
    });
    check(port443.dispatchEvent(touchDown) && !touchDown.defaultPrevented,
      "touch pointerdown was incorrectly canceled");
    portList.scrollTop = 12;
    check(portList.scrollTop > 0, "touch-scroll fixture could not move the recommendation list");
    const scrolledTop = portList.scrollTop;
    check(port443.dispatchEvent(touchMove) && !touchMove.defaultPrevented,
      "touch pointermove was incorrectly canceled");
    check(port443.dispatchEvent(touchUp) && !touchUp.defaultPrevented,
      "touch pointerup was incorrectly canceled");
    check(!port.dataset.selectedValue && !portList.hidden && portList.scrollTop === scrolledTop,
      "touch scroll selected an option, closed the list, or reset its scroll position");
    port443.dispatchEvent(new MouseEvent("click", {bubbles: true, cancelable: true}));
    check(port.dataset.selectedValue === "443", "follow-up click did not select the touch option");
    expectedHistory = expectedVisible(historyBody, "10.0.0.9", "TCP (6)", "443");
    const expectedLatest = expectedVisible(latestBody, "10.0.0.9", "TCP (6)", "443");
    check(visibleRows(historyBody).length === expectedHistory, "AND history filter was wrong");
    check(visibleRows(latestBody).length === expectedLatest, "AND latest filter was wrong");
    check(historyCount.textContent === `전체 ${expectedHistory.toLocaleString("ko-KR")}/20,000건`,
      "history count label was wrong");
    check(latestCount.textContent === `최신 ${expectedLatest}/50건`,
      "latest count label was wrong");
    check(historySummary.textContent ===
      `전체 추적 이력 ${expectedHistory.toLocaleString("ko-KR")}/20,000건 보기`,
      "collapsed history summary did not track the filtered count");
    check(printSummary.hidden === false && getComputedStyle(printSummary).display === "none",
      "screen-hidden print filter marker was not initialized");
    check(printSummary.textContent.includes("IP 10.0.0.9") &&
      printSummary.textContent.includes("프로토콜 TCP (6)") &&
      printSummary.textContent.includes("포트 443"),
      "print filter marker omitted an active condition");

    // Deleting a selected port clears only that condition.
    inputValue(port, "");
    check(!port.dataset.selectedValue && port.value === "",
      "empty port input retained its selected value");
    expectedHistory = expectedVisible(historyBody, "10.0.0.9", "TCP (6)", "");
    check(visibleRows(historyBody).length === expectedHistory,
      "empty port input changed the remaining IP/protocol filters");
    key(port, "Escape");
    inputValue(port, "443");
    key(port, "Enter");
    check(port.dataset.selectedValue === "443", "port deletion setup was not restored");

    // Editing a selected value removes only that condition. Invalid Enter never applies
    // a partial value.
    inputValue(ip, "not-present");
    key(ip, "Enter");
    check(!ip.dataset.selectedValue, "invalid IP input retained a selected value");
    check(status.textContent === "추천 목록에서 값을 선택하세요.",
      "invalid input did not ask the user to choose a recommendation");
    expectedHistory = expectedVisible(historyBody, "", "TCP (6)", "443");
    check(visibleRows(historyBody).length === expectedHistory,
      "editing invalid IP changed the remaining protocol/port filters");

    // Other active filters constrain the candidate set.
    openSuggestions(ip, "198.18.0.77");
    check(options(ipList).length === 0, "UDP-only IP was suggested while TCP was active");

    reset.click();
    check(ip.value === "" && port.value === "" && protocol.value === "",
      "reset did not clear the controls");
    check(!ip.dataset.selectedValue && !port.dataset.selectedValue,
      "reset retained an exact selected value");
    check(visibleRows(historyBody).length === 20000 && visibleRows(latestBody).length === 50,
      "reset did not restore every result row");
    check(historyCount.textContent === "전체 20,000/20,000건", "reset count was wrong");

    // Exact port 80 must never include the prefix-like value 8080.
    key(port, "Escape");
    inputValue(port, "80");
    key(port, "Enter");
    check(port.dataset.selectedValue === "80", "exact port 80 was not selected");
    const port8080Rows = allRows(historyBody).filter((row) =>
      row.dataset.sourcePort === "8080" || row.dataset.destinationPort === "8080"
    );
    check(port8080Rows.length >= 1, "8080 boundary fixture was not rendered");
    check(port8080Rows.every((row) => row.hidden), "exact port 80 included an 8080 row");
    check(visibleRows(historyBody).every((row) =>
      row.dataset.sourcePort === "80" || row.dataset.destinationPort === "80"
    ), "exact port 80 admitted a non-exact port");
    reset.click();

    // Arrow keys select the naturally first recommendation and Enter applies it.
    openSuggestions(ip, "10.0.0.");
    check(ip.getAttribute("aria-activedescendant") === "ip-suggestion-0",
      "ArrowDown did not expose the active option through ARIA");
    key(ip, "Enter");
    check(ip.dataset.selectedValue === "10.0.0.7",
      "keyboard selection did not apply the naturally first IP");
    reset.click();

    // Starting with ArrowUp wraps to the naturally last recommendation.
    key(ip, "Escape");
    inputValue(ip, "10.0.0.");
    key(ip, "ArrowUp");
    check(ip.getAttribute("aria-activedescendant") ===
      `ip-suggestion-${options(ipList).length - 1}`,
      "first ArrowUp did not expose the last option through ARIA");
    key(ip, "Enter");
    check(ip.dataset.selectedValue === "10.0.0.9",
      "first ArrowUp did not apply the naturally last IP");
    reset.click();

    // An old exact value remains discoverable and explains why latest has no match.
    key(ip, "Escape");
    inputValue(ip, "198.18.0.77");
    key(ip, "Enter");
    check(visibleRows(historyBody).length === 1 && visibleRows(latestBody).length === 0,
      "old-only exact selection did not distinguish latest from full history");
    check(status.textContent.includes("전체 이력에는 1건이 있지만 최신 결과에는 없습니다."),
      "old-only result did not provide the latest/history explanation");
    protocol.value = "UDP (17)";
    protocol.dispatchEvent(new Event("change", {bubbles: true}));
    key(port, "Escape");
    inputValue(port, "53");
    key(port, "Enter");
    check(port.dataset.selectedValue === "53", "restore-state setup did not select a port");

    // A browser history restoration must never retain a previous report filter.
    window.dispatchEvent(new PageTransitionEvent("pageshow", {persisted: true}));
    check(ip.value === "" && port.value === "" && protocol.value === "",
      "pageshow did not clear restored control values");
    check(!ip.dataset.selectedValue && !port.dataset.selectedValue,
      "pageshow retained a restored exact selection");
    check(visibleRows(historyBody).length === 20000 && visibleRows(latestBody).length === 50,
      "pageshow did not restore the complete report");
    check(historyCount.textContent === "전체 20,000/20,000건",
      "pageshow did not reset the result counts");

    // Replacing the same 12 suggestions repeatedly must not accumulate DOM nodes.
    openSuggestions(ip, "192.0.2.1");
    check(options(ipList).length === 12, "DOM growth setup did not render 12 options");
    const stableElementCount = document.querySelectorAll("*").length;
    for (let iteration = 0; iteration < 40; iteration += 1) {
      openSuggestions(ip, "192.0.2.1");
      check(options(ipList).length === 12, "repeated suggestion render exceeded its bound");
    }
    check(document.querySelectorAll("*").length === stableElementCount,
      "repeated autocomplete rendering grew the DOM");

    finish({
      ok: true,
      historyRows: allRows(historyBody).length,
      latestRows: allRows(latestBody).length,
      suggestionLimit: options(ipList).length,
      browserDurationMs: Math.round(performance.now() - startedAt),
    });
  })().catch((error) => finish({
    ok: false,
    error: String(error && (error.stack || error.message) || error),
  }));
})();"""


_CSP_FALLBACK_DRIVER = r"""(() => {
  "use strict";

  const finish = (payload) => {
    const result = document.createElement("pre");
    result.id = "browser-test-result";
    result.hidden = true;
    result.textContent = JSON.stringify(payload);
    document.body.appendChild(result);
  };
  try {
    const root = document.getElementById("result-filter");
    const latestRows = Array.from(document.querySelectorAll(
      "#latest-results-body tr.report-row"
    ));
    const historyRows = Array.from(document.querySelectorAll(
      "#history-results-body tr.report-row"
    ));
    const protocolOptions = document.querySelectorAll("#filter-protocol option");
    if (!root || root.hidden !== true) throw new Error("blocked filter panel was visible");
    if (latestRows.length !== 3 || historyRows.length !== 3) {
      throw new Error("static report rows were not preserved");
    }
    if ([...latestRows, ...historyRows].some((row) => row.hidden)) {
      throw new Error("blocked production script hid a static report row");
    }
    if (protocolOptions.length !== 1) {
      throw new Error("production filter script ran despite the broken CSP hash");
    }
    finish({
      ok: true,
      filterHidden: root.hidden,
      latestRows: latestRows.length,
      historyRows: historyRows.length,
    });
  } catch (error) {
    finish({
      ok: false,
      error: String(error && (error.stack || error.message) || error),
    });
  }
})();"""


def _inject_hash_authorized_driver(document: str, driver: str = _BROWSER_DRIVER) -> str:
    digest = base64.b64encode(hashlib.sha256(driver.encode("utf-8")).digest()).decode("ascii")
    csp_pattern = re.compile(r"(script-src\s+[^;\"]+)(;)")
    updated, substitutions = csp_pattern.subn(
        rf"\1 'sha256-{digest}'\2",
        document,
        count=1,
    )
    assert substitutions == 1
    assert f"'sha256-{digest}'" in updated
    assert updated.count("</body>") == 1
    return updated.replace("</body>", f"<script>{driver}</script>\n</body>", 1)


def _break_production_filter_hash(document: str) -> str:
    broken_digest = f"{'A' * 43}="
    pattern = re.compile(r"(script-src\s+)'sha256-[A-Za-z0-9+/=]+'")
    updated, substitutions = pattern.subn(
        rf"\1'sha256-{broken_digest}'",
        document,
        count=1,
    )
    assert substitutions == 1
    assert f"'sha256-{broken_digest}'" in updated
    return updated


def _browser_result(dumped_dom: str) -> dict[str, object]:
    match = re.search(
        r'<pre\b[^>]*\bid="browser-test-result"[^>]*>(?P<result>.*?)</pre>',
        dumped_dom,
        flags=re.DOTALL,
    )
    assert match is not None, "Edge finished without emitting the test driver result"
    return json.loads(html.unescape(match.group("result")))


def _dump_dom_with_edge(edge: Path, report_path: Path, user_data: Path) -> tuple[str, float]:
    user_data.mkdir()
    command = [
        str(edge),
        "--headless=new",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-domain-reliability",
        "--disable-extensions",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-default-browser-check",
        "--no-first-run",
        "--no-pings",
        "--no-proxy-server",
        "--host-resolver-rules=MAP * 0.0.0.0, EXCLUDE localhost",
        f"--user-data-dir={user_data}",
        "--virtual-time-budget=12000",
        "--dump-dom",
        report_path.as_uri(),
    ]
    started_at = time.perf_counter()
    completed = subprocess.run(  # noqa: S603
        command,
        check=False,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=_EDGE_TIMEOUT_SECONDS,
    )
    elapsed = time.perf_counter() - started_at
    assert completed.returncode == 0, (
        f"Edge exited with {completed.returncode} after {elapsed:.2f}s. "
        f"stderr tail:\n{completed.stderr[-4000:]}"
    )
    assert elapsed < _EDGE_TIMEOUT_SECONDS
    return completed.stdout, elapsed


def test_html_autocomplete_filter_in_headless_edge_with_20k_history(
    tmp_path: Path,
) -> None:
    edge = _edge_executable()
    report_path = tmp_path / "ArubaSessionTracker_HTML_자동완성_브라우저_QA.html"
    report_path.write_text(
        _inject_hash_authorized_driver(render_html_report(_large_snapshot())),
        encoding="utf-8",
        newline="\n",
    )
    dumped_dom, elapsed = _dump_dom_with_edge(edge, report_path, tmp_path / "edge-profile")
    result = _browser_result(dumped_dom)
    assert result.get("ok") is True, result.get("error", result)
    assert result["historyRows"] == _HISTORY_ROW_COUNT
    assert result["latestRows"] == 50
    assert result["suggestionLimit"] == 12
    assert elapsed < _EDGE_TIMEOUT_SECONDS


def test_html_report_keeps_static_results_when_filter_script_csp_hash_is_broken(
    tmp_path: Path,
) -> None:
    edge = _edge_executable()
    report_path = tmp_path / "ArubaSessionTracker_HTML_CSP_fallback_QA.html"
    document = render_html_report(_small_snapshot())
    broken = _break_production_filter_hash(document)
    report_path.write_text(
        _inject_hash_authorized_driver(broken, _CSP_FALLBACK_DRIVER),
        encoding="utf-8",
        newline="\n",
    )

    dumped_dom, _elapsed = _dump_dom_with_edge(
        edge,
        report_path,
        tmp_path / "edge-csp-fallback-profile",
    )
    result = _browser_result(dumped_dom)
    assert result.get("ok") is True, result.get("error", result)
    assert result == {
        "ok": True,
        "filterHidden": True,
        "latestRows": 3,
        "historyRows": 3,
    }
