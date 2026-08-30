# Aruba Session Tracker Instructions

## Purpose

This repository contains a Windows 11 PySide6 application that locates an
Aruba AOS 8 client on Mobility Conductor and collects matching read-only
datapath session rows from the relevant 7240XM managed device.

## Safety boundaries

- Never send configuration-changing commands. The runtime allowlist is limited
  to validated `show global-user-table list ip`, `show datapath session table`,
  session-only `no paging`, and optional `enable` handling.
- Do not run live-device tests for this project. The user owns field validation
  and will report sanitized symptoms or error codes when follow-up is needed.
  Tests use sanitized fixtures and local fakes.
- Never persist usernames, passwords, or enable secrets. Session credentials
  remain in memory only.
- Treat parser, SSH, and collection failures as unknown/partial results, never
  as proof that a controller or client is down.
- When Source and Destination resolve to different enabled MDs, query both.
  Keep every controller that owns an active flow in the authoritative poll
  scope; a positive result from one MD must never advance another MD's flow to
  `MISSED` or `CLOSED`.
- Keep one logical lifecycle instance for a controller-free five-tuple while
  preserving every controller-specific observation and Raw link. An
  authoritative controller overlap must not emit `CONTROLLER_CHANGED`; retain
  all overlap controllers in the next required poll scope and confirm a move
  only after an authoritative singleton resolves the overlap.
- Host-key and full-MD-scan approvals share the poll cancellation and monotonic
  deadline. Ignore every approval result that arrives after either boundary,
  and never save a host key or start a scan from that late result. Process and
  Windows file locks for known_hosts must share the same boundary.
- Probe an unknown SSH host before approval, but do not repeat the probe for a
  safely loaded known-host token when the production connector performs the
  strict authenticated check. A wrapped BadHostKey or missing known-host entry
  remains non-retryable `HOST_KEY_CHANGED`; ordinary timeouts remain transient.
- Never fall back to an unfiltered datapath table query.
- Treat managed files, operation manifests, leases, crash journals and their
  parent directories as local security boundaries. Reject symbolic links,
  reparse points, hardlinks and path-to-handle identity changes before reading
  or writing them. Never weaken these checks to recover a damaged workspace.
- Keep the F12 `화면 개선 도우미` (internally, the UI Inspector) disabled at
  every process start. Only an unmodified,
  non-repeating `F12` may toggle it; `Esc` cancels selection without disabling
  the Inspector, and selection mouse or keyboard activation must never reach
  operational controls.
- The Inspector may use and copy only the program version, registered static
  Korean names, stable IDs, screen paths, repository-relative source paths, purposes, and blank
  symptom/change fields. It must never read or copy runtime IP addresses,
  hostnames, accounts, passwords, enable secrets, device data, table cells,
  Raw CLI, diagnostics, logs, configuration values, or absolute paths.
- Never add Inspector state to CLI options, environment variables, config,
  registry, or SQLite, and never send Inspector or clipboard content outside
  the local process.

## Development

- Use CPython 3.13 x64 and a repository-local `.venv`.
- Keep command builders, SSH, parsers, orchestration, storage, and UI separate.
- Keep long-running query, history, reconciliation, export, deletion and
  shutdown work off the Qt GUI thread. Every new lifecycle worker must have a
  bounded wait, cancellation boundary, sanitized failure result and recovery
  behavior that is safe after process interruption.
- Persist one-shot runs as `COMPLETED` for authoritative results, `PARTIAL` only
  when a non-authoritative result retains positive observations, `FAILED` for
  zero-observation non-authoritative failures, and `CANCELLED` for cancellation.
- Bind deferred Qt callbacks to their owning `QObject` lifetime. Daemon workers
  must tolerate their signal sender being deleted during final Qt teardown;
  never leave an unowned callback that can call a deleted window later.
- Treat SQLite WAL disappearance during a read-only size snapshot as a normal
  zero-byte transient. Keep a single `lstat` snapshot for file type, reparse and
  size checks instead of weakening the managed-path boundary or serializing the
  complete background storage scan behind the store lock.
- Run `powershell -ExecutionPolicy Bypass -File .\tools\validate.ps1` before
  packaging.
- Keep global line coverage at or above 83 percent and branch coverage for the
  lifecycle-critical modules listed in `tools/check_coverage_policy.py` at or
  above 65 percent. Do not lower these floors to make CI pass.
- Build with `powershell -ExecutionPolicy Bypass -File .\build_windows.ps1`.
- Run the fixture-only 20,000-poll release soak locally with
  `$env:ARUBA_SOAK_POLLS='20000'; .\.venv\Scripts\python.exe -m pytest -m soak -q`
  before creating a versioned tag.
- The versioned release workflow must repeat that fixture-only soak in a
  separate bounded job on the exact annotated-tag commit before publication.
  Both soak results are test evidence only, not live-device evidence.
- Keep synthetic soak inputs between 1 and 20,000 polls. Each child-process
  timeout must remain between 500 and 3,200 seconds so the two sequential
  long-soak subprocesses stay inside each outer 120-minute workflow watchdog.
- Deadline watchdogs must recheck the shared monotonic deadline after an OS
  timer wait returns. Never treat one early Windows timer wakeup as expiry, and
  keep the connection-manager and owned-socket guards on the same policy.
- Keep real device addresses, logs, raw output, SQLite files, exports, and
  known-host files out of Git and release assets.
- Preserve CSV export as an independent manual path. HTML is a result-only
  presentation of the selected run, not an operator guide or diagnostic
  document. Keep it as a separate single-file HTML5 document with inline CSS,
  no external resources or external JavaScript, responsive and print layouts,
  and escaped database/device values. The only permitted script is exactly one
  deterministic inline result-filter script authorized by its exact SHA-256 in
  the Content Security Policy.
- Show KST as the primary display time and focus the latest 50 results and the
  collapsed full-history section on protocol, source IP:port, and destination
  IP:port. Partial IP or port input may offer at most 12 values from the stored
  full history, but filtering must begin only after the user selects an exact
  value or enters an exact value and presses Enter. Filters apply only to
  presentation, never remove an observation row from the document, are never
  persisted, and must reset whenever the report is reopened.
- Keep the report summary ordered as query source IP:port, direction, query
  destination IP:port, run status, and four core cards: start, end, total
  observations, and unique sessions. Protocol and device distributions may use
  only the same latest logical flows shown in the latest-results table, are
  limited to five values each, and must be hidden from filtered print output.
- Build autocomplete candidates from one full-history reverse index. Partial
  keystrokes may search only the cached unique candidate set, must discard any
  stale active option immediately, and must not rescan the report DOM. Touch
  pointer-down and list scrolling must never select a value; selection occurs
  only after a completed tap/click or explicit keyboard confirmation.
- HTML must preserve every stored observation row regardless of the live Qt
  table's 2,000-row cap. Screen and print show the current exact filter result;
  clearing all filters restores and prints the complete stored history. Show
  both filtered and total counts so hidden rows cannot be mistaken for missing
  data.
- The local report-filter script must not use network access, external
  libraries, browser storage, URLs, clipboard APIs, `eval`, or database/device
  values as executable markup. If CSP blocks it, hide the filter controls and
  leave the complete static report readable.
- Omit packet, byte, and counter-delta values from HTML while preserving them
  in SQLite, CSV, and Raw data. Do not change those storage formats for this
  presentation-only simplification.
- The History and Export screen may show read-only Raw file count, Raw bytes,
  total managed bytes and free space. A 100,000-file Raw warning is advisory
  only: it must not stop polling, show repeated popups, compact, or delete data.
- Exclude diagnostic events and codes, Raw bodies, paths and hashes, CLI and
  program-flow material, troubleshooting, developer information, credentials,
  and logs from HTML. Do not change the SQLite schema, CSV or Raw format for
  report presentation changes.
- Keep staged crash recovery for both managed and user-selected external CSV
  and HTML destinations. External recovery must independently validate owner,
  parent identity, destination and commit receipt before mutating user files.
- A detached external USB or unreachable UNC destination may defer only its
  owned recovery operation while the app starts in limited mode. Classify only
  documented device/network-unavailable Windows errors this way; access,
  credential and policy failures must fail closed.
- Keep the crash journal bounded and sanitized: event, stage, exception class,
  version and incident ID only. It must never accept exception messages,
  tracebacks, runtime values or absolute paths.
- Treat generated HTML reports as private runtime data. Do not add real reports
  to Git, tests, documentation fixtures, CI artifacts, or public packages.
- Preserve the exact 61-ID static Inspector catalog: 7 common, 24 Session Query,
  20 Device Settings, and 10 History and Export entries. Keep catalog IDs stable
  and cover additions or removals with tests that also enforce the static-data
  and click-blocking boundaries.
- Preserve the labels `지속 모니터링 시작`, `현재 조회`, `고급 조건 보기/숨기기`,
  and `상세 정보 보기/숨기기`. Operator state must be one of only `대기`,
  `조회 중`, `정상`, `재시도 중`, or `확인 필요`.
- Desktop presentation changes must not replace Qt widgets or Inspector IDs.
  Keep role-aware keyboard focus visible, retain clickable scrollbar line
  controls, and use native palette roles for high-contrast scrollbars.

## Release

- Public builds are unsigned Windows x64 onedir ZIP files.
- A package smoke test must exercise the packaged EXE against the loopback-only
  fake SSH server for both success and authentication failure, with no Python
  executable available through `PATH`.
- Versioned tags and releases are immutable by workflow policy. The moving
  `continuous` prerelease may be updated only by the verified `main` workflow.
- Reconcile `continuous` drafts by their release ID, never by a tag-only draft
  lookup or upload. Recovery is forward-only: preserve an interrupted owned
  draft and resume it instead of republishing an older workflow target.
- Every public release must contain exactly one uploaded Windows x64 ZIP. Keep
  the verified SHA-256 in the release body and the CycloneDX SBOM inside the ZIP.
  Local build inputs still include the sidecar and external SBOM for verification.
- Install the pinned runtime lock and require `pip check` in a publish runner
  before invoking package or remote-release verification tools.
- Verify release assets while draft, compare GitHub-reported SHA-256 digests,
  re-download authenticated bytes before publish, and re-download public bytes
  after publish. A published versioned release must never be repaired in place.
- CI/package evidence is not live Aruba or clean field-PC evidence.
- Keep deterministic offscreen checks for 100/125/150 percent scaling and an
  injected high-contrast palette. They do not replace Windows 11 field checks
  for a physical F12/Fn Lock key, focus handling, restart-off behavior,
  clipboard output, native high contrast, or multiple monitors.
