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
- Never fall back to an unfiltered datapath table query.
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
- Run `powershell -ExecutionPolicy Bypass -File .\tools\validate.ps1` before
  packaging.
- Keep global line coverage at or above 83 percent and branch coverage for the
  lifecycle-critical modules listed in `tools/check_coverage_policy.py` at or
  above 65 percent. Do not lower these floors to make CI pass.
- Build with `powershell -ExecutionPolicy Bypass -File .\build_windows.ps1`.
- Keep real device addresses, logs, raw output, SQLite files, exports, and
  known-host files out of Git and release assets.
- Preserve CSV export as an independent manual path. Result reports are
  separate single-file HTML5 documents with inline CSS, no external resources,
  responsive and print layouts, escaped database/device values, and no Raw CLI
  body. Never invent VLAN, SSID, Role, interface, topology, or device facts that
  are not stored for the selected run; label missing facts as confirmation
  required.
- HTML must include every stored observation row; the 2,000-row cap applies
  only to the live Qt result table.
- Keep staged crash recovery for both managed and user-selected external CSV
  and HTML destinations. External recovery must independently validate owner,
  parent identity, destination and commit receipt before mutating user files.
- Treat generated HTML reports as private runtime data. Do not add real reports
  to Git, tests, documentation fixtures, CI artifacts, or public packages.
- Preserve the exact 61-ID static Inspector catalog: 7 common, 24 Session Query,
  20 Device Settings, and 10 History and Export entries. Keep catalog IDs stable
  and cover additions or removals with tests that also enforce the static-data
  and click-blocking boundaries.
- Preserve the labels `지속 모니터링 시작`, `현재 조회`, `고급 조건 보기/숨기기`,
  and `상세 정보 보기/숨기기`. Operator state must be one of only `대기`,
  `조회 중`, `정상`, `재시도 중`, or `확인 필요`.

## Release

- Public builds are unsigned Windows x64 onedir ZIP files.
- Versioned tags and releases are immutable by workflow policy. The moving
  `continuous` prerelease may be updated only by the verified `main` workflow.
- Reconcile `continuous` drafts by their release ID, never by a tag-only draft
  lookup or upload. Recovery is forward-only: preserve an interrupted owned
  draft and resume it instead of republishing an older workflow target.
- Every public release must contain exactly one uploaded Windows x64 ZIP. Keep
  the verified SHA-256 in the release body and the CycloneDX SBOM inside the ZIP.
  Local build inputs still include the sidecar and external SBOM for verification.
- Verify release assets while draft, compare GitHub-reported SHA-256 digests,
  re-download authenticated bytes before publish, and re-download public bytes
  after publish. A published versioned release must never be repaired in place.
- CI/package evidence is not live Aruba or clean field-PC evidence.
- Keep deterministic offscreen checks for 100/125/150 percent scaling and an
  injected high-contrast palette. They do not replace Windows 11 field checks
  for a physical F12/Fn Lock key, focus handling, restart-off behavior,
  clipboard output, native high contrast, or multiple monitors.
