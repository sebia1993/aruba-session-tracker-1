# Aruba Session Tracker Instructions

## Purpose

This repository contains a Windows 11 PySide6 application that locates an
Aruba AOS 8 client on Mobility Conductor and collects matching read-only
datapath session rows from the relevant 7240XM managed device.

## Safety boundaries

- Never send configuration-changing commands. The runtime allowlist is limited
  to validated `show global-user-table list ip`, `show datapath session table`,
  session-only `no paging`, and optional `enable` handling.
- Do not run live-device tests without explicit authorization and supplied
  access details. Tests use sanitized fixtures and local fakes.
- Never persist usernames, passwords, or enable secrets. Session credentials
  remain in memory only.
- Treat parser, SSH, and collection failures as unknown/partial results, never
  as proof that a controller or client is down.
- Never fall back to an unfiltered datapath table query.
- Keep the F12 UI Inspector disabled at every process start. Only an unmodified,
  non-repeating `F12` may toggle it; `Esc` cancels selection without disabling
  the Inspector, and selection clicks must never reach operational controls.
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
- Build with `powershell -ExecutionPolicy Bypass -File .\build_windows.ps1`.
- Keep real device addresses, logs, raw output, SQLite files, exports, and
  known-host files out of Git and release assets.
- Preserve CSV export as an independent manual path. Result reports are
  separate single-file HTML5 documents with inline CSS, no external resources,
  responsive and print layouts, escaped database/device values, and no Raw CLI
  body. Never invent VLAN, SSID, Role, interface, topology, or device facts that
  are not stored for the selected run; label missing facts as confirmation
  required.
- Treat generated HTML reports as private runtime data. Do not add real reports
  to Git, tests, documentation fixtures, CI artifacts, or public packages.
- Preserve the exact 60-ID static Inspector catalog: 7 common, 23 Session Query,
  20 Device Settings, and 10 History and Export entries. Keep catalog IDs stable
  and cover additions or removals with tests that also enforce the static-data
  and click-blocking boundaries.

## Release

- Public builds are unsigned Windows x64 onedir ZIP files.
- Versioned tags and releases are immutable by workflow policy. The moving
  `continuous` prerelease may be updated only by the verified `main` workflow.
- Every release must contain the ZIP, SHA-256 sidecar, and CycloneDX SBOM.
- CI/package evidence is not live Aruba or clean field-PC evidence.
- Automated GUI checks do not replace Windows 11 field checks for a physical
  F12/Fn Lock key, focus handling, restart-off behavior, clipboard output,
  100/125/150 percent scaling, high contrast, and multiple monitors.
