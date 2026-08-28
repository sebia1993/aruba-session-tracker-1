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

## Development

- Use CPython 3.13 x64 and a repository-local `.venv`.
- Keep command builders, SSH, parsers, orchestration, storage, and UI separate.
- Run `powershell -ExecutionPolicy Bypass -File .\tools\validate.ps1` before
  packaging.
- Build with `powershell -ExecutionPolicy Bypass -File .\build_windows.ps1`.
- Keep real device addresses, logs, raw output, SQLite files, exports, and
  known-host files out of Git and release assets.

## Release

- Public builds are unsigned Windows x64 onedir ZIP files.
- Versioned tags and releases are immutable. The moving `continuous`
  prerelease may be replaced only by the verified `main` workflow.
- Every release must contain the ZIP, SHA-256 sidecar, and CycloneDX SBOM.
- CI/package evidence is not live Aruba or clean field-PC evidence.

