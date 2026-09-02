# HTML Report Presentation Instructions — Dark NOC Console V1

These instructions apply to report presentation files under
`src/aruba_session_tracker/storage/`.

Read `design-system/aruba-session-tracker/DARK_NOC_CONSOLE_V1.md` first.
Security, privacy, storage, and data-integrity rules from the root instructions remain
mandatory.

## Approved report direction

- Standalone light/white professional Session Investigation Report.
- Keep one self-contained HTML5 file.
- Preserve complete stored observations.
- Keep current local exact-value filtering behavior if present.
- Replace the former session-state summary and recent-event timeline with exactly two
  static, full-history TOP 5 summaries: IP and protocol/port. Each stored observation
  contributes one source count and one destination count.
- Use deterministic ordering (total descending, then IP text or protocol/port ascending),
  omit blank IPs and port 0, and label only catalogue-known services such as
  `443(HTTPS)`; unknown services remain numeric.
- Render accessible horizontal stacked bars with visible counts. They do not respond to
  result filters and require no new JavaScript, SVG, library, or external asset.
- The visible report-basis field is `조회 대상`; do not expose or alter the internal
  run ID. Do not add date text to that field.

## Still forbidden

- Raw CLI bodies;
- diagnostic messages or codes;
- file paths/hashes;
- credentials;
- logs;
- developer/internal workflow material;
- external CSS/JS/fonts/icons/images;
- network requests;
- analytics/telemetry;
- browser storage;
- clipboard APIs;
- `eval` or executable runtime/device markup.
- session-state or lifecycle/controller-event summaries and timelines;
- device/controller, diagnostic, cause, or other distribution charts.

## Security and tests

Retain exact CSP hash authorization for the deterministic local filter script if the
script remains. Runtime/database values must stay escaped. Print view must expose the
complete current filter result and clearing filters must restore the full stored history.
Update report tests and package smoke tests to the new section hierarchy without
weakening privacy/no-network assertions.
