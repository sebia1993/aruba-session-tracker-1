# HTML Report Redesign Instructions — Dark NOC Console V1

These instructions apply to report presentation files under
`src/aruba_session_tracker/storage/` on branch `design/dark-noc-console-v1`.

Read `design-system/aruba-session-tracker/DARK_NOC_CONSOLE_V1.md` first.
For HTML presentation, that design target supersedes the older root presentation rule
that prohibited all lifecycle/controller event timelines. Security, privacy, storage,
and data-integrity rules from the root instructions remain mandatory.

## Approved report direction

- Standalone light/white professional Session Investigation Report.
- Keep one self-contained HTML5 file.
- Preserve complete stored observations.
- Keep current local exact-value filtering behavior if present.
- May add a significant-event timeline using only stored sanitized lifecycle/controller
  facts already present in the report snapshot.
- May add a state summary using deterministic stored lifecycle status counts.
- May use inline SVG/CSS for a compact ring/segmented visualization.
- Do not infer cause, failover, outage, or path from controller/lifecycle events.

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

## Security and tests

Retain exact CSP hash authorization for the deterministic local filter script if the
script remains. Runtime/database values must stay escaped. Print view must expose the
complete current filter result and clearing filters must restore the full stored history.
Update report tests and package smoke tests to the new section hierarchy without
weakening privacy/no-network assertions.
