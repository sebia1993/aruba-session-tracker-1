# HTML report implementation instructions

The approved report baseline is
`design-system/aruba-session-tracker/DARK_NOC_CONSOLE_V1.md`.

For `html_report.py`, the approved report may include a session-state summary
and a sanitized significant-event timeline. This directory-level instruction
supersedes the root document's former visual prohibition on timelines and
summary visualizations while retaining all privacy and determinism rules.

- Keep one standalone UTF-8 HTML file.
- Keep CSS inline and keep the existing deterministic filter script secured by
  its exact CSP SHA-256 hash.
- No external requests, remote assets, fonts, APIs, analytics, or telemetry.
- Timeline entries must come only from stored lifecycle/controller facts.
- Never export Raw CLI, diagnostic messages, support internals, filesystem
  paths, credentials, host-key data, or inferred topology.
- Keep packet, byte, delta, CPU, age, and raw Flags details out of the HTML
  report.
- Preserve the complete observation history and bounded streaming behavior.
