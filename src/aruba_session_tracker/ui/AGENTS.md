# UI Redesign Instructions — Dark NOC Console V1

These instructions apply to files in `src/aruba_session_tracker/ui/` on the
`design/dark-noc-console-v1` branch.

Read `design-system/aruba-session-tracker/DARK_NOC_CONSOLE_V1.md` before making
presentation changes. That file is the approved visual target and overrides older
light-canvas presentation guidance where visual rules conflict.

## Mandatory boundaries

- Preserve all existing network/storage/runtime behavior.
- Preserve the exact 61-ID Inspector catalog and every existing stable ID.
- Do not replace registered operational widgets merely to obtain a new look.
  Prefer styling, wrapping, reparenting, or adding presentation-only companion widgets.
- Keep the exact labels required by root `AGENTS.md`.
- Do not persist or transmit any runtime UI data.
- Do not add a styling framework/runtime dependency.
- No CDN, remote icon, remote font, analytics, telemetry, or upload.

## Approved visual direction

- Dark enterprise NOC/session-investigation console.
- Dense data grid and compact controls.
- Restrained navy/charcoal surfaces with blue, green, amber, and red semantic accents.
- Query flow visually shows source ↔/→ destination without implying routed topology.
- A presentation-only `DETAILS` summary may be added to the existing detail tab container.
- Existing Raw and Diagnostics widgets remain intact; rename their visible tabs to
  `RAW CLI` and `DIAGNOSTICS` if needed for the visual system.
- Raw CLI uses the deepest dark terminal surface and monospace text.
- Metric cards may show only deterministic existing values; never fabricate data.
- Prefer a left navigation-rail appearance only if the existing registered tab objects
  can be preserved. Otherwise retain the registered tabs and use a compact dark NOC nav.

## Tests

Update presentation tests to validate the approved dark tokens, external-resource ban,
widget identity, DPI/high-contrast behavior, and detail presentation. Do not weaken
functional or security tests to make the redesign pass.
