# Aruba Session Tracker — Dark NOC Console V1

## Authority

This document is the approved visual target for branch `design/dark-noc-console-v1`.
Where older presentation guidance conflicts with this document, this document wins for
visual design only. All read-only Aruba, SSH, credential, storage, recovery, Inspector,
and data-protection rules remain mandatory.

The original conversation reference image is not present in this repository.
The tokens, hierarchy, behavior, and acceptance criteria in this document are
therefore the reproducible visual authority.

## Product character

The desktop application should look like a mature enterprise network engineer's
session investigation/NOC tool: dark, precise, compact, calm, and data-first.
It must not look like a generic SaaS dashboard, cyberpunk UI, gaming UI, or marketing page.

The HTML export should look like a clean professional investigation report rather than
a clone of the dark desktop shell.

## Hard constraints

- No new Python runtime dependency solely for styling.
- No CDN, remote CSS, remote JS, remote fonts, remote icons, analytics, telemetry, or uploads.
- Do not add PyQt-Fluent-Widgets, qt-material, PyQtDarkTheme, or pyqtgraph for this redesign.
- Existing PySide6 operational widgets should be reused wherever possible.
- Existing 61 Inspector stable IDs remain unchanged.
- Do not change network commands, SSH logic, parsers, storage schema, lifecycle semantics,
  credential policy, export data semantics, cancellation, or recovery behavior.
- Do not fabricate health, reachability, latency, controller counts, events, or timestamps.

## Desktop visual tokens

| Token | Value |
| --- | --- |
| Canvas | `#101720` |
| Surface 1 | `#16212D` |
| Surface 2 | `#1C2937` |
| Surface 3 | `#223243` |
| Border | `#2D4154` |
| Strong border | `#3B556C` |
| Primary text | `#E8EFF6` |
| Muted text | `#91A5B8` |
| Blue accent | `#2F80ED` |
| Cyan/info | `#42B7C8` |
| Success/live | `#2DBE78` |
| Warning/miss | `#E4A83C` |
| Danger/closed | `#E05C65` |
| Terminal | `#0A1118` |
| Terminal text | `#C8D6E2` |

No gradients, glow, glassmorphism, decorative shadows, or animated status effects.

## Desktop shell

Target composition follows the approved mockup:

1. dark application shell;
2. compact product identity and operational status at the top;
3. navigation visually distinct from the work surface;
4. dense main work region;
5. optional darker Raw CLI surface.

The navigation represents only the existing destinations:

- Session Query;
- Device Config;
- History / Export.

A left-rail presentation is preferred when it can be achieved without replacing the
registered `QTabWidget`/`QTabBar` objects. If platform/DPI behavior makes that unsafe,
use a compact dark top navigation that preserves the same visual hierarchy rather than
replacing stable widgets.

## Session Query — before results

Order:

1. `SESSION QUERY` title;
2. Query Flow card;
3. advanced conditions disclosure;
4. session-only credentials;
5. actions;
6. results region.

Query Flow is a condition representation, not a routed topology diagram:

`Source IP[:port]  ↔/→  Destination IP[:port]`

Never imply routers, firewalls, hops, packet path, or physical topology.

Keep exact operational labels required by the repository, including:

- `지속 모니터링 시작`;
- `현재 조회`;
- `고급 조건 보기/숨기기`;
- `상세 정보 보기/숨기기`.

## Session Query — results

The session table is the visual center.

Default hierarchy should emphasize:

- explicit status indicator + text;
- protocol;
- source IP:port;
- direction;
- destination IP:port;
- controller;
- last seen/age when already available;
- flags.

Existing detailed columns remain available through the current progressive disclosure.
Do not remove stored values merely to simplify the default visual state.

A compact metric strip may be shown above the table, but every number must be derived
from existing current/stored state. If a metric is unavailable, omit it or display `—`;
never invent a value to fill a card.

## Session Detail

Selecting a result should reveal an investigation detail area visually similar to the
approved mockup.

It may show, when already available from the selected row/state:

- Source → Destination flow;
- protocol/service label;
- state;
- controller;
- flags;
- packets/bytes/deltas;
- age/CPU;
- existing observation time values.

The existing detail container remains the host for:

- `DETAILS` (new presentation-only summary);
- `RAW CLI` (existing Raw widget);
- `DIAGNOSTICS` (existing diagnostics widget).

Do not replace the existing Raw or diagnostics widgets.

## Raw CLI

Use the deepest dark surface and monospace text. Raw evidence must remain unchanged by
presentation code. Do not reinterpret or rewrite CLI output.

## Device Config

Use a dark engineering form, not a card-heavy dashboard.

Hierarchy:

1. Primary/Standby Mobility Conductor settings;
2. Managed Device dense table;
3. monitoring/timing criteria;
4. save action;
5. credential/privacy notice.

## History / Export

Separate normal actions from destructive actions.

- Refresh and export are normal operations.
- CSV and HTML export should be grouped.
- Selected deletion and especially delete-all belong in a visually separated danger zone.

## Standalone HTML report

HTML remains one self-contained file and does not adopt the desktop dark shell.
Use a light/white print-friendly professional investigation-report layout.

Required structure:

1. Report identity and run status;
2. run timing/query summary;
3. compact high-level counts;
4. query/traffic-flow summary;
5. static full-history IP TOP 5 and protocol/port TOP 5 observation-frequency bars;
6. explicit source/destination counts and a note that charts are independent of filters;
7. latest sessions;
8. complete observation history, collapsed on screen and complete in print;
9. concise footer.

The report must exclude:

- diagnostic messages/codes;
- Raw CLI bodies;
- file paths/hashes;
- credentials;
- logs;
- developer/internal control-flow information.
- session-state summaries and lifecycle/controller event timelines;
- device/controller, diagnostic, cause, or other distribution charts.

The two TOP 5 charts count every stored observation's source and destination once,
exclude blank IPs and port 0, and use deterministic ties. Service names appear only for
known catalogue pairs. Use semantic HTML and CSS horizontal stacked bars; no chart
library, SVG, or additional script is needed.

## HTML security

Keep or strengthen the existing guarantees:

- single HTML file;
- inline CSS;
- only the existing deterministic local filter script if still required;
- exact CSP hash authorization for that script;
- no network requests;
- no browser storage;
- no clipboard API;
- no `eval`;
- no executable device/database markup;
- escaped values;
- responsive layout;
- print layout;
- all stored observations preserved.

## Visual assets and licensing

Preferred option: draw simple UI glyphs with Qt or existing application primitives.
If actual Tabler SVG icons are bundled, use only a small reviewed subset and:

- keep the SVGs local;
- include Tabler Icons MIT copyright/license evidence;
- add the assets to third-party component/static-asset inventory;
- ensure package verification accounts for them.

NetBox, Nautobot, Beszel, Gatus, and Tabler are visual/interaction references only.
Do not copy their application code or CSS wholesale.

## Acceptance criteria

Desktop acceptance:

- clearly dark NOC/engineering appearance matching the reference image's design language;
- existing operational widgets and 61 Inspector IDs still valid;
- 100%, 125%, 150% DPI usable;
- high-contrast fallback remains usable;
- keyboard focus remains visible;
- no external requests introduced;
- 2,000-row live table remains responsive;
- existing tests and new presentation tests pass.

HTML acceptance:

- visually reads as an investigation report;
- report hierarchy above is present where the underlying data supports it;
- complete observations remain present;
- no Raw/diagnostic/private implementation details leak into HTML;
- CSP/offline/no-external-resource tests pass;
- print output remains readable.
