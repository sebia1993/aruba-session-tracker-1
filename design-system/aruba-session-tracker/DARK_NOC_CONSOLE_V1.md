# Dark NOC Console V1 — Approved Visual Target

This document is the implementation baseline for branch
`design/dark-noc-console-v1`.

## Product split

- **Desktop application:** dark network operations and investigation console.
- **Exported HTML:** light, standalone session investigation report.

Both surfaces must feel authored by a senior network engineer: dense, precise,
quiet, and operational rather than decorative.

## Desktop requirements

1. Preserve the existing `MainWindow`, `QTabWidget`, `QTabBar`, operational
   widgets, callbacks, and all 61 Developer Inspector stable IDs.
2. Present the existing main tabs as a left navigation rail.
3. Reuse the existing product identity frame as a compact top status header.
4. Show only derived or configured facts in the header and KPI strip. Never
   imply MM/MD reachability, packet delivery success, or controller health
   unless the runtime has established that fact.
5. Add a four-card result strip:
   - active logical flows
   - visible result rows
   - changed logical flows
   - distinct controllers represented in visible results
6. Add a selected-session detail page while keeping the existing Raw and
   Diagnostics widgets intact.
7. At wide widths, result grid and detail panel are side by side. At smaller
   supported widths, stack them vertically.
8. Keep the table as the visual center and retain every result column; visual
   reordering and progressive disclosure are allowed.
9. Use no runtime styling dependency beyond PySide6.
10. Keep Qt virtual-method overrides compatible with the pinned PySide6 type
    stubs as well as the runtime's optional widget arguments.

### Desktop tokens

| Purpose | Value |
|---|---|
| Canvas | `#101720` |
| Surface 1 | `#16212D` |
| Surface 2 | `#1C2937` |
| Surface 3 | `#223243` |
| Border | `#2D4154` |
| Strong border | `#3B556C` |
| Primary text | `#E8EFF6` |
| Muted text | `#91A5B8` |
| Operational blue | `#2F80ED` |
| Cyan | `#42B7C8` |
| Success | `#2DBE78` |
| Warning | `#E4A83C` |
| Danger | `#E05C65` |
| Terminal | `#0A1118` |
| Terminal text | `#C8D6E2` |

No gradients, glow, glassmorphism, decorative shadows, animated status, or
fabricated live data.

## HTML report requirements

The report remains a single UTF-8 HTML file containing its own CSS and the
existing deterministic filtering script. It must not load fonts, icons, CSS,
JavaScript, analytics, telemetry, or images from the network.

Required information order:

1. report identity and stored run status
2. timing and query conditions
3. confirmed totals
4. traffic flow
5. session-state summary when derivable from stored facts
6. significant sanitized lifecycle/controller events
7. latest logical sessions
8. complete observation history
9. privacy/footer notice

The traffic-flow panel is the single source of truth for query direction; the
report-basis list must not repeat the same direction fact.

The report may use inline SVG/CSS for a state ring. It must not expose Raw CLI,
diagnostic messages, support internals, filesystem paths, usernames, passwords,
host-key details, or inferred topology. Packet/byte values remain excluded from
the HTML report.

## Reference policy

NetBox, Nautobot, Beszel, Gatus, and Tabler are visual references only. Do not
copy their source or stylesheet wholesale. No GPL UI package may be linked into
the application.

## Implementation map

- `src/aruba_session_tracker/ui/noc_console.py`: presentation controller,
  left navigation, derived status header, KPI strip, and selected-session
  detail composition.
- `src/aruba_session_tracker/ui/theme.py`: local Dark NOC QSS, semantic states,
  high-contrast fallback, table density, and responsive layout rules.
- `src/aruba_session_tracker/storage/html_report_presentation.py`: standalone
  investigation report structure, inline state ring, sanitized event timeline,
  latest sessions, and streaming observation history.
- `src/aruba_session_tracker/storage/__init__.py`: compatibility wiring that
  keeps the existing public report API and `SessionStore` call path intact.
- `tests/test_theme.py` plus the existing HTML, storage, UI, security, and
  packaging suites: regression and acceptance coverage.

No third-party UI runtime, remote asset, font package, icon package, or web
service was introduced by this implementation.

## Acceptance

- Existing functional behavior and Inspector IDs remain intact.
- Qt high-contrast fallback remains usable.
- Desktop QSS contains no URL.
- HTML remains deterministic and self-contained.
- Source files are stored in canonical Ruff format before CI validation.
- Pinned Ruff and mypy validation passes against the Windows build environment.
- Existing security, storage, parser, shutdown, and packaging tests continue to
  pass.
