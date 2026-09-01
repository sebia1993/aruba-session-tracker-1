# UI implementation instructions

The approved visual baseline for this directory is
`design-system/aruba-session-tracker/DARK_NOC_CONSOLE_V1.md`.

- Preserve every operational widget and Developer Inspector stable ID.
- Do not replace `MainWindow`, its main `QTabWidget`, its `QTabBar`, result
  table, Raw widget, diagnostics widget, settings controls, or history controls.
- Presentation-only widgets may be added and existing containers may be
  reparented when object identity and behavior remain intact.
- Derive all NOC metrics from existing configured or observed data. Never
  fabricate reachability, latency, health, or traffic success.
- Keep all resources local. Do not add a theme framework, web view, remote icon,
  CDN, font download, telemetry, or analytics.
- Keep keyboard focus, Windows high-contrast behavior, 100/125/150% DPI, and
  minimum-window layout usable.
- Dark NOC Console V1 supersedes the former light-canvas visual direction for
  this branch only.
