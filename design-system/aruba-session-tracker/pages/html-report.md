# HTML Result Report — Page Override

This report follows the calm network-operations character in `../MASTER.md`,
but it is a result document rather than an application screen or diagnostic
dashboard.

## Primary task

Let an engineer identify the observed protocol, source IP and port, destination
IP and port, and tracked state with the least possible scanning effort.

## Information hierarchy

1. Compact product masthead and collection state.
2. Query direction plus start/end time and result counts.
3. Local IP, protocol, and port autocomplete filters.
4. Latest 50 logical sessions.
5. Complete stored observation history, collapsed until requested.

Protocol and endpoint columns carry the strongest table emphasis. Device and
time remain present but visually secondary. IPv6 endpoints use `[address]:port`
so the address/port boundary is unambiguous.

## Deliberate exclusions

Do not add packet or byte counters, counter changes, protocol/controller
distribution charts, timelines, significant-event cards, CLI, Raw, diagnostics,
logs, file paths, hashes, troubleshooting guidance, or developer information.
Those values either belong to other export formats or would distract from the
requested IP/protocol/port result.

## Offline and accessibility contract

- One local HTML file with inline CSS and the single CSP-hashed filter script.
- No CDN, remote font, external icon, analytics, storage, clipboard, or network
  request.
- Keep all filter IDs, escaped row `data-*` values, keyboard behavior, latest-50
  policy, and complete history contract.
- Use Korean text for every status so color is only reinforcement.
- Keep forced-colors borders and focus outlines, horizontal table scrolling on
  narrow screens, and the applied-filter summary in print output.
