# HTML Result Report — Page Override

This report follows the calm network-operations character in `../MASTER.md`,
but it is a result document rather than an application screen or diagnostic
dashboard.

## Primary task

Let an engineer identify the observed protocol, source IP and port, destination
IP and port, and tracked state with the least possible scanning effort.

## Information hierarchy

1. Compact product masthead and stored run state.
2. Query direction, start/end time, duration, and confirmed counts.
3. Latest-displayed session-state summary and recent stored-fact timeline,
   with their snapshot scope stated explicitly.
4. Local IP, protocol, and port autocomplete filters.
5. Latest 50 logical sessions.
6. Collection information derived only from report observations.
7. Complete stored observation history, collapsed until requested.

The filter is a secondary surface rather than another primary dashboard card.
Each result count sits beside its own section heading, and the latest-results
note updates when filters are active, including a clear no-match state. Between
361 and 520 CSS pixels the controls use two columns with full-width IP and reset
rows; at 360 pixels and below they use one column. Status badges retain text and
visible boundaries in addition to color.

Protocol and endpoint columns carry the strongest table emphasis. Device and
time remain present but visually secondary. IPv6 endpoints use `[address]:port`
so the address/port boundary is unambiguous.

## Deliberate exclusions

Do not add packet or byte counters, counter changes, protocol/controller
distribution charts, CLI, Raw, diagnostics, logs, file paths, hashes,
troubleshooting guidance, or developer information. A compact state summary
and recent-event timeline are allowed only from sanitized facts already present
in the bounded report snapshot. They must not claim complete event coverage or
infer health, reachability, failover, outage, cause, or packet path.

## Offline and accessibility contract

- One local HTML file with inline CSS and the single CSP-hashed filter script.
- No CDN, remote font, external icon, analytics, storage, clipboard, or network
  request.
- Keep all filter IDs, escaped row `data-*` values, keyboard behavior, latest-50
  policy, and complete history contract.
- Use Korean text for every status so color is only reinforcement.
- Keep forced-colors borders and focus outlines, horizontal table scrolling on
  narrow screens, and the applied-filter summary in print output.
