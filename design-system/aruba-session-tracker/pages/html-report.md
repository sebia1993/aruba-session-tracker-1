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
3. Static full-history `IP별 관측 횟수 TOP 5` and
   `포트·프로토콜별 관측 횟수 TOP 5` source/destination bars.
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

Do not add packet or byte counters, counter changes, device/controller or diagnostic
distribution charts, CLI, Raw, diagnostics, logs, file paths, hashes,
troubleshooting guidance, or developer information. Do not present a session-state
summary or lifecycle/controller event timeline. The only charts are the two approved
full-history TOP 5 summaries. Count each observation's source and destination once,
exclude blank IPs and port 0, resolve ties deterministically, and show a service name
only for a catalogue-known protocol/port pair. The charts are not linked to filters and
must not infer health, reachability, failover, outage, cause, path, traffic, or volume.

## Offline and accessibility contract

- One local HTML file with inline CSS and the single CSP-hashed filter script.
- No CDN, remote font, external icon, analytics, storage, clipboard, or network
  request.
- Keep all filter IDs, escaped row `data-*` values, keyboard behavior, latest-50
  policy, and complete history contract.
- Use Korean text for every status so color is only reinforcement.
- Keep forced-colors borders and focus outlines, horizontal table scrolling on
  narrow screens, and the applied-filter summary in print output.
- Keep chart meaning in visible text, mark decorative bars as hidden from assistive
  technology, and preserve the two-column/one-column chart layout in print/mobile.
