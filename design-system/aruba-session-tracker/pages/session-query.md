# Session Query — Page Override

This page follows `../MASTER.md`. The following rules are specific to the
high-frequency session-query workflow.

## Primary task

Locate a client through Mobility Conductor, query only the relevant managed
device session rows, and inspect interpreted status plus raw evidence without
changing Aruba configuration.

## Action hierarchy

- `지속 모니터링 시작`: primary and default.
- `현재 조회`: secondary one-time action.
- `중지`: strong danger; disabled when no work can be stopped.

The state pill must remain adjacent to the action row and use only the fixed
operator vocabulary: `대기`, `조회 중`, `정상`, `재시도 중`, or `확인 필요`.
The presentation-only state role may reinforce those states with neutral, blue,
green, amber, and red styling respectively, but the text never disappears.

## Information hierarchy

The setup guide appears first only when MM/MD configuration is incomplete. The
source/destination flow and current-run login information share one compact
horizontal work area, with the flow shown first. Separate SOURCE and DESTINATION
cards retain visible Korean labels, and the center cue changes between
`양방향 조회` and `입력 방향 조회` with the existing bidirectional setting.
Advanced conditions, detail columns, Raw CLI, and diagnostics remain
progressive disclosure. The controller/result summary appears immediately above
the table. The table remains dominant, and detail panels stay collapsed by
default.

The empty result state explains the next action. It is hidden while the Raw or
diagnostic panel is open because that panel becomes the active evidence surface.
Expanded evidence stacks below the table in the standard workspace and switches
to a side-by-side splitter below 760 logical pixels of window height or whenever
advanced conditions are expanded, so the supported minimum workspace preserves
at least a usable table viewport.

## Table behavior

- Keep all 15 existing columns and their order.
- Use Korean display labels for the operational columns without changing their
  index, raw association, stored values, or export formats.
- Keep columns 5–11 hidden until `상세 열 보기` is selected.
- Preserve row-to-raw-line association.
- Do not enable sorting in this stage.
- Use alternating rows and visible selection.
- Preserve Korean interpreted flag and lifecycle text.

## Safety

- Password and Enable-secret echo modes remain password-protected.
- Placeholder examples contain only documentation address ranges.
- No live addresses or credentials are added to source, tests, or design files.
- Require at least one of the source or destination IPv4 fields. Treat an empty
  endpoint as a wildcard during local filtering; an optional port on that side
  remains an independent constraint.
- When bidirectional search is enabled, swap the entered IP and port constraints
  together. Every MM and MD command must still contain an explicitly entered,
  validated IPv4 filter.
- Preserve the exact labels `지속 모니터링 시작`, `현재 조회`,
  `고급 조건 보기/숨기기`, and `상세 정보 보기/숨기기`.
- Do not introduce an unfiltered query or an unapproved automatic scan.
