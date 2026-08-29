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

## Information hierarchy

The setup guide appears first only when MM/MD configuration is incomplete.
Advanced conditions, detail columns, Raw CLI, and diagnostics remain progressive
disclosure. The controller/result summary appears immediately above the table.
The table remains dominant, and detail panels stay collapsed by default.

## Table behavior

- Keep all 15 existing columns and their order.
- Keep columns 5–11 hidden until `상세 열 보기` is selected.
- Preserve row-to-raw-line association.
- Do not enable sorting in this stage.
- Use alternating rows and visible selection.
- Preserve Korean interpreted flag and lifecycle text.

## Safety

- Password and Enable-secret echo modes remain password-protected.
- Placeholder examples contain only documentation address ranges.
- No live addresses or credentials are added to source, tests, or design files.
- Preserve the exact labels `지속 모니터링 시작`, `현재 조회`,
  `고급 조건 보기/숨기기`, and `상세 정보 보기/숨기기`.
- No new query, polling, or automatic scan behavior is introduced.
