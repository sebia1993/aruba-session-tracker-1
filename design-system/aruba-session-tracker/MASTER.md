# Aruba Session Tracker — UI Design System

## 1. Scope and source of truth

This document is the visual and interaction source of truth for the Windows 11
PySide6 interface. It applies to the three operational screens:

- Session Query
- Device Settings
- History and Export

The direction synthesizes UI UX Pro Max guidance for an analytics dashboard,
productivity tool, and developer/operations console. Repository safety rules,
read-only Aruba behavior, credential handling, and the exact Developer
Inspector catalog always take precedence over visual guidance.

## 2. Product character

**Product type:** internal network operations and troubleshooting tool  
**Primary user:** network engineer operating Aruba AOS 8 Mobility Conductor and
7240XM managed devices  
**Usage context:** long desktop sessions, dense tabular data, time-sensitive
troubleshooting, and potentially sensitive device/session metadata

The interface should feel:

- operational rather than promotional;
- precise rather than decorative;
- dense but not cramped;
- calm during normal work and unmistakable during destructive or failed states;
- native to a Windows desktop workflow.

## 3. Design principles

### 3.1 Data first

The session table, controller context, diagnostics, and Raw CLI are the visual
center of gravity. Decoration must never compete with operational data.

### 3.2 State must be explicit

Color may reinforce state but cannot be the only carrier of meaning. Every
normal, running, uncertain, failed, stopped, and destructive state retains a
clear Korean text label.

### 3.3 Actions have a hierarchy

- **Primary:** start continuous monitoring; open required device settings; save device settings.
- **Secondary:** run a one-time current query, refresh, and export.
- **Danger:** stop running work or delete selected history.
- **Strong danger:** delete all history.

A screen should have no more than one visually dominant primary action in the
user's immediate decision area.

### 3.4 Safe by default

Visual refactoring must not change command builders, SSH behavior, parsers,
storage, export formats, credential lifetime, approval dialogs, or the F12
Developer Inspector boundaries.

### 3.5 Stable desktop density

The application targets Windows 11 at 100%, 125%, and 150% scaling. Use compact
controls with sufficient hit area, predictable tab order, visible keyboard
focus, and text that can expand without clipping.

## 4. Visual direction

**Style:** restrained enterprise operations console  
**Pattern:** data-dense dashboard with progressive detail  
**Mode:** light operational canvas with a dark Raw CLI surface  
**Motion:** none beyond native Qt state feedback  
**Variance:** low  
**Density:** high

Dark mode is not the default because this tool is expected to coexist with
other Windows operations applications and printed/exported evidence. The Raw
CLI panel uses a dark terminal treatment to distinguish unstructured device
output from structured application data. When Windows starts with a high-contrast
palette, the theme switches its surfaces, selection, focus, and controls back to
native `QPalette` roles instead of forcing the normal light tokens.

Avoid:

- glassmorphism, gradients, neon, glow, or decorative shadows;
- animation that delays state feedback;
- icon-only operational actions;
- hidden labels or placeholder-only forms;
- color-only status meaning;
- oversized marketing-style typography;
- arbitrary restructuring of stable widgets and Inspector IDs.

## 5. Color tokens

| Token | Value | Use |
|---|---:|---|
| `canvas` | `#F3F6F9` | application and tab-page background |
| `surface` | `#FFFFFF` | groups, tables, detail panels |
| `surface-muted` | `#E8EEF4` | headers, inactive tabs, status bar |
| `border` | `#CBD5E1` | normal boundaries |
| `border-strong` | `#AEBCCA` | form and data boundaries |
| `text` | `#0F172A` | primary text |
| `text-muted` | `#475569` | secondary text |
| `primary` | `#0B5F9A` | primary operational action |
| `primary-hover` | `#084F82` | primary hover state |
| `focus` | `#1976B9` | visible keyboard focus |
| `selection` | `#CFE4FA` | table/list selection |
| `warning-bg` | `#FFF8E7` | privacy and caution notice |
| `warning-border` | `#E7C978` | caution boundary |
| `danger` | `#B42318` | stop and destructive action |
| `terminal-bg` | `#111C27` | Raw CLI surface |
| `terminal-text` | `#DCE7F2` | Raw CLI text |
| `state-success` | `#0B5D46` | 정상 상태 텍스트 |
| `state-warning` | `#765000` | 재시도 상태 텍스트 |
| `state-danger` | `#981B1B` | 확인 필요 상태 텍스트 |

All normal text/background pairs must target at least WCAG AA contrast. Field
validation on real Windows high-contrast mode remains required because Qt style
sheet behavior can vary by platform theme.

## 6. Typography

- UI family: `Malgun Gothic`, 9 pt default.
- Raw CLI family: `Consolas`.
- Group titles, selected tabs, primary buttons, and table headers use weight
  rather than size jumps to establish hierarchy.
- Do not use body text below 9 pt.
- Do not introduce external fonts or runtime font downloads.

## 7. Spacing and geometry

Base spacing unit: **4 px**.

- Page margin: 18 px horizontal, 14–18 px vertical.
- Major section gap: 12 px.
- Group content gap: 10 px.
- Input and button minimum height: 32 px.
- Main tab minimum height: 34 px.
- Table row target: 30 px.
- Radius: 6–8 px; status pill: 13 px.

Spacing may increase at higher DPI through Qt scaling; fixed pixel values must
be checked at 100%, 125%, and 150% rather than assumed to be physical pixels.

## 8. Component rules

### 8.1 Tabs

The three main tabs are peer-level operational destinations on a compact navy
operations bar. Selected state uses text weight, a light underline, and surface
change—not color alone. The right side carries the product name, current
version, local-only boundary, and read-only-query boundary without adding a
second navigation row. Detail tabs are visually subordinate to the main
navigation. The setup guide remains the first visible recovery path when MM/MD
targets have not yet been configured.

### 8.2 Group boxes

Group boxes act as white operational cards. Titles describe task boundaries,
not decorative sections. Existing Korean titles remain authoritative.

### 8.3 Inputs

- Persistent labels remain visible.
- Placeholder text is example/help content only.
- Focus uses a 2 px blue border.
- Disabled fields use muted text and surface colors.
- Password echo behavior remains unchanged.

### 8.4 Buttons

Dynamic property mapping:

| `buttonRole` | Meaning |
|---|---|
| `primary` | continuous monitoring, open required settings, save settings |
| `secondary` | one-time current query, refresh, export |
| `danger` | delete selected history |
| `dangerStrong` | stop work, delete all history |

Operational actions retain text labels. Hover, pressed, focus, checked, and
disabled states must remain distinguishable. `지속 모니터링 시작` remains the
default primary action; `현재 조회` remains a secondary one-time action.

The operator-state label uses a separate presentation-only `stateRole` while
always retaining the fixed Korean text:

| `stateRole` | Text |
|---|---|
| `neutral` | `대기` |
| `active` | `조회 중` |
| `success` | `정상` |
| `warning` | `재시도 중` |
| `danger` | `확인 필요` |

### 8.5 Tables

- Use alternating rows and a quiet horizontal separator.
- Remove decorative grid noise and vertical headers.
- Keep row selection explicit.
- Do not enable sorting unless selection-to-raw-data mapping is verified.
- Do not truncate status meaning without a full-value access path.
- Existing column order, data, and stored values remain unchanged. User-facing
  headers use clear Korean labels such as `장비`, `프로토콜`, `출발지 IP`, and
  `목적지 IP` instead of mixed English abbreviations.

### 8.6 Raw CLI and diagnostics

Raw CLI uses a dark monospace terminal surface. Diagnostics stays on a light
surface because it contains interpreted application events. Switching between
the two must not clear content or change storage behavior.

### 8.7 Notices

Credential/privacy and data-retention notices use a warm caution surface. They
are informational, not error states, and therefore must not use danger red.

### 8.8 Destructive actions

Selected-record deletion is outlined danger. Stop and delete-all are filled
strong danger because impact is immediate or broad. Existing confirmation
messages and safe default buttons remain unchanged.

## 9. Screen hierarchy

### Session Query

1. Setup guide when required.
2. Source/destination conditions and session-only credentials in one compact
   two-column work area. Source and destination use separate endpoint cards
   with an explicit direction label between them.
3. Progressive advanced conditions.
4. Continuous monitoring, one-time current query, stop, and current state.
5. MM/MD and result-count summary plus progressive detail controls.
6. Session table.
7. Raw CLI and diagnostics when explicitly expanded.

At the default 1320×820 workspace, expanded evidence sits below the result
table. Below 760 logical pixels of window height, or while advanced conditions
are expanded, it moves beside the result table so the supported 1080×680
workspace retains a usable grid. When evidence is open, its diagnostics replace
the redundant empty-state banner rather than collapsing the table viewport.

### Device Settings

1. Mobility Conductor targets.
2. Managed-device targets.
3. Monitoring timing.
4. Save action and credential-storage notice.

The credential-storage notice spans the page below the save action so its text
does not collapse into a narrow corner.

### History and Export

1. Refresh/export actions on the left.
2. Selected and global deletion actions on the right, visually separated by
   spacing, section labels, and danger level.
3. Run history table.
4. plaintext retention warning.

Export and selected-delete actions remain disabled until a row is selected;
delete-all remains disabled when no rows exist. Empty history uses a concise
instructional state instead of an unexplained blank grid.

## 10. Accessibility and resilience checklist

- [ ] All interactive controls remain reachable in logical Tab order.
- [ ] Focus is visible on inputs, buttons, tabs, tables, and lists.
- [ ] Status and severity meaning is present in text, not color alone.
- [ ] Labels remain visible when fields contain values.
- [ ] Dialog default actions stay conservative for trust and deletion flows.
- [ ] No operational action depends only on hover.
- [ ] Korean labels and long device names do not clip at 125%/150% scaling.
- [ ] Windows high-contrast mode is manually checked.
- [ ] Operator state remains one of `대기`, `조회 중`, `정상`, `재시도 중`, or `확인 필요`.
- [ ] Exact progressive labels remain `고급 조건 보기/숨기기` and `상세 정보 보기/숨기기`.
- [ ] F12/Fn Lock and Inspector click blocking are manually checked.
- [ ] Multiple-monitor scaling is manually checked.

## 11. Implementation boundary

The theme is applied after `MainWindow` construction so it supersedes the
legacy local QSS while preserving all existing widget objects and callbacks.
Only presentation properties, spacing, placeholders, user-facing table labels,
display-only status translation, and object names used solely for QSS are
changed. Stored run status codes remain unchanged and are available from the
status-cell tooltip.

The following must remain unchanged:

- all 61 registered Developer Inspector stable IDs and category counts;
- network command allowlist and read-only behavior;
- MM/MD discovery, SSH, parser, tracker, and monitoring logic;
- credentials-in-memory policy;
- SQLite, Raw TXT, CSV, and HTML export semantics;
- existing public widget attributes used by tests;
- confirmation and failure sanitization boundaries.
