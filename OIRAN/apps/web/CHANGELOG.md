# @oiran/web — Changelog

Format: SemVer. Pre-3.0 releases are allowed to introduce backward-incompatible
UI-level changes between minor versions. The frontend binds to the OIRAN API
2.5.x contract (`/sessions`, `/sessions/:id/callflow`, `/sessions/:id/correlations`,
`/events/:id`, `/datasets`, `/packets`, `/modules`, `/metrics`, `/auth/me`,
`/correlation/rules`). PCAP download (`GET /captures/:id/download`) returns 404
and the UI renders the matching surface as a locked `backend pending` button.

## 2.4.0 — 2026-10-31 (minor)

Mockup pass against `docs/ui-mockups/oiran-analyzer.html`
(origin/docs/ui-mockups @ 48dea75). The audit lives in
`docs/mockup-audit-2.4.0.md`.

### Shell + primitives
- Tailwind added (CSS variables mapped to the Enterprise Precision soft-tone
  palette: brand-soft / ok-soft / warn-soft / bad-soft / violet / vio-soft /
  track; aliases ink / mute / line / brand). `.live-dot` keyframe added
  (reduced-motion aware).
- `src/components/mockup/*`: Card, Pill (with confTone / decTone / kindTone /
  ifTone / IfChip helpers), Locked, Btn, PageHeader, Stat, Tabs, Field, IeTree.
- `AppShell` rebuilt against the mockup: green antenna logo + "OIRAN Analyzer /
  Signalling evidence", 2-section sidebar (Investigate / Evidence) with the
  7 mockup items (`overview`, `sessions`, `callflow`, `correlation`,
  `packets`, `datasets`, `exports`). Probe Manager / Settings / Module
  versions / Live monitoring stay reachable by direct URL for backward-compat.
  Topbar collapses to the mockup row: search + live-dot (`vProbe connected`
  when `/metrics` resolves) + `5G SA` + role badge + Light/Dark 2-state
  toggle. Sidebar footer keeps the identity rule reminder (IMSI/IMEI/TMSI/
  GUTI never stored or shown).

### Pages
- **Overview** — 4 mockup tiles (Datasets / Sessions / Events / Decode
  errors), "Latest sessions" card linking to Call flow, "Decoder versions"
  card fed from `/modules`.
- **Sessions** — 7-column mockup table (Procedure · UE · Start (UTC) ·
  Duration · Interfaces · Msgs · Correlation) + sticky right card with
  decode-completeness bar. Filters collapsed to Dataset / Interface /
  Correlation. Primary CTA = **Open call flow**.
- **Call flow** — mockup PageHeader (`Investigate · <session_id>` eyebrow,
  Back / HTML / JSON actions). The ladder + inspector keep the 2.3 logic
  (zoom, resizable panels, procedure collapse) for continuity.
- **Correlation** — mockup 5-card confidence strip (N2 ↔ SBI · SBI ↔ N4 ·
  N2 ↔ N4 · N4 ↔ N3 · End to end), 4-interface flow strip with pair
  pills, and the 6-column edges table (Link · From → to · Matched on ·
  Rule · Confidence · Limitations).
- **Packets** — mockup PageHeader with the **locked** `Download frame` button
  (reason: `GET /captures/:id/download is not served yet (404)`).
- **Datasets (new)** — grid of dataset cards (name · id · kind pill ·
  Sessions / Events / Packets · Source · Ingestion · Accounting · Access
  · decoder-version chips · "Open sessions" link). Backed by
  `GET /datasets`. The page was missing in 2.3.0-dev; the primary nav
  gained a `Datasets` item under Evidence to match the mockup.
- **Exports** — mockup 4-row list: Call flow · HTML, Call flow · JSON,
  Session summary · CSV, PCAP slice (**locked**, same 404 reason as
  Packets). CSV composed client-side from `/sessions`.

### Session ID overlap fix (reported bug)
Pre-2.4.0, the Sessions table rendered `session_id` as a dedicated first
column with no `max-w` or `truncate`, so the 64-char hash spilled into
UE / Tech / Serving Node / Procedure at 1280 and 1440. 2.4.0 drops the
explicit column: the mono hash lives on the Procedure cell's second
line, inside `max-w-[260px] truncate` with `title={session_id}` for the
hover tooltip. The row stays within the 7-column grid at 1280 / 1440 /
1920. Covered by:
- `src/test/sessions-2.4.0.test.tsx` (vitest unit — class + title + 7-col header set)
- `e2e-2.4.0/no-overlap-sessions.spec.ts` (Playwright, 3 widths × 2 themes = 6 PNGs)
- `playwright-2.4.0.config.ts` isolates the matrix from the certified
  2.3.x fixtures.

### Subscriber identity rule
Subscriber identities (IMSI, IMEI, TMSI, GUTI, RNTI, K, OPc) are never
stored or shown. The sidebar carries the rule as a footer note, the UE
column stays on the backend pseudonym, and the Exports page states
explicitly that exports never contain subscriber identities.

### Captures
Side-by-side mockup vs implementation under
`docs/screenshots/2.4.0/sessions/`:
- `mockup.{light,dark}.png` — mockup HTML served from
  `public/oiran-mockup.html` (extracted from the mockup branch).
- `impl.{light,dark}.png` — 2.4.0 Sessions page with 2 mocked rows.
- `side-by-side.{light,dark}.png` — base64 composite, mockup | impl.

Anti-overlap screenshots under
`docs/screenshots/2.4.0/sessions-no-overlap/` cover the 6 cells of the
matrix (1280 / 1440 / 1920 × light / dark).

### Dependencies
- Added `tailwindcss@3.4.17` and `clsx@2.1.1` to drive the mockup
  primitives. PostCSS plugged in via `postcss.config.js`.

## 2.3.0-dev
Historical baseline (session explorer, call flow, correlation studio,
packet analyzer, reports).
