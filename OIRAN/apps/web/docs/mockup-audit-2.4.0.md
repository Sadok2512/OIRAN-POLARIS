# OIRAN Analyzer — mockup audit 2.4.0

**Base**: `d924c35` (OIRAN/apps/web `2.3.0-dev`)
**Mockup**: `origin/docs/ui-mockups @ 48dea75` — `docs/ui-mockups/oiran-analyzer.html`
**Date**: 2026-10-30

Target: reproduce `oiran-analyzer.html` faithfully in `OIRAN/apps/web/`, wire
every screen to the real OIRAN 2.5.x endpoints (`/sessions`,
`/sessions/:id/callflow`, `/events/:id`, `/datasets`, `/packets`, …), and lock
anything the backend does not serve (`/captures/:id/download` = 404) with the
"backend pending" chip. Subscriber identities (IMSI, IMEI, TMSI, GUTI, RNTI)
stay write-only — never surfaced in the UI.

## 0. Shell

| Zone | Mockup | Actuel | Écart |
|---|---|---|---|
| Logo | Green antenna glyph in bg-ok square + "OIRAN Analyzer" + "Signalling evidence" | `RadioTower` icon + "OIRAN" + "Signaling Intelligence" | **Align logo and tagline to the mockup** |
| Sidebar sections | 2 sections — `Investigate` / `Evidence` — in that order | Dynamic sections from `/modules` (`CAPTURE & ANALYSIS`, `REPORTS`, `SYSTEM`) | **Collapse to 2 mockup sections**; keep `/platform/*` + `/reports/monitoring` reachable by URL for backward-compat |
| Sidebar items | 7 items: `overview / sessions / callflow / correlation / packets / datasets / exports` | 10 items (includes Probe Manager, Live Monitoring, Settings, Module Versions) | **Hide Probe Manager / Settings / Module Versions / Live Monitoring from the primary nav**; keep routes alive |
| Footer note | Shield + "Subscriber identities (IMSI, IMEI, TMSI, GUTI) are never stored or shown." | Already present | ✓ keep |
| Topbar left | Search box (session id / UE pseudonym / procedure) | Search present | ✓ |
| Topbar right | `vProbe connected` live-dot + `5G SA` + `Example data` chip + Light/Dark toggle | Richer: disk / cpu / ram summary + 3-state theme toggle | **Replace with the mockup 4-item row**; keep metrics behind `/reports/monitoring` |
| Theme toggle | 2-state (Light/Dark) | 3-state (Light/Dark/System) | **Collapse to 2-state** |
| Palette | Enterprise Precision + soft tones + violet + track | Enterprise Precision only, no soft tones | **Extend tokens: `brand-soft`, `ok-soft`, `warn-soft`, `bad-soft`, `vio` + `vio-soft`, `track`, aliases `ink`, `mute`, `line`, `brand`** |
| `.live-dot` keyframe | Required | Not present | **Add** |

## 1. Overview

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Investigate` · `Overview` · "Datasets, reconstructed sessions and decode quality across everything the probes have captured." | Different (OIRAN system health copy) | **Align copy** |
| Stat grid | 4 tiles: Datasets · Sessions · Events · Decode errors | 8 infra tiles | **Collapse to the 4 mockup tiles**; derive from `/datasets`, `/sessions`, `/events` or `/metrics` |
| "Latest sessions" card | List of 4 latest sessions with procedure + session_id + interfaces chips + start-of-day timestamp + correlation Pill | Not present (shown as metrics strip) | **Add** |
| "Decoder versions" card | 2-col dl of NGAP, NAS-5GS, PFCP, SBI, GTP-U, Session engine versions | Not present | **Add** — fed from `/modules` |

## 2. Sessions

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Investigate` · `Sessions` · "UE contexts and PDU sessions reconstructed from the captured signalling. UEs appear only as pseudonyms." | Different | **Align copy** |
| Header action | `Open call flow` primary (icon = flow) | Varies | **Add primary CTA** |
| Filters | 3 selects: Dataset / Interface / Correlation | More filters | **Collapse to the 3 mockup selects** (keep search in topbar) |
| Columns | 7 cols: Procedure · UE · Start (UTC) · Duration · Interfaces · Msgs · Correlation | 13 cols (Session ID + UE + Tech + Node + Procedure + PDU ID + …) | **Rebuild as the 7 mockup columns**; Procedure cell carries the Session ID + Node on a mono mute sub-line — SOLVES the Session ID overlap bug (truncate hash + hover tooltip) |
| Session cell | `max-w-[260px]` + truncate + title | Full-width mono hash leaks into neighbour cols | **Fix overlap**: `max-w-[260px]` + `truncate` on Procedure cell, mono sub-line truncates with `title={id}` |
| Right card | Sticky `xl:top-4` session detail with decode-completeness bar (decoded / partial / NAS protected) | Richer tabs | **Compact to mockup card**; keep rich tabs reachable from "Call flow" button |
| Pagination | Shown bottom of the card | Present | ✓ |

**Anti-overlap test** (new): widths 1280 / 1440 / 1920 × light + dark. Session ID
mono hash is kept inside `max-w-[260px] truncate` + `title`. The row never bleeds
into UE / Start / Interfaces.

## 3. Call flow

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Investigate · <session_id>` · `Call flow` · descriptive sub | Different | **Align copy** |
| Header actions | `Back to session` + `HTML` + `JSON` download buttons | Export buttons present | ✓ keep, swap to mockup Btn |
| Toolbar | Search message + 4 interface pill toggles (N2/SBI/N4/N3) + correlation summary (4 pairs) | More controls | **Collapse to the mockup trio** |
| Ladder | 4 participants (gNB/AMF/SMF/UPF), colored arrows per interface, procedure headers, timestamp mute sub | Interactive, zoomable | **Simplify to mockup style**; keep zoom behind a settings menu |
| Inspector | Sticky right card, tabs IEs / Correlation · n / Provenance, withheld-identity badge, decoded-status pill | Rich tabs | **Collapse to the 3 mockup tabs** |

## 4. Correlation

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Investigate · <session_id>` · `Correlation` | Different | **Align copy** |
| Top grid | 5 cards: `N2 ↔ SBI`, `SBI ↔ N4`, `N2 ↔ N4`, `N4 ↔ N3`, `End to end` with confidence pills | Different layout | **Rebuild to the 5-card strip** |
| Flow strip | 4 interface tiles + 3 confidence links between | Not present | **Add** |
| Edges table | 6 cols: Link / From → to / Matched on / Rule / Confidence / Limitations | Different | **Rebuild to the 6 mockup columns** |

## 5. Packets

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Evidence` · `Packets` · "Every decoded frame with its exact position in the source capture. Raw bytes are not shown in the analyzer." | Different | **Align copy** |
| Table | 7 cols: Frame · Time · Interface · Path · Message · Length · Decode | Different | **Rebuild to the 7 mockup columns** |
| Right card | Sticky Frame detail + IE tree + `Show in call flow` + locked `Download frame` (reason: `GET /captures/:id/download = 404`) | No download button at all | **Surface the locked button** per audit §9 (be transparent about backend-pending) |

## 6. Datasets

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Entire page | Grid of dataset cards | **MISSING** — no route, no component | **Create `/datasets` route + Datasets page** |
| Card content | Name + id + kind pill + Sessions/Events/Packets dl + Source + Ingestion + Accounting + Access + decoder-version chips + "Open sessions" link | n/a | **Build card from `/datasets` payload** |

## 7. Exports

| Bloc | Mockup | Actuel | Écart |
|---|---|---|---|
| Eyebrow / title / desc | `Evidence` · `Exports` · "Take evidence out of the analyzer. Exports never contain subscriber identities." | Different | **Align copy** |
| List | 4 rows: Call flow HTML, Call flow JSON, Session summary CSV, PCAP slice (locked) | Per-session cards | **Rebuild to the mockup 4-row list**; locked PCAP references `GET /captures/:id/download` 404 |

## 8. Backend reality (per mockup README)

- **Real**: `/sessions`, `/sessions/:id/callflow`, `/events/:id`, `/datasets`, `/packets`.
- **Locked**: `/captures/:id/download` returns 404 → PCAP slice export + per-frame download render as `Locked` with the exact reason.
- **Identity rule**: never surface IMSI / IMEI / TMSI / GUTI / RNTI / K / OPc. Call flow inspector keeps the mockup's "N identity IEs withheld" badge.

## 9. Session ID overlap (reported bug)

Current (`SessionExplorer.tsx`):
- Session ID is the first column, mono, full-width (no `max-w`, no `truncate`).
- At 1280 the 64-char hash spills into UE / Tech / Node cells.

Fix in 2.4.0 (per mockup):
- Procedure cell carries Session ID as a mono mute sub-line, inside a
  `max-w-[260px]` wrapper with `truncate` + `title={session_id}` (hover reveals
  the full identifier). Row stays within the 7-column grid at 1280 / 1440 /
  1920. Covered by `e2e/no-overlap-sessions-2.4.0.spec.ts`.

## 10. Reproduction plan

1. **Branch**: `feat/oiran-analyzer-2.4.0-mockup` from `d924c35`.
2. **Primitives** in `src/components/mockup/`: `Pill`, `Locked`, `Btn`,
   `Card`, `PageHeader`, `Stat`, `IfChip`, `Tabs`, `Field`, `IeTree`.
3. **Tokens**: extend `src/styles/globals.css` with the mockup soft tones +
   violet + track + `.live-dot`. Extend `tailwind.config.*` with the
   `ink`/`mute`/`line`/`brand`/`ok`/`warn`/`bad`/`vio`/`track` aliases.
4. **Shell**: rework `AppShell.tsx` sidebar (2 sections, 7 items, green
   antenna logo), topbar (search + vProbe live-dot + 5G SA + Example data +
   Light/Dark 2-state toggle), footer identity note.
5. **Pages**: rebuild each screen in order Overview → Sessions → Call flow →
   Correlation → Packets → Datasets (new) → Exports. Wire every section to
   the real OIRAN 2.5.x endpoints.
6. **Session ID fix**: Procedure cell + mono sub-line + truncate + title.
7. **Captures**: Playwright side-by-side mockup/impl at 1440 light + dark.
8. **Anti-overlap**: 1280 / 1440 / 1920 × light + dark.

— BC3
