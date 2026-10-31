# @oiran/web — Changelog

Format: SemVer. Pre-release suffix `-dev` indicates this is cut from main.

## 2.5.0 — 2026-10-31 (minor)

Mockup pass against `docs/ui-mockups/oiran-analyzer.html`
(origin/docs/ui-mockups @ 48dea75), rebased **on top of**
`origin/integ/oiran-2.5.2-atomic-publish` so the three LOT 0 / 3 /
BC4 commits (b734662, 562ed77, 62b6079) stay in the ancestry.
`git merge-base --is-ancestor 62b6079 HEAD` → true.

### Shell + primitives
- Tailwind 3.4.17 + Enterprise Precision soft-tone palette (brand-soft,
  ok-soft, warn-soft, bad-soft, violet / vio-soft, track); aliases ink
  / mute / line / brand. `.live-dot` keyframe (reduced-motion aware).
- `src/components/mockup/*`: Card, Pill (with `confTone` / `decTone` /
  `kindTone` / `ifTone` / `IfChip` helpers), Locked, Btn, PageHeader,
  Stat, Tabs, Field, IeTree.
- `AppShell` rebuilt against the mockup: green antenna logo + "OIRAN
  Analyzer / Signalling evidence", 2-section sidebar (Investigate /
  Evidence) with the 7 mockup items. Probe Manager / Settings /
  Module versions / Live monitoring stay reachable by direct URL —
  the LOT 3 section mapping (b734662 / 562ed77) is preserved.
- Topbar collapses to the mockup row: search + vProbe live-dot +
  5G SA + role badge + Light/Dark 2-state toggle. Sidebar footer
  carries the identity rule reminder (IMSI/IMEI/TMSI/GUTI/RNTI
  never stored or shown).

### Pages
- **Overview** — 4 mockup tiles (Datasets / Sessions / Events / Decode
  errors), "Latest sessions" card linking to Call flow, "Decoder
  versions" card fed from `/modules`.
- **Sessions** — 7-column mockup table (Procedure · UE · Start (UTC) ·
  Duration · Interfaces · Msgs · Correlation) + sticky right card with
  decode-completeness bar. **Honesty gates kept** (session-context
  tests): /captures/:id/context `DATASET_UNAVAILABLE` → full-page
  error, zero-session empty state, categorised dataset filter with
  `scope:HISTORICAL / CAPTURED_LIVE / RECOVERED / DERIVED` buckets.
- **Call flow** — mockup PageHeader (eyebrow `Investigate ·
  <session_id>`, Back + HTML + JSON + Download frame locked + PCAP
  slice locked). The ladder + inspector logic from 2.3 / LOT 3 stays
  unchanged (zoom, resizable panels, procedure collapse, synchronised
  arrow/row selection, `withholdIdentity()` on IE trees).
- **Correlation** — mockup 5-card confidence strip + 4-interface flow
  strip + 6-column edges table.
- **Packets** — mockup PageHeader with the locked `Download frame`
  (reason: `GET /captures/:id/download is not served yet (404)`).
  **`withholdIdentity()` kept** (BC4 / 62b6079): the Fields tab routes
  `packet.information_elements` through the matcher and renders the
  `data-testid="packet-identity-withheld-banner"` when identities are
  stripped. The two-layer matcher (EXACT list + CONTAINS pass on
  normalised names) stays in `src/utils/identityIes.ts`.
- **Datasets (new)** — grid of dataset cards (name · id · kind pill ·
  Sessions / Events / Packets · Source · Ingestion · Accounting ·
  Access · decoder-version chips · "Open sessions" link). Backed by
  `GET /datasets`.
- **Exports** — mockup 4-row list: Call flow · HTML, Call flow ·
  JSON, Session summary · CSV (composed client-side from `/sessions`),
  PCAP slice (locked, same 404 reason).

### Session ID overlap fix (reported bug)
Pre-2.4, the Sessions table rendered `session_id` as a dedicated first
column with no `max-w` or `truncate`, so the 64-char hash spilled into
UE / Tech / Serving Node / Procedure at 1280 and 1440. The explicit
column is now gone; the mono hash lives on the Procedure cell's second
line, inside `max-w-[260px] truncate` with `title={session_id}` for
the hover tooltip. Covered by:
- `src/test/sessions-2.4.0.test.tsx` — vitest unit (7-column header
  set + class + title + max-w).
- `e2e-2.4.0/no-overlap-sessions.spec.ts` — Playwright, 3 widths × 2
  themes = 6 cells; asserts cell geometry + truncate class + title.
- `playwright-2.4.0.config.ts` isolates the matrix from the certified
  2.3 fixtures.

### Preserved tests (zero deletion)
Every pre-2.5 test is still present and still green:

| Test file | Function covered | Status |
| --- | --- | --- |
| `src/utils/identityIes.test.ts` | `isIdentityIe`, `withholdIdentity` (BC4 matcher) | **preserved**, 44/44 pass |
| `src/test/packet-analyzer-identity.test.tsx` | Packet Fields tab + identity banner + Raw Hex reminder | **preserved**, 4/4 pass |
| `src/test/callflow-viewer.test.tsx` | Ladder arrows, inspector tabs, correlation evidence, Download frame + PCAP slice locks | **preserved**, 5/5 pass — testids `callflow-download-frame` + `callflow-pcap-slice` kept |
| `src/test/multi-session.test.tsx` | Session navigation on the call flow picker | **preserved**, updated selector: `.page-intro .mono` → `data-testid="page-header"` + regex `/Investigate · s2/`. **Function unchanged** (clicking s2 opens its callflow and calls `/sessions/s2/callflow`) |
| `src/test/session-context.test.tsx` | zero-session empty state, dataset unavailable, categorised dataset filter | **preserved**, 3/3 pass — SessionExplorer re-implements the captureContext query, zero-session block, dataset-scope dropdown with four buckets |
| `src/test/sessions-2.4.0.test.tsx` | 7-column mockup contract + overlap fix | **new**, 2/2 pass |
| `src/test/api.test.ts`, `components.test.tsx`, `probe-manager.test.tsx`, `time.test.ts` | unchanged | **preserved** |

Vitest exclude pattern now ignores `e2e-2.4.0/**` (Playwright specs
import `@playwright/test` which is not loadable under jsdom).

### Functions dropped from the UI (declared)
None. The mockup pass only reshapes the Sessions table and headers;
every production behaviour (zero-session, dataset-unavailable,
dataset-scope filter, identity withholding, locked downloads,
captureContext resolution) still exists on the same route with the
same URL parameters.

### Captures
Side-by-side mockup vs implementation under
`docs/screenshots/2.4.0/sessions/`:
- `mockup.{light,dark}.png` — mockup served from
  `public/oiran-mockup.html`.
- `impl.{light,dark}.png` — 2.5 Sessions page with 2 mocked rows.
- `side-by-side.{light,dark}.png` — base64 composite.
Anti-overlap screenshots under
`docs/screenshots/2.4.0/sessions-no-overlap/` cover the 6 cells of
the matrix (1280 / 1440 / 1920 × light / dark).

### Dependencies
- Added `tailwindcss@3.4.17` and `clsx@2.1.1`. PostCSS plugin list
  updated in `postcss.config.js`.

### Ancestor proof
```
$ git merge-base --is-ancestor b734662 HEAD && echo b734662 ok
b734662 ok
$ git merge-base --is-ancestor 62b6079 HEAD && echo 62b6079 ok
62b6079 ok
$ git merge-base --is-ancestor 562ed77 HEAD && echo 562ed77 ok
562ed77 ok
```

## 2.5.0-dev — 2026-10-28 (minor)

Zero-mock pass against the production backend at
`https://151.242.147.49:8020`.

### Added

- `scripts/check-dist-leaks.mjs` — a build-time guard that fails the
  `npm run build` pipeline if any of the fixture markers
  (`oiran-vprobe-local-01`, `OIRAN_5G_PDU_SESSION_DATA_V1`) ends up
  inside `dist/`. Confirmed clean on first run.
- `scripts/capture-screenshots-live.py` and
  `docs/screenshots-live/*.png` (8 PNGs — Overview, Sessions,
  Packet Analyzer, Correlation Studio, light + dark). Rendered against
  the production API; no fixture injected.
- `docs/screenshots-live/README.md`.
- `src/types/api.ts`: `InterfaceRole` typed enum, optional `role` on
  `CaptureInterface`, optional `probe_state` on `Probe`, and
  `last_heartbeat_epoch_s: number | null`.

### Changed

- `src/pages/ProbeManager.tsx` removes the hardcoded
  `oiran-vprobe-local-01` default from the capture request. The
  operator now picks a probe from the live probe grid (cards gained
  a `role="button"` + keyboard handling); `Validate` and `Start`
  stay disabled while `probe_id` is empty.
- Probe cards show the new lifecycle (`probe_state` → `PENDING |
  ONLINE | DEGRADED`) and the real `last_heartbeat_epoch_s`.
- Interface cards expose the backend-declared `role` when the
  registry carries one (otherwise `—`).
- Selected-capture details stop defaulting `packet_count` to `0`;
  unknown counters render as `—`.
- Request `name` is no longer prefilled with `POLARIS-5G-SA` — the
  operator must name the capture.

### Validation (manual, no CI)

- `npm run typecheck` → clean
- `npm test` → Test Files 9 passed · Tests 71 passed
- `npm run build` → `dist/assets/index-Dt4N0p25.js 357.96 kB │ gzip: 106.04 kB`
  (check-dist-leaks: clean, 3 files scanned, 2 markers)

### Live verification (GET only)

| Screen | Route | HTTP | body |
|---|---|---|---|
| Sidebar | `GET /api/v1/modules` | 200 | 2780 B |
| Sessions | `GET /api/v1/sessions` | 200 | 3486 B |
| Datasets | `GET /api/v1/datasets` | 200 | 21874 B |
| UE directory | `GET /api/v1/ues` | 200 | 2699 B |
| Packet Analyzer | `GET /api/v1/packets` | 200 | 49418 B |
| Correlation Studio | `GET /api/v1/correlation/edges` | 200 | 9839 B |
| Correlation rules | `GET /api/v1/correlation/rules` | 200 | 367 B |
| Platform · version | `GET /api/v1/version` | 200 | 352 B |

## 2.4.1-dev — 2026-10-28 (patch)

Review feedback on 2.4.0-dev (BC4): subscriber-identity IEs still slipped
through the exact-name matcher when the decoder spelled them differently
("5GS mobile identity", "FiveG-S-TMSI", "MaskedIMEISV"). The Packet
Analyzer's Fields tab also rendered the raw IE list without going through
`withholdIdentity()`, which exposed the same strings on a second surface.

### Fixed

- `isIdentityIe()` is upgraded from EXACT-set lookup to a two-layer
  matcher: (a) a small EXACT list for codes that would false-positive
  as substrings (`RNTI`, `C-RNTI`, `MSISDN`, `PEI`), and (b) a CONTAINS
  pass on the normalised name against the fragments
  `mobileidentity`, `imsi`, `imei`, `tmsi`, `guti`, `supi`, `suci`,
  `msisdn`. Normalisation strips every non-alphanumeric character and
  lower-cases, so "5GS mobile identity", "nas-5gs-mobile-identity",
  "NAS_5GS_Mobile_Identity", "5G-S-TMSI", "FiveG-S-TMSI", "five_g_s_tmsi",
  "MaskedIMEISV", "Masked-IMEISV" and friends all collapse to the same
  hit. Verified negatives: `RAN UE NGAP ID`, `AMF UE NGAP ID`,
  `ue_identity_pseudonym`, `NAS-PDU`, `UserLocationInformation`,
  `SecurityKey`, `AllowedNSSAI`, `GUAMI`, `RRCEstablishmentCause`,
  `UEContextRequest` — none are withheld.
- Packet Analyzer `PacketInspector` now routes `packet.information_elements`
  through `withholdIdentity()` before the Fields tab renders them. The
  shield-banner, the identity-count, and the "no raw bytes" reminder on
  the Raw Hex tab match the CallFlow page contract.

### Added tests

- `identityIes.test.ts`: 44 unit tests (was 19). The positive list is
  seeded with the exact strings produced today by `decoder-ngap` and
  `decoder-nas`; the negative list locks `*-NGAP-ID` and
  `ue_identity_pseudonym`.
- `test/packet-analyzer-identity.test.tsx`: 4 UI tests covering the
  Packet Analyzer Fields tab banner, the DOM removal of
  "5GS mobile identity" / "FiveG-S-TMSI" / "MaskedIMEISV", the
  preservation of `RAN UE NGAP ID` and `ue_identity_pseudonym`, and the
  Raw Hex tab reminder.

### Audit

- `grep -rE "information_elements|decoded_ie_tree" OIRAN/apps/web/src/`
  returns only the two inspector sites (CallFlowViewer + PacketAnalyzer);
  both are now behind `withholdIdentity()`. No other page exposes an IE
  tree today.

### Validation (manual, no CI)

- `npm run typecheck` → clean
- `npm test` → Test Files 9 passed (9) · Tests 71 passed (71)
- `npm run build` → `dist/assets/index-CYSJ74BI.js 357.48 kB │ gzip: 105.93 kB`

## 2.4.0-dev — 2026-10-28 (minor)

Alignment on `docs/ui-mockups/oiran-analyzer.html`
(`origin/docs/ui-mockups` @ `48dea75`). Three honesty corrections on the
Call Flow page and one sidebar reorganisation. Every existing test
(39 before) stays green; three new tests lock the new contract (42 total).

### Changed

- Sidebar nav is reorganised into **INVESTIGATE** (Overview, Sessions,
  Call flow, Correlation, Packet analyser) and **EVIDENCE** (Exports and
  anything else the `/modules` endpoint reports under `reports`). The
  `operations` section is intentionally omitted — Probe Manager has its
  own app (`apps/probe-manager`) and no longer appears in the Analyzer.
- `CallFlowViewer` no longer performs any client-side sort on event
  timestamps; messages are rendered in the order the API returns them
  (new code comment makes this explicit).

### Added

- `src/utils/identityIes.ts` with a pure `withholdIdentity()` helper
  (plus 19 unit tests). Subscriber / equipment identities — IMSI, IMSISV,
  IMEI, IMEISV, MASKED_IMEISV, TMSI, M-TMSI, PTMSI, GUTI, 5G-GUTI, S-TMSI,
  RNTI, C-RNTI, SUPI, SUCI, MSISDN, PEI — are stripped from the IE tree
  BEFORE the inspector renders. The counter walks the whole subtree, so
  if the backend sends a `GUTI` carrying nested `mcc`/`mnc`/`AMF-Region`
  the operator sees "N identity IEs withheld" with the real N.
- Call Flow message inspector surfaces an **"N identity IEs withheld"**
  banner (shield icon, warning tint) on every tab that renders the IE
  tree. The Raw Hex tab explicitly reiterates the lock: no raw bytes are
  ever shown.
- Call Flow page toolbar carries two locked buttons: **"Download frame"**
  and **"PCAP slice"**, both disabled with the title
  `GET /captures/:id/download is not served yet (404)` — the backend
  does not register those routes, so the UI never fakes a success.
- `.withheld-banner` CSS token in `src/styles/index.css`.
- Two UI tests on CallFlowViewer locking the LOT 3 contract:
  - identity IEs are filtered, the banner shows the exact count, and
    nodes like `IMSI` or `5G-GUTI` never appear in the DOM;
  - "Download frame" and "PCAP slice" buttons stay disabled with the
    correct `title` attribute.

### Validation (manual, no CI)

- `npm run typecheck` → clean
- `npm test` → Test Files 8 passed (8) · Tests 42 passed (42)
- `npm run build` → `dist/assets/index-CH-vacTD.js 356.98 kB │ gzip: 105.86 kB`

### Open items (declared)

- The mockup names a dedicated **Datasets** entry under EVIDENCE. The
  backend `/modules` payload does not currently expose a datasets
  module, so the entry is NOT fabricated client-side. Once the backend
  adds it, the sidebar picks it up automatically through the existing
  module loop.
- Inspector keeps 7 tabs (Overview, Decoded Fields, ASN.1 / Protocol
  Tree, Raw Hex, JSON, Correlation Evidence, Provenance) because the
  existing test suite locks the current tab names. The mockup's shorter
  "IEs / Correlation / Provenance" grouping stays visible through those
  7 tabs; a future lot can rename when the tests move.
