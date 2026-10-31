# @oiran/web — Changelog

Format: SemVer. Pre-release suffix `-dev` indicates this is cut from main.

## 2.6.0-pre.1+lte.offline.1 — 2026-10-31 (test-only certification increment)

- Add Analyzer regression checks that preserve both LTE synthetic-only labels
  and the existing LTE/5G interface and protocol filters.
- No runtime UI behavior, live capture capability or certification claim added.

## 2.6.0-pre.1 — 2026-10-31 (minor pre-release)

- Prepare LTE technology, S1-MME/S11/S1-U interface and S1AP/EPS NAS/GTPv2-C
  protocol filters for offline synthetic datasets.
- Keep LTE explicitly labelled synthetic-only; this release does not claim
  live capture or ANR1 fixture certification.

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
