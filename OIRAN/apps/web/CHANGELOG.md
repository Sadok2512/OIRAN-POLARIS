# @oiran/web — Changelog

Format: SemVer. Pre-release suffix `-dev` indicates this is cut from main.

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
