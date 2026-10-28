# @telecom/portal — Changelog

Format: SemVer.

## 0.2.0 — 2026-10-28 (minor)

Alignment on `docs/ui-mockups/portal.html` (`origin/docs/ui-mockups` @
`48dea75`). Three honesty / scope corrections and one new section.

### Changed

- The POLARIS brick is now **POLARIS Control** (the backend product name)
  with the tagline `Core · RAN · UE · Scenarios`, replacing the older
  "Simulator Control" wording.
- Probe Manager description reflects the LOT 1 split: topology moved to
  POLARIS; Probe Manager now manages probes and captures only.

### Added

- Each `AppDescriptor` carries a `scope: string[]` field. Scope chips are
  rendered under the description on each card:
  - POLARIS Control: Open5GS · gNB / eNB · Topology · UE Manager · Scenarios
  - Probe Manager: Probes · Interfaces · Live captures · Library
  - OIRAN Analyzer: Sessions · Call flow · Correlation · Packets · Datasets
- Each card footer now shows the exact route the portal health probe
  queries (e.g. `GET /polaris-api/v1/system/health`), in mono, next to
  the health detail (`ok · 42 ms`, `Reachable, authentication required
  (401)`, etc.). The probe stays an anonymous GET with
  `credentials: 'omit'` — never carrying a cross-app token.
- A new `Responsibilities` card below the grid states which app owns what
  and reiterates the "anonymous GET per app base" rule.

### Validation (manual, no CI)

- `npm run typecheck` → clean
- `npm test` → Test Files 1 passed · Tests 15 passed
- `npm run build` → `dist/assets/index-BqytiYuF.js 197.32 kB │ gzip: 62.47 kB`

## 0.1.0 — initial release
