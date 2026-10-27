# Visual review

Date: 2026-10-27
Reviewer: implementation agent (self-review before human sign-off)
Evidence: `WEB/SCREENSHOTS/` (65 PNGs). Full-page captures taken through
Playwright 1.57 on Chromium 1248.

## Methodology

Every route × viewport × theme listed in `FRONTEND_TEST_REPORT.md` was
rendered against the mock OIRAN backend defined in
`WEB/e2e/mock-api.ts`. The mock is explicitly flagged as fixture-only
and never ships in production.

## Portal

| Screenshot                          | Observation                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------- |
| `portal_light_1920x1080.png`        | Three-column grid, tight gap, correct spacing from header                   |
| `portal_light_1440x900.png`         | Same, central alignment preserved                                           |
| `portal_light_1280x800.png`         | Three-column grid still fits comfortably                                    |
| `portal_light_1024x768.png`         | Grid collapses to two columns; last card wraps as expected                  |
| `portal_dark_1920x1080.png`         | Dark theme borders readable, status dots stay visible                       |
| `portal_dark_1440x900.png`          | OK                                                                          |
| `portal_dark_1280x800.png`          | OK                                                                          |
| `portal_dark_1024x768.png`          | Two columns, dark surface contrast respects tokens                          |

Visible details: Reachable status dot per card, latency in milliseconds,
"Open application" primary CTA, portal header with brand mark and theme
switch, footer with Enterprise Precision mention.

## Probe Manager

Each page validated at 1920/1440/1280/1024 × light/dark. Representative
observations:

- **Overview** — metric tiles align in a 4-up grid above 1024 px (2-up
  below); storage safety and probe cards sit side-by-side when there is
  room, stack below ~900 px wide content area.
- **Network Topology** — React Flow canvas fills the viewport; nodes
  colored by evidence tag; MiniMap bottom-right, Controls bottom-left.
  Fullscreen button in the header. Clicking a node highlights neighbours
  and opens the inspector drawer.
- **Probes / Interfaces** — tables + right-side inspector; row hover
  highlights; selected row carries `data-selected="true"`.
- **Live Captures** — per-job cards with every mandated metric field;
  explicit "Not available" labels where the backend omitted a value.
  Stop button raises the ConfirmDialog.
- **Capture Library** — TanStack Table with sortable columns, filters
  bar (search + probe + interface + status), per-row Actions (View,
  Analyzer, Download, failure badge).
- **Settings** — Authentication block + Operational boundaries. When not
  authenticated, EmptyState guides the operator to the external auth
  flow.

## Honest unavailable state

`probe_capture_library_empty_light_1440x900.png` captures the Capture
Library when the backend returns `{ data: [], meta: {} }`. The UI shows
`EmptyState` instead of a fabricated row — satisfying Section 12 of the
brief.

## Deltas vs. the direction

- No glassmorphism, neon glow, decorative gradient or oversized hero
  cards present. Spot-checked every PNG.
- Typography stays within Inter at the specified sizes. Tabular numerals
  verified on every numeric table cell.
- Shadows are flat and subtle; borders remain the primary separator.

## Follow-ups suggested (not blockers)

- Add Linear-style keyboard shortcuts (`g o`, `g t`, `g c`) for route
  jumps.
- Add a per-row expand on Capture Library to inline the plane
  decomposition without opening a modal.
- Add animated edge flow on `DISCOVERED` topology edges when the
  interface reports live packet rate above zero (currently animated
  unconditionally for DISCOVERED edges).
