# Changelog

## 0.2.0 — 2026-10-28 (minor)

Alignment on the UI mockups in `docs/ui-mockups/` (branch `origin/docs/ui-mockups`,
commit `04d7c79`). No new mutating route is called; every unavailable backend
contract is surfaced as a locked UI control with its reason text.

### Added

- `src/data/roleMapping.ts` — deterministic N2/N3/N4/S1 derivation from
  `capture_point` / `protocol` (NGAP → N2, GTP-U → N3, PFCP → N4, S1AP → S1).
  Interfaces whose role cannot be named honestly render as `—`.
- `src/components/RegisterProbeDialog.tsx` — operator-facing registration form
  (vProbe / physical, name → slug, dynamic interfaces + role → BPF). The
  submit button stays **locked** with the badge
  `Backend pending: POST /probes`; a payload preview exposes the JSON that
  will be POSTed once the backend contract exists. Nothing is persisted
  client-side.
- `src/pages/TopologyMoved.tsx` — stub rendered on `/topology` that
  redirects the operator to POLARIS Simulator Control. Keeps old
  bookmarks working without faking topology data.
- Live Captures: file-growth tracking over a 10 s sliding window
  (per-capture snapshots sampled by the existing 4 s poll — strictly
  in-memory, dropped when the capture stops), a disk-usage gauge sourced
  from `GET /storage/safety` with an explicit 90 % stop line, and a stall
  badge for jobs with 0 B growth over 10 s.
- Tests: 76 passed (6 new in `App.test.tsx`, `LiveCaptures.test.tsx`,
  `CaptureLibrary.test.tsx`, 5 in `RegisterProbeDialog.test.tsx`,
  5 in `roleMapping.test.ts`). Commands reported in the PR summary.

### Changed

- Probes table now shows interface **chips** (role badge + name) and
  passes the full `CaptureInterface` list into `ProbeInspector`, which
  surfaces protocol / capture_point / status / device from real fields.
- Capture Library: Download button is **permanently disabled** with the
  tooltip `GET /captures/:id/download = 404 (route not registered on OIRAN API).`
  A page-level banner states the same reason. No `authenticatedDownload`
  fetch is ever issued.
- Live Captures: `Validate capture` and `Start capture` buttons are
  **locked** (no `POST /captures/validate` or `/captures/start` is sent
  in this build); the per-capture `Stop` button is locked with the reason
  `Blocked until lossless resume is proven on OIRAN.`
- Sidebar: `Network Topology` entry removed. Topology moves to POLARIS
  Simulator Control (see LOT 2).

### Removed from the live code path (dead files kept in-tree)

- `src/pages/NetworkTopology.tsx` and `src/topology/*` are no longer
  reachable through routing but stay on disk for the LOT 2 reuse in
  Simulator Control. `buildTopology.test.ts` keeps its tests green.

## 0.1.1 — 2026-10-28 (patch)

- Update `react-router-dom` to `6.30.6` to close the production React Router redirect/XSS
  advisories without changing routes or application behavior.

## 0.1.0

- Initial Probe Manager frontend.
