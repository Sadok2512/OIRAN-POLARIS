# PR body — `feat(analyzer): universal E2E session explorer`

> Paste the content below as the body of the PR
> `feat/analyzer-e2e-session-explorer → main`.

---

## Scope

- **New app**: `apps/oiran-analyzer` (`@telecom/oiran-analyzer` 0.1.0)
- **Shared types extended**: `packages/ui/src/types.ts` gains
  `Dataset`, `UeContext`, `Session`, `CallFlow`, `CallFlowEvent`,
  `CorrelationEdge`, `Packet`, `VersionInfo`
- **E2E fixtures**: `e2e/mock-api.ts` + `e2e/screenshots.spec.ts`
  extended to cover the Analyzer
- **Docs**: `docs/frontend/ANALYZER_IMPLEMENTATION.md` + 64 PNGs

No file under `OIRAN/`, `POLARIS_CONTROL/`, `services/` or
`infrastructure/` is touched. No decoder change. No Rust change.

## Delivered features

### P0 — Session Explorer (`/investigation/sessions`)

Three-pane resizable layout:

- **Left** — dataset selector + search + UE / PDU hierarchy. Grouping
  is strictly by `ue_context_id`; UEs sharing a PDU session id stay
  separate. Sessions whose UE context does not resolve go to an
  explicit `Unknown UE context` bucket.
- **Center** — PDU session summary, correlation banner
  (`N2 ↔ N4`, `N2 ↔ SBI`, `SBI ↔ N4`, `N4 ↔ N3`, `E2E`), signaling
  call-flow ladder.
- **Right** — decoded message inspector with Information-Element tree,
  packet references, capture provenance, decoder name + version.

Hierarchy builder in `src/analyzer/hierarchy.ts` is a pure function
backed by 5 Vitest cases: multi-UE isolation, multi-PDU per UE,
PFCP / GTP-U ID extraction from the backend decoded tree, unknown
correlation bucket, honest empty rendering.

### Signaling (`/investigation/signaling`)

Call-flow ladder with UE / gNB / AMF / SMF / UPF columns, chronological
ordering (via `timestamp_ns`), click → inspector, filter by protocol
(NGAP, NAS, SBI, PFCP, GTP-U). Direction and endpoints come from the
backend event; the UI never invents a direction.

### User Plane (`/investigation/user-plane`)

GTP-U TEIDs, PFCP SEIDs and aggregated flows per PDU session. End-to-end
packet loss and per-tunnel throughput are rendered as `Not available`
because capture drops ≠ path loss — those will light up when the
backend ships the dedicated contract (documented in
`docs/frontend/ANALYZER_IMPLEMENTATION.md`).

### Correlation Studio (`/investigation/correlation`)

React Flow (`@xyflow/react`) renders events as nodes and backend
`correlation_edges` as colored arrows. Confidence governs stroke
color and animation (`EXACT` only). An evidence legend documents each
level.

### Packet Analyzer (`/analysis/packets`)

Server-paginated TanStack Table with scope badge for the current
`capture_id` / `session_id`. Packet detail reuses the shared inspector.

### Overview + Datasets + KPI

Dataset / UE / session / event counters, decoder versions, per-interface
rates. Every absent counter renders as `Not available`.

## Correlation evidence rules

- UI uses the OIRAN classification unchanged: `EXACT`, `STRONG`,
  `POSSIBLE`, `UNKNOWN`.
- `STRONG` → `EXACT` promotion is impossible (test enforces this at the
  badge level).
- Each `CorrelationEdge` surfaces the backend-reported `rule_id`,
  `rule_version`, `evidence_description`, `matching_identifiers`,
  `packet_references`, `scope`, `limitations`.

## Tests

| Workspace          | Command            | Result        |
| ------------------ | ------------------ | ------------- |
| `apps/oiran-analyzer` | `npm run typecheck` | PASS (exit 0) |
| `apps/oiran-analyzer` | `npm run test`      | 16/16 passing |
| `apps/oiran-analyzer` | `npm run build`     | 526 kB JS gzip 163 kB |
| `e2e`              | `npx playwright test -g "analyzer"` | 64/64 passing |

## API integration

Covered: `/version`, `/auth/me`, `/metrics`, `/datasets`,
`/datasets/:id`, `/datasets/:id/sessions`, `/ues`, `/ues/:id`,
`/ues/:id/sessions`, `/sessions/:id`, `/sessions/:id/callflow`,
`/sessions/:id/events`, `/sessions/:id/correlations`, `/packets`,
`/packets/:id`.

Every call names the OIRAN `authScope`; the shared client only attaches
Bearer when the token is under `oiran.access_token` AND the base is in
the OIRAN allowlist. No token in URLs.

## Missing backend contracts (documented, not fabricated)

- `GET /sessions/:id/tunnel-throughput` — per-TEID throughput over time
- UL/DL direction counts on `/sessions/:id/callflow`
- `/metrics/timeseries?window=5m` — historical KPI trends
- `/ues/:id/mobility-events` — standalone NAS-5GMM mobility bucket
- Dedicated path-measurement endpoint for E2E packet loss

Until those exist, the UI renders honest `Not available` placeholders.

## Known limitations

- Call-flow ladder relies on `source_participant`/`destination_participant`
  normalization (UE / gNB / AMF / SMF / UPF); unmapped participants are
  listed verbatim.
- React Flow node positions use a simple grid layout; a dedicated layout
  engine (dagre, ELK) can replace it later without changing the data.
- Packet Analyzer uses standard TanStack Table rendering — virtualization
  via `@tanstack/react-virtual` is wired as a dependency but not yet
  attached to the row model (follow-up).

## Checklist

- [x] Branched from latest `origin/main`
- [x] No backend file modified
- [x] No decoder / Rust change
- [x] No production deploy
- [x] Tests + screenshots regenerated
- [x] Correlation evidence not fabricated
- [x] Multi-UE / multi-PDU isolation enforced
