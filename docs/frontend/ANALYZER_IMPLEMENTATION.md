# OIRAN Analyzer V2 — implementation report

Branch: `feat/analyzer-e2e-session-explorer`
Serving path (preview): `/analyzer/` (BrowserRouter basename)
Vite dev port: `4320`

## Objectives covered

- Hierarchical reconstruction `UE Context → PDU Session → PFCP / GTP-U
  / TCP·UDP·ICMP flows`, derived strictly from backend-reported sessions
  and decoded information-element trees. No synthetic UE, PDU, SEID or
  TEID is ever fabricated.
- Multi-UE and multi-PDU isolation: UEs sharing a PDU session id stay
  separate, orphan sessions sit in a dedicated `Unknown UE context`
  bucket.
- Correlation evidence rendered with OIRAN's own classification
  (`EXACT`, `STRONG`, `POSSIBLE`, `UNKNOWN`). The UI never promotes
  `STRONG` to `EXACT`.
- Decoded message inspector showing IE tree, packet references, capture
  provenance, decoder name + version.
- Honest unavailable states where the backend does not expose a value
  (no fake throughput, no fabricated packet-loss).

## Pages

| Route                             | Component                 | Purpose                                              |
| --------------------------------- | ------------------------- | ---------------------------------------------------- |
| `/overview`                       | `OverviewPage`            | Dataset / UE / session / event counts, decoder vers. |
| `/datasets`                       | `DatasetsPage`            | Dataset table + inspector + Session Explorer link    |
| `/investigation/sessions`         | `SessionExplorerPage`     | **P0** — hierarchy, call-flow preview, inspector     |
| `/investigation/sessions/:sessionId` | `SessionExplorerPage`  | Deep-link via `session_id` + `dataset_id` query      |
| `/investigation/signaling`        | `SignalingPage`           | Full-width call-flow ladder + inspector              |
| `/investigation/user-plane`       | `UserPlanePage`           | GTP-U tunnels, encapsulated flows, N3 events         |
| `/investigation/correlation`      | `CorrelationStudioPage`   | React Flow correlation graph + evidence legend       |
| `/analysis/packets`               | `PacketAnalyzerPage`      | Server-paginated packet table + inspector            |
| `/analysis/kpi`                   | `KpiPage`                 | Metrics tiles + per-interface rates + versions       |

## Hierarchy builder

File: `src/analyzer/hierarchy.ts` — pure function + unit-tested.

- `buildHierarchy(ues, sessions, callFlowsBySessionId?)` groups
  sessions strictly by `ue_context_id`.
- `buildUnknownBucket(ues, sessions)` separates sessions whose
  backend-reported UE context does not exist.
- PFCP SEIDs come from IE whose name matches `/\b(?:F?SEID|seid)\b/i`
  in the decoded tree; GTP-U TEIDs come from `/\bTEID\b/i`. Both are
  deduplicated via a `Set` and left empty when the backend did not
  decode them.
- Encapsulated flows are aggregated from events whose interface
  matches `N3` or `GTP`; they expose protocol/source/destination +
  packet counts.
- No cross-UE merging: multi-UE / multi-PDU tests enforce this.

## API coverage

Consumed OIRAN v1 routes (via `useQuery` under `authScope: 'oiran'`):

```
GET /api/v1/version
GET /api/v1/auth/me
GET /api/v1/metrics
GET /api/v1/datasets?page_size=200
GET /api/v1/datasets/:id
GET /api/v1/datasets/:id/sessions?page_size=500
GET /api/v1/ues?page_size=500
GET /api/v1/ues/:id
GET /api/v1/ues/:id/sessions?page_size=200
GET /api/v1/sessions/:id
GET /api/v1/sessions/:id/callflow
GET /api/v1/sessions/:id/events?page_size=1000
GET /api/v1/sessions/:id/correlations?page_size=1000
GET /api/v1/packets?page=N&page_size=M[&capture_id=…][&session_id=…]
GET /api/v1/packets/:id
```

Every request names the OIRAN `authScope` so the shared client only
attaches a Bearer when the token is stored under
`oiran.access_token` AND the base is allowlisted (`/api/v1`).

## Missing backend fields (documented)

| Capability                                          | Proposed contract                              |
| --------------------------------------------------- | ---------------------------------------------- |
| Per-TEID throughput over time                       | `GET /sessions/:id/tunnel-throughput`         |
| UL/DL direction counters for GTP-U events           | `direction_counts` on `/sessions/:id/callflow` |
| End-to-end packet loss (not derivable from capture drops) | Dedicated path-measurement endpoint       |
| Historical trend for decoder KPIs                   | `GET /metrics/timeseries?window=5m`           |
| Mobility / NAS-5GMM standalone event bucket         | `GET /ues/:id/mobility-events`                |

Each of those is currently rendered as `Not available` (via the shared
`Unavailable` component) with a short explanation. The UI will light up
without code changes once the backend ships the fields.

## Tests

Vitest — **16/16 passing**:

| File                                            | Suite                      | Cases |
| ----------------------------------------------- | -------------------------- | ----- |
| `src/analyzer/hierarchy.test.ts`                | Multi-UE isolation, multi-PDU, SEID/TEID extraction, unknown bucket, honest missing | 5 |
| `src/ui/EvidenceBadge.test.tsx`                 | EXACT / STRONG / POSSIBLE / UNKNOWN, fallback, no promotion | 6 |
| `src/app/App.test.tsx`                          | Default route, 8 nav links, deep-nav, redirect, theme switch | 5 |

Playwright — **64/64 passing** at four viewports × two themes for the
eight Analyzer routes. Screenshots live under
`docs/frontend/SCREENSHOTS/analyzer_*.png`.

Builds:

| App             | tsc | vitest | vite build       |
| --------------- | --- | ------ | ---------------- |
| oiran-analyzer  | PASS | 16/16 | 526 kB JS gzip 163 kB |

## Not changed

- No file under `OIRAN/`, `POLARIS_CONTROL/`, `services/`,
  `infrastructure/` touched.
- No modification to decoder logic.
- No modification to Rust engine.
- `apps/portal`, `apps/probe-manager`, `packages/ui/src/{api,theme,tokens}.ts`
  left intact. `packages/ui/src/types.ts` extended with the Analyzer
  contract types (`Dataset`, `UeContext`, `Session`, `CallFlow`,
  `Packet`, `CorrelationEdge`, `VersionInfo`) that both `Analyzer` and
  future consumers can share.

## Dev commands

```bash
cd apps/oiran-analyzer
npm install
npm run dev            # http://127.0.0.1:4320/analyzer/
npm run typecheck
npm run test
npm run build          # dist/
```
