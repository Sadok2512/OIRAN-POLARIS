# OIRAN Analyzer

**Responsibility (foundation guidance):** protocol decoding presentation,
session reconstruction results, correlation evidence, packet provenance,
and Call Flow. Must not implement decoder logic.

Initialized on `feat/analyzer-e2e-session-explorer` with the premium
Enterprise Precision V2 implementation.

## Routes

- `/overview` — dataset / UE / session counters, decoder versions
- `/datasets` — dataset table + inspector + Session Explorer deep-link
- `/investigation/sessions` + `/investigation/sessions/:id` — **P0**
  hierarchical UE → PDU session → PFCP / GTP-U / flows explorer
- `/investigation/signaling` — full-width signaling call-flow ladder
- `/investigation/user-plane` — GTP-U tunnels + encapsulated flows
- `/investigation/correlation` + `/:id` — React Flow correlation graph
- `/analysis/packets` — server-paginated packet table
- `/analysis/kpi` — metrics tiles + per-interface rates + backend versions

## Scope boundaries

- No decoder implementation. Rust engines (`decoder-ngap`, `decoder-nas`,
  `decoder-pfcp`, `decoder-sbi`, `decoder-gtpu`) remain in `OIRAN/` and
  are consumed only via `/api/v1/*` envelopes.
- No fabricated correlation. `STRONG` is never promoted to `EXACT`.
- No synthetic UE: sessions whose `ue_context_id` does not resolve to a
  known UE sit in a dedicated `Unknown UE context` bucket.
- No fake throughput, no synthetic packet-loss. Missing counters render
  as `Not available`.

## Dev / test commands

```bash
npm install
npm run dev            # http://127.0.0.1:4320/analyzer/
npm run typecheck
npm run test
npm run build          # production bundle in dist/
```

## Delivered artifacts

- 16 Vitest tests (hierarchy builder, evidence badge, routing)
- 64 Playwright screenshots covering every route × 4 viewports × 2 themes
- Detailed report: [`docs/frontend/ANALYZER_IMPLEMENTATION.md`](../../docs/frontend/ANALYZER_IMPLEMENTATION.md)
