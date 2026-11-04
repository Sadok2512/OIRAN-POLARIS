# API / UI parity — POLARIS correlation indicators

Date: 2026-11-04 UTC. Scope: OIRAN Analyzer embedded in POLARIS. The Rust
session/correlation engine, captures, and decoders are unchanged.

## Routes and consumers

| Purpose | API route | UI consumer | Contract |
|---|---|---|---|
| Session context | `GET /api/v1/sessions/:id` | Call Flow Viewer | Technology, interfaces, dataset context |
| Paginated messages | `GET /api/v1/sessions/:id/callflow?limit=100` | Call Flow Viewer | Events and raw engine status; edges may intentionally be empty |
| Correlation evidence | `GET /api/v1/sessions/:id/correlations` | Call Flow Viewer and Correlation Studio | Authoritative bridge status plus all rule-backed edges |

The defect was an API/UI parity error: `CallFlowViewer` only read the paginated
Call Flow object. Production correctly returns `correlation_edges: []` there,
while the separate correlations route contains the evidence. The candidate now
joins the three read-only responses by `session_id`.

## Real 5G SA observation

Read-only commands:

```bash
curl -sS http://127.0.0.1:49152/api/v1/sessions/5g-session-18fe28a814c4b094/callflow?limit=10 | jq '.data | {interfaces,correlation_status,edge_count:(.correlation_edges|length)}'
curl -sS http://127.0.0.1:49152/api/v1/sessions/5g-session-18fe28a814c4b094/correlations | jq '.data | {status,edges:[.edges[]|{edge_id,source_interface,target_interface,confidence,matching_identifiers,packet_references}]}'
```

Observed response facts:

- Call Flow interfaces: `N2`, `N4`, `SBI`.
- Raw status: `N2_SBI=STRONG`, `SBI_N4=STRONG`, `N4_N3=UNKNOWN`,
  `E2E=UNKNOWN`.
- Paginated Call Flow edges: `0`.
- Correlations endpoint edges: `3` total, including one N2↔SBI and one
  SBI↔N4 rule-backed edge.

Candidate UI result:

- N2↔SBI = `CORRELATED` (raw `STRONG`, evidence edge present).
- SBI↔N4 = `CORRELATED` (raw `STRONG`, evidence edge present).
- N4↔N3 = `NO_DATA` (N3 absent from the observed interface set).
- E2E = `NO_DATA`; it is not promoted from partial bridge evidence.

## Transformation and cache rules

The pure mapper is in
`OIRAN/apps/web/src/correlation/statusMapping.ts`. It requires both a positive
engine confidence (`EXACT`/`STRONG`) and at least one matching evidence edge to
emit `CORRELATED`. Null/missing values are classified explicitly. The
correlation query has `staleTime: 0` and `refetchOnMount: "always"`; an API
error renders the error state rather than stale indicators.

DSN means **Data Source Node** in this UI: immutable
`source_file#packet_number` coordinates copied from edge packet references. It
does not mean DNS and does not create a new correlation claim.
