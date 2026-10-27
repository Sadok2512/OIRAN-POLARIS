# S4 API Contract

Base path: `/api/v1`  
API version: `1.0.0`  
Transport: loopback HTTP for S4; place TLS/authenticated private access in front only after approval.

## Authentication and authorization

Every API route requires `Authorization: Bearer <token>`. Viewer and administrator tokens are injected at runtime, must differ operationally and must contain at least 16 characters. S4 exposes read-only routes only, so both roles are authorized for read capabilities; no write/capture-control route exists. Denied requests are audit-logged without tokens.

## Envelope and errors

Successful JSON uses `{ "data": ..., "meta": { "api_version": "1.0.0", ... } }`. Lists add `page`, `page_size`, `total` and `total_pages`. Errors use `{ "error": { "code", "message" }, "meta": { "api_version" } }` with appropriate 400/401/404/500 status.

## Routes

| Method and route | Result |
|---|---|
| `GET /health` | Mode, capabilities and real source-event count |
| `GET /version` | Platform, API, schemas, engines and decoder versions |
| `GET /modules` | Module registry, routes, permissions and flags |
| `GET /probes` | Observed local vProbe only |
| `GET /interfaces` | Manifest-derived N2/N3/N4 metadata |
| `GET /captures` | Paginated/filterable capture library |
| `GET /captures/{id}` | One capture by SHA-based ID |
| `GET /sessions` | Paginated/filterable reconstructed sessions |
| `GET /sessions/{id}` | Summary, procedures, accounting and capture references |
| `GET /sessions/{id}/events` | Paginated events; filters: interface, protocol, association, search |
| `GET /sessions/{id}/callflow` | Canonical call flow with sanitized source paths |
| `GET /sessions/{id}/correlations` | Status and canonical evidence edges |
| `GET /events/{id}` | One canonical event |
| `GET /events/{id}/provenance` | Packet provenance and payload hash reference |
| `GET /correlation/edges` | Paginated/filterable evidence edges |
| `GET /correlation/rules` | Read-only rule/version metadata |
| `GET /exports/callflow/{id}?format=json|html` | Access-controlled canonical export |

`page_size` is clamped to 1–100. Absolute filesystem paths are replaced with `capture://<basename>`. Arbitrary file paths and commands are never accepted.
