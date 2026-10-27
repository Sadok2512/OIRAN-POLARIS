# OIRAN Live V1 API Contract

All routes are under `/api/v1`. Read routes permit Viewer access. Write routes require an `Authorization: Bearer …` token whose SHA-256 fingerprint is provisioned on the server as Operator or Administrator.

| Method | Route | Purpose |
|---|---|---|
| GET | `/probes` | Probe state, heartbeat and independent live capability states |
| GET | `/probes/{id}/interfaces` | Allowlisted interface discovery and availability |
| GET | `/captures` | Historical captures plus live jobs |
| GET | `/captures/{id}` | Authoritative capture job or historical metadata |
| GET | `/captures/{id}/metrics` | Real job packet, byte, rate, drop and storage counters |
| POST | `/captures/validate` | Validate request, interfaces, concurrency and disk budget |
| POST | `/captures/start` | Start one validated OIRAN-owned job |
| POST | `/captures/{id}/stop` | Stop the exact owned job |
| GET | `/datasets` | Historical and completed live datasets |
| GET | `/sessions` | Historical and captured-live reconstructed sessions |
| GET | `/sessions/{id}/callflow` | Canonical evidence-based Call Flow |

The bounded request contains `probe_id`, `name`, `interfaces`, `duration_seconds`, `max_bytes`, `rotation_files`, `profile`, and an optional filter. V1 rejects custom filters and non-allowlisted probes/interfaces.

States are `CREATED`, `VALIDATING`, `READY`, `STARTING`, `CAPTURING`, `STOPPING`, `PROCESSING`, `COMPLETED`, `FAILED`, and `BLOCKED`.
