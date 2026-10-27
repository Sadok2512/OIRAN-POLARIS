# API integration gaps

Baseline: OIRAN API as declared in `OIRAN/apps/api/src/lib.rs`
(route table around line 364) and in `OIRAN/OIRAN_LIVE_V1_API_CONTRACT.md`.
No backend file was modified during this task — see Section 15 of the
brief ("BACKEND_MODIFICATION_AUTHORIZED = FALSE").

## Covered by this frontend

| Endpoint                                 | Consumer                                                       |
| ---------------------------------------- | -------------------------------------------------------------- |
| `GET  /api/v1/auth/me`                   | Portal health probing · Probe Manager Overview/Settings        |
| `GET  /api/v1/health`                    | Portal (Probe Manager card health)                             |
| `GET  /api/v1/system/health`             | Portal (Simulator Control card health)                         |
| `GET  /api/v1/probes`                    | Overview, Probes, Topology                                     |
| `GET  /api/v1/interfaces`                | Interfaces, Topology, Interface inspector                      |
| `GET  /api/v1/captures`                  | Overview, Live Captures, Capture Library                       |
| `GET  /api/v1/metrics`                   | Overview, Interface inspector                                  |
| `GET  /api/v1/storage/safety`            | Overview (storage safety panel)                                |

## Partially covered

| Endpoint                                 | Status                                                                                   |
| ---------------------------------------- | ---------------------------------------------------------------------------------------- |
| `POST /api/v1/captures/validate`         | Payload buildable from UI, not fired — gated by the no-live-capture directive            |
| `POST /api/v1/captures/start`            | Same                                                                                     |
| `POST /api/v1/captures/:id/stop`         | ConfirmDialog wired; the actual network call is intentionally skipped during this review |
| `GET  /api/v1/captures/:id`              | Deep-link format supported in Capture Library actions, not yet rendered as a detail page |
| `GET  /api/v1/captures/:id/metrics`      | Live Captures reads the embedded `metrics` field; dedicated endpoint not polled yet      |
| `GET  /api/v1/datasets`, `/datasets/:id` | Capture Library deep-links to the OIRAN Analyzer; dataset browser not duplicated here   |

## Not reachable from this UI (missing backend contract)

The brief asks the frontend to document anything that the backend does
not expose. The following would upgrade the Probe Manager views without
requiring any client fabrication:

| Capability needed                                                    | Proposed contract                                                             |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Independent list of physical topology links (not derived from planes)| `GET /topology/links` returning `{ source, target, kind, evidence }`. The frontend ships a `VerifiedInterfaceMapping` input ready to consume this contract — see `apps/probe-manager/src/topology/types.ts`. |
| Server-side capture pagination (`page`, `page_size`, `meta.total`, `meta.total_pages`) | Capture Library now requests `GET /captures?page=N&page_size=M` and renders a `partial-results-notice` when `meta.total` is absent. See PR #2 Section 4. |
| Per-application auth boundaries                                      | Each app now owns a dedicated session-storage scope (`oiran`, `polaris`, `probe-manager`) and a dedicated `apiBase`. Shared client refuses cross-origin tokens. See PR #2 Section 3 and `docs/contracts/AUTHENTICATION_BOUNDARIES.md`. |
| Authorized PCAP download                                             | `GET /api/v1/captures/:id/download` is the frontend target; the Download action stays disabled until `/auth/me.authenticated === true` AND `size_bytes > 0`. |
| Historical trend for CPU/RAM/disk per probe                          | `GET /probes/:id/telemetry?window=5m` → time-series samples                   |
| Per-interface live counters (packets/s, bits/s, drops)               | `GET /interfaces/:id/metrics` streaming via SSE or short-poll JSON            |
| Capture job events                                                   | `GET /captures/:id/events` or WebSocket `/captures/:id/stream`                |
| Explicit UP/DOWN and admin state separate from `status`              | Return `admin_state` and `oper_state` fields on `/interfaces`                 |
| Agent management lifecycle (`Start Probe Agent` / `Stop Probe Agent`)| `POST /probes/:id/agent/start` and `POST /probes/:id/agent/stop`              |
| Fine-grained capture authorization reasons                           | Extend `/captures/validate` to return `blockers` with `code` + `remediation`  |
| Multi-UE / multi-gNB topology hints                                  | Allow `/probes` to return multiple RAN endpoints and multiple UE contexts     |

Until those contracts exist, the Probe Manager renders honest fallbacks:

- Agent start/stop controls are **present** but disabled with an
  explanatory tooltip; they do not simulate progress.
- Per-interface live counters are rendered through the `/metrics` entry
  for that interface; otherwise `Not available` is shown.
- Historical trends are deliberately omitted — a one-point chart would
  mislead operators and we chose not to draw it.

## Policy

> No fabricated counters. Fixture data is only used in isolated
> Storybook/tests or explicitly marked demo mode.

Demo mode is only used by `e2e/mock-api.ts` (Playwright). Production
builds never serve fixtures.
