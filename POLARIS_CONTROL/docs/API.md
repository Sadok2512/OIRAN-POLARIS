# API contract

Base URL: `http://127.0.0.1:49153/api/v1`.

Read-only routes allow anonymous Viewer access. Operator and Administrator accounts authenticate over HTTPS. Rust stores sessions server-side and returns a Secure HttpOnly cookie; mutation requests also require the session CSRF token. Public-IP HTTP cannot create or use privileged sessions.

| Route | Role | Purpose |
|---|---|---|
| `GET /health` | public loopback | Liveness only |
| `GET /version` | Public Viewer | Component versions |
| `GET /capabilities` | Public Viewer | Explicit supported/unavailable features |
| `POST /auth/login` | Public over HTTPS | Verify a named account and create a server session |
| `POST /auth/logout` | Authenticated + CSRF | Revoke the current server session |
| `GET /auth/me` | Viewer | Effective role |
| `GET /system/health` | Viewer | Real disk measurement and safety decision |
| `GET /lab` | Viewer | Sanitized read-only lab inventory |
| `GET /scenarios` | Viewer | Controller-owned jobs only |
| `GET /scenarios/running` | Viewer | Active controller-owned jobs only |
| `GET /scenarios/status` | Viewer | Authoritative active job plus most recent terminal job |
| `GET /scenarios/history` | Viewer | Controller history |
| `GET /ues` | Viewer | UE profile and runtime inventory |
| `POST /configuration` | Operator + CSRF | Persist desired count and enqueue one idempotent delta reconciliation; returns `202` |
| `POST /ues/start` | Operator + CSRF | Compatibility endpoint for one exact provisioned controller-owned UE |
| `POST /ues/stop` | Operator + CSRF | Stop one exact controller-owned UE job; never a shared UE |
| `POST /ues/group/start` | Operator + CSRF | Compatibility endpoint for an exact bounded provisioned set; UE-01 remains protected |
| `POST /ues/group/stop` | Operator + CSRF | Stop only the selected controller-owned UE jobs |
| `GET /traffic/status` | Viewer | Bounded traffic runtime state |
| `POST /scenarios/validate` | Operator + CSRF | Validate the exact bounded profile and issue a five-minute session precondition |
| `GET /scenario-capabilities` | Viewer | Certified policies, authorization state, resource readiness |
| `POST /scenarios/start` | Operator + CSRF | Starts only `bounded-existing-ue-udp-v1` after validation and all gates pass |
| `POST /scenarios/stop` | Operator + CSRF | Stops the exact controller-owned job; never a shared process |
| `POST /admin/scenario-policy` | Administrator + CSRF | Persistently enables or disables the certified policy |
| `GET /live-tests/polaris-live-001` | Viewer | Persistent result and current one-time approval state |

The API never accepts filesystem paths, arbitrary destinations, or shell commands.

Multi-UE responses keep desired, process, Registration, PDU Session and traffic state as independent fields. The stable profile allowlist is UE-01 through UE-10, while `max_ues_live_certified` remains `1`; implementation and offline tests are not certification. Current NAS (`nr-cli status`), current PDU (`nr-cli ps-list`), and a same-session address on a `uesimtunN` interface drive Registration/PDU state; container health and historical log success do not. Reconciliation also requires `POLARIS_ADDITIONAL_UE_LIVE_ENABLED=true` in live mode.

The UE job registry path is configured with `POLARIS_UE_JOB_STATE_PATH`. Registry writes are atomic. Restart recovery retains an active handle only when its exact container ID and ownership/profile labels are still proven; otherwise it fails closed.
