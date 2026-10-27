# Release Consolidation Fix V1.1 — POLARIS Control

Date: 2026-10-27 UTC

## Root cause

`GET /api/v1/ues` performed the complete Docker/NR runtime observation on each request. The production-shaped observation takes about 1.9 seconds. Concurrent route polling and the browser inventory scenario repeatedly re-entered that expensive path, producing the 19/20 timeout.

The observation lock and cache were also process-global statics, which made isolated application states share freshness implicitly.

## Correction

- UE observation coordination, cache, and freshness timestamp are now owned by `AppState`.
- A successful observation is reusable for ten seconds; configuration rows are still rebuilt for every response.
- Cache expiry and application restart force a fresh authoritative observation.
- Lifecycle execution, ownership, RBAC, CPU/RAM/disk gates, and shared UE protection are unchanged.

## Measured candidate behavior

- First authoritative observation: 1.909 seconds.
- Four subsequent cached responses: 0.082–0.093 seconds.
- After candidate restart: first refresh 1.870 seconds, next response 0.088 seconds.
- Counts before and after restart: 4 configured, 3 running, 3 registered, 3 active PDU sessions.

## Validation

- Rust workspace: 89 passed, 0 failed.
- API crate: 55 passed, 0 failed.
- Frontend: 5 passed, 0 failed; TypeScript/production build passed.
- Browser E2E: 20 passed, 0 failed, 0 skipped, 0 flaky in 60.908 seconds.
- The dedicated regression verifies a fresh inventory response completes in under 100 ms even while the observation slot is occupied.

## Candidate artifacts

- `polaris-control-api`: `12bd6ccb66f42d540c5ef7dab3db8ea9d8a99d30903789cf64fc570ec186567c`
- Frontend JavaScript: `767aecacfc519ca6ffd7ce6154f1abb176f5dad58b5ab46ada873694a0bfc8db`

No production service, UE, gNB, Open5GS component, capture process, or ETV/OTV process was modified.
