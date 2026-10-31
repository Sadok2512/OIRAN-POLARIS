# POLARIS real laboratory live implementation — ANR2

Date: 2026-10-31 UTC  
Scope: POLARIS API and simulator-control UI, offline/read-only validation  
Verdict: **PARTIAL — candidate OFFLINE_PASS, production deployment BLOCKED**

## Git and versions

- Base: `integ/oiran-polaris-lte-e2e-v2` at
  `87daa3445e3058352d21efeba21d05fefe3029d4`.
- Branch: `feat/polaris-real-lab-live-p0-anr2`.
- Functional candidate: `e91211cbdacc787efe3bb98d05f8438ad53fdee9`.
- `git merge-base --is-ancestor 87daa344... e91211c...` returned `0`.
- Candidate API: `polaris-control-api 0.25.0`.
- Candidate UI: `@telecom/simulator-control 0.18.0`.
- Integrated functional commits: professional 13-template catalogue
  `abd226f`, dual LTE/5G topology `d38a4a9`, RAT-aware UE Manager `656f448`.
- No `merge -s ours` was used.

The shared foundation and the worktrees of ANR1/ANR3 were inspected but not
modified. All changes were made in `/root/OIRAN_POLARIS_REAL_LIVE_ANR2`.

## Production observation (read-only)

Production was not changed or restarted.

| Evidence | Observed value |
|---|---|
| URL | `https://151.242.147.49:8020/simulator/` — HTTP 200 |
| POLARIS API | `0.19.8`, platform `3.2.1` |
| Frontend | `0.11.1`, bundle `assets/index-CFDCtloT.js` |
| Bundle SHA-256 | `f2c58890df98f7c342307c9d6a6ddcdec1cd3a576a4716a52bb0408a95ac792c` |
| `/nodes` | HTTP 200 |
| `/ues` | HTTP 200; 2 configured, 0 active, 0 registered |
| `/scenario-templates` | HTTP 404 (HTML SPA fallback) |
| `/traffic/sessions` | HTTP 404 (HTML SPA fallback) |
| `/lte/status` | HTTP 404 (HTML SPA fallback) |

The real `/ues` response reported `Deployment validation` as `UNKNOWN /
NOT_OBSERVED` and `UE-201` as `STOPPED / DEREGISTERED`; neither item exposed a
UE IP. No LTE E2E state can be certified from that API version.

Real production capture (no click or mutation):
`apps/simulator-control/docs/screenshots/production-0.11.1-topology-1440.png`.
It proves the currently served page, but also shows that production still uses
the old contract and therefore is not evidence that candidate 0.18.0 is live.

## Candidate implementation

### Backend

- `/nodes` no longer publishes hard-coded PLMN, cell, link addresses or
  endpoints. It derives process state from Docker inspection and N2/S1 from
  bounded socket/runtime observations. UDP socket presence is
  `SOCKET_OBSERVED`, never falsely promoted to `CONNECTED`.
- LTE S1-U is `SESSION_OBSERVED` only when an observed session and UE IP exist;
  it is not presented as a proved peer connection.
- `/lte/profiles/LTE-SRSUE-TEST-01` publishes the canonical technology,
  simulator and serving RAN, with runtime/APN/timestamp sourced from the
  srsRAN runtime. Missing observations are `UNKNOWN`, `NOT_AVAILABLE` or null.
- `/lab.observed.lte_attach` comes from runtime observation instead of a fixed
  label.
- Traffic accounting no longer synthesizes requested-rate samples. Missing UE,
  route, PDU or iperf observation fails the session and publishes no sample.
- The immutable catalogue contains exactly 13 bounded templates: 6 LTE and 7
  5G SA. Existing UERANSIM controllers and routes remain present.
- Existing Grant V2, operator/viewer RBAC, CSRF, persistent ownership,
  expiration/revocation/anti-replay and controller cleanup paths are preserved.

### Frontend

- Operational feature flags are API-only; production localStorage cannot
  select browser UE/scenario fixtures.
- UE Manager joins the canonical LTE profile with real `/ues` runtime data,
  displays Technology, Simulator and Serving RAN, and leaves Attach,
  Registration, session and IP unknown until observed.
- Topology renders both real contract chains: UERANSIM/gNB/5GC with N2/N3 and
  srsUE/srsENB/EPC with S1-MME/S1-U. Link color requires explicit evidence.
- Scenario Builder and library consume server definitions/templates only.
- Traffic Generator selects UEs from `/ues` or the canonical LTE profile. It
  derives rates from successive observed cumulative counters and never from
  the requested rate.
- Console/Core and top bar no longer claim static core version, addresses,
  PLMN, TAC, slice, DNN or PASS states. Missing values display
  `NOT_AVAILABLE`/`UNKNOWN`.
- IMSI behavior remains role-aware: raw identity only for operator/admin;
  viewer receives the protected representation. Authentication secrets are
  never read back.

## Manual commands and results

Resource preflight was repeated before heavy commands. Successful runs began
with `MemAvailable >= 4194304 KiB`. Attempts below the threshold exited `75`
before starting work.

| Command | Result |
|---|---|
| `git diff --check` | PASS |
| `CARGO_BUILD_JOBS=1 cargo check -p polaris-control-api` | PASS; 7 warnings |
| `CARGO_BUILD_JOBS=1 cargo test -p polaris-control-api` | PASS; 228 passed, 0 failed, 3 ignored manual benchmarks |
| `cargo fmt --all -- --check` | FAIL; pre-existing format drift in the integrated base and several untouched files; no global rewrite performed |
| Node 20 isolated: `npm ci --no-audit --no-fund` | PASS; Node `v20.20.2`, 265 packages |
| `npm run typecheck` | PASS |
| `npm test -- --reporter=verbose` | PASS; 36 files, 224 tests |
| `npm run build` | PASS; 1708 modules, JS 539.02 kB (151.91 kB gzip) |
| Playwright Topology, 1280/1440/1920, light/dark | PASS; 6/6 |
| Playwright UE Manager, 1280/1440/1920, light/dark | PASS; 6/6 |
| Playwright Scenario Builder, 1280/1440/1920, light/dark | PASS; 6/6 |
| Playwright LTE lock + Traffic Generator, all six projects | PASS; 12/12 |

Two initial Playwright runs exposed obsolete assertions in old tests (`ACTIVE`
text instead of `data-pdu="ACTIVE"`, and the removed grouped Runtime header).
The assertions were updated to the current RAT-aware DOM contract and the six
projects then passed. Offline route stubs are explicitly test-only and are not
part of the built application.

Final safety evidence during the work:

```text
/dev/sda1 usage = 51%
dumpcap_count = 12
production writes/restarts = 0
live simulator starts = 0
grants created = 0
traffic launched = 0
```

## Remaining defects and blockers

1. Production remains API 0.19.8/UI 0.11.1. Its missing LTE, traffic-session
   and template routes prevent the candidate UI from being operational there.
2. Deployment was explicitly forbidden. Consequently the criterion “all
   production pages use only real sources” is not yet met.
3. No authorized LTE live run occurred. Attach, IP, UL/DL and LTE E2E remain
   `UNKNOWN`/not certified; this report does not claim `REAL_PASS`.
4. The candidate was validated with offline contract stubs and read-only
   production observation. A staging instance of API 0.25.0 connected to the
   lab is still required to capture candidate pages with real responses.
5. Repository-wide `cargo fmt --check` remains red from inherited formatting
   drift. Functional compile and tests are green.
6. ANR3 OIRAN live-session/call-flow integration is outside this ANR2 commit
   and must be integrated by its owning branch before final platform release.

## Controlled deployment and rollback plan (not executed)

1. Require distinct deployment authorization and ANR1 security/live gates.
2. Recheck disk `<85%`, RAM `>=4 GiB`, exactly 12 external dumpcap processes,
   and `git merge-base --is-ancestor` for both deployed API and frontend SHAs.
3. Back up the active API binary, frontend directory, state registries and
   reverse-proxy configuration with hashes and timestamps.
4. Stage API 0.25.0 and UI 0.18.0 in new versioned directories; verify their
   hashes and run read-only smoke tests before switching anything.
5. Switch API and frontend atomically as one release. Do not create a grant or
   start any UE during deployment verification.
6. Smoke-test `/version`, `/lab`, `/nodes`, `/ues`, `/lte/status`, canonical LTE
   profile, 13 templates and traffic-session reads; verify viewer/operator IMSI
   projection and mutation protections.
7. Any failed check rolls both components back to the saved API 0.19.8/UI
   0.11.1 release, followed by the same read-only smoke tests.

## Final assessment

The candidate code is **OFFLINE_PASS** for ANR2 functionality and security
regression testing. The overall requested production outcome is **PARTIAL /
BLOCKED_FOR_PRODUCTION** until an authorized atomic deployment and real-lab
read-only/staging validation prove the new endpoints. LTE E2E remains
uncertified by design.

— ANR2
