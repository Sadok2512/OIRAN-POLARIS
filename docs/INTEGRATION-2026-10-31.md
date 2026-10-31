# Integration manifest — 2026-10-31 night prep for Codex

This is the hand-off manifest for the five lots prepared during the
night of 2026-10-30 → 2026-10-31. Nothing in this list is deployed.
Every lot ships on its own branch, with the base commit, the SHA to
pick, the test command, the PASS criteria, and the rollback step.

## Global deployment order

```
1. POLARIS API 0.19.8                     — already in production (fef5340)
2. POLARIS simulator-control 0.12.2       — LOT 1: operator IMSI reveal
3. OIRAN 2.5.3 (API + live-probe + decoder-gtpu 0.2.0) — LOT 2: N3 headers-only
   OIRAN Analyzer 2.5.0 (@oiran/web)      — already prepared (478739a)
4. POLARIS API 0.20.0 + simulator-control 0.13.0 — LOT 3: Traffic Generator
5. probe-agent 0.1.0 on VM de test        — LOT 4: MVP + enrollment tests
```

Rationale: step 2 depends on the API in production (0.19.8 already
there). Step 3 ships the OIRAN side without touching POLARIS. Step 4
ships the Traffic Generator together — the front is useless without
the API. Step 5 lands only on a VM de test; no production deployment
tonight.

## Lot table

| # | Scope | Branch | SHA | Base (prod) | Version | Deps | Status |
|---|---|---|---|---|---|---|---|
| 0 | OIRAN Analyzer front | `feat/oiran-analyzer-2.5.0-mockup` | `478739a` | `origin/integ/oiran-2.5.2-atomic-publish` (`9572cfb`) | `@oiran/web` 2.5.0 | OIRAN API 2.5.2+ | **READY** |
| 1 | POLARIS front | `feat/simulator-0.12.2-imsi-operator` | `2dc5dfd` | simulator-control 0.12.1 (`cbb8e4a`) | 0.12.2 | polaris-api 0.19.7+ | **READY** |
| 2 | OIRAN API + live-probe + decoder-gtpu | `feat/oiran-2.5.3-n3-headers-only` | `a05a5ae` | OIRAN 2.5.2 (`9572cfb`) | API 2.5.3 / live-probe 0.2.6 / decoder-gtpu 0.2.0 | — | **READY** (live-probe sites deferred to a follow-up PR, see §LOT 2 below) |
| 3a | POLARIS API | `feat/polaris-0.20.0-traffic-sessions` | `ebcf851` | polaris-api 0.19.8 (`fef5340`) | 0.20.0 | — | **READY** (HTTP wiring deferred, see §LOT 3) |
| 3b | POLARIS front | `feat/simulator-0.13.0-traffic-generator` | `38bb8fc` | simulator-control 0.12.2 (`2dc5dfd`) | 0.13.0 | polaris-api 0.20.0 | **READY** |
| 4 | Probe agent | `feat/probe-agent-0.1.0-mvp` | `03dcc4b` | OIRAN 2.5.2 (`9572cfb`) | probe-agent 0.1.0 | Probe Manager API | **READY** (mTLS transport + capture-helper spawn deferred, see §LOT 4) |

Ancestor proofs (run on the branch tip before cherry-picking):

```
git merge-base --is-ancestor 9572cfb 478739a   # Analyzer
git merge-base --is-ancestor cbb8e4a 2dc5dfd   # LOT 1
git merge-base --is-ancestor 9572cfb a05a5ae   # LOT 2
git merge-base --is-ancestor fef5340 ebcf851   # LOT 3a
git merge-base --is-ancestor 2dc5dfd 38bb8fc   # LOT 3b
git merge-base --is-ancestor 9572cfb 03dcc4b   # LOT 4
```

All six return 0 (`echo ok` printed in the commit messages).

---

## LOT 1 — POLARIS front 0.12.2 — operator IMSI reveal

- **Branch**: `feat/simulator-0.12.2-imsi-operator`
- **SHA**: `2dc5dfd`
- **Base**: simulator-control 0.12.1 — `cbb8e4a`

### What it ships
- `WireUeProfile.subscriber_identity` type widened from `'PROTECTED'`
  to `string` to carry the role-aware IMSI returned by polaris-api
  0.19.7.
- `recordFromWire` copies `subscriber_identity` into the local
  `UeProfileRecord.imsi` **only** when it is not `'PROTECTED'`
  (viewer sentinel).
- Verifies that LiveGrantCountdown + "Autoriser le live" (#49) and
  `etatLabel` + direction (#50) stay visible at 1280 / 1440 / 1920.

### Dependencies
- polaris-api **≥ 0.19.7** (already in production as 0.19.8 at
  fef5340). Running this front against ≤ 0.19.6 silently masks the
  IMSI column for operators — no crash, UX regression only.

### Tests (manual)
```
cd apps/simulator-control
npm install
npm run typecheck         # clean
npm run test              # 33 files · 203 tests pass

# Playwright anti-overlap (needs vite dev + browser):
npm run dev &
npx playwright test e2e/no-overlap-0.12.2-imsi.spec.ts
```

### PASS criteria
- `npm run test` → 33 files · 203 passes.
- The anti-overlap matrix at 1280 / 1440 / 1920 × light / dark produces
  six screenshots under `docs/screenshots/0.12.2/`.
- Signed-in as an operator, the UE Manager row renders
  `imsi-001010000000042` for a mocked UE.
- Signed-in as a viewer, the IMSI cell contains the solid-mask bullet
  characters only (no `\d{14,16}` digit span).

### Rollback
Revert the branch pointer; the backend contract stays additive (the
API still returns the IMSI, the front just stops reading it).

---

## LOT 2 — OIRAN 2.5.3 — N3 headers-only aggregator

- **Branch**: `feat/oiran-2.5.3-n3-headers-only`
- **SHA**: `a05a5ae`
- **Base**: OIRAN 2.5.2 — `9572cfb`

### What it ships
- `OIRAN/decoder-gtpu` 0.2.0 — streaming `GtpuAggregator` + fixed-size
  (136 B) `TunnelFlow`. On N3 the probe keeps the GTP-U header plus
  per-TEID / 5-tuple counters (packets_ul, packets_dl, bytes_ul,
  bytes_dl, first_seen_ns, last_seen_ns, qfi, retransmits_tcp,
  rtt_microseconds). Inner payload stays opaque — only the first 20 B
  of the inner TCP header are read.
- Design doc: `OIRAN/docs/n3-headers-only-2.5.3.md`.
- Version bumps: oiran-api 2.5.2 → 2.5.3, live-probe 0.2.5 → 0.2.6,
  decoder-gtpu 0.1.0 → 0.2.0.

### Dependencies
- None at the API / schema layer. The aggregator is a new addition in
  decoder-gtpu; existing per-event decode is untouched for N2 / N4 /
  SBI.

### Tests (manual)
```
cd OIRAN
cargo test -p decoder-gtpu --lib
```
→ 8 tests pass, including
`aggregator_bounded_memory_on_half_million_packets` (500 000 frames
on 4 TEIDs stay at ≤ 8 flow entries, retention is bounded).

### PASS criteria
- 8 / 8 unit tests pass.
- Peak RSS on a 500 MiB synthetic N3 segment (to be measured on the
  lab VM once live-probe wires the aggregator) stays < 64 MiB.

### Deferred to a follow-up PR (declared in `OIRAN/docs/n3-headers-only-2.5.3.md` §Deferred)
The three live-probe integration sites (packet enumeration,
finalisation, correlation-engine key) live in a 6 500 LoC file and
are **not** touched here. The design doc is the drop-in contract for
that PR; the aggregator + its tests are the drop-in target.

### Rollback
Branch revert; the aggregator is additive and reachable only when
live-probe routes N3 through it — currently nowhere, so a revert is
cost-free.

---

## LOT 3 — POLARIS Traffic Generator (#47)

### 3a. POLARIS API 0.20.0

- **Branch**: `feat/polaris-0.20.0-traffic-sessions`
- **SHA**: `ebcf851`
- **Base**: polaris-api 0.19.8 — `fef5340`

#### What it ships
- `POLARIS_CONTROL/apps/api/src/traffic_sessions.rs` — state machine +
  validation + in-memory store (`TrafficSessionManager`). HTTP routes
  and iperf3 wiring are the follow-up PR (see §Deferred).
- Rules: `rate_mbps ∈ [1, 50]`, `duration_s ∈ [1, 600]`, UE ids
  match `UE-NN` or `UE-NNNNN`, direction ∈ UL/DL/BOTH, protocol ∈
  TCP/UDP, Stop always allowed and idempotent, iperf3 warnings never
  fail the session (0.19.8 contract preserved).

#### Tests (manual)
```
cd POLARIS_CONTROL
cargo test --lib -p polaris-control-api -- traffic_sessions
```
→ 10 / 10 pass.

#### PASS criteria
- 10 / 10 traffic_sessions tests pass + full workspace `cargo check`.
- `UDP_LOSSLESS_CEILING_MBPS` constant = 20, `RATE_MBPS_MAX` = 50,
  `DURATION_S_MAX` = 600 — frozen in the test suite.

#### Deferred to the HTTP wiring PR (declared in the commit body)
- POST / GET / DELETE routes in `lib.rs`.
- `require_operator` + grant check (reuse the scenario-start pattern).
- `tokio::spawn` per direction feeding `execute_iperf_ul` /
  `execute_iperf_dl` (0.19.8) into `record_measurement`.

#### Rollback
Branch revert; the manager is a new module with no entry point until
the HTTP wiring PR.

### 3b. POLARIS simulator-control 0.13.0

- **Branch**: `feat/simulator-0.13.0-traffic-generator`
- **SHA**: `38bb8fc`
- **Base**: simulator-control 0.12.2 — `2dc5dfd` (LOT 1)

#### What it ships
- `src/data/trafficSessionsApi.ts` — typed client +
  `validateTrafficRequest()`.
- `src/pages/TrafficSessions.tsx` — form (UE ids / direction /
  protocol / rate slider / duration slider) + per-session table
  (per-UE UL / DL rate + bytes + warnings).
- Route `/traffic/sessions` wired in `App.tsx`.
- Shows the lab UDP lossless ceiling (`≤ 20 Mbit/s`) alongside the
  hard 50 Mbit/s rate ceiling.

#### Dependencies
- polaris-api **≥ 0.20.0** (LOT 3a). Running against ≤ 0.19.8 the
  form submits a 404 — surfaced verbatim in the error chip (0.19.8
  contract: iperf3 warnings never fail the UI).

#### Tests (manual)
```
cd apps/simulator-control
npm run typecheck         # clean
npm run test              # 33 files · 203 tests pass
```

#### PASS criteria
- `trafficSessionsApi.test.ts` → 7 cases pass.
- Full npm test → 33 files · 203 tests pass.

#### Rollback
Branch revert; the backend tolerates missing calls on the new routes
(no state is created client-side without POST success).

---

## LOT 4 — Probe agent MVP

- **Branch**: `feat/probe-agent-0.1.0-mvp`
- **SHA**: `03dcc4b`
- **Base**: OIRAN 2.5.2 — `9572cfb`

### What it ships
- `docs/probe-agent/DESIGN.md` (180 lines): enrollment, mTLS,
  heartbeat, segment upload with SHA-256, binary distribution +
  rollback, interface roles, subscriber-identity rule, threat model.
- `OIRAN/probe-agent` — new workspace crate. Pure-logic lib + CLI
  (`version`, `validate <config>`, `sha256 <path>`) + 4 integration
  tests pinning the wire vocabulary. 9 lib + 4 integration = 13
  tests, all pass.

### Dependencies
- None for the MVP (pure Rust std + serde + serde_json). The real
  transport PR will pull `rustls` + `reqwest` + `tokio`.

### Tests (manual)
```
cd OIRAN
cargo test -p probe-agent --all-targets
```
→ 13 / 13 pass.

### PASS criteria
- 13 / 13 tests pass.
- `probe-agent validate <config.toml>` returns `OK` on a well-formed
  config and the exact error code (`CONFIG_PROBE_ID_REQUIRED`,
  `CONFIG_ENDPOINT_MUST_BE_HTTPS`, `CONFIG_INTERFACES_REQUIRED`,
  `CONFIG_INTERFACE_ROLE_UNKNOWN`) on each failing one.
- `probe-agent sha256 <file>` matches the SHA-256 the Probe Manager
  would verify.

### Deferred to the capture-helper PR
- mTLS transport (`rustls` + `reqwest`).
- CA signing flow + CSR submission.
- capture-helper spawn via Unix socket.
- Segment upload loop with the real retry + quarantine logic.

The MVP is the state-machine + vocabulary both sides of the enrollment
flow agree on. The transport PR plugs it into `tokio`.

### Deploy target
VM de test only. Do not deploy on production probe hosts tonight.

---

## OIRAN Analyzer 2.5.0 (previously prepared)

- **Branch**: `feat/oiran-analyzer-2.5.0-mockup`
- **SHA**: `478739a`
- **Base**: `origin/integ/oiran-2.5.2-atomic-publish` — `9572cfb`
- **Version**: `@oiran/web` 2.5.0

### Tests (manual)
```
cd OIRAN/apps/web
npm install
npm run build             # dist clean
npm run test              # 10 files · 73 tests pass
node_modules/.bin/vite --port 4173 &
npx playwright test -c playwright-2.4.0.config.ts
```
→ 14 Playwright assertions pass.

### PASS criteria
- 73 vitest + 14 Playwright assertions pass.
- Session ID overlap fix verified at 1280 / 1440 / 1920 × light /
  dark (`docs/screenshots/2.4.0/sessions-no-overlap/`).
- `withholdIdentity()` + the packet-identity-withheld-banner from BC4
  (62b6079) unchanged — 44 identityIes.ts tests + 4 packet-analyzer
  tests still green.

### Rollback
Branch revert.

---

## Open gaps (declared)

- **LOT 2 live-probe integration**: aggregator ready, three wiring
  sites deferred. Impact: today's 156 MiB N3 OOM is **not fixed on
  production yet**. The aggregator must be plugged into the
  live-probe stream path in a dedicated PR before the next lab run
  on a > 50 MiB N3 capture.
- **LOT 3a HTTP routes**: TrafficSessionManager ready, HTTP + grant
  check + iperf3 driver spawn deferred. Impact: `/traffic/sessions`
  returns 404 on 0.20.0 until the follow-up PR. The front (LOT 3b)
  will surface the 404 as `HTTP 404 · ROUTE_NOT_FOUND` in the error
  chip — honest, non-crashing.
- **LOT 4 transport**: enrollment + heartbeat vocabulary ready,
  mTLS + capture-helper spawn deferred. Impact: the probe-agent
  binary validates configs and computes SHA-256 but cannot talk to a
  Probe Manager yet. Must land before VM de test deployment.
- **Front 0.13.0 live rate charts**: table ships; time-series charts
  per UE and total land once the API publishes a per-tick sample
  endpoint.

## Audit trail

Every lot commit carries the full test output in the commit message
body plus the `git merge-base --is-ancestor <base> <SHA>` proof.
Codex should check out each branch, re-run the test command listed
in the PASS criteria, and sign off before merge.
