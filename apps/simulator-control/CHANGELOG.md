# @telecom/simulator-control — Changelog

Format: SemVer. Pre-1.0 releases are allowed to introduce backward-incompatible
UI-level changes between minor versions.

## 0.4.1 — 2026-10-28 (patch)

Review feedback on 0.4.0: four honesty corrections on the new Network section.

### Fixed

- `isLinkUp()` is replaced by `linkState()` returning `configured`, `down`
  or `unknown`. The UI never says "UP" — NG Setup success stays `unknown`
  until a dedicated backend route proves it. "configured" means the
  process is running AND an endpoint is reported; "down" means the process
  isn't running; "unknown" means no endpoint is reported.
- Topology and Core · Open5GS now badge the aggregate container as
  **`AMF container: <process_state>, <health>`** (source line explicitly
  cites `/lab.observed.open5gs = oiran-lab-amf-1`). The old "5G Core
  HEALTHY" aggregate wording is gone; every other NF remains "not exposed".
- Topology eNB cards swap the 5G labels for LTE ones:
  **S1-MME · S1AP** and **S1-U · GTP-U** instead of N2 / N3.
- Screenshots refreshed under `docs/screenshots/`. The companion
  `docs/screenshots/README.md` makes the "mocked API" nature explicit.

### Validation (manual, no CI)

- `npm run typecheck` → clean
- `npm test` → Test Files 14 passed (14) · Tests 117 passed (117)

## 0.4.0 — 2026-10-28 (minor)

Alignment on the UI mockups in `docs/ui-mockups/polaris-control.html` (branch
`origin/docs/ui-mockups` @ `04d7c79`). Adds a dedicated **Network** section
with Topology, Core · Open5GS and gNodeBs; no mutating route is exercised,
every unavailable backend contract is surfaced as a locked UI control with
its reason text.

### Added

- `/network/topology` (`src/pages/Topology.tsx`): client-side composition
  of `GET /lab` + `GET /nodes` + `GET /ues`. Shows the Open5GS container
  state, each gNB with its PLMN / Cell ID / link / N2 / N3 endpoint, and
  the UEs that report `serving_node = <id>`. NGAP state is "unknown" when
  the backend didn't report an endpoint or state — never fabricated.
- `/network/core` (`src/pages/CoreOpen5gs.tsx`), 3 tabs:
  - **Network functions**: AMF HEALTHY read from the aggregate container
    reported by `/lab`; every other NF (SMF/UPF/NRF/…) is listed with
    `not exposed` because POLARIS does not yet surface per-NF state. Every
    Restart button is locked with the reason text.
  - **Configuration**: PLMN / TAC / S-NSSAI / DNN only when
    `GET /capabilities` carries them, otherwise `not exposed`. Edit
    configuration button locked.
  - **Subscribers**: `GET /ue-profiles/provisioning-slots` with `slot_id`
    and `bound_ue_id` only. Identity column is always "PROTECTED" — no
    IMSI, K or OPc is ever requested or rendered. Provision button locked.
- `/network/gnbs` (`src/pages/Gnbs.tsx`): reads `GET /nodes`. GNB-01
  renders as the real card (`SHARED_NODE_PROTECTED` surfaced); GNB-02 is
  dashed with the exact backend reason `LIVE_005_APPROVAL_REQUIRED` and
  a locked "Deploy and start" button; ENB-01 lives under the "LTE profile
  (not certified)" group with the badge `LTE_ATTACH_NOT_CERTIFIED`. "Add
  gNodeB" and every start/stop button are locked.
- `useLabObserved()`, `useProvisioningSlots()`, `useGnbs()` typed hooks in
  `src/data/queries.ts`.
- Tests: 112 pass (11 new across the three Network pages + 2 updated in
  `App.test.tsx`). Commands reported in the PR summary.

### Changed

- Sidebar now shows an explicit **NETWORK** section (Topology, Core · Open5GS,
  gNodeBs) and groups the simulator pages under **SIMULATION**. The legacy
  `Network Nodes` entry is retired.
- `/nodes` route still responds with a redirect to `/network/gnbs`, so old
  bookmarks don't 404. `NetworkNodes.tsx` stays on disk for reference but
  is no longer routed to.

### Unchanged

- UE Manager, Scenarios, Scenario Builder, Execution Monitor, Settings:
  not touched. All their existing tests remain green.

### Open items (declared)

- Per-NF state (SMF/UPF/NRF/…): POLARIS `/lab` only exposes the aggregate
  `open5gs` container; individual NF state renders as `not exposed` until
  the backend splits them.
- Topology link state: based on `process_state === 'running'` plus the
  presence of an endpoint. There is no `/ng-setup` route yet; the UI never
  guesses an NGAP OK status.

## 0.3.1 — 2026-10-28 (patch)

- Update `react-router-dom` to `6.30.6` to close the production React Router redirect/XSS
  advisories without changing routes or application behavior.

## 0.3.0 — 2026-10-28 (minor)

Wired to polaris-control-api 0.11.0 (`feat/polaris-gnb-binding-and-provisioning`).
Both backend switches stay OFF by default.

### Fixed (would have broken every backend call)

- **POLARIS bodies are raw JSON**, not the OIRAN `{data, meta}` envelope. Every
  POLARIS query read `envelope.data` and therefore received `undefined` in
  production; the test fixtures used the envelope, which hid it. New
  `src/data/polarisClient.ts` reads the raw body (and still unwraps a real
  `{data, meta}` envelope). `queries.ts` and `scenarioApi.ts` share it.
- **POLARIS error codes**: `{"error":"CODE"}` is now surfaced as `ApiError.code`
  (shared `packages/ui/src/api.ts`, backward compatible with OIRAN errors).
- **Fixed parameters** are sent as `{"fixed": value}`; a bare number is rejected
  by the backend (`ParameterSpec` is an untagged enum of `fixed` / `random`).
- **Random bounds** must be integers (backend `i64`); non-integers are refused.
- **Scenario loop** is the definition `loop_count` (scenario 0.10.0); steps get
  `loop_count: 1`. RANDOM and INFINITE loops are refused instead of being
  converted to `max` — the editor disables them in backend mode (V2 badge).
- `GET /scenario-definitions` returns `{items, total, schema_version}`;
  `GET /scenarios/:job_id/steps` returns `{job_id, scenario_definition_id, steps}`;
  step times are epoch **seconds**; clone requires `{target_id}`.
- Execution Monitor follows the current job (active, else latest terminal), so
  mock-mode definition runs — which complete immediately — are visible; shows
  scenario/step loop positions.

### Added

- `src/scenarios/library.ts` — `useScenarioLibrary()`: Library, Builder,
  Console, UE Manager and Monitor use the backend catalog when
  `scenarioBackend` is ON (create = POST on first save, update = PUT).
- `profileBackend` flag + `src/data/profileApi.ts`, `src/ue/profileSource.ts`,
  `src/ue/UeProfileBackendForm.tsx`: UE profiles created, edited, cloned,
  deleted and assigned through `/ue-profiles`. Identity is write-only:
  preferred path is a **provisioned subscriber slot** (backend reads SUPI/K/OPc
  server-side); manual SUPI/K/OPc use password inputs and are never stored.
  Serving gNB comes from `GET /gnbs`. Open5GS status badge per row.
  Sanitized CSV export from the server. CSV import and bulk stay disabled in
  backend mode (no import route; bulk UI planned for V1.1).
- Tests on measured contract bodies: 83 → 100 (`npm test`: 11 files, 100 passed).

## 0.2.0 — 2026-10-28 (minor)

Alignment on polaris-control-api 0.9.0 (commit `f676ceb`, not yet pushed to
the shared remote at the time of writing). Nothing calls new backend routes
until the operator enables **Settings → Use backend scenario catalog (0.9.0)**;
default is OFF so `polaris.scenarios.v1` stays authoritative.

### Added

- `src/data/featureFlags.ts` — localStorage-backed flag store with
  `scenarioBackend` (default OFF).
- `src/data/scenarioApi.ts` — typed React Query hooks for the new routes
  (`GET/POST /scenario-definitions`, `GET/PUT/DELETE /:id`, `POST /:id/clone`,
  `POST /scenarios/start`, `GET /scenarios/:job_id/steps`). All hooks are
  `enabled: false` while the flag is OFF — no request is issued.
- `src/scenarios/wireCodec.ts` — pure codec between the local `Scenario`
  model and the wire shape `{id, name, version, steps:[{type, loop_count,
  parameters}]}`. Numeric params encode as bare numbers or
  `{random:{min,max}}`.
- Settings page: operator-visible toggle for the `scenarioBackend` flag.
- Execution Monitor: when the flag is ON, replaces the local projection
  with a live `/steps` section rendering `state` and `resolved_parameters`
  per step.
- Tests: 18 new (`wireCodec.test.ts` 11, `scenarioApi.test.tsx` 4,
  plus coverage counted in existing suites) — total **83 passed (8 files)**.

### Changed

- `STEP_METADATA` in `src/scenarios/model.ts`: `REGISTER_5G`,
  `WAIT_REGISTRATION`, `DEREGISTER` flipped from `backendCertified: true`
  to `false`. The polaris-control-api 0.9.0 contract only accepts six
  types (`ue_start`, `ue_stop`, `pdu_establish`, `pdu_release`,
  `udp_traffic`, `wait`); the three affected kinds remain visible in
  the Builder with a "Backend requis" badge and the exact note:
  *Not in polaris-control-api 0.9.0 (6-type whitelist)*.
- `UeInventory` TypeScript interface: optional `cache_version?: string`
  and `cache_fresh?: boolean` added for forward-compatibility with /ues
  0.9.0. Not consumed in UI (no field invented, no behavior change).

### Unchanged

- `polaris.scenarios.v1` / `polaris.assignments.v1` are untouched —
  local catalog remains authoritative while the flag is OFF.
- `polaris.ueProfiles.v1` is untouched — the UE-profile contract from
  the backend is still **OPEN**.

### Open items (declared, not closed)

- **Scenario-level `loop_count`** — the published contract only shows
  `loop_count` at step level. The frontend currently spreads the local
  scenario loop across every step on encode (`FIXED` → `cycles`, `RANDOM`
  → `max`, `INFINITE` → rejected). Codex has been asked for a scenario-
  level loop field; the codec will be adjusted when confirmed.
- **UE-profile contract** — no routes published yet. UE profiles stay
  on `polaris.ueProfiles.v1` as per spec (point 4 of the task).
- **Backend error envelope** — surfaced as `.message` string; exact
  JSON shape pending the final backend doc.

## 0.1.0 — 2026-10-27 (initial)

Previous Scenario Builder + UE Profile Manager V2 scope (see
`feat/polaris-simulator-ui-v2`).
