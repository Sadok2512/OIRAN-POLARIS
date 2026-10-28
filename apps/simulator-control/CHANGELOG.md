# @telecom/simulator-control — Changelog

Format: SemVer. Pre-1.0 releases are allowed to introduce backward-incompatible
UI-level changes between minor versions.

## 0.6.1 — 2026-10-28 (patch)

Align the provisioning calls with the real backend contract shipped by
Codex on polaris-control-api **0.15.1 (`fc6d8ed`)**. The 0.6.0 stubs
(/provisioning/import, /ue-profiles/import, multipart form data) are
gone; the UI now hits the real endpoints with the exact body shapes.

The integrated release also preserves the V2 scenario wire contract,
production base paths, live-locked template cloning, and adds an
authenticated production test for one protected subscriber plus a
two-row `/subscribers/bulk` import. Test credentials and subscriber
secrets are injected through the process environment and never logged.
Because API 0.15.1 is the required backend for this release,
`polarisProvisioning` now defaults to ON for fresh browser sessions
instead of rendering an unavailable provisioning page. The independent
UE profile-registry switch retains its prior default.
`scenarioTemplates` also defaults to ON because its read/clone contracts
are present in the required API 0.15.1.
The UE detail reader now normalizes the measured API 0.15.1 response
(`subscriber`, `snssai`, `last_job`) and renders missing Registration or
PDU fields as unavailable instead of crashing the route.

### Changed

- **`POST /subscribers/bulk`** replaces `/provisioning/import`. Body is
  **raw `text/csv`** (not multipart). Expected header:
  `imsi,k,opc,sst,sd,dnns,ambr_uplink,ambr_downlink`.
- **`POST /ue-profiles/bulk`** replaces `/ue-profiles/import`. Same
  `text/csv` contract. Expected header:
  `ue_id,gnb_id,note,imsi`.
- **`uploadCsvImport(target, file)`** in `src/data/provisioningApi.ts`:
  target type becomes `'subscribers' | 'ue-profiles'`; builds a plain
  `text/csv` body (`await file.text()`) and sets the matching
  `Content-Type` header.
- **CsvImportDialog descriptions** reflect the new column headers so the
  operator sees the real contract before uploading.

### Added

- **`AddSubscriberDialog`** (`src/subscribers/AddSubscriberDialog.tsx`)
  wired to `POST /subscribers` with the exact body:
  `{ imsi, k, opc, sst, sd, dnns[], ambr: { uplink, downlink } }`.
  IMSI, K and OPc are password inputs; the three fields are **scrubbed
  from React state immediately after submit** so the browser never
  retains the secret across renders. On success, a green banner shows
  the backend-assigned slot id and reminds the operator the material
  is now `PROTECTED`.
- Backend error codes are surfaced verbatim with the HTTP status —
  `409 SUBSCRIBER_NOT_POLARIS_OWNED`, `422 SUBSCRIBER_NOT_PROVISIONED`
  and others. No translation, no fallback copy.
- **`createSubscriber(input)`** helper exported from
  `src/data/provisioningApi.ts` so the dialog can live in its own
  module without pulling in the full React Query mutation surface.

### Removed

- The disabled "Add subscriber" placeholder on the Provisioning page is
  replaced with the real dialog.
- `/provisioning/import` and `/ue-profiles/import` paths are no longer
  referenced anywhere in the frontend.

### Validation (manual, no CI)

- `npx tsc --noEmit` → clean
- `npx vitest run` → **Test Files 23 passed (23) · Tests 148 passed (148)**
  (4 new in `AddSubscriberDialog.test.tsx`, CSV test rewritten against
  the real `text/csv` + `/subscribers/bulk` contract).
- `npm run build` → clean, no fixture leak in `dist/`.

## 0.6.0 — 2026-10-28 (minor)

Provisioning layer anticipating Codex's `feat/polaris-provisioning` branch
(polaris-control-api). Everything new sits behind the
**`polarisProvisioning`** feature flag, default **OFF**, honest "Backend
pending" placeholders when the backend returns 404. Three commits
compose this release:

### Added

- **Flag `polarisProvisioning`** (default OFF). When ON, the UI consumes
  `/owners`, `/plmns`, `/dnns`, `/subscribers`, `/ue-profiles/import`,
  `/provisioning/import` and `/ue-profiles/:id`. `profileBackend` is
  forced ON (the local UE form path is unmounted).
- **Templates "Clone"** no longer POSTs the backend clone route. It
  decodes the template into a `Scenario` and navigates to
  `/scenarios/new` with `location.state.seedFromTemplate`. The Builder
  consumes the seed, clears the id/version so Save creates a new
  definition; `tpl-*` stay read-only.
- **Add UE dialog** (`UeProvisioningAddDialog`) exposes four fields —
  Name, gNB, Owner, Note, masked IMSI. IMSI is a password input,
  cleared from component state immediately after submit; the backend
  echoes it back as `PROTECTED`.
- **Provisioning page** (`/provisioning`): subscriber directory + CSV
  import (≤ 100 000 rows). Sidebar entry under `PLATFORM`.
- **Shared `CsvImportDialog`** with a streaming preview
  (`src/data/csvImport.ts`): non-blocking chunked read (1 MiB blocks,
  yielding to the event loop between chunks), local cap at
  `CSV_IMPORT_MAX_LINES = 100 000`, per-line backend error report
  rendered as a scrollable table (code column + message). Used by
  Provisioning AND the UE Manager (Import CSV button swaps to the
  backend dialog under the flag).
- **UE detail page** (`/ues/:ueId`) with eight structured blocks —
  Identity, Provisioning, Network profile, Registration, PDU sessions,
  IMS, Scenario, Traffic. IMSI/authentication display as `PROTECTED`
  (with a lock icon). Links from UE Manager rows when the flag is ON.
- **Dropdowns**: `/owners`, `/plmns`, `/dnns`, `/gnbs` and
  `/scenario-definitions` back every write path. Free-text input is
  gone from the create-time surface; dropdowns show "Backend pending"
  when their directory is empty or 404.
- **Playwright minimal setup**: `playwright.config.ts` with two
  projects (`chromium-light`, `chromium-dark`), `e2e/captures.spec.ts`
  with `page.route`-mocked POLARIS, screenshots for Templates /
  UE Manager / Provisioning / UE detail land in
  `docs/screenshots/v0.6.0/*.{chromium-light,chromium-dark}.png`.
  Captures are tagged as "mocked API" in `docs/screenshots/v0.6.0/README.md`.

### Benchmarks

- **CSV preview — 100 000 rows parsed in ~211 ms** (jsdom, see
  `src/data/csvImport.test.ts` stdout). A `setTimeout(…, 0)` sentinel
  task fires during the parse — proof the main thread yields and the
  UI stays responsive without a Web Worker.

### Validation (manual, no CI)

- `npx tsc --noEmit` → clean
- `npx vitest run` → **Test Files 22 passed (22) · Tests 144 passed (144)**
- `npm run build` → clean
- Playwright captures: run `npm run e2e` after
  `npm install @playwright/test@1.57.0` (added to `devDependencies`).

## 0.5.2 — 2026-10-28 (patch)

Honesty follow-up on the Scenario Builder palette: `TRAFFIC_UL`, `DETACH`
and `REPEAT` are NOT executed by the production backend today. 0.5.1
incorrectly offered them as clickable because scenario-definition v2 was
assumed landed on `polaris-control-api`. It is not.

### Changed

- **`STEP_METADATA` demotion**: `TRAFFIC_UL`, `DETACH`, `REPEAT` move from
  `backendCertified: true` to `backendCertified: false`. Each now carries
  the exact reason **"Backend pending: feat/polaris-traffic-templates."**.
  Pre-0.5.2 whitelist of clickable chips is now: `UE_START`,
  `PDU_ESTABLISH`, `UDP_TRAFFIC`, `IDLE`, `PDU_RELEASE`, `UE_STOP` — **6
  chips**.
- **Capabilities-driven promotion**: `Capabilities` gains an optional
  `scenario_step_kinds?: string[]`. When `GET /capabilities` lists a wire
  type (e.g. `"traffic_ul"`), the Builder promotes that kind back to
  "Supported" automatically — without touching `STEP_METADATA`. The
  single source of truth for "the backend will execute this step" is the
  capabilities payload, not a frontend constant.
- **New helper** `isStepKindExecutable(kind, advertisedWireTypes)` in
  `src/scenarios/model.ts` centralises the OR between the metadata flag
  and the advertised wire-type list, so ScenarioBuilder, Save guard and
  banner all answer the same question identically.

### Validation (manual, no CI)

- `npx tsc --noEmit` → clean
- `npx vitest run` → **Test Files 17 passed (17) · Tests 129 passed (129)**
  (new test covers both the 6-chip baseline and the capabilities-driven
  promotion of `traffic_ul` / `detach` / `repeat`).
- `npm run build` → clean, no fixture leak in `dist/`.

## 0.5.1 — 2026-10-28 (patch)

Honesty pass on the Scenario Builder: `scenarioBackend` now defaults to ON,
so the first thing a new operator sees is the certified-only palette and
the backend-safe loop presets. The local catalog becomes an explicit
**offline-draft** mode behind the existing Settings toggle.

### Changed

- **`scenarioBackend` default: OFF → ON** (`src/data/featureFlags.ts`).
  Settings now labels the toggle "Honest Builder" vs "Offline draft" so
  operators understand what each state means.
- **ScenarioBuilder palette** (`src/pages/ScenarioBuilder.tsx`): split
  into two groups.
  - **Supported** (9 chips, clickable): the backend-certified step kinds —
    `UE_START`, `PDU_ESTABLISH`, `UDP_TRAFFIC`, `IDLE`, `PDU_RELEASE`,
    `UE_STOP`, `TRAFFIC_UL`, `DETACH`, `REPEAT`.
  - **Not supported yet** (11 chips, locked with `aria-disabled="true"`
    and their exact `backendNote` on `title`): `REGISTER_5G`,
    `WAIT_REGISTRATION`, `TCP_TRAFFIC`, `ICMP_TRAFFIC`, `HTTP_TRAFFIC`,
    `WAIT_RRC_CONNECTED`, `WAIT_RRC_IDLE`, `DEREGISTER`, `TRAFFIC_DL`,
    `IMS_REGISTER`, `VOICE_CALL`.
- **LoopEditor** (`src/components/LoopEditor.tsx`): `Custom` joins
  `Infinite` and `Random` as a locked preset when `backendOnly === true`.
  Only `Once`, `×50` and `×100` stay clickable; operators who need an
  exact count click a preset and edit the cycles input.
- **Save blocked in backend mode when the draft holds a non-certified
  step**. A warning banner (`data-testid="builder-locked-step-banner"`)
  tells the operator to either remove the step or flip to offline-draft.

### Validation (manual, no CI)

- `npx tsc --noEmit` → clean
- `npx vitest run` → **Test Files 17 passed (17) · Tests 128 passed (128)**
  (4 new tests in `src/pages/ScenarioBuilder.test.tsx`)
- `npm run build` → clean (same bundle shape as 0.5.0, no fixture leak).

## 0.5.0 — 2026-10-28 (minor)

Preparation layer for the scenario-definition v2 contract that Codex ships
on `feat/polaris-traffic-templates` (`polaris-control-api` 0.11.0). Nothing
in this release calls the new backend by default — every network path is
gated behind the `scenarioTemplates` feature flag (OFF by default) so the
UI continues to work against today's 0.10.0 contract until an operator
flips the flag in Settings.

### Added

- **Feature flag `scenarioTemplates`** (default OFF) in
  `src/data/featureFlags.ts`. Everything below is gated by it.
- **Scenario model**: 6 new step kinds — `TRAFFIC_DL`, `TRAFFIC_UL`,
  `DETACH`, `REPEAT`, `IMS_REGISTER`, `VOICE_CALL`. Each one carries its
  own `backendCertified` + `backendNote`, so the editor renders the exact
  backend refusal code (`DL_SENDER_NOT_AVAILABLE`, `IMS_NOT_AVAILABLE`,
  …). The new numeric parameters `bytes`, `rate_kbps`, `duration_ms` and
  `loop_count` land in `PARAM_META` with the backend caps
  (`bytes ≤ 200 MiB`, `loop_count ≤ 10 000`). `MAX_REPEAT_NESTING = 2`
  and `MAX_RESOLVED_STEPS = 10_000` mirror the backend validator.
- **Wire codec**: `WireScenarioStep.steps?` (nested list used by
  `type: "repeat"`), `SCENARIO_SCHEMA_VERSION =
  "polaris.scenario-definition.v2"` and `WireScenarioExportFile` matching
  the `GET /scenario-definitions/:id/export` response.
- **Scenario-templates client** `src/data/scenarioTemplatesApi.ts`:
  `useScenarioTemplates()` (filters `/scenario-definitions` to `tpl-*`),
  `useScenarioEstimate(id)`, `downloadScenarioExport(id)` (parses
  `Content-Disposition`, falls back to `${id}-v${version}.json`,
  surfaces the exact backend code on failure), and `useScenarioImport()`
  (`POST /scenario-definitions/import?mode=new_version | ?rename=<id>`,
  propagates 409 / 413 / 422 verbatim).
- **Scenarios page** gains a **Templates** tab (locked when the flag is
  OFF, honest "Backend pending" message when the backend returns 404),
  with Clone and Download JSON actions per template.
- **Import JSON dialog** (`src/scenarios/ImportScenarioDialog.tsx`): file
  picker → local JSON parse → local `schema_version` check → structural
  preview with the nested step tree → `POST /scenario-definitions/import`;
  on 409 (`SCENARIO_ID_EXISTS` or `TEMPLATE_ID_RESERVED`), offers "Import
  as new version" or "Rename & import"; backend error codes are shown
  verbatim (no translation).
- **Builder**: nested step editor for `REPEAT` with a nested palette and
  a depth guard aligned on `MAX_REPEAT_NESTING = 2`. Locked step kinds
  render their backend-note badge verbatim so the operator sees the exact
  refusal code before saving.

### Validation (manual, no CI)

- `npx tsc --noEmit` → clean
- `npx vitest run` → Test Files 16 passed (16) · Tests 124 passed (124)
- `check-dist-leaks` guard stays clean (fixtures live only in tests).

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
