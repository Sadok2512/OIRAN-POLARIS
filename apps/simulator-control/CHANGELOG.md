# @telecom/simulator-control — Changelog

Format: SemVer. Pre-1.0 releases are allowed to introduce backward-incompatible
UI-level changes between minor versions.

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
