# ANR3 POLARIS default scenarios UI report

Date: 2026-10-31  
Scope: offline UI integration only  
Base: `integ/oiran-polaris-lte-e2e-v2` at `87daa3445e3058352d21efeba21d05fefe3029d4`  
Branch: `feat/anr3-polaris-default-scenarios-ui-v1`  
Worktree: `/root/POLARIS_DEFAULT_SCENARIOS_ANR3`

## Result

The existing POLARIS Scenario Builder now consumes the finalized ANR1
`polaris.scenario-template-catalog.v1` contract. It exposes the exact thirteen
system IDs (six LTE and seven 5G), RAT/category filters, immutable metadata,
steps, duration, bounded throughput, prerequisites and authoritative support
status. `Use Template` and `Customize` load the existing builder. Saving uses
the server clone route and then updates only the new mutable definition.

No second application was created. No UE Manager file was changed. No live
state is synthesized and Run remains disabled when role, step support, LTE
certification or Grant V2 is absent.

The Multi-UE category remains selectable but empty: ANR1 explicitly publishes
`multi_ue_templates=false`. The UI does not invent a system template.

## Contract coordination

- ANR1 contract branch: `anr1/polaris-default-scenarios-backend-v1`
- Contract SHA reviewed: `ff748ef26af67325e896de0dfed53434f762410c`
- Routes integrated: `GET /api/v1/scenario-templates` and
  `POST /api/v1/scenario-definitions/:template_id/clone`.
- Clone provenance is preserved because the subsequent PUT omits provenance
  fields, per the contract.

## Tests and real commands

| Command | Result |
|---|---|
| `npm ci --ignore-scripts` | PASS; npm reported 6 dependency advisories (2 moderate, 2 high, 2 critical), not introduced by this change |
| `npm test` | PASS: 36 files, 221 tests |
| `npm run typecheck` | PASS |
| `npm run build` | PASS: 1709 modules, JS 540.58 kB (151.62 kB gzip); pre-existing mixed dynamic/static `profileApi` warning |
| `POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:49300/simulator/ npx playwright test e2e/default-scenarios.spec.ts` | PASS: 6/6 projects, 1280/1440/1920, light/dark |
| `cargo test -p polaris-control-api definition_live_execution_is_locked_by_default` | PASS: 1/1; default live definition execution returns `StatusCode::LOCKED` / HTTP 423 semantics |
| `git diff --check` | PASS |

The E2E path validates catalogue synchronization, LTE/5G filtering, immutable
source selection, five-step LTE full-session loading, editing, authoritative
clone request, PUT of the copy, Run gating and absence of horizontal overflow.
All API data is mocked and anonymized.

## Captures

Twelve PNG files are stored under
`apps/simulator-control/docs/screenshots/default-scenarios/`: LTE and 5G for
each of the six Playwright projects. They are test-preview captures, not
production evidence.

## Safety and resources

- Disk observed at 47%, below the strict 85% ceiling.
- RAM available was 4.2 GiB immediately before the final test pass.
- External `dumpcap` count remained 12.
- No UE, scenario, live traffic, capture, Open5GS, OIRAN or gNB action ran.
- No production service or shared ANR2 preview was modified or restarted.
- The isolated Vite preview on `127.0.0.1:49300` was started only for mocked
  Playwright and stopped after the suite. The shared preview was intentionally
  left untouched to avoid overwriting another agent's work.

## Open items

- The ANR1 branch currently publishes the contract document; an integrated
  backend implementation of the catalogue/clone routes must be present in the
  eventual integration branch before a real backend recette.
- Live LTE certification and Grant V2 remain required; no REAL_PASS is claimed.
- Existing npm dependency advisories and React test `act(...)` warnings remain
  outside this scoped UI change.

## Verdict

`READY` for review and integration against the ANR1 backend implementation.
The offline PASS criterion is met in the authorized isolated test environment:
an operator can select a template, load its steps, customize it and save a
server-cloned copy. Production deployment and live certification remain
blocked by their separate gates.

— **ANR3**
