# Changelog

## 0.17.1 (polaris-control-api)

- Persist bounded iperf3 JSON `stdout` alongside `stderr`, exit code and the
  executed command in step `failure_evidence`. iperf3 emits `-J` connection
  errors on stdout, so prior evidence could retain an empty stderr while losing
  the actionable diagnostic. Both streams are independently limited to 2048
  characters and no command execution behaviour or safety gate is changed.

## 0.17.0 (polaris-control-api)

- Added `GET /api/v1/subscribers/:slot` — returns the sanitized subscriber
  record (slot, state, PLMN, SNSSAI, DNNs, AMBR) plus
  `linked_profile_ue_ids[]` resolved via the plan file and the UE profile
  registry. Identity and authentication material remain `PROTECTED` and
  are never surfaced in the response. Read-only, no operator role needed.
- Added `PUT /api/v1/subscribers/:slot` — operator-gated partial update
  of slice (SST/SD), DNNs, AMBR and/or authentication material (K/OPc).
  `k` / `opc` are strictly write-only: they are never present in the
  response body. The served-network policy still gates the slice/DNN
  values. Backend writes the Open5GS record and takes a mongodump backup
  first via the existing `backup()` path.
- Added `POST /api/v1/subscribers/generate` — operator-gated bulk
  generator. Allocates `count` fresh IMSIs in the fixed `001/01` range
  (lowest free MSIN) and provisions each with `K`/`OPc` material drawn
  from the OS CSPRNG (`rand_core::OsRng` via `getrandom`). Response is
  the array of `{slot, state:"PROVISIONED", subscriber_identity:"PROTECTED",
  authentication_material:"PROTECTED"}` — `K` and `OPc` never leave the
  server. `count` is bounded by `GENERATE_MAX_COUNT=1000`.
- Enriched `GET /api/v1/scenarios/:job_id/steps` with job-level `state`,
  `started_at`, `ended_at`, `duration_ms` and a `failure` object
  summarizing the first FAILED step: `{step_id, step_name, code, message,
  failure_evidence, started_at, ended_at, duration_ms}`. `failure_evidence`
  is the bounded iperf3 payload delivered in 0.16.3 and is passed through
  unchanged. No change to the per-step records.
- `subscriber_provisioning.rs` grew the new `SubscriberUpdate` type, three
  new `SubscriberBackend` trait methods (`fetch_slot`, `apply_update`,
  `taken_imsis`), a `generate_authentication_key()` CSPRNG helper and an
  `allocate_next_imsis()` next-free MSIN allocator. All new logic lives
  in that module — `lib.rs` only grew by the three HTTP handlers and the
  update-side validator.
- Tests: added seven new unit tests in `subscriber_provisioning::tests`
  covering CSPRNG uniqueness, next-free IMSI allocation (including the
  `SUBSCRIBER_GENERATE_COUNT_INVALID` bound), partial update behaviour,
  authentication-material rewrite, missing-slot fail-closed, sanitized
  fetch and the `taken_imsis` projection. Every sanitize-oriented test
  explicitly asserts the serialized JSON does **not** contain the raw
  IMSI, K or OPc.
- Does not touch `POLARIS_IPERF3_PATH`, `failure_evidence` (0.16.3) nor
  the pinned `release/iperf3-3.21/*` runtime (2e89c71).

## 0.16.4 (polaris-control-api)

- Port the 0.15.5 portable test harness and `lab_nf_tests` module on top of
  Codex's 0.16.3 iperf failure-evidence base. Does not touch
  `POLARIS_IPERF3_PATH` nor `failure_evidence` (both delivered in 0.16.3).
- Portable P0 test paths: the two hard-coded `/root/.hermes/cache/scratch/*`
  literals in `apps/api/src/lib.rs` (previously `state()` and
  `restored_open5gs_copy_accepts_provisioning_without_secret_disclosure`)
  now use `std::env::temp_dir()`, so the suite runs on any workstation /
  CI runner, not only the Codex Hermes sandbox.
- Tests: the `uid=0` check in the UE profile registry and the scenario
  catalog loaders is split via `#[cfg(all(unix, not(test)))]` (strict,
  release) vs `#[cfg(all(unix, test))]` (owner uid tolerated, group /
  world-write bits still refused). Covers
  `UE_PROFILE_REGISTRY_PERMISSIONS_UNSAFE` and
  `SCENARIO_CATALOG_PERMISSIONS_UNSAFE`.
- Tests: three new `lab_nf_tests` units exercise Codex's
  `network_function_observation` + the 12-entry `LAB_NETWORK_FUNCTIONS`
  catalogue (AMF, SMF, UPF, NRF, AUSF, UDM, UDR, PCF, NSSF, BSF, Kamailio,
  RTPengine). Absent containers render `observed:false` with null
  `process_state` / `health`, matching the honest-UI contract.
- No change to runtime behaviour, no deployment, no shared service touched.

## 0.16.2 (polaris-control-api)

- Store Open5GS UE-AMBR and session AMBR values as native numeric BSON values so Open5GS 2.8 can produce AccessAndMobilitySubscriptionData.

## 0.16.1 (polaris-control-api)

- Fix controller-owned scenario resource validation so it no longer depends on the legacy shared UE-01 container or profile; disk, memory, CPU and shared lab infrastructure health gates remain enforced.
- Normalize persistent controller UE identifiers and render the configured/default NSSAI fields required by runtime provisioning validation.
- Scope launch-time provisioning verification to the explicitly requested controller-owned UE so unrelated legacy profiles cannot block or contaminate its lifecycle decision.
- Verify POLARIS-owned launch profiles byte-for-byte against the current protected MongoDB subscriber record, while retaining the legacy attestation path for non-POLARIS records.

## 0.16.0 (polaris-control-api)

- Adds a health-gated N6 downlink sender for `traffic_dl`, using a digest-pinned, non-public
  iperf3 container with a scoped route to the UE pool through the UPF.
- Measures downlink bytes independently in the DN sender report and the UE-network-namespace
  receiver report; no UE identity or authentication material is exposed.
- Routes `traffic_ul` to a one-shot iperf3 receiver in the same DN container and records both the
  UE sender count and DN receiver count instead of assuming a server on the UPF tunnel address.
- Advertises `traffic_dl` as executable only while the sender container, N6 identity and UE route
  are all measured healthy; otherwise the existing `DL_SENDER_NOT_AVAILABLE` fail-closed contract
  remains active.

## 0.15.4 (polaris-control-api)

- Adds `PATCH /api/v1/ue-profiles/:ue_id/scenario`, which updates only scenario metadata and preserves the protected subscriber link and provisioning evidence.
- Preserves `subscription_verified` on full profile updates when all subscriber-facing fields are unchanged; subscriber/network changes still require revalidation.
- Rejects assignment of definitions containing unavailable steps with the exact backend code (`DL_SENDER_NOT_AVAILABLE` or `IMS_NOT_AVAILABLE`).

## 0.15.3 (polaris-control-api)

- Patch: expose a measured `observed.nfs[]` inventory from `/lab` for every Open5GS network
  function plus Kamailio and RTPengine, using Docker inspect state and health only.
- Honesty: missing or uninspectable containers are returned with `observed: false` and null state
  fields; the API never fabricates network-function availability.

## 0.15.2 (polaris-control-api)

- Patch: create a UE from a POLARIS-owned subscriber using IMSI alone; K and OPc are resolved
  inside the protected subscriber backend and never cross the API response or audit boundary.
- Patch: accept canonical 15-digit IMSIs and the equivalent `imsi-` form for subscriber
  provisioning, UE creation and CSV imports.
- Safety: validate subscriber S-NSSAI and DNN against the explicitly configured AMF/SMF served
  network policy; unsupported slices fail with `422 SNSSAI_NOT_SERVED`.

## 0.15.1 (polaris-control-api)

- Patch: raise the persistent UE profile registry ceiling to 100,000 while retaining the
  independently bounded live-UE limit, server-side pagination, search and atomic persistence.
- Validation: benchmark 100,000-profile bulk persistence/reload and paginated search, and exercise
  the production MongoDB adapter against an isolated restored Open5GS copy.

## 0.15.0 (polaris-control-api)

- Minor: add Operator/CSRF-protected Open5GS subscriber provisioning with mandatory protected
  `mongodump`, POLARIS ownership markers, sanitized inventory, and bounded CSV batching.
- Minor: create UE profiles by protected subscriber identity, add bounded CSV profile import,
  sanitized profile detail, and real gNB/owner/PLMN/DNN menu registries.
- Security: IMSI, K, and OPc remain write-only and are excluded from response types, audit targets,
  errors, and logs; existing non-POLARIS subscriber records are never modified.

## 0.14.0 (polaris-control-api)

- Minor: advertise the scenario-definition step contract through `GET /api/v1/capabilities`,
  separating executable step types from the explicitly unavailable downlink and IMS types.
- Contract: publish the enforced traffic-byte, repeat-depth, and resolved-step ceilings without
  changing the live-definition authorization lock or any runtime safety gate.

## 0.13.0 (polaris-control-api)

- Minor: add four immutable, clonable traffic/voice scenario templates and bounded nested
  `repeat`, `idle`, `detach`, `traffic_ul`, and `traffic_dl` contracts.
- Minor: add duration estimates plus versioned JSON v2 export/import with Operator, CSRF,
  collision, schema, and payload-size enforcement.
- Safety: keep IMS steps locked with `IMS_NOT_AVAILABLE`, reject downlink execution without a
  verified DN sender, retain the global live-definition feature lock, and record measured iperf3
  uplink bytes only after an authorized execution.

## Follow-up security ticket — migrate React Router 7

- The laboratory deployment decision accepted the two moderate advisories reported by
  `npm audit --omit=dev` for the explicitly pinned `react-router-dom` 6.30.6 candidate.
- Track a separately reviewed migration to React Router 7; do not apply npm's breaking
  `--force` upgrade without frontend contract and browser regression validation.

## 0.12.1 (polaris-control-api)

- Patch: execute `pdu_establish` with UERANSIM `nr-cli ps-establish` and `pdu_release` with
  `nr-cli ps-release-all` inside the exact controller-owned UE container.
- Patch: require an observed `ACTIVE`/`INACTIVE` state after each PDU command; PDU release no
  longer stops the UE process.

## 0.12.0 (polaris-control-api)

- Minor: execute the six V1 scenario-definition steps through the existing controller-owned UE
  runtime, bounded UDP profile and `MAX_LIVE_UES` selection limit.
- Minor: keep definition execution fail-closed behind
  `POLARIS_DEFINITION_LIVE_ENABLED=true` (disabled by default), persist real per-step transitions,
  and make Operator stop clean up only UEs started by the job.
- Minor: allow `polaris-provisioning-attest` to attest the current protected UE profile registry
  after slot binding; the documented helper remains dry-run by default and never writes Open5GS.

## 3.2.5 - Candidate UE inventory latency correction

- Replaced process-global UE observation coordination with per-application state.
- Reuse a verified runtime observation for a bounded ten-second interval so route polling does not repeatedly block on Docker inspection.
- Preserve a full refresh after process restart or cache expiry; configuration and runtime counts remain authoritative.
- Added a regression for the route-navigation race that previously caused the nineteenth browser test to time out.

## 3.2.4 - E2E-002 release stabilization

- Restored the certified V3.2 Apply Configuration, Add UE, multi-selection and selected Start/Stop controls on top of the CPU-evidence candidate.
- Kept configuration changes independent from UE execution and retained Viewer, ownership and execution-mode locks.
- Added fail-closed credential injection for authenticated browser tests and serialized candidate logins.
- Reconciled production-browser assertions with the evidence-bearing CPU safety contract without weakening a hard block.

## 3.2.3 - Evidence-preserving CPU admission decisions

- Persisted bounded, protected, atomic CPU safety decision evidence with exact trigger metrics and thresholds.
- Split warnings into non-blocking and latched blocking states with consecutive-sample and recovery hysteresis.
- Kept stale telemetry, unknown capacity, cgroup exhaustion, sustained pressure/throttling, and resource overcommit fail-closed.
- Added operator-only decision inspection and evidence-bearing HTTP 503 responses.

## 3.2.2 - UE-targeted bounded traffic (offline validated)

- Replaced the load-average/API-quota CPU gate with host `/proc/stat` deltas, PSI, cgroup capacity and throttling deltas, scenario budgets, telemetry freshness, consecutive samples, and hysteresis.
- Added precise READY/WARNING/BLOCKED safety states and production UI evidence without changing CPU quotas or enabling live execution.
- Added selection of verified controller-owned, registered UEs with active PDU Sessions to the Traffic Generator.
- Bound each traffic job to an allowlisted UE registry record, exact owned container, network namespace, `uesimtunN` interface, UE source IP, and approved route.
- Preserved the five-datagram UDP profile and fixed laboratory destination without accepting browser-provided interfaces, namespaces, commands, or destinations.
- Kept traffic and UE lifecycles independent; exact-job Stop changes traffic state without terminating the UE or releasing its PDU Session.
- Added sustained CPU-contention rejection plus targeted ownership, TUN/route, PDU, duplicate-job, RBAC, and shared-UE regression coverage.
- Added a non-applied four-profile configuration plan for UE-01 through UE-04. No production state or simulator process was changed.

## 3.2.1 - Configured UE profile visibility

- Merged configured UE profiles with observed and controller-owned runtime state using stable internal UE IDs.
- Made the Console and UE Manager show one honest state row for every configured profile.
- Kept provisioning, process, Registration, PDU Session, and traffic state as independent dimensions.
- Added explicit `NOT_STARTED`, `NOT_OBSERVED`, and `INACTIVE` states without fabricating runtime activity.
- Added regression coverage for 1, 3, 5, and 10 configured profiles and retained lifecycle authorization locks.

## 3.2.0 - Ten synthetic subscriber readiness

- Provisioned nine missing synthetic Open5GS records for a total of ten compatible subscribers.
- Added ten restricted UERANSIM profiles with unique authentication material.
- Increased configurable UE capacity from five to ten while retaining a live-certified maximum of one.
- Added an idempotent, compensating-rollback provisioning workflow and sanitized verification reports.
- Preserved all live UE/gNB lifecycle locks; no simulator process was started.

## 3.1.1 - Configurable inventory counts

- Added persistent Operator-controlled UE (1..5) and gNB (1..2) inventory selectors.
- Added configuration-only `Add UE` workflow and explicit subscriber provisioning status.
- Separated configured, running, registered, and PDU-active UE counts.
- Added atomic configuration persistence, RBAC/CSRF enforcement, and audit logging.
- Kept all uncertified UE/gNB lifecycle operations locked; configuration never starts processes.

## 3.0.0-dev

- Replaced the guided V2 dashboard with one compact operational console.
- Added complete light, dark, and system themes using semantic tokens with persisted preference.
- Added real node inventory, separate UE process/registration/PDU state, and precise lifecycle restrictions.
- Added independent scenario and traffic controls without coupling traffic completion to UE lifecycle.
- Added measured CPU/memory telemetry and explicit zero/no-data traffic visualization.
- Added the `/api/v1/nodes` inventory and CPU sampling to system health.
- Preserved Viewer/Operator/Administrator enforcement, CSRF, exact process ownership, disk gates, and the single certified bounded profile.
- Added browser validation at 1440×900 and 1920×1080 in both themes.

## 2.1.2-dev

- Added one authoritative runtime snapshot containing the active job and most recent terminal job.
- Preserved short-lived `COMPLETED`, `FAILED`, and `STOPPED` results across polling, page refreshes and browser sessions.
- Added start/end timestamps, terminal result, owned PID and explicit UDP write accounting to persisted jobs.
- Corrected duplicate Start and Stop-after-completion behavior without weakening exact process ownership.
- Updated the Dashboard Scenario Status panel without redesigning the application.
- Audited UERANSIM 3.3.0 multi-UE capabilities; new UE creation remains locked and current 85.04% disk utilization blocks capture-producing tests.

## 2.1.1-dev

- Replaced browser-stored bearer credentials with named Operator/Administrator accounts, Argon2id password hashes, server-side sessions, Secure HttpOnly SameSite cookies, and CSRF protection.
- Added explicit login/logout UI and a root-only `polaris-userctl` provisioning command.
- Required an authenticated, session-bound validation of the exact certified profile before Start.
- Kept new UE creation, multi-UE, gNB lifecycle and all unrestricted control locked.
- Added Viewer denial, login, CSRF, role, resource-gate, certified-profile, idempotent Start/Stop and password-storage tests.

## 2.1.0-dev

- Added configurable Viewer, Operator, and Administrator authorization.
- Added a persistent certified-scenario policy registry and Administrator enable/disable control.
- Enabled Start/Stop only for `bounded-existing-ue-udp-v1` using the existing healthy UE and PDU Session.
- Added exact controller-owned process handles, idempotent duplicate Start, exact-job Stop, persisted history, and restart recovery.
- Added append-only audit logging for authorization, Start, Stop, resource failures, and policy changes.
- Replaced the generic lock message with explicit capability and execution states in the Web UI.
- Kept new UE creation, multi-UE execution, gNB lifecycle control, LTE, ICMP, and TCP locked.
- Kept public HTTP in Viewer mode by stripping authorization at the public-IP proxy; Operator control is available through the existing HTTPS endpoint or localhost tunnel.

## POLARIS-LIVE-001

- Added a single-purpose, one-time backend execution path for the explicitly approved bounded test.
- Reused the already healthy shared gNB, UE registration, and PDU session without restarting them.
- Sent exactly five UDP datagrams through `uesimtun0` to the controlled UPF endpoint.
- Consumed and removed the ephemeral approval, kept generic Start/Stop locked, and verified zero orphan processes.
- Recorded ten N3 GTP-U packets: five uplink UDP packets and five downlink ICMP port-unreachable responses.

## 2.0.0-dev

- Replaced the audit-style landing page with a four-step guided simulator workflow.
- Added capability-driven 5G SA and LTE cards; LTE remains disabled because Attach is not certified.
- Added bounded scenario validation, real UE inventory state, traffic state, and running-scenario views.
- Added the dedicated Running Scenarios workspace and clearer profile/runtime distinctions.
- Expanded real host and laboratory health reporting without adding control privileges.
- Preserved the live-execution approval gate: no simulator process is started by this release.
- Preserved public read-only access after the operator's prior token-removal request.

## 1.0.0-dev

- Removed all access-token requirements by explicit operator request; the public role remains read-only and live execution stays locked.
- Added isolated React/TypeScript control application and Rust API.
- Added bounded UE/scenario/traffic validation.
- Added exact controller-owned job registry and idempotent lifecycle model.
- Added permanent 75/80/85/90 disk safety guard with fail-closed monitoring.
- Kept live UERANSIM execution disabled pending explicit approval.

# 3.1.0 — 2026-10-25

- Added a bounded five-profile UERANSIM model with unique UE/profile validation and secret-safe configuration rendering.
- Added independent controller-owned UE process, Registration, PDU Session and traffic state tracking.
- Added idempotent single/group Start and Stop contracts with partial-failure isolation and exact ownership.
- Updated UE Manager with configured/running/registered/PDU counts, profile selection and lifecycle controls.
- Added a non-deployed gNB-02 plan; multi-gNB execution remains locked for LIVE-005.
- Preserved the one-UE live certification boundary and kept all new lifecycle actions locked pending LIVE-002/003/004.
- Added offline multi-UE, authorization, resource-safety and UI regression coverage.
## API 0.10.0 — minor

- Add an atomic, versioned scenario-definition catalog with CRUD and clone routes.
- Add nested scenario/step fixed-loop V1 validation, backend random-parameter resolution, persisted
  resolved values, definition-based offline execution history, and per-job step status retrieval.
- Add versioned UE inventory snapshots and fixture-backed browser inventory coverage.
- Preserve the legacy certified scenario endpoints and reject definition-based Live execution until
  it receives separate authorization and validation.

## Web 3.2.2 — patch

- Replace four lab-state-dependent inventory checks with a strict, known API fixture.
- Keep a separate read-only Live inventory test disabled by default and manually selectable.

## 0.11.0 (polaris-control-api) / 0.4.0 (ueransim-adapter)

- Minor: `serving_gnb` now feeds the UERANSIM `gnbSearchList` through a gNB registry
  (laboratory default `GNB-01 → 10.77.0.20`, or a validated JSON file named by
  `POLARIS_GNB_REGISTRY_PATH`). An unknown gNB is refused with `UNKNOWN_SERVING_GNB`; there is
  no silent fallback. Rendering for `GNB-01` is byte-identical to 0.10.0, so existing
  provisioning attestations remain valid.
- Minor: new read-only `GET /api/v1/gnbs`.
- Minor: `POST /api/v1/ue-profiles` accepts `provisioning_slot` to bind a profile to a subscriber
  already provisioned in Open5GS. SUPI/K/OPc are read server-side from the private V3.2 plan
  (`POLARIS_SUBSCRIBER_PLAN_PATH`, default `/var/lib/polaris-control/subscriber-secrets/v3.2.plan`,
  mode must deny group/other). A slot binds at most once. Open5GS is never written.
- Minor: new read-only `GET /api/v1/ue-profiles/provisioning-slots` (slot ids and bound UE only).
# 0.16.3

- Preserve bounded iperf3 failure evidence (command, exit code and bounded stderr).
- Use the packaged POLARIS iperf3 client instead of assuming `/usr/bin/iperf3` exists.
