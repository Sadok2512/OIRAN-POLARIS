# Changelog

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
