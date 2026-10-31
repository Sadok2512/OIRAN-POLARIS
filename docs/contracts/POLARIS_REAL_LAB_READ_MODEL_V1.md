# POLARIS Real-Lab Read Model v1

Status: ANR1 infrastructure contract, offline integration only

Reference source: `87daa3445e3058352d21efeba21d05fefe3029d4`

Observed: 2026-10-31 UTC

## Truth rules

1. A configured object is never presented as running or connected.
2. `RUNNING` requires a current process/container observation. `CONNECTED`, `ATTACHED`, `REGISTERED`, and `ACTIVE` each require their protocol-specific proof.
3. Missing, stale, ambiguous, or inaccessible evidence is `UNKNOWN` or `NOT_AVAILABLE`, never a successful state.
4. Historical traffic results are labelled historical and never reused as current counters.
5. Subscriber identities remain role-gated; authentication material is always `PROTECTED` and is never logged.
6. Read endpoints cannot create grants or trigger lifecycle, traffic, capture, or provisioning actions.

## Certified read sources

| UI concern | API route | Real source | Contract |
|---|---|---|---|
| Host safety | `GET /api/v1/system/health` | `/proc/stat`, PSI, cgroup v2, `statvfs`, `/proc/meminfo` | Measured timestamp and freshness required. |
| Core/NF inventory | `GET /api/v1/lab` | bounded `docker inspect` of allowlisted containers | Missing container returns `observed=false`; state fields are null/unknown. |
| UE inventory | `GET /api/v1/ues` | persistent profile/controller registries plus current runtime observation | Configured, process, registration, session, traffic, and ownership states remain independent. |
| gNB/eNB inventory | `GET /api/v1/gnbs` | configured registry joined to current Docker/SCTP observation | `LAB_DEFAULT` is configuration only and MUST NOT imply running or connected. |
| LTE runtime | `GET /api/v1/lte/status` | exact Compose service discovery, ownership ledger, Docker state, S1/Attach/EPC/IP proofs | Absent srsENB/srsUE returns `observed=false`, attach/session `UNKNOWN`. |
| Scenario catalogue | `GET /api/v1/scenario-templates` | immutable backend catalogue | Exact support status; no frontend fixture may override it. |
| Scenario definitions | `GET /api/v1/scenario-definitions` | durable definition store | User definitions remain distinct from immutable system templates. |
| Traffic | `GET /api/v1/traffic/status`, `/traffic/sessions`, `/traffic/sessions/:id/samples` | persisted job/session accounting | A terminal result is historical; live rates require current samples. |
| UE activity | `GET /api/v1/ues/:ue_id/activity[/stream]` | controller observation and bounded counters | Identity filtering and role-based IMSI projection are mandatory. |

The public preview maps these routes below `/polaris-api/v1`; internal API tests use `/api/v1`.

## Measured laboratory state

The production API currently reports version `0.19.8`, platform `3.2.1`. Its measured state is:

- Open5GS EPC/5GC containers are running and healthy, including MME/HSS/SGW/PGW and AMF/SMF/UPF/NRF/AUSF/UDM/UDR/PCF/NSSF/BSF.
- UERANSIM gNB container is running and healthy. No UERANSIM UE container is running.
- `GET /ues` reports two configured profiles and zero active/registered/PDU-active UEs. This is a real registry/runtime result, not a demo count.
- No `srsenb` or `srsue` container exists. LTE attach and LTE session state are therefore `UNKNOWN`, not `ATTACHED`.
- Production `GET /lte/status` and `GET /scenario-templates` currently return HTTP 404. These are open version/deployment gaps; the reference source contains the routes but is not production.
- Production `GET /gnbs` reports `source=LAB_DEFAULT`; this proves configuration only. It cannot prove NG or S1 connectivity.

## Real network observations

| Plane | Host bridge | Subnet | Observed endpoints/listener |
|---|---|---|---|
| S1-MME | `br-oiran-s1m` | `10.77.10.0/24` | MME `10.77.10.10:36412/SCTP`; eNB endpoint absent |
| S1-U | `br-oiran-s1u` | `10.77.11.0/24` | SGW-U `10.77.11.13:2152/UDP`; eNB endpoint absent |
| S11 | `br-oiran-s11` | `10.77.12.0/24` | MME/SGW-C/PGW-C endpoints present; SGW-C `:2123/UDP` |
| N2 | `br-oiran-n2` | `10.77.21.0/24` | AMF `10.77.21.11:38412/SCTP`; gNB endpoint present |
| N3 | `br-oiran-n3` | `10.77.22.0/24` | gNB and UPF `:2152/UDP` present |
| N4 | `br-oiran-n4` | `10.77.23.0/24` | SMF and UPF `:8805/UDP` present |
| N6 | `br-oiran-n6` | `10.77.24.0/24` | UPF and bounded DN sender present |

The LTE Compose model contains `srsenb` and `srsue` services under profile `lte`, pinned to image digest `sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43`. The real service instances are absent, so the UI must render `STOPPED`/`NOT_OBSERVED` rather than infer a live eNB/UE from configuration.

## Grant V2 and lifecycle boundary

Grant V2 (`polaris.live-grant.v2`) is bound to:

- exact LTE profile and revision;
- configuration SHA-256 and canonical Compose model SHA-256;
- exact scenario and revision;
- operator role and authenticated session subject;
- nonce hash, idempotency key, issue/expiry time, and a single run.

The persistent store is private (`0600`), restarts revoke issued grants and move consumed grants to recovery-only, and ownership is checked from exact Compose project/service/config labels plus the pinned image reference. CSRF and operator RBAC remain mandatory on mutations. A read-only UI must not synthesize authority from a configured profile.

## LTE-SRSUE-TEST-01 validation plan (not executed)

Preconditions must all pass immediately before a separately authorized run:

1. Disk usage below 85%, stable available RAM at or above 4 GiB, and all 12 external `dumpcap` PIDs unchanged.
2. Exact profile/Compose digests match, ownership ledger is private and consistent, no ambiguous service instance exists.
3. A valid Grant V2 binds `LTE-SRSUE-TEST-01` to the bounded five-minute scenario: one UE, UDP UL/DL at no more than 1 Mbit/s.
4. State sequence: `IDLE → ENB_STARTING → S1_READY → UE_STARTING → ATTACHED → IP_READY → TRAFFIC_RUNNING → STOPPING → CLEAN`.
5. Proof gates: S1 Setup observed, LTE Attach accepted with EPC context, UE IP observed, UL and DL byte counters observed, then clean stop/removal. A timeout or absent proof fails closed and runs cleanup.
6. OIRAN publication must reference real S1AP, S11/GTPv2-C and S1-U/GTP-U evidence; no LTE E2E PASS is possible before that separately authorized live certification.

At audit time RAM crossed below the 4 GiB threshold in two of five one-second samples (`4,101,624` and `4,104,776` kB). The live gate is therefore **BLOCKED until RAM is stably at least 4 GiB**, even though offline development may continue.

— ANR1
