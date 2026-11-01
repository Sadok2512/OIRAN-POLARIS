# CODEX North Star Lab Final Certification P0

Date UTC: 2026-11-01  
Agent: ANR3/Codex  
Host: `OIRAN` (`root`)  
Mode: production verification read-only

## Verdict summary

```text
PRODUCTION_VERSION = POLARIS API 0.28.3 / Platform 3.2.1; OIRAN API 2.7.4
RUNNING_SHA256 = POLARIS 9e7eefd24f8f53a6259920fc03302741854e45611e106cf4ab715c233842aeae; OIRAN 2b88a78f2667a1a94caddfee7bb11367bc94ef5b78a1aac3dd0d5873c157b0a3
CONFIG = BLOCKED_FOR_0.29.0: POLARIS_LTE_TRAFFIC_PEER_IP absent in production; candidate drop-in sets 10.77.24.30 and matches the healthy DL sender
OPEN5GS = PASS_READ_ONLY: 15/15 identified EPC/5GC core containers running healthy; no restart observed or performed
PFCP = PASS_LISTENERS / PARTIAL_ASSOCIATION_PROOF: SMF, UPF, SGWC and PGWC bind UDP/8805; controller-side association records present, UPF-side log match count was zero
DUMPCAP = PASS_POINT_IN_TIME: 12 processes; PID-set SHA256 d98a34975a285f21fb627e060689f40860cf7b5c681503c1e5c66913484dba41; untouched by ANR3
RESOURCE_GATES = PASS: RAM available 9590026240 bytes, RAM used 11380555776 bytes; disk available 82439139328 bytes, 81% used
RELEASE_READY = PARTIAL: canonical 0.29.0 binary and source verified; production configuration, evidence roots and fresh rollback backup still required
DEPLOYMENT = NOT_PERFORMED: no deployment authority granted to Codex for this mission
LTE_ATTACH = HISTORICAL_PASS_ONLY: latest real run proved S1 Setup, Attach and UE IP before cleanup; no new live test performed
LTE_DATA = FAIL_HISTORICAL / NOT_TESTED_CURRENT: historical ping UL failed; ping DL and UDP UL/DL did not run
CAPTURE_REFS = FAIL: 0 capture_refs and 0 evidence bundles across the five stored LTE runs
OIRAN_CALLFLOW = BLOCKED_FOR_LTE: OIRAN historical Session Explorer/Call Flow APIs work, but no LTE evidence bundle exists to import
BLOCKERS = explicit Codex deployment authorization absent; separate LTE-live authorization absent; production remains 0.28.3; traffic-peer environment absent; finalizer route and POLARIS evidence roots absent; no SANITIZED_APPROVED release; exact fresh rollback backup absent
NEXT_ACTION = authorize a tightly scoped POLARIS 0.29.0 deployment first; validate it read-only; then issue a separate grant/live authorization for LTE-SRSUE-TEST-01
FINAL_VERDICT = BLOCKED
```

`REAL_PASS` is not claimed. The North Star chain stops after historical Attach/IP and before data traffic, evidence publication, OIRAN import and LTE Call Flow.

## Git and release identity

- Shared worktree `/root/OIRAN_POLARIS_FOUNDATION` was already heavily modified and contained unmerged files. It was not changed.
- Report worktree: `/root/ANR3_NORTH_STAR_LAB`.
- Report branch: `report/anr3-north-star-lab-final-p0`.
- Report base: `6734c75891832cce83edbfd3e5e622a8289835e6`.
- Candidate worktree `/root/ANR1_POLARIS_0290_GATE` is clean and detached at the requested source SHA.
- Candidate artifact:
  `/root/ANR1_POLARIS_0290_GATE/POLARIS_CONTROL/target/release/polaris-control-api`.
- Candidate SHA256: `cde36bd2451800104d6bce0758d2bc0f9f0eb38e872632006e887a5d3dc8b97e` — exact match.
- The finalizer functional commit `5d4c7ecca...` and its report commit `207122b...` are ancestors of the candidate.
- No active build, Git merge/rebase, or POLARIS/OIRAN restart command was found. Two old read-only debug APIs remain on loopback ports 49325 and 49326; they are not deployment processes. `run-u10061.service` is inactive after an earlier OOM failure.

Commands:

```bash
git -C /root/ANR1_POLARIS_0290_GATE rev-parse HEAD
git -C /root/ANR1_POLARIS_0290_GATE status --short
git merge-base --is-ancestor 5d4c7ecca... 6734c758...
sha256sum /root/ANR1_POLARIS_0290_GATE/POLARIS_CONTROL/target/release/polaris-control-api
pgrep -af 'cargo (build|test)|rustc|git (merge|rebase)|systemctl (restart|start) (polaris-control|oiran-api)'
```

## Running production

Both services were active throughout the inspection:

| Component | HTTP proof | Executed binary SHA256 |
|---|---|---|
| POLARIS | `/api/v1/version` = 0.28.3; `/health` = HTTP 200 | `9e7eefd24f8f53a6259920fc03302741854e45611e106cf4ab715c233842aeae` |
| OIRAN | `/api/v1/version` = 2.7.4; `/health` = HTTP 200 | `2b88a78f2667a1a94caddfee7bb11367bc94ef5b78a1aac3dd0d5873c157b0a3` |

Commands:

```bash
systemctl show polaris-control.service oiran-api.service -p ActiveState -p SubState -p MainPID -p ExecStart -p DropInPaths
curl -fsS http://127.0.0.1:49153/api/v1/version
curl -fsS http://127.0.0.1:49152/api/v1/version
sha256sum /proc/$(systemctl show -p MainPID --value polaris-control.service)/exe
sha256sum /proc/$(systemctl show -p MainPID --value oiran-api.service)/exe
```

`polaris-portal.service` was in `activating (auto-restart)` during inspection. This is outside the authorized mutation scope and was not restarted.

## Core, PFCP and capture continuity

- 15 identified Open5GS EPC/5GC containers were `Up (healthy)` with restart count zero in the inspected set.
- PFCP listeners were present on SMF `10.77.23.12:8805`, UPF `10.77.23.13:8805`, SGWC `10.77.18.12:8805`, and PGWC `10.77.18.14:8805`.
- Association-pattern log counts were SMF 4, UPF 0, SGWC 26, PGWC 7. This proves controller-side association activity but does not justify a claim of lossless PFCP continuity.
- Exactly 12 `dumpcap` processes were present at the final checkpoint. No signal, restart, file access, or configuration change was made. The point-in-time PID-set hash was `d98a34975a285f21fb627e060689f40860cf7b5c681503c1e5c66913484dba41`.
- A stopped historical container `polaris-control-ue-201` exists. It was not removed because cleanup mutation was not authorized.

Commands:

```bash
docker ps --format '{{.Names}}|{{.Status}}'
ss -lunp | grep ':8805'
pgrep -x dumpcap | sort -n
pgrep -x dumpcap | sort -n | sha256sum
```

## Resources

Final checkpoint at `2026-11-01T22:53:53Z`:

```text
RAM_TOTAL=20970582016
RAM_USED=11380555776
RAM_AVAILABLE=9590026240
DISK_TOTAL=414921494528
DISK_USED=332465577984
DISK_AVAILABLE=82439139328
DISK_PERCENT=81%
```

The RAM gates pass. Disk is below the 85% stop threshold but above the 80% warning threshold; release writes must be bounded and rechecked immediately before any authorized deployment.

Commands:

```bash
free -b
df -B1 --output=source,size,used,avail,pcent,target /
```

## Traffic peer and 0.29.0 prerequisites

- Production has `POLARIS_DL_SENDER_IP=10.77.24.30`.
- The healthy `polaris-dn-sender` container actually owns `10.77.24.30`.
- Production does **not** have `POLARIS_LTE_TRAFFIC_PEER_IP` in its effective service environment.
- Candidate 0.29.0 fails closed when the peer is missing or differs from the DL sender.
- Candidate drop-in `deployment/dn-sender/polaris-control-dl-sender.conf` sets both values to `10.77.24.30`; SHA256 is `1c3005f27dcebc84ba2ace30e3a1a541f261ce2d4826c0147428244d700826dc`.

The candidate drop-in was inspected only. Installing it is a production mutation and requires explicit authorization.

## Finalizer, evidence and SANITIZED_APPROVED

Production OIRAN is configured with:

```text
OIRAN_LTE_EVIDENCE_ROOT=/var/lib/oiran/lte-evidence
OIRAN_LTE_EVIDENCE_BUNDLE_ROOT=/var/lib/oiran/lte-evidence-inbox
```

Both roots exist with mode `0700`, but contain zero regular files and zero bytes. The corresponding POLARIS roots `/var/lib/polaris-control/lte-evidence-releases` and `/var/lib/polaris-control/lte-evidence-bundles` do not exist in production, and 0.28.3 does not expose the candidate finalizer route (`GET` returned 404 and `POST` returned 405).

Candidate 0.29.0 contains `finalize_authorized_evidence_release` and `/lte/runs/:run_id/evidence-finalize`. Its contract requires a versioned manifest, actual authorized files, SHA256, RAT/interface/timestamps/run outcome, privacy checks, and `SANITIZED_APPROVED`. No such approved release currently exists. Therefore neither a `capture_ref` nor an import may be fabricated.

## Stored LTE state and North Star gap

Read-only inspection of `/var/lib/polaris-control` found:

- 5 grants: all revoked; no active grant.
- 5 LTE runs: all `CLEAN`; outcomes 4 `FAILED`, 1 `CANCELLED`.
- 0 runs with `capture_refs`; 0 evidence bundles.
- Profile `LTE-SRSUE-TEST-01`: disabled, no temporary activation, no certification.
- Ownership store: zero active containers.

The latest stored run completed preflight, eNB start, S1 Setup, UE start, LTE Attach and UE IP. `ping_ul` then failed with `LTE_TRAFFIC_FAILED`; ping DL and both UDP directions remained pending. Cleanup completed and reported dumpcaps preserved. This is useful historical evidence for Attach/IP only, not a current certification and not an E2E pass.

## OIRAN Session Explorer, Call Flow and privacy

Read-only API checks against the first pseudonymous historical session returned:

```text
/sessions                       HTTP 200, total 10
/sessions/:id                   HTTP 200
/sessions/:id/events            HTTP 200, total 13, page size 5 returned 5
/sessions/:id/procedures        HTTP 200
/sessions/:id/callflow          HTTP 200, 17 elements in data
/sessions/:id/correlations      HTTP 200
```

Raw JSON leak scans over sessions, one session, events, Call Flow and datasets found zero forbidden keys or markers for `IMSI`, `SUCI`, `GUTI`, `TMSI`, `IMEI`, `IMEISV`, `MaskedIMEISV`, `K`, or `OPc`. No raw PCAP was opened. These checks validate existing historical API behavior only. There is no LTE bundle for the North Star run, so LTE Session Explorer and LTE Call Flow remain unavailable.

## Backup, deployment and rollback plan

No exact backup matching the current running POLARIS or OIRAN binary size/hash was found in the known backup roots. A fresh backup is therefore mandatory immediately before any authorized mutation.

Authorized deployment preconditions, in order:

1. Reconfirm source `6734c758...`, candidate artifact SHA256, effective unit/drop-ins, resources, 12 dumpcap PID set, and absence of concurrent deployment.
2. Copy the active POLARIS binary, unit, all drop-ins, and relevant configuration/state metadata to a timestamped root-owned `0700` backup; hash every file.
3. Ensure the two POLARIS evidence roots under `/var/lib/polaris-control` have minimal permissions. Do not broaden systemd `ReadWritePaths` beyond the already authorized state root.
4. Install only the canonical POLARIS 0.29.0 binary and reviewed Traffic Peer drop-in. OIRAN remains unchanged.
5. Run `systemd-analyze verify`, daemon-reload, and restart only `polaris-control.service`.
6. Validate version, running process hash, health, fail-closed RBAC/CSRF/Grant behavior, zero active grant/run, traffic peer, finalizer route, and evidence directories.
7. On any critical failure, restore the exact backup binary/config/drop-ins, daemon-reload, restart POLARIS only, and revalidate hashes, services, resources and all 12 dumpcap PIDs.

No backup or deployment action was performed in this mission.

## Prepared LTE-SRSUE-TEST-01 recipe — not authorized to execute

The candidate enforces the requested bounds: one UE; maximum 300 seconds; 1–5 pings per direction; UDP 1–1,000,000 bit/s for 1–30 seconds per direction; one stream; payload at most 1200 bytes; hard-deadline cleanup; peer equal to the DL sender.

Execution gates:

1. Obtain a **separate explicit live authorization** naming `LTE-SRSUE-TEST-01`, the time window, one UE, traffic limits, and responsible operator.
2. Authenticate Operator and create one exact Grant V2; record ownership, digest, expiry and anti-replay proof.
3. Recheck RAM, disk, dumpcap PIDs, zero competing run and zero residual LTE containers.
4. Observe and timestamp S1 Setup, Attach Complete, EPS bearer and UE IP.
5. Permit ping/UDP only after all previous gates pass, within the stated bounds.
6. Stop traffic at the deadline, perform cleanup/revocation, and prove no residual containers or active grants.
7. Finalize only actual authorized capture segments as `SANITIZED_APPROVED`, retaining distinct provenance and SHA256 for S1-MME, S11 and S1-U.
8. Publish real `capture_refs`, import idempotently into OIRAN, and validate correlated TEID/E-RAB/session, pagination, privacy, Session Explorer and chronological Call Flow.
9. Declare `REAL_PASS` only if every link is supported by retained evidence. Otherwise report the exact partial boundary.

## Commands actually executed

All commands were manual and read-only except creation of this isolated report worktree and Git/GitHub report publication:

```bash
hostname; whoami
git worktree list --porcelain
git status --short --branch
systemctl show ...
curl -fsS http://127.0.0.1:49153/api/v1/version
curl -fsS http://127.0.0.1:49152/api/v1/version
curl -fsS http://127.0.0.1:49152/api/v1/sessions?page=1\&page_size=1
curl -fsS http://127.0.0.1:49152/api/v1/sessions/:id/{events,procedures,callflow,correlations}
sha256sum /proc/<service-pid>/exe <candidate-binary>
docker ps --format '{{.Names}}|{{.Status}}'
ss -lunp
pgrep -x dumpcap
free -b
df -B1 ...
```

No Rust/frontend/Playwright suite was rerun on production: this mission began with lab verification, no source change was made, and restarting or loading production for redundant build tests was neither necessary nor authorized.

— ANR3
