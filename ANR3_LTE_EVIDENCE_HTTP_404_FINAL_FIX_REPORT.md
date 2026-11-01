# ANR3 — LTE evidence HTTP 404 final analysis

Date UTC: 2026-11-01  
Run: `lte-run-b12f8f56374b06af8dc4678908f4834b`  
Base/source: `880c493f6bba5c760722e22b20d15bad3cfe4b78`  
Scope: read-only production diagnosis plus offline tests. No import, deployment, grant, capture, collector change, traffic, or raw-PCAP decoding was performed.

## Mandatory result

```text
REQUEST_URL = Historical client request is not logged. Reproduced endpoints:
  GET  https://151.242.147.49:8020/polaris-api/v1/lte/evidence/{run_id} -> wrong/nonexistent POLARIS route
  POST https://151.242.147.49:8020/polaris-api/v1/lte/runs/{run_id}/evidence-envelope -> real POLARIS publication route
  GET  https://151.242.147.49:8020/api/v1/lte/evidence/{run_id} -> real OIRAN imported-resource route
HTTP_STATUS = POLARIS wrong route 404; publication route queried with GET 405; OIRAN resource GET 404 LTE_ARTIFACT_UNAVAILABLE
ROOT_CAUSE = No evidence finalizer/producer exists outside tests, the POLARIS bundle root is absent/unconfigured, and no run manifest was staged; therefore publication and import never occurred
EVIDENCE_FILES = No bundle, proof manifest, inbox entry, or OIRAN LTE dataset for the run. External capture metadata indicates S1-MME/S11/S1-U segments existed during the run, but they were not opened, hashed, approved, or promoted to evidence
CAPTURE_REFS = [] in the durable CLEAN/FAILED POLARIS run; evidence_bundle_id=null
FIX = BLOCKED pending an authorized real capture finalizer and staging configuration. No synthetic manifest or capture_ref was created
INGESTION = NOT_PERFORMED; OIRAN correctly returns 404 because no artifact exists
CALLFLOW = NOT_AVAILABLE for this run; existing non-LTE Call Flow remains healthy
TESTS = POLARIS 19/19; OIRAN evidence 10/10; OIRAN API 3/3; frontend 16/16; TypeScript/build/leak scan PASS
SOURCE_SHA = 880c493f6bba5c760722e22b20d15bad3cfe4b78
BINARY_SHA256 = active production OIRAN 2.7.4: 2b88a78f2667a1a94caddfee7bb11367bc94ef5b78a1aac3dd0d5873c157b0a3; no new binary produced
VERDICT = BLOCKED
BLOCKERS = Missing finalizer implementation, missing POLARIS_LTE_EVIDENCE_BUNDLE_ROOT deployment/configuration, missing approved manifest and normalized events, no authorized import; historical exact HTTP request unavailable because no access log records it
```

## Route and reverse-proxy proof

POLARIS source exposes:

```text
POST /api/v1/lte/runs
GET  /api/v1/lte/runs/:run_id
POST /api/v1/lte/runs/:run_id/evidence-envelope
POST /api/v1/lte/runs/:run_id/stop
```

There is no POLARIS route `/api/v1/lte/evidence/:run_id`.

OIRAN source exposes:

```text
POST /api/v1/lte/evidence/import
GET  /api/v1/lte/evidence/:run_id
GET  /api/v1/lte/evidence/:run_id/sessions
GET  /api/v1/lte/evidence/:run_id/sessions/:session_id/callflow
```

The preview proxy maps `/polaris-api/v1/*` to POLARIS port 49153 and `/api/v1/*` or `/analyzer-api/v1/*` to OIRAN port 49152. Caddy forwards HTTPS 8020 unchanged to that proxy. Direct and proxied responses were identical.

Commands/results:

```text
GET POLARIS /api/v1/lte/runs/{run_id}                  -> 200
GET POLARIS /api/v1/lte/runs/{run_id}/evidence-envelope -> 405 (POST-only route)
GET POLARIS /api/v1/lte/evidence/{run_id}             -> 404 (route does not exist)
GET OIRAN   /api/v1/lte/evidence/{run_id}             -> 404 LTE_ARTIFACT_UNAVAILABLE
GET OIRAN   /api/v1/lte/evidence/{run_id}/sessions    -> 404 LTE_ARTIFACT_UNAVAILABLE
```

No POST was replayed because that would mutate production and requires a real `bundle_id`, Operator authentication and CSRF.

No Caddy, preview, POLARIS, or OIRAN access log contains the run ID or evidence URL. Consequently, the exact historical client request cannot be claimed. The three requests above are direct reproductions that distinguish route absence, method mismatch, and resource absence.

## Durable run state

Sanitized read-only summary:

```text
state = CLEAN
final_state = FAILED
cleanup_required = false
cleanup = all five observations true
capture_refs_count = 0
evidence_bundle_id = null
s1_setup = COMPLETED
lte_attach = COMPLETED
ue_ip = COMPLETED
ping_ul = FAILED / LTE_TRAFFIC_FAILED
cleanup = COMPLETED
```

This proves the 2.7.4/0.28.3 retention logic is reachable for `CLEAN/FAILED`, but it had no observed bundle to retain. The failure is before `publish_capture_refs`, not a deletion during cleanup or revocation.

## Evidence filesystem proof

Systemd has no `POLARIS_LTE_EVIDENCE_BUNDLE_ROOT` environment variable. The code therefore defaults to:

```text
/var/lib/polaris-control/lte-evidence-bundles
```

Production state:

```text
/var/lib/polaris-control/lte-evidence-bundles = MISSING
/var/lib/oiran/lte-evidence-inbox = PRESENT, EMPTY
/var/lib/oiran/lte-evidence/datasets = PRESENT, no dataset for run
matching polaris-evidence-proof.json = 0
matching OIRAN manifest = 0
```

Repository search at the source SHA found consumers and test-only writers for `polaris-evidence-proof.json`, but no production finalizer binary, service, script or function that creates it. Documentation says an OIRAN capture finalizer owns staging; that component is not implemented in the release tree.

External collector metadata, without reading payloads, shows the rotation covering the run window (19:41:05–19:42:17 UTC):

```text
S1-MME segment metadata: present, final size 7,432 bytes
S11 segment metadata: present, final size 1,004 bytes
S1-U segment metadata: present, header-only size 292 bytes
```

These are raw external capture candidates, not approved evidence. ANR3 did not open or hash them and does not claim they are sufficient, anonymized, or session-bound.

## Why no capture reference can be recovered here

A valid reference requires all of the following from an approved finalizer:

- exact run/profile/scenario binding and UTC observation interval;
- immutable sanitized capture file;
- normalized sanitized event JSONL;
- SHA256 of both artifacts;
- frame bounds, decoder and event-schema versions;
- LTE RAT, endpoint roles and pseudonymous session reference;
- privacy approval state `SANITIZED_APPROVED`.

File name, modification time or proximity to the run is insufficient. Deriving `capture_refs` directly from the rotation metadata would violate the provenance contract and risk mixing adjacent sessions.

## Required corrective action

The smallest truthful production fix is not an OIRAN 404 change. OIRAN's 404 is correct because the resource is absent. The missing upstream boundary must be supplied:

1. implement and review a real OIRAN LTE capture finalizer;
2. provide it read-only access to the approved rotation source without changing dumpcap;
3. bind selection to the exact POLARIS run interval and approved capture scope;
4. decode and anonymize S1-MME/S11/S1-U into normalized events;
5. stage immutable artifacts and `polaris-evidence-proof.json` under a dedicated configured `POLARIS_LTE_EVIDENCE_BUNDLE_ROOT`;
6. publish using the Operator+CSRF protected POLARIS POST route;
7. import the returned envelope through the OIRAN Operator+CSRF POST route;
8. verify idempotent replay, conflicts, Session Explorer and Call Flow.

This requires explicit authorization for raw-capture processing and deployment/configuration. It cannot be replaced by an API alias or by returning HTTP 200 for a missing dataset.

## Offline verification at exact source SHA

### POLARIS

```bash
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/anr3-polaris-evidence-target \
  cargo test -p polaris-control-api lte_orchestrator::tests:: -- --nocapture
```

Result: `19 passed; 0 failed; 0 ignored; 250 filtered out`.

Coverage includes COMPLETED, FAILED/timeout, CANCELLED, EMPTY, PARTIAL, cleanup persistence, replay idempotence, drift conflict, server-side re-hashing, unique fixtures, and mandatory three-plane evidence for completed runs.

### OIRAN Rust/API

```bash
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/anr3-oiran-evidence-target \
  cargo test -p live-probe lte_evidence::tests:: -- --nocapture
CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/tmp/anr3-oiran-evidence-target \
  cargo test -p oiran-api lte_evidence -- --nocapture
```

Results:

```text
live-probe LTE evidence = 10 passed; 0 failed
OIRAN LTE API = 3 passed; 0 failed
```

Verified offline: import atomicity, `IMPORTED_PARTIAL`, exact replay, conflict, missing-run 404, cleanup gate, privacy rejection, RBAC/CSRF, bounded pagination, JSON/HTML export and Call Flow without fabricated edges.

### Frontend

```bash
npm test -- --run src/test/lte-offline-ui.test.ts \
  src/test/callflow-viewer.test.tsx \
  src/test/packet-analyzer-identity.test.tsx
npm run typecheck
npm run build
```

Results:

```text
Vitest = 16 passed; 0 failed
TypeScript = PASS
Vite build = PASS, 1,636 modules
check-dist-leaks = clean
```

## SemVer and code changes

No application code was changed because neither a route alias nor a fabricated manifest fixes the proven missing-finalizer defect. Versions remain POLARIS 0.28.3, OIRAN 2.7.4 and Live Probe 0.4.2. The branch contains only this evidence-backed blocker report; therefore no artificial SemVer bump or CHANGELOG entry was made.

## Safety

```text
dumpcap = 12
dumpcap snapshot SHA256 = 75850e0445da3f3dea1fb4ce05e867cef90955998e0bfa4895367fed84831840
disk = 79%
production deployment = none
live/grant/new capture/import = none
```

No subscriber or equipment identity was printed or committed.

— ANR3
