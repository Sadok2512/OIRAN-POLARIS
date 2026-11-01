# POLARIS / OIRAN — Final release approval review

Date UTC: 2026-11-01  
Reviewer: ANR3  
Scope: offline/read-only review; no grant, live LTE, capture, service restart, or deployment.

## Short report

POLARIS_SHA = `70faacb5c9c98b8e2968de0944c1d05414704c2a` — remote branch `fix/polaris-0.27.1-final-anr2` exact match; API `0.27.1`.

OIRAN_SHA = `92c1b08cd63202272986b64702ee97a334f010a3` — remote branch `hermes/final-anr3-20261101` exact match; API `2.7.1`.

GIT_LINEAGE = PASS — deployed POLARIS source `4669de8b5d9165e2176d8394931b821415ee100a` is an ancestor of the POLARIS candidate; deployed OIRAN 2.5.4 source `6464476a2ffd24324aecf0ab43ce60af3161f5f8` is an ancestor of the OIRAN candidate. The two candidates diverge after merge-base `7f84c4963c36b80c582f7572000596a2ab7c57d9`: they must be built and released as two exact, independent component artifacts, not presented as one combined monorepo SHA.

SECURITY = PASS (offline) — the four LTE defects are present and targeted tests pass; Grant V2 ownership/RBAC/CSRF, canonical digests, expiration, revocation, anti-replay, bounded execution and cleanup fail closed. OIRAN removes identity-bearing keys/IE objects from dataset, session, event, packet and Call Flow responses and exports; raw-response privacy tests pass for viewer and operator.

API_COMPATIBILITY = PASS — both candidates use canonical evidence schema `oiran-polaris.lte-e2e-evidence.v1`; the shared contract trees are byte-identical and the schema SHA-256 is `4eb2a8c124845e6ebfadc32b3ad5459142b24c523e86697178b7fb2395cc1e14`. OIRAN expects the documented outer ingestion envelope `oiran.lte-evidence-ingestion.v1` and rejects mismatched schemas.

TESTS = PASS — 47 targeted offline tests replayed: POLARIS 38/38 and OIRAN 9/9; 0 failed. No live test was run. Previously documented ignored stress/manual tests and repository-wide `rustfmt` debt remain release notes, not silently promoted to PASS.

RESOURCE_GATES = PASS at final measurement — available RAM `4,936,511,488` bytes (>= 4 GiB), used RAM `16,034,070,528` bytes (<= 16 GiB), root disk `57%` (<85%), 12 `dumpcap` processes. Their PIDs and start times stayed stable during this review, but continuity across a future deployment is not yet certifiable.

DEPLOYMENT_READY = YES

BLOCKERS = No offline release blocker. Deployment still requires distinct explicit authorization, fresh verified backups, exact-SHA artifact hashes, and before/after equality of the 12 `dumpcap` PID/start-time snapshot. LTE REAL_PASS remains blocked until an independently authorized real LTE certification.

## Evidence

### Git and deployed baseline

Commands and results:

```text
git ls-remote origin refs/heads/fix/polaris-0.27.1-final-anr2
70faacb5c9c98b8e2968de0944c1d05414704c2a

git ls-remote origin refs/heads/hermes/final-anr3-20261101
92c1b08cd63202272986b64702ee97a334f010a3

git merge-base --is-ancestor 4669de8b5d9165e2176d8394931b821415ee100a 70faacb5c9c98b8e2968de0944c1d05414704c2a
exit 0

git merge-base --is-ancestor 6464476a2ffd24324aecf0ab43ce60af3161f5f8 92c1b08cd63202272986b64702ee97a334f010a3
exit 0

git merge-base 70faacb5c9c98b8e2968de0944c1d05414704c2a 92c1b08cd63202272986b64702ee97a334f010a3
7f84c4963c36b80c582f7572000596a2ab7c57d9

git merge-base --is-ancestor <either-candidate> <other-candidate>
exit 1 in both directions
```

Read-only production queries confirmed that production was unchanged:

- POLARIS API `0.26.0`, platform `3.2.1`; active binary SHA-256 `5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`.
- OIRAN API/platform `2.5.4`; active binary SHA-256 `7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`.

All three isolated review worktrees were clean before this report was written. Existing untracked files in `/root/HERMES_FINAL_ANR2_20261101` were not modified.

### Exact LTE security corrections

The POLARIS candidate is a documentation-only child of security commit `57104ff0ea2ad82740a4f7949f69b0cd22e23e03`; the API sources and lockfile are unchanged between those SHAs. The four reviewed fixes are:

1. Disabling temporary LTE activation revokes its bound Grant; revoked or expired Grants cannot be replayed through the idempotent activation path.
2. A single async LTE lifecycle lock serializes start/stop/cleanup. Cancellation, Grant expiry and the run deadline are checked again immediately before process starts and traffic.
3. Consumed-Grant lower bounds constrain ping and UDP payload/rate/duration per direction and by remaining deadline; bounded UDP uses a 1200-byte payload ceiling.
4. The memory gate requires both `MemAvailable >= 4 GiB` and `MemUsed <= 16 GiB`; missing measurements fail closed.

Static review also confirmed operator ownership, session-bound RBAC/CSRF, hashed nonce/idempotency keys, persistent mode-0600 Grant/run stores, exact canonical Compose/profile hashes, immutable srsRAN image digest, fixed argv/timeouts, revocation and emergency cleanup independent of a live Grant.

### OIRAN privacy and compatibility

The common response sanitizer removes identity-labelled keys and entire identity IE objects recursively before returning API material. It is applied to datasets, sessions, events, packets, Call Flow, and JSON/HTML exports. The tests explicitly exercise raw JSON for both viewer and operator roles; useful non-identity fields remain present. Clear identity material is rejected by LTE ingestion.

Compatibility checks:

```text
git diff --quiet 70faacb... 92c1b08... -- infrastructure/lte-certification docs/contracts
exit 0

sha256sum infrastructure/lte-certification/lte-evidence-schema.json
4eb2a8c124845e6ebfadc32b3ad5459142b24c523e86697178b7fb2395cc1e14
```

The canonical payload carries the required S1-MME/S11/S1-U capture references, hashes, frame bounds, decoder/event versions and `SANITIZED_APPROVED` state. OIRAN's API boundary requires operator plus CSRF for import and its ingestion layer performs the documented envelope adaptation.

### Tests replayed manually

No CI result is used as the cross-review proof. Cached binaries were replayed from the clean exact candidate worktrees after checking the RAM/disk gate.

POLARIS command form:

```text
/root/HERMES_FINAL_ANR2_20261101/POLARIS_CONTROL/target/debug/deps/polaris_control_api-275fd2fa4e3dde78 <filter> --exact --nocapture
```

Results:

- `lte_grant::tests::`: 9 PASS.
- `lte_orchestrator::tests::`: 11 PASS.
- `srsran_controller::tests::`: 13 PASS.
- Five P0 exact tests covering operator/CSRF, activation revocation, dual memory limits, emergency cleanup and restart recovery: 5 PASS.
- Total POLARIS: 38 PASS, 0 FAIL.
- Test binary SHA-256: `25314965b03473fe7fa0ad092970aa12cff2eef47ef41c4ea204c48acdf475e6`.

OIRAN command forms:

```text
/root/HERMES_FINAL_ANR3_20261101/OIRAN/target/debug/deps/oiran_api-8df18ffba0dd7ebc --exact <test> --nocapture
/root/HERMES_FINAL_ANR3_20261101/OIRAN/target/debug/deps/live_probe-fd5213b5b6d4f8b2 --exact <test> --nocapture
```

Results:

- API: raw-route privacy, recursive sanitizer, synthetic LTE session, import RBAC/CSRF and installed LTE/5G decoders: 5 PASS.
- Live Probe: atomic/idempotent materialization, identity rejection and ambiguous-TEID isolation, retained-event memory fail-close, bounded S1AP/S11/S1-U correlation: 4 PASS.
- Total OIRAN: 9 PASS, 0 FAIL.
- API test binary SHA-256: `e0c65dfac7a86527023978433962f08912fb8b2c136c49ae723e19054ebc074a`.
- Live Probe test binary SHA-256: `9c5439d5a70de355601e577c7ff1d70716787b0bd3d54c0593ae85d45b3934ba`.

The candidates retain documented ignored high-volume/manual tests (POLARIS resource/pagination fixtures; OIRAN 300/500/512 MiB and approximately 1.2 GiB stress fixtures) and pre-existing repository-wide formatting debt. They were not executed under the 4 GiB reserve gate and are not counted in the 47 PASS.

### Resource and capture gate

Final commands:

```text
free -b
Mem used      16034070528
Mem available 4936511488

df -P /root
/dev/sda1 ... 57%

pgrep -x dumpcap | wc -l
12
```

The observed dumpcap PIDs were `906440,906442,906455,906461,906485,906489,906492,906511,906519,906520,906524,906527`. PID/start-time snapshot SHA-256: `4fe9f419d92e43bd68cdf78cf7e36d15e7fed415245bc36bff072f23084cf9e5`. A single review can prove preservation during the review, not continuity through a future deployment; the deployment procedure must compare the same fields immediately before and after each component change.

## Backup, deployment recipe and rollback

This is a prepared procedure only; it was not executed.

1. Recheck remote branch SHA, production-source ancestry, RAM, used RAM, disk, and the 12-process PID/start-time snapshot. Abort on any mismatch.
2. Create fresh, mode-0700, timestamped backups with SHA-256 manifests:
   - POLARIS: active API binary, served UI, environment/configuration, systemd unit/drop-ins, profile/run/Grant/audit stores.
   - OIRAN: `/opt/oiran/bin`, served web assets, `/etc/oiran`, systemd unit/drop-ins and registry/catalog metadata. Do not copy, rewrite or rotate historical/raw captures.
3. Perform a read-only restore rehearsal into temporary directories and verify every manifest. Preserve current persistent Grant/run state on rollback unless the migration plan explicitly proves a compatible restore.
4. Build OIRAN only from `92c1b08...` and POLARIS only from `70faacb...`; record artifact hashes. Recheck `merge-base --is-ancestor` immediately before installation.
5. Under separate explicit deployment authorization, release one component at a time, OIRAN first. Restart only that application's services; never touch Open5GS, srsRAN, UERANSIM, gNB/eNB or dumpcap.
6. After each component, verify version/health, privacy scans, bounded pagination, schema compatibility, UI/API smoke tests, resources and exact dumpcap PID/start-time continuity. Do not create a Grant or invoke an action route.
7. Any failed check triggers immediate component-local rollback: atomically restore its backed-up binary/assets/config, restart only its own service, repeat the read-only recipe, and confirm the 12 dumpcaps. Do not roll back or mutate captures/datasets.

Release approval is therefore **READY_FOR_DEPLOYMENT offline**, not deployment authorization and not LTE `REAL_PASS`.

— ANR3
