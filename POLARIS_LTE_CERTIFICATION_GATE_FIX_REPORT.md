# POLARIS LTE Certification Gate Fix P0 — ANR2

Date UTC: 2026-10-31  
Verdict: **READY** for offline review; **not REAL_PASS**, not deployed and not LTE E2E certified.

## Source and lineage

- Isolated worktree: `/root/OIRAN_POLARIS_LTE_CERT_GATE_FIX_ANR2`
- Branch: `fix/polaris-lte-certification-gate-p0-anr2`
- Base: `2dd98d70adca010a5f142378278e50002d5c2c38`
- Implementation commit: `93e0284695827324f66ec938061d0cdb74688109`
- `git merge-base --is-ancestor 2dd98d70... 93e02846...` returned `0`.
- The shared worktree `/root/OIRAN_POLARIS_FOUNDATION` was dirty/conflicted at preflight and was not modified.
- Reference reviewed: `/root/POLARIS_REAL_LAB_INTEGRATION/POLARIS_LTE_ACTIVATION_PLAN.md`.

## Versions

- POLARIS API: `0.26.0` (from `0.25.2`).
- POLARIS UI: `0.19.0` (from `0.18.2`).
- Both changelogs were updated.

## Implemented contract

`CERTIFICATION_RUN` and `LIVE_OPERATIONAL` are separate typed purposes in the API, persistent Grant V2 journal and UI. The operation mode is fail-closed:

- `CERTIFICATION_RUN` exists only when execution is live-enabled, srsRAN lifecycle is enabled, `POLARIS_LTE_CERTIFICATION_RUN_ENABLED=true`, and `POLARIS_LTE_E2E_CERTIFIED=false`.
- `LIVE_OPERATIONAL` exists only when the existing explicit certification flag is true.
- A run result never writes or promotes `POLARIS_LTE_E2E_CERTIFIED`; certification remains an external/manual decision based on real evidence.
- Grant issuance and run consumption require matching purpose. A certification grant cannot authorize an operational run or vice versa.
- Only controller-owned `LTE-SRSUE-TEST-01`, revision 1, and `lte-e2e-certification-v1` are accepted.
- The exact action set is required: S1 Setup, LTE Attach, ping UL/DL, UDP UL/DL and cleanup. Duplicate or missing actions fail closed.
- Bounds remain one UE, 300 seconds maximum, five pings/direction, UDP at most 1,000,000 bit/s/direction, 30 seconds/direction, 1,200-byte payload and one stream.
- The certified immutable image is `oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43` and the canonical Compose digest is `308053a274844259c16da7751708b39e6559cfec2b8d958dc4fcafebecd0da19`. Both are verified before certification grant issuance and run start; the local image ID is inspected with fixed argv and a host timeout.
- Existing Grant V2 subject/session ownership, Operator RBAC, CSRF, nonce hash, expiry, revocation, one-time consume and replay protections remain authoritative. Old journal records remain checksum-compatible.
- A hard global deadline marks the active step `LTE_GLOBAL_TIMEOUT`, then invokes the common idempotent cleanup.
- `POST /api/v1/lte/runs/:run_id/emergency-stop` is Operator+CSRF protected but deliberately grant-independent, so expiration/revocation cannot prevent Stop/Cleanup.
- Startup reconciliation schedules cleanup for nonterminal durable runs whose journal still requires cleanup.
- `/lte/status` publishes `operation_mode`, `certification_state`, `certification_run_enabled`, and `manual_certification_required`. States are `CERTIFICATION_PENDING`, `CERTIFICATION_RUNNING`, `CERTIFICATION_FAILED`, and `CERTIFIED`.
- The existing UERANSIM 5G APIs and views were not changed.

## Manual test evidence

No srsENB, srsUE, UERANSIM, grant, traffic or production component was started.

| Command | Result |
|---|---|
| `cargo check -p polaris-control-api` | PASS |
| `cargo test --workspace -- --nocapture` | PASS: API 238 passed, 3 ignored manual benchmarks/integration tests; all other workspace crates passed (45 tests total outside API). |
| Targeted Grant/orchestrator/controller/certification/cleanup tests | PASS: Grant 7, orchestrator 11, controller 11, certification 4, emergency cleanup 1, restart recovery 1, mode separation 1. |
| Node `v20.20.0`; `npm test` | PASS: 38 files, 235 tests. |
| `npm run typecheck` | PASS. |
| `npm run build` | PASS: 1,708 modules, production bundle built. |
| `npx playwright test e2e/lte-integration.spec.ts` | PASS: 6/6, 1280/1440/1920, light/dark. |
| `npx playwright test e2e/ue-manager.spec.ts e2e/topology.spec.ts e2e/traffic.spec.ts` | PASS: 18/18, 1280/1440/1920, light/dark; covers LTE/5G topology, UERANSIM/srsRAN UE inventory and traffic UI. |

Additional observations:

- Running the Vitest suite under the host's default Node 18 was impossible because dependencies were absent. Node 26 caused 45 legacy localStorage test failures; rerunning with isolated Node 20.20.0 produced the authoritative 235/235 PASS result.
- A broad `npx playwright test` attempt was stopped after three legacy capture-spec failures caused by old/incomplete capture fixtures (`Invalid API response` / capture expectations). The release-relevant LTE and regression specs were then run explicitly and passed 24/24. This historical capture-suite debt is not hidden and should be repaired separately.
- `cargo fmt --all -- --check` reports pre-existing formatting drift in multiple base files outside this change. `git diff --check` passes.

## Resource and safety evidence

Final commands:

```text
free -b
Mem available = 5,646,995,456 bytes
Mem used      = 15,323,586,560 bytes

df -P /root
/dev/sda1 = 54% used

pgrep -x dumpcap | sort -n
3691817 3691819 3691835 3691841 3691851 3691867
3691868 3691894 3691899 3691902 3691904 3691905
count = 12
```

The twelve dumpcap processes were never signalled or controlled by ANR2. Their PIDs differed from the initial observation while this isolated work was in progress, indicating external process churn; the required count remained exactly twelve at final verification.

## Remaining gates

- No live LTE test was performed, so real S1 Setup, Attach, IP, UL/DL and cleanup evidence do not exist yet.
- `POLARIS_LTE_E2E_CERTIFIED` must remain false until the authorized real E2E evidence is reviewed; this code cannot promote it.
- No production configuration was changed. Enabling certification mode, issuing a dedicated real Grant V2 and starting the bounded run still require separate explicit authorization.
- Production deployment requires its own lineage, backup, atomic API/UI deployment, recipe and rollback authorization.

— ANR2
