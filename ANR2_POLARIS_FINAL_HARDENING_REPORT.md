# ANR2 — POLARIS LTE Final Hardening V2

Date: 2026-10-31 UTC  
Verdict: **BLOCKED**  
Code reviewed: `ad3ab117` (`fix/polaris-lte-final-hardening-v2`)  
Scope: POLARIS API + simulator-control UI; offline/mock only; no deployment, grant, simulator or traffic execution.

## 1. Initial state and lineage

- Isolated worktree: `/root/OIRAN_POLARIS_LTE_FINAL_HARDENING_ANR2`.
- Branch base: `anr2/polaris-lte-grant-v2` at `14e7a292`; merge commit `538b08b1` has parents `14e7a292` and prior lifecycle hardening `9cb69cdc`.
- Other ANR1/ANR3 worktrees were inspected read-only and not modified.
- `git merge-base --is-ancestor` returned `0` for:
  - requested base `0d2943c`;
  - Grant V2 `14e7a29`;
  - lifecycle hardening `9cb69cd`;
  - frontend 0.13.1 lineage `a39e692`;
  - API 0.20.1 lineage `29f8ef5`.

Production was read-only:

- `GET https://151.242.147.49:8020/polaris-api/v1/version` → HTTP 200, API `0.19.8`, UERANSIM adapter `0.5.0`.
- `GET .../auth/me` → HTTP 200, unauthenticated `viewer`.
- `/simulator/` → HTTP 200, asset `assets/index-CFDCtloT.js`, embedded frontend version `0.11.1`.
- No production mutation or restart was performed.

## 2. Delivered architecture and controls

### Backend `polaris-control-api` 0.22.1

- Grant V2 reuses `/live/grant` with a discriminated schema; V1 remains limited to existing UERANSIM flows.
- Persistent checksum-protected mode-0600 profile/grant stores, atomic temp-write/fsync/rename, nonce hash only, idempotency and one-time consumption.
- Grant binding includes profile/revision/config hash, canonical scenario hash, exact constraints, expiration, issuing role and hashed authenticated session. Restart converts `ISSUED` to `REVOKED_RESTART` and `CONSUMED` to `RECOVERY_ONLY`.
- RBAC and CSRF are required for grant creation/revocation, run start/stop and profile administration. Viewer mutations fail closed.
- Direct LTE component Start is rejected in live mode with `LTE_GRANT_V2_REQUIRED`; only `/lte/runs` may consume a V2 grant.
- Run state machine: preflight → ENB start → observed S1 wait → UE start → observed Attach/IP/session wait → running → hard-deadline cleanup. Cancellation, revocation and failure paths stop srsUE before srsENB and persist terminal state.
- Docker lifecycle accepts only Compose project `oiran-lab`, file `/root/POLARIS/compose/docker-compose.oiran-lab.yml`, services `srsenb`/`srsue`, exact immutable image reference and exact controller-owned container IDs. Commands use `/usr/bin/timeout` with TERM/KILL and no shell-supplied HTTP values.
- S1, Attach, LTE IP and session are based on current observations. Missing or non-`10.45.0.0/16` IP evidence remains `UNKNOWN`/null.
- LTE traffic cannot use a legacy V1 grant. It requires a consumed, unexpired V2 run, certification/live gates, ownership, observed Attach/IP/session and disk/memory gates. ANR1 constraints enforce UDP only, at most 1 Mbit/s per direction and 30 seconds.
- Existing 5G/UERANSIM routes and V1 grant behavior remain in the merged lineage.

### Frontend `@telecom/simulator-control` 0.15.1

- Existing UE Manager, Scenario Builder, Simulator Control and Traffic Generator host both LTE 4G/srsRAN and 5G SA/UERANSIM; no second application.
- Operator action `Start LTE certified run` creates then consumes Grant V2. The 256-bit nonce remains only in browser memory and is not stored or displayed.
- LTE state shows real backend S1/Attach/APN/IP/session/ownership values and preserves `UNKNOWN` when evidence is absent.
- Stop remains grant-independent but ownership-checked by the backend.
- LTE Traffic UI applies the ANR1 UDP bounds; 5G UDP/TCP behavior and graphs remain unchanged.
- IMSI role handling is retained: operator tests expose it only to operator; viewer receives protected identity.

## 3. Real laboratory discovery

Read-only command:

```text
rg -n '^  (srsenb|srsue):' /root/POLARIS/compose/docker-compose.oiran-lab.yml
242:  srsenb:
254:  srsue:
```

Configuration files exist and were hashed without printing subscriber material:

```text
ue.conf  80a51824a49ca5dc5f61eff27e442d96ac17b495f43728961a08e9f7d1c5caa4 (0600)
enb.conf 6f8d37535ab47a8b15c6fa37170fba336e0fa8df8eff43659feddec1553aa5e5 (0644)
rr.conf  2147d8f65f7ecfc6df9dc9404242ff48b0709176d9f6005633aca1759ea53784 (0644)
compose  533ea910c9ca89025c243829193db22dc5060f8802b8f1bb2b59ac24d0566b45
versions b29b92194588dda7644e7574cd214b8d085b880c7b966d86969c84f7d1f56d2e
```

Final safety check: `df -P /root` → `77%`; `pgrep -x dumpcap | wc -l` → `12`. No dumpcap process was signalled or restarted.

## 4. Test evidence

All commands were executed manually.

| Command | Result |
|---|---|
| `cargo check -p polaris-control-api` | PASS; 5 existing dead-code warnings |
| `cargo test -p polaris-control-api` | PASS: 211 passed, 0 failed, 3 ignored |
| `cargo test -p polaris-control-api lte_grant::tests` after added negative cases | PASS: 6 passed, 0 failed |
| `cargo test -p polaris-control-api srsran_controller::tests` | PASS: 6 passed, 0 failed |
| scoped `rustfmt --check` on LTE modules | PASS |
| `npm ci` | PASS; 265 packages; Node engine warning noted below |
| `npm test -- --run` first concurrent run | 214 passed, 1 timeout failure (`UeManager` 10K test) |
| isolated retry of timed-out test | PASS: 1 passed |
| clean full `npm test -- --run` rerun | PASS: 35 files, 215/215 tests |
| `npm run build` | PASS: TypeScript + Vite, 1708 modules |
| `npm audit --omit=dev --json` | PASS: 0 production vulnerabilities |
| `npx playwright test e2e/lte-integration.spec.ts` | PASS: 6/6, 1280/1440/1920, light/dark, mocked API |
| `npx playwright test` full regression | FAIL/INTERRUPTED: 15 passed, 3 failed, 1 interrupted, 167 not run |

The full Playwright failures were recorded, not hidden:

1. `hotfix-flags.production.spec.ts` failed at 1280 light.
2. `live-grant-0.11.1.spec.ts` crashed during `page.goto`/timed out; its route set leaked to the local proxy and no backend was running.
3. `no-overlap-0.10.2.spec.ts` found truncated UE status text at 1280 (`clientWidth=1`, `scrollWidth=238`).
4. The next no-overlap test was interrupted after the required failure evidence was captured; remaining projects did not run.

No test invoked real Docker, srsRAN, UERANSIM, Open5GS or traffic.

## 5. Blocking findings

1. **Immutable image mismatch:** `LTE_GRANT_CONTRACT.md` and the controller require `oiran/srsran4g@sha256:69e094...d43`; the real `/root/POLARIS/compose/versions.env` currently pins `oiran/srsran4g@sha256:9415af...b92`. The controller correctly fails closed with `LTE_RUNTIME_OWNERSHIP_CONFLICT`. ANR1 must certify one digest and align the contract/runtime; ANR2 must not guess.
2. **Full responsive regression is not green:** the complete Playwright run has the failures above. The LTE-specific six-project suite is green, but 5G/full UI regression cannot be declared PASS.
3. **LTE TCP is not authorized by ANR1 Grant V2:** the canonical allowed actions include UDP but not TCP. Backend/UI therefore block LTE TCP instead of expanding authority. The contract must be revised and certified before TCP can be enabled.
4. **No real LTE E2E evidence:** ANR1 live authorization was not provided. S1, Attach, IP, UL/DL and cleanup remain unverified in a real run; production certification is forbidden.
5. Local Node is `18.19.1` while installed React Router declares Node `>=20`. Build/tests passed, but the release build host should be upgraded or the supported dependency set explicitly pinned before certification.

## 6. Prepared atomic deployment and rollback (not executed)

Prerequisites: resolve every blocker; ANR1 E2E and ownership PASS; full Playwright PASS; explicit deployment authorization; production backup; `git merge-base --is-ancestor` PASS against deployed API/frontend SHAs; disk below 85%; capture PID/start-time snapshot still unchanged.

Deployment plan:

1. Record production API/frontend versions, checksums, service state and health; copy the current API binary/config and frontend asset directory to a timestamped mode-0700 backup directory on the same filesystem.
2. Build API and frontend once from the reviewed SHA; record SHA-256 checksums. Stage both in versioned release directories without changing live symlinks.
3. Validate staged API configuration with live execution flags still false and validate frontend asset references locally.
4. In one controlled maintenance transaction, switch the API unit/binary reference and frontend release symlink to their staged versions; restart only the POLARIS API if authorized. Do not restart Open5GS, OIRAN, gNB, UERANSIM, srsRAN or dumpcap.
5. Run read-only health/version/RBAC/UI smoke tests. Keep LTE profile disabled and do not create a grant or run traffic during deployment validation.
6. Any failed check triggers rollback of both components, not a partial release.

Rollback plan:

1. Restore the previous frontend symlink and API binary/config from the recorded backup.
2. Restart only the POLARIS API if that restart was explicitly authorized.
3. Verify previous version endpoints, viewer/operator RBAC, 5G pages and dumpcap count/start times.
4. Preserve failed-release logs and checksums; never delete grant/ownership stores blindly. Consumed grants recover as `RECOVERY_ONLY`, issued grants as `REVOKED_RESTART`.

## 7. Conclusion

The code-level Grant V2/lifecycle integration is reviewable and its focused offline suites pass. The release verdict remains **BLOCKED** because the certified image digest differs from the real Compose pin, the full Playwright regression is not green, LTE TCP is outside the approved contract, and no authorized real LTE E2E test has occurred. No production certification is claimed.

— ANR2
