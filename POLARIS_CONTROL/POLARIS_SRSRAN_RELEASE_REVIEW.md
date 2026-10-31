# POLARIS srsRAN Release Review — ANR2

Date: 2026-10-31  
Repository: `Sadok2512/OIRAN-POLARIS`  
Reviewed branch: `feat/polaris-srsran-lte-ui-v1`  
Reviewed SHA: `3f8f0ee2b1e2025db5bf9be5c87e46cb1ee92e64`  
API candidate: `0.21.0`  
Frontend candidate: `0.14.0`  
Verdict: **BLOCKED**

No deployment, merge, production restart, live UE, live scenario, live traffic, Open5GS/OIRAN/gNB mutation, or capture operation was performed.

## 1. Release verdict

The Git lineage, 0.13.1 frontend preservation, RBAC/grant gates, mock tests, 5G regression suite, responsive mock Playwright checks, disk safety, and dumpcap preservation pass.

The release is not deployable yet:

1. ANR1 LTE E2E certification and explicit deployment authorization are absent.
2. Exact runtime targets `oiran-lab-srsenb-1` and `oiran-lab-srsue-1` are not present on the host; only `oiran-lab-mme-1` was observed running/healthy.
3. Live LTE scenario definitions are always rejected outside mock mode, even if certification flags become true (`lib.rs:10421-10427`).
4. Traffic Generator disables LTE Start unconditionally (`TrafficSessions.tsx:267`); no LTE traffic runtime adapter is connected.
5. Docker `inspect`, `logs`, `start`, and `stop` subprocesses have no host-side timeout. `docker stop --time 10` bounds container grace but not the CLI call itself.
6. Attach/S1/session state is inferred from the last 200 log lines, without lifecycle timestamps. `active_sessions` is derived from a historical attach marker, APN is fixed to `internet`, and S1 can remain reported from a stale log. These are not sufficient as certified real-time states.

## 2. Production and Git lineage

### Production evidence

- `GET https://151.242.147.49:8020/polaris-api/v1/version` returned API `0.19.8` and HTTP 200.
- Production API historical SHA: `fef53408709580251c372c2253c28937f3efe852`.
- Production frontend historical SHA: `b0adf3b6c7dbd65cb674f2c06a9fcbff93b4c3bc` (`0.11.1`).
- Production JS: `index-CFDCtloT.js`, SHA-256 `f2c58890df98f7c342307c9d6a6ddcdec1cd3a576a4716a52bb0408a95ac792c`.
- The same JS in the detached `b0adf3b` build has the identical SHA-256.
- Production API binary SHA-256: `1e9030da06a40a6e3c5afffc20c1e5b4d8d3f3df64cb789a024d0c47dd92eca2`.
- Production frontend `index.html` SHA-256: `47010732beee1cd7b648416a9876af6ea306f20816f1c8cbb04295b624553420`.

### Ancestry commands

```bash
git merge-base --is-ancestor fef53408709580251c372c2253c28937f3efe852 3f8f0ee2b1e2025db5bf9be5c87e46cb1ee92e64
git merge-base --is-ancestor b0adf3b6c7dbd65cb674f2c06a9fcbff93b4c3bc 3f8f0ee2b1e2025db5bf9be5c87e46cb1ee92e64
git merge-base --is-ancestor a483e0a9e0e0031c42b0e805eaf29ea052dbe746 3f8f0ee2b1e2025db5bf9be5c87e46cb1ee92e64
git merge-base --is-ancestor a39e692b416ac4fd2ebbbf0a10b6d09f6e56ad78 3f8f0ee2b1e2025db5bf9be5c87e46cb1ee92e64
```

Result: all four commands returned exit code 0.

## 3. Audit of the `merge -s ours`

Merge commit `d73d9570b4cc5911f9d9ae729ac3dec2e55e7cce` has parents:

- first parent `0932d075279dcc27c17208b74a6e17eeca1de714`;
- second parent frontend `a39e692b416ac4fd2ebbbf0a10b6d09f6e56ad78`.

Evidence:

```bash
git diff --quiet d73d957^1 d73d957
# exit 0: the ours merge changed no tree content

git diff --quiet a39e692 48343a3 -- apps/simulator-control
# exit 0: the pre-LTE baseline contains the exact 0.13.1 frontend tree

git diff --diff-filter=D --name-only a39e692 3f8f0ee -- \
  apps/simulator-control/src apps/simulator-control/e2e \
  apps/simulator-control/package.json apps/simulator-control/package-lock.json
# no output: no functional source, E2E, or package file was deleted
```

Conclusion: the `ours` merge records ancestry only. It did not replace frontend code. The 0.13.1 subtree had already been imported exactly in `48343a3`; 0.14.0 then adds LTE changes. Historical screenshots were removed to control disk use, but no runtime/test source was deleted. The complete 215-test frontend suite passes, including the existing UE Manager, Scenario Builder, provisioning, traffic, topology, IMSI role, and 5G tests.

## 4. API/security/runtime review

| Area | Result | Evidence |
|---|---|---|
| API version | PASS | Cargo package `0.21.0`; `/version` includes srsRAN controller version. |
| RBAC | PASS | Start/Stop call `require_operator`; only operator/administrator accepted, CSRF required. |
| Grant | PASS | Start requires one active, non-revoked, non-expired grant covering `LTE-UE-01`; Stop is intentionally grant-exempt for safety. |
| Target validation | PASS | Exact `ENB-01` / `LTE-UE-01` allowlist; arbitrary container and UE rejected by unit tests. |
| Shell safety | PASS | Direct `Command` argv; no shell interpolation. |
| Process bounds | FAIL | No host timeout for Docker CLI calls; Stop grace alone is insufficient. |
| Runtime presence | FAIL | srsENB/srsUE exact containers not found; EPC running/healthy. |
| State truthfulness | PARTIAL | Container state is from Docker inspect; attach/S1/session are log-derived and can be stale; UE IP stays honestly null. |
| Audit trail | PASS | Start/Stop success and refusal paths call the audit sink. |
| Secrets | PASS/PARTIAL | Known IMSI/SUPI/OPc/K markers are redacted; redaction is marker-based and should be fuzz-tested before certification. |
| LTE scenarios | FAIL for live | Types validate/catalogue correctly, but all live LTE execution is hard-blocked outside mock mode. |
| LTE traffic | FAIL for live | UI offers LTE selection/parameters, but Start is hard-disabled and no LTE runner exists. |
| 5G isolation | PASS | Full existing backend/frontend suites pass; LTE inventory is absent unless an LTE/EPC component is observed. |

## 5. Manual tests rerun

### Backend

```bash
CARGO_TARGET_DIR=/dev/shm/anr2-release-review-target \
  cargo test --manifest-path POLARIS_CONTROL/apps/api/Cargo.toml \
  --locked --offline
```

Result: **PASS — 199 passed, 0 failed, 3 ignored**. The ignored cases are explicit manual 100,000-row/restored-MongoDB tests. Existing warnings: five dead-code warnings plus one duplicated test attribute; no test failure.

### Frontend typecheck and unit/regression tests

```bash
node_modules/.bin/tsc -p tsconfig.json --noEmit
node_modules/.bin/vitest run
```

Result: **PASS — 35 files, 215 tests**. Existing React `act(...)` warnings remain non-fatal.

### Playwright mock, no live backend

```bash
POLARIS_SIM_VITE_CACHE_DIR=/dev/shm/anr2-review-vite-cache \
  node_modules/.bin/vite --host 127.0.0.1 --port 4331

POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:4331/simulator/ \
  node_modules/.bin/playwright test e2e/lte-integration.spec.ts
```

Result: **PASS — 6/6**:

- 1280 light/dark;
- 1440 light/dark;
- 1920 light/dark.

The test verifies the unified UE Manager LTE panel, certification lock, disabled live controls, and absence of horizontal page overflow. API calls are intercepted. No srsRAN/UERANSIM process or traffic was started.

## 6. Host safety evidence

Commands:

```bash
df -B1 --output=size,used,avail,pcent /root
curl -ksS https://151.242.147.49:8020/polaris-api/v1/system/health
pgrep -a -x dumpcap
docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}not_available{{end}}|{{.Name}}' \
  oiran-lab-srsenb-1 oiran-lab-srsue-1 oiran-lab-mme-1
```

Observed:

- disk: `71.6253%` used (`df` displays 72%), API decision `NORMAL`, writes allowed;
- dumpcap: exactly **12** processes before and after tests; no signal/restart/action sent;
- `oiran-lab-mme-1`: running/healthy;
- `oiran-lab-srsenb-1`: not found;
- `oiran-lab-srsue-1`: not found.

## 7. Backup plan — prepared, not executed

Prerequisites: ANR1 certification, explicit deployment authorization, all blockers closed, clean reviewed SHA, disk <85%, 12 dumpcap processes, and production health READY/NORMAL.

The approved deployment operator should create a root-only backup on the same host. Example commands below are a plan only:

```bash
release_stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_root=/opt/oiran-polaris-preview/backups/polaris-srsran-$release_stamp
install -d -m 0700 "$backup_root"
cp --preserve=all /root/POLARIS_CONTROL/target/release/polaris-control-api "$backup_root/api-0.19.8"
cp -a /opt/oiran-polaris-preview/public/simulator "$backup_root/simulator-0.11.1"
cp -a /var/lib/polaris-control "$backup_root/runtime-state"
install -m 0600 /root/POLARIS_CONTROL/config/polaris-control.env "$backup_root/polaris-control.env"
systemctl cat polaris-control.service > "$backup_root/polaris-control.service.txt"
sha256sum "$backup_root/api-0.19.8" "$backup_root/simulator-0.11.1/index.html" \
  > "$backup_root/SHA256SUMS"
```

Do not copy or print subscriber secrets into the release report. Verify backup permissions and hashes before changing any active path.

## 8. Coordinated atomic deployment plan — not executed

Use an immutable release directory containing both artifacts:

```text
/opt/polaris-control/releases/<reviewed-sha>/
├── api/polaris-control-api
└── frontend/...
```

Proposed transaction after approval:

1. Rebuild from the exact reviewed/certified SHA in an isolated worktree; run the commands from section 5 and ANR1 E2E acceptance.
2. Record SHA-256 for API binary, `index.html`, JS and CSS assets.
3. Copy both artifacts to the immutable release directory; set root ownership and least privileges.
4. Create a release manifest with Git SHA, SemVer, hashes, test results, production baseline hashes, and rollback release path.
5. Bootstrap a stable `/opt/polaris-control/current` symlink. Configure:
   - systemd `ExecStart=/opt/polaris-control/current/api/polaris-control-api`;
   - `/opt/oiran-polaris-preview/public/simulator` as a stable link to `/opt/polaris-control/current/frontend`.
6. Recheck disk, CPU/memory, 12 dumpcaps, no active scenario/traffic, and current production hashes.
7. Prepare `current.next` pointing to the new immutable release, then atomically rename the symlink on the same filesystem.
8. Restart only `polaris-control.service`; do not restart Open5GS, OIRAN, gNB, dumpcap, or preview service unless separately authorized.
9. Validate `/version`, `/system/health`, authentication roles, read-only `/lte/status`, frontend asset hashes, existing 5G pages, and that LTE remains locked unless the certified flags and valid grant are present.
10. If any check fails, execute rollback immediately.

The symlink switch is the atomic release point for the paired artifact set. The API process adopts the new target at its controlled restart; therefore the old/new API and frontend must remain backward-compatible during that short transition.

## 9. Rollback plan — not executed

1. Atomically repoint `/opt/polaris-control/current` to the recorded previous release.
2. Restart only `polaris-control.service`.
3. Confirm API `0.19.8`, production frontend JS hash `f2c58890...ac792c`, system health NORMAL, disk <85%, and 12 dumpcaps.
4. If the unified symlink bootstrap itself failed, restore:
   - API binary from `api-0.19.8` using a same-filesystem atomic rename;
   - frontend directory from `simulator-0.11.1`;
   - original systemd unit/drop-in, then `daemon-reload` and API-only restart.
5. Restore runtime state only if a schema migration changed it and its migration-specific rollback has been validated. Do not blindly overwrite live state.
6. Record failure evidence and hashes; keep LTE flags false.

## 10. Conditions to change verdict to READY

- ANR1 certifies LTE Attach/Detach/Data UL/DL and cleanup E2E.
- Exact srsENB/srsUE runtime targets exist and are verified without touching captures or 5G.
- LTE scenario executor is implemented behind certification/grant/resource gates.
- LTE Traffic Generator is wired to a bounded real runner and no longer hard-disabled after certification.
- Docker subprocesses receive hard timeouts and deterministic cleanup/order enforcement.
- Attach, S1, APN, UE IP, and active-session states use current structured observations, not stale log presence.
- New negative/timeout/cleanup tests and mock Playwright tests pass.
- Explicit deployment authorization is issued for the certified SHA.

— ANR2
