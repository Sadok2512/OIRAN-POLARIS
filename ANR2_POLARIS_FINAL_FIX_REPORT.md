# ANR2 — POLARIS 0.27.1 final fix report

Date UTC: 2026-11-01

## Verdict

**READY** for review. This is an offline-only delivery. No deployment, Grant,
srsENB/srsUE start, UERANSIM start or traffic generation was performed.

## Git and preservation

- Requested base: `a6c34e1d17d8ad2980c385bf689312e29cc0e5a2`.
- Source commit containing the hardening: `57104ff0ea2ad82740a4f7949f69b0cd22e23e03`.
- Delivery branch: `fix/polaris-0.27.1-final-anr2`.
- `git merge-base --is-ancestor a6c34e1d... HEAD`: exit `0`.
- A concurrent agent moved the supplied worktree from
  `hermes/final-anr2-20261101` to `fix/anr1-polaris-0.27.1-lte-security` and
  committed/pushed `57104ff` at 08:46:28 UTC. ANR2 did not rewrite that commit;
  this branch starts exactly from it.
- Pre-existing untracked ANR2 checkpoints and `release/` were preserved and
  intentionally excluded from this delivery commit.

## Versions and changes

- POLARIS API: `0.27.1` (`Cargo.toml` and `Cargo.lock`).
- Simulator Control UI: `0.20.0` (unchanged).
- CHANGELOG: 0.27.1 records revocation, lifecycle serialization, exact Grant
  constraints and dual RAM gates.
- Administrator disable revokes the temporary activation's Grant before
  clearing the activation.
- Revoked/expired Grant activation replay is rejected.
- LTE process start and cleanup are serialized; Grant state, expiry and run
  cancellation are rechecked immediately before srsENB/srsUE start.
- Runtime ping and UDP use the exact lower Grant limits. UDP passes explicit
  rate, duration and payload to iperf; `Both` runs independently bounded UL and
  DL measurements.
- Traffic sessions recheck the exact consumed Grant on every iteration.
- LTE admission requires both `MemAvailable >= 4 GiB` and
  `MemUsed <= 16 GiB`; missing measurements fail closed.
- Existing UERANSIM/5G code and UI were not changed.

## Memory budget and build

The build budget was calculated each time as:

`min(MemAvailable - 4 GiB, 16 GiB - MemUsed)`

Initial measured values:

- total: `20,970,582,016` bytes;
- used: `16,466,087,936` bytes;
- available: `4,504,494,080` bytes;
- safe incremental budget: `209,526,784` bytes.

Command attempted:

```text
CARGO_TARGET_DIR=/root/.hermes/cache/scratch/oiran-polaris-final-delivery-20261101/build-anr2 \
CARGO_BUILD_JOBS=1 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test -p polaris-control-api --lib --no-run
```

It was interrupted deliberately with SIGINT before the 4 GiB reserve could be
crossed (remaining reserve headroom: `83,767,296` bytes). No 768 MiB cgroup or
other hard compilation limit was used, and no OOM occurred in this run.

A concurrent pre-existing `cargo test -p polaris-control-api ...` then built
`target/debug/deps/polaris_control_api-275fd2fa4e3dde78`; its mtime
`1793522318.7053269340` is later than the newest API source mtime
`1793521965.0226700420`. ANR2 executed that exact artifact directly for the
targeted and full suites, avoiding another memory-heavy link.

## Tests executed manually

### API focused GREEN

Eight exact tests were run directly with `--exact --test-threads=1`:

- certification activation requirement;
- expired/revoked/wrong-nonce fail-closed behavior;
- activation ownership, idempotency and replay safety;
- expired/revoked legacy grant coverage rejection;
- 4 GiB reserve and 16 GiB used-memory ceiling;
- Operator/RBAC/CSRF/nonce/revocation HTTP contract;
- UDP cap rejection;
- exact iperf UDP `-b`, `-t`, `-l` arguments.

Result: **8 passed, 0 failed**.

### API regression

```text
POLARIS_CONTROL/target/debug/deps/polaris_control_api-275fd2fa4e3dde78 --test-threads=1
```

Result: **244 passed, 0 failed, 3 ignored**, duration `423.60s`. The ignored
items are explicit manual 100k-profile/pagination and restored-MongoDB tests.

### Simulator Control UI 0.20.0

Node: `v22.23.4`.

- `npm run typecheck`: PASS.
- `npm test`: **38 files, 235 tests passed**.
- `npm run build`: PASS, Vite `1708` modules, bundle
  `dist/assets/index-B9ER92_e.js`.
- Non-blocking debt: existing React `act(...)` warnings and a Vite dynamic vs
  static import chunk warning.

### Playwright LTE/5G and responsive

Vite ran on loopback only. `POLARIS_SIM_API_TARGET=http://127.0.0.1:1` forced
every unmocked API request to fail closed. Command:

```text
npx playwright test e2e/lte-integration.spec.ts e2e/topology.spec.ts \
  e2e/ue-manager.spec.ts e2e/traffic.spec.ts
```

Result: **24 passed** in `56.8s` across light/dark at 1280x800, 1440x900 and
1920x1080. Proven surfaces: bounded LTE certification without false
certification, combined LTE/5G topology with UERANSIM/srsENB/srsUE, UE RAT and
simulator columns, and UL/DL measured Traffic Generator cards.

### Additional POLARIS web package

Node `v22.23.4`: typecheck PASS, Vitest **5/5**, Vite build PASS.

## Safety evidence

- Final memory used: `15,772,540,928` bytes (<=16 GiB).
- Final memory available: `5,198,041,088` bytes (>=4 GiB).
- Final disk usage: `56%` (<85%).
- Final dumpcap count: `12`.
- Dumpcap PIDs remained:
  `906440,906442,906455,906461,906485,906489,906492,906511,906519,906520,906524,906527`.
- A foreign concurrent debug build transiently crossed the memory gates; ANR2
  did not start another compile during that interval. After it ended, resources
  returned compliant before testing resumed.
- No production service, Open5GS, OIRAN, capture process or radio simulator was
  changed or restarted.

## Remaining observations

- Repository-wide `cargo fmt --all -- --check` reports pre-existing formatting
  drift across many unrelated files; no mass formatting rewrite was applied.
- The delivery is offline-certified only. It does not claim LTE E2E REAL_PASS
  or production certification.

— ANR2
