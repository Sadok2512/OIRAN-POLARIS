# POLARIS Operator LTE Temporary Activation V1 — ANR2

Date UTC: 2026-11-01  
Verdict: **READY_FOR_REVIEW**  
Branch: `feat/polaris-operator-lte-temp-activation-v1-anr2`  
Base: `4669de8b5d9165e2176d8394931b821415ee100a`  
Implementation commit: `698e1f265b43b243a208a692035e02fb778145ba`  
Versions: POLARIS API `0.27.0`, POLARIS UI `0.20.0`

## Scope and safety

- Work was performed only in the isolated worktree
  `/root/OIRAN_POLARIS_OPERATOR_LTE_TEMP_ANR2`.
- Production, Open5GS, OIRAN, UERANSIM, srsENB and srsUE were not modified or
  restarted. No real grant, LTE session or traffic was created.
- `POLARIS_LTE_E2E_CERTIFIED` is never written by this implementation and
  remains `false` until an independently reviewed real E2E certification.
- The 12 external dumpcap processes remained present with unchanged PIDs:
  `3691817,3691819,3691835,3691841,3691851,3691867,3691868,3691894,3691899,3691902,3691904,3691905`.

## Initial evidence

Commands:

```text
git branch --show-current
git rev-parse HEAD
git status --short
git worktree list --porcelain
git merge-base --is-ancestor 4669de8b5d9165e2176d8394931b821415ee100a HEAD
```

Result: clean source at exact base `4669de8...`; dedicated worktree and branch
created; final ancestry check returned exit code 0. The shared foundation
worktree contained unrelated changes and was not touched.

## RBAC and Grant V2 audit

The pre-change permanent profile mutation remains
`PATCH /api/v1/lte/profiles/:profile_id`, restricted to Administrator plus
CSRF. `require_operator` accepts an authenticated Operator or Administrator
and enforces CSRF.

Grant V2 already provided persistent 0600 storage, checksum validation,
subject/session binding, hashed nonce, expiration, revocation, one-time
consumption, idempotency and restart recovery. Its exact LTE envelope already
restricted the request to:

- profile `LTE-SRSUE-TEST-01`, revision 1, controller ownership;
- scenario `lte-e2e-certification-v1`, revision 1 and exact SHA-256;
- one UE and at most 300 seconds;
- exact actions S1 Setup, LTE Attach, bidirectional ping, bidirectional UDP and
  cleanup;
- ping at most 5 packets per direction;
- UDP at most 1,000,000 bit/s per direction, at most 30 seconds per direction,
  payload at most 1,200 bytes and one stream;
- certified configuration, Compose model and image subject.

The bootstrap cycle was that Grant creation required the profile to have been
permanently enabled by an Administrator. Certification Grant creation now
accepts the exact disabled controller-owned profile, while `LIVE_OPERATIONAL`
still requires permanent enablement and real LTE certification.

## Implementation

New endpoint:

```text
POST /api/v1/lte/profiles/LTE-SRSUE-TEST-01/certification-activation
```

It requires authenticated Operator RBAC, CSRF, a current Certification Grant
V2, the same authenticated session/role, the original nonce, a unique
idempotency key, exact profile/scenario ownership and the current certified
configuration/Compose/image subject. Other profiles, operational grants,
expired/replayed grants and changed subjects fail closed.

The temporary activation stores only `grant_id` and expiry in the private
profile registry. The raw nonce is never persisted or returned. It is cleared
on grant expiry, revocation, Stop, cleanup success/failure, administrator
disable and API restart. Cleanup remains grant-independent after expiry or
revocation. Certification run consumption additionally requires activation
bound to the same grant.

The UI implements three explicit stages:

1. `Préparer Grant V2 LTE` creates the exact bounded Certification Grant.
2. `Autoriser certification LTE` stays disabled until that valid grant and
   nonce exist in browser memory, then activates only the canonical profile.
3. `Start LTE certification run` stays disabled until the backend reports the
   matching active temporary authorization.

The execution nonce is never stored in local/session storage. The UI polls the
canonical profile, shows `AUTHORIZED`/`INACTIVE`, the remaining `MM:SS`, and
backend error codes. Existing UERANSIM/5G routes and views are unchanged.

## Manual test evidence

All frontend commands below used isolated Node `v22.23.0`.

```text
cargo check -p polaris-control-api
```

PASS; API compiled. Existing dead-code warnings only.

```text
cargo test -p polaris-control-api --lib
```

PASS: 241 passed, 0 failed, 3 ignored manual benchmarks. Coverage includes
RBAC, CSRF, nonce, session ownership, expiry, anti-replay, revocation,
restart/recovery, cleanup, certification/operational separation and existing
UERANSIM behavior.

```text
npx --yes --package node@22.23.0 node node_modules/vitest/vitest.mjs run
```

PASS: 38 files, 235 tests. Existing React `act(...)` warnings remain.

```text
npx --yes --package node@22.23.0 node node_modules/typescript/bin/tsc -b --pretty false
npx --yes --package node@22.23.0 node node_modules/vite/bin/vite.js build
```

PASS: TypeScript clean; Vite transformed 1,708 modules and produced the
production bundle. Existing dynamic/static import warning only.

```text
POLARIS_SIM_E2E_BASE_URL=http://127.0.0.1:4342/simulator/ \
npx --yes --package node@22.23.0 node node_modules/@playwright/test/cli.js \
  test e2e/lte-integration.spec.ts e2e/topology.spec.ts
```

PASS: 12/12. The mock-only tests validated the disabled-without-grant control,
temporary authorization, countdown, bounded start gate and LTE/5G topology at
1280, 1440 and 1920 pixels in light and dark themes. Every API mutation was
intercepted by Playwright; no laboratory action occurred.

```text
git diff --check
```

PASS.

`cargo fmt --all -- --check` remains non-zero because the inherited tree has
formatting drift across many unrelated Rust files. No mass reformat was
performed. `npm ci` reported 6 inherited dependency advisories (2 moderate,
2 high, 2 critical); dependency remediation is outside this focused change
and should be reviewed separately before a future production release.

## Resource evidence after tests

At `2026-11-01T00:14:23Z`:

```text
RAM total     20,970,582,016 bytes
RAM used      15,710,691,328 bytes
RAM available  5,259,890,688 bytes
Disk /root                 54%
dumpcap count              12
```

The requested thresholds were satisfied: available RAM >=4 GiB, used RAM
<=16 GiB, disk <85%.

## Remaining boundaries

- No REAL_PASS or production certification is claimed.
- Real expiry/cleanup against srsRAN still requires the separately authorized,
  bounded certification run and operational review.
- No production deployment was performed or prepared as part of this mission.

VERDICT = READY_FOR_REVIEW

— ANR2
