# POLARIS API 0.12.1 + Simulator front 0.3.1 deployment plan

This is a plan only. It does not authorize deployment or Live execution.

## Preconditions

1. Check that the candidate commit is clean and record `git rev-parse HEAD`.
2. Run the complete manual Rust, HTTP, frontend typecheck/test/build, and browser fixture suites.
3. Build the API and attestation CLI from the candidate commit; build
   `apps/simulator-control` 0.3.1 from its lockfile. Record `sha256sum` for every candidate.
4. Confirm `df -P /root` is below 90%, sufficient backup space exists, CPU/RAM gates are ready,
   and there is no active controller-owned UE/scenario/traffic job.
5. Confirm the current four UE/runtime observations and gNB/Open5GS health read-only. Do not alter
   them.

## Backup and atomic transition

1. Create a timestamped root-only backup directory on the same filesystem.
2. Copy the running POLARIS binary, Simulator static directory, systemd unit/drop-ins, environment,
   users reference, UE/profile/job registries, scenario catalog, provisioning attestation, and
   release manifest. Record `sha256sum` plus file owner/mode.
3. Verify backup readability before changing artifacts.
4. Install versioned candidate artifacts beside the running release. Atomically switch only the
   POLARIS API binary and Simulator static-directory symlink.
5. Keep `POLARIS_DEFINITION_LIVE_ENABLED` absent/false. Restart only
   `polaris-control.service`; do not restart Open5GS, gNB, UEs, OIRAN, ETV, or OTV.

## Verification and rollback

1. Verify `/proc/$PID/exe`, running binary SHA256, `/health`, `/version`, Operator auth, profile and
   scenario read APIs, Simulator asset hashes, Viewer behavior, and browser fixture suite through
   the existing `:8020/simulator/` and `:8020/polaris-api/v1/` paths.
2. Confirm API 0.12.1 still returns HTTP 423 for definition Live start while the flag is disabled.
3. Confirm UE/gNB observations and persistent registries are unchanged.
4. On any critical failure, restore only the versioned API/static symlinks and reviewed unit/env,
   restart only `polaris-control.service`, and re-run the read-only checks. Never roll back a newer
   persistent registry over recent records.

## Candidate artifacts (2026-10-28 UTC)

These hashes were measured after the full manual test and release-build sequence. They must be
recalculated after any source change.

| Artifact | SHA256 |
|---|---|
| `target/release/polaris-control-api` | `01f98de4cd9163bd457688f568743e5b3ec5a87ec4a0aa8cbd5004a0af5da4a1` |
| `target/release/polaris-provisioning-attest` | `922ff3d88e5f60528babc5f2f30c8b7988782e8d5e810199d2489b15da3895fd` |
| Simulator `dist/index.html` | `4c8e67cfbf35166dc77b1a4c1d90b6c898f82867ce0333f2e795089da961cdae` |
| Simulator JavaScript | `849778f5516bf92a6201b8efa6eceeafae9c305f63223f04b449520c635a52fe` |
| Simulator CSS | `cac08d5a606ce31f6802d9978d5b5131f93fc9919677e9e4df83694b82e0bfe5` |

## Manual validation evidence

- `cargo test --workspace`: 123 passed, 0 failed.
- Simulator unit suite: 100 passed; typecheck and production build passed.
- Probe Manager unit suite: 66 passed; typecheck and production build passed.
- Portal unit suite: 11 passed; typecheck and production build passed.
- POLARIS Playwright fixture suite: 20/20 passed in each of three consecutive runs.
- `npm audit --omit=dev` is clean for Portal. Simulator and Probe Manager each report two
  moderate React Router advisories even at the explicitly required `react-router-dom` 6.30.6;
  npm's available remediation is the breaking major upgrade to 7.18.5. Deployment remains blocked
  pending an explicit risk decision or a separately reviewed React Router 7 migration.
