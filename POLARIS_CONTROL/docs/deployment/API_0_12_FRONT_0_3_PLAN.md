# POLARIS API 0.12.0 + Simulator front 0.3.0 deployment plan

This is a plan only. It does not authorize deployment or Live execution.

## Preconditions

1. Check that the candidate commit is clean and record `git rev-parse HEAD`.
2. Run the complete manual Rust, HTTP, frontend typecheck/test/build, and browser fixture suites.
3. Build the API and attestation CLI from the candidate commit; build
   `apps/simulator-control` 0.3.0 from its lockfile. Record `sha256sum` for every candidate.
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
2. Confirm API 0.12.0 still returns HTTP 423 for definition Live start while the flag is disabled.
3. Confirm UE/gNB observations and persistent registries are unchanged.
4. On any critical failure, restore only the versioned API/static symlinks and reviewed unit/env,
   restart only `polaris-control.service`, and re-run the read-only checks. Never roll back a newer
   persistent registry over recent records.
