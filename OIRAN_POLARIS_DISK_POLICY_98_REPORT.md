# OIRAN / POLARIS disk policy 98% — ANR3

Date: 2026-11-02 UTC  
Branch: `fix/anr3-disk-policy-98-p0`  
Base: `6734c75891832cce83edbfd3e5e622a8289835e6`

OLD_GATES = POLARIS `safety-guard` and two API start paths used 75/80/85/90 and a hard-coded 85% refusal; OIRAN `disk-safety`, API policy output, Live Probe tests, S4.2 manifest and UI/docs used 75/80/85/90. No active systemd threshold override was found.

NEW_MAX = 98%

FREE_BYTES_RESERVE = 8 GiB (`8,589,934,592` bytes). Every producing operation must fit its complete projected write budget below the 98% ceiling after retaining this reserve. The existing per-job maximum remains 2 GiB.

CONFIG_CHANGED = Source candidate only: POLARIS API `0.29.1`, `safety-guard 0.2.0`, web `3.2.3`; OIRAN API `2.7.5`, `disk-safety 0.2.0`. Information is 95%, warning 97%, hard ceiling 98%. The POLARIS LTE and generic scenario gates now publish estimated bytes, admitted budget and reserve. Production services/configuration were not changed or restarted.

TESTS =

- `cargo test -p safety-guard`: PASS, 6/6.
- `cargo test -p disk-safety`: PASS, 8/8.
- `cargo test -p oiran-api disk_safety_is_measured_and_capture_remains_unconfigured`: PASS, 1/1.
- `cargo test -p polaris-control-api stop_is_exempt_from_resource_gate_while_start_is_blocked`: PASS, 1/1; Stop remains available.
- `npm run typecheck`: PASS with bundled Node 22.23.4.
- `npm run build`: PASS; Vite production build completed.
- `npm test -- --run`: PASS, 5/5.
- Boundary coverage: 80/85/90 accepted when projected budget and reserve fit; 95 information; 97 warning; 98 hard refusal; reserve exhaustion, inode exhaustion and measurement/ENOSPC failure refuse writes; active OIRAN writes finalize on unsafe growth.
- `cargo fmt --all -- --check`: FAIL on pre-existing workspace-wide formatting debt outside this change; `git diff --check`: PASS.

DUMPCAP = 12 processes observed before and after; no process was signalled, restarted or reconfigured by this task.

DISK = Final pre-cleanup measurement `/dev/sda1`: total `414,921,494,528`, used `316,523,130,880`, available `98,381,586,432` bytes, `df` 77%; inode use 5%. The 98% value is a ceiling, not a target.

ROLLBACK = Revert this isolated branch commit. Production rollback is not applicable because no service/configuration was changed.

VERDICT = PASS for the tested source candidate; production remains on the prior compiled policy until an explicit deployment authorization names the final SHAs/binaries.

— ANR3
