# OIRAN / POLARIS production deployment report

Date: 2026-11-01 UTC  
Release commit: `7e5e43b512c4066971d2761ee7265c92214f7cc0`

DEPLOYMENT = **FAILED AND ROLLED BACK**. ANR1 declared the pre-flight blocked,
but concurrent actors replaced and restarted both APIs at 11:42 UTC. OIRAN
2.7.3 immediately entered an auto-restart loop with `Read-only file system (os
error 30)`, confirming the gate. Both components were restored. Final
production is POLARIS 0.26.0 and OIRAN 2.5.4.

POLARIS_VERSION = Final running `0.26.0`. Candidate `0.28.1` was briefly
installed and served `/version` and `/health`, then was rolled back because
the coordinated release failed at OIRAN.

POLARIS_RUNNING_SHA256 =
`5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`
for the final active executable
`/root/POLARIS_CONTROL/target/release/polaris-control-api`. Candidate verified
and briefly executed:
`3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.

OIRAN_VERSION = Final running `2.5.4`. Candidate `2.7.3` was installed but
never reached a listening/healthy state; systemd logged repeated read-only
filesystem failures before rollback.

OIRAN_RUNNING_SHA256 =
`7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`
for `/opt/oiran/bin/oiran-api`. Candidate verified before the stop decision:
`bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`.

BACKUP = POLARIS PASS: root-only backup
`/root/POLARIS_CONTROL/backups/0.28.1-20261101T114052Z`; its previous binary
hash is the restored `5d042aa4...7fc8`, and it includes configuration, unit,
drop-ins and state. OIRAN pre-deployment backup was not created by the
concurrent deployer. During emergency rollback, the failed candidate plus
current unit/drop-ins/config were preserved root-only at
`/var/lib/oiran/deployment-backups/oiran-2.7.3-failed-20261101T114215Z`.
The exact previous 2.5.4 artifact was recovered from the certified deployment
worktree and matched the pre-flight running hash before installation.

GIT_LINEAGE = PASS. Both
`8cb356a7e4264b80fb82e2f1c90b9511f581df41` and
`724e6a0c93fdc09c28dfe9fb255ef64d8a5563bd` are ancestors of release commit
`7e5e43b512c4066971d2761ee7265c92214f7cc0` (`git merge-base --is-ancestor`
exit 0 for each). Candidate artifact hashes match the authorization exactly.

API_HEALTH = Final production: POLARIS service active/running on
`127.0.0.1:49153`; OIRAN service active/running on `127.0.0.1:49152`.
OIRAN `/api/v1/version` returned 2.5.4 and `/api/v1/health` returned HTTP 200,
`status=healthy`, 54 source events and one session. OIRAN candidate health
FAIL: no listener and repeated exit status 1. Final 2.5.4 health returned HTTP
200 after rollback.

HTTP_INTEGRATION = FAIL / NOT REACHED. OIRAN 2.7.3 could not start, so the
production POLARIS→OIRAN candidate recipe was impossible. The offline
certification remains PASS but is not substituted for production proof.

SECURITY = PASS for rollback containment. No grant was created, no RBAC/CSRF
control was bypassed, and no srsENB, srsUE, UE or traffic was started. The
candidate production security recipe was not completed and remains pending.

PRIVACY = No production dataset was injected or modified. No raw subscriber
identity was read or emitted during pre-flight. Candidate privacy verification
remains pending deployment.

DUMPCAP = PASS / PRESERVED. Twelve processes remained active. PID/start/command
snapshot SHA-256:
`b9925f6c0bc1963f951bc684a9005d39fceb974a3d23f26614ae45e2f3ee8a00`.

RAM = PASS: pre-flight available samples 4,816,916,480 to 4,840,484,864
bytes; final available 4,447,363,072 bytes and used 16,523,218,944 bytes,
still below the binary 16-GiB used limit.

DISK = PASS: root filesystem 60% used, below the 85% stop threshold.

ROLLBACK = PASS. POLARIS was restored twice because a second concurrent
candidate install occurred during the first coordinated rollback. Final file
and `/proc/<pid>/exe` both equal `5d042aa4...7fc8`; `/version` is 0.26.0 and
`/health` is `ok`. OIRAN failed candidate `bbb7ca64...0845` was preserved,
then `/opt/oiran/bin/oiran-api` was restored to `7a9c5711...657`; final
`/proc/<pid>/exe`, `/version` 2.5.4 and `/health` all passed. Only the two API
services were restarted. Live Probe, Analyzer, Open5GS and capture services
were not restarted.

BLOCKERS = OIRAN 2.7.3 initializes `runtime/lte-evidence` and
`runtime/lte-evidence-inbox`. Both paths are absent in `/root/OIRAN_VPROBE`.
The active unit has `ProtectHome=read-only`, `ProtectSystem=strict` and
`ReadOnlyPaths=/root/OIRAN_VPROBE`; its only relevant writable paths are
`/var/lib/oiran/captures` and `/var/lib/oiran/registry`. It defines neither
`OIRAN_LTE_EVIDENCE_ROOT` nor `OIRAN_LTE_EVIDENCE_BUNDLE_ROOT`. Consequently,
replacing only the binary would either fail startup while creating the roots or
leave LTE ingestion unwritable. Fixing this needs an explicitly authorized API
configuration change: create dedicated roots (recommended under
`/var/lib/oiran`), add them to `ReadWritePaths`, and set the two OIRAN
environment variables. ANR1 therefore did not release ANR2/ANR3 to deploy.

FINAL_VERDICT = **BLOCKED / ROLLED_BACK**. No false PASS and no partial
candidate production upgrade remains active.

## Commands and evidence

```text
git show -s 7e5e43b512c4066971d2761ee7265c92214f7cc0
git merge-base --is-ancestor <source_sha> 7e5e43b...  # exit 0 twice
sha256sum <both candidate binaries>                   # exact authorized hashes
systemctl show/cat oiran-api.service polaris-control.service
sha256sum /proc/<main_pid>/exe
curl -fsS http://127.0.0.1:49152/api/v1/version
curl -fsS http://127.0.0.1:49152/api/v1/health
free -b; df -P /root
ps -C dumpcap -o pid=,lstart=,args= | sort | sha256sum
```

Required next authorization: permit the minimal OIRAN API persistence drop-in
and two empty dedicated data roots, with backup/hash/rollback, before retrying
the coordinated binary deployment.

— ANR1 / ANR2 / ANR3
