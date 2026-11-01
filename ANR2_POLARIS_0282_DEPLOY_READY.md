# ANR2 — POLARIS 0.28.2 Deploy Readiness

Date UTC: 2026-11-01

VERDICT = READY

SHA = source `d22b24ffc0b4fea792310084dbc7b5020aafbbff`; binary `c7b2687c6f2f374609c4b8455b0583f1a1211b810cab1d3018c7ff039bb2a2f3`.

BACKUP = PASS — `/root/release-gate-backups/20261101T134642Z-polaris-0282-prep/polaris-0281-current.tar`, SHA256 `fa09dcd14e1d94daa69b517f3d6f9e73025c9cf8177dcf4870c3326203beeed5`, root-only directory mode 0700 and archive mode 0600. It contains the active 0.28.1 API, `polaris-control.env`, systemd unit/drop-ins and `/var/lib/polaris-control`. Archive listing and extraction succeeded. The extracted rollback binary is exactly `3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.

ROLLBACK = READY — restore only the API binary unless configuration integrity also fails. Verify the extracted 0.28.1 hash, install it to a same-filesystem temporary path preserving root:root/0755, atomically rename it over `/root/POLARIS_CONTROL/target/release/polaris-control-api`, restart only `polaris-control.service`, then require `/api/v1/version=0.28.1`, `/health=ok`, running `/proc/<MainPID>/exe` hash `3294fc…d450`, unchanged dumpcap PIDs and conforming resources. Restore configuration/unit/state from the same archive only if those files were changed or fail integrity checks.

RESOURCE_GATES = PASS — RAM total 20,970,582,016 B; used 7,573,798,912 B; available 13,396,783,104 B. Disk 64%. Twelve dumpcap PIDs recorded: `1803146,1803148,1803159,1803167,1803196,1803202,1803241,1803293,1803305,1803312,1803318,1803320`.

BLOCKERS = None for deployment preparation. Deployment remains prohibited until a distinct authorization identifies 0.28.2 and this source/binary SHA.

## Verified state

- Production POLARIS: 0.28.1, health `ok`, running and on-disk hash `3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`.
- Production OIRAN: 2.7.3, running hash `bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`.
- Candidate: API 0.28.2, x86-64 GNU/Linux PIE, 21,255,432 bytes, build ID `33f2acac495102f6359d1a15f62405288d8db490`.
- Git lineage: `git merge-base --is-ancestor 8cb356a7… d22b24ff…` returned 0.
- The candidate diff changes no HTTP route or request/response structure. OIRAN 2.7.3 compatibility is unchanged.
- Certified test evidence was not rerun: targeted Docker-health tests 19/19 PASS; workspace regression 300 PASS, 0 FAIL, 3 manual tests ignored; UERANSIM 15/15 PASS.

## Prepared deployment sequence — not executed

1. Recheck candidate SHA256, production 0.28.1 hash, RAM/disk and the exact 12 dumpcap PID/start identities.
2. Verify `sha256sum -c` in the backup directory.
3. Install candidate to a temporary file beside the active binary, preserving owner/mode; verify `c7b268…a2f3`; atomically rename.
4. Restart only `polaris-control.service`.
5. Abort and rollback on any failed check below.

## Prepared read-only recipe

```text
GET /api/v1/version
  require HTTP 200, api=0.28.2

GET /api/v1/health
  require HTTP 200, status=ok, version=0.28.2

sha256sum /proc/<MainPID>/exe
  require c7b2687c6f2f374609c4b8455b0583f1a1211b810cab1d3018c7ff039bb2a2f3

GET /api/v1/auth/me
  anonymous viewer; can_start=false; no CSRF token

GET /api/v1/live/grant
  require 0 legacy grants and 0 LTE Grant V2 grants

GET /api/v1/lte/status
  require certified=false, grant_active=false, traffic_allowed=false;
  S1/Attach/session remain UNKNOWN without independent evidence

GET /api/v1/scenario-templates
  require exactly 13 templates

GET /api/v1/traffic/sessions
  require zero newly created sessions
```

Docker health absent/null is already certified offline by `docker_health_absent_null_starting_healthy_and_unhealthy_are_explicit`; `running_without_healthcheck_does_not_prove_s1_ready` proves the separate S1 gate. No live container should be created merely to repeat these tests in production.

Post-recipe gates: same 12 dumpcap PID/start identities, RAM available >=4 GiB, used <=16 GiB, disk <85%, OIRAN 2.7.3 health unchanged, zero grant and zero traffic. Any critical failure triggers immediate binary rollback.

No deployment, grant, simulator start or traffic action was performed during this preparation.

— ANR2
