# OIRAN / POLARIS — Production Deployment Report

Date UTC: 2026-11-01

DEPLOYMENT = ROLLED_BACK

POLARIS_VERSION = 0.26.0 restored (candidate 0.28.1 was briefly served, then coordinated rollback)

POLARIS_RUNNING_SHA256 = `5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`

OIRAN_VERSION = 2.5.4 restored (candidate 2.7.3 failed startup)

OIRAN_RUNNING_SHA256 = `7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`

BACKUP = PASS — fresh root-only backup `/root/release-gate-backups/20261101T113300Z`; `sha256sum -c SHA256SUMS` returned OK for both archives. `polaris-current.tar` = `c5fc2129ece78c0999a9d389516ded164eed43c77932dbcd556bd631fc9c6dff`; `oiran-current.tar` = `73b9e390883693ecd33dc285058f30cafd8de7775868ef5f2ac167193e2071ec`.

GIT_LINEAGE = PASS — release HEAD `7e5e43b512c4066971d2761ee7265c92214f7cc0`; `git merge-base --is-ancestor` returned 0 for POLARIS `8cb356a7e4264b80fb82e2f1c90b9511f581df41` and OIRAN `724e6a0c93fdc09c28dfe9fb255ef64d8a5563bd` against the release commit.

API_HEALTH = PASS AFTER ROLLBACK — `polaris-control.service` active/running, PID 1559943, `/version` and `/health` HTTP 200 reporting 0.26.0/ok. `oiran-api.service` active/running, PID 1559473, `/version` and `/health` HTTP 200 reporting 2.5.4/healthy.

HTTP_INTEGRATION = BLOCKED FOR CANDIDATES — OIRAN 2.7.3 exited repeatedly before binding `127.0.0.1:49152`; therefore no valid candidate-to-candidate HTTP recipe was possible. Existing restored OIRAN sessions endpoint returned HTTP 200.

SECURITY = FAIL-CLOSED / NO LIVE ACTION — final POLARIS state: anonymous viewer, `can_start=false`, no CSRF token, 0 legacy grants, 0 Grant V2 grants, `LTE_E2E_CERTIFIED=false`, certification `CERTIFICATION_PENDING`, ownership false, traffic disallowed. Thirteen scenario templates remained readable. No grant, LTE UE, srsENB/srsUE or traffic was started.

PRIVACY = PASS FOR OBSERVED READS — no DEMO/mock/fixture marker was found in the read-only POLARIS UE, topology and traffic-session responses. The OIRAN sessions JSON privacy key scan returned 0 prohibited identity/secret keys. No environment or subscriber secret was printed.

DUMPCAP = PASS FOR PROCESS PRESERVATION — the same 12 PIDs remained present before and after deployment/rollback: `1483604,1483611,1483622,1483629,1483648,1483655,1483660,1483664,1483680,1483681,1483692,1483694`. No collector was signalled or restarted. Packet-loss-free continuity was not claimed.

RAM = PASS — final total 20,970,582,016 B; used 16,514,674,688 B; available 4,455,907,328 B (>= 4 GiB and used <= 16 GiB).

DISK = PASS — `/` 60% used (<85%).

ROLLBACK = PASS — OIRAN was restored from the verified archive immediately after the startup failure; its running process hash equals the pre-deployment hash and health is restored. ANR1 then restored POLARIS coordinately; its running process hash and 0.26.0 endpoints equal the pre-deployment state. No partial candidate release remains active.

BLOCKERS = OIRAN API 2.7.3 (`bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`) fails under the existing production systemd sandbox with `Read-only file system (os error 30)`. The required write path must be identified and mapped to an explicitly allowed writable state directory, then tested offline/staging without weakening unrelated production protections.

FINAL_VERDICT = ROLLED_BACK — production is healthy on POLARIS 0.26.0 / OIRAN 2.5.4; the requested coordinated release is not deployed.

## Commands and decisive evidence

```text
sha256sum candidate-binaries
  POLARIS candidate = 3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450
  OIRAN candidate   = bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845

systemctl restart oiran-api.service
journalctl -u oiran-api.service --since '2026-11-01 11:41:30'
  11:42:15..11:42:36: error=Read-only file system (os error 30)
  restart counter reached 4; health port unavailable

tar -xf oiran-current.tar .../oiran-api
sha256sum restored-binary
systemctl restart oiran-api.service
  rollback running hash = 7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657
  GET /api/v1/version = 2.5.4
  GET /api/v1/health  = healthy

sha256sum /proc/<polaris-pid>/exe /proc/<oiran-pid>/exe
  POLARIS final = 5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8
  OIRAN final   = 7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657
```

No UI, Analyzer, Live Probe, Open5GS, UERANSIM or capture component was deployed or modified.

— ANR2
