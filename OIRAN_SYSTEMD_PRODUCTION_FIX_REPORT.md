# OIRAN 2.7.3 systemd production preparation

Date: 2026-11-01 UTC  
Scope: systemd configuration and two empty persistent directories only. No
application binary deployment was performed.

SYSTEMD_FIX = **PASS**. `systemd-analyze verify
/etc/systemd/system/oiran-api.service` exited 0. The effective unit contains
the two requested environment variables and only the two new LTE paths on the
new `ReadWritePaths` directive. OIRAN API 2.5.4 remains healthy. The ANR3
controlled restart occurred at 11:46:56 UTC; a second concurrent clean restart
was observed at 11:47:37 UTC and is reported rather than hidden.

PATHS =

- `OIRAN_LTE_EVIDENCE_ROOT=/var/lib/oiran/lte-evidence`
- `OIRAN_LTE_EVIDENCE_BUNDLE_ROOT=/var/lib/oiran/lte-evidence-inbox`

Both directories were empty after the write/confinement test. No historical
dataset was copied, removed or modified.

PERMISSIONS = Service identity `root:root`, supplementary group
`oiran-capture`. Both new directories are `root:root` mode `0700`. Drop-in
`/etc/systemd/system/oiran-api.service.d/lte-evidence.conf` is `root:root`
mode `0644`, SHA-256
`583b1ade17d264333bbb8c367c525af62c89ffc8215d13af127672f21aea2c6c`.

READWRITEPATHS = The drop-in adds exactly:

```text
ReadWritePaths=/var/lib/oiran/lte-evidence /var/lib/oiran/lte-evidence-inbox
```

The effective list also retains the two pre-existing production paths
`/var/lib/oiran/captures` and `/var/lib/oiran/registry`; neither was added or
broadened by this fix. `/root/OIRAN_VPROBE` remains explicitly read-only and
`ProtectHome=read-only`, `ProtectSystem=strict` remain active.

BACKUP = PASS. Root-only backup:
`/var/lib/oiran/deployment-backups/oiran-systemd-lte-evidence-20261101T114626Z`.
It contains the pre-change main unit, every prior drop-in, and `/etc/oiran`
configuration with original file modes. The backup root, `systemd` directory
and parent access boundary are mode `0700`; configuration contents are not
included in this report.

SERVICE_HEALTH = PASS. Final executable remains OIRAN API 2.5.4 with file and
`/proc/<pid>/exe` SHA-256
`7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`.
`/api/v1/version` returned 2.5.4 and `/api/v1/health` returned HTTP 200,
`status=healthy`, 54 source events and one session. Both restart sequences in
the journal are clean and contain the listening message, with zero `Read-only
file system`, `permission denied` or `error=` entries.

SANDBOX = PASS. A transient oneshot with the service identity and equivalent
`ProtectSystem`, `ProtectHome`, `ReadOnlyPaths` and `ReadWritePaths` wrote one
temporary file in each authorized directory. Writes to
`/root/OIRAN_VPROBE/runtime` and `/etc` both failed with `Read-only file
system`. The two authorized test files were then unlinked. No global chmod and
no writable `/root` path were introduced. ANR1 additionally inspected the
service mount namespace: `/root/OIRAN_VPROBE`, the `/var/lib/oiran` parent,
`/etc` and `/opt/oiran/bin` were not writable; only the two requested LTE
roots were writable among the tested new targets.

RAM = PASS. Pre-flight available RAM was 4,943,650,816 bytes and used RAM
16,026,931,200 bytes. ANR1 final sample: 4,948,668,416 bytes available and
16,021,913,600 bytes used, below 16 GiB used.

DISK = PASS. Root filesystem remained 60% used.

DUMPCAP = PASS. Count remained 12 and the complete PID/start/command snapshots
were byte-identical before and after. SHA-256:
`b9925f6c0bc1963f951bc684a9005d39fceb974a3d23f26614ae45e2f3ee8a00`.
`oiran-capture-helper.service` retained PID 4028363 and start time
2026-10-27 09:34:36 UTC.

ROLLBACK = READY / NOT EXECUTED because the fix passed. Exact rollback is:
restore the saved unit/drop-in directory, remove only the new drop-in, remove
the two new directories only if still empty, run `systemctl daemon-reload`,
restart only `oiran-api.service`, and verify the 2.5.4 hash/health and dumpcap
snapshot. No binary rollback is involved.

BLOCKERS = None for the systemd preparation itself. Deployment of OIRAN 2.7.3
and POLARIS 0.28.1 remains explicitly outside this authorization and has not
been completed. The future application deployment still requires its own
authorization and full backup/recette/rollback gates.

Additional non-regression evidence: POLARIS remained API 0.26.0 with SHA
`5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`;
Open5GS process start times were unchanged; no srsENB, srsUE, grant or traffic
was started.

— ANR3 / ANR1
