# OIRAN / POLARIS production redeploy P0

Date: 2026-11-01 UTC

DEPLOYMENT = **PASS** — POLARIS API 0.28.1 and OIRAN API 2.7.3 are the
active production processes. No UI, Analyzer, Live Probe, Open5GS, UERANSIM or
capture component was deployed or modified.

POLARIS_VERSION = `0.28.1`.

POLARIS_RUNNING_SHA256 =
`3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`
for both `/proc/1686063/exe` and the installed binary.

OIRAN_VERSION = `2.7.3`.

OIRAN_RUNNING_SHA256 =
`bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`
for both `/proc/1685704/exe` and the installed binary.

SYSTEMD_FIX = **PASS** — drop-in SHA-256
`583b1ade17d264333bbb8c367c525af62c89ffc8215d13af127672f21aea2c6c`.
`ProtectSystem=strict` and `ProtectHome=read-only` remain active. The two LTE
roots are `0700 root:root`; the inbox is empty and the evidence root contains
only empty `datasets` and `exports` metadata directories created at startup.
No read-only filesystem, fatal, OOM or service-failure journal entry occurred
after the final start.

BACKUP = **PASS** — fresh root-only backup
`/root/release-gate-backups/20261101T122726Z`. `sha256sum -c SHA256SUMS`
returns OK for `polaris-current.tar` and `oiran-current.tar`. Independent
component backups and the previous binary hashes remain available for rollback.

API_HEALTH = **PASS** — both `/api/v1/version` and `/api/v1/health` return
HTTP 200. POLARIS reports 0.28.1/ok; OIRAN reports 2.7.3/healthy.

HTTP_INTEGRATION = **PASS** — the exact offline three-plane contract recipe
remains PASS with 3/3 events and E2E STRONG. Production read-only compatibility
also passes: ten real historical sessions and ten datasets are readable;
Call Flow pagination returned two of thirteen events with a cursor and the next
page returned two more. No synthetic envelope was injected into a production
dataset.

SECURITY = **PASS / fail-closed** — anonymous POLARIS identity is Viewer with
`can_start=false`; live Grant list is empty. Unauthorized/no-CSRF/malformed
Grant paths fail closed. Direct and outer synthetic OIRAN imports are rejected
HTTP 403 before mutation. The authenticated OIRAN CSRF branch was not rerun in
production because no plaintext token was sought; it remains covered by the
exact candidate offline suite. No grant, UE, simulator or traffic was started.

PRIVACY = **PASS** — actionable JSON leak scan count is zero, HTML-visible
identity terms are zero, and no DEMO/mock/fixture marker appears as operational
POLARIS data. No subscriber secret was printed or persisted by this recipe.

DUMPCAP = **PASS for preservation** — all twelve reference PIDs remained
unchanged during this deployment window:
`1642009,1642019,1642027,1642029,1642032,1642052,1642063,1642080,1642096,1642097,1642110,1642112`.
They rotated externally before the window; packet-loss-free continuity across
that earlier rotation is not claimed.

RAM = **PASS** — final used memory `16,071,532,544` bytes and available memory
`4,899,049,472` bytes. Six consecutive health samples remained above the 4 GiB
availability threshold. OIRAN's cgroup is close to its 256 MiB `MemoryMax`
because of charged cache (`memory.events max=24529`), but `oom=0`, `oom_kill=0`,
PID and HTTP health stayed stable. This is a capacity warning, not a failed gate.

DISK = **PASS** — root filesystem is 60% used.

ROLLBACK = **READY** — previous POLARIS 0.26.0 and OIRAN 2.5.4 artifacts,
configuration and units are hash-verified. Rollback remains component-scoped;
the validated systemd LTE-path fix is retained unless separately reverted.

BLOCKERS = None for the completed authorized redeployment. Operational warning:
monitor OIRAN cgroup memory headroom; dumpcap rotation continuity remains
uncertified. LTE REAL_PASS is not claimed.

No live operation was performed.

— ANR1 / ANR2 / ANR3
