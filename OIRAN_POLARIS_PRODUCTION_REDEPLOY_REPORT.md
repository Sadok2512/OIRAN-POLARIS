# OIRAN / POLARIS production redeployment

Date: 2026-11-01 UTC  
Authorized sources: POLARIS `8cb356a7e4264b80fb82e2f1c90b9511f581df41`;
OIRAN `724e6a0c93fdc09c28dfe9fb255ef64d8a5563bd`.

DEPLOYMENT = **PASS**. Final controlled sequence: OIRAN restarted at 12:30:04
UTC, then POLARIS at 12:30:08 UTC. Earlier concurrent candidate transitions
and a clean coordinated rollback were observed and are not hidden; the final
bascules below were executed directly after all delegated agents had stopped
writing.

POLARIS_VERSION = `0.28.1`

POLARIS_RUNNING_SHA256 =
`3294fc65dbb7b5b28a734dc0d92e621c99fd0d9501b3e837ed7fdc05d8d7d450`
for both the installed file and `/proc/<pid>/exe`.

OIRAN_VERSION = `2.7.3`

OIRAN_RUNNING_SHA256 =
`bbb7ca640794d17654540c4b80f23c17cd5afb0cacb401337e96fae4e23c0845`
for both the installed file and `/proc/<pid>/exe`.

SYSTEMD_FIX = PASS. Drop-in SHA-256
`583b1ade17d264333bbb8c367c525af62c89ffc8215d13af127672f21aea2c6c`.
`/var/lib/oiran/lte-evidence` and
`/var/lib/oiran/lte-evidence-inbox` remain `root:root` mode `0700`.
`ProtectSystem=strict`, `ProtectHome=read-only` and
`ReadOnlyPaths=/root/OIRAN_VPROBE` remain effective. No read-only,
permission-denied or startup error appears after the final OIRAN restart.

BACKUP = PASS with provenance caveat documented. POLARIS rollback baseline:
`/root/POLARIS_CONTROL/backups/0.28.1-20261101T114052Z`, previous binary SHA
`5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8`.
OIRAN configuration/unit/drop-in backup:
`/var/lib/oiran/deployment-backups/oiran-2.7.3-redeploy-20261101T122716Z`;
it includes the exact rollback artifact `oiran-api.rollback-2.5.4`, SHA
`7a9c5711ed1827dc9ed8fef1c34ff63816a86deccc70fadf4219643153cfd657`.
Concurrent actors prepositioned candidates before the fresh copy commands, so
the report distinguishes staged candidates from the independently verified
prestate rollback artifacts.

API_HEALTH = PASS. Production `/version` and `/health` returned HTTP 200 for
both APIs. POLARIS reported 0.28.1 and `status=ok`; OIRAN reported 2.7.3 and
`status=healthy`. POLARIS `/lab`, `/nodes`, `/ues`, `/scenario-templates`,
`/lte/status`, `/auth/me`, `/live/grant` and `/traffic/status` all returned
200. OIRAN datasets, sessions, packets and correlation-edge reads all returned
200.

HTTP_INTEGRATION = PASS on an isolated loopback workspace using the exact
production binaries and the previously certified anonymized POLARIS envelope:
anonymous import 403, Operator without CSRF 403, first import 201, exact replay
200 idempotent, conflict 409, invalid cursor 422 and limit 257 rejected 422.
Three of three events were associated into one session, with two correlation
edges and `S1_MME_S11=STRONG`, `S11_S1_U=EXACT`, `E2E=STRONG`. JSON and HTML
Call Flow exports returned 200. No fixture was imported into the production
LTE roots. Evidence is under `/tmp/anr3-prod-redeploy-http.DMPUEV`; aggregate
proof SHA-256 `c9ca9c17004f95ff45c4c6521d57e1c0f11a8c3cced0ea10cbccb3e7a210d2ad`.

SECURITY = PASS. Production contains 0 live grants; anonymous grant creation
and scenario start returned 403. LTE status is fail-closed:
`grant_active=false`, `traffic_allowed=false`, `traffic_ready=false`,
`certified=false`, with S1/Attach unknown. OIRAN production rejected a valid
anonymous evidence envelope with 403. No grant, UE, srsENB, srsUE or traffic
was started. CSRF and idempotence were additionally exercised in the isolated
HTTP recipe.

PRIVACY = PASS. Raw production read responses and isolated JSON/HTML exports
contained zero forbidden subscriber/equipment/key labels, zero clear IMSI
outside opaque pseudonym fields, and zero DEMO/mock/fake markers. POLARIS
reported `subscriber_identity_exposed=false`.

DUMPCAP = PASS. Count remained 12 and complete PID/start/command snapshots
were byte-identical across the final window. Baseline/final SHA-256:
`6c297e6f70dc5565fcc99abb1f723c1537e9144ecfd2186bf10c567627ccb608`.
The capture helper retained PID 4028363 and its 2026-10-27 start time.

RAM = PASS. Final sample: 4,497,162,240 bytes available and 16,473,419,776
bytes used, below the binary 16-GiB used limit.

DISK = PASS. Root filesystem remained 60% used.

ROLLBACK = READY and hash-verified for both components. The earlier rollback
exercise restored both prior binaries successfully. Final recipe did not
trigger rollback because all critical checks passed.

BLOCKERS = None for this API redeployment. No real LTE E2E certification is
claimed: production has no active LTE run and therefore no `capture_refs`;
none was fabricated. Open5GS PIDs/start times and the existing UERANSIM gNB
were unchanged; no UERANSIM UE was started. UI, Analyzer, Live Probe and
collectors were not deployed or restarted.

FINAL_VERDICT = **PASS** for the two authorized API deployments and HTTP
offline integration recipe. This is not `REAL_PASS LTE`.

— ANR1 / ANR2 / ANR3
