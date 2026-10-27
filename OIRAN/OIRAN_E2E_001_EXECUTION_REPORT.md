# OIRAN-E2E-001 Execution Report

Execution state: **NOT EXECUTED**.

## Exact proposed execution plan

Prerequisites requiring separate authorization and validation:

1. Add a narrowly scoped POLARIS Control traffic target field restricted to controller-owned, registered UE jobs; retain the fixed destination `10.46.0.1:49001`, five datagrams and no arbitrary namespace selection.
2. Test Viewer denial, Operator/CSRF enforcement, exact UE ownership, UE-04 namespace selection and preservation of UE-01/02/03.
3. Deploy only the reviewed POLARIS Control change, then configure the count from 3 to 4 without starting a process.
4. Re-run provisioning attestation, CPU/RAM/disk checks and require OTV/ETV contention to be acceptable.

After a second explicit live approval:

1. Recheck all safety gates and confirm zero active OIRAN capture jobs.
2. Validate one OIRAN capture request for `N2,SBI,N4,N3`, group `OIRAN-E2E-001`, duration 180 seconds, total requested bytes 268,435,456 and four rotated files.
3. Start that exact capture and require authoritative `CAPTURING` with all four writers initialized within 10 seconds.
4. Start only controller-owned `UE-04` through `POST /api/v1/ues/start`; wait at most 60 seconds for REGISTERED and a further 30 seconds for PDU ACTIVE.
5. Send exactly five UDP datagrams from the verified UE-04 namespace to `10.46.0.1:49001`, maximum 64-byte application payload, at no more than one datagram/second.
6. Gracefully stop capture group `OIRAN-E2E-001`; preserve every per-plane result even if another plane fails.
7. Explicitly stop only UE-04 through its exact controller-owned job. UE-01/02/03, the shared gNB and Open5GS remain untouched.
8. Decode, compare with TShark and reconstruct/correlate offline.

Expected live window: 3 minutes maximum capture time, approximately 5 minutes including UE startup and graceful stop. Offline validation may take an additional 5–10 minutes.

## Abort and rollback

- Abort before capture if disk reaches 85%, memory/CPU pressure is unsafe, OTV/ETV is degraded, an active capture exists, or any interface is unavailable.
- On failure, stop only the exact UE-04 traffic job, exact capture ID and exact UE-04 controller job, in that order.
- Preserve finalized PCAPs and manifests. Do not retry automatically.
- Restore configured count to 3 only after UE-04 is confirmed stopped and only if included in the approval.
- Never restart Open5GS, the shared gNB, shared UE or ETV/OTV.

