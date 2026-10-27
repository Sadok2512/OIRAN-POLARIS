# OIRAN P0 — Capture Lifecycle and Zero-Packet Diagnosis

## Authoritative evidence

Capture `live-1792957785082-0001` was created at `2026-10-25T19:49:45.083Z`, entered capture at `19:49:45.089Z`, and terminated at `19:49:46.091Z` after approximately 1.000 seconds. Its persisted stop reason was `CAPTURE_HELPER_EXITED`. No PCAP file exists and the job recorded zero packets and zero bytes.

The previous implementation discarded helper exit status and stderr, then processed the missing output as an empty dataset and incorrectly persisted `COMPLETED`. The exact historical exit code is therefore unavailable.

## Root cause

`tcpdump` uses the local `tcpdump` service account (UID 107/GID 108) after opening capture devices. The job PCAP directory was `root:root 0755`; a read-only permission check proves the `tcpdump` account could not write there. Filter compilation succeeds and N2/N3/N4 devices were present and UP. This establishes output-directory permissions as the helper failure cause with high confidence.

POLARIS Control recorded no generated traffic during the actual 19:49:45–19:49:46 capture window. Its next bounded five-packet UDP job ran at `19:51:00`, 75 seconds after capture start and 15 seconds beyond the requested 60-second window. Therefore no packet-generation evidence overlaps this job.

## Corrections

- The OIRAN API runs with primary group `tcpdump`; each exact job PCAP directory remains root-owned and is set to group `tcpdump` with mode `0770`. This gives the privilege-dropped helper access without adding `CAP_CHOWN` or opening access to other users.
- Helper interface, PID, exit code and bounded stderr are persisted.
- Premature helper exit or missing output is `FAILED`, never `COMPLETED`.
- A legitimate header-only capture becomes `COMPLETED` with `EMPTY_CAPTURE_COMPLETED`; its dataset state is `COMPLETED_EMPTY` and it has zero sessions.
- Registry recovery reclassifies the affected legacy job as `FAILED` and does not register its empty manifest as a live dataset.
- The selected-capture panel now follows the polling result by capture ID instead of retaining the stale Start response.
- Stop continues to target only the exact PID set stored in the controller-owned runtime.

No new capture or traffic was generated during diagnosis or validation.

## Deployment verification

- `oiran-api.service` is active with `Group=tcpdump`.
- Its capability set remains limited to `CAP_NET_RAW` and `CAP_NET_ADMIN`.
- The directory-permission regression test passes both normally and with effective group `tcpdump`.
- The health endpoint is operational on `127.0.0.1:49152`; the public gateway remains available on the existing port.

The subsequent job `live-1792960036447-0001` proved that directory preparation succeeded, then failed explicitly because tcpdump's automatic privilege drop required `setuid/setgid`, which the service sandbox correctly excludes. The helper command now uses `-Z root`: it retains the service's existing confined identity and only the bounded `CAP_NET_RAW`/`CAP_NET_ADMIN` capabilities. No `CAP_SETUID`, `CAP_SETGID`, or `CAP_CHOWN` capability was added.
