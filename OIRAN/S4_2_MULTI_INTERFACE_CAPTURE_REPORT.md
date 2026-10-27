# S4.2 multi-interface capture report

Existing POLARIS capture service is healthy and mounts its capture volume at `/captures`. The current compose file limits Docker JSON logs to 10 MiB × 3, but the existing capture scripts do not constitute an S4.2-certified 256 MiB × 8 scenario-owned rotation controller.

Required approved capture set:

| Interface | Protocol | Required evidence |
|---|---|---|
| N2 | NGAP/SCTP | five registration/PDU context sequences |
| N4 | PFCP/UDP 8805 | five establishment lifecycles and tunnel IEs |
| N3 | GTP-U/UDP 2152 | bounded UE-originated traffic for every session |
| SBI | HTTP/2 | optional only if already observable and authorized |

Files must be newly named by scenario/capture ID, never overwrite existing captures, and be finalized/checksummed within the disk guard budget. No capture was started in this mission.
