# OIRAN Capture Readiness Report

Only `ValidateCapture` was executed. No StartCapture request was issued.

Authenticated API validation returned `READY`, `valid=true`, and no blockers for the bounded POLARIS 5G SA profile.

| Interface | Device | Protocol | State |
|---|---|---|---|
| N2 | `br-oiran-n2` | NGAP / SCTP, port 38412 | UP / validated |
| N3 | `br-oiran-n3` | GTP-U / UDP, port 2152 | UP / validated |
| N4 | `br-oiran-n4` | PFCP / UDP, port 8805 | UP / validated |

The helper IPC authorization succeeded. The requested 256 MiB budget plus 32 MiB reserve was accepted. Filesystem utilization was 47.22% during validation, below the 85% stop threshold. Rotation remains bounded to three files for this validation profile.

An initial deliberately bounded validation using an incorrect probe identifier was rejected with `PROBE_NOT_ALLOWLISTED`; using the discovered `oiran-vprobe-local-01` identifier then passed. This confirms fail-closed probe allowlisting.

