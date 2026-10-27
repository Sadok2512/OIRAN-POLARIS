# Capture Readiness Report

Authenticated `ValidateCapture` was executed; `StartCapture` was not executed.

| Interface | Device | State | Protocol | Result |
|---|---|---|---|---|
| N2 | `br-oiran-n2` | UP | NGAP/SCTP | PASS |
| N3 | `br-oiran-n3` | UP | GTP-U/UDP | PASS |
| N4 | `br-oiran-n4` | UP | PFCP/UDP | PASS |

Validation result: `READY`, with no blockers. The filesystem was 45.38% used during API validation; the requested 256 MiB budget plus 32 MiB reserve was accepted below the 85% stop threshold. At final measurement `/dev/sda1` had 226,472,804,352 bytes available and inode use was 2%.

The capture directory is `oiran-capture:oiran-capture` mode `0770`. Validation created no capture file. Packet acquisition and decoding remain intentionally unverified until a separately authorized bounded live test.
