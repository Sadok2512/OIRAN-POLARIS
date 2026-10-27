# S3.2.2 N3 capture report

The active N3 PCAPNG grew from 292 to 1,912 bytes and contains ten valid G-PDUs. All five transmitted requests and all five received responses are present, so no functional loss was observed. Snapshot SHA-256: `806a4ae1eb758a1b2c08ae10d7b7f54881c5e571c7f80ed047f564cb222cb35a`.

| Direction | Frames | Outer endpoints | TEID | GTP length | Inner traffic |
|---|---|---|---|---:|---|
| uplink | 1–5 | `10.77.22.20 → 10.77.22.13` | `0x000096a8` | 66 | UE UDP request |
| downlink | 6–10 | `10.77.22.13 → 10.77.22.20` | `0x00000003` | 94 | UPF gateway ICMP response |

All packets use outer UDP/2152 and timestamps from `22:22:43.765541804Z` through `22:22:43.771427572Z`. Native Rust decoded 10/10 without malformed length, missing provenance or unsupported GTP-U header.
