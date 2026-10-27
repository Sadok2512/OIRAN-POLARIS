# S3.2.2 correlation evidence

| Relationship | Source → destination | Shared/bridged evidence | Classification |
|---|---|---|---|
| N2 session | N2 frame 3 → 17 | RAN/AMF UE NGAP ID 4; PDU Session ID 1 | EXACT |
| N4 session | N4 frame 7 → 10 | PFCP sequence 93/94; F-SEID `0x1a8`/`0x35e` | EXACT |
| N3 tunnel | N3 frames 1–10 | directional TEID plus both tunnel endpoints | EXACT |
| N2 ↔ N4 uplink | N2 frame 15 ↔ N4 frame 8 | `0x96a8` at UPF `10.77.22.13` | STRONG |
| N2 ↔ N4 downlink | N2 frame 17 ↔ N4 frame 9 | `0x3` at gNB `10.77.22.20` | STRONG |
| N4 ↔ N3 uplink | N4 frame 8 ↔ N3 frames 1–5 | same `0x96a8`, gNB→UPF endpoints | EXACT |
| N4 ↔ N3 downlink | N4 frame 9 ↔ N3 frames 6–10 | same `0x3`, UPF→gNB endpoints | EXACT |
| Complete E2E | N2 15/17 ↔ N4 8/9 ↔ N3 1–10 | paired tunnel IDs/endpoints plus continuous session owner lifetimes | STRONG |

No relationship is based on timestamp proximity alone.
