# S3.3 correlation evidence report

## Certified result

| Relationship | Classification | Edges | Rule |
|---|---|---:|---|
| N2 ↔ N4 | STRONG | 2 | `n2-n4-certified-tunnel-bridge` 1.0.0 |
| N4 ↔ N3 | EXACT | 10 | `n4-n3-teid-endpoint` 1.0.0 |
| E2E | STRONG | derived | weakest independently required bridge |

Every edge stores both event IDs, interfaces, rule/version, matching identifiers, description and source/target packet references.

### N2 ↔ N4

- N2 PDU Session Resource Setup Request ↔ PFCP Session Establishment Response: PDU Session ID 1 and certified uplink TEID `0x000096a8` at UPF `10.77.22.13`.
- N2 PDU Session Resource Setup Response ↔ PFCP Session Modification Request: PDU Session ID 1 and certified downlink TEID `0x00000003` at gNB `10.77.22.20`.

Classification stays STRONG because the native NGAP nested transfer is PARTIAL. The bridge explicitly cites the certified scenario/TShark evidence; it is not promoted to EXACT.

### N4 ↔ N3

Five uplink G-PDUs match PFCP TEID `0x000096a8` plus UPF endpoint `10.77.22.13`. Five downlink G-PDUs match PFCP TEID `0x00000003` plus gNB endpoint `10.77.22.20`. Those ten direct header/endpoint matches are EXACT.

The engine refuses ambiguous PFCP candidates and produces no edge for missing evidence. Tests cover reuse/ambiguity and missing-message behavior. Timestamp proximity is never a correlation rule.
