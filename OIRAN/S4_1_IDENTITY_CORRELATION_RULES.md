# S4.1 identity and correlation rules

| Rule | Inputs | Result | Ambiguity behavior |
|---|---|---|---|
| `ngap-context-v2` | capture point, endpoints, RAN/AMF IDs, lifecycle | UE context | no time-only merge; release closes generation |
| `pdu-session-v2` | UE context ID + PDU Session ID | PDU session | missing ID is not invented |
| `pfcp-lifecycle-v2` | endpoint scope + sequence + SEID/F-SEID | PFCP session | unmatched transaction remains incomplete |
| `gtpu-tunnel-v2` | endpoints + TEID + direction | tunnel | TEID is never globally unique |
| `n4-n3-discovered-teid-endpoint` 1.1.0 | unique F-TEID + endpoint + packet evidence | EXACT edge | zero or multiple PFCP candidates creates no edge |

All generated edges contain source and target event IDs, packet references, a rule ID/version, matched identifiers and confidence. The certified manifest-backed N2↔N4 STRONG rules remain version 1.0.0 for backward compatibility. No S4.1 rule inflates them to EXACT.
