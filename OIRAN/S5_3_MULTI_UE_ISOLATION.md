# S5.3 multi-UE isolation

Replay retained six observed UE contexts, including one released lifecycle, and five PDU sessions. PDU Session IDs remain scoped by UE context; shared NF endpoints and timestamps never merge identities. Six PFCP sessions remain separate and the corpus has zero GTP-U tunnels.

Negative tests verify identifier reuse and reject a correlation based only on a reused PDU Session ID. No cross-UE contamination was observed. This result does not prove user-plane correlation because the multi-IMSI capture contains no GTP-U evidence.
