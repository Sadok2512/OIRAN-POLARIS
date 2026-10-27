# S4.2 correlation validation

Live five-UE validation: **NOT_RUN**.

The required acceptance matrix per UE is:

1. NGAP association + RAN/AMF UE IDs establish scoped UE context.
2. PDU Session ID remains scoped to that UE lifecycle.
3. PFCP sequence and SEID/F-SEID establish a distinct PFCP lifecycle.
4. N4 F-TEID plus endpoint associates N3 direction; TEID alone is insufficient.
5. N2↔N4 remains STRONG unless decoded shared evidence independently proves more.
6. N4↔N3 may be EXACT only for a unique TEID+endpoint candidate.
7. Every edge retains rule version and both packet references.

Ambiguous candidates remain unlinked. No confidence or message was generated for the unexecuted scenario.
