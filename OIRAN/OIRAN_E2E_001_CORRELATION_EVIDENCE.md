# OIRAN-E2E-001 Correlation Evidence Plan

State: **NOT OBSERVED**.

- NGAP to SBI requires a UE-scoped PDU Session ID plus an observed SM Context/N2 SM relationship. Timestamp proximity alone is rejected.
- SBI to PFCP requires the SMF/session context and independently observed PFCP F-SEID/F-TEID evidence.
- PFCP to GTP-U requires TEID, tunnel endpoint IP, direction and PDR/FAR context; TEID alone is insufficient.
- UE-04 identifiers must be isolated from UE-01/02/03 across NGAP IDs, SM Context references, SEIDs, TEIDs and packet provenance.

Each eventual edge will be EXACT, STRONG, POSSIBLE or UNKNOWN. E2E certification is forbidden if any required bridge remains unproven.

