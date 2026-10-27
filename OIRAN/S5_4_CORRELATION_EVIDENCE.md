# S5.4 correlation evidence requirements

## NGAP ↔ SBI

Required minimum: a UE-scoped pair of RAN UE NGAP ID and AMF UE NGAP ID, PDU Session ID, parent NGAP/NAS packet references, and an SBI SM Context transaction tied through an authorized pseudonym or decoded N1/N2 SM container. A PDU Session ID or timestamp alone is insufficient.

## SBI ↔ PFCP

Required minimum: observed SM Context reference plus SMF identity and a protocol-derived association to the PFCP transaction's CP/UP F-SEID or tunnel information. An SM Context URI must not be treated as a PFCP SEID. If no explicit cross-layer mapping is observable, the edge remains STRONG/POSSIBLE only when multiple independent identifiers agree; otherwise it is UNKNOWN.

## PFCP ↔ GTP-U

Required minimum: F-TEID/outer-header TEID, endpoint IP pair, direction and the owning PDR/FAR within the PFCP session. TEID alone is not globally unique.

## Evidence levels

- `EXACT`: explicit uniquely scoped identifier relationship with packet provenance on both sides.
- `STRONG`: multiple independent consistent identifiers, no conflicting candidate.
- `POSSIBLE`: plausible but incomplete association.
- `UNKNOWN`: insufficient or conflicting evidence.

Every edge records its rule/version, source/target event IDs, matching identifiers, packet references and rejected alternatives. Timing is supporting evidence only.

## Evidence expected from OIRAN-E2E-001

- N2: fresh UE IDs and PDU Session ID from the owned UE-04 lifecycle.
- SBI: direct AMF/SMF CreateSMContext and UpdateSMContext, response status, SM Context reference and sanitized UE binding.
- N4: Session Establishment/Modification with distinct SEIDs, PDR/FAR and F-TEIDs.
- N3: five uplink GTP-U datagrams and corresponding controlled downlink ICMP responses, tied through TEID and endpoints.

The test is not E2E-certified if any required bridge remains UNKNOWN.
