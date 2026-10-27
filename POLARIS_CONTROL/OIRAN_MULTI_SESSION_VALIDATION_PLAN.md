# OIRAN Multi-Session Validation Plan

## Required accounting

For each finalized phase, ingest only the explicit scenario manifest and immutable N2/N3/N4 files. Report total, decoded, session-associated, background, unmatched and duplicate events; totals must reconcile exactly.

## Per-UE verification

1. Create one pseudonymous UE context from scoped AMF endpoint, gNB/SCTP association, RAN UE NGAP ID, AMF UE NGAP ID and lifecycle.
2. Identify PDU Session ID and state without assuming one UE equals one session.
3. Reconstruct PFCP session using SMF/UPF endpoints and SEID/F-SEID lifecycle.
4. Identify GTP-U tunnel using both endpoint IPs, direction, TEID and validity window.
5. Associate the UE to gNB-01 or gNB-02 using the observed N2 association and Global RAN Node identity; do not rely on `gnbSearchList` alone.
6. Generate an independent Call Flow containing only that session's real events and provenance.

## Cross-contamination tests

- No event may belong to two UE contexts unless explicitly classified as shared background signaling.
- Reused NGAP IDs require association/lifecycle scope.
- Reused TEIDs require endpoint/direction/time scope.
- N2-to-N4 evidence remains `STRONG` unless a demonstrable identifier bridge improves it.
- N4-to-N3 may be `EXACT` only when F-TEID and endpoints match.
- Timestamp overlap alone is never sufficient.

## Certification

Compare every supported field against TShark 4.2.2 and retain packet number, capture ID, SHA-256 and decoder version. Expected counts are not predeclared. Certification requires the observed number of UEs/PDU sessions, correct 3+2 gNB association in Phase D, no fabricated events, no unexplained duplicates, full provenance and five independent Call Flows only if all five sessions are actually observed.

Current status: `NOT_EXECUTED`; prior certified evidence covers one UE only.
