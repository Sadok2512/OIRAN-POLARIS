# S5.3 cross-interface correlation

## Implemented evidence policy

- NGAP to SBI may use UE-scoped NGAP identifiers, PDU Session ID, an explicit SM Context reference and decoded N2 SM information.
- SBI to PFCP requires an explicit context/SEID/F-TEID relationship or multiple independently scoped identifiers.
- PFCP to GTP-U requires TEID plus endpoints, direction, time validity and PFCP PDR/FAR context.
- Timestamp proximity, shared network functions or PDU Session ID alone cannot produce an EXACT edge.
- SCP routing produces an EXACT observation only when identical sanitized method/URI evidence is uniquely observed on both consumer-to-SCP and SCP-to-producer legs.

## Corpus result

The multi-IMSI capture provides SBI operations and five UE-scoped PDU sessions, but it lacks an explicit mapping from SM Context references to PFCP SEID/F-TEID values. Its PDU Session IDs are reused across UEs and it contains no GTP-U packets. Some consumer-side headers also depend on HPACK state established before capture.

Consequently no new NGAP-SBI, SBI-PFCP or PFCP-GTP-U edge is promoted. Five potential end-to-end session bridges remain `UNKNOWN`; EXACT, STRONG and POSSIBLE counts are zero. This is the required false-association rejection, not a decoding failure.

`N2_SBI_N4_CORRELATION_CERTIFIED = NO` and `E2E_SESSION_CERTIFIED = NO` for this corpus.
