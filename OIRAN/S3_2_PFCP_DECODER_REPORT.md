# S3.2 PFCP decoder report

## Result

decoder-pfcp 0.1.0 parsed 52 real PFCP messages according to TS 29.244. Packet number, timestamp, endpoints, message type and 24-bit sequence number aligned exactly with TShark: 52 aligned, 0 mismatch, 0 missing.

Observed messages:

- 16 Heartbeat Requests and 16 Responses;
- 2 Association Setup Requests and 2 Responses;
- 2 Session Establishment Requests and 2 Responses;
- 3 Session Modification Requests and 3 Responses;
- 2 Session Deletion Requests and 2 Responses;
- 1 Session Report Request and 1 Response.

## IE handling

The decoder supports S=0 and S=1 headers and does not assume a SEID exists. It recursively parses grouped IEs with a depth bound. Typed extraction includes Cause, F-TEID, Network Instance, PDR ID, F-SEID, UE IP, FAR ID and QER ID. UE IP values are pseudonymized by default. Header SEID, nested F-SEID, TEID and rule IDs are emitted as distinct identifiers.

Unknown/release-new IEs retain type, length and SHA-256. Forty messages were DECODED; 12 were PARTIAL because unknown IE types remained. No malformed real PFCP message was observed. Unit tests cover SEID presence/absence, grouped and unknown IEs and invalid length.

## Limitations

Not every TS 29.244 IE has a typed value decoder. Enterprise-specific IE payloads are retained but not interpreted. Conditional procedure semantics and cross-message state validation are deferred to session reconstruction.
