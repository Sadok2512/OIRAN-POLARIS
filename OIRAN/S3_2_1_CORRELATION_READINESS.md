# S3.2.1 correlation readiness

## Schema readiness

Event schema 1.2.0 exposes `probe_id`, `capture_point_id`, immutable `capture_id`, packet references, exact source timestamp, interface/protocol/message, endpoints, UE context IDs, PDU Session ID, SEID/F-SEID, TEID/F-TEID where decoded, decoder/schema versions, status, errors, raw reference and evidence references.

Evidence states have strict meanings:

- `EXACT`: direct packet/field identity or cryptographic provenance;
- `STRONG`: independent identifier agreement across interfaces;
- `POSSIBLE`: circumstantial evidence requiring confirmation;
- `UNKNOWN`: evidence is absent or insufficient.

Subscriber-sensitive values are pseudonymized; protected NAS remains opaque. Timestamps can order already-linked evidence but are not a session key.

## Readiness decision

The event contract is ready for S3.3 implementation, but the validation data is not. N2↔N4 can be linked strongly through PDU Session ID plus paired F-TEID/transport endpoints. Operational N3 linkage remains UNKNOWN because no user-plane packet exists. S3.3 certification should wait for an approved coherent N2/N4/N3 run.

Recommended correlation key progression: RAN/AMF UE IDs → PDU Session ID → PFCP CP/UP SEIDs → F-TEID with both tunnel endpoints → observed N3 TEID/direction. Ambiguity, reuse, restart epochs and identifier lifetime must remain explicit.
