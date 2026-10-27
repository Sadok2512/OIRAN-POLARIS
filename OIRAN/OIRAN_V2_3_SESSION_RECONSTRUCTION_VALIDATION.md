# OIRAN V2.3 Session Reconstruction Validation

The fixture at `tests/fixtures/oiran-v2.3-multi-session/corpus.json` is explicitly synthetic TEST DATA and is never loaded into the production registry.

Expected and observed offline results:

- 3 independent UE contexts.
- 3 independent PDU sessions.
- 3 PFCP sessions.
- 3 endpoint/direction-scoped GTP-U tunnels.
- 3 stable session identifiers.
- 0 unmatched events and 0 cross-UE contamination.

The fixture uses distinct RAN UE NGAP IDs, AMF UE NGAP IDs, SEIDs and TEID/endpoint tuples. Existing tests additionally cover identifier reuse after release, out-of-order input, concurrent sessions, duplicate imports, incomplete procedures and ambiguous TEID rejection.

This establishes `MULTI_SESSION_DECODER_VALIDATED_OFFLINE`, not live multi-UE certification.
