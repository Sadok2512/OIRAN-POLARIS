# S4 Rust Integration Report

`apps/api` is a new workspace crate built on Axum and the existing `callflow-schema` crate. At startup it validates that configured dataset/export paths canonicalize beneath `/root/OIRAN_VPROBE`, deserializes the S3.3 canonical JSON into `CallFlow`, and derives capture records from the certified scenario manifest.

## Preserved semantics

- Event IDs, nanosecond timestamps and stable ordering are unchanged.
- Decoder name/version and `DECODED`/`PARTIAL` status are passed through.
- Packet number, offsets, lengths, capture IDs and raw SHA references remain available.
- The 26 `SESSION` and 28 `BACKGROUND` associations remain distinct.
- All 12 correlation edges retain event IDs, packet references, identifiers, rule ID/version and confidence.
- N2↔N4 remains `STRONG`, N4↔N3 `EXACT`, and E2E `STRONG`.

Only presentation-safe path adaptation is applied: a source such as `datasets/.../N3.pcapng` becomes `capture://N3.pcapng`. The certified artifact is not mutated. The frontend typed client consumes the API model and contains no NGAP, PFCP, GTP-U or correlation implementation.

Schema compatibility is reported through `/version`; module compatibility uses Core API range `^1.0`. Future schema changes must add fields compatibly or introduce a new API major version.
