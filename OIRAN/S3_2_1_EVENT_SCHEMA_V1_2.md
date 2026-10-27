# OIRAN normalized event schema 1.2.0

Schema 1.2.0 extends 1.1 without removing packet provenance. Required correlation-readiness additions are `probe_id`, `capture_point_id`, and `evidence_references[]` containing `state`, `kind`, and `reference`. Valid states are `EXACT`, `STRONG`, `POSSIBLE`, and `UNKNOWN`.

Protocol identifiers remain typed entries in `session_identifiers`; subscriber values must be pseudonymized. Every event must contain at least one packet reference and a raw payload reference. Decoder status remains one of `DECODED`, `PARTIAL`, `UNSUPPORTED`, `MALFORMED`, or `ENCRYPTED_OR_PROTECTED`.

The canonical Rust definition is in `event-schema/src/lib.rs`; the 99-record example dataset is `S3_2_1_NORMALIZED_EVENTS.jsonl`.
