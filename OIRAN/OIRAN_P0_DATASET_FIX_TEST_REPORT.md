# OIRAN P0 Dataset Fix Test Report

Offline coverage includes:

- Missing dataset directory created by the pipeline itself.
- Empty PCAP producing an explicit empty dataset.
- Valid PCAP with unsupported traffic producing zero fabricated events.
- Valid NGAP/PFCP/GTP-U fixtures producing normalized events and provenance.
- Explicit permission-error classification.
- Malformed capture/decoder failure with no finalized or registered dataset.
- Atomic JSONL, Call Flow and dataset-manifest finalization.
- Dataset registration rejection when the final manifest is absent or inconsistent.
- Recovery of a failed capture without mutating source evidence.
- Idempotent repeated recovery.
- Timeout, graceful Stop, bounded rotation and partial-interface failure behavior.

No live capture or simulator traffic is used by these tests.
