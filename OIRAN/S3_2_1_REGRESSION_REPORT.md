# S3.2.1 regression report

## Outcome

- `cargo test --workspace --no-fail-fast`: **46 passed, 0 failed**.
- `cargo build --workspace --release`: **PASS** with Rust 1.75.
- Previous suite preserved: 40/40; added coverage: 6 tests.
- Generated events: 99; packet provenance plus exact evidence: 99/99.

New coverage includes nested/optional/choice NGAP fields, malformed/extension/unknown handling, nested and invalid-length PFCP IEs, observed scalar parity and deterministic provenance. No performance benchmark was run.

The four Open5GS fixture packet errors reported by the CLI are ARP frames (`EtherType 0x0806`), an explicitly unsupported network type for the IP decode path; they are not decoder crashes or missing target-protocol events.
