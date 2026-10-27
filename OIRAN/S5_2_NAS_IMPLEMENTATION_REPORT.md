# S5.2 Native 5G NAS Implementation

## Outcome

OIRAN now has a separate native Rust `decoder-nas` crate integrated at NGAP NAS-PDU boundaries. It dispatches 5GMM (`0x7e`) and 5GSM (`0x2e`), validates all reads, retains unknown IE hashes, and emits logical child events without creating extra physical packet observations.

The NGAP parent remains unchanged. Each NAS child carries `parent_event_id`, inherited timestamp/direction/UE identifiers, packet provenance, relative container offset, decoder version, security state and procedure. Event schema 1.4.0 is additive; NGAP is 0.3.0, NAS is 0.1.0, and session-engine is 0.3.0.

## Scope

- Plain observed Registration, Authentication and Reject messages are decoded.
- Integrity-only inner messages are decoded but explicitly marked partial because integrity is not verified.
- Ciphered envelopes are classified and retained without interpreting inner bytes.
- Standalone/nested 5GSM parsing is implemented and deterministically tested; the reference NGAP corpus does not provide an authorized decodable 5GSM inner payload.
- Mobile identities are pseudonymized; secret material is never serialized.

Reference: 3GPP TS 24.501 Release 17. No third-party decoder code was imported.

## Reproduction

```bash
cargo test --workspace --no-fail-fast
python3 benchmarks/S5_2_NATIVE_NAS/tools/run_corpus.py
python3 benchmarks/S5_2_NATIVE_NAS/tools/run_performance.py
```

Implementation commit: `2f3bfee560335e04b86f0d1441a9a16dc7386157`.
