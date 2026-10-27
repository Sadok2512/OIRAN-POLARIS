# S2 integrity test report

## Result

All **17 automated tests passed** after optimization. Release compilation and warning-denied all-target checks pass. No incorrect GTP-U TEID, silent packet loss, duplicate/missing provenance, byte-count mismatch, integrity error or length error was observed in accepted zero-drop runs.

## Invariants

| Invariant | Enforcement/evidence | Result |
|---|---|---|
| Generated accounting | Runtime result requires `generated = processed + explicitly dropped` | PASS for all optimized measurements |
| Silent loss/duplication | With zero drops, packet-number sum and XOR must equal sequence expectations | PASS |
| Frame integrity | FNV-1a expected fingerprint generated and checked; error counter exported | 0 errors |
| Correct length | Actual bytes checked against captured/original provenance lengths | 0 matrix errors; mismatch fixture detected |
| GTP-U TEID | Parser fixture expects `0x12345678`; worker accumulator consumes TEIDs | PASS |
| Total bytes | Four-worker test expects 1,000 × 64 = 64,000 bytes | PASS |
| Per-worker totals | Per-worker snapshots sum to global totals | PASS |
| Duplicate processing | Packet count plus packet-number sum/XOR and ordered accumulator | PASS on zero-drop runs |
| Same-flow order | Live one-worker ordered digest equals deterministic replay digest | PASS |
| Deterministic replay | Two replay executions produce identical snapshots | PASS |
| Graceful shutdown | Accepted batches are drained before joined shutdown | PASS |
| Backpressure | Capacity-one saturation produces explicit drops/events within bound | PASS |
| Malformed/truncated | Ethernet truncation and invalid GTP-U declared length rejected | PASS |
| VLAN path | Tagged frame retains correct TEID decode | PASS |
| Plugin compatibility | Incompatible plugin API rejected | PASS |

## Automated command

```bash
cargo fmt --all -- --check
RUSTFLAGS='-D warnings' cargo test --workspace
cargo build --workspace --release
```

Test distribution after S2:

- `benchmark-engine`: 4
- `capture-core`: 1
- `flow-dispatcher`: 2
- `packet-classifier`: 3
- `plugin-runtime`: 1
- `worker-runtime`: 6
- Total: 17

## Matrix integrity

- Pre-optimization full matrix: 192 rows, zero reported drops or integrity errors. Length mismatch instrumentation did not yet exist and is recorded as `not_instrumented` in CSV.
- Post-optimization full matrix: 192 rows, zero malformed, integrity, length or CPU-affinity errors.
- Seven post-optimization saturation rows reported 31,616 explicit drops. Highest single loss: 13.630627%.
- Best configuration and all strict reproduction rows: zero drops.

Explicit drops are not silent loss: rejected batches increment both `dropped` and `backpressure_events`, and generated accounting still closes. They nevertheless make those seven rows unsuitable as lossless capacity claims.

## Limitations

- Sequence sum/XOR is a strong deterministic benchmark check, not a cryptographic proof against adversarial collision.
- Ordering is verified for a single software-affined flow; cross-interface session-key mapping remains a future control-plane responsibility.
- No live NIC frames or real PCAPs were processed in S2.
- IPv4 fragmentation and IPv6 extension headers remain unsupported and explicit.

