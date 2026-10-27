# S2 optimization changelog

## Accepted changes

### Owned packet buffers

- Before: synthetic `Vec<u8>` converted to `Arc<[u8]>` for every full-pipeline packet.
- After: `PacketBuffer::Owned(Box<[u8]>)` is moved through queues; `Shared(Arc<[u8]>)` remains available for pre-generated replay.
- Versioning: `capture-core` 0.1.0 → 0.2.0 because the public `bytes` field type changed. Constructors preserve the original `PacketRecord::new(Arc<[u8]>)` path and add `from_owned`.
- Correctness: existing integrity/replay tests plus full matrix checksum and packet-accounting checks pass.

### Batched worker telemetry

- Before: up to five atomic operations per packet for common counters.
- After: worker-local registers aggregate a batch, then perform one relaxed atomic update per metric.
- Versioning: `telemetry` and `worker-runtime` 0.1.0 → 0.2.0.
- Correctness: four-worker totals, byte totals, graceful draining, saturation and deterministic replay tests pass.

### Stronger integrity instrumentation

- Added generated-packet count, provenance-length error count, packet-number sum/XOR and ordered TEID/provenance work accumulator.
- A result with zero explicit drops fails if generated packet-number invariants do not match processed data.
- Added generator-only and pre-generated processing modes to `benchmark-engine` 0.2.0.

## Strict before/after evidence

The comparison uses 2 workers, batch 64, 250 ms, three repetitions and identical synthetic distribution.

| Frame | Before median wire Gbit/s | After | Change | Decision |
|---:|---:|---:|---:|---|
| 64 | 1.039135 | 1.180679 | +13.62% | Keep |
| 128 | 0.634159 | 0.905779 | +42.83% | Keep |
| 512 | 1.591668 | 2.156521 | +35.49% | Keep |
| 1500 | 2.694994 | 3.037666 | +12.72% | Keep |

All comparison runs had zero drops, malformed packets, integrity errors, length errors and affinity failures.

## Changes intentionally not made

- No unsafe SIMD/checksum implementation: isolated profiles were not available to justify the risk.
- No unbounded queue or blocking producer: explicit backpressure remains part of the contract.
- No global CPU/kernel tuning, huge pages, DPDK, AF_XDP or system package installation.
- No change to the stable dispatcher hash or packet-classifier public result types.

## Git history

- `1b5a3fb04098a561f57248b5b31a54be3a203afc` — `[OIRAN-S2] capture S1 baseline`
- `db3ddb53200ebe4232cb2e6511b668dc136243ed` — `[OIRAN-S2] optimize owned buffers and batched telemetry`

