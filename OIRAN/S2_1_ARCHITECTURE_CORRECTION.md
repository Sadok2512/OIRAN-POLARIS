# S2.1 architecture correction

Status: **IMPLEMENTED; PERFORMANCE BENCHMARK DEFERRED**.

## Corrected data paths

The three stages are intentionally separate:

1. **A — generator:** allocates and fills realistic Ethernet/IPv4/UDP/GTP-U frames, computes fingerprints, and consumes the result through an observable accumulator. It does not invoke the parser.
2. **B — preloaded fast path:** creates and fingerprint-validates immutable packet batches, then builds deterministic flow partitions before timing. Each worker owns one partition and local counters. The timed loop has no producer, allocation, checksum, queue, shared lock, or atomic counter operation. A barrier establishes one start instant; the decoded-TEID accumulator prevents dead-code removal.
3. **C — full pipeline:** retains allocation, generation, software dispatch, bounded per-worker queues, parsing, aggregation, explicit backpressure, and graceful draining.

All modes use the same GTP-U frame constructor, TEID population, flow count, frame sizes, and batch sizes. Mode B is parser capacity only; it is not capture capacity.

## Production boundary

`capture-core::PacketBatchSource` describes a queue-oriented source with explicit capabilities and source kind (`Synthetic`, `Pcap`, `AfXdp`, `Dpdk`). No AF_XDP or DPDK adapter is implemented. A future adapter supplies owned batches by RX queue; `flow-dispatcher` then maps either a five-tuple or a control-plane correlation key to worker-local processing. Cross-interface affinity is never inferred from RSS alone.

The completed-run invariant is `generated = processed + explicitly_dropped`; in-flight is zero after shutdown. Preloaded workers generate unique strided logical packet numbers without coordination. Fingerprints, provenance lengths, TEID work accumulators, packet sums/XOR, and per-worker counts prevent silent elision or unreported corruption.

## Version boundary

- `capture-core` 0.3.0: source abstraction and immutable preloaded packets/batches.
- `worker-runtime` 0.3.0: cpuset-aware affinity planning, effective-mask reporting, producer affinity guard, worker-local preloaded parser path.
- `benchmark-engine` 0.3.0: isolated A/B/C modes and mandatory fresh safety receipt.

The 25/100 Gbit/s figures remain design targets. No performance certification was attempted in S2.1.
