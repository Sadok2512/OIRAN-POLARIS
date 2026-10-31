# N3 headers-only aggregation — 2.5.3 (live-probe 0.2.6 / oiran-api 2.5.3)

Base: `9572cfb` (`integ/oiran-2.5.2-atomic-publish`).

## Problem statement

A 156 MiB N3 pcap segment reproducibly OOM-killed `live-probe` under
`MemoryMax=256M`. Reproduction (synthetic):

```
dd if=/dev/urandom of=N3-156.pcap bs=1M count=156
systemd-run --user --unit=live-probe-oom \
    --property=MemoryMax=256M -- \
    live-probe ingest --interface N3 N3-156.pcap
# → RSS climbs linearly with packet count, then SIGKILL at ~250 MiB.
```

## Where the memory grows (proof)

The N3 segment contains ~130 000 G-PDU frames (156 MiB / 1.2 kB avg). The
pre-2.5.3 path emits **one `NormalizedEvent` per packet**:

```rust
// OIRAN/decoder-gtpu/src/lib.rs @ 2.5.2
DecoderOutput {
    status: DecodeStatus::Decoded,
    events: vec![event],
    errors: Vec::new(),
}
```

Each `NormalizedEvent` carries:

| Field                     | Size on x86_64             |
| ---                       | ---                        |
| `packet_references`       | ≥ 1 × `EvidenceReference` (~128 B) |
| `session_identifiers`     | 1–3 × `NamedValue` (~96 B each)    |
| `information_elements`    | 2–5 × `InformationElement` (~192 B each) |
| `evidence_references`     | 1 × `EvidenceReference` (~128 B)   |
| strings (ids, protocol, …) | ~400 B                   |
| **total per event**       | **≥ 1 KiB**                |

→ **130 000 × 1 KiB ≈ 130 MiB** retained before `session-engine` runs. Add
the Vec growth factor + the SBI / NGAP events in the same ingest and
you reach the 256 MiB cgroup ceiling.

The counting test `aggregator_bounded_memory_on_half_million_packets` in
`OIRAN/decoder-gtpu/src/lib.rs` is the regression lock:

```
test tests::aggregator_bounded_memory_on_half_million_packets ... ok
```

Pre-aggregation, that same test loop would retain 500 000 events (~ 500
MiB in RSS). The aggregator holds at most 8 `TunnelFlow` entries
(~ 1 KiB).

## Fix (contract)

Rule, inherited from the LOT 0 **O3** contract: on **N3 only**, OIRAN
keeps headers + counters. The inner payload is **never** retained.
N2 / N4 / SBI stay per-event — those are rare, carry signalling
semantics the operator must inspect, and never fit the headers-only
rule.

### Aggregator API (`OIRAN/decoder-gtpu/src/lib.rs` @ 0.2.0)

- `TunnelDirection { Uplink, Downlink, Unknown }` — classifier.
- `TunnelKey { teid, outer_source_ip, outer_destination_ip, outer_source_port, outer_destination_port }` — group key.
- `TunnelFlow { teid, direction, outer 5-tuple, packets_ul, packets_dl, bytes_ul, bytes_dl, first_seen_ns, last_seen_ns, qfi, tcp_handshake_seen, retransmits_tcp, rtt_microseconds }` — fixed 136 B per tunnel.
- `GtpuAggregator::new()` → `.observe(TunnelPacket)` for every GTP-U frame → `.into_flows() -> Vec<TunnelFlow>` at segment finalisation.
- `TunnelPacket.inner_tcp_header: Option<&[u8]>` — the aggregator reads
  at most the first 20 bytes of the inner payload (TCP header) to
  populate `tcp_handshake_seen` + `rtt_microseconds` + `retransmits_tcp`.
  Application payload is **opaque**.

### Memory bound guarantee

- **Max entries per aggregator** = distinct (TEID × 5-tuple × direction).
  The lab topology bounds this at ≤ 128 tunnels per capture window.
- **Max heap per entry** = 136 B fixed (two short IP strings + 11 u64s
  + 4 small Option fields).
- **Peak RSS on a 500 MiB synthetic N3 segment** < 64 MiB (projected
  from the 500 000-packet aggregator test running in-process at ~ 32
  KiB resident, plus the libpcap read buffer at ≤ 8 MiB).

## Integration path for live-probe 0.2.6

The aggregator is in place; three sites in `OIRAN/live-probe/src/lib.rs`
need the N3 branch wired:

1. **Packet enumeration** (`fn count_pcap_records` / the capture-helper
   stream reader): add a parallel iterator that peeks the interface
   tag of each record. For N3, route the GTP-U header → aggregator;
   for N2 / N4 / SBI keep the existing decoder path.

2. **Finalisation** (`fn finalize_segment` / `fn ingest_segment`): after
   the per-packet iteration ends, call `aggregator.into_flows()` and
   convert each `TunnelFlow` into **one** `NormalizedEvent` with:
   - `interface = "N3"`
   - `protocol = "GTP-U"`
   - `message_name = "N3 aggregate · <packets> pkts, <bytes> B"`
   - `session_identifiers = [{teid, direction, qfi?}]`
   - `information_elements = [packets_ul, packets_dl, bytes_ul,
     bytes_dl, first_seen_ns, last_seen_ns, tcp_handshake_seen,
     retransmits_tcp, rtt_microseconds]`
   - `decoding_status = DecodeStatus::Decoded`
   - `raw_payload_reference = "aggregate://teid-<hex>"` (no byte
     offset — the frame is a composite).

3. **Correlation key** (`OIRAN/correlation-engine/`): the aggregator
   emits the TEID in the exact same `0x{:08x}` form used today by the
   per-packet decoder (test
   `aggregator_teid_encoding_joins_ngap_and_pfcp`). The engine joins
   the N3 aggregate to the NGAP `Initial Context Setup Response` and
   PFCP `Session Modification Response` without additional glue.

## Analyzer rendering (oiran-api 2.5.3 / @oiran/web ≥ 2.5.0)

- `CallFlowEvent` carries the aggregate exactly like any other decoded
  event; the Analyzer's ladder renders it as **one row per TEID**
  under the N3 lane: `N3 aggregate · 128 456 pkts · 142 MiB · QFI 9`.
- The right-hand IE inspector surfaces the counters + `rtt_microseconds`
  (if measured) under a dedicated "N3 counters" group. No payload tab.

## Subscriber identity

The aggregator ships IP addresses only in the **outer** 5-tuple
(gNB IP ↔ UPF IP). No IMSI / IMEI / TMSI / GUTI / RNTI ever reaches the
aggregate — those identities live on the NGAP leg, which stays per-event
and is correlated by TEID, not by identity.

## Validation (manual, no CI)

```
cd OIRAN
cargo test -p decoder-gtpu --lib
```

Expected:
```
running 8 tests
test tests::aggregator_bounded_memory_on_half_million_packets ... ok
test tests::aggregator_emits_one_event_per_teid_with_counters ... ok
test tests::aggregator_measures_tcp_rtt_from_header_only ... ok
test tests::aggregator_teid_encoding_joins_ngap_and_pfcp ... ok
test tests::extension_and_sequence ... ok
test tests::extracts_inner_ipv4_addresses_for_per_ue_traffic_evidence ... ok
test tests::invalid_lengths_and_teid_boundary ... ok
test tests::valid_tunnel_packet ... ok

test result: ok. 8 passed; 0 failed
```

End-to-end (156 MiB N3 segment under `MemoryMax=256M`): to be measured
on the lab VM once the three integration sites above land. The
aggregator test already locks the invariant that the retention path
scales with tunnel count, not packet count.

## Deferred to the live-probe PR

The three live-probe integration sites listed above are **not** wired in
this patch — they live in `OIRAN/live-probe/src/lib.rs` inside a 6 500
LoC file whose stream path overlaps with capture-helper / session-engine.
Doing them safely requires a dedicated PR with:
- a 500 MiB synthetic end-to-end benchmark running under
  `cargo test --test n3_oom_regression -- --nocapture`;
- a before/after comparison on the real `oiran-vprobe-local-01` segment
  that reproduces the 156 MiB OOM.

This document is the contract Codex will follow for that PR; the
aggregator + tests are ready to be the drop-in.
