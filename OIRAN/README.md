# OIRAN vProbe and Network Intelligence Web

OIRAN combines a native Rust capture/decoder/session engine with a premium read-only telecom investigation application. V2 adds a dark-default operational shell, dual themes, truthful monitoring, packet-level provenance inspection and evidence-driven Call Flow analysis while preserving the certified `OIRAN_5G_PDU_SESSION_DATA_V1` result. The frontend consumes versioned API models; it contains no decoder or correlation logic.

Project version: `2.0.0-dev`

## V2 build and test

```bash
cargo build --workspace --release
cargo test --workspace --release
cd apps/web
npm ci
npm run typecheck
npm test
npm run build
```

Local read-only startup:

```bash
cd /root/OIRAN_VPROBE
OIRAN_API_BIND=127.0.0.1:49152 \
./target/release/oiran-api
```

Open `http://127.0.0.1:49152`. No access token is required. Live capture actions remain deliberately unavailable.

The V2 modules are Overview, Probe Manager, Session Explorer, Call Flow Viewer, Correlation Studio, Packet Analyzer, Export & Reports, Live Monitoring, Settings and Module Versions. All operational metrics distinguish current telemetry from immutable historical evidence.

The current real dataset contains one certified PDU session. Five-UE/multiple-PDU behavior is validated with explicitly synthetic Rust fixtures; see `S4_1_MULTI_UE_TEST_PLAN.md` before generating any additional POLARIS traffic.

Run the bounded benchmark:

```bash
./target/release/benchmark-engine \
  --mode full --workers 2 --duration-ms 250 --frame-size all \
  --batch-size 64 --queue-batches 256
```

Modes are `generator`, `processing` (pre-generated immutable buffers), and `full`. The CLI accepts 64, 128, 512 and 1500-byte captured-frame profiles. It refuses runs longer than 10 seconds, unavailable worker counts, and runs under memory pressure. Synthetic throughput is a software regression indicator, not 25/100 Gbit/s capture certification.

S2 benchmarking was stopped when an unrelated OTV container lifecycle change was observed. Subsequent S3/S3.3 functional work produced the immutable certified call flow consumed by S4. This does not constitute 25/100 Gbit/s performance certification.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data path and scaling boundaries and [BENCHMARK_BASELINE.md](BENCHMARK_BASELINE.md) for the measured VPS baseline.

# Live capture foundation

OIRAN now includes an execution-gated live capture pipeline for the discovered POLARIS N2/N3/N4 bridges. Acquisition is implemented by the separate native Rust `capture-helper` over authenticated Unix IPC; the Web API no longer launches tcpdump. It is disabled by default and requires an authenticated Operator, explicit server-side enablement, and the separately deployed helper socket. See `docs/OIRAN_CAPTURE_HELPER_DEPLOYMENT_PLAN.md` and `OIRAN_LIVE_CAPTURE_TEST_PLAN.md` before any live test.

