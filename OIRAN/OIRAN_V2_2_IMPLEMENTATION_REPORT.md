# OIRAN V2.2 Implementation Report

## Outcome

The Capture → Dataset → Session path now resolves exact identity and refuses unrelated fallback. Session Explorer distinguishes historical, recovered, processing and failed-capture contexts, keeps selection in the URL, and presents an explicit zero-session state with packet, decoded-event and capture-detail actions.

The Call Flow Viewer is now a resizable three-panel investigation workspace. It uses evidence-derived participants, SVG lifelines, bidirectional arrows, GTP-U data-flow styling, UTC millisecond timestamps, real procedure groups and synchronized arrow/table selection. The inspector exposes actual decoder fields, protocol-appropriate hierarchy, canonical JSON, correlation evidence and packet provenance.

## Integration

- API 2.2.0 adds exact capture context and packet provenance filters.
- Web 2.2.0-dev preserves capture, dataset, session, probe, technology and event identifiers through navigation.
- Packet Analyzer accepts exact provenance deep links.
- Existing S3.3 decoders, session engine, correlation engine and schemas are reused unchanged.

## Validation

- Rust workspace: 133/133 tests passed.
- React unit/component tests: 17/17 passed.
- TypeScript validation: passed.
- Isolated production build: passed, 351.25 kB JavaScript / 104.17 kB gzip and 28.09 kB CSS / 6.26 kB gzip.
- Browser E2E: 37/37 workflows passed, including strict capture context, selection synchronization and mandatory visual evidence.
- Historical PCAP SHA-256 values remained `2f23390...`, `806a4ae1...`, and `8fad2f34...`.

No live capture, traffic generation, production deployment or service restart occurred.

