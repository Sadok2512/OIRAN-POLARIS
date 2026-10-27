# S4.1 dataset registry report

`dataset-registry` 0.1.0 is a deterministic, in-memory, read-only registry. A record carries dataset/capture IDs, basenames, probe and capture-point IDs, interfaces, checksums, packet/byte counts, decoder versions, ingestion generation and accounting.

Safety controls:

- at least one capture and a 64-character SHA256 are mandatory;
- file names are basename-only; arbitrary paths are rejected;
- mutable records are rejected;
- a sorted capture-hash fingerprint prevents duplicate imports under aliases;
- startup scans only the configured dataset and at most 128 explicit JSON files under its `callflows` directory;
- POLARIS is never recursively ingested.

The current registry contains one immutable dataset, three captures, 54 events, one materialized session, two observable UE contexts, 28 certified background events, zero duplicate observations and zero ingest errors.
