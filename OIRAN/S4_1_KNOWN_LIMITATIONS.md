# S4.1 known limitations

- Real multi-UE capture evidence is not available. Multi-UE and multi-PDU behavior is certified only by explicitly synthetic Rust fixtures.
- The current read-only registry is rebuilt at API startup; persistent incremental ingest and authorized import/reprocess actions are deferred.
- Automatic extra-session Call Flows contain only events whose UE/PDU membership is demonstrable. Cross-interface PFCP/N3 inclusion requires a canonical sidecar or unique evidence bridge.
- A direct general N2↔N4 bridge cannot be guaranteed when nested NGAP tunnel transfer fields remain partial.
- PCAP decoding into normalized JSONL remains an offline Rust workflow, not a browser/API write action.
- Existing documentation PCAPNG files under POLARIS were excluded because they are not certified scenario evidence.
- Live capture and distributed probes remain unavailable; S5 is not started.

Because the real-data gate is missing, the correct S4.1 status is `S4_1_PARTIAL`, not certified against real multi-UE traffic.
