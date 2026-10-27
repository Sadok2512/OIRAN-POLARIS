# S5.2 Corpus Regression

The unchanged S5.1 corpus was verified before and after replay:

- Files: 13.
- Packets: 4,205.
- Bytes: 758,864.
- SHA256 integrity: PASS for every file.
- SLL2 packet behavior: unchanged.
- NGAP/PFCP/GTP-U parent decoding: unchanged; NAS children are additive logical events.
- Multi-IMSI UE contexts: 6.
- Multi-IMSI PDU sessions: 5.
- Cross-UE contamination: none observed.

Workspace regression: 152/152 PASS. The first full run saw one pre-existing timing-sensitive `worker-runtime` queue high-watermark assertion; an immediate isolated/full retry passed without code change. The reported final run is 152/152.

Raw replay evidence, before/after checksum logs, normalized events and discovery outputs are under `benchmarks/S5_2_NATIVE_NAS/`.
