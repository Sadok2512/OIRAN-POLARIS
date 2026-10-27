# OIRAN P0 Dataset Output Root-Cause Report

## Finding

Capture `live-1792964646320-0003` was successfully acquired and finalized by the isolated Rust helper. The helper recorded 50 packets, zero drops, three PCAP files, and a valid atomic forensic manifest. The API then entered `PROCESSING`, decoded the first non-empty input in memory, and failed when opening:

`/var/lib/oiran/captures/live-1792964646320-0003/dataset/oiran_events.jsonl`

The parent `dataset/` directory did not exist. This was an execution-order defect, not a permissions, acquisition, timeout, rotation, flush, decoder, disk, or manifest-finalization failure. The deployed API was still the pre-fix artifact when this job ran.

## Corrected ordering

1. Verify source PCAP integrity.
2. Create and verify `dataset/callflows`.
3. Decode all eligible PCAP segments into memory.
4. Atomically write normalized JSONL, including an explicit zero-length file when there are no events.
5. Atomically write each Call Flow JSON/HTML artifact.
6. Atomically write the dataset manifest last.
7. Validate event count, manifest identity, checksums and Call Flow artifacts.
8. Register the dataset only after every validation succeeds.

No fabricated events or sessions are introduced.
