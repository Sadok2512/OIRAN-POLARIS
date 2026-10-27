# S2.1 benchmark A/B/C methodology

## Safety prerequisite

Run `scripts/s2_1_safety_gate.sh` and use its short-lived receipt. The observer runs for at least 900 seconds and rejects container lifecycle/health changes, OOM state, major ETV/OTV bursts, CPU PSI `some avg10 >= 2%`, memory full pressure, steal `>= 1%`, root-cgroup throttling, less than 8 GiB available RAM, or an existing benchmark process. A receipt expires after five minutes. The CLI refuses to run without it.

The gate did not pass during this mission, so every S2.1 performance field is `NOT_RUN`.

## Reproducible commands (review/run only after a passing gate)

```bash
cd /root/OIRAN_VPROBE
scripts/s2_1_safety_gate.sh
cargo build --release --locked
systemd-run --scope -p MemoryMax=1G -p CPUQuota=300% \
  target/release/benchmark-engine --safety-receipt S2_1_SAFETY_RECEIPT.env \
  --mode processing --workers 2 --duration-ms 250 --frame-size 1500 \
  --batch-size 256 --queue-batches 256 --flows 256 --affinity auto
```

Repeat separately with `--mode generator`, `processing`, and `full`. Use workers 1–4, sizes 64/128/512/1500, batches 32/64/128/256, three repetitions, identical flow count, and medians. Start at one worker. The example limits only OIRAN; it does not change other processes.

## Metrics

- A: generated packets/s, allocation/checksum cost, process CPU and RSS.
- B: parsed packets/s, per-worker throughput, scaling efficiency, CPU/RSS; generation excluded.
- C: generated/enqueued/processed/dropped/in-flight, queue high-water marks, parser integrity, CPU/RSS.
- All: captured-byte, GTP-U payload, and Ethernet-wire-equivalent rates remain distinct.

Reject any run with lifecycle change, nonzero integrity error, silent accounting difference, affinity failure, expired receipt, pressure threshold breach, or unexpected throttling. Synthetic results never certify NIC capture throughput.
