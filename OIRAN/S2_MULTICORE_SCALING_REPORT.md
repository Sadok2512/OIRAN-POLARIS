# S2 multi-core scaling report

## Result

S2 measured the complete requested full-pipeline matrix before and after optimization: 1–4 workers × batch sizes 32/64/128/256 × frames 64/128/512/1500 × three repetitions, for 192 points per phase. Component-mode profiling was stopped before execution when an external OTV lifecycle change was detected. Consequently, S2 is **PARTIAL**, not certified complete.

The best accepted three-run median was **3.175694 Gbit/s Ethernet-wire equivalent** at 2 workers, batch 256 and 1500-byte frames. The same point produced 3.125683 captured Gbit/s and 3.021494 GTP-U payload Gbit/s, with 0.260474 Mpps, 197.52% process CPU, 3.29 MiB RSS, zero drops and zero integrity/length errors.

## Environment and reproducibility

- Baseline commit: `1b5a3fb04098a561f57248b5b31a54be3a203afc`
- Optimized code commit: `db3ddb53200ebe4232cb2e6511b668dc136243ed`
- Branch: `feat/s2-multicore-performance`
- Rust/Cargo: 1.75.0; release profile with thin LTO and one codegen unit
- CPU: 10 vCPU, Intel Xeon Platinum 8173M, 1 socket, 10 cores, 1 thread/core, one NUMA node, KVM
- Matrix duration: 100 ms per point; strict baseline reproduction: 250 ms per point
- Queue capacity: 256 batches per worker
- Process guards: 1 GiB virtual-memory limit, five-second timeout, CPU set 0–4

Strict reproduction command:

```bash
(ulimit -v 1048576; timeout 5s taskset -c 0-4 \
  ./target/release/benchmark-engine \
  --mode full --workers 2 --duration-ms 250 --frame-size all \
  --batch-size 64 --queue-batches 256)
```

Matrix command pattern, repeated three times for every worker/batch combination:

```bash
(ulimit -v 1048576; timeout 5s taskset -c 0-4 \
  ./target/release/benchmark-engine \
  --mode full --workers "$workers" --duration-ms 100 --frame-size all \
  --batch-size "$batch" --queue-batches 256)
```

All 408 recorded result rows, including generated/processed/drop counts and commit identity, are in `S2_BENCHMARK_RESULTS.csv`.

## Baseline reproduction and strict optimization comparison

| Frame | Baseline median wire Gbit/s | Optimized median | Gain | Optimized min–max |
|---:|---:|---:|---:|---:|
| 64 | 1.039135 | 1.180679 | 13.62% | 1.141480–1.227718 |
| 128 | 0.634159 | 0.905779 | 42.83% | 0.884433–0.913044 |
| 512 | 1.591668 | 2.156521 | 35.49% | 1.997993–2.186889 |
| 1500 | 2.694994 | 3.037666 | 12.72% | 2.661682–3.077336 |

This is the valid before/after comparison because worker count, batch, duration, frame distribution and process guards are identical. The best matrix point is reported separately and is not substituted into the gain calculation.

## Best optimized configuration

| Frame | Median Mpps | Payload Gbit/s | Captured Gbit/s | Wire equivalent Gbit/s | Drops |
|---:|---:|---:|---:|---:|---:|
| 64 | 1.859297 | 0.208241 | 0.951960 | 1.308945 | 0 |
| 128 | 0.771202 | 0.481230 | 0.789711 | 0.937782 | 0 |
| 512 | 0.511817 | 1.891676 | 2.096403 | 2.194672 | 0 |
| 1500 | 0.260474 | 3.021494 | 3.125683 | 3.175694 | 0 |

Configuration: 2 workers, batch 256. For 1500 bytes, the three-run wire-equivalent range was 3.020839–3.187903 Gbit/s (range/median 5.26%).

## Worker scaling at batch 256 / 1500 bytes

| Workers | Median wire Gbit/s | Median CPU | Median RSS | Efficiency vs one worker | Drops |
|---:|---:|---:|---:|---:|---:|
| 1 | 2.999539 | 187.66% | 3.20 MiB | 100.00% | 0 |
| 2 | 3.175694 | 197.52% | 3.29 MiB | 52.94% | 0 |
| 3 | 2.975891 | 178.33% | 3.30 MiB | 33.07% | 0 |
| 4 | 2.745450 | 187.79% | 3.14 MiB | 22.88% | 0 |

Efficiency is `throughput(N) / (N × throughput(1))`. Adding workers does not produce linear scaling because frame generation/checksum work remains serial in the producer and already consumes roughly one additional core. Two workers are optimal for this implementation and host; three/four workers add scheduling/queue overhead without increasing supply.

## Batch-size effect at two workers / 1500 bytes

| Batch | Median wire Gbit/s | Median Mpps | Median queue high-watermark | Drops |
|---:|---:|---:|---:|---:|
| 32 | 2.792045 | 0.229006 | 3 | 0 |
| 64 | 2.718579 | 0.222981 | 7 | 0 |
| 128 | 3.056939 | 0.250733 | 2 | 0 |
| 256 | 3.175694 | 0.260474 | 2 | 0 |

The larger batches amortize channel and atomic accounting overhead. This result applies only to the synthetic in-memory workload.

## Saturation and outliers

Seven of 192 optimized matrix points reported explicit queue drops, all on one-worker 64/128-byte cases with batch 32 or 64. Total explicit drops were 31,616; the highest individual loss was 13.630627%. Generated packets always equaled processed plus explicitly dropped packets. The accepted best configuration and strict before/after comparison had zero drops.

The largest single-run packet rate was 4.033931 Mpps (1 worker, batch 128, 64-byte frames), while the best three-run median was 2.072607 Mpps (1 worker, batch 256, 64-byte frames). The single-run peak is retained as evidence but not used as the stable performance claim.

## Interpretation

- OBSERVED: batching and owned buffers improve identical-profile medians by 12.72–42.83%.
- OBSERVED: the best median occurs at two workers, not four.
- OBSERVED: small-frame one-worker producer/consumer imbalance can fill the bounded queue; losses are explicit.
- INFERRED: the producer's allocation, frame fill and checksum path is the dominant scaling constraint. Separate mode measurements were not run because of the safety stop.
- NOT VALIDATED: NIC ingress, kernel capture, AF_XDP/DPDK, NUMA scale-out, 25 Gbit/s and 100 Gbit/s.

