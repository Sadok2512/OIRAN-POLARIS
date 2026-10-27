# S1 performance regression baseline

## Safety envelope

- Date: 2026-10-24 UTC
- Host: OIRAN VPS, 10 vCPU, 20 GiB nominal RAM
- Available memory before run: approximately 15 GiB
- Workers: 2, CPU affinity enabled and successful
- Duration: 250 ms per frame profile; approximately 1 second total
- Batch size: 64 packets
- Queue capacity: 256 batches per worker
- Rust: 1.75.0, optimized release build

This was a bounded in-process synthetic generator/classifier test. It did not exercise a NIC, kernel capture path, Docker bridge or physical wire, and it is not a 25 Gbit/s certification.

## Results

| Captured frame | MPPS | GTP-U payload Gbit/s | Captured Gbit/s | Ethernet wire equivalent Gbit/s | CPU | RSS | Drops | Integrity errors |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 64 B | 1.363988 | 0.152767 | 0.698362 | 0.960248 | 179.87% | 4.23 MiB | 0 | 0 |
| 128 B | 0.536337 | 0.334674 | 0.549209 | 0.652186 | 199.82% | 4.23 MiB | 0 | 0 |
| 512 B | 0.391085 | 1.445449 | 1.601883 | 1.676971 | 191.46% | 4.23 MiB | 0 | 0 |
| 1500 B | 0.224678 | 2.606269 | 2.696140 | 2.739278 | 183.72% | 4.23 MiB | 0 | 0 |

Maximum process RSS independently reported by `/usr/bin/time -v` was 4,352 KiB. Aggregate command CPU usage was 188%. All profiles reported zero malformed packets, fingerprint errors, drops and affinity failures.

## Per-worker balance

| Frame | Worker 0 packets/s | Worker 1 packets/s |
|---:|---:|---:|
| 64 B | 681,994 | 681,994 |
| 128 B | 268,041 | 268,296 |
| 512 B | 195,542 | 195,542 |
| 1500 B | 112,467 | 112,211 |

## Regression use

These figures are an environmental baseline, not hard CI pass/fail thresholds. A repeat on the same host/toolchain/configuration should be reviewed if median MPPS falls by more than 20%, drops or integrity errors become nonzero, affinity fails, or RSS grows materially. Reliable gating requires repeated warm runs on otherwise idle dedicated hardware; that was intentionally not done on this shared VPS.

## S2 controlled reproduction

Baseline commit: `1b5a3fb04098a561f57248b5b31a54be3a203afc`. Three repetitions used the same S1 parameters, plus process-only safety wrappers (`ulimit -v 1048576`, `timeout 5s`, `taskset -c 0-4`).

| Frame | S1-reproduction median wire Gbit/s | Minimum | Maximum | Range/mean |
|---:|---:|---:|---:|---:|
| 64 B | 1.039135 | 0.971521 | 1.041213 | 6.85% |
| 128 B | 0.634159 | 0.628941 | 0.647996 | 2.99% |
| 512 B | 1.591668 | 1.572695 | 1.638169 | 4.09% |
| 1500 B | 2.694994 | 2.423679 | 2.748063 | 12.37% |

The 1500-byte median is within 1.6% of the original S1 result, so the baseline is considered reproduced on this shared host.

## S2 optimized comparison

Optimization commit: `db3ddb53200ebe4232cb2e6511b668dc136243ed`. The strict comparison retained 2 workers, batch 64, 250 ms, identical frame construction/distribution and the same wrappers.

| Frame | Before median | After median | Gain |
|---:|---:|---:|---:|
| 64 B | 1.039135 | 1.180679 | 13.62% |
| 128 B | 0.634159 | 0.905779 | 42.83% |
| 512 B | 1.591668 | 2.156521 | 35.49% |
| 1500 B | 2.694994 | 3.037666 | 12.72% |

All strict-comparison runs had zero drops, malformed frames, integrity errors, length errors and affinity failures. The broader matrix includes explicitly reported saturation cases and is documented separately; no silent loss was found.
