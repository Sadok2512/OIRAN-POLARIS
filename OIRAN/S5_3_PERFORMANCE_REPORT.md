# S5.3 performance report

Offline benchmark method: one warm-up followed by five measured runs on the same host and unchanged 13-file, 4,205-packet corpus.

| Metric | Result |
|---|---:|
| Median total time | 0.13 s |
| Median throughput | 32,346.15 packets/s |
| Median SBI rate | 1,523.08 transactions/s |
| Peak RSS | 6,796 KiB |

The measured path includes native corpus decode and SBI transaction production. Results are bounded functional measurements only; they are not 25G/100G or production scalability certification. Raw run data is in `benchmarks/S5_3_NATIVE_SBI/results/performance.json`.
