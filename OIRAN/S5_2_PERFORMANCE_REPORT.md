# S5.2 Performance Report

Bounded offline measurement used one warm-up and five measured full-corpus runs on the same host.

- Median total time: 0.04 s.
- Median throughput: 105,125 packets/s.
- Median NAS event rate: 2,900 events/s.
- Peak RSS: 4,492 KiB.
- Corpus: 13 files / 4,205 packets.

The dataset is small and `/usr/bin/time` has centisecond resolution, so these values are regression indicators only. They are not a 25G/100G or production scalability certification. Full runs are in `benchmarks/S5_2_NATIVE_NAS/results/performance.json`.
