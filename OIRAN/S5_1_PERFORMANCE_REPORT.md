# S5.1 bounded offline performance

One warm-up and five measured runs processed the same 13 files on the same host.

- Median total execution: 0.020 s.
- Range: 0.020–0.030 s.
- Median throughput: 210250.0 packets/s.
- Peak observed RSS: 4188 KiB.
- Mean observed CPU: 80.7%.
- Allocation count: NOT_MEASURED.

The corpus is small and `/usr/bin/time` has centisecond resolution, so these values are functional regression indicators, not production throughput or 25G/100G certification.
