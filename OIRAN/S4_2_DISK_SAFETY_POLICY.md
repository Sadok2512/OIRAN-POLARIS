# S4.2 mandatory disk safety policy

This policy is enforced by `disk-safety` 0.2.0 for every OIRAN-owned capture writer.

| Usage | State | Capture behavior |
|---:|---|---|
| <95% | NORMAL | may start only after projected-budget approval |
| ≥95% | INFORMATION | operator information; bounded capture may start |
| ≥97% and <98% | WARNING | warning; bounded capture may start only if the absolute reserve remains intact |
| ≥98% | DISK_HARD_LIMIT | reject all OIRAN capture writes; keep read-only analysis and cleanup available |

The guard measures bytes and inodes with `statvfs`, fails closed on measurement failure, and authorizes each write against a reserved per-job budget. Default bounds are 256 MiB per file, eight files, 2 GiB per job, 15 minutes, one concurrent job, one-second active polling and an 8 GiB absolute free-space reserve. A job is refused if its complete projected budget would reach 98%, consume the reserve, exhaust inodes, or if measurements fail. ENOSPC and unexpected growth remain fatal to the writer; cleanup and read-only analysis remain available.

Polling is not the sole limit: the monotonically decreasing write budget caps bytes between samples. Thresholds are evaluated before start and before every writer authorization. No delete API or cleanup action exists.
