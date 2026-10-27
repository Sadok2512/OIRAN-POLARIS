# S4.2 mandatory disk safety policy

This policy is enforced by `disk-safety` 0.1.0 for every future OIRAN-owned capture writer.

| Usage | State | Capture behavior |
|---:|---|---|
| <75% | NORMAL | may start only after budget approval |
| ≥75% | INFORMATION | operator information; bounded capture may start |
| ≥80% | WARNING | warning; bounded capture may start only within reserved budget |
| ≥85% | STOP_NEW_CAPTURES | reject new jobs and gracefully finalize active OIRAN writers |
| ≥90% | DISK_HARD_LIMIT | reject all OIRAN capture writes; keep read-only analysis |

The guard measures bytes and inodes with `statvfs`, fails closed on measurement failure, and authorizes each write against a reserved per-job budget. Default bounds are 256 MiB per file, eight files, 2 GiB per job, 15 minutes, one concurrent job, one-second active polling and a 32 MiB between-poll reserve. A job is refused if the complete requested budget plus reserve cannot remain below 85% or if inodes are insufficient.

Polling is not the sole limit: the monotonically decreasing write budget caps bytes between samples. Thresholds are evaluated before start and before every writer authorization. No delete API or cleanup action exists.
