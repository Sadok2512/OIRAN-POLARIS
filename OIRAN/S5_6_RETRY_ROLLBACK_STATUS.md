# S5.6 Retry Rollback Status

Rollback is ready at:

`/var/backups/oiran/s5_6_retry_20261026T210023Z`

The backup contains the previous API/helper binaries, frontend assets, systemd units/drop-ins, protected OIRAN configuration, capture/dataset registries and release manifests. It contains 56 files (20,390,760 bytes). `SHA256SUMS` verification passed before deployment.

The previous frontend directory is additionally retained at the exact path recorded in `/tmp/s5_6_retry_frontend_rollback_path`. Rollback requires restarting only the two OIRAN services. It must not restore or enable the legacy tcpdump path.

Rollback was not required because all critical post-deployment checks passed.

