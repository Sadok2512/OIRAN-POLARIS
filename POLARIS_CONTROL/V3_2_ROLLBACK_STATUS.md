# V3.2 Rollback Status

Rollback is ready at `/root/POLARIS_CONTROL/deployment/backups/20261026T2144Z_pre_ue_targeted`.

The mode-0700 backup contains the previous API binary, frontend assets, service unit, application configuration, UE profile/job registry, traffic/scenario job registry, authentication references, provisioning attestation and release manifests. Its SHA256 manifest was verified after creation. Secret-bearing files retain restricted permissions and are not reproduced in reports.

Rollback requires restoration of only POLARIS Control artifacts and restart of only `polaris-control.service`. No rollback was needed.

