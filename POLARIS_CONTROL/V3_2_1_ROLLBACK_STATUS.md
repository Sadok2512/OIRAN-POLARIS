# V3.2.1 Rollback Status

Rollback is ready at:

`/root/POLARIS_CONTROL/backups/v3_2_1_20261026T223500Z`

The mode-0700 backup contains the previous API binary, frontend assets, systemd unit, application configuration and persistent controller registries. The previous API hash is `1f016dd2bc2dc2cd9dea93c2e99233b184ec1fd57aa86b26f917d6a7b64c4579`.

Rollback would restore these reviewed artifacts and restart only `polaris-control.service`. Persistent UE and traffic registries are preserved. Open5GS, UERANSIM, OIRAN, ETV and OTV are outside the rollback action.

Rollback was not required. Backup readability and hashes were verified.
