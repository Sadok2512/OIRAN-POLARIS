# V3.1 Rollback Status

Rollback is prepared but was not required.

Private backup: `deployment/backups/20261025T2307Z_pre_v3_1`

It contains the prior API binary, frontend assets, systemd unit, environment configuration, version manifest, users, scenario registry and audit log. Authentication material is protected with mode `0600` and excluded from Git.

If rollback is authorized, stop only `polaris-control.service`, restore the backed-up API/frontend/unit/configuration and compatible registries, reload systemd, then start only `polaris-control.service`. Verify API 0.6.0, historical scenario visibility and the unchanged shared UE/gNB. Never restart Open5GS, UERANSIM, OIRAN, ETV or OTV as part of this rollback.

The pre-deployment `jobs.json` SHA256 and the post-deployment SHA256 are both `4edb6c81cab37d2fd8f29e61949a30061b2ac194671ab027c97efc386758c65a`, proving scenario history was preserved.

