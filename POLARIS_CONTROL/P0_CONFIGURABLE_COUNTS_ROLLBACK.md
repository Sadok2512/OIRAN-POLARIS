# P0 Configurable Counts Rollback

Before deployment, preserve the current executable, frontend assets, systemd unit, environment configuration, version manifest, authentication registry, scenario registries, and audit state in a private timestamped backup directory.

If verification fails:

1. Restore the prior API executable and frontend assets.
2. Restore the prior systemd unit and environment configuration.
3. Reload systemd and restart only `polaris-control.service`.
4. Verify API health, authentication, the existing shared gNB/UE, and the certified bounded traffic workflow.
5. Keep new UE/gNB execution locked.

Rollback does not touch Open5GS, shared UERANSIM processes, OIRAN, POLARIS, ETV, or OTV.
