# Rollback Plan

1. Before deployment, snapshot installed binaries, frontend assets, systemd units/drop-ins, configuration, and registries with SHA256.
2. Refuse deployment while any controller-owned job is active.
3. Install candidate artifacts atomically and restart only the affected application.
4. On critical verification failure, restore the captured prior artifacts and restart only that application.
5. Verify authentication, historical analysis, registries, IPC where applicable, and shared UE/gNB health.
6. Keep live execution disabled. Never restore the legacy tcpdump backend and never delete capture evidence.

This plan was prepared only; no rollback or deployment action was executed.
