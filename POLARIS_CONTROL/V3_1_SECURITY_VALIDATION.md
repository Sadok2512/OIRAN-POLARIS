# V3.1 Security Validation

- HTTPS Operator authentication: PASS.
- One enabled Operator account was detected; no password hash or credential is included here.
- Viewer mutation denial, server-side role enforcement and CSRF enforcement: PASS.
- New UE lifecycle remains locked behind LIVE-002/003/004 approval and provisioning.
- New gNB lifecycle remains locked behind LIVE-005 approval.
- Shared UE/gNB are non-controller-owned and cannot be stopped through the new endpoints.
- Systemd retains `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `MemoryMax=256M` and `CPUQuota=100%`.
- POLARIS lab files remain read-only to the service; only `/var/lib/polaris-control` and `/var/log/polaris-control` are writable.
- The UE registry defaults to `/var/lib/polaris-control/ue-jobs.json`, uses atomic mode-0600 writes, and remains absent until the first authorized controller-owned UE action.

Residual limitation: the existing service identity is `root`. This deployment preserved the reviewed service model and introduced no additional privilege. Migrating to a dedicated service account requires a separate compatibility review.

