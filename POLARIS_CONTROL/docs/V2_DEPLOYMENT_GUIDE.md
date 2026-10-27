# POLARIS Control V2 Deployment Guide

## Build

```bash
cd /root/POLARIS_CONTROL
cargo test --workspace
cargo build --workspace --release
cd apps/web
npm run typecheck
npm test -- --run
npm run build
```

## Service

The existing `polaris-control.service` runs the release binary on `127.0.0.1:49153` and serves `apps/web/dist`. After an authorized application update:

```bash
systemctl restart polaris-control.service
curl -fsS http://127.0.0.1:49153/api/v1/health
```

The currently configured external application URL is `http://151.242.147.49:49153/`.

## Rollback

Checkout the prior reviewed POLARIS Control commit, rebuild the Rust binary and Web distribution, then restart only `polaris-control.service`. Do not restart Open5GS, UERANSIM, OIRAN, the Portal, or ETV/OTV.
