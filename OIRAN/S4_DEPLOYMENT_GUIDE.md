# S4 Deployment Guide

## Prerequisites

- Rust/Cargo 1.75 or compatible toolchain.
- Node 22.23.4 (a project-local development runtime is pinned).
- Immutable S3.3 artifacts in `/root/OIRAN_VPROBE`.

## Build and validate

```bash
cd /root/OIRAN_VPROBE
cargo build --release -p oiran-api
cargo test --release --workspace
cd apps/web
npm ci
npm run typecheck
npm test
npm run build
```

## Authorized temporary local startup

```bash
cd /root/OIRAN_VPROBE
OIRAN_API_BIND=127.0.0.1:49152 \
./target/release/oiran-api
```

Health check:

```bash
curl http://127.0.0.1:49152/api/v1/health
```

The same process serves `apps/web/dist`. S4 does not install or start `deployment/oiran-api.service`; that template requires separate approval and security review. Do not expose port 49152 publicly or alter an existing reverse proxy without approval.

## Rollback

Stop only the explicitly launched OIRAN API process with `Ctrl-C`. Because the service is read-only and no persistent state is created, rollback requires no database, Docker, network or dataset action. Revert the S4 Git commit to remove application code. Never remove certified datasets as part of rollback.
