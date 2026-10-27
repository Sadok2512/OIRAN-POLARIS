# OIRAN V2 Deployment Guide

## Build

```bash
cd /root/OIRAN_VPROBE
CARGO_BUILD_JOBS=2 cargo build --release -p oiran-api
cd apps/web
npm ci
npm run typecheck
npm test
npm run build
```

## Local startup

```bash
cd /root/OIRAN_VPROBE
OIRAN_API_BIND=127.0.0.1:49152 ./target/release/oiran-api
```

Health checks:

```bash
curl --fail http://127.0.0.1:49152/api/v1/health
curl --fail http://127.0.0.1:49152/api/v1/version
curl --fail http://127.0.0.1:49152/api/v1/metrics
```

## Rollback

Stop only the OIRAN API process, check out the previous OIRAN commit, rebuild the API/frontend, then start the same localhost listener. No database, Docker network, POLARIS or certified dataset rollback is required because V2 does not modify them.
