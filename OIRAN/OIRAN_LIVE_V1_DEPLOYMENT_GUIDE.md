# OIRAN Live V1 Deployment Guide

Build with `cargo build --release -p oiran-api` and `cd apps/web && npm run build`. Bind the API to `127.0.0.1:49152`.

Required configuration:

- `OIRAN_WORKSPACE=/root/OIRAN_VPROBE`
- `OIRAN_API_BIND=127.0.0.1:49152`
- `OIRAN_OPERATOR_TOKEN_SHA256=<sha256 fingerprint>` and/or `OIRAN_ADMIN_TOKEN_SHA256=<sha256 fingerprint>`
- `OIRAN_CAPTURE_EXECUTION_ENABLED=1` only for an approved deployment/test window

Generate the fingerprint without writing the plaintext token to project files. Supply the token to the authorized operator out of band. Run capture under a dedicated service identity with only the packet-capture capability required for the three approved bridges. Keep the external gateway and role policy separate from telecom interfaces.

Rollback: disable `OIRAN_CAPTURE_EXECUTION_ENABLED`, gracefully stop any exact OIRAN-owned job through its API, restart only the OIRAN API if required, and retain job/PCAP evidence. Never remove POLARIS or certified data.
