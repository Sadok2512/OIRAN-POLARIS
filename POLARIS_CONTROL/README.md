# POLARIS Control

Standalone operational console for bounded UERANSIM laboratory scenarios. Version `3.0.0-dev` adds a unified real-state console, independently reported node/UE/PDU/traffic lifecycles, measured telemetry, and persistent light/dark/system themes while preserving exact job ownership and fail-closed safety gates.

Live UE lifecycle supports a desired total from 1 through the ten statically provisioned profiles, including protected shared UE-01. Applying a count requires Operator authentication, CSRF, exact profile attestations, resource gates, and the deployment-time `POLARIS_ADDITIONAL_UE_LIVE_ENABLED=true` gate. The controller reconciles only the delta and never starts or stops shared UE-01, the shared gNB, or Open5GS. `max_ues_live_certified` remains 1 until separate live acceptance evidence exists.

## Build and validate

```bash
cargo test --workspace
cargo build --workspace --release
cd apps/web
npm run typecheck
npm test
npm run build
```

## Authorized local preview

```bash
cargo run --release -p polaris-control-api
```

The production process remains loopback-bound and is published through the fixed reverse proxy at `http://151.242.147.49:49153`.

The public-IP HTTP endpoint remains read-only. Authorized Operator and Administrator sessions use `https://polaris.etv-sadok.duckdns.org/`. Passwords are Argon2id-hashed in a root-readable server-side user database; the browser receives only an HttpOnly session cookie and a CSRF token.

Provision an Operator interactively on the VPS (the password is never passed on the command line):

```bash
sudo POLARIS_USERS_PATH=/var/lib/polaris-control/users.json \
  /root/POLARIS_CONTROL/target/release/polaris-userctl provision \
  --username operator --role operator
```

Then open the HTTPS application and sign in from **Settings**. Set the desired UE total in **Console** and choose **Apply desired count**; progress and per-UE failures are reported separately from observed running, registered, and PDU counts. Scenario traffic retains its independent validation step.
