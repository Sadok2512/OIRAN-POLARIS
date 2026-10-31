# POLARIS Grant V2 production deployment report

Date: 2026-10-31 UTC
Agent: ANR2
Deployment authorization: explicitly granted by the user
Deployment verdict: **PASS**

## Released versions

| Component | Before | After | Deployed artifact |
|---|---:|---:|---|
| POLARIS API | 0.19.8 | **0.25.2** | `23f412d10a61f61c9d786e65327373f44e2c2208323d4f76f588768e9f58a98b` |
| POLARIS UI | historical production bundle | **0.18.2** | hashes listed below |
| Platform | 3.2.1 | 3.2.1 | unchanged |

Deployed Git SHA:
`2dd98d70adca010a5f142378278e50002d5c2c38` from
`release/polaris-grant-v2-prep-anr2`.

No grant was created. No LTE E2E test, UDP/TCP traffic, srsENB, srsUE, or
UERANSIM process was started. Open5GS, OIRAN, and external captures were not
modified or restarted.

## Git and preflight gates

```sh
git fetch origin release/polaris-grant-v2-prep-anr2
git rev-parse HEAD
git rev-parse origin/release/polaris-grant-v2-prep-anr2
# both: 2dd98d70adca010a5f142378278e50002d5c2c38

git merge-base --is-ancestor fef53408709580251c372c2253c28937f3efe852 HEAD
git merge-base --is-ancestor b0adf3b6c7dbd65cb674f2c06a9fcbff93b4c3bc HEAD
git merge-base --is-ancestor 29f8ef5 HEAD
git merge-base --is-ancestor a39e692 HEAD
# exit 0 for every base
```

Pre-activation gates:

```text
MemAvailable: 5,326,596 kB
used/non-available: 15,516,147,712 bytes
filesystem /: 53%
dumpcap: 12
```

These satisfy available RAM >= 4 GiB, used/non-available RAM <= 16 GiB, and
disk < 85%.

## Backup and rollback

Backup created before the first production edit:

```text
/var/backups/polaris-grant-v2/20261031T224450Z
mode: 0700 root:root
size: 41,361,042 bytes
manifested files: 55
sha256sum -c: 55 OK, 0 FAILED
manifest SHA-256: af7a93077ef0e6ebc0279c7039e06295e9c4acde1ba0f8667340c5c22814136a
```

The backup contains the old API binary, complete simulator UI directory,
frontend server, `versions.env`, Compose file, srsRAN configuration/runtime,
POLARIS environment, persistent state, audit log, systemd unit, and drop-ins.
Subscriber material is protected by the mode-0700 backup parent and is not
printed in this report.

Important rollback hashes:

```text
old API:   1e9030da06a40a6e3c5afffc20c1e5b4d8d3f3df64cb789a024d0c47dd92eca2
old UI index: 47010732beee1cd7b648416a9876af6ea306f20816f1c8cbb04295b624553420
old UI JS:    f2c58890df98f7c342307c9d6a6ddcdec1cd3a576a4716a52bb0408a95ac792c
old UI CSS:   1d2107098def07fcd7beca9cc9e4102584b3bb233fabb08b2174d2cdf5947e77
old versions.env: b29b92194588dda7644e7574cd214b8d085b880c7b966d86969c84f7d1f56d2e
```

Rollback script:

```text
/var/backups/polaris-grant-v2/20261031T224450Z/rollback.sh
SHA-256: 754614020e37a2a1e22b8c83b15cdf7f3311a0939d4bd66b242afb43c1365077
bash -n: PASS
isolated payload restore and byte comparison: PASS
```

The rollback was not executed because the complete recipe passed. The script
restores API, UI, configuration, state, audit data, and systemd definitions,
then requires API 0.19.8 to answer before succeeding.

## Certified srsRAN subject

Only this line changed in production `versions.env`:

```text
SRSRAN4G_IMAGE=oiran/srsran4g@sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43
```

The image is locally present with the same RepoDigest and image ID. Compose was
rendered but never started:

```sh
/usr/bin/timeout 10s /usr/bin/docker compose \
  --project-name oiran-lab --profile lte \
  --env-file /root/POLARIS/compose/versions.env \
  -f /root/POLARIS/compose/docker-compose.oiran-lab.yml \
  config --format json | jq -S -c . | tr -d '\n' | sha256sum

# 308053a274844259c16da7751708b39e6559cfec2b8d958dc4fcafebecd0da19
```

The deployed API independently reports the same digest for
`LTE-SRSUE-TEST-01`. Running srsRAN container count remained zero.

## Coordinated activation

The candidate binary and the three-file UI were staged and hash-checked. In a
single maintenance window only these services were stopped and started:

```sh
systemctl stop polaris-control.service oiran-polaris-preview.service
# atomic rename of the staged API and UI into their final paths
systemctl start polaris-control.service oiran-polaris-preview.service
```

Both services are active with `NRestarts=0`. No other service restart command
was issued.

Deployed UI hashes match the candidate exactly:

```text
b0b1356ed47d72a508a325ebfe660dea9b70e773262893f0308ed4814a06344d  index.html
83ee901539c019a9db5d4366e884edf665a0acd95e26ca708c532ca5b9c6a472  index-Bwcm9z8L.css
a940acedea620085db0b94a128e26d91ab0d70bf51114b87dc1a302484b2e077  index-DePFJ2pi.js
```

Public production verification:

```text
GET https://151.242.147.49:8020/simulator/ -> HTTP 200
GET /simulator/assets/index-DePFJ2pi.js -> HTTP 200
```

## API recipe

All requests below were read-only unless explicitly marked as a rejected
negative-security request.

| Route | HTTP | Verified result |
|---|---:|---|
| `GET /api/v1/version` | 200 | API 0.25.2, platform 3.2.1, `staging_read_only=false` |
| `GET /api/v1/health` | 200 | status `ok` |
| `GET /api/v1/system/health` | 200 | valid health payload |
| `GET /api/v1/lte/status` | 200 | S1/Attach/session `UNKNOWN`, IP null, sessions 0, grant/live/traffic false |
| `GET /api/v1/lte/profiles/LTE-SRSUE-TEST-01` | 200 | LTE/srsUE, owner POLARIS_CONTROLLER, disabled, runtime UNKNOWN, certified Compose digest |
| `GET /api/v1/live/grant` | 200 | 0 grants |
| `GET /api/v1/ues` | 200 | 3 records from current NAS/PDU and controller registry |
| `GET /api/v1/ue-profiles` | 200 | 2 profiles |
| `GET /api/v1/subscribers` | 200 | 3 protected records |
| `GET /api/v1/scenario-templates` | 200 | exactly 13 templates |
| `GET /api/v1/traffic/sessions` | 200 | 0 sessions, no fabricated counters |

The LTE state remained fail-closed: no S1, Attach, IP, or session was inferred
without evidence.

## RBAC, CSRF, replay, and privacy

Production negative HTTP checks:

```text
POST /api/v1/live/grant without session -> HTTP 403 OPERATOR_PERMISSION_REQUIRED
POST /api/v1/lte/runs with schema-valid inert body, without session
  -> HTTP 403 OPERATOR_PERMISSION_REQUIRED
PATCH /api/v1/lte/profiles/LTE-SRSUE-TEST-01 without session
  -> HTTP 403 ADMINISTRATOR_PERMISSION_REQUIRED
grant count before/after: 0 / 0
```

One preliminary malformed `{}` LTE-run request returned HTTP 422 at JSON schema
extraction. It had no side effect. The schema-valid repeat above proved the
RBAC gate.

Manual tests against the exact deployed source and binary candidate:

```text
lte_grant::tests: 6/6 PASS
operator + CSRF before Grant V2 schema processing: PASS
one-time consumption, subject binding, wrong role/session: PASS
expiry, revocation, wrong nonce, idempotency conflict and replay: PASS
private persistent 0600 store; plaintext nonce absent: PASS
viewer/operator IMSI projection: PASS
traffic requires an active Grant V2: PASS
```

No real grant or authenticated mutation was used for these checks. Anonymous
production bodies for UE, profile, and subscriber reads produced:

```text
DEMO hits: 0
14-16 digit subscriber identity hits: 0
subscriber-secret key paths: 0
```

## Frontend and Playwright

A production-only read test used Node 20.20.2 and the deployed loopback UI. It
performed GET requests only.

```sh
npx playwright test --config=/tmp/polaris-prod-e2e/playwright.config.js
# 6 passed in 1.5m
```

PASS combinations:

- 1280x800 light and dark;
- 1440x900 light and dark;
- 1920x1080 light and dark.

It verified API 0.25.2, zero grants, both LTE srsRAN and 5G UERANSIM topology
chains, UE Manager LTE/srsUE fields, 13 scenario templates, Traffic Generator,
no horizontal overflow, and no visible DEMO data. Evidence screenshot:

```text
/var/backups/polaris-grant-v2/20261031T224450Z/topology-production-1440.png
SHA-256: 436c3d51eb866e1bc75a97261134123ab0369bd2988d4aa196732a787f57ed35
```

## Post-deployment infrastructure gates

```text
MemAvailable: 5,055,132 kB (4.82 GiB) — PASS
used/non-available: 15,794,126,848 bytes (14.71 GiB) — PASS
filesystem /: 53% — PASS
POLARIS API errors since activation: 0
```

All dumpcap PIDs are identical before and after:

```text
3467795 3467803 3467812 3467820 3467829 3467837
3467849 3467861 3467863 3467870 3467880 3467881
```

- 12/12 dumpcap preserved.
- OIRAN API still reports 2.5.4; `oiran-api` and capture helper retain their
  pre-deployment start times and `NRestarts=0`.
- 15 Open5GS containers remain healthy and have uptimes of 3 or 7 days.
- The pre-existing UERANSIM gNB remains healthy with seven-day uptime; it was
  not restarted.
- srsENB/srsUE running count is 0.

## Final status

```text
DEPLOYMENT = PASS
API_VERSION = 0.25.2
UI_VERSION = 0.18.2
DEPLOYED_SHA = 2dd98d70adca010a5f142378278e50002d5c2c38
COMPOSE_DIGEST = 308053a274844259c16da7751708b39e6559cfec2b8d958dc4fcafebecd0da19
GIT_LINEAGE = PASS
BACKUP = PASS, 55/55 hashes verified
API_ROUTES = PASS
UI_REAL_DATA = PASS
RBAC_SECURITY = PASS (negative HTTP + exact-source tests; no real grant)
DUMPCAP = PASS, 12/12 same PIDs
RAM = PASS
DISK = PASS, 53%
ROLLBACK_STATUS = READY_AND_DRY_RESTORE_TESTED; NOT_REQUIRED
BLOCKERS = NONE FOR THIS DEPLOYMENT; LTE E2E remains separately uncertified/not run
```

— ANR2
