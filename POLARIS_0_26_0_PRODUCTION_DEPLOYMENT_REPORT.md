# POLARIS 0.26.0 production deployment report

Date: 2026-10-31 UTC  
Agent: ANR2  
Authorization: explicitly granted by the user  
Activation: `2026-10-31T23:43:28Z`

## Verdict

**DEPLOYMENT = PASS**

POLARIS API 0.26.0 and UI 0.19.0 were activated as one coordinated release. Only `polaris-control.service` and `oiran-polaris-preview.service` were stopped and started. No grant was created, no LTE/5G simulator or traffic was started, and Open5GS, OIRAN, UERANSIM and external captures were not modified or restarted.

## Git and released artifacts

```text
release branch = fix/polaris-lte-certification-gate-p0-anr2
deployed SHA   = 4669de8b5d9165e2176d8394931b821415ee100a
remote SHA     = 4669de8b5d9165e2176d8394931b821415ee100a
production base = 2dd98d70adca010a5f142378278e50002d5c2c38
git merge-base --is-ancestor base deployed = exit 0
```

Deployed hashes equal the candidates built from that exact commit:

```text
5d042aa4620f4d92c05f5d73ef316dfc1df18940d78a58a7eb4ab5ee43f27fc8  polaris-control-api
cf04e0eb50dd263e22deaa37fc8e0a30c0c7173730d3a07a99559ce0671838fe  simulator/index.html
83ee901539c019a9db5d4366e884edf665a0acd95e26ca708c532ca5b9c6a472  index-Bwcm9z8L.css
212714b3a96c85c8ee390dfa77c095d64b6cd738fa37f0fc74c1cabc776ff87b  index-CcMRPPo_.js
```

`GET /polaris-api/v1/version` returns API `0.26.0`, platform `3.2.1`; the public simulator returns HTTP 200 and the new `index-CcMRPPo_.js` bundle.

## Backup and rollback

Backup created before the first production edit:

```text
/var/backups/polaris-0.26.0/20261031T234241Z
mode = 0700, root:root
size = 42,734,770 bytes before evidence screenshots
manifested files = 52
SHA256SUMS SHA-256 = 30bf5aab5439931d50256efaca9b240eb2b525ee7d95c85171f0fcddc633e022
sha256sum -c = 52 OK, 0 failed
```

It contains the previous API, complete simulator UI, frontend server, POLARIS environment, Compose/version files, srsRAN configuration, persistent state, audit data and the relevant systemd unit/drop-ins. Subscriber material remains inside the mode-0700 backup and is never printed.

Rollback:

```text
/var/backups/polaris-0.26.0/20261031T234241Z/rollback.sh
SHA-256 = fcdcb1e2397beed7e60d0ab542411883a9c5bca699e18f66e686cd068b544bef
bash -n = PASS
isolated API/environment/UI restoration and byte comparison = PASS
```

The rollback restores API 0.25.2, UI 0.18.2 and the previous environment, restarts only the two POLARIS units, verifies API/UI and requires twelve dumpcap processes. It was not executed because the complete recipe passed. Persistent Grant/run stores are not blindly overwritten by the rollback.

## Coordinated activation

The environment was staged, validated for exactly one occurrence of each gate, mode 0600, then atomically renamed with the API and UI:

```text
POLARIS_SRSRAN_LIVE_ENABLED=true
POLARIS_LTE_CERTIFICATION_RUN_ENABLED=true
POLARIS_LTE_E2E_CERTIFIED=false
```

Only these service operations were issued:

```sh
systemctl stop polaris-control.service oiran-polaris-preview.service
# atomic renames of staged API, UI and environment
systemctl start polaris-control.service oiran-polaris-preview.service
```

Both units are active/running with `NRestarts=0`; their activation time is `2026-10-31 23:43:27 UTC`. Error-level journal entries since activation: API 0, preview 0.

## LTE certification gate

Production `GET /lte/status` returns:

```json
{
  "certified": false,
  "live_enabled": true,
  "operation_mode": "CERTIFICATION_RUN",
  "certification_state": "CERTIFICATION_PENDING",
  "certification_run_enabled": true,
  "manual_certification_required": true,
  "grant_active": false,
  "traffic_ready": false,
  "s1_state": "UNKNOWN",
  "attach_state": "UNKNOWN",
  "ue_ip": null,
  "active_sessions": 0
}
```

The exact persistent profile is owned by `POLARIS_CONTROLLER`, revision 1, limited to one UE, and deliberately remains `enabled=false` until a separately authorized certification execution. Its Compose digest is `308053a274844259c16da7751708b39e6559cfec2b8d958dc4fcafebecd0da19`.

The certified image ID and RepoDigest both equal `sha256:69e094349657cc6a062ce3717661d6b8a553a23ce571f821e33256beec753d43`. A read-only Compose render produced the expected canonical digest. No srsENB or srsUE container exists.

`LIVE_OPERATIONAL` is not the published mode while certification is false. Exact-source negative tests also prove that an operational-purpose Grant is rejected in certification mode. No production Grant was needed to establish this gate.

## API, real-data and security recipe

Read-only production results:

| Check | Result |
|---|---|
| health/version | HTTP 200, API 0.26.0 |
| LTE status/profile | HTTP 200; pending, uncertified, no inferred S1/Attach/IP/session |
| grants | 0 |
| UEs | 3, source `CURRENT_NAS_PDU_AND_CONTROLLER_REGISTRY` |
| UE profiles | 2 |
| nodes | 2, source `CONTROLLER_AND_RUNTIME_OBSERVATIONS` |
| scenario templates | exactly 13 |
| traffic sessions | 0 |
| production response scan | 0 `DEMO`, 0 clear IMSI/SUPI, 0 subscriber-secret keys |

Production negative requests used schema-valid inert bodies and no authenticated session:

```text
POST /live/grant purpose LIVE_OPERATIONAL -> 403 OPERATOR_PERMISSION_REQUIRED
POST /lte/runs -> 403 OPERATOR_PERMISSION_REQUIRED
PATCH exact LTE profile enabled=true -> 403 ADMINISTRATOR_PERMISSION_REQUIRED
grant count before/after = 0 / 0
```

Exact-release offline security tests after deployment:

```text
lte_grant::tests = 7/7 PASS
certification/digest tests = 4/4 PASS
RBAC + CSRF ordering = PASS
emergency cleanup after grant expiry/revocation = PASS
```

These cover subject/session ownership, nonce hashing, expiration, revocation, one-time consumption, anti-replay/idempotency, exact certified digests and the bounded action envelope without creating a real grant.

Frontend critical tests: 4 files, 26/26 PASS. TypeScript and production build also PASS under isolated Node 20.20.0.

## Public Playwright recipe

A strictly read-only browser test used the real public URL and issued only GET/navigation actions. Six projects passed:

- 1280x800 light/dark;
- 1440x900 light/dark;
- 1920x1080 light/dark.

It verified API 0.26.0, `CERTIFICATION_RUN`, `CERTIFICATION_PENDING`, `certified=false`, zero grants, 13 templates, visible UERANSIM and srsENB topology, UE Manager, Scenario Library, Traffic Generator, no `DEMO`, and no horizontal overflow. Because the exact LTE profile is intentionally disabled, the UI certification Start button remains disabled.

Evidence screenshot:

```text
/var/backups/polaris-0.26.0/20261031T234241Z/production-0.26.0-1440.png
SHA-256 = bee5069cf2b757638c8741e4da90bc684435bb2ab342b0980734c4e1ffa225cd
```

## Infrastructure continuity

Final resource gates:

```text
RAM total     = 20,970,582,016 bytes
RAM used      = 16,075,038,720 bytes (below 16 GiB)
RAM available = 4,895,543,296 bytes (above 4 GiB)
disk /root    = 54%
```

All twelve dumpcap PIDs and start times are identical before/after deployment:

```text
3691817 3691819 3691835 3691841 3691851 3691867
3691868 3691894 3691899 3691902 3691904 3691905
```

- OIRAN API remains 2.5.4; `oiran-api.service` and `oiran-capture-helper.service` retained their PID, activation time and `NRestarts=0`.
- All 17 observed Open5GS core containers remain healthy.
- UERANSIM gNB retained container `c9bddd91a8bc`, seven-day uptime and healthy state.
- srsRAN running count remains 0.
- The unrelated transient `polaris-portal.service` was already in auto-restart/203 before this maintenance. The production listener on port 8020 uses the healthy `oiran-polaris-preview.service`; it was not necessary or authorized to alter the transient service.

## Final status

```text
DEPLOYMENT = PASS
API_VERSION = 0.26.0
UI_VERSION = 0.19.0
DEPLOYED_SHA = 4669de8b5d9165e2176d8394931b821415ee100a
GIT_LINEAGE = PASS
BACKUP = PASS; 52/52 hashes verified
CERTIFICATION_RUN = AVAILABLE / PENDING; exact profile remains disabled
LTE_E2E_CERTIFIED = false
LIVE_OPERATIONAL_GATE = BLOCKED while uncertified
API_ROUTES = PASS
UI_REAL_DATA = PASS; no DEMO
SECURITY = PASS; negative HTTP + exact-source tests, zero real grants
DUMPCAP = PASS; 12/12 same PID/start time
RAM = PASS
DISK = PASS; 54%
ROLLBACK_STATUS = READY_AND_DRY_RESTORE_TESTED; NOT_REQUIRED
BLOCKERS = none for deployment; real LTE E2E remains separately unauthorized/not run
```

— ANR2
