# Codex POLARIS 0.29.0 Production Deployment Report

Mission: `NS-20261101-CODEX-DEPLOY-0290`  
Date UTC: 2026-11-01  
Host: `OIRAN`  
Executor: ANR3/Codex

## Result

```text
DEPLOYMENT = PASS
VERSION = POLARIS API 0.29.0 / Platform 3.2.1
RUNNING_SHA256 = cde36bd2451800104d6bce0758d2bc0f9f0eb38e872632006e887a5d3dc8b97e
CONFIG = PASS — POLARIS_LTE_TRAFFIC_PEER_IP=10.77.24.30; drop-in SHA256 1c3005f27dcebc84ba2ace30e3a1a541f261ce2d4826c0147428244d700826dc
BACKUP = PASS — /var/backups/polaris-control/20261101T225900Z-pre-0290
HEALTH = PASS — loopback /api/v1/version and /api/v1/health HTTP 200; simulator URL 5/5 HTTP 200
SECURITY = PASS_WITH_LIMITATION — unauthenticated Grant V2 creation denied HTTP 403; zero grant/run mutation; CSRF guard present in exact deployed source, but no authenticated mutation was attempted
OIRAN_UNCHANGED = PASS — 2.7.4, PID unchanged, SHA256 2b88a78f2667a1a94caddfee7bb11367bc94ef5b78a1aac3dd0d5873c157b0a3, healthy
DUMPCAP = PASS — 12 processes, unchanged PID-set SHA256 d98a34975a285f21fb627e060689f40860cf7b5c681503c1e5c66913484dba41
RAM = PASS — used 11408039936 bytes; available 9562542080 bytes
DISK = PASS_WITH_WARNING — used 332488314880 bytes; available 82416402432 bytes; 81%
ROLLBACK = READY_NOT_USED — no candidate-critical failure
BLOCKERS = intermittent TLS handshake failure observed on direct polaris.etv-sadok.duckdns.org probes; Caddy was not changed and the authorized simulator URL remained 5/5 HTTP 200
```

No LTE/5G grant, UE, RAN component, traffic, capture, PCAP processing, Open5GS change, OIRAN change, or collector change occurred.

## Authorization and pre-flight

The direct ChatGPT instruction and GitHub Issue #10 comment `6565141878`, authored by `Sadok2512`, explicitly authorized ANR3/Codex on host OIRAN to deploy only:

- source `6734c75891832cce83edbfd3e5e622a8289835e6`;
- binary SHA256 `cde36bd2451800104d6bce0758d2bc0f9f0eb38e872632006e887a5d3dc8b97e`;
- `Environment=POLARIS_LTE_TRAFFIC_PEER_IP=10.77.24.30`;
- restart of `polaris-control.service` only.

Pre-flight proved: clean candidate worktree at the exact source SHA, exact binary hash, production 0.28.3 hash `9e7eefd...aeae`, 0 active grants, 0 nonterminal LTE runs, 0 running srsENB/srsUE containers, 12 dumpcap processes, no concurrent deployment/build, 15 identified Open5GS containers healthy, and resource gates passing.

## Backup and rollback

Fresh backup root: `/var/backups/polaris-control/20261101T225900Z-pre-0290`, mode `0700`.

| Backup object | SHA256 |
|---|---|
| POLARIS 0.28.3 binary | `9e7eefd24f8f53a6259920fc03302741854e45611e106cf4ab715c233842aeae` |
| systemd unit | `906bcf92a55914f132a3266dd2ab1e6291a872fc6a1468438d505b717dc50877` |
| former DL sender drop-in | `0ed1a267f6ea6afdbadbc44aaf2a2f09700105723fb98a1979bef72dfaa7d725` |
| iperf drop-in | `5d128e6e5bbfd85b4650d0aa19055e8e46ea7617131272172595abc73f73c131` |
| configuration registry | `0c01d66132125baf652f45006472e9a7464cbf6a36381f3d1234aec7861c0e9b` |

The exact rollback consists of restoring those files, daemon-reloading systemd, restarting only POLARIS, and verifying version 0.28.3, the old running hash, resources, OIRAN/Open5GS health and the same dumpcap PID set. It was not used because the candidate service itself passed the deployment recipe.

## Applied changes

1. Copied the canonical candidate to a temporary file in the active binary directory.
2. Reverified the temporary binary SHA256.
3. Added only the authorized Traffic Peer environment line to the existing DL sender drop-in. The resulting drop-in exactly matches the reviewed candidate file.
4. Ran `systemd-analyze verify` successfully and `systemctl daemon-reload`.
5. Atomically replaced the active binary.
6. Restarted only `polaris-control.service`.

New service PID: `3497221`; activation time: `2026-11-01 22:57:59 UTC`.

## Production recipe

- `/api/v1/version`: HTTP 200, API `0.29.0`, platform `3.2.1`, `staging_read_only=false`.
- `/api/v1/health`: HTTP 200, status `ok`, version `0.29.0`.
- Running `/proc/3497221/exe` SHA256 exactly equals the authorized candidate.
- Effective systemd environment contains both DL sender and LTE traffic peer at `10.77.24.30`.
- DL sender container remained healthy.
- Finalizer route is registered: an unauthenticated malformed request returned HTTP 422 rather than the former 404/405, and did not alter state.
- Unauthenticated `POST /api/v1/live/grant` returned HTTP 403 `OPERATOR_PERMISSION_REQUIRED`.
- Grant count remained 5 stored / 0 active; LTE run count remained 5 / 0 nonterminal.
- No POLARIS journal error/fatal/panic match after restart.
- `https://151.242.147.49:8020/simulator/` returned HTTP 200 in five consecutive checks.
- Direct `polaris.etv-sadok.duckdns.org` health succeeded once but subsequent TLS handshakes were intermittent. Caddy stayed active, had zero recorded error matches and was not modified. This is reported separately instead of being concealed or incorrectly attributed to the API binary.

## Preserved components

- OIRAN remained active and healthy at 2.7.4 with its original PID and executable hash.
- 15 identified Open5GS EPC/5GC containers remained healthy; summed restart count was zero.
- The 12 dumpcap PID set was identical before and after deployment.
- Final state: 0 active grants, 0 nonterminal LTE runs, 0 running srsENB/srsUE containers.

## Commands executed

```bash
gh api repos/Sadok2512/OIRAN-POLARIS/issues/10/comments ...
git rev-parse HEAD; git status --short
sha256sum <candidate> /proc/<pid>/exe
systemctl show polaris-control.service ...
free -b; df -B1 ...
pgrep -x dumpcap
docker ps ...
install -d ...; cp --archive ...
systemd-analyze verify /etc/systemd/system/polaris-control.service
systemctl daemon-reload
systemctl restart polaris-control.service
curl ... /api/v1/version /api/v1/health
```

No test LTE live was performed.

— ANR3
