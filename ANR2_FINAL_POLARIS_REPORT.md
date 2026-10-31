# ANR2 — Final POLARIS report

Date UTC: 2026-10-31  
Agent: ANR2  
Verdict: **PARTIAL / DEPLOYMENT BLOCKED**

## Versions and lineage

- Branch: `fix/polaris-srsran-lte-hardening-v1`
- Requested base: `3f8f0ee2b1e2025db5bf9be5c87e46cb1ee92e64`
- Implementation commit: `491ec9c`
- API: `polaris-control-api 0.21.1`
- Frontend: `@telecom/simulator-control 0.14.1`
- `git merge-base --is-ancestor 3f8f0ee2 HEAD` -> exit 0
- `git merge-base --is-ancestor a39e692b416ac4fd2ebbbf0a10b6d09f6e56ad78 HEAD` -> exit 0 (frontend 0.13.1 preserved)
- `git merge-base --is-ancestor 29f8ef5 HEAD` -> exit 0 (API 0.20.1 lineage preserved)

No merge, deployment, production restart, live grant or simulator/traffic launch was performed.

## Real laboratory architecture observed read-only

Authoritative Compose input: `/root/POLARIS/compose/docker-compose.oiran-lab.yml`, project `oiran-lab`, environment file `/root/POLARIS/compose/versions.env`, LTE profile `lte`.

| Component | Compose service | Command/config evidence |
|---|---|---|
| LTE eNodeB | `srsenb` | `srsenb /etc/srsran/enb.conf`; read-only mount `../config/srsran:/etc/srsran` |
| LTE UE | `srsue` | `srsue /run/secrets/ue.conf`; read-only mount `../runtime/srsran:/run/secrets` |
| EPC | `mme` | Existing shared EPC dependency; never controlled by this change |

Configuration inventory was inspected by metadata only: `enb.conf`, `drb.conf`, `rr.conf`, `sib.conf`, `ue.conf.template`; runtime `ue.conf` is mode 0600. Subscriber secrets were not printed or copied.

At final read-only check, no `srsenb` or `srsue` container existed. This is reported as `UNKNOWN`/not observed, not as a successful S1 Setup or Attach.

## Implemented controls

- Compose service discovery uses exact labels for project, service and authoritative config file. No assumed container name and no HTTP-supplied Docker target.
- Controller ownership survives API restart in an atomic mode-0600 ledger containing exact container IDs. Existing/unowned or ambiguous instances are observable but cannot be started, stopped or used for traffic.
- Docker, Compose and exec operations use host-enforced TERM/KILL timeouts. Partial create/start failures clean only the exact new container; rollback failure has a distinct error.
- Stop is grant-exempt for safety but still requires verified ownership. srsENB stop is refused while srsUE is running.
- S1 is based on a current SCTP socket observation; UE IP on current `tun_srsue`; Attach/session become valid only when current S1 and UE IP agree. Unverifiable values are `UNKNOWN`; stale log text is not state.
- Logs are bounded and redact IMSI/SUPI/OPc/key markers.
- LTE Scenario Builder steps execute through the same controller: Attach, Detach, UL, DL and Attach+Data. Cancellation and terminal cleanup route through controller-owned Stop.
- LTE Traffic Generator accepts only `LTE-UE-01`, is separate from the legacy 5G synthetic path, and requires certification, live enablement, active grant, ownership, current Attach/IP/session, peer configuration and resource gates. UDP/TCP and UL/DL/BOTH use bounded iperf3 JSON measurements.
- Grant V2 adds operator ownership, CSRF/RBAC, expiry/revocation, random IDs and a persistent mode-0600 SHA-256 nonce journal. A replay is rejected with HTTP 409. Active grants themselves remain non-persistent elevation and disappear on API restart.
- Frontend controls derive their enabled state from certification, active grant, safety and verified ownership; responsive LTE coverage remains at 1280/1440/1920. 5G paths were not changed.

## Offline tests and exact results

| Command | Result |
|---|---|
| `cargo check --locked -p polaris-control-api` | PASS; API 0.21.1; 5 pre-existing dead-code warnings |
| `cargo test -p polaris-control-api --lib` | PASS; **205 passed, 0 failed, 3 ignored**; 129.84 s |
| `npm run typecheck` | PASS |
| `npm run build` | PASS; 1708 modules; Vite chunk warning only |
| `npm test -- --run --reporter=dot` | PASS on isolated rerun; **35 files, 215 tests**; 60.65 s |
| `npx playwright test e2e/lte-integration.spec.ts` | PASS; **6/6**: light/dark at 1280, 1440 and 1920; mocked API, no live simulator |
| `git diff --check` | PASS |

One concurrent frontend run failed four performance/time-limit assertions while Cargo and other host workloads were active (211/215). The required isolated rerun passed 215/215; the failed run is retained as a resource-contention anomaly, not hidden.

`npm ci --ignore-scripts` reported 6 dependency advisories (2 moderate, 2 high, 2 critical) and Node 18 engine warnings for packages requiring Node >=20. No automatic dependency upgrade was applied because that would be a separate compatibility change.

## Safety evidence

- Final `df -P /root`: `/dev/sda1`, 300545244/405196772 blocks used, **75%**, below 85%.
- `pgrep -a dumpcap | wc -l`: **12**. No dumpcap process was signalled or modified.
- `docker ps -a` with exact Compose label filters for `srsenb` and `srsue`: no rows at final check.
- Production URL was not mutated, restarted or used for live tests.

## Gates and remaining blockers

| Gate | State | Evidence/reason |
|---|---|---|
| 1 — offline code/tests | PASS | Commands above |
| 2 — Grant V2 + LTE ownership | CODE PASS / CERTIFICATION PENDING | Offline negative tests pass; external security certification not supplied |
| 3 — security/isolation review | PENDING | ANR1/independent review required |
| 4 — explicit LTE live authorization | BLOCKED | Not supplied |
| 5 — real LTE E2E | BLOCKED | No authorized S1/Attach/IP/data run |
| 6–7 — real anonymized PCAP/OIRAN certification | OUT OF ANR2 SCOPE / BLOCKED | Requires ANR1/ANR3 evidence |
| 8 — deployment authorization | BLOCKED | Not supplied |
| 9 — controlled deployment/production acceptance | BLOCKED | Gate 8 not passed |

The code is ready for offline review, but **FINAL_PASS is prohibited** until ANR1 certifies the LTE contract and the user explicitly authorizes live validation and deployment.

— ANR2
