# Changelog

## 0.29.14 (polaris-control-api) — 2026-11-03 — accept the `base,overlay` compose label

- `parse_container_inspect()` and the srsRAN ownership ledger now compare
  `com.docker.compose.project.config_files` to the comma-joined list of
  `COMPOSE_FILES`, in Docker declaration order. 0.29.13 kept comparing to the
  base file alone, so every srsENB/srsUE that create() spawned (with both
  `-f` files) was immediately rejected with `LTE_RUNTIME_OWNERSHIP_CONFLICT`
  and no S1 setup could occur. The expected value was validated by ANR3 on a
  real run — see issue #10 comment 6613958815.
- Introduces `compose_config_files_label()` as the single source of truth for
  that string, built from `COMPOSE_FILES: [&str; 2]`; `COMPOSE_FILE_ARGS` also
  references `COMPOSE_FILES`. Every ownership check and ledger access reads
  from the same constant.
- Migrates the ownership ledger validation: an existing ledger that still
  records `compose: COMPOSE` (base only, written by 0.29.13 or earlier) is
  rejected fail-closed with the dedicated code
  `SRSRAN_OWNERSHIP_LEDGER_OBSOLETE_COMPOSE_LABEL`. No silent upgrade path.
- Audit of the whole workspace for any `/root/POLARIS/compose/` or
  `config_files` reference: the three legacy UE-01 migration call sites in
  `apps/api/src/lib.rs` read the base compose file directly and are not part
  of the LTE ownership path; left untouched.
- Adds six regression tests: the exact `base,overlay` label value, accept /
  reject container labels, reject label from a different project, legacy
  ledger rejection with the dedicated error code, and new-ledger acceptance.
- No change to `CERTIFIED_COMPOSE_MODEL_SHA256`
  (`fa7fe0c168bf6139b9c67f2b9b129ae3b7a0370d94f7dac70f9858dc380121fc`), the
  overlay content, compose files, image digests, or safety-guard behaviour.

## 0.29.13 (polaris-control-api) — 2026-11-03 — unify LTE `docker compose` file list

- `DockerSrsranRuntime::create()` now passes the same `-f` compose files as the
  certified compose model render (`compose_config_args()`): both the base
  `docker-compose.oiran-lab.yml` and the LTE overlay
  `docker-compose.polaris-0.29.8.yml`. 0.29.12 shipped `create()` with only the
  base file, so srsUE was spawned without the overlay (/tmp = 64 MiB default
  instead of the certified 16 MiB, and no SYS_NICE / rtprio / memlock), while
  the SHA256 of the certified compose model kept covering both files.
- Introduces `COMPOSE_FILE_ARGS: [&str; 4]` as the single source of truth for
  the `-f` list, used by `create()` and `compose_config_args()`. Any new
  `docker compose` subcommand added later must reuse it.
- Adds three regression tests: the `-f` pairs of `create()` are strictly
  identical to those of the certified model, every compose call includes the
  overlay, and `CERTIFIED_COMPOSE_MODEL_SHA256` is unchanged
  (`fa7fe0c168bf6139b9c67f2b9b129ae3b7a0370d94f7dac70f9858dc380121fc`).
- No change to the compose model, the overlay content, image digests, log
  fragments, or safety-guard behaviour.

## 0.29.12 (polaris-control-api) — 2026-11-03 — writable confined iperf3 runtime

- Gives both LTE iperf3 endpoints a bounded 16 MiB `/tmp` tmpfs with
  `noexec,nosuid,nodev` and mode 1777. The previous SGi DN sidecar used mode
  1700 while running as uid 65532, so iperf3 could accept its control
  connection but could not create the UDP stream.
- Runs the pre-Grant UE/DN tooling checks with the same read-only rootfs and
  writable confined `/tmp` used by the live services.
- Persists the final 512 UTF-8 bytes of iperf3 stdout and stderr plus its exit
  code before a failed traffic step is cleaned up.

## 0.29.11 (polaris-control-api) — 2026-11-03 — validate the real Initial Attach Modify Bearer completion

- Fixes the fail-closed E-RAB gate for the Open5GS Initial Attach path. SGW-C
  does not log a literal `Modify Bearer Response` on this path: after
  `Modify Bearer Request`, the successful PFCP `Session Modification Response`
  causes `sxa-handler.c` to build and commit the S11 response without naming it
  in the log. The gate now accepts that ordered pair while rejecting reversed,
  incomplete, or unrelated PFCP responses; the direct S5-C response marker
  remains supported.

## 0.29.10 (polaris-control-api) — 2026-11-03 — pin the runtime canonical Compose digest

- Pins the certified LTE Compose model to the digest produced by the API's
  actual `serde_json` canonicalization path. POLARIS 0.29.9 incorrectly pinned
  the output of `jq -cS`; numeric rendering differs, so the runtime model was
  rejected before Grant consumption. The preflight remains fail-closed and no
  live run was started with the mismatched release.
- Aligns the deployed UE log fragment with the controller's nine frozen
  runtime log pairs by adding `usim_level = warning`. The previous fragment
  omitted that pair, so the fail-closed log gate rejected run creation before
  srsENB/srsUE startup. This is a configuration-only correction and does not
  require a POLARIS service restart.

## 0.29.9 (polaris-control-api) / safety-guard 0.2.1 — 2026-11-03 — restore the 98% disk ceiling + 8 GiB reserve removed in 0.29.8

- Restores observable srsENB/srsUE runtime logs: the LTE overlay no longer
  selects Docker's `none` logging driver and both runtime fragments emit to
  stdout. This keeps `docker logs`, the exact ICS/MBR gates and terminal
  evidence collection on the same stream without changing the LTE real-time,
  CPU, capability or command settings.
- Restores `crates/safety-guard/src/lib.rs` byte-identical to the 7a256ac0
  state (POLARIS 0.29.8 pre-merge of commits 34f0c6d / 99dce07). The
  original `Policy` defaults are back:
  `information: 95, warning: 97, stop: 98, hard: 98, reserve_bytes: 8 GiB`.
  Evaluation enforces the percentage thresholds + absolute reserve +
  `available_inodes > 16`, as mandated by the project policy that bans
  disabling the 98 % ceiling. The original tests are back as well
  (`exact_thresholds`,
   `projected_budget_and_absolute_reserve_fail_closed_before_98_percent`,
   `inode_exhaustion_and_measurement_failure_remain_closed`,
   `reserve_caps_budget`, `monitor_failure_is_closed`,
   `legacy_thresholds_do_not_block_when_budget_and_reserve_fit`).
- Bumps `safety-guard` from `0.2.0` to `0.2.1` with the same change
  recorded in its `VERSION` constant and `Cargo.toml`. Clients tracking
  the crate's VERSION will see the bump even though the behaviour is
  "back to the 0.29.7 default" — this is the project's safety-guard
  guarantee being restored, not a new regression.

## 0.29.8 (polaris-control-api) — 2026-11-03 — bounded LTE diagnostics + deterministic bearer gates

- Writes bounded srsUE/srsENB logs to root-only per-run files, disables the
  PHY-library flood, raises only RRC/NAS/PDCP/RLC to debug, and persists a
  private final-4-KiB RRC extract. Hex-dump continuation lines are removed by
  the subscriber-material sanitizer.
- Applies real-time/memlock limits only to srsUE and srsENB, removes their CPU
  quotas, preserves `SYS_NICE`, and pins the resulting canonical compose model.
- Requires the exact srsRAN 25.10 `Tx S1AP SDU,
  InitialContextSetupResponse` marker and the Open5GS SGW-C `Modify Bearer
  Response` marker; approximate legacy strings no longer produce a PASS.
- Executes both UE and LTE DN tooling checks in the certified-release gate
  before profile activation/Grant consumption.
- Removes percentage-based disk gates. Writes remain fail-closed on
  insufficient free bytes, exhausted inodes, or ENOSPC.
- Installs and validates a fixed `[log]` section in
  `/root/POLARIS/runtime/srsran/ue.conf` before every run, with
  `phy_lib_level=none`, `phy_level=warning`, `mac_level=info`,
  `rlc_level=debug`, `pdcp_level=debug`, `rrc_level=debug`,
  `nas_level=debug`, `usim_level=warning`, `all_hex_limit=64`. The patch
  is section-aware and every other section stays byte-identical. Addresses the
  15730a0f pathology where 99.77 % of 156 328 srsUE log lines were
  PHY_LIB/I noise and the RRC window vanished with Docker log rotation.
  Expected total log volume per run < 5 MiB with these levels.
- The release deployment assets install the matching eNB log section outside
  the sandboxed API process, with backup and rollback.
- Terminal evidence now carries an `rrc_extracts: BTreeMap<String, String>`
  with the sanitized `[RRC]` lines of srsUE and srsENB, bounded 4 KiB
  tail per component. The private evidence remains in the root-only run
  store (`/var/lib/polaris-control/lte-runs-v2/<run_id>.json`), never in
  a public HTTP body.
- New primitives (pure functions): `inject_log_section`,
  `extract_rrc_lines`, and the constant `RUN_UE_LOG_SECTION`.
- The runtime gate verifies the installed UE log section before starting
  srsRAN and fails closed if it is absent or altered.

## 0.29.7 (polaris-control-api) — 2026-11-03 — ERAB gate + terminal evidence persistence

- Adds a fail-closed `LTE_ERAB_NOT_ESTABLISHED` gate run **before every ping
  or UDP step**. The gate reads srsENB and MME logs via the runtime and
  requires at least one Initial Context Setup Response marker (S1AP
  procedure 9 successfulOutcome, E-RAB id 5) on srsENB **and** at least one
  Modify Bearer Response marker (GTPv2 type 35) on the MME. Returns the
  observed marker counts in the sanitized evidence so an operator can see
  exactly what was and was not emitted. Addresses the d62245de pathology
  (ICS Request arrived, ICS Response never sent, Modify Bearer absent,
  S1-U 0 trames).
- Persists the FULL sanitized `docker logs` of srsENB and srsUE
  **before cleanup** to a root-only file (`/var/lib/polaris-control/runs/
  <run_id>/<component>.log`, mode `0o600`). The public evidence contains
  only path + SHA256 + byte count + bounded last-512 tail, never the raw
  contents. srsRAN container stdout is no longer lost at cleanup.
- Collects read-only `ip neigh` and `ip -s link` in srsENB and
  `ip neigh` in the SGW-U container before cleanup. No Open5GS mutation.
- Introduces `TerminalEvidence`, `FullLogRecord`, `EnbNetworkDiagnostics`
  and `ErabEstablishmentEvidence` as JSON-serialisable structs; the
  runtime trait gains `verify_erab_established()` and
  `collect_terminal_evidence()` with safe Mock defaults + injectable
  overrides for tests.

## 0.29.6 (polaris-control-api) — 2026-11-02 — pinned 0.29.6-rc1 image + exec preflight

- Pins the certified UE tooling image reference to
  `oiran/srsran4g-ue-tools:0.29.6-rc1` and the image ID to
  `sha256:aab719ffdfa518777ed3d197ffe02cdcef02f78f578095d9abb1da9f327db2a5`.
  The previous 0.29.4-rc1 reference / `sha256:218e848b…4d04` is explicitly
  rejected with `LTE_CERTIFIED_IMAGE_MISMATCH` so an operator pointing at a
  stale image gets a precise diagnostic.
- Pins `CERTIFIED_COMPOSE_MODEL_SHA256` and `SRSRAN4G_COMPOSE_MODEL_SHA256`
  to `1e93feba4b3511f1c46ee27e63175c0ce5be2125f9b11af65c27f670f24b3ed1`
  (0.29.6-rc1 compose render); the previous `d0c80ea1…35f5d` is rejected
  with `LTE_CERTIFIED_COMPOSE_MODEL_MISMATCH`.
- Adds an exec preflight before every Grant V2 issuance: a disposable
  container is spawned from the certified image with the *same* cap_drop /
  cap_add / user / `read_only` / `no-new-privileges` as the live service
  (`UE_SERVICE_EXEC_SPEC` and `DN_SGI_SERVICE_EXEC_SPEC`), `--network none`,
  running `ping -c1 -W1 127.0.0.1 && iperf3 --version`. A non-zero exit
  surfaces `LTE_UE_TOOLING_NOT_EXECUTABLE` or `LTE_DN_TOOLING_NOT_EXECUTABLE`
  with a bounded tail-preserving diagnostic.
- Preserves every 0.29.5 safeguard (SGi/N6 safeguards, Grant V2, finalizer,
  dumpcap ownership, Open5GS). Workspace behaviour unchanged on the data
  plane.

## 0.29.6-rc1 (srsran4g-ue-tools) — 2026-11-02 — unprivileged ping execution

- Derives only from the certified 0.29.4 UE tooling image and removes the
  `cap_net_raw=ep` file capability from `/usr/bin/ping`; no container
  capability is added. With the production-equivalent `cap_drop: ALL`,
  `NET_ADMIN`, `SYS_NICE`, read-only filesystem and no-new-privileges policy,
  the network-isolated loopback ping now exits successfully.
- Keeps `srsue` and `srsenb` byte-identical to the certified base image.

## 0.29.5 (polaris-control-api) — 2026-11-02 — LTE ping failure evidence retention

- Review corrections retain the filtered final 512 UTF-8 bytes of srsUE/srsENB
  logs, capture S1-U/ZMQ eNB link counters, and restore fail-closed DL sender
  tooling classification on the ping result.
- Persists bounded, subscriber-sanitized ping stdout/stderr/exit status before
  `fail_step` and before cleanup, so terminal run evidence retains the exact
  `LTE_PING_FAILED` cause.
- Preserves read-only UE interface counters and routes, filtered 200-line
  srsUE/srsENB log tails, eNB UL/DL bitrate lines, effective S1-C/S1-U bind
  addresses, attached eNB networks and running container image IDs.
- Bounds every diagnostic stream to 512 UTF-8 bytes and expands subscriber
  material filtering to SUCI/GUTI/TMSI/IMEI/IMEISV/MSISDN markers.
- Adds unit coverage for each diagnostic field and for persistence across the
  failed-step/cleanup transition. No live, Grant, deployment or capture change.

## 0.29.4 (polaris-control-api) — 2026-11-02 — LTE UE UL route installation

- Adds a fail-closed `/32` route installation to the configured LTE SGi peer
  through `tun_srsue` after UE IP readiness and before any UL traffic probe.
  Installation failures surface as `LTE_UL_ROUTE_INSTALL_FAILED`.
- Verifies `ip`, `ping`, and `iperf3` in a disposable, network-disabled UE
  image container before issuing a certification Grant V2; missing tooling
  surfaces as `LTE_UE_TOOLING_MISSING`.
- Persists bounded (512-character), subscriber-sanitized exit code, stdout and
  stderr diagnostics for UL and DL route probes in each step evidence record.
- Adds a UE tooling image derived from the exact certified srsRAN4G digest,
  adding only pinned `iperf3=3.16-1build2`; the `srsue` binary remains
  byte-identical and is verified during the offline release gate.
- Preserves SGi/N6 separation, Grant V2, cleanup, evidence finalization,
  Open5GS configuration and external dumpcap ownership.

## 0.29.3 (polaris-control-api) — 2026-11-02 — LTE SGi dedicated DN + hardened preflight

- Requires an explicit LTE DN sender container
  (`POLARIS_LTE_DN_SENDER_CONTAINER`); refuses silent fallback to the 5G N6
  `polaris-dn-sender`. Rejects empty names, invalid characters, and verbatim
  collision with the N6 container (`LTE_DN_SENDER_COLLIDES_WITH_N6`).
- Requires a configured PGW-U LTE next-hop
  (`POLARIS_LTE_PGW_U_NEXT_HOP`) and a UE subnet
  (`POLARIS_LTE_UE_SUBNET`, defaults to `10.45.0.0/16`); missing or
  malformed values fail-closed before any traffic is spawned.
- Hardens `evaluate_lte_dl_return_route`:
  - rejects UE addresses outside the configured subnet
    (`LTE_UE_IP_OUTSIDE_SUBNET`);
  - rejects `unreachable` resolutions and unparseable `dev` fields
    (`LTE_DL_RETURN_ROUTE_UNAVAILABLE`);
  - rejects outbound devices listed in
    `POLARIS_LTE_FORBIDDEN_RETURN_DEVS`
    (`LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV` — default list rejects `lo`,
    `null0`, `blackhole`, `eth0`, and the N6 bridge `oiran-lab-n6`);
  - requires an explicit `via <PGW-U LTE>` next-hop matching
    `POLARIS_LTE_PGW_U_NEXT_HOP` (`LTE_DL_RETURN_ROUTE_MISSING_VIA`
    and `LTE_DL_RETURN_ROUTE_WRONG_NEXT_HOP`).
- Rejects explicit SGi/N6 IP collision at `configured_traffic_peer`
  (`LTE_SGI_COLLIDES_WITH_N6`).
- Classifies DN container exec exit codes 126/127 and
  `command not found` stderr as `LTE_DN_SENDER_TOOLING_MISSING`
  without leaking raw stderr.
- Removes the active `Environment=POLARIS_LTE_TRAFFIC_PEER_IP=10.77.24.30`
  line from the N6 drop-in; the LTE path now reads the dedicated SGi drop-in
  `deployment/dn-sender/lte-sgi/polaris-control-lte-sgi.conf`, with the
  offline-validated container, peer, next-hop, UE subnet and forbidden-device
  policy. Production activation remains separately gated.
- Ships the offline-certified SGi sidecar definition
  (`deployment/dn-sender/lte-sgi/compose.yaml`) with `cap_drop: [ALL]`,
  `no-new-privileges`, `read_only`, non-root user, pid/mem/cpu limits
  and immutable image digest
  `sha256:e60eb72bf7619fd049f6bbbc45cf06927eb73ed7c613446678644f6742af31f3`.
- Adds a digest- and ownership-bound route installer plus a systemd unit;
  the SGi interface is named `sgi_lte` and the return route is required to be
  `10.45.0.0/16 via 10.77.16.15 src 10.77.16.30`.
- Synchronizes `VERSION_MANIFEST.toml` with API 0.29.3, web 3.2.3,
  UERANSIM adapter 0.5.1 and safety-guard 0.2.0.
- Preserves Grant V2, cleanup, finalizer, 12-dumpcap ownership, disk
  policy 98% / 8 GiB reserve, and OIRAN 2.7.5 compatibility.

## 0.29.2 (polaris-control-api) — 2026-11-02 — LTE SGi / N6 topology separation

- Removes the ANR2 strict-equality requirement
  `POLARIS_LTE_TRAFFIC_PEER_IP == POLARIS_DL_SENDER_IP`. The LTE SGi peer
  is a dedicated DN endpoint distinct from the 5G N6 sender; the two values
  may legitimately differ and the LTE path no longer requires
  `POLARIS_DL_SENDER_IP` to be defined.
- Adds fail-closed LTE SGi preflights before every ping and iperf3 call:
  - UL preflight runs `docker exec UE ip route get <peer>` inside the UE
    container and rejects any resolution that does not use `tun_srsue`.
    Error code: `LTE_UL_ROUTE_NOT_VIA_UE_TUN`.
  - DL preflight runs `docker exec polaris-dn-sender ip route get <ue_ip>`
    and rejects `unreachable`, loopback/blackhole exits, or an unparseable
    resolution. Error code: `LTE_DL_RETURN_ROUTE_UNAVAILABLE`.
- Binds UL traffic to the UE tun interface and source IP:
  - `ping -I tun_srsue -c <count> <peer>` from the UE container.
  - `iperf3 -c <peer> -B <ue_ip> ...` from the UE container.
  - Guarantees the Linux stack cannot pick a bridge interface even if one is
    reachable from the UE container.
- Preserves bounded error codes and sanitized counters: the preflight returns
  explicit codes with the raw `ip route get` line included in the step
  evidence; no raw stderr, no secret, no subscriber material leaks.
- Does not change Grant V2, cleanup, finalizer, OIRAN compatibility (2.7.5),
  12-dumpcap ownership or Open5GS. Disk policy 98% / 8 GiB reserve unchanged.

## 0.29.1 (polaris-control-api) / safety-guard 0.2.0 / web 3.2.3 — 2026-11-02 — 98% disk ceiling

- Replaces the legacy 80/85/90 percentage blockers with 95% information,
  97% warning and a fail-closed 98% hard ceiling.
- Preserves an 8 GiB absolute free-space reserve and rejects an operation when
  its projected write budget cannot fit below both the ceiling and reserve.
- Keeps measurement failure, inode exhaustion, ENOSPC and unexpected growth
  fail-closed while leaving Stop, cleanup and read-only inspection available.
- Applies the same budget decision to LTE and generic scenario start gates and
  reports the estimate, maximum admitted budget and reserve in gate evidence.

## 0.29.0 (polaris-control-api) — 2026-11-01 — real LTE evidence finalizer

- Adds the Operator+CSRF protected `evidence-finalize` boundary that consumes
  only server-owned `SANITIZED_APPROVED` releases and never trusts capture
  paths, hashes, provenance, timestamps or session references from HTTP.
- Binds releases to the exact run/profile/scenario, RAT, terminal outcome and
  start/end timestamps; re-hashes every sanitized PCAP and normalized JSONL,
  rejects identity-bearing events, then creates an immutable private bundle by
  atomic rename before publishing any capture reference.
- Preserves non-empty observed subsets for `FAILED` and `CANCELLED` runs,
  requires S1-MME/S11/S1-U for `COMPLETED`, and keeps exact retries idempotent
  while returning HTTP 409 for drift.
- Does not read collector-owned paths, create captures, import production data,
  synthesize events or promote LTE E2E certification.

## 0.28.4 (polaris-control-api) — 2026-11-01 — LTE traffic peer preflight

- Fails the certification request before Grant consumption or simulator start
  when the LTE traffic peer is absent, invalid, or differs from the validated
  controller-managed DN sender address.
- Adds the missing `POLARIS_LTE_TRAFFIC_PEER_IP=10.77.24.30` to the canonical
  DN-sender deployment drop-in and documents the required exact match.
- Retains the precise bounded ping/UDP failure code in run evidence instead of
  collapsing every controller error into `LTE_TRAFFIC_FAILED`; cleanup,
  expiration and revocation behavior is unchanged.

## 0.28.3 (polaris-control-api) — 2026-11-01 — LTE Attach deadline reconciliation

- Replaces unscoped srsUE/MME log matching with an Open5GS MME `Attach
  Complete` proof carrying a verified RFC3339 event timestamp and explicit
  provenance, bounded to the current srsUE start window.
- Extends the Attach budget to a bounded 90 seconds, always clipped by the
  Grant V2/global deadline, and adds a two-second observation reconciliation
  window that accepts only events emitted no later than the protocol deadline.
- Keeps IP assignment separate from Attach proof, rejects late events after
  timeout, and revalidates the consumed Grant immediately before every ping or
  UDP launch so expiration or revocation cannot restart traffic.
- Retains clean terminal `FAILED` and `CANCELLED` evidence publication for the
  independently observed LTE planes; successful publication remains gated on
  the complete S1-MME/S11/S1-U proof set.

## 0.28.2 (polaris-control-api) — 2026-11-01 — srsENB Docker health handling

- Parses the complete `docker inspect` JSON instead of dereferencing the
  optional `.State.Health` field in a Go template.
- Classifies absent/null, starting, healthy and unhealthy health states while
  treating a running process without a healthcheck only as startup evidence.
- Keeps S1 readiness bound to an independently observed SCTP association and
  fails closed on stopped, crashed, unhealthy or timed-out containers with
  controller-owned rollback and cleanup preserved.

## 0.28.1 (polaris-control-api) — 2026-11-01 — evidence scope and replay binding

- Binds every server-staged LTE evidence manifest to the exact run, controller
  profile and certification scenario before any capture reference is published.
- Persists the admitted bundle ID with the run, makes an exact retry idempotent,
  and rejects changed bundle or capture metadata as a publication conflict.
- Confines capture and normalized-event files after canonicalization so a nested
  directory symlink cannot escape the private evidence bundle.

## 0.28.0 (polaris-control-api) — 2026-11-01 — fail-closed OIRAN LTE evidence bridge

- Adds an Operator+CSRF protected evidence-envelope route for completed LTE
  certification runs and emits the exact OIRAN 2.7.1 ingestion wrapper.
- Publishes only three independently observed `SANITIZED_APPROVED` LTE capture
  proofs (`S1_MME`, `S11`, `S1_U`), with lower-case SHA256, decoder/schema
  versions, bounded frame ranges, provenance and pseudonymous session refs.
- Rejects missing, duplicate, raw, unsupported/5G or unresolved evidence and
  preserves `POLARIS_LTE_E2E_CERTIFIED=false`; evidence publication never
  promotes operational certification.
- Accepts only a bundle id over HTTP. The OIRAN capture finalizer stages a
  private proof manifest and sanitized files; POLARIS streams and re-hashes
  every referenced capture/event file before emitting the direct OIRAN 2.7.1
  ingestion wrapper.

## 0.27.1 (polaris-control-api) — 2026-11-01 — activation revocation hardening

- Makes Administrator profile disable revoke the bound Certification Grant V2
  before clearing temporary activation.
- Rejects idempotent activation retries after grant revocation, preventing the
  original Operator request from restoring an Administrator-disabled profile.
- Serializes LTE start and cleanup, rechecks the consumed Grant immediately
  before each process start, and fails closed when expiry or cancellation wins.
- Applies the exact Grant V2 ping/UDP limits to runtime commands, including
  rate, duration and payload bounds for both traffic directions.
- Enforces both the 4 GiB available-memory reserve and the 16 GiB used-memory
  ceiling before LTE starts, with explicit measurement errors.
- Preserves the activation request/response schema, certification envelope,
  grant-independent cleanup and existing UERANSIM/5G behavior.

## 0.27.0 (polaris-control-api) — 2026-11-01 — temporary Operator LTE activation

- Adds a persisted, one-time temporary activation for only
  `LTE-SRSUE-TEST-01`, bound to the authenticated Operator session and exact
  Certification Grant V2 nonce, expiry, profile and certified digests.
- Keeps permanent profile enablement administrator-only and keeps
  `LIVE_OPERATIONAL` locked while `POLARIS_LTE_E2E_CERTIFIED=false`.
- Revokes temporary activation on expiry, Stop, failure, grant revocation or
  restart, while retaining grant-independent emergency cleanup.
- Preserves the one-UE, 300-second, ping and bidirectional UDP <=1 Mbit/s
  certification envelope and all existing UERANSIM paths.

## 0.26.0 (polaris-control-api) — 2026-10-31 — bounded LTE certification run

- Separates the one-time `CERTIFICATION_RUN` bootstrap path from
  `LIVE_OPERATIONAL` without changing `POLARIS_LTE_E2E_CERTIFIED` from real
  evidence or a run result.
- Requires the exact controller-owned LTE test profile, certified image and
  canonical Compose digests, Grant V2 purpose, subject/session ownership,
  RBAC, CSRF, nonce, expiry, anti-replay and the one-UE/five-minute traffic
  envelope before the certification orchestrator can start.
- Adds a five-minute global timeout, grant-independent emergency cleanup and
  automatic restart recovery while preserving observed-state transitions and
  the existing UERANSIM 5G paths.
- Publishes certification pending/running/failed/certified state separately
  from operation mode and keeps certification promotion manual.

## 0.25.2 (polaris-control-api) — 2026-10-31 — canonical LTE Compose model

- Includes the `lte` profile explicitly in the fixed-argv canonical Compose
  rendering so the digest covers the real `srsenb` and `srsue` service model.
- Sorts every JSON object recursively before hashing, independently of the
  `serde_json` map backend or the key order emitted by Docker Compose.
- Keeps the immutable image reference check independent from the rendered-model
  digest; neither mismatch can be used to authorize a runtime operation.
- Adds a regression test proving that the canonical command cannot silently
  omit profile-gated LTE services.

## 0.25.1 (polaris-control-api) — 2026-10-31 — isolated read-only staging

- Adds `POLARIS_STAGING_READ_ONLY=true`, a router-level fail-closed gate that
  permits reads and local staging login/logout while returning HTTP 423 before
  every lifecycle, grant, traffic, provisioning or catalogue mutation handler.
- Publishes `staging_read_only` from `/health` and `/version` so staging probes
  can prove the safety mode without relying on deployment configuration alone.
- Keeps all state/audit paths configurable so staging uses isolated registries
  and never writes to the production controller state.

## 0.25.0 (polaris-control-api) — 2026-10-31 — real-lab evidence only

- Makes `/nodes` publish Docker/process/socket and srsRAN observations with
  explicit evidence sources; unavailable PLMN, cell, address and interface
  evidence stays `NOT_AVAILABLE` or `NOT_OBSERVED`.
- Enriches the canonical LTE profile contract for UE Manager and derives its
  runtime/APN/timestamp fields from current srsRAN observation.
- Removes requested-rate traffic accounting fallback: unavailable UERANSIM or
  iperf measurement now fails the session without emitting synthetic samples.
- Preserves Grant V2, RBAC, CSRF, ownership, bounded cleanup and the immutable
  13-template LTE/5G catalogue introduced in 0.24.0.

## 0.24.0 (polaris-control-api) — 2026-10-31 — professional default scenario catalogue

- Adds the versioned read-only `/scenario-templates` catalogue with six LTE
  srsRAN and seven 5G SA UERANSIM templates, exact RAT/simulator metadata,
  required capabilities and honest `SUPPORTED`, `BACKEND_REQUIRED` or
  `CERTIFICATION_REQUIRED` status.
- Applies conservative defaults of one UE, one execution, UDP 1 Mbit/s for
  60 seconds. TCP requires an explicit authorization parameter; no multi-UE
  template is advertised before certification.
- Keeps system templates immutable while server-side clone creates a durable,
  mutable user definition with source provenance. Existing user scenarios are
  migrated additively and never replaced.
- Rejects UDP rate/duration templates with `SCENARIO_BACKEND_REQUIRED` until
  the dedicated executor exists; existing 5G and LTE safety, RBAC, CSRF,
  ownership, Grant V2 and certification gates remain authoritative.

## 0.23.1 (polaris-control-api) — 2026-10-31 — proof-before-state and unified LTE cleanup

- Separates durable operation intent from public LTE run state; S1, Attach,
  EPC context, UE IP and traffic states advance only after current evidence.
- Requires independent sanitized EPS Attach and EPC-context observations;
  S1 connectivity plus a UE address can no longer imply `ATTACHED`.
- Routes cancellation, expiry, revocation, Stop and start failures through one
  idempotent cleanup path that explicitly removes/observes run-owned sidecars
  and finalizes the journal as `CLEAN` or `RECOVERY_BLOCKED`.
- Rechecks the hard deadline, cancellation and resource gate immediately
  before every ping/UDP side effect and persists the precise gate failure.
- Aligns capture references with the amended canonical evidence contract by
  requiring `decoder_version` and `event_schema_version`.

## 0.23.0 (polaris-control-api) — 2026-10-31 — LTE orchestration V2

- Adds the checksummed, atomic, mode-0600 LTE run journal, exclusive profile
  lease, restart-to-cleanup recovery and idempotent run creation.
- Implements the contracted ENB/S1/UE/Attach/IP/traffic/cleanup phase machine,
  bounded retries and deadlines, cancellation and grant-independent cleanup.
- Emits bounded sanitized evidence using
  `oiran-polaris.lte-e2e-evidence.v1`; mandatory OIRAN capture references are
  unique, approved and validated before handoff.
- Raises the LTE preflight memory reserve to 4 GiB and requires the exact set
  of twelve external dumpcap processes without signalling them.

## 0.22.1 (polaris-control-api) — 2026-10-31 — final LTE Grant V2 and runtime hardening

- Adds the persistent, checksummed, mode-0600 LTE Grant V2 store with atomic
  writes, nonce hashing, subject binding, bounded idempotency and one-time
  consumption. API restarts revoke issued grants and move consumed grants to
  recovery-only instead of restoring privilege.
- Adds the exact `LTE-SRSUE-TEST-01` profile and
  `lte-e2e-certification-v1` run contract (`/lte/profiles/:id`, `/lte/runs`,
  `/lte/runs/:id`, `/lte/runs/:id/stop`). V1 grants remain compatible only
  with the existing UERANSIM paths; mixed V1/V2 bodies fail closed.
- Replaces user-addressable LTE component Start with Grant V2 run
  consumption. Cleanup remains Operator/CSRF protected but grant-exempt.
- Pins the runtime to the exact Compose project/file/services and image,
  verifies ownership labels, and bounds Compose operations with a timeout.
  No HTTP value becomes a command, service, path or container argument.
- Aligns run evidence with the ANR1 `polaris.lte-evidence.v1` schema and ANR3
  sanitized capture handoff contract. Full live certification remains locked.
- Resolves the real `srsenb` and `srsue` Compose services by immutable Compose
  labels and the authoritative `oiran-lab` configuration path; container names
  are no longer assumed.
- Adds an atomic mode-0600 ownership ledger. Start, Stop and traffic operate on
  exact recorded container IDs and reject unowned or ambiguous instances.
- Bounds Docker/Compose/exec operations with host-enforced TERM/KILL timeouts,
  exact cleanup and start rollback. No shell or HTTP-supplied command is used.
- Derives S1, Attach, UE IP and session from current structured observations;
  unverifiable values are `UNKNOWN`, never inferred from stale logs.
- Gates LTE traffic on certification, live mode, active non-expired grant,
  verified ownership, current Attach/IP/session and disk/memory safety. LTE uses
  bounded iperf3 results and never enters the legacy 5G synthetic-sample path.
- Adds negative coverage for ownership, timeout classification, rollback and
  the allowlisted LTE UE identifier while retaining existing RBAC/grant tests.
- Binds Grant V2 consumption to the issuing authenticated session and role,
  validates the canonical scenario hash, and prevents legacy V1 grants from
  authorizing LTE traffic or scenario execution.
- Adds a bounded ENB/S1/UE/Attach run orchestrator with persistent states,
  hard-deadline cleanup, cancellation, revocation cleanup and rollback.

## 0.21.0 (polaris-control-api) — 2026-10-31 — bounded srsRAN LTE integration

- Integrates LTE into the existing POLARIS API through `/lte/status`,
  `/lte/logs` and bounded `/lte/components/{start,stop}` actions; no second
  control application is introduced.
- Adds an injected srsRAN controller with an exact ENB-01 / LTE-UE-01
  allowlist, real Docker observations, sanitized logs, idempotent Stop and
  audit events. It never invokes a shell or accepts a command/path from HTTP.
- Live Start is fail-closed behind Operator + CSRF, an active UE grant,
  disk/memory safety, `POLARIS_SRSRAN_LIVE_ENABLED=true` and
  `POLARIS_LTE_E2E_CERTIFIED=true`. Both flags default false. Stop stays
  grant-exempt so an expired grant cannot trap a process.
- Extends `/nodes`, `/ues`, `/capabilities` and `/version` with typed LTE,
  srsENB/srsUE, EPC/S1 and controller-version fields. Unknown measurements
  remain `NOT_OBSERVED`; no LTE state or UE IP is fabricated.
- Adds catalog validation for LTE Attach, Detach, UL, DL and Attach + Data.
  Mock/catalog flows are available, while live scenario execution returns
  `423 LTE_E2E_CERTIFICATION_REQUIRED` pending ANR1 certification.
- Subscriber authentication material remains `PROTECTED`; srsRAN log lines
  containing identity/authentication markers are replaced with a redaction.


## 0.20.2 (polaris-control-api) — 2026-10-31 — role-aware IMSI on /ue-profiles and /ues

Rebased on top of `29f8ef5` (0.20.1 — Traffic Generator HTTP surface +
samples ring). `git merge-base --is-ancestor 29f8ef5 HEAD` → true.
This bundles Traffic Generator **and** role-aware IMSI; it is the
single POLARIS API deployment target going forward.

### Routes gaining the 0.19.7 (#48) IMSI gate
- `GET /api/v1/ue-profiles` — each item in `items[]` now carries a
  role-projected `subscriber_identity`: raw IMSI for
  `operator` / `administrator`, `"PROTECTED"` for every other role
  (anonymous viewer, unauthenticated session). Response gains the
  top-level `subscriber_identity_exposed: bool` flag so the UI can
  render the correct chip without round-tripping to `/auth/me`.
- `GET /api/v1/ue-profiles/:ue_id` — same projection on the top-level
  `subscriber_identity`, on the nested
  `subscriber.subscriber_identity` (via the new
  `subscriber_provisioning::sanitize_for_role(record, visibility)` path),
  and the response adds `subscriber_identity_exposed`.
- `GET /api/v1/ues` — every entry in both `items[]` and
  `configured_profiles[]` gains `subscriber_identity`
  (role-projected) + `authentication_material: "PROTECTED"`. The
  response adds `subscriber_identity_exposed`. IMSI per UE is resolved
  **once** at the top of the handler into a `BTreeMap<ue_id, IMSI>` so
  the hot per-row loop remains O(n).

### What stays protected for every role
- **K / OPc** material never leaves the API process. The
  `authentication_material` field is hard-coded to `"PROTECTED"` on
  every surface, independent of role (operator included).
- The **mutation** responses (`POST`, `PUT`, `PATCH /scenario`, clone)
  keep `subscriber_identity = "PROTECTED"` in their reply bodies even
  for an operator. These are deliberate: only the two GET surfaces +
  `/ues` project the IMSI. The test
  `ue_profile_endpoints_reject_mutation_responses_from_leaking_imsi`
  locks this invariant.

### Reused infrastructure
- `subscriber_provisioning::SubscriberIdentityVisibility::for_role` —
  the exact helper 0.19.7 ships for `/subscribers`. No new vocabulary.
- `subscriber_provisioning::sanitize_for_role(record, visibility)` —
  same path 0.19.7 uses to project the nested subscriber record on
  `/subscribers` detail. New call site: the nested `subscriber` object
  on `/ue-profiles/:id`.
- `profile_store.subscriber_imsi(record)` — internal join between a
  managed profile and its Open5GS subscription. Docstring updated to
  reflect that 0.19.7 / 0.20.2 allow this value through the
  `SubscriberIdentityVisibility::for_role` gate (and nowhere else).

### Tests (`cargo test -p polaris-control-api`)
- `ue_profiles_list_exposes_raw_imsi_for_operator_and_protects_viewer`
  — operator → IMSI + `subscriber_identity_exposed:true`; viewer →
  "PROTECTED" + `subscriber_identity_exposed:false`; viewer body does
  not contain the raw IMSI string anywhere.
- `ue_profile_detail_exposes_raw_imsi_for_operator_and_protects_viewer`
  — same, plus the nested `subscriber.subscriber_identity` is also
  role-projected.
- `ues_list_tags_each_item_with_role_aware_subscriber_identity` —
  both `items[]` and `configured_profiles[]` tagged. K / OPc never
  appear in the operator body.
- `ue_profile_endpoints_reject_mutation_responses_from_leaking_imsi`
  — PATCH scenario response keeps IMSI out even for an operator.
- Full `cargo test -p polaris-control-api` → **195 passed · 0 failed
  · 3 ignored** (ignored pre-existing). No regression on the 191
  tests shipped at 0.20.1.

### Deployment envelope
0.20.2 is the single POLARIS API we deploy going forward: Traffic
Generator (0.20.1) + role-aware IMSI (0.20.2) in one atomic release.

## 0.20.1 (polaris-control-api) — 2026-10-30 — Traffic Generator HTTP surface

Rebased on top of `ebcf851` (0.20.0 — Traffic Generator state machine
+ validation). `git merge-base --is-ancestor ebcf851 HEAD` → true.

### Routes (#47)
- `POST   /api/v1/traffic/sessions` — operator-gated. Requires an active
  live grant covering every UE in `ue_ids` (same gate as `scenarios/start`).
  Validates the payload against the 0.20.0 contract and returns `422`
  with the stable error code on bad input, `423`
  `TRAFFIC_SESSION_GRANT_REQUIRED` when no grant covers the request.
  Spawns the driver loop via `tokio::spawn` and returns `201 Created`
  with the session snapshot.
- `GET    /api/v1/traffic/sessions` — list all sessions.
- `GET    /api/v1/traffic/sessions/:id` — one session's full snapshot.
- `DELETE /api/v1/traffic/sessions/:id` — **always allowed** (0.20.0
  Stop-is-sacred rule); still requires a valid CSRF token.
- `GET    /api/v1/traffic/sessions/:id/samples` — new in 0.20.1.
  Returns the per-session rolling ring (max 60 ticks at 1 Hz) for the
  simulator-control 0.13.1 live charts. Shape (POLARIS top-level
  envelope, matching `/live/grant`): `{items: [TrafficSample…],
  session_id, samples_ring_max: 60}` where each sample carries
  `{epoch_s, bytes_ul_cum, bytes_dl_cum, rate_ul_bps?, rate_dl_bps?}`.

### Response envelope
POLARIS endpoints answer with raw top-level named fields (not the OIRAN
`{data, meta}` envelope). This matches the existing `/scenarios`,
`/live/grant`, `/subscribers` conventions and keeps `polarisApi<T>`'s
`unwrapPolarisBody` auto-unwrap a no-op for the Traffic Generator routes.
- `GET /traffic/sessions` → `{items: [TrafficSession…], total: N}`
- `GET /traffic/sessions/:id` / `POST` / `DELETE` → raw `TrafficSession`
- `GET /traffic/sessions/:id/samples` → `{items, session_id, samples_ring_max}`

### iperf3 (measurement, never blocking)
- One `tokio::spawn` per POST drives the measurement loop at 1 Hz.
  Each tick:
  1. Attempts to resolve a `VerifiedTrafficTarget` per UE via
     `UeRuntime::resolve_traffic_target`.
  2. For UEs whose target resolves, spawns a blocking iperf3
     measurement (`tokio::task::spawn_blocking` →
     `UeRuntime::execute_iperf_ul/_dl`) and folds the result's warning
     codes into `record_measurement`.
  3. For UEs whose target does **not** resolve (mock mode, UE not
     `REGISTERED` + PDU-`ACTIVE`, …) surfaces the resolution failure
     as a warning string and keeps the pipeline moving so the live
     chart still draws — the 0.19.8 "measurement never fails the
     session" invariant.
- Exits early when the session leaves `RUNNING`. At `duration_s` the
  session transitions to `COMPLETED` (idempotent — a STOP beats a
  natural completion).

### State machine extensions (traffic_sessions.rs)
- `TrafficSample` struct + per-session bounded `VecDeque<TrafficSample>`
  (cap = `SAMPLES_RING_MAX = 60`) keyed by `session_id`. Fixed-size — a
  10-minute run cannot grow the API process RSS.
- `push_sample` evicts the oldest tick on overflow; `samples()` returns a
  cloned snapshot; `complete()` transitions `Running → Completed` and
  stays a no-op on terminal `Stopped` / `Failed`.

### Tests
- 5 new unit tests in `traffic_sessions::tests`. Full module: 15 / 15.
- 5 new HTTP integration tests in `p0_tests`:
  - `traffic_session_post_requires_an_active_grant` — 423
    `TRAFFIC_SESSION_GRANT_REQUIRED`.
  - `traffic_session_post_rejects_invalid_payload_with_422` — empty
    `ue_ids` → 422 `TRAFFIC_SESSION_UE_IDS_REQUIRED`.
  - `traffic_session_happy_path_posts_then_lists_then_gets_then_streams_samples`
    — grant installed → 201 → 1.2 s sleep → list + detail + samples
    endpoint all serve the session with the UL rate sample present.
  - `traffic_session_delete_is_always_allowed_but_still_requires_csrf`
    — DELETE without CSRF → 403; with CSRF → 200 twice (idempotent).
  - `traffic_session_samples_endpoint_returns_404_on_unknown_id`.
- Full `cargo test -p polaris-control-api` → **191 passed · 0 failed · 3
  ignored** (ignored are pre-existing).

### Identity invariant (unchanged)
The Traffic Generator never carries subscriber identity on the wire. UE
ids are the operator-facing `UE-NN` / `UE-NNNNN` labels; IMSI / IMEI /
TMSI / GUTI / RNTI / K / OPc never reach the state store or the samples
endpoint.

## 0.17.9 (polaris-control-api) — AMBR BSON int (0.17.8 rolled back in lab)

- **#39 (continued), live labo rejection**: Codex deployed 0.17.8 (BSON
  `long` for AMBR `value`) and observed `UDR: No UE-AMBR`, AMF `GET am-data`
  returning HTTP 400, UE refused with `FIVEG_SERVICES_NOT_ALLOWED`. The
  lab's healthy WebUI-created subscribers store both `ambr.value` and
  `ambr.unit` as BSON `int32`; the Open5GS 2.8.0 UDR path running there
  does not accept a `long` encoding for the AMBR magnitude, even though
  `bson_iter_as_int64` would read it in isolation. 0.17.8 was rolled back
  to 0.17.7 in production.
- Fix: AMBR is now written as `(value: int32, unit: int32)` with the
  largest unit for which the quotient is a positive int32. The 3GPP /
  Open5GS unit convention is used (0=bps, 1=Kbps, 2=Mbps, 3=Gbps,
  4=Tbps, 5=Pbps). Reference points matching the operator spec:
  - 1 Gbit/s → `{value: 1,    unit: 3}`
  - 500 Mbit/s → `{value: 500,  unit: 2}`
  - 1 Mbit/s → `{value: 1,    unit: 2}`
  - 1.5 Gbit/s → `{value: 1500, unit: 2}` (not an exact Gbps multiple).
  The encoding/decoding lives in `encode_ambr_bps_to_value_unit` /
  `decode_ambr_value_unit`; both are covered by round-trip unit tests.
- `MongoSubscriberBackend::provision_batch` and
  `apply_update_script` both emit the AMBR as `NumberInt(value)` /
  `NumberInt(unit)` at every schema path (`ambr.{uplink,downlink}.*` and
  `slice.0.session.*.ambr.{uplink,downlink}.*`). The 0.17.8 `NumberLong`
  form is explicitly asserted absent by the regression test.
- `decode_record` now reads the stored `(value, unit)` pair and
  rematerialises the bps magnitude for the sanitised response, so the
  `GET /subscribers/:slot` AMBR field continues to report the full bits-
  per-second number the operator typed in.
- `apply_update_script` adds a defensive `parseExistingAmbrLeg` helper
  for the DNN-rewrite path: if the current record was previously written
  by POLARIS 0.17.0..0.17.8 (EJSON sub-doc or BSON long) we still extract
  a usable value, cast to BSON int32, and rewrite the sessions correctly.
- Tests:
  - Unit: `encode_ambr_picks_largest_unit_with_integer_quotient` locks
    the operator's four reference points plus overflow guard;
    `encode_decode_ambr_roundtrip_preserves_magnitude` round-trips 7
    representative bps values.
  - Static regression: `apply_update_script_never_emits_ejson_literals_for_ambr`
    asserts the emitted mongosh script contains `NumberInt(500)`,
    `NumberInt(1500)`, `NumberInt(2)` and does NOT contain the 0.17.8
    `NumberLong("...")` form.
  - Live-MongoDB: `ambr_put_writes_real_bson_long_in_live_mongo` (same
    name kept for continuity) now asserts `$type == "int"` strictly for
    every AMBR `value` and `unit` field (top-level and both sessions),
    plus `qos.index` + `qos.arp.priority_level`. Round-trip proof on
    live Mongo:
    `BSON_TYPES={"sessions":[{"dl_unit_type":"int","dl_value":1500,"dl_value_type":"int",...}]`.
    Reproduce: `POLARIS_TEST_MONGODB_CONTAINER=<container>
    cargo test -p polaris-control-api --lib
    subscriber_provisioning::tests::ambr_put_writes_real_bson_long_in_live_mongo
    -- --nocapture`.
  - Full suite: `cargo test -p polaris-control-api --lib` → **129 passed,
    0 failed, 3 ignored** (up from 127 on 0.17.8; +2 encoding unit tests).

## 0.17.8 (polaris-control-api) — critical AMBR BSON corruption patch

- **#39 critical, data corruption**: `PUT /subscribers/:slot` (regressed in
  0.17.0 when the subscriber update path was added) wrote the AMBR as a
  literal JSON sub-document `{"$numberLong":"N"}` instead of a BSON long.
  mongosh evaluates the surrounding `--file` input as JavaScript, not EJSON,
  so each `$set` payload serialized through `serde_json::to_string` embedded
  the EJSON marker as plain field names in a sub-document rather than as a
  BSON `Long` constructor call. Downstream, the Open5GS UDR read the field
  as a sub-document (`bson_iter_as_int64` fails), the AMF then returned
  HTTP 400 on `GET am-data`, and the UE was refused with
  `FIVEG_SERVICES_NOT_ALLOWED`.

  Fix: `MongoSubscriberBackend::apply_update_script` now builds the mongosh
  script text directly — not by serializing a `serde_json::Map` — and emits
  real `NumberLong("N")` / `NumberInt(U)` constructor calls at every AMBR
  path (`ambr.{uplink,downlink}.{value,unit}` and
  `slice.0.session.*.ambr.{uplink,downlink}.{value,unit}`). The duplicate
  `$set` key in the DNN-rewrite branch (two `$set` keys in the same
  updateOne argument, where the second silently clobbered the first — the
  AMBR update was dropped on the floor whenever DNNs were also updated) is
  removed in favour of a single typed `setFields` object. The DNN rewrite
  also preserves per-session `qos.index` / `qos.arp.*` and carries the AMBR
  (either from the update or the current record) rather than reducing each
  session to `{name}` only.

- **BSON type note.** The healthy subscribers created by the lab's Open5GS
  WebUI 2.8.0 store both `ambr.*.value` and `ambr.*.unit` as BSON `int`
  (int32). 0.17.8 writes `value` as BSON `long` (int64) and keeps `unit` as
  BSON `int`. This deliberate asymmetry is accepted: Open5GS reads AMBR
  with `bson_iter_as_int64`, which accepts both `int` and `long` without
  precision loss, and `long` lifts the 2.1 Gbit/s ceiling that `int32`
  would impose on `value` — a 5G AMBR can legitimately exceed `2^31` bps.
  `unit` is a small enum (0..=5) and stays `int` to match the lab schema
  exactly. The `$type ∈ {int, long}` assertion in the live-MongoDB test
  reflects this contract.

- **#38**: `POST /subscribers/generate` default AMBR raised from 1 Mbit/s
  to 1 Gbit/s uplink and downlink, with the same typed BSON encoding
  flowing through `provision_batch`.

- `MongoSubscriberBackend::provision_batch` now also emits `NumberLong(...)`
  for the AMBR `value` field (previously it used the untyped mongosh
  `Number()`, which stores as a BSON double — functional on the Open5GS
  side, but not what the schema contract above specifies).

- Tests:
  - Static regression lock
    (`apply_update_script_never_emits_ejson_literals_for_ambr`) asserts
    that the emitted script never contains the EJSON injection form and
    that it uses `NumberLong(...)` / `NumberInt(...)` for every typed
    field, and that it issues exactly one `db.subscribers.updateOne` call.
  - Mandatory live-MongoDB test
    (`ambr_put_writes_real_bson_long_in_live_mongo`) gated by
    `POLARIS_TEST_MONGODB_CONTAINER`. When the env var is set the test
    MUST pass; when unset it skips with a loud `SKIPPED_NO_MONGO` marker
    and is NOT `#[ignore]`'d. The test provisions a subscriber with TWO
    DNNs (so there are TWO sessions, not just the first) via
    `provision_batch`, PUTs a new AMBR via `apply_update`, then runs a
    `$type` aggregation that **first `$unwind`s `$slice` and then
    `$unwind`s `$slice.session`** before applying `$type` to the scalar
    leaves. Applying `$type` directly to `"$slice.session.ambr.*"` would
    have classified the paths as `array` (because `slice[]` and
    `slice[].session[]` are both arrays), hiding whether each leaf is
    actually a BSON long; the unwind pipeline forces one row per session
    and gives honest leaf-level types. The test asserts
    `$type ∈ {int, long}` for every AMBR `value` and `unit` on BOTH
    top-level and EVERY session row, plus `qos.index` and
    `qos.arp.priority_level`. It also re-reads the full document and
    asserts that `slice` is still an array of session-bearing objects,
    `slice[0].session` is still an array of session objects, and that
    no AMBR `value` field anywhere in the document is a leftover
    `{"$numberLong":"N"}` sub-doc from the pre-0.17.8 EJSON injection
    bug. Validated locally against a `mongo:7` container; command for
    operator reproduction:
    `POLARIS_TEST_MONGODB_CONTAINER=<container> cargo test -p polaris-control-api --lib subscriber_provisioning::tests::ambr_put_writes_real_bson_long_in_live_mongo -- --nocapture`.

## 0.17.7 (polaris-control-api)

- Retain the immutable runtime approval and process handle acquired by a
  scenario job until that job reaches its terminal state.
- Reuse the job-owned approval for `detach`, explicit terminal stop and failure
  cleanup, while keeping already-`STOPPED` cleanup idempotent. Runtime
  observation can therefore clear its registry copy without causing a false
  `LIVE_RUNTIME_APPROVAL_MISSING` failure.
- Use the controller stop result as the authoritative final `STOPPED` / PDU
  `INACTIVE` observation instead of querying the already-terminated runtime a
  second time.

## 0.17.6 (polaris-control-api)

- Make terminal `detach` issue `ps-release-all`, immediately continue with
  switch-off deregistration and stop, then require the authoritative final
  controller observation to be `STOPPED` with an `INACTIVE` PDU state.
- Keep standalone `pdu_release` strict: it still waits for UERANSIM `ps-list`
  to stop reporting an active PSI. This avoids treating the transient release
  window before UERANSIM automatic re-establishment as a durable state.
- Record separate release-request and final-state evidence for completed
  detach steps.
- Treat a controller-owned UE already observed `STOPPED` after switch-off as
  an idempotent stop success, even when runtime observation has already
  cleared its launch approval and process handle.

## 0.17.5 (polaris-control-api)

- Make `transfer_verify` SHA-256 equality the blocking delivery proof and run
  it before the corresponding paced iperf3 measurement in certified E2E jobs.
- Persist `IPERF3_RECEIVER_SHORT` as a non-blocking warning with sender bytes,
  receiver bytes and retransmission count. Connection failures and zero-byte
  receiver reports remain blocking.

## 0.17.4 (polaris-control-api)

- Pace UL and DL iperf3 transfers with a validated configurable rate
  (`POLARIS_IPERF3_RATE`, default `5M`) and retain the server's independent
  JSON report through `--get-server-output`.
- Keep the `64K` TCP window after isolated loss tests showed fewer
  retransmissions and exact delivery than the unbounded run.
- Add the strict `transfer_verify` scenario step for a byte-exact 1 MiB TCP
  transfer with independent sender/receiver SHA-256 evidence.

## 0.17.3 (polaris-control-api)

- Bound the TCP sender socket window to `64K` for both UL and DL iperf3
  transfers. This prevents the client control channel from issuing
  `TEST_END` while a large unacknowledged payload remains queued across a
  lossy GTP-U path.
- Preserve the byte-exact contract: a successful traffic step requires the
  receiver report to equal the requested sender byte count.
- Reproduce the prior short receive in disposable network namespaces with
  packet loss and verify exact UL/DL delivery with the bounded window.

## 0.17.2 (polaris-control-api)

- Install an idempotent source-policy rule inside each owned UE network
  namespace after PDU establishment: priority `10000`, source UE IPv4,
  routing table `100`, default device the verified `uesimtunN` interface.
- Remove that namespace-local rule and route on PDU release, detach and UE
  stop. No host route or Open5GS configuration is changed.
- Run UL and DL pre-flight as
  `ip route get <DN sender> from <UE IPv4>` and retain the bounded raw kernel
  result in successful step measurements as well as failure evidence.
- Derive `GET /api/v1/version` from `CARGO_PKG_VERSION` to prevent release
  metadata drift.
- Add unit coverage for rule idempotence and source-policy pre-flight.

## 0.17.1 (polaris-control-api)

- UL / DL pre-flight: before spawning iperf3 the API now runs
  `ip route get <destination>` inside the UE network namespace
  (`nsenter --target <ue_pid> --net -- ip route get …`) and parses the
  `dev` field. If the kernel resolves the route to anything other than the
  verified UE TUN interface (`uesimtun*`), the step fails fast with
  `UL_ROUTE_NOT_VIA_UE_TUN` (uplink leg) or `DL_ROUTE_NOT_VIA_UE_TUN`
  (downlink receiver), *without* spawning iperf3. The raw `ip route get`
  output and the parsed `{expected_dev, actual_dev, src}` land in
  `failure_evidence.preflight` so the operator can prove the UE routing
  state at the exact spawn attempt time, even when iperf3 is never run.
- UL client bind: the UE-side iperf3 client now runs with
  `-B <ue_ip> --bind-dev <uesimtun*>` so the socket cannot pick an
  unrelated host interface. The pinned `release/iperf3-3.21` binary
  advertises `--bind-dev` (SO_BINDTODEVICE) — a feature added upstream
  in iperf3 3.17 and present in 3.21.
- Pre-flight failure body also carries over when iperf3 is spawned and
  then fails later (`IPERF3_UL_FAILED`): the `preflight` object is
  appended to the regular `failure_evidence` body, so a "command sent
  but 0 bytes" post-mortem still shows the UE route state at the time
  of the attempt.
- Tests: new unit coverage for `parse_ip_route_get` /
  `evaluate_ue_route_preflight` with two shapes (route-via-TUN → ok,
  route-via-host-iface → `UL_ROUTE_NOT_VIA_UE_TUN`) and for the
  composite `preflight_failure` JSON body.
- Persist bounded iperf3 JSON `stdout` alongside `stderr`, exit code and the
  executed command in step `failure_evidence`. iperf3 emits `-J` connection
  errors on stdout, so prior evidence could retain an empty stderr while losing
  the actionable diagnostic. Both streams are independently limited to 2048
  characters and no command execution behaviour or safety gate is changed.

## 0.17.0 (polaris-control-api)

- Added `GET /api/v1/subscribers/:slot` — returns the sanitized subscriber
  record (slot, state, PLMN, SNSSAI, DNNs, AMBR) plus
  `linked_profile_ue_ids[]` resolved via the plan file and the UE profile
  registry. Identity and authentication material remain `PROTECTED` and
  are never surfaced in the response. Read-only, no operator role needed.
- Added `PUT /api/v1/subscribers/:slot` — operator-gated partial update
  of slice (SST/SD), DNNs, AMBR and/or authentication material (K/OPc).
  `k` / `opc` are strictly write-only: they are never present in the
  response body. The served-network policy still gates the slice/DNN
  values. Backend writes the Open5GS record and takes a mongodump backup
  first via the existing `backup()` path.
- Added `POST /api/v1/subscribers/generate` — operator-gated bulk
  generator. Allocates `count` fresh IMSIs in the fixed `001/01` range
  (lowest free MSIN) and provisions each with `K`/`OPc` material drawn
  from the OS CSPRNG (`rand_core::OsRng` via `getrandom`). Response is
  the array of `{slot, state:"PROVISIONED", subscriber_identity:"PROTECTED",
  authentication_material:"PROTECTED"}` — `K` and `OPc` never leave the
  server. `count` is bounded by `GENERATE_MAX_COUNT=1000`.
- Enriched `GET /api/v1/scenarios/:job_id/steps` with job-level `state`,
  `started_at`, `ended_at`, `duration_ms` and a `failure` object
  summarizing the first FAILED step: `{step_id, step_name, code, message,
  failure_evidence, started_at, ended_at, duration_ms}`. `failure_evidence`
  is the bounded iperf3 payload delivered in 0.16.3 and is passed through
  unchanged. No change to the per-step records.
- `subscriber_provisioning.rs` grew the new `SubscriberUpdate` type, three
  new `SubscriberBackend` trait methods (`fetch_slot`, `apply_update`,
  `taken_imsis`), a `generate_authentication_key()` CSPRNG helper and an
  `allocate_next_imsis()` next-free MSIN allocator. All new logic lives
  in that module — `lib.rs` only grew by the three HTTP handlers and the
  update-side validator.
- Tests: added seven new unit tests in `subscriber_provisioning::tests`
  covering CSPRNG uniqueness, next-free IMSI allocation (including the
  `SUBSCRIBER_GENERATE_COUNT_INVALID` bound), partial update behaviour,
  authentication-material rewrite, missing-slot fail-closed, sanitized
  fetch and the `taken_imsis` projection. Every sanitize-oriented test
  explicitly asserts the serialized JSON does **not** contain the raw
  IMSI, K or OPc.
- Does not touch `POLARIS_IPERF3_PATH`, `failure_evidence` (0.16.3) nor
  the pinned `release/iperf3-3.21/*` runtime (2e89c71).

## 0.16.4 (polaris-control-api)

- Port the 0.15.5 portable test harness and `lab_nf_tests` module on top of
  Codex's 0.16.3 iperf failure-evidence base. Does not touch
  `POLARIS_IPERF3_PATH` nor `failure_evidence` (both delivered in 0.16.3).
- Portable P0 test paths: the two hard-coded `/root/.hermes/cache/scratch/*`
  literals in `apps/api/src/lib.rs` (previously `state()` and
  `restored_open5gs_copy_accepts_provisioning_without_secret_disclosure`)
  now use `std::env::temp_dir()`, so the suite runs on any workstation /
  CI runner, not only the Codex Hermes sandbox.
- Tests: the `uid=0` check in the UE profile registry and the scenario
  catalog loaders is split via `#[cfg(all(unix, not(test)))]` (strict,
  release) vs `#[cfg(all(unix, test))]` (owner uid tolerated, group /
  world-write bits still refused). Covers
  `UE_PROFILE_REGISTRY_PERMISSIONS_UNSAFE` and
  `SCENARIO_CATALOG_PERMISSIONS_UNSAFE`.
- Tests: three new `lab_nf_tests` units exercise Codex's
  `network_function_observation` + the 12-entry `LAB_NETWORK_FUNCTIONS`
  catalogue (AMF, SMF, UPF, NRF, AUSF, UDM, UDR, PCF, NSSF, BSF, Kamailio,
  RTPengine). Absent containers render `observed:false` with null
  `process_state` / `health`, matching the honest-UI contract.
- No change to runtime behaviour, no deployment, no shared service touched.

## 0.16.2 (polaris-control-api)

- Store Open5GS UE-AMBR and session AMBR values as native numeric BSON values so Open5GS 2.8 can produce AccessAndMobilitySubscriptionData.

## 0.16.1 (polaris-control-api)

- Fix controller-owned scenario resource validation so it no longer depends on the legacy shared UE-01 container or profile; disk, memory, CPU and shared lab infrastructure health gates remain enforced.
- Normalize persistent controller UE identifiers and render the configured/default NSSAI fields required by runtime provisioning validation.
- Scope launch-time provisioning verification to the explicitly requested controller-owned UE so unrelated legacy profiles cannot block or contaminate its lifecycle decision.
- Verify POLARIS-owned launch profiles byte-for-byte against the current protected MongoDB subscriber record, while retaining the legacy attestation path for non-POLARIS records.

## 0.16.0 (polaris-control-api)

- Adds a health-gated N6 downlink sender for `traffic_dl`, using a digest-pinned, non-public
  iperf3 container with a scoped route to the UE pool through the UPF.
- Measures downlink bytes independently in the DN sender report and the UE-network-namespace
  receiver report; no UE identity or authentication material is exposed.
- Routes `traffic_ul` to a one-shot iperf3 receiver in the same DN container and records both the
  UE sender count and DN receiver count instead of assuming a server on the UPF tunnel address.
- Advertises `traffic_dl` as executable only while the sender container, N6 identity and UE route
  are all measured healthy; otherwise the existing `DL_SENDER_NOT_AVAILABLE` fail-closed contract
  remains active.

## 0.15.4 (polaris-control-api)

- Adds `PATCH /api/v1/ue-profiles/:ue_id/scenario`, which updates only scenario metadata and preserves the protected subscriber link and provisioning evidence.
- Preserves `subscription_verified` on full profile updates when all subscriber-facing fields are unchanged; subscriber/network changes still require revalidation.
- Rejects assignment of definitions containing unavailable steps with the exact backend code (`DL_SENDER_NOT_AVAILABLE` or `IMS_NOT_AVAILABLE`).

## 0.15.3 (polaris-control-api)

- Patch: expose a measured `observed.nfs[]` inventory from `/lab` for every Open5GS network
  function plus Kamailio and RTPengine, using Docker inspect state and health only.
- Honesty: missing or uninspectable containers are returned with `observed: false` and null state
  fields; the API never fabricates network-function availability.

## 0.15.2 (polaris-control-api)

- Patch: create a UE from a POLARIS-owned subscriber using IMSI alone; K and OPc are resolved
  inside the protected subscriber backend and never cross the API response or audit boundary.
- Patch: accept canonical 15-digit IMSIs and the equivalent `imsi-` form for subscriber
  provisioning, UE creation and CSV imports.
- Safety: validate subscriber S-NSSAI and DNN against the explicitly configured AMF/SMF served
  network policy; unsupported slices fail with `422 SNSSAI_NOT_SERVED`.

## 0.15.1 (polaris-control-api)

- Patch: raise the persistent UE profile registry ceiling to 100,000 while retaining the
  independently bounded live-UE limit, server-side pagination, search and atomic persistence.
- Validation: benchmark 100,000-profile bulk persistence/reload and paginated search, and exercise
  the production MongoDB adapter against an isolated restored Open5GS copy.

## 0.15.0 (polaris-control-api)

- Minor: add Operator/CSRF-protected Open5GS subscriber provisioning with mandatory protected
  `mongodump`, POLARIS ownership markers, sanitized inventory, and bounded CSV batching.
- Minor: create UE profiles by protected subscriber identity, add bounded CSV profile import,
  sanitized profile detail, and real gNB/owner/PLMN/DNN menu registries.
- Security: IMSI, K, and OPc remain write-only and are excluded from response types, audit targets,
  errors, and logs; existing non-POLARIS subscriber records are never modified.

## 0.14.0 (polaris-control-api)

- Minor: advertise the scenario-definition step contract through `GET /api/v1/capabilities`,
  separating executable step types from the explicitly unavailable downlink and IMS types.
- Contract: publish the enforced traffic-byte, repeat-depth, and resolved-step ceilings without
  changing the live-definition authorization lock or any runtime safety gate.

## 0.13.0 (polaris-control-api)

- Minor: add four immutable, clonable traffic/voice scenario templates and bounded nested
  `repeat`, `idle`, `detach`, `traffic_ul`, and `traffic_dl` contracts.
- Minor: add duration estimates plus versioned JSON v2 export/import with Operator, CSRF,
  collision, schema, and payload-size enforcement.
- Safety: keep IMS steps locked with `IMS_NOT_AVAILABLE`, reject downlink execution without a
  verified DN sender, retain the global live-definition feature lock, and record measured iperf3
  uplink bytes only after an authorized execution.

## Follow-up security ticket — migrate React Router 7

- The laboratory deployment decision accepted the two moderate advisories reported by
  `npm audit --omit=dev` for the explicitly pinned `react-router-dom` 6.30.6 candidate.
- Track a separately reviewed migration to React Router 7; do not apply npm's breaking
  `--force` upgrade without frontend contract and browser regression validation.

## 0.12.1 (polaris-control-api)

- Patch: execute `pdu_establish` with UERANSIM `nr-cli ps-establish` and `pdu_release` with
  `nr-cli ps-release-all` inside the exact controller-owned UE container.
- Patch: require an observed `ACTIVE`/`INACTIVE` state after each PDU command; PDU release no
  longer stops the UE process.

## 0.12.0 (polaris-control-api)

- Minor: execute the six V1 scenario-definition steps through the existing controller-owned UE
  runtime, bounded UDP profile and `MAX_LIVE_UES` selection limit.
- Minor: keep definition execution fail-closed behind
  `POLARIS_DEFINITION_LIVE_ENABLED=true` (disabled by default), persist real per-step transitions,
  and make Operator stop clean up only UEs started by the job.
- Minor: allow `polaris-provisioning-attest` to attest the current protected UE profile registry
  after slot binding; the documented helper remains dry-run by default and never writes Open5GS.

## 3.2.5 - Candidate UE inventory latency correction

- Replaced process-global UE observation coordination with per-application state.
- Reuse a verified runtime observation for a bounded ten-second interval so route polling does not repeatedly block on Docker inspection.
- Preserve a full refresh after process restart or cache expiry; configuration and runtime counts remain authoritative.
- Added a regression for the route-navigation race that previously caused the nineteenth browser test to time out.

## 3.2.4 - E2E-002 release stabilization

- Restored the certified V3.2 Apply Configuration, Add UE, multi-selection and selected Start/Stop controls on top of the CPU-evidence candidate.
- Kept configuration changes independent from UE execution and retained Viewer, ownership and execution-mode locks.
- Added fail-closed credential injection for authenticated browser tests and serialized candidate logins.
- Reconciled production-browser assertions with the evidence-bearing CPU safety contract without weakening a hard block.

## 3.2.3 - Evidence-preserving CPU admission decisions

- Persisted bounded, protected, atomic CPU safety decision evidence with exact trigger metrics and thresholds.
- Split warnings into non-blocking and latched blocking states with consecutive-sample and recovery hysteresis.
- Kept stale telemetry, unknown capacity, cgroup exhaustion, sustained pressure/throttling, and resource overcommit fail-closed.
- Added operator-only decision inspection and evidence-bearing HTTP 503 responses.

## 3.2.2 - UE-targeted bounded traffic (offline validated)

- Replaced the load-average/API-quota CPU gate with host `/proc/stat` deltas, PSI, cgroup capacity and throttling deltas, scenario budgets, telemetry freshness, consecutive samples, and hysteresis.
- Added precise READY/WARNING/BLOCKED safety states and production UI evidence without changing CPU quotas or enabling live execution.
- Added selection of verified controller-owned, registered UEs with active PDU Sessions to the Traffic Generator.
- Bound each traffic job to an allowlisted UE registry record, exact owned container, network namespace, `uesimtunN` interface, UE source IP, and approved route.
- Preserved the five-datagram UDP profile and fixed laboratory destination without accepting browser-provided interfaces, namespaces, commands, or destinations.
- Kept traffic and UE lifecycles independent; exact-job Stop changes traffic state without terminating the UE or releasing its PDU Session.
- Added sustained CPU-contention rejection plus targeted ownership, TUN/route, PDU, duplicate-job, RBAC, and shared-UE regression coverage.
- Added a non-applied four-profile configuration plan for UE-01 through UE-04. No production state or simulator process was changed.

## 3.2.1 - Configured UE profile visibility

- Merged configured UE profiles with observed and controller-owned runtime state using stable internal UE IDs.
- Made the Console and UE Manager show one honest state row for every configured profile.
- Kept provisioning, process, Registration, PDU Session, and traffic state as independent dimensions.
- Added explicit `NOT_STARTED`, `NOT_OBSERVED`, and `INACTIVE` states without fabricating runtime activity.
- Added regression coverage for 1, 3, 5, and 10 configured profiles and retained lifecycle authorization locks.

## 3.2.0 - Ten synthetic subscriber readiness

- Provisioned nine missing synthetic Open5GS records for a total of ten compatible subscribers.
- Added ten restricted UERANSIM profiles with unique authentication material.
- Increased configurable UE capacity from five to ten while retaining a live-certified maximum of one.
- Added an idempotent, compensating-rollback provisioning workflow and sanitized verification reports.
- Preserved all live UE/gNB lifecycle locks; no simulator process was started.

## 3.1.1 - Configurable inventory counts

- Added persistent Operator-controlled UE (1..5) and gNB (1..2) inventory selectors.
- Added configuration-only `Add UE` workflow and explicit subscriber provisioning status.
- Separated configured, running, registered, and PDU-active UE counts.
- Added atomic configuration persistence, RBAC/CSRF enforcement, and audit logging.
- Kept all uncertified UE/gNB lifecycle operations locked; configuration never starts processes.

## 3.0.0-dev

- Replaced the guided V2 dashboard with one compact operational console.
- Added complete light, dark, and system themes using semantic tokens with persisted preference.
- Added real node inventory, separate UE process/registration/PDU state, and precise lifecycle restrictions.
- Added independent scenario and traffic controls without coupling traffic completion to UE lifecycle.
- Added measured CPU/memory telemetry and explicit zero/no-data traffic visualization.
- Added the `/api/v1/nodes` inventory and CPU sampling to system health.
- Preserved Viewer/Operator/Administrator enforcement, CSRF, exact process ownership, disk gates, and the single certified bounded profile.
- Added browser validation at 1440×900 and 1920×1080 in both themes.

## 2.1.2-dev

- Added one authoritative runtime snapshot containing the active job and most recent terminal job.
- Preserved short-lived `COMPLETED`, `FAILED`, and `STOPPED` results across polling, page refreshes and browser sessions.
- Added start/end timestamps, terminal result, owned PID and explicit UDP write accounting to persisted jobs.
- Corrected duplicate Start and Stop-after-completion behavior without weakening exact process ownership.
- Updated the Dashboard Scenario Status panel without redesigning the application.
- Audited UERANSIM 3.3.0 multi-UE capabilities; new UE creation remains locked and current 85.04% disk utilization blocks capture-producing tests.

## 2.1.1-dev

- Replaced browser-stored bearer credentials with named Operator/Administrator accounts, Argon2id password hashes, server-side sessions, Secure HttpOnly SameSite cookies, and CSRF protection.
- Added explicit login/logout UI and a root-only `polaris-userctl` provisioning command.
- Required an authenticated, session-bound validation of the exact certified profile before Start.
- Kept new UE creation, multi-UE, gNB lifecycle and all unrestricted control locked.
- Added Viewer denial, login, CSRF, role, resource-gate, certified-profile, idempotent Start/Stop and password-storage tests.

## 2.1.0-dev

- Added configurable Viewer, Operator, and Administrator authorization.
- Added a persistent certified-scenario policy registry and Administrator enable/disable control.
- Enabled Start/Stop only for `bounded-existing-ue-udp-v1` using the existing healthy UE and PDU Session.
- Added exact controller-owned process handles, idempotent duplicate Start, exact-job Stop, persisted history, and restart recovery.
- Added append-only audit logging for authorization, Start, Stop, resource failures, and policy changes.
- Replaced the generic lock message with explicit capability and execution states in the Web UI.
- Kept new UE creation, multi-UE execution, gNB lifecycle control, LTE, ICMP, and TCP locked.
- Kept public HTTP in Viewer mode by stripping authorization at the public-IP proxy; Operator control is available through the existing HTTPS endpoint or localhost tunnel.

## POLARIS-LIVE-001

- Added a single-purpose, one-time backend execution path for the explicitly approved bounded test.
- Reused the already healthy shared gNB, UE registration, and PDU session without restarting them.
- Sent exactly five UDP datagrams through `uesimtun0` to the controlled UPF endpoint.
- Consumed and removed the ephemeral approval, kept generic Start/Stop locked, and verified zero orphan processes.
- Recorded ten N3 GTP-U packets: five uplink UDP packets and five downlink ICMP port-unreachable responses.

## 2.0.0-dev

- Replaced the audit-style landing page with a four-step guided simulator workflow.
- Added capability-driven 5G SA and LTE cards; LTE remains disabled because Attach is not certified.
- Added bounded scenario validation, real UE inventory state, traffic state, and running-scenario views.
- Added the dedicated Running Scenarios workspace and clearer profile/runtime distinctions.
- Expanded real host and laboratory health reporting without adding control privileges.
- Preserved the live-execution approval gate: no simulator process is started by this release.
- Preserved public read-only access after the operator's prior token-removal request.

## 1.0.0-dev

- Removed all access-token requirements by explicit operator request; the public role remains read-only and live execution stays locked.
- Added isolated React/TypeScript control application and Rust API.
- Added bounded UE/scenario/traffic validation.
- Added exact controller-owned job registry and idempotent lifecycle model.
- Added permanent 75/80/85/90 disk safety guard with fail-closed monitoring.
- Kept live UERANSIM execution disabled pending explicit approval.

# 3.1.0 — 2026-10-25

- Added a bounded five-profile UERANSIM model with unique UE/profile validation and secret-safe configuration rendering.
- Added independent controller-owned UE process, Registration, PDU Session and traffic state tracking.
- Added idempotent single/group Start and Stop contracts with partial-failure isolation and exact ownership.
- Updated UE Manager with configured/running/registered/PDU counts, profile selection and lifecycle controls.
- Added a non-deployed gNB-02 plan; multi-gNB execution remains locked for LIVE-005.
- Preserved the one-UE live certification boundary and kept all new lifecycle actions locked pending LIVE-002/003/004.
- Added offline multi-UE, authorization, resource-safety and UI regression coverage.
## API 0.10.0 — minor

- Add an atomic, versioned scenario-definition catalog with CRUD and clone routes.
- Add nested scenario/step fixed-loop V1 validation, backend random-parameter resolution, persisted
  resolved values, definition-based offline execution history, and per-job step status retrieval.
- Add versioned UE inventory snapshots and fixture-backed browser inventory coverage.
- Preserve the legacy certified scenario endpoints and reject definition-based Live execution until
  it receives separate authorization and validation.

## Web 3.2.2 — patch

- Replace four lab-state-dependent inventory checks with a strict, known API fixture.
- Keep a separate read-only Live inventory test disabled by default and manually selectable.

## 0.11.0 (polaris-control-api) / 0.4.0 (ueransim-adapter)

- Minor: `serving_gnb` now feeds the UERANSIM `gnbSearchList` through a gNB registry
  (laboratory default `GNB-01 → 10.77.0.20`, or a validated JSON file named by
  `POLARIS_GNB_REGISTRY_PATH`). An unknown gNB is refused with `UNKNOWN_SERVING_GNB`; there is
  no silent fallback. Rendering for `GNB-01` is byte-identical to 0.10.0, so existing
  provisioning attestations remain valid.
- Minor: new read-only `GET /api/v1/gnbs`.
- Minor: `POST /api/v1/ue-profiles` accepts `provisioning_slot` to bind a profile to a subscriber
  already provisioned in Open5GS. SUPI/K/OPc are read server-side from the private V3.2 plan
  (`POLARIS_SUBSCRIBER_PLAN_PATH`, default `/var/lib/polaris-control/subscriber-secrets/v3.2.plan`,
  mode must deny group/other). A slot binds at most once. Open5GS is never written.
- Minor: new read-only `GET /api/v1/ue-profiles/provisioning-slots` (slot ids and bound UE only).
# 0.16.3

- Preserve bounded iperf3 failure evidence (command, exit code and bounded stderr).
- Use the packaged POLARIS iperf3 client instead of assuming `/usr/bin/iperf3` exists.
