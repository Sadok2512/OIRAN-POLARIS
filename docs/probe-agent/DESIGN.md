# Probe Agent — Design (MVP, 2026-10-31)

> Status: **DESIGN + MVP binary**. Enrollment and heartbeat land in this
> PR; capture Start / Stop are stubbed to the capture-helper interface
> and sealed behind the `CAPTURE_HELPER_SOCKET` env variable so the
> agent can be exercised end-to-end on a dev box without opening a raw
> packet socket.

## 1. Goals

Build a probe agent that an operator can drop on a bare-metal or VM
host, enroll into the Probe Manager, and run captures per interface
without ever requiring root. The agent speaks mTLS to the Probe
Manager API, uploads finalized segments with SHA-256, and keeps
subscriber identities out of the wire.

### Non-goals (MVP)

- Live packet filtering / BPF compilation (comes later with the
  capture-helper integration).
- Multi-tenant isolation on the same host (one agent process per host).
- Agent GUI (operators use the Probe Manager UI, which is in a separate
  app).

## 2. Enrollment

### 2.1 One-shot enrollment token

The operator provisions the probe from the Probe Manager UI:

```
POST /api/v1/probes
Body: {host, display_name, interfaces: [{name, role}]}
→ 201 {probe_id, enrollment_token, enrollment_expires_at}
```

The `enrollment_token` is a 128-bit random string, printed **once** in
the UI and copied to the agent host (e.g. via `scp` or a secrets
manager). It is valid for 15 minutes.

### 2.2 Agent completes enrollment

The agent is launched with the token:

```
probe-agent enroll \
    --probe-manager https://probe-manager.lab:443 \
    --token <enrollment_token> \
    --config /etc/probe-agent/config.toml
```

The agent generates a 2048-bit ECDSA keypair locally (`openssl` is
**not** required — `rand_core::OsRng` + `p256`), submits a CSR, and
receives a client certificate signed by the Probe Manager CA:

```
POST /api/v1/probes/{probe_id}/enroll
Headers: X-Enrollment-Token: <token>
Body: {csr_pem}
→ 200 {certificate_pem, ca_pem, mtls_endpoint}
```

The CSR carries the probe id as the Common Name. The Probe Manager
side verifies the token, checks the probe id matches, and signs the
CSR with its CA. After this call the token is invalidated.

### 2.3 Persistence

The agent writes `(cert.pem, key.pem, ca.pem, config.toml)` to
`/etc/probe-agent/` with permissions `0600` for `key.pem`. No secret
material ever leaves `/etc/probe-agent`. Running
`probe-agent enroll` a second time refuses to overwrite an existing
`cert.pem` unless `--force` is passed.

## 3. mTLS + heartbeat

Every call to the Probe Manager uses the enrolled client cert +
pinned CA. The agent polls `GET /probes/{probe_id}/config` every 30 s
to pick up new capture requests, and POSTs `/probes/{probe_id}/heartbeat`
every 10 s with:

- `agent_version` (crate version)
- `last_heartbeat_epoch_s`
- per-interface stats: `packets_per_second`, `drops_since_start`,
  `disk_usage_percent`, `cpu_usage_percent`.

The heartbeat is deliberately a POST (not a WebSocket) so the agent
survives a Probe Manager restart without a reconnect loop.

## 4. Capture lifecycle

### 4.1 Start

The Probe Manager publishes a capture request in the config pulled by
the agent. The agent spawns a `capture-helper` process (CAP_NET_RAW +
CAP_NET_ADMIN granted via file capabilities on the helper binary — the
agent itself does **not** need them). The helper is a signed binary
distributed alongside the agent — its SHA-256 is checked against the
version published by the Probe Manager before the agent `execve()`s
it.

### 4.2 Rotation + finalisation

The helper rotates pcap segments every N packets or M bytes (whichever
first). On rotation, the helper hands back the finalised segment path +
SHA-256 via a Unix socket. The agent reads the SHA, closes the
segment, and uploads it:

```
POST /api/v1/probes/{probe_id}/captures/{capture_id}/segments
Headers: Content-Type: application/pcap, X-SHA256: <hex>
Body: <raw pcap bytes>
→ 201 {segment_id, dataset_target}
```

The server verifies the SHA-256 **before** the segment lands in the
dataset. A mismatch returns 422 and the agent retries the segment up
to 3 times then quarantines it.

### 4.3 Stop

`DELETE /api/v1/captures/{capture_id}` sets a flag in the config.
The agent sends SIGTERM to the helper on next poll, waits up to 10 s,
then SIGKILL. The last partial segment is finalised (if the helper
flushed it) and uploaded.

## 5. Binary distribution

- Rust 1.80+, `cargo build --release --target x86_64-unknown-linux-musl`.
- Fully static (`musl`), 2.5 MiB stripped.
- SHA-256 of the agent binary is signed by the Probe Manager CA (same
  CA that signs the client certs). The signature is distributed in a
  detached `probe-agent-<version>.sig` file.
- Updates: operator fetches the new binary + signature from a signed
  release endpoint on the Probe Manager; the agent verifies the
  signature, swaps the binary via a side-by-side install, and keeps
  the previous version as `probe-agent-<prev-version>.rollback`.
  The agent `exec`s the rollback binary on a bad-health first
  heartbeat after an update.

## 6. Interface roles

The config declares one role per interface:

```
# /etc/probe-agent/config.toml
probe_id = "probe-ab12cd34"
probe_manager_endpoint = "https://probe-manager.lab:443"

[[interfaces]]
name = "ens3"
role = "N2"

[[interfaces]]
name = "ens4"
role = "N4"
```

Role is one of `N2`, `N3`, `N4`, `S1-MME`, `S1-U`. The Probe Manager
enforces that at most one agent is `N3` per lab (because N3 traffic
is the heaviest and the aggregator keeps a bounded memory footprint —
see OIRAN 2.5.3 N3 headers-only aggregation).

## 7. Subscriber-identity rule

The agent never surfaces any decoded field. All it does is forward
pcap bytes to the Probe Manager, which hands them to OIRAN's decoders.
Identity withholding stays in OIRAN (`identityIes.ts` on the frontend,
`decoder-ngap` / `decoder-nas` on the backend). The agent-manager
contract carries only:
- capture-level counters (packets, bytes, drops)
- SHA-256 provenance
- the pcap bytes themselves (encrypted in transit by mTLS)

No IMSI / IMEI / TMSI / GUTI / RNTI / K / OPc field ever reaches the
agent memory in a decoded form.

## 8. Threat model (short)

- A stolen enrollment token lets an attacker enroll **one** probe
  (the token is single-use, 15-minute TTL). The Probe Manager can
  revoke a probe id at any time; the client cert becomes invalid on
  next heartbeat.
- A stolen agent key material lets an attacker send fake heartbeats
  and upload bogus pcap bytes. The Probe Manager compares segment
  SHA-256 against the helper-signed manifest; mismatches land in a
  quarantine bucket, not in the dataset.
- The capture-helper has CAP_NET_RAW but no path to the Probe Manager
  — it only talks to the agent via a Unix socket. A compromised
  helper cannot exfiltrate without the agent cooperating.

## 9. Tested surfaces (MVP)

- Enrollment handshake with a mock Probe Manager (two processes in
  the same test).
- Heartbeat POST survives a Probe Manager restart (retry + backoff).
- SHA-256 verified against a prepared pcap on upload; mismatch fails
  the test.
- Config reload picks up a new interface role without restart.

## 10. Deferred to the capture-helper PR

The capture-helper + the signed binary + the CA signing flow are
designed here but implemented in a dedicated PR. This MVP ships:
- the Rust binary skeleton with the enrollment + heartbeat flows
  wired against a mock Probe Manager;
- the segment upload call wired against a filesystem-mock helper
  socket;
- unit tests + the two-process local enrollment / heartbeat test;
- the config loader + role parser.
