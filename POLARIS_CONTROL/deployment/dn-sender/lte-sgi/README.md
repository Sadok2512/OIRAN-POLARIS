# LTE SGi DN sidecar — candidate definition

This directory contains **candidate** artifacts for the dedicated LTE SGi DN
sender. Nothing in this directory may be deployed verbatim.

## Scope

The POLARIS LTE runtime (`srsran_controller::DockerSrsranRuntime`) requires a
DN container that is **physically and logically distinct from the 5G N6
sender** (`polaris-dn-sender`) in order to pass the LTE preflight gates:

- `LTE_TRAFFIC_PEER_NOT_CONFIGURED` — `POLARIS_LTE_TRAFFIC_PEER_IP` unset.
- `LTE_SGI_COLLIDES_WITH_N6` — the LTE peer equals the 5G N6 sender.
- `LTE_DN_SENDER_NOT_CONFIGURED` — `POLARIS_LTE_DN_SENDER_CONTAINER` unset.
- `LTE_DN_SENDER_COLLIDES_WITH_N6` — the LTE DN container name equals the
  5G N6 container `polaris-dn-sender`.
- `LTE_DN_SENDER_NAME_INVALID` — illegal characters in the container name.
- `LTE_PGW_U_NEXT_HOP_NOT_CONFIGURED` / `LTE_PGW_U_NEXT_HOP_INVALID` — the
  PGW-U LTE next-hop is unset or not a valid IPv4.
- `LTE_UE_SUBNET_INVALID` — the UE subnet CIDR is malformed.
- `LTE_DN_SENDER_TOOLING_MISSING` — the DN container cannot execute
  `ip`, `ping` or `iperf3` (exit codes 126/127 or `command not found`).
- `LTE_DL_RETURN_ROUTE_VIA_FORBIDDEN_DEV` — the DN's return route to the UE
  subnet exits via an interface listed in `POLARIS_LTE_FORBIDDEN_RETURN_DEVS`
  (defaults include `lo`, `null0`, `blackhole`, `eth0`, `oiran-lab-n6`).
- `LTE_DL_RETURN_ROUTE_MISSING_VIA` / `LTE_DL_RETURN_ROUTE_WRONG_NEXT_HOP` —
  the return route is direct or hops through a non-PGW-U address.
- `LTE_UL_ROUTE_NOT_VIA_UE_TUN` — UE SGi route does not use `tun_srsue`.

Everything above is enforced **offline**, before any ping or iperf3 is spawned,
so the sidecar can be prepared without any production impact.

## Files

| File | Purpose |
| --- | --- |
| `compose.yaml` | Compose service definition for the SGi DN sidecar. **Image is `pending@sha256:0…0`** — Codex must pin the real digest before activation. |
| `polaris-control-lte-sgi.conf` | systemd drop-in with the four required env vars for the LTE path, **all commented out**. Codex un-comments and sets after reservation. |

## Hardening

- `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, `read_only: true`.
- Non-root user `65532:65532` (default `nonroot` of distroless-like images).
- `pids_limit`, `mem_limit`, `cpus` set to prevent sidecar misuse.
- No volume mounts; no host network; no raw PCAP access.
- Healthcheck verifies the 10.45.0.0/16 return route is installed.

## Codex checklist before activation

1. Reserve the SGi network `oiran-lab-sgi` and the IP `10.77.16.30/24` (or
   alternative — update `POLARIS_LTE_TRAFFIC_PEER_IP` and the compose network
   accordingly).
2. Confirm/replace the PGW-U LTE next-hop `10.77.16.15` for the
   `10.45.0.0/16` return route.
3. Build or receive a dedicated LTE SGi DN image containing `iproute2`,
   `iputils-ping`, `iperf3`, and nothing extraneous. Pin its digest. Record
   it as `SIDE_CAR_IMAGE_DIGEST` in the next mission report.
4. Un-comment the four `Environment=` lines in
   `polaris-control-lte-sgi.conf` with the confirmed values.
5. Deploy under a separate maintenance window; this is **not** performed by
   the POLARIS release itself.
