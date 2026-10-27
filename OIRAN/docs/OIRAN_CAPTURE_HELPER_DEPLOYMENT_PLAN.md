# OIRAN Capture Helper Deployment Plan

This is a review-only plan. The helper was not installed, enabled, or started during implementation.

## Preconditions

1. Confirm `/var/lib/oiran/captures` is on a filesystem below the 85% stop threshold.
2. Record ETV/OTV, POLARIS, Open5GS, and UERANSIM health.
3. Create a locked, non-login `oiran-capture` service account.
4. Resolve the numeric API UID/GID and helper UID; place numeric client IDs in `/etc/oiran/capture-helper.env`.
5. Copy the reviewed Release binary to `/opt/oiran/bin/oiran-capture-helper` as root-owned, mode `0755`.
6. Install the helper unit and the reviewed API drop-in.

## Authorized deployment commands

Commands below are proposals and were not executed:

```bash
useradd --system --home-dir /var/lib/oiran --shell /usr/sbin/nologin oiran-capture
install -d -o oiran-capture -g oiran-capture -m 0750 /var/lib/oiran/captures
install -o root -g root -m 0755 target/release/oiran-capture-helper /opt/oiran/bin/oiran-capture-helper
install -o root -g root -m 0644 deployment/oiran-capture-helper.service /etc/systemd/system/oiran-capture-helper.service
```

Provision the environment and replace `REPLACE_WITH_OIRAN_CAPTURE_UID`, then run `systemd-analyze verify` before any start. Remove the old API `CAP_NET_RAW/CAP_NET_ADMIN`, `Group=tcpdump`, and tcpdump-specific configuration at the same controlled change window.

## Validation sequence

1. Start the helper only; verify socket owner/mode and `/api/v1/health` remains unaffected.
2. Restart only the OIRAN API with the reviewed drop-in.
3. Run `ValidateCapture`; confirm `READY` and no PCAP creation.
4. Obtain separate approval for one short N3 capture with bounded traffic.
5. Verify state progression, packet provenance, manifest SHA-256, Stop ownership, and absence of orphan processes.

## Rollback

Stop and disable only `oiran-capture-helper.service`, remove the API drop-in, daemon-reload, and restart only OIRAN API. Preserve `/var/lib/oiran/captures` for forensic review. Do not delete captures automatically.
