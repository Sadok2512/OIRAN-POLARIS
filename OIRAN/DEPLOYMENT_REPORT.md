# OIRAN Capture Helper Deployment Report

Deployment completed at 2026-10-25T21:22:14Z from implementation commit `dc8479b4dcdbee11f07c7f37e76ab95c257d30dc` on branch `feat/live-vprobe-capture-v1`.

## Outcome

- Installed the reviewed API at `/opt/oiran/bin/oiran-api`.
- Installed the isolated helper at `/opt/oiran/bin/oiran-capture-helper`.
- Created the dedicated `oiran-capture` service identity (UID 995, GID 987).
- Enabled and started only `oiran-capture-helper.service` and `oiran-api.service`.
- Replaced the stale transient API unit with the persistent hardened unit in `/etc/systemd/system/oiran-api.service`.
- Removed the API's former `tcpdump` group and packet-capture capabilities.
- Verified authenticated `ValidateCapture` for N2, N3, and N4. No capture was started.

The full reviewed API SHA256 is `ad560d2bd3aa7d790f11efc12c91f231603b99e5bd28236c5a1326c147c7e9c3`. The hash printed in the deployment request omitted the substring `5a1326`; the deployed artifact matches the full hash previously established for the requested commit.

## Service impact

No POLARIS, POLARIS Control, Portal, ETV, OTV, PostgreSQL, Open5GS, or UERANSIM service was restarted or modified. All Open5GS and UERANSIM containers were healthy after deployment. The existing POLARIS capture container has a pre-existing restart count of 25 and remained healthy; this deployment did not restart it.

## Live execution

No live capture, simulator traffic, or PCAP write was executed. The next step requires separate authorization for the bounded N3 test.
