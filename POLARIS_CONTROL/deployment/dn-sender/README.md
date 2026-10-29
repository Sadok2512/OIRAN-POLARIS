# POLARIS N6 downlink sender

This component provides the DN-side iperf3 client used by the `traffic_dl` scenario step. It is
attached only to the existing external `oiran-lab-n6` Docker network, publishes no host ports and
uses the digest-pinned image declared in `compose.yaml`.

The systemd unit starts the container and then installs one route inside that container's network
namespace:

```text
10.46.0.0/16 via 10.77.24.13 src 10.77.24.30
```

POLARIS independently checks the container running/health state, its exact N6 address and this
route before advertising `traffic_dl` as executable. A missing or unhealthy component preserves
the fail-closed `DL_SENDER_NOT_AVAILABLE` response.

Deployment installs this directory at `/opt/polaris-control/dn-sender`, installs and enables
`polaris-dn-sender.service`, and installs `polaris-control-dl-sender.conf` as a systemd drop-in for
`polaris-control.service`. Rollback removes the drop-in, restores the previous API binary, restarts
only POLARIS Control, and stops/disables `polaris-dn-sender.service`.

No UE is started by this component. During an authorized scenario, POLARIS starts a one-shot
iperf3 receiver in the already-running UE network namespace, invokes the DN client with an exact
bounded byte count, and records both sender and receiver byte counters.
