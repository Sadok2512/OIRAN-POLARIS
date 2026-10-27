# S3.2.2 user-plane functional test

## Outcome

Scenario `OIRAN_5G_PDU_SESSION_DATA_V1` passed. The existing synthetic UE `UE-A` was registered with active PDU Session ID 1 and `uesimtun0=10.46.0.4/16`. Five 30-byte UDP datagrams were sent through that TUN to the authorized UPF gateway `10.46.0.1:9`; the gateway returned five ICMP port-unreachable responses. No public destination was contacted.

Traffic ran from `22:22:43.660165635Z` to `22:22:43.772972948Z`. TUN counters changed by exactly five TX packets / 290 bytes and five RX packets / 430 bytes. The initial `ping` attempt did not execute because the binary is absent and changed no counter. No package was installed.

The test did not alter routes, firewall, NAT, Docker networks, configuration, or service lifecycle. It used Bash's existing UDP socket support and terminated automatically after five writes.

## Session continuity

The UE, gNB, AMF, SMF and UPF had no restart between establishment at 20:07 UTC and the user-plane test. Capture-only restart did not change session state. N2/N4 control evidence and N3 packets share both directional TEIDs and their exact endpoints, which prevents an unrelated time-overlap claim.
