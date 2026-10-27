# OIRAN P0 Offline Recovery Report

Source capture: `live-1792964646320-0003`

The immutable forensic inputs were validated independently with TShark and SHA256 before recovery:

| Interface | Packets | SHA256 |
|---|---:|---|
| N2 | 24 | `135e3ce9fdd5a2a4c799314b345fce2670fd81c86606bd912f7894196ef3d265` |
| N3 | 0 | `acc530668c8bc60b2d229281130b1899bfc81d70fdada5c34b3236c628f739c8` |
| N4 | 26 | `b03dcda272c50f0917844ac7e7fd819bf73e5c1faf33f080a427abc7dd6daa6b` |

Recovery output:

- Directory: `/var/lib/oiran/captures/recovered-datasets/live-1792964646320-0003`
- Dataset: `recovered-dataset-live-1792964646320-0003`
- Decoder version: `0.2.0`
- Recovered packets: 50
- Generated events: 20
- Events: 10 PFCP Heartbeat Requests and 10 PFCP Heartbeat Responses
- Decode/transport errors: 8 (2 non-NGAP N2 frames and 6 non-PFCP N4 ARP frames)
- Sessions: 0; the capture contains background control traffic, not evidence sufficient for a UE session
- Dataset integrity SHA256: `79b5100e1dc8b7b26d4ce4834129639680d071602a6637c17dbc10f4cb44ffae`
- Persistent registration: `VALIDATED_REGISTERED`

Running recovery twice returned the same dataset ID, recovery timestamp and integrity digest. The original job remains `FAILED`, with `dataset_id = null`; its PCAPs and forensic manifest retain their original checksums.
