# S4.1 session discovery report

## Certified dataset result

Dataset `OIRAN_5G_PDU_SESSION_DATA_V1` remains unchanged. Discovery over its 54 normalized observations found:

| Entity | Count | Interpretation |
|---|---:|---|
| UE contexts | 2 | one active context (IDs 4/4) and one observed released context (3/3) |
| PDU sessions | 1 | PDU Session ID 1 on the active UE context |
| PFCP sessions | 2 | current established lifecycle and an earlier deletion lifecycle |
| GTP-U tunnels | 2 | directional uplink/downlink tunnel keys; both uniquely related to PFCP |
| Duplicate observations | 0 | capture/event/packet composite |

The certified primary Call Flow remains exactly 26 session events and 28 background events. Discovery does not promote the released context or old PFCP deletion into that UE session.

## Synthetic behavioral validation

The explicitly synthetic Rust fixture contains five UE contexts, six PDU sessions, two PDU sessions for UE 1, interleaved timestamps and one incomplete setup. Tests also cover sequential identifier reuse after release, out-of-order input, repeated import, deterministic IDs and duplicate observations. This fixture is not captured network evidence.

## Flow materialization

Existing canonical Call Flow JSON wins whenever it contains all discovery anchor events. Additional allowlisted `callflows/*.json` files are loaded independently. A missing sidecar produces a conservative NGAP-only incomplete flow; it does not fabricate PFCP/N3 membership or confidence.
