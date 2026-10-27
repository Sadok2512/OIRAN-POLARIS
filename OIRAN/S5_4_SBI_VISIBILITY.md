# S5.4 SBI visibility

## Deployment model

No SCP container, address or Open5GS SCP configuration was found. The observed topology is direct AMF ↔ SMF. NRF is present at `10.77.20.10`; it is service discovery, not an SCP transit node.

The completed 12:12 UTC SBI capture contains direct AMF-to-SMF CreateSMContext and UpdateSMContext requests, SMF-to-AMF N1N2MessageTransfer requests and their responses. TShark observed 45 packets between AMF and SMF and two new AMF/SMF TCP connections during the relevant window.

## Transport security

- SBI configuration uses `http://...:7777`.
- TShark found 8,986 HTTP/2 frames and zero TLS records in the inspected file.
- No decryption, key extraction or secret inspection was attempted.

## HPACK completeness

Global completeness is partial because several long-lived NRF and NF connections existed before the hourly capture began. S5.3 reported 17 TCP gap/partial conditions on this file. The two new AMF/SMF connections include their SYN and the six priority transactions were decoded: two CreateSMContext, two N1N2MessageTransfer and two UpdateSMContext.

For OIRAN-E2E-001, accept full HPACK evidence only when the relevant connection preface and all preceding header blocks are present. If a reused connection predates capture, either preserve/replay the immediately preceding rotations with continuous HPACK state or mark affected headers unresolved. Shared NFs must not be restarted merely to obtain a new connection.

`SCP_PRESENT = FALSE`, `TLS_STATUS = PLAINTEXT_HTTP2`, and `HPACK_COMPLETENESS = PARTIAL_GLOBAL / COMPLETE_FOR_INSPECTED_NEW_AMF_SMF_FLOWS`.
