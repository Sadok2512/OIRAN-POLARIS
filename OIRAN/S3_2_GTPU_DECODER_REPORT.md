# S3.2 GTP-U decoder report

## Result

decoder-gtpu 0.1.0 implements the TS 29.281 mandatory header, TEID, optional sequence/N-PDU fields, extension-header chain and PDU Session Container summary. Declared length and every extension boundary are validated.

The finalized operational N3 captures are valid but contain zero packets, so they cannot validate GTP-U behavior. The immutable Open5GS 5g-roaming-lbo.pcapng reference supplied ten G-PDUs. OIRAN emitted ten events with exact packet number, timestamp, outer endpoints, message type 0xff and TEID alignment against TShark. All ten were DECODED; mismatch and missing counts were zero.

Extracted data includes outer tunnel endpoints, TEID, optional sequence number, packet/payload length, extension type, PDU type and QFI where the PDU Session Container supplies them. User-plane application bytes remain opaque and are referenced only by SHA-256.

## Limitations

The selected real GTP-U sample did not exercise every optional field or extension type; those paths are unit-tested. Direction is emitted only when endpoint-to-network-function mapping demonstrates it. TEID is never treated as a globally unique session identifier. Physical capture loss cannot be inferred from these files.
