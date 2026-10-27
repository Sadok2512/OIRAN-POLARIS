# S3.3 known limitations

- NGAP nested Release-17 APER transfers remain partial. The Call Flow preserves 11 PARTIAL NGAP events and never invents missing fields.
- N2↔N4 is STRONG, not EXACT, because its TEID bridge relies on certified TShark/manifest evidence while native nested NGAP remains opaque.
- The certified control-plane and user-plane capture windows are separated in time within one continuously active session. Timestamps are not rewritten.
- Certification covers one UE and one PDU Session. Multi-UE identifier reuse and ambiguity handling are unit-tested but not yet validated on a multi-session capture.
- Participant roles rely on the endpoint roles recorded during certified decoding/topology mapping; arbitrary captures without that mapping produce `Unknown endpoint`.
- HTML exposes payload hashes/references, not unrestricted raw NAS or user payload bytes.
- No graphical browser was installed, so pixel-level responsive rendering was not automatically tested.
- This mission implements offline analysis/export, not live ingestion, persistence, UI authentication or capture control.
