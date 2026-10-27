# S5.4 known limitations

- Production OIRAN is pre-S5.3 and cannot expose native SBI events through its deployed API.
- The isolated Capture Helper only supports N2/N3/N4; SBI currently belongs to a separate laboratory capture service.
- The aligned 12:12 UTC evidence has no N3 packets, so it is not E2E proof.
- Existing three-UE background traffic runs every 30 seconds and can contaminate a future N3 window unless separately paused or rigorously isolated by proven identifiers.
- Global HPACK state is incomplete on long-lived connections when hourly files start mid-connection.
- No SCP is deployed; S5.4 can validate direct AMF↔SMF only.
- Ten subscribers are attested and ten protected profiles exist, but only the first three were verified through current runtime evidence in this audit.
- Starting UE-04 is not authorized by this mission and may require a separate POLARIS Control lifecycle certification gate.
- An SM Context reference is not an inherent PFCP SEID mapping; the future capture may still leave SBI↔PFCP below EXACT.
- Current CPU pressure is acceptable for audit but warrants a quieter live-test window to protect ETV/OTV.
