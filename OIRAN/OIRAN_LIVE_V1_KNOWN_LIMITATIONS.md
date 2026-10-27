# OIRAN Live V1 Known Limitations

- Live capture, live decoding and live session reconstruction are not certified until `OIRAN-LIVE-CAPTURE-001` is explicitly approved and executed.
- The deployed service is intentionally read-only and has no Operator token or capture enable flag. Its systemd sandbox must receive a narrowly scoped writable runtime path and packet-capture capability during an approved deployment.
- Packet-drop telemetry is `NOT AVAILABLE` because V1 does not yet parse helper end-of-run drop statistics.
- Completed-capture processing is asynchronous; V1 exposes bounded polling rather than SSE.
- Existing SCTP I-DATA and CRC32C limitations and partial nested NGAP decoding remain unchanged.
- A capture containing only N3 traffic may produce an unassociated flow instead of a UE session when evidence is insufficient.
- Distributed probes are modeled but not validated.
