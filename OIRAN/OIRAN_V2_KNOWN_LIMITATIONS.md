# OIRAN V2 Known Limitations

- Live capture backend, authenticated Operator control and live packet telemetry are not configured.
- Probe online means the registered API instance is reachable; it does not claim active packet acquisition.
- N2/N3/N4 indicators refer to certified historical captures.
- Only one real certified UE/PDU session is present. Multi-session logic is regression-tested, but real multi-UE certification remains pending.
- NGAP Release-17 nested structures retain explicit PARTIAL states where unresolved.
- Raw packet bytes are not present in the public event model; only references and hashes are shown.
- SCTP I-DATA and CRC32C validation retain their documented decoder limitations.
- Distributed multi-probe correlation is schema-ready but not validated.
