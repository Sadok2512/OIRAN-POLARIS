# OIRAN V2.3 Known Limitations

- Real multi-UE session reconstruction is not certified because no registered capture contains establishment evidence for the three currently active POLARIS UEs.
- Two live datasets and one recovered dataset contain PFCP background events only and reconstruct zero UE sessions.
- Runtime POLARIS state cannot replace captured NGAP/PFCP/GTP-U correlation evidence.
- NGAP nested Release-17 fields retain the documented partial-decoding limitations.
- Live execution and production deployment were explicitly outside this mission.

The next safe step is a separately approved bounded multi-UE N2/N3/N4 capture while preserving exact capture and scenario metadata.
