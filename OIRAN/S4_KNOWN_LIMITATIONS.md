# S4 Known Limitations

- Live capture start/stop/settings are not configured and remain disabled.
- Distributed probe registration, SSE updates and multi-probe correlation are data-model preparations only.
- Only one certified 5G SA session and its 54-event dataset are available; no scale claim follows from it.
- NGAP Release-17 nested structures remain partially decoded in 11 session events and stay visibly `PARTIAL`.
- SCTP I-DATA and CRC32C validation limitations from S3 remain unchanged.
- The application is desktop-focused at 1440×900 and above; mobile layouts are not certified.
- Authentication uses runtime bearer tokens without expiry/identity-provider integration and is restricted to localhost evaluation.
- Audit records are process logs, not a durable external audit store.
- Correlation rules are read-only; editing/replay is deferred.
- Capture import means registration through a future authorized backend; S4 provides no upload or arbitrary path picker.
- Performance measurements use 54 events and cannot establish large-PCAP or concurrent-user scalability.
- External OTV and POLARIS capture-container lifecycle transitions were visible during the final read-only health snapshot. S4 did not cause or control them; historical attribution is unavailable.
