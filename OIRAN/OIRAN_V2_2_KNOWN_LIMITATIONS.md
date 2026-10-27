# OIRAN V2.2 Known Limitations

- Raw packet bytes are not present in the normalized event model, so Raw Hex reports that evidence is unavailable instead of synthesizing content.
- Byte-range synchronization is unavailable because decoder field offsets are not proven in the current schema.
- NGAP nested Release-17 fields retain the existing documented partial-decoding status.
- Participant roles are limited to evidence present in canonical events/topology; unresolved endpoints remain explicit.
- This change was validated with a local candidate API and browser preview. It was not deployed and no production service was restarted.
- No live capture or distributed-probe certification is implied.
