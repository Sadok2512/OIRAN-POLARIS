# OIRAN V2.3 Multi-Session Audit

## Outcome

The single visible session was not caused by a hardcoded frontend row or a single-session decoder. The registered evidence contains exactly one reconstructible session: `5g-UE-A-pdu-1` in the certified historical dataset. The two completed live datasets and one recovered dataset contain PFCP background/heartbeat events but no evidence sufficient to form a UE/PDU session.

The Rust session engine already supports multiple UE contexts, multiple PDU sessions per UE, multiple PFCP sessions, directional GTP-U tunnels, lifecycle generations and deterministic ordering. It scopes identity by association/endpoints/lifecycle instead of PDU Session ID alone.

## Corrections

- Normalized every registered dataset through API 2.3.
- Added explicit Historical, Live and Recovered dataset scopes.
- Removed implicit historical fallback from zero-session selections.
- Preserved dataset identity in session and Call Flow URLs.
- Scoped decode-completeness accounting to session events.
- Added a three-UE offline corpus and isolation assertions.

No decoder behavior or certified evidence was altered.
