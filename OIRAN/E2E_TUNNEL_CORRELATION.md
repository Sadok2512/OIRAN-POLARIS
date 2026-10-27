# Exact NGAP/PFCP Tunnel Correlation

The decoder now structurally normalizes the NGAP UP transport endpoint and TEID from the bounded `UPTransportLayerInformation` open type. The correlation engine uses a typed key: endpoint IP, normalized TEID, capture-group scope, and observed interface roles.

For `live-1793054609378-0001`, NGAP N2 packet 39 contains `10.77.22.13 / 0xb3b5`; PFCP N4 packet 30 contains the same Created-PDR F-TEID. The tuple is unique in the relevant capture scope and produces `EXACT_TUNNEL_MATCH`, scope `tunnel-only`.

This edge explicitly does not claim exact UE or full session identity. Duplicate/reused tuples are rejected as ambiguous.
