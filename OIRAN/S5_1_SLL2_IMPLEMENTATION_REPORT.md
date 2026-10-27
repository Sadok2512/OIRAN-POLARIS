# S5.1 SLL2 implementation report

## Result

Native `LINKTYPE_LINUX_SLL2` (276) support is implemented in `capture-pcap` 0.2.0. The implementation parses the fixed 20-byte header in network byte order and reuses the existing IPv4, IPv6, UDP and SCTP paths. No protocol decoder was rewritten.

Parsed metadata: protocol type, reserved field, interface index, ARPHRD hardware type, packet type, address length and the eight-byte address field. Address lengths above eight, truncated headers and non-IP protocol values are explicit errors.

IPv4 fragments and IPv6 fragments/ESP are explicitly unsupported. IPv6 Hop-by-Hop, Routing, Destination Options and AH extension headers are traversed with bounds checks.

## Validation

- LAB packets read: 4075/4,075.
- LAB transport errors: 0.
- Decoded NGAP/PFCP/GTP-U envelopes: 239 exact against TShark.
- Full Rust workspace: 140/140 tests passed.
- Production deployment and live capture: not executed.
