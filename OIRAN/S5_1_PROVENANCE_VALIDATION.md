# S5.1 provenance validation

Event schema 1.3.0 adds optional, backward-compatible packet-reference fields: source SHA256, link type, SLL2 protocol/reserved/ifindex/ARPHRD/packet-type/address-length/address.

Across all 239 decoded LAB events:

- source SHA256 failures: 0;
- link-type/SLL2 metadata failures: 0;
- packet-number mapping failures: 0;
- timestamp mismatches with TShark: 0;
- outer IP endpoint mismatches with TShark: 0.

Existing source file, packet number, byte offset, PCAPNG interface ID, captured length and original length fields remain present.
