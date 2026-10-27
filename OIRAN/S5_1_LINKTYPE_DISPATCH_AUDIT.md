# S5.1 link-type dispatch audit

The classic PCAP reader obtains the 32-bit link type from the global header. The PCAPNG reader obtains a separate 16-bit link type from every Interface Description Block and copies that interface identity into each packet record.

`transport_view` is the only link-layer-to-network-layer dispatch point:

- 1: Ethernet, including the existing bounded VLAN traversal.
- 113: Linux cooked capture v1.
- 276: Linux cooked capture v2, fixed 20-byte header.
- all others: `UnsupportedLinkType`.

SLL2 protocol `0x0800` dispatches to the existing IPv4 parser and `0x86dd` to the existing IPv6 parser. Other protocol values return an explicit `InvalidNetwork` error. The Ethernet path was not structurally changed.
