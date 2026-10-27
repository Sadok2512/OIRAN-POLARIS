# S5.1 known limitations

- Nested NAS decoding is absent: 79 independently observed NAS occurrences remain unsupported.
- SBI/HTTP2 is not represented in OIRAN normalized events; AMF→SCP→SMF relay evidence remains external.
- 116 NGAP envelopes are partially decoded even though their top-level message identity is exact.
- IPv4/IPv6 fragment reassembly is not implemented; fragments are explicit unsupported packets.
- IPv6 ESP is explicitly unsupported; bounded extension-header traversal supports common non-fragment headers.
- A capture invocation still supplies one logical interface label, so combined LAB files can label PFCP/GTP-U events with the configured capture point despite correct protocol identity.
- Multi-IMSI N2↔N4 correlation remains `UNKNOWN`; the fixture lacks multi-UE GTP-U traffic.
- Performance allocation counts were not measured and the corpus is too small for capacity claims.
