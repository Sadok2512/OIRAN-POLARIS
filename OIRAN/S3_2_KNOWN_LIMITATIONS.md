# S3.2 known limitations

S3.1/S3.2 is functional but PARTIAL, for these precise reasons:

1. NGAP uses the Release 17.3 schema-derived envelope, procedure and IE metadata, but not a complete generated APER binding for every nested IE. Thirty-three of 37 real NGAP messages therefore contain explicit partial/unsupported IE values.
2. NAS payloads are classified as plain or protected and pseudonymized; NAS security is not bypassed and full NAS message-field decoding is outside this decoder.
3. Twelve of 52 PFCP messages contain one or more IE types without typed value support. Their IDs, lengths and SHA-256 values are preserved.
4. Operational POLARIS N3 files are empty. Real GTP-U validation uses the immutable Open5GS reference under POLARIS, not the operational capture point.
5. SCTP I-DATA/interleaving and CRC32c verification are unsupported. Fragment/retransmission behavior is unit-tested because the selected real SCTP traffic is unfragmented.
6. IPv4 fragment reassembly, IPv6 extension-header traversal, Linux cooked v2, ARP and non-IP link payloads are unsupported.
7. The reader currently bounds a capture at 256 MiB and reads it into memory. Streaming/mmap indexing is deferred.
8. Network-function direction depends on an explicit endpoint map. Unknown endpoints remain UNKNOWN; no role is guessed.
9. No IP/user payload application decoding is performed. TEID alone is not considered proof of session identity.
10. TShark header/message parity is exact for the selected data, but full nested-IE parity is not claimed.

Required next corrective work before S3 certification: generate or integrate a Rust-1.75-compatible full NGAP Release 17 APER binding, extend PFCP typed IE coverage from the observed unknown-ID inventory, and generate a finalized non-empty operational N3 capture. S3.3 must not begin automatically.
