# Decoder Integration

The unified workspace contains SLL2 PCAP/PCAPNG, NGAP/SCTP, nested 5GMM/5GSM, bounded TCP reassembly, HTTP/2/HPACK/SBI, PFCP and GTP-U decoders. Live finalization calls the existing `oiran-decode` pipeline for every non-empty plane file and preserves partial, encrypted, unsupported and malformed statuses. No NAS or TLS decryption was added.
