# S5.2 Known Limitations

- Sixty ciphered NAS payloads remain intentionally unresolved; no authorized security context is available.
- Integrity-only messages are parsed but their MAC is not verified.
- The corpus contains no independently decodable NGAP-carried plain 5GSM message; 5GSM corpus certification is therefore pending.
- SBI HTTP/2 NAS transport is outside S5.2 and is not normalized.
- QoS Rules, Session AMBR and several optional Release-17 IEs are retained partially rather than fully interpreted.
- NAS container offset is relative to the decoded NGAP IE; a packet-absolute byte range is not claimed.
- NGAP Release-17 nested ASN.1 remains partial, and N2↔N4 correlation is not upgraded by NAS alone.
- The baseline figure of 79 NAS messages used a different occurrence metric from this audit's 116 NGAP containers and 84 TShark message-type occurrences.
