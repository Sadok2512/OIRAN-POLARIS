# S3.2.1 known limitations

- NGAP is not a complete generated Release-17 ASN.1 implementation: 28/37 selected messages remain PARTIAL because protected NAS and several deep transfer/list structures are opaque.
- SCTP I-DATA/interleaving and CRC32C validation remain unsupported.
- PFCP is complete for the selected observed IE set, not every TS 29.244 or vendor IE.
- Operational N3 and N6 captures contain zero packets; GTP-U validation therefore uses the immutable Open5GS fixture.
- No coherent operational N2/N4/N3 ground-truth dataset exists.
- Direction is emitted only when endpoint roles are explicitly supplied; it is not guessed.
- No cross-interface session reconstruction or Call Flow builder is implemented in this mission.
- The 581/581 field result is curated comparable-field parity, not full ASN.1 field parity.
