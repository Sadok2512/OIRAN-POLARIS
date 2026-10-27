# S3.2 NGAP decoder report

## Result

decoder-ngap 0.1.0 decoded the APER NGAP-PDU envelope, PDU choice, procedure code, criticality, message open type and ProtocolIE container for all 37 real reassembled messages. Packet/procedure alignment against TShark was exact: 37 aligned, 0 mismatch, 0 missing.

Schema baseline: 3GPP TS 38.413 V17.3.0 (38413-h30), SHA-256 b705532dd52674fce67ccc01df7bd17a8412341ea82740c164029a5b545f04d2. See decoder-ngap/ASN1_SCHEMA.md.

## Real procedure inventory

| Message | Count |
|---|---:|
| NGSetupRequest / Response | 1 / 1 |
| InitialUEMessage | 3 |
| Downlink / Uplink NAS Transport | 7 / 9 |
| InitialContextSetupRequest / Response | 2 / 2 |
| PDUSessionResourceSetupRequest / Response | 2 / 2 |
| UEContextReleaseRequest | 1 |
| UEContextReleaseCommand / Complete | 3 / 3 |
| UERadioCapabilityInfoIndication | 1 |

AMF-UE-NGAP-ID and RAN-UE-NGAP-ID are typed and matched the accessible TShark values. NAS-PDU and 5G-S-TMSI are pseudonymized. Protected NAS is never decrypted or represented as plaintext.

## Honest coverage status

Four messages were fully DECODED for the currently typed relevant fields; 33 are PARTIAL because one or more nested Release 17 IE values remain opaque. Every opaque/unknown value retains ID, name when known, length and SHA-256. Unsupported extensions and fragmented APER length determinants fail explicitly.

This is a general PDU/container decoder driven by procedure and IE identifiers from the versioned schema; it does not compare sample byte strings. It is not yet a complete generated ASN.1 Release 17 binding, so S3 NGAP certification remains partial.
