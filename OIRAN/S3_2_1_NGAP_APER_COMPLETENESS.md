# S3.2.1 NGAP APER completeness

## Result

`decoder-ngap` 0.2.0 improves the selected Release-17.3 dataset from 4 fully typed / 33 partial messages to **9 fully typed / 28 partial**. This is a schema-aware APER envelope and observed-IE decoder, not a claim of complete TS 38.413 coverage.

The declared schema baseline is 3GPP TS 38.413 V17.3.0; its existing workspace fingerprint remains `b705532dd52674fce67ccc01df7bd17a8412341ea82740c164029a5b545f04d2`.

## Added typed coverage

- initiating, successful and unsuccessful PDU envelopes, procedure code and criticality;
- AMF UE NGAP ID and RAN UE NGAP ID;
- PLMN, TAI/TAC, NR CGI and observed User Location Information NR choices;
- S-NSSAI SST/SD, PDU Session ID, observed cause choices and RRC establishment cause;
- GUAMI fields, UE Context Request, PDU Session Type and UE security capability masks;
- NAS presence/length/security metadata with protected content kept opaque;
- raw SHA-256 and provenance for every unresolved IE or nested transfer.

## Explicit remaining gaps

| Area | Occurrences | Status |
|---|---:|---|
| Protected NAS-PDU | 21 | PARTIAL / protected; never decrypted or guessed |
| PDU-session resource transfer bodies | 5 | PDU Session ID typed; nested transfer retained by hash |
| UE aggregate maximum bitrate | 4 scalar values | PARTIAL; raw APER retained |
| Supported TA List | 1 | PARTIAL |
| PLMN Support List | 1 | PARTIAL |
| Served GUAMI List | 1 | PARTIAL |
| Global RAN Node ID node-choice body | 1 | PLMN typed; node ID raw retained |

Unknown IEs and extensions are never silently treated as decoded. Malformed APER returns an explicit error. Optional/nested SEQUENCE and CHOICE paths have regression coverage, but arbitrary Release-17 extension additions remain outside the certified subset.

## Evidence

- Input: 37 NGAP messages across the selected operational N2 and immutable reference fixture.
- Output: [S3_2_1_NORMALIZED_EVENTS.jsonl](S3_2_1_NORMALIZED_EVENTS.jsonl), 9 `DECODED`, 28 `PARTIAL`.
- Independent comparison: [S3_2_1_FIELD_PARITY_REPORT.md](S3_2_1_FIELD_PARITY_REPORT.md).
- Tests: six NGAP tests, including nested structures, optional IE, unknown IE, malformed input, extension and security capability cases.
