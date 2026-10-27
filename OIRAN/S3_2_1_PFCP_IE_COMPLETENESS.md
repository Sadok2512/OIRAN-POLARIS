# S3.2.1 PFCP IE completeness

## Result

`decoder-pfcp` 0.2.0 improves the selected dataset from 40 fully typed / 12 partial messages to **52 fully typed / 0 partial**. This result applies to the observed IE set; it is not universal TS 29.244 coverage.

## Implemented observed coverage

The recursive decoder validates IE boundaries and types Node ID, F-SEID, F-TEID, PDR/FAR/QER/URR IDs, Create/Update PDR and FAR groups, PDI, forwarding parameters, outer header creation/removal, UE IP (pseudonymized), network instance, source/destination interface, cause, recovery timestamp, precedence, apply action, QFI, S-NSSAI, PDN type, BAR ID, feature masks, measurement/time/volume fields, and usage-report sequence values.

Grouped IEs inherit the most severe child status. A known but unimplemented leaf is `PARTIAL`; unknown and vendor-specific IEs are `UNSUPPORTED`; invalid typed length is `MALFORMED`. Raw hashes and paths are retained in every case.

## Validation boundary

- 52 PFCP messages aligned with TShark at message and packet level.
- All observed PFCP IE nodes in this dataset receive typed or explicit grouped representations.
- Curated scalar parity covers sequence, cause, IDs, F-TEID/F-SEID and Node ID with zero mismatch.
- Unseen Release/vendor IEs remain an explicit future-coverage concern.
