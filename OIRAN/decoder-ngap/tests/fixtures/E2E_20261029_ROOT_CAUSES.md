# E2E 2026-10-29 NGAP root causes

The fixture payloads are sanitized, length-preserving NGAP messages. Subscriber
identities and authentication material are not present.

| Fixture | Message | Previous status | Information element | Resolution |
|---:|---|---|---|---|
| 1 | InitialUEMessage | PARTIAL | NAS-PDU | NGAP envelope is fully bounded and is now DECODED; nested NAS status stays on the child event. |
| 2 | DownlinkNASTransport | PARTIAL | NAS-PDU | Same correction. |
| 3 | UplinkNASTransport | PARTIAL | NAS-PDU | Same correction. |
| 4 | DownlinkNASTransport | PARTIAL | NAS-PDU | Same correction. |
| 5 | UplinkNASTransport | PARTIAL | NAS-PDU | Same correction. |
| 6 | InitialContextSetupRequest | PARTIAL | NAS-PDU | Same correction; the sanitized SecurityKey container is structurally decoded. |
| 7 | UplinkNASTransport | PARTIAL | NAS-PDU | Same correction. |
| 8 | UplinkNASTransport | PARTIAL | NAS-PDU | Same correction; duplicate input remains deterministic. |
| 9 | DownlinkNASTransport | PARTIAL | NAS-PDU | Same correction. |
| 10 | PDUSessionResourceSetupRequest | MALFORMED | UEAggregateMaximumBitRate | The eight-octet value is valid and is decoded as two 32-bit rates. The message remains PARTIAL because PDUSessionResourceSetupListSUReq retains an opaque nested N2 SM transfer. |
| 11 | PDUSessionResourceSetupResponse | PARTIAL | PDUSessionResourceSetupListSURes | Intentionally remains PARTIAL: session id and transfer provenance are retained, but the nested transfer is not typed. |

Across the complete finalized N2 inventory, the only remaining NGAP partial
root causes after this patch are `PDUSessionResourceSetupListSUReq` and
`PDUSessionResourceSetupListSURes`. This is a documented decoder limitation,
not evidence of a malformed radio message.
