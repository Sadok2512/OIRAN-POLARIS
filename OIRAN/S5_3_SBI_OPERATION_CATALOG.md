# S5.3 SBI operation catalog

Operations are identified from the HTTP method, sanitized URI template, API version, paired response and content type—not from endpoint IP alone.

| Service | Operation | Corpus transactions | State |
|---|---|---:|---|
| Nsmf_PDUSession | CreateSMContext | 6 | Decoded |
| Nsmf_PDUSession | UpdateSMContext | 6 | Decoded |
| Nsmf_PDUSession | ReleaseSMContext | 2 | Decoded |
| Namf_Communication | N1N2MessageTransfer | 6 | Decoded |
| Namf_Communication | UEContextTransfer | 0 | Implemented classification, not observed |

Other observed services are retained as `UnsupportedSbiOperation` with transport/HTTP metadata and provenance. A 2xx response closes an HTTP transaction but is not alone considered proof that a 5G procedure completed.
