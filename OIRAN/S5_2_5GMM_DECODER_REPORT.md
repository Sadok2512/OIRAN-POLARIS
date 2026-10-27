# S5.2 5GMM Decoder Report

Implemented observed-first message dispatch for Registration, Deregistration, Service, Configuration Update, Authentication, Identity, Security Mode and UL/DL NAS Transport identities defined by TS 24.501.

Corpus results: 116 5GMM envelope events; 46 plain messages, 10 integrity-only inner messages and 60 ciphered unresolved envelopes. Known causes 7, 21 and 111 are retained numerically. Authentication RAND/AUTN/RES material is represented only by length and SHA256, never clear text.

Registration Request mobile identity uses bounded LV-E parsing and emits only a deterministic pseudonym. Unknown optional IEs are retained by IEI, length and digest. Truncation changes status to `MALFORMED`; it never panics or silently drops the field.
