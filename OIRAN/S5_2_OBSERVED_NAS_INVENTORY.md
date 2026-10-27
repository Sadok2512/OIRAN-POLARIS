# S5.2 Observed NAS Inventory

The immutable 13-file corpus contains 116 NGAP-carried NAS containers when every occurrence is counted: 46 plain, 10 integrity-only and 60 integrity-protected/ciphered. OIRAN classified every container.

| Decoded 5GMM message | Count | Result |
|---|---:|---|
| Registration Request | 12 | decoded, optional fields partial |
| Registration Reject | 2 | decoded including cause |
| Authentication Request | 16 | decoded |
| Authentication Response | 10 | decoded |
| Authentication Failure | 6 | decoded including cause |
| Security Mode Command | 10 | decoded inside integrity-only envelope; integrity not verified |
| Ciphered 5GMM envelope | 60 | explicitly unresolved |

The mission baseline value `NAS_MESSAGES_OBSERVED = 79` is retained as the prior S5.1 metric. The new occurrence-aware audit finds 84 TShark message-type field occurrences (56 5GMM and 28 5GSM) plus 32 protected containers for which TShark exposes no independently comparable clear message type. Message-field occurrences and NAS containers are therefore not interchangeable.

The 28 visible 5GSM TShark occurrences are carried through SBI and/or visible beneath laboratory null-cipher handling. OIRAN S5.2 is integrated only at NGAP NAS-PDU boundaries and does not use SBI as substitute protocol evidence.
