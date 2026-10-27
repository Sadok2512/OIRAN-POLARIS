# S5.2 NAS Security Report

Security Header Type is classified before any message-body parsing:

- `0`: `PLAIN`.
- `1` and `3`: `INTEGRITY_PROTECTED`; inner message may be decoded, but verification is explicitly not performed.
- `2` and `4`: `INTEGRITY_PROTECTED_CIPHERED`; security envelope metadata is decoded and the inner payload remains unresolved.
- Other values: `UNKNOWN_SECURITY_STATE`.

No NAS keys are derived, guessed, logged or accepted by this release. No integrity success is claimed. MAC, authentication values and protected bodies are represented by hashes rather than clear values. The decoder has a nesting limit and validates every security-header boundary.

Corpus: 70 protected envelopes classified, including 10 integrity-only and 60 ciphered unresolved. This is the principal certification limitation.
