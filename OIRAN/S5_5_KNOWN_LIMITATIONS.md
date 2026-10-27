# Known Limitations

- No live four-plane capture was authorized or executed.
- The reference corpus lacks multi-UE GTP-U evidence.
- The explicit SBI-to-PFCP identity bridge is absent, so E2E correlation is not certified.
- Some long-lived HTTP/2 captures lack initial HPACK state; affected headers remain unresolved.
- Encrypted NAS and TLS payloads remain unresolved without authorized keys.
- Native capture filtering supports the verified topology and is intentionally not user-extensible.
