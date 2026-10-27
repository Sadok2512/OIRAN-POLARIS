# S5.3 known limitations

- Twenty-six headers cannot be resolved when the capture begins after HPACK dynamic-table state was established.
- TLS-protected SBI is classified but not decrypted.
- The operation catalog targets observed Nsmf PDUSession and Namf Communication operations; other services remain explicitly unsupported.
- Multipart binary N1/N2 containers are not interpreted unless an existing native decoder has evidence and boundaries.
- The corpus lacks an explicit SM Context-to-PFCP SEID/F-TEID mapping, so N2-SBI-N4 correlation is not certified.
- The multi-IMSI fixture has no GTP-U packets, so its complete E2E user-plane path is not certifiable.
- SBI NF role inference is limited to observed endpoints and request semantics; unseen logical hops are never fabricated.
- Offline throughput is not a live capture or high-rate certification.
