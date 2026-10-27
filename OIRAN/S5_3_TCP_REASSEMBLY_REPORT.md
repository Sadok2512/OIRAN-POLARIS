# S5.3 TCP reassembly report

`transport-tcp` uses canonical bidirectional endpoint keys and independent sequence state per direction. It accepts out-of-order segments, suppresses retransmitted/duplicate bytes, reports gaps, bounds connection count, pending segments and buffered bytes, and supports timeout/finalization of partial connections.

Every delivered byte range retains contributing packet references. Connection reuse is separated after finalized state; partial captures do not manufacture missing prefixes. Unsupported or malformed TCP headers are surfaced by the capture reader.

Deterministic tests cover fragmentation, retransmission, out-of-order delivery, duplicate suppression, gaps and bounded eviction. Corpus replay completed without panics and exposed 48 TCP connections. `TCP_REASSEMBLY_CERTIFIED = PASS` for bounded offline cleartext corpus processing; it is not a live throughput certification.
