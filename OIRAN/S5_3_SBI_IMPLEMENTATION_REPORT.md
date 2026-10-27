# S5.3 SBI implementation report

## Outcome

OIRAN now decodes cleartext laboratory SBI traffic through the native pipeline `PCAP/PCAPNG -> IP/TCP -> bounded stream reassembly -> HTTP/2/HPACK -> SBI transaction -> normalized event`. Existing NGAP, NAS, PFCP and GTP-U decoders were reused without replacement.

The implementation is intentionally conservative: TLS payloads stay encrypted, sensitive headers and subscriber identifiers are not emitted, incomplete HPACK state is reported as partial, and unsupported operations remain named `UnsupportedSbiOperation`.

## Components

| Component | Version | Purpose |
|---|---:|---|
| `transport-tcp` | 0.1.0 | Bounded bidirectional TCP reassembly and packet provenance |
| `decoder-sbi` | 0.1.0 | HTTP/2, HPACK, SBI pairing and selected 3GPP operation decoding |
| `event-schema` | 1.5.0-dev | Compatible optional SBI metadata |
| `oiran-decode` | 0.3.0 | Native TCP/SBI pipeline integration |
| `correlation-engine` | 0.3.0 | Evidence-gated SBI routing correlations |
| `callflow-schema` | 1.1.0 | SBI procedures and dynamic participants |

HPACK is provided by the MIT-licensed Rust `hpack` 0.3.0 crate. No TelcoLadder source was copied or linked.

## Corpus outcome

The unchanged 13-file corpus contained 4,205 packets. OIRAN reconstructed 48 TCP connections, 708 HTTP/2 stream IDs and 198 request/response transactions. Twenty priority operations were identified: six CreateSMContext, six UpdateSMContext, six N1N2MessageTransfer and two ReleaseSMContext transactions.

SBI decoding is partial overall because many corpus operations are outside the S5.3 priority catalog and 26 header fields require HPACK dynamic-table history that predates the capture.

## Safety

No production deployment, service restart, live capture or simulator execution occurred. All work was performed in the isolated `feat/s5-3-sbi-correlation` worktree.
