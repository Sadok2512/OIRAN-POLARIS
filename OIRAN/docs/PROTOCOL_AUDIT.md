# OIRAN protocol decoder coverage audit

- Scope: 12 reference planes carried by OIRAN captures (4G EPC + 5GC + N6 user plane).
- Method: static source review of `OIRAN/decoder-*` crates on `feat/decoder-s1ap` (branched from `fix/polaris-portable-tests-nf-state` → `707a43b` → based on `a0168f5` `0.15.5`). No PCAP was processed on this host; measured decode ratios on live captures will be produced separately on the OIRAN host.
- "Decoder — covered messages" lists the `message_families` string table declared by each decoder's `capabilities()`, trimmed to the procedures that are actually matched in `message_name()`/`parse()`.

| # | Plane | Transport | Expected protocol (3GPP TS) | OIRAN decoder crate | Protocol enum variant | Covered procedures / message families | Status |
|---|-------|-----------|-----------------------------|---------------------|-----------------------|---------------------------------------|--------|
| 1  | s1mme | SCTP (36412) | **S1AP** — TS 36.413 | **MISSING** (added by this change: `decoder-s1ap`) | **MISSING** → `Protocol::S1ap` (added) | — until this change: S1 Setup, Initial UE, DL/UL NAS Transport, Initial Context Setup, UE Context Release, E-RAB Setup/Release, Paging | **GAP → addressed by lot 1** |
| 2  | s1u   | GTPv1-U/UDP | **GTP-U** — TS 29.281 | `decoder-gtpu` v0.1.0 | `Protocol::Gtpu` | G-PDU, Echo, Error Indication (header + extension chain, inner IP opaque) | COVERED |
| 3  | s11   | GTPv2-C/UDP | **GTPv2-C** — TS 29.274 | **MISSING** | — | — | GAP (not in this lot) |
| 4  | s5c   | GTPv2-C/UDP | **GTPv2-C** — TS 29.274 (same crate as s11) | **MISSING** | — | — | GAP (not in this lot) |
| 5  | s5u   | GTPv1-U/UDP | **GTP-U** — TS 29.281 (same crate as s1u) | `decoder-gtpu` v0.1.0 | `Protocol::Gtpu` | G-PDU, Echo, Error Indication | COVERED (shared with s1u) |
| 6  | s6a   | Diameter/SCTP (3868) | **Diameter S6a** — TS 29.272 | **MISSING** | — | — | GAP (not in this lot) |
| 7  | sxab  | PFCP/UDP (8805) — Sx (EPC) | **PFCP** — TS 29.244 (same crate as N4) | `decoder-pfcp` v0.2.0 | `Protocol::Pfcp` | Heartbeat, Association Setup, Session Establishment, Session Modification, Session Deletion | COVERED (shared with N4) |
| 8  | n2    | SCTP (38412) | **NGAP** — TS 38.413 (and inner **NAS-5GS** TS 24.501) | `decoder-ngap` v0.3.0 + `decoder-nas` v0.1.0 | `Protocol::Ngap`, `Protocol::Nas5gmm`, `Protocol::Nas5gsm` | NG Setup, Initial UE, NAS Transport, Initial Context Setup, PDU Session Resource Setup, UE Context Release (NGAP) + 5GMM/5GSM NAS envelopes | COVERED |
| 9  | n3    | GTPv1-U/UDP | **GTP-U** — TS 29.281 (same crate as s1u) | `decoder-gtpu` v0.1.0 | `Protocol::Gtpu` | G-PDU, Echo, Error Indication | COVERED |
| 10 | n4    | PFCP/UDP (8805) | **PFCP** — TS 29.244 | `decoder-pfcp` v0.2.0 | `Protocol::Pfcp` | Heartbeat, Association Setup, Session Establishment, Session Modification, Session Deletion | COVERED |
| 11 | n6    | IP user plane (opaque payload) | — (DN side, not a signalling protocol) | — (byte accounting via Analyzer / DN sender) | — | — | OUT OF SCOPE for decoder audit (byte-level only) |
| 12 | sbi   | HTTP/2 over TCP/TLS | **5G SBI** — TS 29.500 / 29.501 OpenAPI family | `decoder-sbi` v0.1.0 | `Protocol::SbiHttp2` | HTTP/2 preface + frames, HPACK, request/response transaction correlation (service / operation / status; TLS-encrypted flows marked `ENCRYPTED_OR_PROTECTED`) | COVERED |

## Summary

- **Covered end-to-end (static)**: s1u, s5u, n3 (GTP-U); n4, sxab (PFCP); n2 (NGAP + inner NAS); sbi (HTTP/2 SBI).
- **GAP closed by this lot**: s1mme (S1AP, TS 36.413) — new crate `OIRAN/decoder-s1ap` with APER envelope + ProtocolIE container shared contract with NGAP, procedures listed above, identity IEs (IMSI, M-TMSI, S-TMSI, GUTI) emitted as `pseudonymized: true` so the Analyzer strips them.
- **Still open after this lot** (not in scope of lot 1):
  - s11 / s5c — GTPv2-C (TS 29.274): no decoder crate.
  - s6a — Diameter (TS 29.272): no decoder crate.
- **N6**: not a signalling plane; validated via the DN sender byte-accounting path (`polaris-dn-sender`) and not through a protocol decoder.

## Live-measurement follow-up (to run on OIRAN host, not here)

For each covered plane, planned measurement on one real PCAP from `oiran-lab-capture-1` using tshark + the `oiran-decode` CLI; this host does **not** have access to those captures, so numbers are deliberately not fabricated here. Template:

```
# packets total on the plane:
tshark -r <pcap> -Y '<display filter>' | wc -l
# oiran-decode counters (decoded / malformed / unsupported):
oiran-decode decode --capture-id <id> --plane <plane> --input <pcap> --emit-counters
```

| Plane | tshark display filter | oiran-decode plane | To be measured |
|-------|----------------------|--------------------|----------------|
| s1mme | `s1ap`                | `s1mme`            | total / decoded / malformed / unsupported |
| s1u   | `gtp`                 | `s1u`              | total / decoded |
| s5u   | `gtp`                 | `s5u`              | total / decoded |
| sxab  | `pfcp`                | `sxab`             | total / decoded |
| n2    | `ngap or nas-5gs`     | `n2`               | total NGAP / NAS inner / decoded |
| n3    | `gtp`                 | `n3`               | total / decoded |
| n4    | `pfcp`                | `n4`               | total / decoded |
| sbi   | `http2`               | `sbi`              | total frames / transactions |
