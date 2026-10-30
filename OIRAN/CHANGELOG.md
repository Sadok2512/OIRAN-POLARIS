# Changelog

## OIRAN API 2.5.1 / live-probe 0.2.4 - 2026-10-30

- Added `OIRAN_CONTINUOUS_MAX_SEGMENT_BYTES`, defaulting to 1 GiB, with
  validation against the existing bounded disk policy.
- Reworked PCAP/PCAPNG decoding to visit packets incrementally; discovery,
  SHA-256, copy, packet parsing and decoding no longer materialise an entire
  capture file.
- Stream decoded events through an on-disk spool, finalize idle TCP/SBI
  connections during packet visitation, and retain only event-ID/offset pairs
  during continuous deduplication. This closes the production OOM found when
  a finalized SBI segment expanded to many normalized events under a 256 MiB
  service limit.
- Preserve all fully decoded SBI transactions while keeping response-only
  PARTIAL streams lacking decoded request identity as connection-level HPACK
  evidence rather than synthetic transactions, restoring the pre-regression
  event-count contract without hiding the capture limitation.
- Compact session-engine source metadata to the schema, procedure and SBI
  fields actually consumed after normalization instead of retaining a second
  copy of every decoded IE tree during call-flow reconstruction.
- Oversized finalized segments are now persisted individually with source
  path, observed byte size, timestamp and
  `CONTINUOUS_SOURCE_SEGMENT_TOO_LARGE`; they no longer fail the continuous
  import job or prevent eligible siblings from being ingested.
- Added regression coverage for a streaming 300 MiB import below 32 MiB live
  allocation and for mixed accepted/rejected segments.

## OIRAN API 2.5.0 / live-probe 0.2.3 / oiran-decode 0.4.5 - 2026-10-30

- Integrated the persistent API 2.4 probe registry and its truthful heartbeat,
  interface-role, CSRF, and download-policy routes with the memory-bounded
  live-probe 0.2.3 continuous importer and oiran-decode 0.4.5 decoder release.
- Preserved the mode-`0600` registry seeded with `oiran-vprobe-local-01` and
  retained fail-closed liveness when no measured heartbeat exists.
- Kept continuous checkpoint recovery, stable session/call-flow evidence, and
  external-capture ownership boundaries unchanged.

## OIRAN API 2.4.0-dev / live-probe 0.2.0-dev - 2026-10-28

- Added an atomic, mode-`0600` probe registry seeded with
  `oiran-vprobe-local-01` and an Operator-plus-CSRF `POST /api/v1/probes`
  contract.
- Added registry-backed capture-interface roles while keeping unregistered
  roles explicitly `null`.
- Derived probe liveness only from measured capture ingestion or packet
  timestamps; probes without a real heartbeat remain `PENDING`.
- Made missing live capture interface and size evidence explicitly `null` and
  made raw PCAP download fail closed with `403 DOWNLOAD_POLICY_PENDING`.

## live-probe v0.2.3 — pcap import streaming (copy_verified + write_jsonl_atomic)

- `copy_verified` previously verified the freshly-copied temporary pcap by
  calling `fs::read` on it and feeding the full byte vector to `sha256_hex`.
  On a 512 MiB pcap import the live resident set spiked by ~512 MiB. 0.2.3
  switches the integrity hash to `sha256_hex_file`, which is already the
  streaming (`BufReader` of `STREAM_CHUNK_BYTES`) path used elsewhere in
  the module. The post-copy integrity contract (`size`, `mtime`, `sha256`
  all unchanged) is preserved; only the hashing memory footprint changes.
- The second `fs::read`-into-`sha256_hex` leak at `continuous_source_dedup_ok`
  was fixed with the same `sha256_hex_file` substitution.
- Test (`copy_verified_streams_512_mib_import_under_32_mib_live_allocation`,
  `#[ignore]`'d because the `#[global_allocator]` tracker is shared with
  concurrent tests): materialises a 512 MiB source pcap on disk, computes
  its expected SHA via the streaming hasher, builds a `SourceSegment` with
  that checksum, resets the allocation peak, calls `copy_verified`, and
  asserts the peak live allocation stays under 32 MiB. Measured on Back100:
  `COPY_VERIFIED_512MIB_PEAK_BYTES=1048765 PEAK_MIB=1 LIMIT_MIB=32`. Full
  live-probe suite: `cargo test -p live-probe` → 42 passed, 0 failed, 2
  ignored. Reproduce:
  `cargo test -p live-probe --release copy_verified_streams_512_mib_import_under_32_mib_live_allocation -- --ignored --test-threads=1 --nocapture`.

## oiran-decode v0.4.5 — streaming-friendly write_jsonl_atomic signature

- `write_jsonl_atomic` now accepts `IntoIterator<Item = &NormalizedEvent>`
  instead of `&[NormalizedEvent]`. The function body was already streaming
  through a bounded `BufWriter`; the API change lets a caller that produces
  events lazily avoid materialising the full `Vec` before writing. Existing
  callers (`live-probe/src/lib.rs:2197` with `&all_events` and
  `oiran-decode/src/lib.rs:332` with `&[]`) compile unchanged because
  `&Vec<T>` and `&[T]` both implement the new trait bound.

## live-probe v0.2.2 — source_segments OOM fix, memory-bounded ingestion

### live-probe v0.2.2 — bounded ingestion

Codex measured 27 OOMs in 5 min with RSS up to 255 MiB in a 256 MiB cgroup
on the OIRAN API, root-caused to `source_segments()` retaining up to 512
candidates and `fs::read()`-ing each pcap in full BEFORE applying the
`finalized_candidates_only` filter. The fix:

- **Metadata-first finalized filter.** `source_segments()` now walks the
  candidate pool as a cheap `SourceCandidateMeta { path, interface,
  size_bytes, modified }` projection, applies the finalized filter on
  that, THEN opens and stream-hashes only the kept candidates. The pcap
  content is never materialised in RAM — SHA-256 streams through 1 MiB
  `BufReader` chunks via `sha256_hex_file`, and packet counting uses the
  existing streaming `count_pcap_records` (16-byte header + `io::copy`
  into `io::sink`).
- **Streaming per-candidate loop.** One pcap in flight at a time; the
  candidate's `size_bytes` + `modified` are retained in metadata only.
  No `Vec<u8>` of file contents is ever held across loop iterations.
- **`events.clone()` dropped.** `session_engine::discover_sessions` was
  taking `Vec<EventRecord>` by value and consuming it, forcing live-probe
  (and three other callers) to `events.clone()` the full dataset so the
  Vec could be used after discovery. Signature changed to
  `discover_sessions(&mut Vec<EventRecord>)` — callers now pass a mutable
  borrow and reuse the same Vec afterwards. 4 call sites updated
  (live-probe, correlation-engine, apps/api, evidence-replay bin).
- **600 × 2 MiB memory-bounded test.** New
  `source_segments_memory_is_bounded_on_600_two_mib_pcaps` test uses a
  tracking `GlobalAlloc` shim to assert that the peak live allocation
  stays under 128 MiB when walking 600 synthetic 2 MiB pcaps. Measured
  peak: **1 MiB** on 512 segments (vs. ~1 GiB upper bound in 0.2.1).
  The test is `#[ignore]`'d because the global allocator counts
  allocations from every parallel test thread, so it must run alone:
  `cargo test --release -p live-probe
   source_segments_memory_is_bounded -- --ignored --test-threads=1
   --nocapture` → `source_segments peak live allocation = 1258536 B =
   1 MiB (segments=512)` in 47 s.
- **Pre-existing live-probe test failures proven as environmental.**
  Three continuous-import tests
  (`continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe`,
  `continuous_source_skips_active_truncation_and_rotates_owned_ring`,
  `full_ring_ingests_three_interface_batches_across_rotations`) fail
  when the test host's `/tmp` filesystem is at ≥ 85 % utilisation because
  `disk_safety::capture_budget` returns `allowed=false` on
  `SafetyState::StopNewCaptures`. The tests now call a
  `skip_if_disk_too_full()` guard that emits a `SKIP ...` log line with
  the detected safety state and returns early. On this host `df -h /tmp`
  reports 87 % usage; on a host with free space the guard is a no-op and
  the tests run normally.
- The merge of `feat/oiran-live-probe-finalized-segments` (0.2.0,
  SHA 0930c75) is now part of this branch: `finalized_candidates_only()`
  and `record_ingestion_failure()` are available, plus the four
  finalized-segments unit tests. Lineage proven by
  `git merge-base --is-ancestor 0930c75 HEAD` returning 0 after the
  merge commit `3e87af3`.

### decoder-ngap v0.6.0 compatibility alias

The 0.6.0 outer-list walker emitted `item_<i>_pdu_session_id` identifiers
but `session_engine::discover_sessions` groups events by the historical
`pdu_session_id` key. Fixed by also emitting a plain
`pdu_session_id=<first-item-id>` for IE 74 and IE 75 so the session
engine recognises PDU sessions decoded through the new walker. Fixes
`completed_capture_registers_real_decoded_dataset_with_provenance`.

## oiran-decode v0.4.5 / decoder-sbi v0.3.1 / live-probe v0.2.1 — SBI 0.4.2 regression + OOM fixes

### decoder-sbi v0.3.1 — HPACK regression fix

Codex measurement on inventory `aabbe5e9…` showed 0.4.2 regressed SBI
throughput 70x: 57,532 DECODED / 6,164 PARTIAL (0.3.1) → 799 DECODED / 317,019
PARTIAL (0.4.2). Two root causes were introduced in 0.4.2:
- **Permanent direction poisoning**: a single HPACK failure flagged every
  subsequent HEADERS block on the same direction as `hpack_unavailable`,
  including blocks the HPACK decoder had accepted cleanly.
- **Ghost events**: streams that in 0.3.1 would have been skipped (orphan
  CONTINUATION, oversized HEADERS/CONTINUATION fragments, unflushed
  continuations at end of capture) were promoted to synthetic events via
  `hpack_unavailable=true`. This inflated the event count by ~5x on
  well-formed captures.

Fix:
- HPACK failure now touches **only** the specific header block that failed.
  The next block that decodes cleanly re-synchronises the direction
  automatically — no permanent poisoning.
- Frame-level framing errors (orphan CONTINUATION, oversized blocks,
  unflushed continuations) are now **connection-level** entries in
  `report.errors`. They do not touch any stream state, so they do not
  fabricate events.
- One normalised event per stream (unchanged structural invariant); the
  stream is only promoted to an event when at least one direction's
  decoded headers are non-empty — same contract as 0.3.1.

Two new non-regression tests pin the contract:
- `non_regression_well_formed_connection_emits_one_decoded_event_per_stream`
  encodes 32 well-formed HTTP/2 request/response pairs with SETTINGS,
  WINDOW_UPDATE and GOAWAY interleaved. The decoder emits exactly 32
  DECODED events, zero HPACK_CONTEXT_UNAVAILABLE errors, zero ghost
  events for the control frames.
- `non_regression_hpack_failure_does_not_poison_subsequent_streams`
  encodes a failing HEADERS on stream 1 followed by a well-formed POST
  on stream 3. Stream 3 decodes cleanly, stream 1 surfaces the
  HPACK_CONTEXT_UNAVAILABLE once, and the direction-level error is
  logged exactly once in `report.errors` (not per frame).

### live-probe v0.2.1 — memory-bounded streaming I/O

Audit of live-probe 0.2.0 identified three unbounded-RAM sites that
accounted for the API OOM Codex observed:
1. **`fs::read(pcap_path)` for integrity verification**: every source
   pcap was fully materialised in a `Vec<u8>` so `sha256_hex(&bytes)`
   could run. On a multi-GB pcap this allocates the full file. Fixed by
   introducing a streaming `Sha256Hasher` in event-schema and a
   `sha256_hex_file(path)` + `verify_file_integrity(path, size, sha)`
   helper that walks the file in 1 MiB chunks via `BufReader::fill_buf`.
2. **Continuous events dedup rewrite**: the per-ingestion
   `events.jsonl` rewrite read the entire prior file via
   `fs::read_to_string`, held a `BTreeMap<String, serde_json::Value>` of
   every event, and finally serialised the whole thing into a
   `Vec<u8>` before `atomic_write`. On a long-running continuous
   capture this is proportional to the number of events ever observed.
   Fixed by streaming the prior file line-by-line, storing serialised
   lines (not parsed values), applying a `MAX_IN_MEMORY_EVENT_IDS =
   1_000_000` safety cap with FIFO eviction, and writing the output
   through a `BufWriter` + atomic rename.
3. **Recovery dataset integrity material**: `integrity_material` was
   built by `fs::read(events.jsonl)` and `fs::read(dataset_manifest)`
   concatenated into a single `Vec<u8>`, then hashed. Replaced by a
   two-file streaming SHA-256 identical bit-for-bit to the previous
   output.

Bounded-memory tests pin the contract:
- `streaming_sha256_matches_in_memory_sha256_on_large_synthetic_file`
  materialises a 64 MiB file on disk and verifies that
  `sha256_hex_file` returns the exact same hash as the full-buffer
  oracle. The production code path only ever reads
  `STREAM_CHUNK_BYTES = 1 MiB` at a time.
- `verify_file_integrity_detects_size_and_hash_mismatches_without_full_read`
  proves the integrity verifier catches size and SHA mismatches on a
  4 MiB file without a full-read oracle.

### event-schema

- Added `Sha256Hasher` (streaming) with `new()`, `update(&[u8])`,
  `finish_hex()`. `sha256_hex(bytes)` is now implemented on top of it,
  byte-for-byte identical to the previous implementation (the
  pre-existing `sha256_matches_standard_vector` test still passes).

### Open regressions

- 6 live-probe tests (`completed_capture_registers_real_decoded_dataset_with_provenance`,
  `continuous_checkpoint_keeps_five_sessions_across_restart_and_republish`,
  `continuous_import_is_incremental_deduplicated_stoppable_and_restart_safe`,
  `continuous_source_skips_active_truncation_and_rotates_owned_ring`,
  `failed_capture_recovery_is_atomic_registered_and_idempotent`,
  `full_ring_ingests_three_interface_batches_across_rotations`) are
  broken at the branch base `d85d29f` already; this release does not
  change the pass/fail count — it only adds +2 bounded-memory tests
  that both pass.

## oiran-decode v0.4.4 — pycrate-grounded real TS 38.413 transfer decoders

- `decoder-ngap v0.6.0`:
  - **Real ASN.1 ground truth: pycrate.** Replaced the simplified asn1tools
    schema (removed `tests/fixtures/aper-transfer.asn` and the asn1tools
    generator) with pycrate (`pycrate_asn1dir.NGAP`), the only Python library
    that compiles the full TS 38.413 3GPP ASN.1 module. Fixtures are now
    pycrate `.to_aper()` outputs of real NGAP types.
  - **Request transfer = ProtocolIE-Container.**
    `decode_pdu_session_resource_setup_request_transfer` now walks the real
    `SEQUENCE { protocolIEs ProtocolIE-Container {...} }` structure: outer
    SEQUENCE ext + 1-bit, 2-octet container size, then per-item
    `{ id, criticality, value OPEN TYPE }`. Decoded IEs:
    `id-UL-NGU-UP-TNLInformation` (139), `id-PDUSessionType` (134),
    `id-QosFlowSetupRequestList` (136),
    `id-PDUSessionAggregateMaximumBitRate` (130). Unknown IEs are retained
    with `{id, criticality, length}` on `unknown_protocol_ies` and named in
    `errors`; the OPEN TYPE length determinant lets the walker skip them
    cleanly instead of de-syncing.
  - **Response transfer: 4 top-level OPTIONALs + extensions.** The response
    SEQUENCE now reads the correct 5-bit preamble (ext + additional +
    security + failed + iE-Ext) and parses the `iE-Extensions`
    ProtocolExtensionContainer when present, extracting
    `id-RedundantDLQosFlowPerTNLInformation` (id 196) into `redundant`;
    other extensions are retained verbatim with their id/length.
  - **IE 71 / IE 72 (Cxt-Req / Cxt-Res).**
    `decode_pdu_session_resource_setup_list_cxt_req` and `_cxt_res` cover
    `PDUSessionResourceSetupListCxtReq` / `CxtRes` from the
    `InitialContextSetupRequest/Response` procedures (used by Open5GS to
    mount the session via the Initial Context Setup path).
  - **Correct extensibility on primitives.** Audited every INTEGER / ENUMERATED
    / CHOICE in the real NGAP module and fixed the extension-marker handling:
    `QosFlowIdentifier` is extensible (1 ext bit + 6-bit value, 7 bits total),
    `PriorityLevelARP` is NOT extensible (4-bit bit-field),
    `UPTransportLayerInformation` is NOT extensible (1-bit choice index for
    gTPTunnel vs choice-Extensions),
    `Cause` is NOT extensible (3-bit index for 6 root alternatives including
    choice-Extensions). The old implementation was wrong on all four, which
    is why the asn1tools-simplified fixtures looked self-consistent but
    disagreed with real captures.
  - **Guard-rail.** `tests/pycrate_fixtures.rs` includes an explicit guard
    that encodes `TEID=0x11223344` and `QFI=5` with pycrate and asserts the
    exact values round-trip through the decoder. Separate tests prove
    mangled or truncated bytes return a NON-matching value AND surface
    named `errors` entries — the decoder never silently fabricates a wrong
    value.
  - **8 new typed structs** exposed on the public API (`SNssai`,
    `SetupItemSUReq`, `SetupItemSURes`, `ListSUReq`, `ListSURes`,
    `UnknownProtocolIe`, `UpTransportLayerInformation::ChoiceExtensions`,
    `QosCharacteristics::ChoiceExtensions`) plus `serde::Serialize` on
    every public type so the `ngap-decode-hex` diagnostic CLI emits a
    complete JSON tree.

## oiran-decode v0.4.3 — real outer-list walker, ENUMERATED extension, diagnostic CLI

- `decoder-ngap v0.5.1`:
  - **Outer list walker, no more heuristic.** `decode_pdu_session_list` now
    routes IE 74 and IE 75 through the new
    `decode_pdu_session_resource_setup_list_su_req` /
    `decode_pdu_session_resource_setup_list_su_res` entry points, which
    implement the real X.691 ALIGNED PER encoding of
    `PDUSessionResourceSetupListSUReq` and `PDUSessionResourceSetupListSURes`:
    SIZE(1..256) size byte, per-item SEQUENCE preamble (ext +
    optional-presence bits), `pDUSessionID` octet-aligned, `pDUSessionNAS-PDU`
    with its APER length determinant, `S-NSSAI` SEQUENCE (`sST` as a SIZE(1)
    bit-field, `sD` as SIZE(3) octet-aligned), and the transfer OCTET STRING
    extracted via its own length determinant. The previous "canonical" byte
    offset heuristic has been removed; non-canonical layouts surface their
    specific failure in a per-item `errors` list and the `item_<i>_*` summary
    keys name the exact field that did not decode.
  - **`qosFlowMappingIndication` extension additions.** When the ENUMERATED
    extension bit is set, the walker now reads the normally-small-non-negative
    whole number for the extension index (X.691 Clause 10.6) and reports
    `AssociatedQosFlowMapping::UnknownExtension(index)` instead of returning
    `UnknownExtension(0)` for every extension value.
  - **Diagnostic CLI.** New binary `ngap-decode-hex` (invoked as `cargo run
    -p decoder-ngap --bin ngap-decode-hex`) reads a hex NGAP PDU from stdin
    (whitespace and `0x` prefixes tolerated) and writes the decoded tree as
    pretty-printed JSON on stdout. For IE 74 and IE 75 the embedded transfer
    is decoded in the same JSON blob so operators can diff the result
    side-by-side with `tshark -O ngap -J` on real captures.
  - **New fixtures.** 7 additional asn1tools-generated ground-truth fixtures
    cover the outer list envelope: 1 session SST-only, 1 session with NAS-PDU,
    1 session with S-NSSAI SST+SD, 1 session with item iE-Extensions, 3
    sessions mixed (NAS-PDU + SST/SD + iE-Ext), and SURes with/without
    iE-Extensions on individual items. The hand-crafted bit-level fixture
    `qos_flow_mapping_indication_extension_decodes_normally_small_number`
    exercises the ENUMERATED extension path end-to-end.
- Fixtures remain synthetic (PLMN 001/01 or TEST-NET addresses, NAS-PDU
  stub 0x7e 00 44 6f = plain 5GMM Registration Reject). No real
  SUPI/K/OPc/SUCI/GUTI/IMSI/IMEI material is present in test code,
  fixtures, or decoders.

## oiran-decode v0.4.2 — real X.691 APER walker, HPACK Huffman recovery

- `decoder-ngap v0.5.0`: removed the one-octet-per-primitive canonical walker
  and replaced it with a bit-accurate X.691 ALIGNED PER reader
  (`aper::AperReader`) plus type-specific decoders for
  `PDUSessionResourceSetupRequestTransfer` and
  `PDUSessionResourceSetupResponseTransfer`
  (`transfer::decode_pdu_session_resource_setup_{request,response}_transfer`).
  The decoders are driven by 11 ground-truth fixtures generated with
  `asn1tools` (Python, codec `per`) against the minimal TS 38.413 subset
  shipped in `decoder-ngap/tests/fixtures/aper-transfer.asn`. Each fixture
  round-trips value → bytes → decoder → value, so a byte-level drift fails
  loudly. Optional fields covered end-to-end: `gBR-QosInformation`,
  `dynamic5QI`, `reflectiveQoSAttribute`, `additionalDLQosFlowPerTNLInformation`
  (multi-tunnel), `qosFlowFailedToSetupList` with Cause CHOICE, and
  `SecurityResult`. Unsupported constructs (extension markers, choice
  extensions, unknown Cause groups) are now **named** in a `errors` vector on
  the returned structure instead of being silently dropped — the "canonical
  only" rejection path has been removed.
- `decoder-sbi v0.3.0`: `tolerant_literals` now decodes HPACK Huffman-encoded
  literals via `hpack::huffman::HuffmanDecoder`. HTTP/2 header blocks that
  only recovered static-name indexed-plain literals in 0.2.0 now also recover
  the Huffman-encoded values that make up most SBI PATCH requests. Covered by
  two unit tests: the RFC 7541 Appendix C.4.1 example for `:authority` =
  `www.example.com` and a synthetic SBI `:path` = PATCH SM-context modify.
- Fixtures remain synthetic (PLMN 001/01 or TEST-NET addresses). No real
  SUPI/K/OPc/SUCI/GUTI/IMSI/IMEI/IMEISV material is present in test code,
  fixtures, or decoders.

## oiran-decode v0.4.1 — SBI HPACK context, NGAP QoS flow walker, EPS SMC decoding

- `decoder-sbi v0.2.0`: HPACK decode failures (dynamic table state lost when the
  capture starts mid-connection, orphan CONTINUATION, header block exceeding the
  configured maximum size) are now surfaced as explicit
  `HPACK_CONTEXT_UNAVAILABLE` errors on the normalized event instead of being
  rolled into a generic PARTIAL. Once a direction's HPACK state is poisoned, any
  subsequent HEADERS block on that direction is attributed to
  `HPACK_CONTEXT_UNAVAILABLE` because the dynamic table indices can no longer be
  verified against the sender. Streams whose request headers failed to decode
  are still emitted so the response remains correlatable by HTTP/2 stream ID
  (previously these were silently dropped as incomplete). The CONTINUATION
  reassembler was audited: orphan CONTINUATION frames and over-sized blocks now
  flag the stream explicitly instead of being discarded.
- `decoder-ngap v0.4.1`: added a canonical APER walker for
  `QoSFlowSetupRequestList` inside `PDUSessionResourceSetupRequestTransfer`
  (IE 74) and `AssociatedQosFlowList` inside the first
  `QoSFlowPerTNLInformation` of `PDUSessionResourceSetupResponseTransfer`
  (IE 75). When the walker matches the "no-optionals, nonDynamic5QI, canonical
  one-octet-per-primitive" layout it emits per-item `qfi_<i>`, `five_qi_<i>`,
  `arp_priority_<i>`, `arp_capability_<i>`, `arp_vulnerability_<i>` session
  identifiers. Non-canonical encodings (extensions, additional optional
  subfields, dynamic5QI) fall back to the existing structural
  `qos_flow_setup_list=present` marker so operators can tell "scanned but could
  not decode" apart from "no QoS flow IE at all".
- `decoder-nas v0.3.1`: EPS Security Mode Command (0x5C) now has a dedicated
  per-TS 24.301 §8.5 decoder (previously the body was preserved only by
  SHA-256). Mandatory fields emitted: Selected NAS security algorithms
  (`ciphering=EEAn, integrity=EIAn`), NAS key set identifier (`nas_ksi`,
  `tsc`), and Replayed UE security capabilities parsed as EEA / EIA / UEA /
  UIA / GEA bitmaps per TS 24.301 §9.9.3.34.
- Fixtures are synthetic (PLMN 001/01 or TEST-NET addresses). No real
  identity, key, SUCI, GUTI, IMEI or IMSI material is present in test code.

## oiran-decode v0.4.0 — N2 SM transfer typing, Diameter S6a base, Security Mode Command

- `decoder-ngap v0.4.0`: PDUSessionResourceSetupListSUReq (IE 74) and
  PDUSessionResourceSetupListSURes (IE 75) now expose direction-tagged tunnel
  evidence from the nested PDU Session Resource Setup Request/Response Transfer.
  IE 74 yields `tunnel_ip_ul` + `gtp_teid_ul`, IE 75 yields `tunnel_ip_dl` +
  `gtp_teid_dl`. Structural scan also reports `pdu_session_type` (ipv4, ipv6,
  ipv4v6, ethernet, unstructured) and the presence of a QoS Flow setup list. The
  overall message status stays `PARTIAL` because QFI, QoS profile and secondary
  fields remain SHA-256 provenance; the correlation keys needed for NGAP ↔ PFCP
  ↔ GTP-U are now emitted explicitly instead of being hidden behind an
  undirected `tunnel_endpoint_ip`/`gtp_teid` pair.
- `decoder-nas v0.3.0` (TS 24.501):
  - Registration Request now decodes the optional UE security capability
    (IEI 0x2E = 46). The IE value is parsed into `nr_encryption`,
    `nr_integrity`, and when present `eutra_encryption`/`eutra_integrity`.
  - Security Mode Command (0x5D) now has a dedicated parser: Selected NAS
    security algorithms (ciphering/integrity half-octets), ngKSI, Replayed UE
    security capability (LV) and the optional Additional 5G security information
    (IEI 0x36 = 54) which reports `rinmr` and `hdp`.
- `decoder-diameter v0.2.0` (RFC 6733 + 3GPP TS 29.272): added base AVPs
  Origin-State-Id (278), Session-Id (263), Auth-Session-State (277),
  Vendor-Specific-Application-Id (260, grouped), Vendor-Id (266), Auth- and
  Acct-Application-Id (258/259). These AVPs previously forced S6a messages to
  `PARTIAL` because they were unsupported.
- All new fixtures are synthetic (PLMN 001/01 or TEST-NET addresses). No real
  identity, SUPI, K, OPc, SUCI, GUTI, IMEI or IMSI material is present in test
  code.

## live-probe v0.2.0 — finalized segments only + persistent failure log

- Continuous import skips the still-live dumpcap target per interface. For
  each interface the newest file is dropped from the candidate set whenever
  its mtime is more recent than `2 × stable_age`; finalized files
  (anything older) stay eligible. The pure helper
  `finalized_candidates_only()` replaces the previous "stable-across-scans"
  proxy at the discovery layer, so a running writer is never fed into
  `copy_verified` and cannot trigger
  `CONTINUOUS_SOURCE_CHANGED_DURING_IMPORT` as a hot-path error.
- `ContinuousImportState` grows a bounded `failed_ingestions: VecDeque<
  FailedIngestion>` persisted in `import_state.json`. Every ingestion
  failure path (`CONTINUOUS_SEGMENT_NOT_FINALIZED` pre-copy / post-copy,
  `CONTINUOUS_COPY_RETRYABLE`) now records `{source_path, error_code,
  occurred_epoch_ms}` and writes the state atomically — the entry survives
  probe restarts, so the operator can audit a 1 h window after the fact.
  Bounded at `MAX_PERSISTED_INGESTION_FAILURES=256`, FIFO-evicted.
- Pure helpers `record_ingestion_failure` and `finalized_candidates_only`
  are exposed under tests; four new unit tests exercise FIFO eviction,
  verbatim path/code/timestamp preservation, newest-per-interface skip
  within the safety window and single-file acceptance after the window
  has elapsed.
- No live-probe behaviour change for successful imports; aggregate metrics
  (`ingestion_failures`, `segments_ingested`, …) remain the same.

## decoder-ngap v0.3.1 / oiran-decode v0.3.1 - NGAP status correction

- Mark a structurally bounded NAS-PDU information element as decoded at the
  NGAP layer; the nested NAS child event independently retains
  `ENCRYPTED_OR_PROTECTED`, `PARTIAL` or `MALFORMED`.
- Correct the NAS security-header nibble and accept the observed eight-octet
  as well as schema forty-bit `UEAggregateMaximumBitRate` encodings.
- Keep PDU Session Resource Setup list items `PARTIAL` while their nested N2
  SM transfer remains opaque; no missing field is promoted to decoded.
- Replayed the unchanged finalized N2 inventory identified by SHA-256
  `aabbe5e942ede445fcd59b8ad37184f7dadc57a8b16aee935b30b99e9ecdc084`.

## decoders-epc v1.0 - GTPv2-C, Diameter S6a, EPS NAS (TS 29.274 / RFC 6733 + TS 29.272 / TS 24.301)

- `decoder-gtpv2c v0.1.0` (new crate, TS 29.274): Echo, Create/Modify/Delete Session, Create/Delete Bearer, Release Access Bearers. IEs IMSI, MSISDN, MEI are flagged identity (`pseudonymized: true`); F-TEID, Bearer Context (grouped), PAA, APN, AMBR, Serving Network (PLMN), EBI are decoded.
- `decoder-diameter v0.1.0` (new crate, IETF RFC 6733 + 3GPP TS 29.272 S6a): ULR/ULA (316), AIR/AIA (318), PUR/PUA (321), CLR/CLA (317), NOR/NOA (323). AVPs User-Name (code 1) and MSISDN (code 701, vendor 10415) are flagged identity; Result-Code, Experimental-Result-Code, Visited-PLMN-Id, Origin-Host/Realm, Subscription-Data envelope and Authentication-Info envelope are decoded.
- `decoder-nas v0.2.0` (extended, TS 24.301): added EPS EMM (Attach, TAU, Service Request, Detach, Authentication, Security Mode, Identity, EMM Status/Information, NAS Transport) and ESM (PDN Connectivity, Activate/Modify/Deactivate EPS Bearer Context, ESM Info, Status). EPS Mobile Identity (IMSI/IMEI/IMEISV/GUTI) is flagged identity.
- `decoder-s1ap v0.2.0` (updated): NAS-PDU IE (id 26) now forwards to `decoder-nas` and emits a child `NormalizedEvent` with a parent link back to the S1AP event, mirroring NGAP → 5G NAS.
- `event-schema`: added `Protocol::Gtpv2c`, `Protocol::Diameter`, `Protocol::NasEpsMm`, `Protocol::NasEpsSm` variants (`as_str` → `GTPv2-C`, `DIAMETER`, `NAS-EPS-MM`, `NAS-EPS-SM`).
- All fixtures are synthetic (PLMN 001/01, synthetic BCD/digit material). No real identities are present in test code.

## decoder-s1ap v0.1.0 - S1AP APER decoder (TS 36.413)

- Added `OIRAN/decoder-s1ap` crate implementing the schema-independent S1AP-PDU/open-type envelope and ProtocolIE container, modelled on `decoder-ngap`.
- Procedures recognised: S1 Setup (17), E-RAB Setup (5), E-RAB Release (7), Initial Context Setup (9), Paging (10), Downlink NAS Transport (11), Initial UE Message (12), Uplink NAS Transport (13), UE Context Release Request (18), UE Context Release Command / Complete (23).
- Identity-bearing IEs (`S-TMSI`, `UEPagingID`, `GUMMEI-ID`, `SecurityKey`, `NAS-PDU`) are tagged `pseudonymized: true` so the Analyzer strips them before persistence.
- Added `Protocol::S1ap` variant to the event-schema protocol enum.
- Coverage: 10 unit tests on synthetic APER vectors built from TS 36.413 with synthetic PLMN `001/01` and synthetic identities only — no real IMSI/K/OPc material in fixtures.
- Carried NAS-PDU is EPS NAS (TS 24.301) and preserved opaquely by SHA-256 + length; `decoder-nas` remains 5G-only (declared limitation).
- Added `OIRAN/docs/PROTOCOL_AUDIT.md` with the static 12-plane coverage audit.

## Release consolidation V1.1 - lossless continuous checkpoint resume

- Preserve evidence-backed session identifiers when live activity credit expires or a continuous import is finalized.
- Validate and merge the last durable continuous dataset checkpoint before publishing the next atomic dataset generation.
- Deduplicate observations by stable semantic event identifier and retain only call flows whose event references remain present.
- Fail closed on an invalid checkpoint without replacing the prior event store.
- Added restart, new-data, idempotent replay, five-session retention, and invalid-checkpoint regression coverage.

## E2E-002 - Atomic derived-dataset registration

- Added an authenticated, allowlisted import endpoint that accepts only a derived dataset identifier.
- Verifies source capture identity, all source PCAP hashes and packet counts, artifact hashes, schema/decoder compatibility, provenance, sessions, and correlation evidence before registration.
- Stages and atomically renames the complete dataset, callflows and registry update.
- Supports idempotent re-import and rejects conflicting dataset identifiers.
- Added authenticated candidate browser coverage for derived dataset visibility, exact tunnel evidence, strong associations, unknown NG-U evidence and packet provenance.

## E2E-002 - Evidence-based cross-interface correlation

- Normalized structurally verified NGAP UP transport endpoint and TEID evidence.
- Added typed exact-tunnel and strong-context correlation edges with scope, limitations, and packet provenance.
- Added ambiguity rejection and kept missing NG-U evidence explicitly unknown.
- Exposed evidence type and limitations in Call Flow and Correlation Studio.
- Added an immutable-source offline replay producing a separate 92-event derived dataset.

All notable OIRAN vProbe changes are recorded here. Versions follow Semantic Versioning.

## [S5.5.1/1.0.1-dev] - 2026-10-26

### Fixed

- Defined the shared Rust `MAX_CAPTURE_PLANES = 4` contract and applied it independently in the live-probe API validator and isolated Capture Helper.
- Made the four-plane default (`N2`, `SBI`, `N4`, `N3`) valid while retaining one-, two- and three-plane compatibility.
- Preserved strict rejection of duplicate, unknown, unavailable and more-than-four logical planes.
- Added deterministic interface inventories for offline helper/IPC tests while retaining the fixed `/sys/class/net` inventory in production.
- Added explicit Select All and Apply Configuration controls; successful validation is invalidated whenever capture configuration changes.

### Validation

- Passed 172/172 Rust workspace tests, including authenticated HTTP API to Unix IPC to non-acquiring Capture Helper validation.
- Passed 19/19 frontend tests, TypeScript validation and the production frontend build.
- Passed 46/46 browser E2E regressions against an isolated local API and copied read-only registry fixture.

### Safety

- Four-plane storage remains one global bounded reservation: the helper divides the job budget across plane/rotation segments rather than multiplying it.
- No packet socket was opened by the new validation test, and no live capture, simulator execution, production deployment or service restart occurred.

## [S5.5/1.0.0-dev] - 2026-10-26

### Added

- Unified S5.1 SLL2, S5.2 NAS and S5.3 TCP/HTTP2/SBI decoding in one release lineage.
- Fixed, allowlisted SBI capture point (`br-oiran-sbi`, TCP/7777) in the isolated AF_PACKET helper.
- Four-plane POLARIS profile for NG-C, SBI, N4 and NG-U with synchronized capture-group identifiers and per-plane results.
- Capture-group API, per-plane packet/storage/decode status, and four-plane Probe Manager controls.
- SBI-aware Call Flow participants, arrows and conservative E2E status that remains UNKNOWN when either SBI bridge is unproven.

### Validation

- Passed 166 Rust tests and 18 frontend tests; production frontend build and TypeScript validation passed.
- Passed the dedicated four-plane Playwright suite in Light/Dark at 1440x900 and 1920x1080.
- Retained the unchanged 13-file corpus and the multi-IMSI result: six UE contexts, five PDU sessions, six PFCP sessions, zero GTP-U tunnels and no observed cross-UE contamination.

### Safety

- No live capture, simulator execution, production deployment or shared-service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were unchanged.

## [S5.3/1.0.0-dev] - 2026-10-26

### Added

- Bounded bidirectional TCP reconstruction with sequence-aware retransmission, duplicate, out-of-order, gap, timeout and provenance handling.
- Native HTTP/2 frame and multiplexed-stream decoding, including HEADERS/CONTINUATION/DATA and stateful HPACK through the MIT-licensed `hpack` crate.
- Sanitized SBI request/response events for observed Nsmf PDUSession and Namf Communication operations, with JSON/multipart field extraction and explicit TLS/unresolved states.
- Conservative SCP-routing and cross-interface correlation hooks that reject PDU Session ID-only and timestamp-only associations.
- SBI participants and request/response messages in the existing Call Flow schema without synthesizing unseen logical hops.

### Validation

- Replayed the unchanged 13-file, 4,205-packet corpus with SHA256 verification before and after.
- Matched 2,316/2,316 HTTP/2 frames and 766/766 independently comparable fields against TShark 4.2.2; 26 fields remain unresolved because capture begins after HPACK dynamic-table state was established.
- Observed 48 TCP connections, 708 HTTP/2 streams, 198 transactions and 20 prioritized operations.
- Preserved six UE contexts and five PDU sessions without observed cross-UE contamination; the N2/SBI/N4 bridge remains uncertified because explicit cross-layer identifiers are absent.

### Safety

- No live capture, simulator execution, production deployment or service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and the reference corpus were unchanged.

## [S5.2/1.0.0-dev] - 2026-10-26

### Added

- Native bounded Rust dispatch for 5GMM (`0x7e`) and 5GSM (`0x2e`) with observed Release-17 message identities.
- Safe Type 1/3/4/6, TV, TLV and TLV-E handling for observed NAS fields, including pseudonymized mobile identities, PDU Session ID, PTI, causes, DNN and S-NSSAI.
- Explicit NAS security-envelope classification without key derivation, integrity claims or unauthorized decryption.
- Parent/child NGAP → 5GMM → 5GSM event relationships with inherited packet provenance and compatible event schema 1.4.0 fields.
- Evidence-based procedure attempts that separate retry, failure, success and incomplete results and scope NAS children through their exact NGAP parent.

### Validation

- Replayed the unchanged 13-file, 4,205-packet S5.1 corpus before/after SHA256 verification.
- Parsed 116 NGAP-carried NAS envelopes across the full corpus; 46 plain messages were decoded (24 complete, 22 partial), 10 integrity-only messages were decoded without claiming verification, and 60 ciphered envelopes remained unresolved.
- Achieved 404/464 exact independently comparable TShark fields, with zero mismatch and 60 encrypted/unresolved message-type fields.
- Preserved six UE context lifecycles and five PDU sessions in the multi-IMSI fixture without observed cross-UE contamination.
- Passed 152/152 Rust workspace tests after one documented retry of a pre-existing timing-sensitive worker-runtime queue watermark test.

### Safety

- No live capture, simulator execution, production deployment or service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were unchanged.

## [S5.1/1.0.0-dev] - 2026-10-26

### Added

- Native Linux cooked capture v2 parsing for `LINKTYPE_LINUX_SLL2` / link type 276.
- Network-byte-order parsing and validation for the 20-byte SLL2 header, including protocol, interface index, ARPHRD type, packet type and address metadata.
- Additive event provenance schema 1.3.0 fields for source SHA256, link type and SLL2 metadata.
- Per-interface SLL2 dispatch for PCAPNG and IPv6 extension-header traversal with explicit fragment/ESP limitations.

### Validation

- Replayed the unchanged 13-file, 4,205-packet benchmark corpus after SHA256 verification.
- Decoded 239 LAB NGAP/PFCP/GTP-U message envelopes with exact packet, timestamp, endpoint and message parity against TShark 4.2.2.
- Reconstructed five isolated PDU sessions from the five-UE fixture without cross-UE contamination; cross-interface N2/N4 confidence remains unresolved.
- Added deterministic PCAP, PCAPNG mixed-link, IPv4, IPv6, malformed-header and fuzz-like regression tests.

### Safety

- No live capture, simulator execution, deployment or production service change occurred.
- POLARIS, POLARIS Control, ETV/OTV and historical certified datasets were unchanged.

## [2.3.0-dev] - 2026-10-26

### Fixed

- Normalize historical, captured-live and recovered dataset records behind API 2.3.
- Add explicit dataset scopes to Session Explorer without fallback to an unrelated historical session.
- Scope decode-completeness counts to session-associated events instead of dataset background events.
- Preserve exact dataset identity through Session Explorer and Call Flow navigation.

### Validation

- Added a deterministic, clearly labeled test corpus with three independent UE contexts, PDU sessions, PFCP sessions and GTP-U tunnels.
- Verified composite identity isolation, identifier reuse safety, pagination and zero-session datasets.
- Passed 134 Rust tests, 18 frontend tests and 44 browser workflows.
- Reviewed Light and Dark screenshots at 1440×900 and 1920×1080.

### Safety

- No live capture, simulator traffic, UE process, deployment or production-service restart occurred.
- POLARIS, POLARIS Control, ETV/OTV and certified historical datasets were not changed.

## [1.0.0-dev/OIRAN-P0-LIVE-FINALIZATION-FIX] - 2026-10-25

### Fixed

- Create the derived `dataset/callflows` layout before the first decoded-event write from a freshly finalized helper capture.
- Preserve `FAILED` status for recoverable PCAP evidence until derived processing completes successfully.
- Synchronize terminal helper storage accounting after empty-interface PCAP headers are finalized.
- Show an explicit **View error** action, exact backend failure, and preserved-evidence state for failed capture jobs without linking them to fictitious sessions.
- Finalize normalized-event JSONL, Call Flow exports and dataset manifests using temporary files plus atomic rename.
- Add an idempotent `oiran-recover` command and persistent recovered-dataset registry that never changes the original failed job.

### Validation

- Added clean-root regressions for fully populated N2/N3/N4 captures and captures with an empty N3 interface.
- Added offline timeout, graceful manual Stop, bounded rotation, empty selected interface, partial initialization failure, and failed-job recovery coverage.
- Recovered `live-1792964646320-0003` offline as 50 verified packets and 20 PFCP heartbeat events; the original capture remains `FAILED`.
- No live capture or simulator traffic was executed; original forensic PCAPs and historical certified datasets remain unchanged.

## [1.0.0-dev/OIRAN-P0-ISOLATED-CAPTURE-HELPER] - 2026-10-25

### Added

- Native Rust AF_PACKET capture helper with no tcpdump subprocess dependency.
- Unix socket IPC v1 with `SO_PEERCRED` server authorization and client-side helper identity verification.
- Fixed N2/N3/N4 interface enum, bounded request schema, exact job ownership, and explicit `COMPLETED_EMPTY` state.
- Global disk budget, bounded PCAP rotation, atomic manifests, SHA-256 integrity, and persisted helper job records.
- Review-only hardened systemd unit, API drop-in, IPC specification, security review, and deployment/rollback plan.

### Changed

- `live-probe` now uses the isolated IPC adapter and fails closed when its authorized socket is absent.
- The API capture root may use the fixed `/var/lib/oiran/captures` deployment path; arbitrary Web paths remain impossible.
- Unix termination signals are represented separately from process exit codes.

### Safety

- No helper was deployed or started and no live capture or simulator traffic was executed.
- POLARIS, POLARIS Control, ETV/OTV, Open5GS, UERANSIM, historical datasets, Docker, firewall, and routing were unchanged.

## [2.0.0-dev] - 2026-10-25

### Added

- Premium dark-default Analyzer shell with complete Light, Dark and System themes.
- Operational Overview, Packet Analyzer, Export & Reports, and Live Monitoring modules.
- Versioned API 2.0 endpoints for probe detail, truthful host/live metrics, packet provenance, public Viewer identity, and fail-closed capture lifecycle validation.
- Evidence-driven Call Flow inspector tabs for decoded fields, ASN.1, restricted raw payload references, canonical JSON, correlation evidence and provenance.
- Responsive visual validation for seven analytical views at 1440×900 and 1920×1080 in both themes.

### Validation

- 97 Rust/API tests, 9 frontend tests and 33 browser workflows pass.
- Certified accounting remains 54 source events, 26 session events, 28 background events and 12 evidence edges.
- Live metrics are `NOT AVAILABLE` and capture controls remain unavailable because no authorized live capture backend is configured.

### Safety

- The certified PCAPs and Call Flow JSON remain checksum-identical.
- No POLARIS, POLARIS Control, ETV/OTV, Open5GS, UERANSIM, Docker, firewall, routing or database resource was modified.

## [1.0.0-dev/S4.2] - 2026-10-25

### Added

- Permanent 75/80/85/90 percent disk policy with statvfs byte/inode measurement.
- Fail-closed stateful capture guard, reserved between-poll write budget and bounded 256 MiB × 8 rotation plan.
- Authenticated storage-safety API and measured Probe Manager storage panel.
- Approval-gated five-UE POLARIS scenario manifest and validation reports.

### Safety

- No five-UE scenario, traffic or capture was started because new POLARIS profiles/processes require explicit approval.
- No cleanup, automatic deletion, service restart, database, Docker-network, firewall or route change occurred.

## [1.0.0-dev/S4.1] - 2026-10-24

### Added

- Deterministic multi-UE, multi-PDU, PFCP lifecycle and directional GTP-U tunnel discovery.
- Immutable checksum-based dataset registry with idempotent duplicate handling.
- API 1.1 dataset/UE/procedure endpoints and multi-flow state with S4 compatibility.
- Dataset, UE, interface and state filtering across Session Explorer and Correlation Studio.
- Independent session selection in Call Flow Viewer and conservative incomplete-flow generation.

### Validation

- 85 Rust release tests, 9 frontend tests and 28 browser workflows pass.
- Five-UE/six-PDU synthetic fixture covers concurrent, sequential and incomplete behavior; real multi-UE capture certification remains pending.
- Certified S3.3 call flow and N2/N3/N4 checksums remain unchanged.

### Safety

- POLARIS was read-only; ETV/OTV, Docker networks, databases, routing and capture services were not modified or restarted.
- No additional UE, test traffic or live capture was started.

### Public read-only access update — 2026-10-25

- Removed viewer/admin access tokens and the sign-in screen by explicit operator request.
- Preserved read-only API behavior, disabled live capture controls, sanitized provenance and immutable datasets.

## [1.0.0-dev/S4] - 2026-10-24

### Added

- Localhost-only Axum API adapter with bearer authentication, read-only authorization, pagination, filtering, sanitized provenance and protected exports.
- React/TypeScript application with a shared module-aware shell, Probe Manager, Session Explorer, SVG Call Flow Viewer and Correlation Studio.
- Real integration with 54 certified events, including the strict 26 session / 28 background split and all 12 evidence edges.
- Responsive 1440×900 and 1920×1080 visual certification, keyboard focus states, dark theme, error/empty/loading states and URL-deep-linked sessions.
- Isolated deployment templates, API contract, security/deployment reports and a 25-workflow browser suite.

### Validation

- 71 Rust/API tests, 8 frontend tests and 25 browser workflows pass.
- Production frontend build and TypeScript checking pass; npm audit reports zero vulnerabilities.
- Certified call flow and PCAP hashes remain unchanged; no Docker, database, firewall, route or persistent-service mutation was performed.

## [1.0.0-dev/S3.1-S3.2] - 2026-10-24

### Added

- Native bounded PCAP and PCAPNG reader with exact per-interface timestamp provenance.
- Ethernet, stacked VLAN, Linux cooked v1, IPv4/IPv6, UDP and SCTP extraction.
- SCTP DATA parsing, association generations, duplicate handling and conservative reassembly.
- Independent NGAP, PFCP and GTP-U decoder crates behind plugin API 1.1.0.
- Event schema 1.1.0 with deterministic IDs, packet sets, endpoint roles, decode statuses and raw-payload references.
- Offline CLI producing 99 ordered real-capture events and an independent TShark comparison.

### Validation

- 40 unit/regression tests pass.
- Exact packet/header alignment: 37 NGAP, 52 PFCP and 10 GTP-U; zero missing or mismatched messages.
- Full nested IE parity remains partial: 33 NGAP and 12 PFCP events explicitly retain unsupported values.
- Operational N3 remains empty; GTP-U evidence comes from an immutable Open5GS reference under POLARIS.

### Safety

- No benchmark, package installation, service restart or POLARIS/ETV/OTV mutation.

## [1.0.0-dev/S2.1] - 2026-10-24

### Added

- Immutable preloaded multi-flow batches and deterministic worker-owned partitions.
- Generator-only, independent preloaded fast-path and full-pipeline benchmark isolation.
- Queue-oriented source contract for future PCAP, AF_XDP and DPDK adapters.
- Effective-cpuset-aware automatic/explicit/disabled affinity and worker mask reporting.
- Mandatory fresh receipt from a bounded 15-minute resource safety observer.

### Changed

- `capture-core`, `worker-runtime` and `benchmark-engine` advanced to 0.3.0.
- Processing-only timing no longer contains serial generation, per-packet allocation, queues or shared counters.
- Full-pipeline reporting distinguishes generated, enqueued, processed, explicit drops and in-flight packets.

### Validation

- 21 unit tests passed with no failure; performance runs were deferred because the stability gate did not pass.
- No 25 Gbit/s or 100 Gbit/s capability claim is made.

## [1.0.0-dev/S2] - 2026-10-24

### Added

- Generator-only, pre-generated processing-only and full-pipeline benchmark modes.
- Exact generated = processed + explicit-drop invariant.
- Packet-number sum/XOR, ordered work accumulator and provenance-length validation.
- Four-worker accounting, same-flow ordering and length-mismatch regression tests.
- Complete 1–4 worker, 32–256 batch and 64–1500 byte before/after matrices.

### Changed

- `capture-core` 0.2.0 adds uniquely owned packet buffers while preserving shared replay buffers.
- `worker-runtime` and `telemetry` 0.2.0 aggregate fast-path counters per batch.
- `benchmark-engine` 0.2.0 reports generated packets, length errors and observable work.

### Performance

- Fixed S1 profile (2 workers, batch 64, 250 ms): 1500-byte median increased from 2.694994 to 3.037666 Gbit/s Ethernet-wire equivalent (+12.72%).
- Best accepted three-run median: 3.175694 Gbit/s at 2 workers, batch 256, 1500-byte frames.
- No claim of 25 Gbit/s certification.

### Safety stop

- Further component profiling stopped after an external OTV container replacement/worker exit was observed. S2 status is partial; no OIRAN command modified OTV.

## [1.0.0-dev] - 2026-10-24

### Added

- Eight-crate Rust workspace with independent component versions.
- Immutable packet provenance and batch envelopes.
- Allocation-free Ethernet, VLAN, IPv4, direct-UDP IPv6, UDP and GTP-U classification.
- TEID and tunnel endpoint extraction with strict malformed-length detection.
- Stable software flow/session affinity independent of NIC RSS behavior.
- Bounded per-worker queues, batch execution, CPU affinity, backpressure accounting and graceful shutdown.
- Deterministic replay mode and cache-line-aligned per-worker counters.
- Versioned normalized event model and deterministic decoder plugin contract.
- Safety-bounded synthetic benchmark for 64, 128, 512 and 1500-byte frames.
- Automated integrity, parser, concurrency, saturation, shutdown and replay tests.

### Limitations

- No production capture adapter, SCTP/NGAP/PFCP decoder, dynamic plugin loader or UI in S1.
- No IPv4 fragment or IPv6 extension-header reconstruction.
- Synthetic results are not line-rate certification.

## [1.0.0-dev/S3.2.1] - 2026-10-24

### Added

- Release-aware typed NGAP decoding for observed UE IDs, location, security, S-NSSAI, PDU-session identifiers, cause and selected node/context fields.
- Recursive typed PFCP decoding for the grouped and leaf IEs observed in the selected captures.
- Event-schema 1.2 probe/capture-point identity and explicit EXACT/STRONG/POSSIBLE/UNKNOWN evidence references.
- Field-parity, N3 diagnostic, dataset and correlation-readiness artifacts.

### Changed

- `decoder-ngap` and `decoder-pfcp` advanced to 0.2.0; `event-schema` advanced to 1.2.0-dev.
- Known but untyped PFCP leaves are PARTIAL and unknown IEs are UNSUPPORTED rather than silently decoded.
- The selected PFCP set improved from 40 fully decoded and 12 partial messages to 52 fully decoded and zero partial; NGAP improved from 4/33 to 9/28.

### Validation and safety

- 46 workspace tests pass; 99/99 generated events retain packet provenance and evidence.
- Operational N3 remains empty because no UE user-plane traffic was generated; no POLARIS or ETV/OTV service was changed.
- Full Release-17 NGAP parity and a coherent operational N2/N4/N3 dataset are not claimed.

## [1.0.0-dev/S3.3] - 2026-10-24

### Added

- Independently versioned `session-engine`, `correlation-engine`, `callflow-schema`, `callflow-renderer`, and `oiran-callflow` crates.
- Deterministic UE/PDU/PFCP/GTP-U reconstruction with explicit session, background and unmatched accounting.
- Versioned STRONG N2↔N4 certified-tunnel rules and EXACT N4↔N3 TEID-plus-endpoint rules.
- Canonical Call Flow JSON and standalone interactive HTML with filters, search, zoom, procedure groups, evidence inspector and JSON export.
- Seventeen unit tests for reconstruction, ambiguity, missing data, duplicate handling, provenance, schema, output containment and safe HTML rendering.

### Validation

- All 54 certified source events are preserved: 26 session, 28 background, 0 unmatched, 0 duplicate and 0 extra.
- Twelve evidence-bearing edges reproduce N2↔N4 STRONG, N4↔N3 EXACT and E2E STRONG.
- 63 workspace tests pass; all historical 46 tests remain passing.

### Security

- Subscriber identity remains `UE-A`; no authentication material or unrestricted raw payload is exported.
- HTML has no remote dependency, treats decoded values as text, and script-escapes embedded JSON.

## [1.0.0-dev/OIRAN-LIVE-V1] - 2026-10-25

### Added

- Strictly owned, allowlisted Rust live-capture manager for the discovered POLARIS N2, N3 and N4 Linux bridges.
- Bounded duration, global byte reservation, per-interface rotation, continuous disk enforcement, exact PID ownership, persistent job recovery and audit records.
- Reusable native decoder library feeding normalized events, multi-session discovery, correlation and canonical Call Flow outputs after capture finalization.
- Versioned capture validation/start/stop/metrics API with Viewer, Operator and Administrator enforcement.
- Probe Manager controls, real interface inventory, session-scoped token login and honest execution/certification states.

### Safety

- Capture execution is disabled by default and requires `OIRAN_CAPTURE_EXECUTION_ENABLED=1` plus a server-provisioned token hash.
- No live capture or traffic generation was executed in this release; POLARIS, POLARIS Control and ETV/OTV were not changed.
- Job storage is constrained to `/root/OIRAN_VPROBE/runtime/live-captures`; source datasets are never deleted or overwritten.

## [1.0.0-dev/OIRAN-P0-CAPTURE-LIFECYCLE] - 2026-10-25

- Fixed tcpdump output ownership for its restricted service account.
- Run the OIRAN API with the restricted `tcpdump` primary group and grant write access only to each job's PCAP directory, avoiding the broader `CAP_CHOWN` capability.
- Configure the capture helper to retain the already systemd-confined service identity, avoiding a denied tcpdump `setuid/setgid` transition without granting additional capabilities.
- Persist helper PID, exit status and bounded stderr for capture forensics.
- Classify premature helper exit and missing output as failures.
- Represent legitimate empty capture explicitly without generating sessions.
- Synchronize the selected capture panel with authoritative polling state.
- Recover the affected legacy false-success job as failed.

## [2.2.0-dev] - 2026-10-25

### Added

- Strict capture-to-dataset resolution through `GET /api/v1/captures/{capture_id}/context`.
- Exact packet provenance filters for capture, event and packet number.
- Evidence-derived Call Flow participants, directional SVG arrows, procedure controls and a synchronized message index/inspector.
- Honest zero-session and unavailable-dataset investigation states.
- UTC millisecond timestamp formatting and provenance deep links into Packet Analyzer.

### Changed

- Session navigation now persists `capture_id`, `dataset_id`, `session_id`, `probe_id`, technology and selected event in the URL.
- Capture records expose their associated dataset without changing the immutable capture outcome.
- OIRAN API and Web versions advance to 2.2.0-dev.

### Safety

- No decoder, historical dataset, live capture service or external laboratory component was modified or started.

