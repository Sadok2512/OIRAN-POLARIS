# OIRAN vProbe architecture through S4.2

## V2.3 dataset-scoped investigation

API 2.3 normalizes immutable historical, completed-live and recovered dataset records into one read-only inventory. Dataset kind, capture identity and stable session identifiers travel in URL state. Session Explorer never substitutes the certified historical flow when a selected dataset has no reconstructed session. The Rust session engine remains authoritative; POLARIS scenario metadata is advisory discovery context and cannot create or correlate a session.

The deterministic V2.3 fixture covers three independent UE contexts and three PDU/PFCP/GTP-U chains. Composite NGAP context, endpoint-scoped SEID and endpoint/direction-scoped TEID keys prevent cross-UE merging. This is offline validation, not live multi-UE certification.

## OIRAN-LIVE-V1 capture boundary

The `live-probe` crate discovers only the approved POLARIS bridges (`br-oiran-n2`, `br-oiran-n3`, `br-oiran-n4`) and delegates acquisition over an authenticated Unix socket to the isolated `capture-helper` crate. The helper maps an enum to those fixed devices and uses native Linux AF_PACKET sockets; it accepts no shell command, executable, output path, raw device name, or user-supplied filter. A capture job owns a global write budget, duration and rotation limits. Stop targets only the exact helper-owned job and never touches POLARIS capture processes.

```text
authenticated API -> Unix IPC/SO_PEERCRED -> native AF_PACKET helper
 -> allowlisted bridge -> bounded PCAP rotation -> oiran-decode
 -> normalized JSONL -> session-engine -> correlation-engine
 -> canonical Call Flow JSON/HTML -> authenticated API
```

Execution is fail-closed and disabled by default. Both the deployment gate and authorized helper socket must exist. The public role remains Viewer. Operator and Administrator roles are derived from server-side SHA-256 token fingerprints and control only OIRAN-owned jobs. Completed jobs and datasets survive controller restart; an interrupted active job is recovered as failed rather than silently resumed. The proposed helper service has only `CAP_NET_RAW`; the API has no packet-capture capability.

## S4.2 permanent storage guard

`disk-safety` 0.1.0 measures the affected filesystem with `statvfs`, evaluates exact 75/80/85/90 percent states, validates inode and byte headroom, and issues a bounded write budget. Capture writers must obtain a start budget and authorize every write. The budget provides an event-driven ceiling between one-second samples; measurement failure and 85% utilization finalize OIRAN-owned writes while read-only analysis remains available. The crate has no cleanup or deletion operation.

## S4.1 discovery boundary

`session-engine` 0.2.0 separates UE contexts, PDU sessions, PFCP sessions, GTP-U tunnels and procedures. Composite scoped identities and lifecycle generations prevent identifier reuse from merging distinct UEs. `dataset-registry` indexes only immutable, checksum-addressed, allowlisted captures and rejects duplicate capture sets. API 1.1 stores a map of canonical Call Flows instead of one global flow; the React views select dataset, UE and session without implementing correlation logic.

Ambiguous TEID reuse produces no PFCP↔GTP-U edge. Additional PDU sessions are materialized as conservative independent flows from observed events; cross-interface observations are added only through unique evidence or an existing canonical sidecar. Full rules and limitations are documented in `S4_1_MULTI_SESSION_ARCHITECTURE.md` and `S4_1_IDENTITY_CORRELATION_RULES.md`.

## S4 application boundary

```text
immutable certified PCAP/JSON
          |
  existing Rust S3.3 engine artifacts
          |
 public read-only oiran-api (Axum, /api/v1)
          |
 React/TypeScript module shell (TanStack Query/Table, SVG views)
```

`apps/api` is a versioned adapter, not a decoder. It deserializes the canonical `callflow-schema` model, preserves event IDs/timestamps/decoding states/evidence, sanitizes filesystem paths, paginates events and serves protected exports. `apps/web` renders only API responses. Live capture, command execution, filesystem selection, decoder replay and rule editing have no S4 route.

The backend remains loopback-bound behind a fixed reverse proxy. The module registry supplies route, navigation, core compatibility, capabilities and permissions for six modules; the shell does not contain protocol-specific decoder logic. Public access needs no token because the API exposes only read operations and no write capability exists.

## Design goals and boundary

S1 establishes a deterministic Rust foundation for a 25 Gbit/s initial design target and an eventual 100 Gbit/s scale-out path. It does not claim either rate as achieved or certified. The implemented source is offline/synthetic and makes no change to POLARIS, ETV/OTV, capture interfaces or running services.

```text
capture source / deterministic replay
                 |
          immutable PacketRecord
                 |
    Ethernet -> IP -> UDP -> GTP-U classifier
                 |
       software affinity dispatcher
       (flow or correlation key)
          /          |          \
   bounded Q0   bounded Q1   bounded Qn
       |             |           |
    worker 0      worker 1    worker n
       \             |           /
       per-worker counters + normalized events
```

## Workspace components

| Crate | Version | Responsibility |
|---|---:|---|
| `capture-core` | 0.3.0 | Owned/shared/preloaded packet buffers, provenance, source abstraction and integrity fingerprints |
| `packet-classifier` | 0.1.0 | Allocation-free Ethernet/VLAN/IP/UDP classification and strict GTP-U parsing |
| `flow-dispatcher` | 0.1.0 | Stable bidirectional flow hash and explicit cross-interface correlation affinity |
| `worker-runtime` | 0.3.0 | Bounded queues, independent preloaded workers, cpuset-aware affinity, replay and shutdown |
| `event-schema` | 1.2.0-dev | JSONL normalized events, probe/capture identity, exact timestamps, provenance, evidence, pseudonymization and statuses |
| `plugin-runtime` | 1.1.0-dev | Versioned decoder manifests, capabilities, input and output contract |
| `telemetry` | 0.2.0 | Cache-line-aligned per-worker batch counters and integrity accumulators |
| `benchmark-engine` | 0.3.0 | Safety-receipted, isolated generator/preloaded/full-pipeline measurement modes |
| `capture-pcap` | 0.1.0 | Native bounded PCAP/PCAPNG reader and L2/L3/L4 extraction |
| `transport-sctp` | 0.1.0 | SCTP DATA parsing, duplicate detection and conservative message reassembly |
| `decoder-ngap` | 0.2.0 | Release-17.3 APER envelope/IE container with typed observed fields and explicit opaque nested transfers |
| `decoder-pfcp` | 0.2.0 | PFCP header plus recursive typed grouped/leaf IE decoder with strict length validation |
| `decoder-gtpu` | 0.1.0 | GTP-U header, optional fields and extension-chain decoder |
| `oiran-decode` | 0.1.0 | Offline decoding CLI and ordered JSONL event sink |
| `session-engine` | 0.2.0 | Deterministic multi-UE/PDU/PFCP/GTP-U discovery, lifecycle handling and event accounting |
| `correlation-engine` | 0.2.0 | Versioned evidence rules, composite tunnel matching and ambiguity rejection |
| `dataset-registry` | 0.1.0 | Immutable capture-set indexing, deduplication, search and comparison |
| `disk-safety` | 0.1.0 | Fail-closed filesystem thresholds, reserved capture budgets and bounded rotation |
| `callflow-schema` | 1.0.0 | Canonical JSON model shared by analysis and presentation |
| `callflow-renderer` | 0.1.0 | Standalone dependency-free interactive HTML renderer |
| `oiran-callflow` | 0.1.0 | Dataset-to-JSON/HTML certification CLI |

## Fast path

`packet-classifier` parses borrowed byte slices and performs no heap allocation. It validates Ethernet/VLAN boundaries, IPv4/IPv6 direct-UDP lengths, UDP length and GTPv1-U mandatory/optional header bounds. It returns endpoints, ports, message type, TEID and payload offset/length. IPv6 extension-header traversal and fragmented-IP reassembly are deliberately unsupported in S1 and fail explicitly instead of being guessed.

Packet storage uses `PacketBuffer`: generated/live packets remain uniquely owned as `Box<[u8]>`, while pre-generated replay fixtures may use `Arc<[u8]>`. Queues move the buffer owner rather than copying frames. This removes the S1 `Vec → Arc<[u8]>` conversion from the full pipeline. Synthetic generation still allocates one source buffer per packet and is not representative of a future zero-copy capture front end.

## Scheduling, affinity and backpressure

Each worker owns a bounded `sync_channel`, avoiding a global shared receiver. A stable FNV-1a software hash canonicalizes both directions of the same UDP/GTP-U flow. Cross-interface N2/N3/N4 processing must use `correlation_affinity` with a control-plane-derived canonical session key; RSS and five-tuples are not assumed to provide session affinity.

Nonblocking submission detects a full queue, increments backpressure/drop counters and releases the rejected batch. Queue telemetry counts the queued batch plus a transient handoff to the active worker. Graceful shutdown closes senders and joins workers after accepted batches drain.

Linux workers can call `sched_setaffinity`; failures are reported and never silently interpreted as successful pinning. Deterministic replay sorts packet records by `(timestamp_ns, packet_number)` and executes stable software partitioning without concurrent scheduling.

## Traceability and plugin isolation

Every packet carries capture ID, packet number, nanosecond timestamp, captured/original lengths and ingress interface. The synthetic engine adds an expected fingerprint and workers verify it. Production cryptographic capture identity remains a capture-ingest responsibility for S2.

The plugin API requires a deterministic manifest and exact API version. S1 supplies the contract and event model, not dynamic library loading or an NGAP decoder. Future out-of-process adapters should apply memory/CPU limits, remove network access and validate normalized events at the boundary.

## Telemetry semantics

- `packets` and `bytes`: successfully dequeued and processed frames;
- `gtpu_packets`: valid GTP-U classifications;
- `malformed`: classifier failures;
- `integrity_errors`: synthetic fingerprint mismatches;
- `dropped`: packets rejected before processing;
- `backpressure_events`: rejected batch submissions;
- `queue_high_watermark`: maximum outstanding queue/handoff batches per worker.
- `length_errors`: mismatch between captured bytes and provenance lengths;
- `packet_number_sum`/`packet_number_xor`: duplicate/loss detection when no explicit drop occurred;
- `work_accumulator`: ordered, observable use of decoded TEIDs and packet provenance.

Worker-local counts are accumulated in registers for a batch and committed atomically once per metric per batch. This preserves concurrent snapshots while removing S1's multiple atomic operations per packet.

CPU percentage is process CPU time divided by elapsed wall time; 200% represents two fully utilized logical CPUs. Throughput fields are distinct:

- GTP-U payload Gbit/s excludes Ethernet, outer IP/UDP and GTP-U headers;
- captured Gbit/s uses the generated captured-frame byte length;
- Ethernet wire-rate equivalent adds 4-byte FCS, 8-byte preamble/SFD and 12-byte inter-frame gap.

## Path toward 25/100 Gbit/s

The current generator/classifier baseline is correctness-oriented. Progression to line-rate requires measured stages: AF_XDP or DPDK capture adapter, preallocated buffer pools, zero-copy batches, NIC queue/RSS characterization, NUMA-local memory and workers, huge pages where justified, hardware timestamp/drop telemetry, multi-port testing, and real replay with a calibrated traffic generator. For cross-interface correlation, a software session-directory stage must map N2/N4 control identifiers onto the N3 worker key.

No synthetic in-process result is accepted as 25 Gbit/s certification. Certification requires physical ingress, verified frame loss, NIC/driver counters and sustained tests on dedicated hardware.

## S2.1 corrected benchmark boundary

Preloaded processing builds immutable multi-flow batches and assigns them to worker-owned partitions before the timed section. Workers start through a barrier and parse with local counters; there is no producer, allocation, queue, lock or shared atomic counter in that timed packet loop. The full-pipeline mode remains separate and includes generation, dispatch, bounded queues and aggregation. A queue-oriented `PacketBatchSource` boundary admits future PCAP, AF_XDP and DPDK adapters without claiming those adapters exist.

Affinity plans are validated against the effective process cpuset. Automatic placement separates one producer from all workers; explicit and disabled modes are supported, and effective worker masks are reported. Performance execution additionally requires a fresh receipt from the 15-minute safety observer. S2.1 performance was deferred because stability was not demonstrated.

## S2 measured boundary

The best accepted three-run median was 3.175694 Gbit/s Ethernet-wire equivalent (2 workers, batch 256, 1500-byte frames), with zero drops and zero integrity/length errors. Scaling efficiency at that profile was 52.94% for two workers relative to one worker, then decreased for three and four workers. This demonstrates a producer/generation bottleneck rather than linear worker scaling. Separate generator-only and pre-generated profiling modes are implemented but were not executed after an external OTV lifecycle change triggered the safety stop.

## S3 offline decode path

The functional correctness path is independent from the performance engine:

```text
read-only PCAP/PCAPNG -> exact PacketMetadata -> Ethernet/SLL/VLAN/IP
       |                                      |
       | UDP 8805 -> decoder-pfcp             | SCTP DATA/reassembly -> PPID 60 -> decoder-ngap
       | UDP 2152 -> decoder-gtpu             |
       +----------------> plugin-runtime contract ----------------+
                                                                  |
                                           ordered provenance-complete JSONL
```

The core CLI routes by transport port or SCTP PPID and contains no protocol decoding. Decoder crates report version/capabilities and preserve unknown values by length and SHA-256. Endpoint roles are explicit inputs; direction is never guessed. Subscriber-sensitive values are pseudonymized and NAS protection is respected.

Validation uses immutable capture IDs and independent TShark output. Across the selected set, all 37 NGAP, 52 PFCP and 10 GTP-U messages align at packet/header level. Full nested NGAP/PFCP IE parity is not claimed: S3 is partial until the recorded opaque values gain schema-complete typed support and operational N3 contains traffic.

## S3.2.1 decoder and evidence boundary

NGAP 0.2.0 decodes observed Release-17.3 envelope, UE IDs, PLMN/location, cause, security capabilities, S-NSSAI and PDU-session identifiers. Protected NAS is never decrypted, and complex resource-transfer/list encodings that are not schema-complete remain PARTIAL with a raw SHA-256 reference. PFCP 0.2.0 recursively decodes every observed grouped/leaf IE in the selected data, validates typed lengths and preserves unknown/vendor IEs as UNSUPPORTED.

Schema 1.2.0 adds stable `probe_id`, `capture_point_id`, and evidence references classified EXACT, STRONG, POSSIBLE or UNKNOWN. At the S3.2.1 boundary the operational N3 captures were empty. S3.2.2 subsequently certified `OIRAN_5G_PDU_SESSION_DATA_V1` with ten bounded GTP-U packets and paired N2/N4 tunnel evidence; S3.3 consumes that immutable dataset.

## S3.3 E2E reconstruction and presentation

```text
certified JSONL + scenario manifest
        |
        v
session-engine ── UE/PDU/PFCP/tunnels + exhaustive accounting
        |
        v
correlation-engine ── versioned edges + packet evidence
        |
        v
callflow-schema 1.0 ── canonical JSON
        |
        +── callflow-renderer ── standalone interactive HTML
```

The session engine selects the UE context anchored by observed PDU Session Resource Setup identifiers, joins PFCP establishment/modification by sequence and F-SEID continuity, and admits GTP-U only when TEID plus a PFCP tunnel endpoint match. Heartbeats and unrelated deletion/release contexts remain background records rather than being forced into the UE session.

N2 nested transfer TEIDs are still partial in the native NGAP decoder. Therefore N2↔N4 remains STRONG and explicitly cites the certified TShark/manifest bridge. N4↔N3 requires direct TEID and endpoint equality and is EXACT. The renderer consumes only the canonical model; it performs no correlation. Decoded values are inserted with DOM `textContent`, embedded JSON escapes script-significant characters, and no CDN or remote code is used.

# OIRAN V2 Web Integration

The V2 browser remains a presentation client for the native Rust pipeline. `oiran-api` loads only allowlisted workspace artifacts, exposes API v2 schemas, sanitizes filesystem paths, and serves the static React build on the same origin. Decoding, session reconstruction and correlation remain in their independently versioned Rust crates.

The live path is intentionally fail-closed: capture validation reports the measured disk decision plus explicit backend and authorization blockers; Start never invokes shell commands or capture processes. Historical N2/N3/N4 events are exposed separately from live metrics, which remain null when no telemetry producer exists.

## V2.2 investigation context and Call Flow presentation

The Web client carries a canonical investigation context (`capture_id`, `dataset_id`, `session_id`, `probe_id`, technology and `event_id`) in the URL. The API resolves capture ownership through `/api/v1/captures/{id}/context`; the client never substitutes the historical certified dataset when the selected capture has no dataset or no reconstructed session.

The Call Flow renderer remains a presentation layer over the canonical S3.3 model. Participants are derived from event endpoints and the canonical participant list. SVG lifelines and directional arrows use only observed source/destination evidence. Unknown direction is rendered explicitly, and GTP-U is labelled as packet data flow. Decoder output, correlation confidence and packet provenance pass through unchanged.

