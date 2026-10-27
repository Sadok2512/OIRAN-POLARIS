// Re-exported telecom types derived from OIRAN/apps/web/src/types/api.ts.
// Keeping a local copy avoids coupling to the OIRAN web workspace while
// preserving an identical shape with the backend contract.

export type Confidence = 'EXACT' | 'STRONG' | 'POSSIBLE' | 'UNKNOWN';

export type EvidenceLevel = 'DISCOVERED' | 'CONFIGURED' | 'INFERRED' | 'UNKNOWN';

export type CaptureState =
  | 'READY'
  | 'STARTING'
  | 'CAPTURING'
  | 'STOPPING'
  | 'COMPLETED'
  | 'COMPLETED_EMPTY'
  | 'FAILED';

export interface ApiEnvelope<T> {
  data: T;
  meta: {
    api_version?: string;
    page?: number;
    page_size?: number;
    total?: number;
    total_pages?: number;
  };
}

export interface AuthState {
  authenticated: boolean;
  role: string;
  permissions: string[];
  capture_control: boolean;
  capture_execution_enabled: boolean;
  reason: string;
}

export interface Probe {
  probe_id: string;
  name: string;
  host: string;
  probe_type: string;
  version: string;
  health: string;
  online: boolean;
  connected_interfaces: string[];
  capture_state: string;
  last_heartbeat?: string | null;
  last_heartbeat_epoch_s?: number;
  packet_rate_pps: number | null;
  decode_rate_eps: number | null;
  packet_drops: number | null;
  cpu_usage_percent: number | null;
  memory_usage_bytes: number | null;
  disk_usage_percent: number | null;
  historical_packet_count: number;
  telemetry_status: string;
  distributed: boolean;
  capture_control_available?: boolean;
}

export interface CaptureInterface {
  interface: string;
  protocol: string;
  capture_point: string;
  source: string;
  status: string;
  device?: string;
  reason?: string | null;
  packet_count: number | null;
  file_size: number | null;
  capture_start: string | null;
  capture_end: string | null;
  live_capture_available: boolean;
}

export interface CapturePlaneStatus {
  plane: string;
  interface: string;
  capture_job_id: string;
  start_timestamp?: number | null;
  end_timestamp?: number | null;
  packet_count: number;
  byte_count: number;
  drop_count?: number | null;
  storage_bytes: number;
  decode_status: string;
  dataset_id?: string | null;
  source_sha256: string[];
  error?: string | null;
}

export interface Capture {
  capture_id: string;
  name: string;
  interface?: string;
  interfaces?: string[];
  protocol?: string;
  checksum_sha256?: string;
  packet_count?: number;
  decoded_messages?: number;
  size_bytes?: number;
  source?: string;
  status?: string;
  state?: CaptureState | string;
  error?: string | null;
  metrics?: {
    packets_received: number;
    bytes_received: number;
    packets_per_second: number;
    bits_per_second: number;
    decoded_events: number;
    decode_errors: number;
    packet_drops: number | null;
    storage_bytes: number;
  };
  dataset_id?: string | null;
  dataset_state?: string;
  dataset_kind?: 'HISTORICAL' | 'CAPTURED_LIVE' | 'RECOVERED';
  session_ids?: string[];
  probe_id?: string;
  technology?: string;
  capture_group_id?: string | null;
  scenario_id?: string | null;
  planes?: CapturePlaneStatus[];
}

export interface DiskSafety {
  filesystem: {
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    usage_percent: number;
    total_inodes: number;
    available_inodes: number;
  } | null;
  decision: {
    state: string;
    new_capture_allowed: boolean;
    active_capture_must_finalize: boolean;
    read_only_analysis_allowed: boolean;
    reason: string;
  };
  budget: {
    allowed: boolean;
    requested_bytes: number;
    maximum_allowed_bytes: number;
    headroom_to_stop_bytes: number;
    reserved_bytes: number;
    reason: string;
  };
  rotation: {
    max_file_bytes: number;
    max_files: number;
    maximum_job_bytes: number;
    max_job_seconds: number;
  };
  policy: {
    information_percent: number;
    warning_percent: number;
    stop_percent: number;
    hard_limit_percent: number;
    polling_interval_ms: number;
  };
  capture_job: { state: string; active: boolean; writes_enabled: boolean };
  monitoring: {
    poll_interval_ms: number;
    event_driven_limit: string;
    failure_mode: string;
  };
}

export interface Metrics {
  observed_at_epoch_s: number;
  mode: string;
  packet_rate_pps: number | null;
  bitrate_bps: number | null;
  decode_rate_eps: number | null;
  packet_drops: number | null;
  capture_queue_utilization_percent: number | null;
  active_captures: number;
  active_sessions: number;
  historical_sessions: number;
  historical_events: number;
  decode_errors: number;
  cpu: {
    usage_percent: number | null;
    load_one: number | null;
    logical_cpus: number;
  };
  memory: {
    total_bytes: number | null;
    available_bytes: number | null;
    used_bytes: number | null;
  };
  disk: {
    usage_percent: number;
    available_bytes: number;
    available_inodes: number;
  } | null;
  interfaces: {
    interface: string;
    state: string;
    packet_rate_pps: number | null;
  }[];
}

export interface CaptureRequest {
  probe_id: string;
  name: string;
  interfaces: string[];
  duration_seconds: number;
  max_bytes: number;
  rotation_files: number;
  profile: string;
  optional_filter: null;
  capture_group_id?: string | null;
  scenario_id?: string | null;
}

// ---------------------------------------------------------------------------
// OIRAN v1 Analyzer contract — Dataset / UE context / Session / Call Flow /
// Correlation edges / Packet. Mirrors OIRAN/apps/web/src/types/api.ts so the
// Analyzer app does not reach into the legacy workspace.
// ---------------------------------------------------------------------------

export type Association = 'SESSION' | 'BACKGROUND' | 'UNMATCHED';

export type DecodeStatus =
  | 'DECODED'
  | 'PARTIAL'
  | 'UNSUPPORTED'
  | 'MALFORMED'
  | 'ENCRYPTED_OR_PROTECTED';

export type DatasetKind = 'HISTORICAL' | 'CAPTURED_LIVE' | 'RECOVERED';

export interface Dataset {
  dataset_id: string;
  display_name: string;
  dataset_kind: DatasetKind;
  source: string;
  technology: string;
  ingestion_status: string;
  ingestion_generation: number;
  session_count: number;
  ue_context_count: number | null;
  pdu_session_count?: number;
  event_count: number;
  normalized_event_count?: number;
  packet_count?: number;
  background_event_count: number | null;
  unmatched_event_count: number | null;
  duplicate_observation_count: number | null;
  error_count: number;
  read_only: boolean;
  captures: Capture[];
  capture_id?: string;
  session_ids?: string[];
  capture_start_timestamp?: number | null;
  capture_end_timestamp?: number | null;
  accounting_status?: string;
  decoder_versions: Record<string, string>;
}

export interface UeContext {
  ue_context_id: string;
  ue_pseudonym: string;
  ran_ue_ngap_id?: string;
  amf_ue_ngap_id?: string;
  ran_endpoint: string;
  amf_endpoint: string;
  association_id: string;
  lifecycle_generation: number;
  state: string;
  first_timestamp_ns: string;
  last_timestamp_ns: string;
  event_count: number;
  session_count: number;
  /** Set on live UE contexts (`live_ue_summary` in the backend). */
  dataset_id?: string;
  dataset_kind?: DatasetKind;
}

/**
 * Runtime evidence attached to a live session (`live_session_summary` on
 * the OIRAN API). The backend derives these fields from the controller
 * runtime — they are the only *proven* source for UE IP, UL/DL direction
 * and per-TEID observation. Treat them as backend-reported; never
 * substitute values when absent.
 */
export interface SessionRuntimeEvidence {
  observed_epoch_ms?: number | null;
  provenance?: string | null;
  correlation_status?: string | null;
  ue_ip?: string | null;
  teids?: string[] | null;
  directions?: Record<string, string> | null;
}

export interface Session {
  session_id: string;
  /** `dataset_id` may be null when the backend manifest did not expose a
   * `scenario_id` (historical dataset without a tagged scenario). */
  dataset_id: string | null;
  dataset_kind?: DatasetKind | string;
  ue_context_id: string;
  technology: string;
  ue_pseudonym: string;
  pdu_session_id: string;
  serving_node?: string;
  procedure: string;
  start_timestamp: string;
  end_timestamp: string;
  duration_ns: string;
  interfaces: string[];
  message_count: number;
  source_event_count: number;
  background_event_count: number;
  correlation_status: Confidence;
  decode_completeness: {
    decoded: number;
    partial: number;
    unresolved_fields: number;
  };
  state: string;
  /** Present on live sessions only. */
  runtime_evidence?: SessionRuntimeEvidence | null;
}

export interface PacketReference {
  source_file: string;
  packet_number: number;
  byte_offset: number;
  interface_id: number;
  captured_length: number;
  original_length: number;
}

export interface InformationElement {
  id: number | null;
  name: string;
  length: number;
  value: string | null;
  raw_sha256: string | null;
  status: DecodeStatus;
  children?: InformationElement[];
  byte_start?: number;
  byte_end?: number;
}

export interface CallFlowEvent {
  event_id: string;
  timestamp: string;
  timestamp_ns: string;
  interface: string;
  protocol: string;
  message_name: string;
  source_participant: string;
  destination_participant: string;
  direction: string;
  /**
   * The backend declares this as `Value` (serde_json::Value) so callers
   * must defensively treat it as a wide union. In practice OIRAN emits
   * `InformationElement[]`; absent/null/object shapes are tolerated.
   */
  decoded_ie_tree: InformationElement[] | Record<string, unknown> | null;
  decoding_status: DecodeStatus;
  semantic_status: 'NORMAL' | 'SUCCESS' | 'FAILURE' | 'PARTIAL';
  association: Association;
  procedure_group: string;
  packet_references: PacketReference[];
  capture_id: string;
  decoder_name: string;
  decoder_version: string;
  raw_payload_reference: string;
  errors: string[];
}

/**
 * Shape returned by `GET /sessions/:id/correlations`:
 *   `{ "status": <correlation_status>, "edges": <CorrelationEdge[]> }`
 * where `status` is the same `BTreeMap<String, String>` found on
 * `CallFlow.correlation_status`. The envelope `data` is this object, NOT
 * the plain `CorrelationEdge[]`.
 */
export interface SessionCorrelationsResponse {
  status: Record<string, string>;
  edges: CorrelationEdge[];
}

export type CorrelationEvidenceType =
  | 'EXACT_TUNNEL_MATCH'
  | 'EXACT_CONTEXT_MATCH'
  | 'STRONG_CONTEXT_ASSOCIATION'
  | 'POSSIBLE_ASSOCIATION'
  | 'UNKNOWN';

export interface CorrelationEdge {
  edge_id: string;
  source_event_id: string;
  target_event_id: string;
  source_interface: string;
  target_interface: string;
  matching_identifiers: string[];
  rule_id: string;
  rule_version: string;
  evidence_description: string;
  packet_references: PacketReference[];
  confidence: Confidence;
  evidence_type?: CorrelationEvidenceType;
  scope?: string;
  limitations?: string[];
}

export interface CallFlow {
  callflow_id: string;
  session_id: string;
  technology: string;
  start_timestamp: string;
  end_timestamp: string;
  participants: { id: string; role: string; addresses: string[] }[];
  interfaces: string[];
  procedures: { id: string; name: string; event_ids: string[]; status: string }[];
  events: CallFlowEvent[];
  correlation_edges: CorrelationEdge[];
  correlation_status: {
    N2_N4: Confidence;
    N2_SBI?: Confidence;
    SBI_N4?: Confidence;
    N4_N3: Confidence;
    E2E: Confidence;
  };
  decoder_versions: Record<string, string>;
  schema_version: string;
  capture_references: string[];
  accounting: {
    source_events: number;
    session_events: number;
    background_events: number;
    unmatched_events: number;
    duplicate_events: number;
    extra_events: number;
  };
  unresolved_fields: number;
}

export interface Packet {
  packet_id: string;
  capture_id: string;
  event_id: string;
  timestamp: string;
  timestamp_ns: string;
  interface: string;
  protocol: string;
  source: string;
  destination: string;
  direction: string;
  message_name: string;
  captured_length: number;
  original_length: number;
  byte_offset: number;
  packet_number: number;
  source_file: string;
  decode_status: DecodeStatus;
  decoder_name: string;
  decoder_version: string;
  raw_payload_reference: string;
  information_elements: InformationElement[];
  raw_bytes: string;
}

export interface VersionInfo {
  platform_core: string;
  backend_api: string;
  web_frontend: string;
  event_schema: string;
  callflow_schema: string;
  session_engine: string;
  correlation_engine: string;
  dataset_registry?: string;
  disk_safety?: string;
  decoders: Record<string, string>;
}

// Logical telecom plane descriptors used by both apps.
export const TELECOM_PLANES = [
  { id: 'N2', label: 'NG-C', protocol: 'NGAP / SCTP', family: 'control' },
  { id: 'SBI', label: 'SBI', protocol: 'HTTP/2', family: 'control' },
  { id: 'N4', label: 'N4', protocol: 'PFCP / UDP', family: 'control' },
  { id: 'N3', label: 'NG-U', protocol: 'GTP-U / UDP', family: 'user' },
] as const;

export type TelecomPlaneId = (typeof TELECOM_PLANES)[number]['id'];
