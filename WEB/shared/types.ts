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

// Logical telecom plane descriptors used by both apps.
export const TELECOM_PLANES = [
  { id: 'N2', label: 'NG-C', protocol: 'NGAP / SCTP', family: 'control' },
  { id: 'SBI', label: 'SBI', protocol: 'HTTP/2', family: 'control' },
  { id: 'N4', label: 'N4', protocol: 'PFCP / UDP', family: 'control' },
  { id: 'N3', label: 'NG-U', protocol: 'GTP-U / UDP', family: 'user' },
] as const;

export type TelecomPlaneId = (typeof TELECOM_PLANES)[number]['id'];
