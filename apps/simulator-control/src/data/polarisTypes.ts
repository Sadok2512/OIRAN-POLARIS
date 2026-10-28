// POLARIS v1 control-plane contract types, mirrored from
// POLARIS_CONTROL/apps/web/src/api.ts and the handler surface in
// POLARIS_CONTROL/apps/api/src/lib.rs. Keep this file focused on the
// endpoints the Simulator Control app consumes.

export interface PolarisAuthState {
  authenticated: boolean;
  username: string | null;
  role: 'viewer' | 'operator' | 'administrator';
  can_start: boolean;
  can_manage_permissions: boolean;
  csrf_token?: string | null;
}

export interface Technology {
  id: string;
  name: string;
  simulator: string;
  available: boolean;
  certified: boolean;
  node_label: string;
  reason?: string;
}

export interface ServiceCapability {
  id: string;
  name: string;
  supported: boolean;
  reason?: string;
}

export interface Capabilities {
  live_control: boolean;
  approval_state: string;
  max_ues: number;
  max_ues_live_certified?: number;
  max_nodes: number;
  max_nodes_live_certified?: number;
  registration_modes: string[];
  traffic_protocols: string[];
  approved_destinations: string[];
  profiles: {
    id: string;
    name: string;
    available: boolean;
    source: string;
    subscription_verified?: boolean;
  }[];
  technologies: Technology[];
  services: ServiceCapability[];
  /**
   * 0.5.2 — Wire step types the backend is willing to execute, as
   * published by `GET /capabilities`. The field stays optional: when the
   * backend omits it, we fall back to the six-type polaris-control-api
   * 0.9.0 whitelist (`ue_start`, `ue_stop`, `pdu_establish`, `pdu_release`,
   * `udp_traffic`, `wait`). Any kind flagged `backendCertified: false` in
   * `STEP_METADATA` becomes clickable only when it appears in this list.
   */
  scenario_step_kinds?: string[];
  /** API 0.14.0+ canonical name. */
  executable_scenario_step_types?: string[];
  unavailable_scenario_step_types?: Array<{
    type: string;
    http_status: number;
    reason: string;
  }>;
}

/**
 * Backend scenario catalog item. These are the CERTIFIED scenario
 * profiles that `/scenarios/validate` and `/scenarios/start` accept.
 * User-defined scenarios composed in the frontend builder are mapped
 * onto one of these certified profiles when their shape matches.
 */
export interface ScenarioCapabilityItem {
  id: string;
  version: string;
  certified: boolean;
  enabled: boolean;
  technology: string;
  simulator: string;
  existing_ue_only: boolean;
  creates_ue: boolean;
  controls_gnb: boolean;
  protocol: string;
  datagrams: number;
  destination: string;
  destination_port: number;
}

export interface ScenarioCapabilities {
  items: ScenarioCapabilityItem[];
  execution_status: string;
  reason: string;
  role: string;
}

export interface NodeItem {
  id: string;
  name: string;
  technology: string;
  simulator: string;
  plmn: string;
  cell_id: string;
  link_ip: string;
  n2_endpoint: string | null;
  n3_endpoint: string | null;
  process_state: string;
  health: string;
  configured: boolean;
  controller_owned: boolean;
  uptime_seconds: number | null;
  actions: { start: boolean; stop: boolean; reason: string };
}

export interface NodeInventory {
  items: NodeItem[];
  configured_count: number;
  running_count: number;
  observed_at_epoch_s: number;
  source: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResult {
  authenticated: true;
  username: string;
  role: 'operator' | 'administrator';
  csrf_token: string;
  expires_at_epoch_s: number;
}

export interface UeState {
  id: string;
  internal_ue_id?: string;
  profile?: string;
  profile_state?: string;
  subscription_status?: string;
  serving_node?: string;
  process_state?: string;
  registration_state: string;
  rrc_state?: string;
  pdu_session: string;
  ue_ip: string | null;
  traffic_state: string;
  uptime_seconds?: number | null;
  last_event: string | null;
  controller_owned: boolean;
  traffic_target_verified?: boolean;
  actions?: {
    start: boolean;
    stop: boolean;
    pdu_start: boolean;
    pdu_stop: boolean;
    traffic: boolean;
    provisioning_review?: boolean;
    reason: string;
  };
}

export interface UeProfile {
  id: string;
  pseudonym?: string;
  profile: string;
  serving_gnb?: string;
  simulator: string;
  state: string;
  configured?: boolean;
  controller_owned: boolean;
  subscription_status?: string;
  actions?: { start: boolean; stop: boolean; traffic: boolean; reason: string };
}

export interface UeReconciliation {
  operation_id: string | null;
  desired_count: number;
  state: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  started_at_epoch_s: number | null;
  completed_at_epoch_s: number | null;
  started: string[];
  stopped: string[];
  failures: [string, string][];
}

export interface UeInventory {
  items: UeState[];
  configured_profiles: UeProfile[];
  configured_count: number;
  planned_count?: number;
  max_configurable?: number;
  active_count: number;
  registered_count: number;
  pdu_session_count?: number;
  observed_at_epoch_s?: number;
  source: string;
  // polaris-control-api 0.9.0 adds these two fields to /ues. Typed as
  // optional so older backends keep deserializing; no UI consumption yet.
  cache_version?: string;
  cache_fresh?: boolean;
}

export interface ScenarioState {
  scenario_id: string;
  job_id?: string;
  target_ue_id?: string;
  target_ue_pseudonym?: string;
  tun_interface?: string | null;
  technology: string;
  simulator: string;
  started_at: string;
  started_at_epoch_s: number;
  ended_at_epoch_s: number | null;
  duration_seconds: number;
  configured_ues: number;
  registered_ues: number;
  active_pdu_sessions: number;
  traffic_state: string;
  packets_requested: number;
  packets_sent: number | null;
  terminal_result: string | null;
  cpu: string;
  memory: string;
  state: string;
  controller_owned: boolean;
}

export interface ScenarioRuntime {
  active_job: ScenarioState | null;
  latest_terminal_job: ScenarioState | null;
  active_count: number;
  history_count: number;
  observed_at_epoch_s: number;
  source: string;
}

export interface ScenarioList {
  items: ScenarioState[];
  total: number;
  source: string;
  live_execution: boolean;
  note?: string;
}

export interface TrafficState {
  state: string;
  packets_requested: number;
  packets_sent: number | null;
  packets_received: number | null;
  bytes: number | null;
  current_rate_pps?: number | null;
  accounting_source: string;
  target_ue_id?: string | null;
  target_ue_pseudonym?: string | null;
  tun_interface?: string | null;
  last_result: ScenarioState | null;
  approved_destinations: string[];
}

export interface ValidationResult {
  valid: boolean;
  execution?: string;
  next?: string;
  scenario_type?: string;
  error?: string;
}

export interface LabConfiguration {
  ue_count: number;
  desired_ue_count: number;
  gnb_count: number;
  max_ues: number;
  max_gnbs: number;
  max_ues_live_certified: number;
  max_gnbs_live_certified: number;
  missing_subscriber_profiles: number;
  updated_at_epoch_s: number;
  updated_by: string;
  observed_controller_running: number;
  observed_total_running: number;
  reconciliation: UeReconciliation;
  execution_started: boolean;
}

export interface SystemHealth {
  cpu?: { usage_percent: number | null; idle_percent?: number | null; logical_cpus: number };
  memory: { total_bytes: number | null; available_bytes: number | null; used_bytes: number | null };
  disk: {
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    usage_percent: number;
  } | null;
  decision: { state: string; writes_allowed: boolean; reason: string; maximum_budget_bytes: number };
  load_average: string;
  uptime_seconds: number | null;
  observed_at_epoch_s?: number;
}
