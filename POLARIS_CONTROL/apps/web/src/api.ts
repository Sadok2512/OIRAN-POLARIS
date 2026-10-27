export type Disk = { total_bytes: number; used_bytes: number; available_bytes: number; usage_percent: number; available_inodes: number };
export type CpuSafety = { decision_id: string; decision_timestamp_epoch_ms: number; state: string; classification: string; blocking: boolean; reason: string; trigger: { metric: string; observed_value: number | null; threshold: number | null; comparator: string; consecutive_samples: number; required_samples: number } | null; sample_window_ms: number; ready: boolean; telemetry_fresh: boolean; telemetry_age_ms: number; observed_at_epoch_ms: number; valid_samples: number; consecutive_breaches: number; consecutive_recoveries: number; host: { valid: boolean; source: string; observed_at_epoch_ms: number; sample_duration_ms: number; logical_cpus: number; usage_percent: number | null; idle_percent: number | null; iowait_percent: number | null; steal_percent: number | null }; pressure: { valid: boolean; source: string; some_avg10: number | null; some_avg60: number | null; some_avg300: number | null; full_avg10: number | null; full_avg60: number | null; full_avg300: number | null; some_stall_delta_usec: number | null }; api_cgroup: { valid: boolean; version: string; source: string; effective_capacity_cpus: number | null; effective_cpuset_cpus: number | null; nr_periods_delta: number | null; nr_throttled_delta: number | null; throttled_usec_delta: number | null; throttled_period_ratio: number | null }; ue_target_capacity_cpus: number; oiran_capture_capacity_cpus: number | null; available_host_cpus: number | null; shared_headroom_cpus: number; budget: { id: string; cpu_cpus: number; ram_bytes: number; storage_bytes: number; target_capacity_cpus: number; concurrent_reservations: number } };
export type Health = { disk: Disk | null; decision: { state: string; writes_allowed: boolean; reason: string; maximum_budget_bytes: number }; memory: { total_bytes: number | null; available_bytes: number | null; used_bytes: number | null }; cpu?: { usage_percent: number | null; idle_percent?: number | null; steal_percent?: number | null; iowait_percent?: number | null; logical_cpus: number; sample_duration_ms?: number }; cpu_safety?: CpuSafety; load_average: string; uptime_seconds: number | null; observed_at_epoch_s?: number; poll_interval_ms: number; capture_limits: { max_file_bytes: number; max_files: number; max_duration_seconds: number; max_concurrent_jobs: number }; automatic_cleanup: boolean };
export type Technology = { id: string; name: string; simulator: string; available: boolean; certified: boolean; node_label: string; reason?: string };
export type ServiceCapability = { id: string; name: string; supported: boolean; reason?: string };
export type Capabilities = { live_control: boolean; approval_state: string; max_ues: number; max_ues_live_certified?: number; max_nodes: number; max_nodes_live_certified?: number; registration_modes: string[]; traffic_protocols: string[]; approved_destinations: string[]; profiles: { id: string; name: string; available: boolean; source: string; subscription_verified?: boolean }[]; technologies: Technology[]; services: ServiceCapability[] };
export type AuthState = { authenticated: boolean; username: string | null; role: 'viewer' | 'operator' | 'administrator'; can_start: boolean; can_manage_permissions: boolean; csrf_token?: string | null };
export type LoginResult = { authenticated: true; username: string; role: 'operator' | 'administrator'; csrf_token: string; expires_at_epoch_s: number };
export type ScenarioCapabilities = { items: { id: string; version: string; certified: boolean; enabled: boolean; technology: string; simulator: string; existing_ue_only: boolean; creates_ue: boolean; controls_gnb: boolean; protocol: string; datagrams: number; destination: string; destination_port: number }[]; execution_status: string; reason: string; role: string };
export type NodeItem = { id: string; name: string; technology: string; simulator: string; plmn: string; cell_id: string; link_ip: string; n2_endpoint: string | null; n3_endpoint: string | null; process_state: string; health: string; configured: boolean; controller_owned: boolean; uptime_seconds: number | null; actions: { start: boolean; stop: boolean; reason: string } };
export type NodeInventory = { items: NodeItem[]; configured_count: number; running_count: number; observed_at_epoch_s: number; source: string };
export type ProcessState = { process_state: string; health: string; observed: boolean };
export type RuntimeState = { source: string; configuration_changed: boolean; observed: { ueransim_ue_profile: boolean; ueransim_profile: string; open5gs: ProcessState; ueransim_gnb: ProcessState; ueransim_ue: ProcessState; srsran_enb: ProcessState; srsran_ue: ProcessState; lte_attach: string; controller_owned_active_jobs: number } };
export type UeInventory = { items: UeState[]; configured_profiles: UeProfile[]; configured_count: number; planned_count?: number; max_configurable?: number; active_count: number; registered_count: number; pdu_session_count?: number; observed_at_epoch_s?: number; source: string };
export type UeProfile = { id: string; pseudonym?: string; profile: string; serving_gnb?: string; simulator: string; state: string; configured?: boolean; controller_owned: boolean; subscription_status?: string; actions?: { start: boolean; stop: boolean; traffic: boolean; reason: string } };
export type UeReconciliation = { operation_id: string | null; desired_count: number; state: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED'; started_at_epoch_s: number | null; completed_at_epoch_s: number | null; started: string[]; stopped: string[]; failures: [string,string][] };
export type LabConfiguration = { ue_count: number; desired_ue_count: number; gnb_count: number; max_ues: number; max_gnbs: number; max_ues_live_certified: number; max_gnbs_live_certified: number; missing_subscriber_profiles: number; updated_at_epoch_s: number; updated_by: string; observed_controller_running: number; observed_total_running: number; reconciliation: UeReconciliation; execution_started: boolean };
export type UeState = { id: string; internal_ue_id?: string; profile?: string; profile_state?: string; subscription_status?: string; serving_node?: string; process_state?: string; registration_state: string; rrc_state?: string; pdu_session: string; ue_ip: string | null; traffic_state: string; uptime_seconds?: number | null; last_event: string | null; controller_owned: boolean; traffic_target_verified?: boolean; actions?: { start: boolean; stop: boolean; pdu_start: boolean; pdu_stop: boolean; traffic: boolean; provisioning_review?: boolean; reason: string } };
export type ScenarioList = { items: ScenarioState[]; total: number; source: string; live_execution: boolean; note?: string };
export type ScenarioState = { scenario_id: string; job_id?: string; target_ue_id?: string; target_ue_pseudonym?: string; tun_interface?: string | null; technology: string; simulator: string; started_at: string; started_at_epoch_s: number; ended_at_epoch_s: number | null; duration_seconds: number; configured_ues: number; registered_ues: number; active_pdu_sessions: number; traffic_state: string; packets_requested: number; packets_sent: number | null; terminal_result: string | null; cpu: string; memory: string; state: string; controller_owned: boolean };
export type ScenarioRuntime = { active_job: ScenarioState | null; latest_terminal_job: ScenarioState | null; active_count: number; history_count: number; observed_at_epoch_s: number; source: string };
export type TrafficState = { state: string; packets_requested: number; packets_sent: number | null; packets_received: number | null; bytes: number | null; current_rate_pps?: number | null; accounting_source: string; target_ue_id?: string | null; target_ue_pseudonym?: string | null; tun_interface?: string | null; last_result: ScenarioState | null; approved_destinations: string[] };
export type ValidationResult = { valid: boolean; execution?: string; next?: string; scenario_type?: string; error?: string };

export const eligibleTrafficTargets = (items: UeState[]) => items.filter(item =>
  item.controller_owned &&
  item.traffic_target_verified === true &&
  item.actions?.traffic === true &&
  item.process_state === 'RUNNING' &&
  item.registration_state === 'REGISTERED' &&
  item.pdu_session === 'ACTIVE'
);

export const targetedTrafficStartRequest = (scenarioId: string, targetUeId: string) => ({
  scenario_id: scenarioId,
  scenario_type: 'bounded-controller-ue-udp-v1',
  target_ue_id: targetUeId,
});

const csrfKey = 'polaris-csrf-token';
export const setCsrfToken = (value: string) => value ? sessionStorage.setItem(csrfKey, value) : sessionStorage.removeItem(csrfKey);

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const csrf = sessionStorage.getItem(csrfKey) ?? '';
  const response = await fetch('/api/v1' + path, { ...init, credentials: 'same-origin', headers: { 'content-type': 'application/json', ...(!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrf ? { 'x-csrf-token': csrf } : {}), ...init?.headers } });
  const body = await response.json().catch(() => ({ error: 'INVALID_RESPONSE' }));
  if (body && typeof body === 'object' && 'csrf_token' in body && typeof body.csrf_token === 'string' && body.csrf_token) setCsrfToken(body.csrf_token);
  if (!response.ok) throw new Error(typeof body.error === 'string' ? body.error : `API ${response.status}`);
  return body as T;
}
