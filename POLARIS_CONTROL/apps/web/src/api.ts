export type Disk = { total_bytes: number; used_bytes: number; available_bytes: number; usage_percent: number; available_inodes: number };
export type CpuSafety = { decision_id: string; decision_timestamp_epoch_ms: number; state: string; classification: string; blocking: boolean; reason: string; trigger: { metric: string; observed_value: number | null; threshold: number | null; comparator: string; consecutive_samples: number; required_samples: number } | null; sample_window_ms: number; ready: boolean; telemetry_fresh: boolean; telemetry_age_ms: number; observed_at_epoch_ms: number; valid_samples: number; consecutive_breaches: number; consecutive_recoveries: number; host: { valid: boolean; source: string; observed_at_epoch_ms: number; sample_duration_ms: number; logical_cpus: number; usage_percent: number | null; idle_percent: number | null; iowait_percent: number | null; steal_percent: number | null }; pressure: { valid: boolean; source: string; some_avg10: number | null; some_avg60: number | null; some_avg300: number | null; full_avg10: number | null; full_avg60: number | null; full_avg300: number | null; some_stall_delta_usec: number | null }; api_cgroup: { valid: boolean; version: string; source: string; effective_capacity_cpus: number | null; effective_cpuset_cpus: number | null; nr_periods_delta: number | null; nr_throttled_delta: number | null; throttled_usec_delta: number | null; throttled_period_ratio: number | null }; ue_target_capacity_cpus: number; oiran_capture_capacity_cpus: number | null; available_host_cpus: number | null; shared_headroom_cpus: number; budget: { id: string; cpu_cpus: number; ram_bytes: number; storage_bytes: number; target_capacity_cpus: number; concurrent_reservations: number } };
export type Health = { disk: Disk | null; disk_measurement_error?: string | null; decision: { state: string; writes_allowed: boolean; reason: string; maximum_budget_bytes: number }; memory: { total_bytes: number | null; available_bytes: number | null; used_bytes: number | null }; cpu?: { usage_percent: number | null; idle_percent?: number | null; steal_percent?: number | null; iowait_percent?: number | null; logical_cpus: number; sample_duration_ms?: number }; cpu_safety?: CpuSafety; load_average: string; uptime_seconds: number | null; observed_at_epoch_s?: number; poll_interval_ms: number; capture_limits: { max_file_bytes: number; max_files: number; max_duration_seconds: number; max_concurrent_jobs: number }; automatic_cleanup: boolean };
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
export type UeProfile = { id: string; pseudonym?: string; profile: string; serving_gnb?: string; simulator: string; state: string; configured?: boolean; controller_owned: boolean; subscription_status?: string; subscriber_identity?:string; scenario_id?:string|null; actions?: { start: boolean; stop: boolean; traffic: boolean; reason: string } };
export type UeReconciliation = { operation_id: string | null; desired_count: number; state: 'IDLE' | 'RUNNING' | 'COMPLETED' | 'FAILED'; started_at_epoch_s: number | null; completed_at_epoch_s: number | null; started: string[]; stopped: string[]; failures: [string,string][] };
export type LabConfiguration = { ue_count: number; desired_ue_count: number; gnb_count: number; max_ues: number; max_gnbs: number; max_ues_live_certified: number; max_gnbs_live_certified: number; missing_subscriber_profiles: number; updated_at_epoch_s: number; updated_by: string; observed_controller_running: number; observed_total_running: number; reconciliation: UeReconciliation; execution_started: boolean };
export type UeState = { id: string; internal_ue_id?: string; profile?: string; profile_state?: string; subscription_status?: string; subscriber_identity?:string; scenario_id?:string|null; serving_node?: string; process_state?: string; registration_state: string; rrc_state?: string; pdu_session: string; ue_ip: string | null; traffic_state: string; uptime_seconds?: number | null; last_event: string | null; controller_owned: boolean; traffic_target_verified?: boolean; actions?: { authorize?:boolean; start: boolean; start_reason?:string; stop: boolean; stop_reason?:string; pdu_start: boolean; pdu_stop: boolean; traffic: boolean; provisioning_review?: boolean; reason: string } };
export type ScenarioList = { items: ScenarioState[]; total: number; source: string; live_execution: boolean; note?: string; error_summary?: { error_code:string; count:number; last_occurrence_epoch_s:number; target_pseudonym:string; action:string; status:number }[] };
export type ScenarioState = { scenario_id: string; job_id?: string; target_ue_id?: string; target_ue_pseudonym?: string; tun_interface?: string | null; technology: string; simulator: string; started_at: string; started_at_epoch_s: number; ended_at_epoch_s: number | null; duration_seconds: number; configured_ues: number; registered_ues: number; active_pdu_sessions: number; traffic_state: string; packets_requested: number; packets_sent: number | null; terminal_result: string | null; error_code?: string; cause?: string; action?: string; cpu: string; memory: string; state: string; controller_owned: boolean };
export type ScenarioRuntime = { active_job: ScenarioState | null; latest_terminal_job: ScenarioState | null; active_count: number; history_count: number; observed_at_epoch_s: number; source: string };
export type TrafficState = { state: string; packets_requested: number; packets_sent: number | null; packets_received: number | null; bytes: number | null; current_rate_pps?: number | null; accounting_source: string; target_ue_id?: string | null; target_ue_pseudonym?: string | null; tun_interface?: string | null; last_result: ScenarioState | null; approved_destinations: string[] };
export type ValidationResult = { valid: boolean; execution?: string; next?: string; scenario_type?: string; error?: string };
export type ScenarioDefinition = { id:string; name:string; version:number; loop_count:number; steps:{type:string;parameters?:Record<string,unknown>}[]; created_at_epoch_s:number; updated_at_epoch_s:number; catalog_scope:'SYSTEM'|'USER'; mutable:boolean; cloneable:boolean; assigned_ues:number; backend_support:string; executable:boolean; execution_block_reason:string|null; execution_message:string|null; archived:boolean };
export type ScenarioDefinitions = { items:ScenarioDefinition[]; total:number; archived_total:number; include_archived:boolean; schema_version:number };

export const secondsToDurationMs = (seconds:number) => Math.round(seconds * 1000);
export const maskSubscriberIdentity = (value:string|undefined|null) => {
  if (!value || value === 'PROTECTED') return 'PROTECTED';
  if (/^…\d{4}$/.test(value)) return value;
  const digits = value.replace(/^imsi-/i,'');
  return /^\d{4,}$/.test(digits) ? `…${digits.slice(-4)}` : 'PROTECTED';
};
export const reportedState = (value:string|undefined|null) => value && value !== 'UNKNOWN' ? value : '-- (non rapporté par UERANSIM)';
const safeRefusalCode=/^[A-Z][A-Z0-9_]{2,63}$/;
const sensitiveDigitRun=/\d{5,}/;
const isSafeRefusalCode=(value:string)=>safeRefusalCode.test(value)&&!sensitiveDigitRun.test(value);
export const safeAuditReference = (value:string|undefined|null) => value&&isSafeRefusalCode(value.trim()) ? value.trim() : 'REFUS_MASQUE';
export const eventFailureDetail = (event:{detail?:{error?:string};error?:string}) => {
  const raw=event.detail?.error ?? event.error;
  return raw ? humanActionReason(safeAuditReference(raw)) : '';
};
export const actionReasonMessages:Readonly<Record<string,string>> = {
  ADDITIONAL_UE_LIVE_AUTHORIZATION_REQUIRED: 'Autorisation live de cet UE requise. Action : valider le contrôle de l’UE avant de le démarrer.',
  ADMINISTRATOR_PERMISSION_REQUIRED: 'Droit administrateur requis. Action : demander à un administrateur d’effectuer cette opération.',
  AUTHENTICATED_SESSION_REQUIRED: 'Session authentifiée requise. Action : se reconnecter puis relancer l’opération.',
  CERTIFIED_SCENARIO_VALIDATION_REQUIRED: 'Validation du scénario certifié requise. Action : cliquer sur Validate avant de démarrer le scénario.',
  CPU_CAPACITY_UNAVAILABLE: 'Capacité CPU indisponible. Action : attendre la fin de la charge puis relancer la validation.',
  CPU_DECISION_EVIDENCE_INVALID: 'Preuve de décision CPU invalide. Action : actualiser la santé système et demander une vérification si le défaut persiste.',
  CPU_DECISION_EVIDENCE_UNREADABLE: 'Preuve de décision CPU illisible. Action : demander à un agent lab de vérifier la télémétrie en lecture seule.',
  CPU_PSI_ABOVE_RECOVERY_THRESHOLD: 'Pression CPU trop élevée. Action : attendre le retour sous le seuil puis relancer.',
  CPU_RECOVERY_SAMPLING: 'Récupération CPU en cours de mesure. Action : attendre les échantillons requis puis relancer.',
  CPU_TELEMETRY_NOT_SAMPLED: 'Télémétrie CPU absente. Action : actualiser la santé système avant de relancer.',
  CPU_TELEMETRY_WARMING_UP: 'Télémétrie CPU en initialisation. Action : attendre la fin de l’initialisation puis relancer.',
  CSRF_TOKEN_REQUIRED: 'Jeton de session manquant. Action : recharger la page puis se reconnecter.',
  DETACH_FINAL_STATE_NOT_OBSERVED: 'État final de détachement non observé. Action : ouvrir l’activité de l’UE et vérifier son arrêt avant de relancer.',
  DL_SENDER_NOT_AVAILABLE: 'Émetteur de trafic descendant indisponible. Action : vérifier la santé du générateur de trafic avant de relancer.',
  INVALID_DESTINATION: 'Destination de trafic refusée. Action : sélectionner une destination certifiée dans Traffic Generator.',
  INVALID_GROUP_REQUEST: 'Sélection d’UE invalide. Action : sélectionner des UE distincts et autorisés puis relancer.',
  INVALID_USERNAME_OR_PASSWORD: 'Identifiants invalides. Action : vérifier le compte puis se reconnecter.',
  LAB_HEALTH_GATE_FAILED: 'Santé du lab insuffisante. Action : ouvrir System Health et fermer chaque alerte avant de relancer.',
  OPERATOR_AUTHORIZATION_REQUIRED: 'Autorisation opérateur requise. Action : se connecter avec un compte opérateur.',
  OPERATOR_PERMISSION_REQUIRED: 'Droit opérateur requis. Action : se reconnecter avec un compte autorisé.',
  OPERATOR_SESSION_REQUIRED: 'Session opérateur requise. Action : recharger la page puis se reconnecter.',
  PDU_DNN_NOT_OBSERVED: 'Session PDU du DNN non observée. Action : vérifier le DNN et l’activité de l’UE avant de relancer.',
  PDU_RUNTIME_COMMAND_UNSUPPORTED: 'Commande PDU non prise en charge. Action : choisir un scénario certifié compatible.',
  PDU_STATE_ACTIVE_NOT_OBSERVED: 'Session PDU active non observée. Action : vérifier l’établissement PDU dans l’activité UE.',
  PDU_STATE_INACTIVE_NOT_OBSERVED: 'Libération PDU non observée. Action : vérifier l’arrêt de la session avant une nouvelle exécution.',
  POLICY_PERSISTENCE_FAILED: 'Politique non enregistrée. Action : demander à un administrateur de vérifier le stockage Control.',
  SCENARIO_BACKEND_REQUIRED: 'Backend de scénario indisponible. Action : vérifier la santé de Control puis relancer.',
  SCENARIO_CONFLICT: 'Un scénario est déjà actif. Action : attendre sa fin ou arrêter le job actif.',
  SCENARIO_DEFINITION_LIVE_EXECUTION_NOT_AUTHORIZED: 'Exécution live de ce scénario non autorisée. Action : choisir un scénario certifié ou demander sa certification.',
  SCENARIO_DEFINITION_NOT_FOUND: 'Scénario introuvable. Action : actualiser la bibliothèque puis choisir un scénario existant.',
  SCENARIO_ID_REQUIRED: 'Identifiant de scénario manquant. Action : revenir à la bibliothèque et relancer depuis Run.',
  SCENARIO_JOB_NOT_FOUND: 'Job de scénario introuvable. Action : actualiser History avant de relancer une action.',
  SCENARIO_NAME_VERSION_CONFLICT: 'Nom ou version de scénario en conflit. Action : choisir un nom ou une version distincte.',
  SCENARIO_NOT_CERTIFIED: 'Scénario non certifié. Action : sélectionner un scénario marqué exécutable et certifié.',
  SCENARIO_ARCHIVED: 'Scénario archivé. Action : le restaurer avant de demander son exécution.',
  SCENARIO_TYPE_REQUIRED: 'Type de scénario manquant. Action : relancer depuis le scénario certifié de la bibliothèque.',
  SCENARIO_UE_NOT_CONTROLLER_OWNED: 'UE non géré par Control. Action : sélectionner un UE dont la propriété Control est vérifiée.',
  SCENARIO_UE_SELECTION_DUPLICATE: 'UE sélectionné plusieurs fois. Action : conserver une seule occurrence de chaque UE.',
  SCENARIO_UE_SELECTION_INVALID: 'Sélection d’UE invalide. Action : sélectionner le nombre d’UE requis et uniquement des UE éligibles.',
  SCENARIO_VALIDATION_REQUIRED: 'Validation requise. Action : cliquer sur Validate avant de démarrer le scénario.',
  SCENARIO_ALREADY_ACTIVE: 'Un scénario est déjà actif. Action : attendre sa fin ou arrêter le job actif.',
  SCENARIO_NO_ACTIVE_JOB: 'Aucun job actif. Action : actualiser l’état ou démarrer un scénario avant de demander son arrêt.',
  TRAFFIC_BYTES_OUT_OF_RANGE: 'Volume de trafic hors limites. Action : utiliser les valeurs bornées du profil certifié.',
  TRAFFIC_DESTINATION_NOT_ALLOWLISTED: 'Destination de trafic non autorisée. Action : sélectionner la destination certifiée.',
  TRAFFIC_ESTIMATED_DURATION_EXCEEDS_SERVER_LIMIT: 'Durée de trafic trop longue. Action : réduire le volume ou le débit demandé.',
  TRAFFIC_PROCESS_SPAWN_FAILED: 'Générateur de trafic non démarré. Action : vérifier System Health puis relancer.',
  TRAFFIC_PROTOCOL_INVALID: 'Protocole de trafic non autorisé. Action : sélectionner un protocole certifié.',
  TRAFFIC_RATE_DURATION_OUT_OF_RANGE: 'Débit ou durée hors limites. Action : utiliser les bornes affichées par Traffic Generator.',
  TRAFFIC_SESSION_GRANT_REQUIRED: 'Autorisation de trafic requise. Action : valider la session de trafic avant de la démarrer.',
  TRAFFIC_SESSION_NOT_FOUND: 'Session de trafic introuvable. Action : actualiser Traffic Generator avant de relancer.',
  TRAFFIC_TARGET_RESOLUTION_UNSUPPORTED: 'Cible de trafic non résolue. Action : vérifier la PDU et la route de l’UE.',
  TRANSFER_PEER_NOT_AVAILABLE: 'Pair de transfert indisponible. Action : vérifier la santé du générateur de trafic.',
  UE_ALREADY_RUNNING: 'UE déjà démarré. Action : ouvrir UE Manager et l’arrêter avant une nouvelle exécution.',
  UE_CAPACITY_REACHED: 'Capacité maximale atteinte. Action : arrêter ou retirer un UE avant d’en ajouter un.',
  UE_CONFIGURATION_LOADING: 'Configuration UE en cours de chargement. Action : attendre son affichage puis réessayer.',
  UE_CONTROL_VALIDATION_REQUIRED: 'Validation Control requise. Action : ouvrir UE Manager, puis autoriser cet UE avant de relancer.',
  ATTESTATION_INCOMPLETE: 'Attestation incomplète. Action : demander à un agent lab de vérifier le profil en lecture seule.',
  PROVISIONING_PROFILE_INVALID: 'Profil de provisioning invalide. Action : demander à un agent lab de comparer le profil avec la base autoritative.',
  SUBSCRIBER_PROVISIONING_REVIEW_REQUIRED: 'Abonnement non attesté. Action : ouvrir Paramètres, puis lancer la vérification du provisioning.',
  SHARED_UE_PROTECTED: 'UE partagée protégée. Action : choisir un UE géré par Control ou demander son transfert explicite.',
  PROTECTED_OR_UNAPPROVED_UE: 'UE hors du périmètre autorisé. Action : demander la validation de sa prise en charge par Control.',
  LIVE_EXECUTION_NOT_CONFIGURED: 'Exécution live désactivée. Action : demander à un administrateur de vérifier la configuration d’exécution.',
  UE_NOT_RUNNING: 'UE arrêté. Action : ouvrir UE Manager et le démarrer avant de poursuivre.',
  NOT_CONFIGURED: 'UE non configuré. Action : ouvrir UE Manager et terminer sa configuration.',
  UE_NOT_REGISTERED: 'UE non enregistré sur le réseau. Action : ouvrir son activité et vérifier l’attachement.',
  PDU_SESSION_NOT_ACTIVE: 'Session PDU inactive. Action : ouvrir son activité et vérifier l’établissement de la session.',
  UE_RUNTIME_OWNERSHIP_NOT_VERIFIED: 'Propriété du processus UE non vérifiée. Action : demander à un agent lab de vérifier le processus en lecture seule.',
  LTE_E2E_CERTIFICATION_REQUIRED: 'Certification LTE de bout en bout requise. Action : demander l’exécution de la recette LTE autorisée.',
  SRSRAN_LIVE_DISABLED: 'Exécution srsRAN live désactivée. Action : demander à un administrateur de vérifier la configuration srsRAN.',
  LTE_LIVE_GRANT_REQUIRED: 'Autorisation live LTE requise. Action : demander une autorisation bornée pour cet UE.',
  LIVE_GRANT_REQUIRED: 'Autorisation live requise. Action : demander une autorisation bornée avant de poursuivre.',
  SRSRAN_CONTROLLER_OWNERSHIP_REQUIRED: 'Propriété srsRAN non vérifiée. Action : demander à un agent lab de vérifier le processus en lecture seule.',
  LTE_ATTACH_OR_IP_NOT_OBSERVED: 'Attachement LTE ou adresse de session non observé. Action : ouvrir l’activité LTE et vérifier l’attachement.',
  UE_NON_ELIGIBLE: 'UE non éligible. Action : ouvrir UE Manager et vérifier son provisioning, son autorisation et son état.',
  UE_NOT_STARTED: 'UE non démarré dans ce job. Action : démarrer l’UE avec le même scénario avant l’étape suivante.',
  UE_NOT_OWNED_BY_CONTROLLER: 'UE non possédé par Control. Action : choisir un UE géré par Control.',
  UE_NOT_PROVISIONED: 'UE non provisionné. Action : vérifier son profil et son abonnement avant de le démarrer.',
  UE_OPERATION_IN_PROGRESS: 'Opération UE déjà en cours. Action : attendre son résultat avant de relancer.',
  UE_PROFILE_BULK_TOO_LARGE: 'Trop de profils UE demandés. Action : réduire la sélection puis relancer.',
  UE_PROFILE_NOT_READY: 'Profil UE non prêt. Action : corriger son provisioning avant de le démarrer.',
  UE_RECONCILIATION_IN_PROGRESS: 'Réconciliation UE en cours. Action : attendre sa fin avant de modifier la configuration.',
  UE_REGISTRY_UNAVAILABLE: 'Registre UE indisponible. Action : demander une vérification de Control avant de relancer.',
  UE_SELECTION_REQUIRED: 'Aucun UE sélectionné. Action : sélectionner au moins un UE éligible.',
  UE_TRAFFIC_PREREQUISITES_NOT_MET: 'Prérequis trafic UE absents. Action : vérifier enregistrement, PDU et route avant de relancer.',
  UL_RECEIVER_NOT_AVAILABLE: 'Récepteur de trafic montant indisponible. Action : vérifier la santé du générateur de trafic.',
  IMS_CALL_200_TIMEOUT: 'Réponse SIP 200 non reçue. Action : vérifier le pair IMS et la signalisation avant de relancer.',
  IMS_CALL_CAPTURE_FAILED: 'Capture voix impossible. Action : vérifier les outils de capture du scénario IMS.',
  IMS_CALL_REQUIRES_REGISTERED_UES: 'UE IMS non enregistrés. Action : terminer REGISTER pour les deux UE avant l’appel.',
  IMS_CALL_RTP_BIDIRECTIONAL_NOT_OBSERVED: 'RTP bidirectionnel non observé. Action : vérifier les routes IMS et RTPengine.',
  IMS_CALL_SIGNALING_INCOMPLETE: 'Signalisation d’appel incomplète. Action : vérifier INVITE, réponse 200 et BYE.',
  IMS_CLIENT_CONFIGURATION_UNAVAILABLE: 'Configuration client IMS indisponible. Action : vérifier le profil voix de l’UE.',
  IMS_CLIENT_OWNERSHIP_CONFLICT: 'Client IMS déjà possédé par un autre job. Action : arrêter le job actif puis relancer.',
  IMS_CLIENT_START_FAILED: 'Client IMS non démarré. Action : consulter l’activité voix puis vérifier son profil.',
  IMS_NOT_AVAILABLE: 'Service IMS indisponible. Action : vérifier la santé IMS avant de relancer.',
  IMS_PCSCF_UNREACHABLE: 'P-CSCF injoignable. Action : vérifier la PDU IMS et sa route.',
  IMS_PDU_NOT_ACTIVE: 'PDU IMS inactive. Action : établir la PDU IMS avant REGISTER.',
  IMS_REGISTER_NOT_OBSERVED: 'REGISTER IMS non observé. Action : vérifier la signalisation SIP du client.',
  IMS_REGISTER_REFUSED: 'REGISTER IMS refusé. Action : vérifier le profil et l’authentification IMS.',
  IMS_REGISTER_TIMEOUT: 'REGISTER IMS expiré. Action : vérifier la PDU IMS et le P-CSCF puis relancer.',
  IMS_TUN_NOT_READY: 'Interface IMS non prête. Action : attendre la PDU IMS avant de lancer la voix.',
  IMS_UE_NOT_AUTHORIZED: 'UE non autorisé pour IMS. Action : sélectionner un UE voix certifié.',
  IMS_UE_REQUIRED: 'UE voix manquant. Action : sélectionner l’UE requis par le scénario IMS.',
  VOICE_TWO_DISTINCT_UES_REQUIRED: 'Deux UE distincts sont requis. Action : sélectionner un appelant et un appelé différents.',
  OPERATION_IN_PROGRESS: 'Opération en cours. Action : attendre sa fin avant de relancer.',
  BUILDER_RUN_NOT_CERTIFIED: 'Brouillon non exécutable. Action : certifier toutes les étapes avant de lancer Run.',
  LTE_NOT_CERTIFIED: 'LTE non certifié dans ce parcours. Action : utiliser le parcours 5G ou demander la certification LTE.',
  TRAFFIC_TARGET_REQUIRED: 'Aucun UE trafic éligible. Action : enregistrer un UE géré par Control avec une PDU active.',
  TRAFFIC_VALIDATION_REQUIRED: 'Validation trafic requise. Action : cliquer sur Validate avant Start Traffic.',
  TRAFFIC_JOB_ALREADY_ACTIVE: 'Un trafic est déjà actif. Action : attendre sa fin ou arrêter le job actif.',
  TRAFFIC_NO_ACTIVE_JOB: 'Aucun trafic actif pour cet UE. Action : actualiser l’état ou démarrer un trafic.',
};
export const humanActionReason = (code:string|undefined|null) => {
  if (!code) return 'Motif indisponible. Action : actualiser la page, puis demander une vérification si le blocage persiste.';
  if (!isSafeRefusalCode(code)) return 'Blocage non documenté. Action : actualiser la page, puis demander une vérification.';
  return actionReasonMessages[code] ?? `Blocage non documenté (${code}). Action : ouvrir UE Manager et demander une vérification.`;
};
export const humanDisabledReason = (reason:string|undefined|null) => humanActionReason(reason ?? 'OPERATION_IN_PROGRESS');
export const humanApiRefusal = (error:unknown) => {
  const raw=error instanceof Error?error.message:String(error??'');
  const code=raw.split(':',1)[0]?.trim();
  if (code&&isSafeRefusalCode(code)) {
    if (actionReasonMessages[code]) return humanActionReason(code);
    return `L’API a refusé l’opération (${code}). Action : réessayer, puis demander une vérification si le refus persiste.`;
  }
  return 'L’API a refusé l’opération. Action : réessayer, puis demander une vérification si le refus persiste.';
};
export const filterScenarioDefinitions = (items:ScenarioDefinition[], scope:'SYSTEM'|'USER', query:string) => {
  const needle=query.trim().toLocaleLowerCase();
  return items.filter(item => item.catalog_scope===scope && (!needle || item.id.toLocaleLowerCase().includes(needle) || item.name.toLocaleLowerCase().includes(needle)));
};
export const filterAndSortHistory = (items:ScenarioState[], query:string, state:string) => {
  const needle=query.trim().toLocaleLowerCase();
  return [...items].filter(item => {
    const matchesState=!state||item.state===state;
    const haystack=[item.scenario_id,item.job_id,item.target_ue_pseudonym,item.error_code?safeAuditReference(item.error_code):null,item.cause?safeAuditReference(item.cause):null,item.terminal_result?safeAuditReference(item.terminal_result):null].filter(Boolean).join(' ').replaceAll('_',' ').toLocaleLowerCase();
    return matchesState&&(!needle||haystack.includes(needle));
  }).sort((left,right)=>(right.started_at_epoch_s??0)-(left.started_at_epoch_s??0));
};

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
  const response = await fetch('/api/v1' + path, { ...init, cache: 'no-store', credentials: 'same-origin', headers: { 'content-type': 'application/json', ...(!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrf ? { 'x-csrf-token': csrf } : {}), ...init?.headers } });
  const body = await response.json().catch(() => ({ error: 'INVALID_RESPONSE' }));
  if (body && typeof body === 'object' && 'csrf_token' in body && typeof body.csrf_token === 'string' && body.csrf_token) setCsrfToken(body.csrf_token);
  if (!response.ok) throw new Error(typeof body.error === 'string' ? `${body.error}${body.suggestion?`: ${body.suggestion}`:''}` : `API ${response.status}`);
  return body as T;
}
