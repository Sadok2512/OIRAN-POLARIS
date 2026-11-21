//! Versioned, read-only HTTP adapter for certified OIRAN artifacts.
// 2.11.1 : la macro `json!` dans le handler `metrics` a dépassé la
// profondeur de récursion par défaut (128) après l'ajout des 5
// nouveaux champs pending/open/zero exigés par ANR1 (#10 comment
// 6778895992). On remonte la limite plutôt que d'éclater le JSON
// en sous-blocs — c'est le même pattern que d'autres gros
// handlers API.
#![recursion_limit = "512"]

mod identity_vault;
mod live_trace;
mod polaris_config;
mod probe_registry;
mod read_time_patch;
mod session_catalog;
mod session_filters;
mod subscriber_journey;
// 2.21.78 (ordre #9 7013448739) — débit live GTP-U par seconde, par
// session, par QFI. SSE indépendant de la live trace.
mod throughput;

use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use callflow_schema::{build_callflow, CallFlow};
use dataset_registry::{CaptureRecord, DatasetRecord, DatasetRegistry};
use disk_safety::{assess, capture_budget, measure_path, rotation_plan, Policy};
use event_schema::{pseudonym_subscriber_text, sha256_hex};
use identity_vault::{IdentityObservation, IdentityVault};
use live_probe::{
    load_dataset_events,
    lte_evidence::{
        LteDatasetManifest, LteEvidenceError, LteEvidenceImportPayload, LteEvidenceStore,
    },
    offline_lte_callflows, read_callflow_page, CaptureManager, CaptureRequest,
    ContinuousImportConfig, DEFAULT_CALLFLOW_PAGE_EVENTS, DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES,
    MAX_CALLFLOW_PAGE_EVENTS,
};
use probe_registry::{CreateError as ProbeCreateError, ProbeInput, ProbeRecord, ProbeRegistry};
use serde::Deserialize;
use serde_json::{json, Value};
use session_engine::{
    discover_sessions, reconstruct, Association, DiscoveryResult, LteSession, ReconstructionHints,
};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::{
    compression::CompressionLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

// 2.7.17 — both version constants are now derived from CARGO_PKG_VERSION so
// the binary, the /version response and the test assertion can never drift
// from the package manifest (ANR2 refused 2.7.16 because API_VERSION was
// hardcoded to "2.7.15" while apps/api/Cargo.toml was already at 2.7.16).
pub const API_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PLATFORM_VERSION: &str = env!("CARGO_PKG_VERSION");
/// 2.7.17 — the web frontend's version is read from `apps/web/package.json`
/// at build time via `build.rs` (`cargo:rustc-env=OIRAN_WEB_FRONTEND_VERSION`),
/// so bumping the frontend never requires editing this crate again.
pub const WEB_FRONTEND_VERSION: &str = env!("OIRAN_WEB_FRONTEND_VERSION");
const HEARTBEAT_ONLINE_WINDOW_SECONDS: u64 = 15;
const CSRF_HEADER: &str = "x-csrf-token";
const DEFAULT_IDENTITY_VAULT_DIR: &str = "/var/lib/oiran/identity-vault";
const DEFAULT_IDENTITY_VAULT_PATH: &str = "/var/lib/oiran/identity-vault/vault.json";

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    flows: BTreeMap<String, CallFlow>,
    flow_values: BTreeMap<String, Value>,
    flow_paths: BTreeMap<String, PathBuf>,
    primary_session_id: String,
    manifest: Value,
    captures: Vec<Value>,
    registry: DatasetRegistry,
    discovery: DiscoveryResult,
    storage_path: PathBuf,
    capture_manager: CaptureManager,
    /// 2.21.63 — interdit le préchauffage startup de courir devant la
    /// première publication continue. L'observateur de publication devient
    /// l'unique frontière de préchauffage dans ce mode.
    continuous_import_enabled: bool,
    probe_registry: ProbeRegistry,
    derived_import_root: PathBuf,
    lte_evidence_store: LteEvidenceStore,
    lte_evidence_bundle_root: PathBuf,
    operator_token_sha256: Option<String>,
    administrator_token_sha256: Option<String>,
    identity_vault: IdentityVault,
    live_traces: live_trace::LiveTraceRegistry,
    /// 2.21.78 (ordre #9 7013448739) — registre des flux SSE de débit
    /// par session. Partagé avec le lecteur unique de `live_trace`
    /// (voir `start_reader`) qui lui pousse chaque event GTP-U
    /// résolu à une session via `TeidSessionIndex`.
    throughput: throughput::ThroughputRegistry,
    /// 2.14.7 (ANR1 #10) — compteurs du patcher à la lecture. Partagé
    /// via `Arc` : chaque chargement/accès à un `flow_value`
    /// incrémente ces compteurs sans verrouillage global. Exposé dans
    /// `/api/v1/version` pour que la gate ANR1 puisse constater que
    /// le patch est actif.
    read_time_patch_counters: Arc<read_time_patch::PatchCounters>,
    /// 2.14.8 (ANR1 #10) — racine du dataset de référence quand
    /// `reference_dataset_enabled`. Utilisée par le patcher à la
    /// lecture pour relire `oiran_events.jsonl` / `event-shards/*`
    /// quand une requête vient du chemin A (`flow_value_for`). None
    /// en mode operational (le chemin A n'a jamais servi d'event).
    reference_dataset_root: Option<PathBuf>,
    /// 2.14.9 (ANR1 #10 6859228701) — cache LRU borné des indexes raw
    /// par (dataset_root, session_id). Remplace la map non bornée de
    /// 2.14.8 qui a provoqué un OOM à 4 Gio sur la prod ANR1. Limites
    /// configurables via `OIRAN_READ_TIME_PATCH_CACHE_SESSIONS`
    /// (défaut 16) et `OIRAN_READ_TIME_PATCH_CACHE_BYTES` (défaut 64
    /// MiB). Compteurs exposés dans
    /// `/api/v1/version.read_time_patch.cache.*`.
    raw_index_cache: read_time_patch::RawIndexCache,
    /// 2.14.11 (ANR1 #10 6860508699) — registre des index compacts
    /// `event_id → byte offset` construits UNE fois au démarrage (en
    /// arrière-plan) par `oiran_events.jsonl` et par shard. Évite la
    /// relecture complète du JSONL (3,4 Go côté prod → ~60 s par
    /// cache miss en 2.14.9). Mise à jour incrémentale append-only.
    /// Compteurs exposés dans
    /// `/api/v1/version.read_time_patch.index.*`.
    compact_index_registry: Arc<read_time_patch::CompactJsonlIndexRegistry>,
    /// 2.10.0 : index des filtres Session Explorer (messages, causes,
    /// pseudonymes), construit au chargement depuis `flows` + mis à
    /// jour par `refresh_session_filter_index` quand le capture
    /// manager publie une nouvelle version du dataset continu.
    /// Verrouillé par `RwLock` : lecteurs multiples (handlers HTTP)
    /// + rare upsert sous `write`.
    session_filter_index: std::sync::RwLock<session_filters::SessionFilterIndex>,
    /// 2.18.12 — signature des sources de l'index de filtrage (rebuild
    /// seulement si elle change) et index de parcours abonné en cache.
    session_filter_signature: std::sync::Mutex<Option<Vec<String>>>,
    journey_index_cache: std::sync::Mutex<JourneyCache>,
    list_row_cache: std::sync::Mutex<ListRowCache>,
    /// 2.21.74 — génération publiée dont l'index de filtre ET les lignes
    /// de liste sont entièrement préchauffés. L'application du contrat est
    /// activée par `install_session_filter_cache_prewarm`, avant l'ouverture
    /// du listener ; les états construits isolément dans les tests gardent
    /// le comportement historique tant que l'installation n'a pas eu lieu.
    session_filter_cache_readiness: std::sync::Mutex<SessionFilterCacheReadiness>,
    /// 2.21.85 (CLAUDE1, ordre #9 7015585561) — double tampon READY
    /// pour `/sessions/filter`. Le snapshot Arc'd capture au moment du
    /// swap l'état cohérent (filter_index + journey_index + list_rows)
    /// de la dernière génération. La route n'accède plus aux caches
    /// mutables ni au disque ; elle lit l'Arc, servant l'ancienne
    /// génération pendant que la publication + le prewarm construisent
    /// la suivante. Aucune 503 pendant une publication si une
    /// génération READY existait auparavant.
    generation_slot: std::sync::RwLock<Option<Arc<FilterGeneration>>>,
    generation_counter: std::sync::atomic::AtomicU64,
    /// 2.21.92 (défaut bloquant ANR1 #10 7035121536) — compteur et dernière
    /// occurrence d'un refus de bascule du double tampon. Un refus signifie
    /// qu'une génération candidate n'a pas pu remplacer la précédente car :
    ///   * son `session_count` divergeait du nombre de sessions publiées
    ///     (/health.published_session_count) hors cas « vrai zéro », ou
    ///   * un des verrous (filter_index/journey_index_cache/list_row_cache)
    ///     était empoisonné ou le journey cache n'avait pas encore été
    ///     construit.
    /// Avant 2.21.92 ces cas basculaient silencieusement une génération vide
    /// ou tronquée (`unwrap_or_else(|_| …empty())` / `unwrap_or_default()`),
    /// servie à 200 OK avec `meta.total=0` et `data=[]` alors que
    /// `/health.session_count` annonçait N > 0 (recette 2.21.89 ANR1).
    /// Exposé via `/health.sessions_filter_generation_swap_refused`.
    generation_swap_refused: std::sync::Mutex<GenerationSwapRefusedState>,
    /// 2.21.92 raffinement (ordre #9 7036719807 trou 1) — jalon de la règle
    /// « une génération à 0 session ne remplace jamais une génération non
    /// vide sur un seul préchauffage ». Positionné à `Some(now + 30 s)`
    /// quand un `(0,0)` est refusé au titre de `empty_after_nonempty_unconfirmed`.
    /// Le préchauffage suivant, s'il observe encore `(0,0)` ET que cette
    /// deadline n'est pas dépassée, accepte la bascule (confirmation par
    /// double observation). Le first-boot (slot=None) n'est pas concerné
    /// et bascule un `(0,0)` au premier préchauffage.
    pending_empty_confirmation_until: std::sync::Mutex<Option<std::time::Instant>>,
    /// 2.21.92 raffinement (ordre #9 7036719807 trou 2) — compteur des
    /// nouvelles tentatives programmées après un refus. Exposé dans
    /// `/health.sessions_filter_generation_swap_refused.retries_scheduled_total`.
    /// Sous `cfg(test)`, l'incrément se fait mais le thread du retry
    /// n'est PAS lancé (évite les side-effects asynchrones en test).
    generation_swap_retry_scheduled: std::sync::Mutex<u64>,
    /// 2.21.94 (défaut bloquant prod ANR1 #10 7040235279, ordre #9 7040291627) —
    /// compteur et dernière occurrence d'une bascule acceptée malgré un écart
    /// entre `candidate_session_count` et `reference_session_count`. Il y en a
    /// deux cas d'usage :
    ///   * first-boot (`generation_slot=None`) : on bascule pour éviter 503
    ///     permanent sur `/sessions/filter`, candidat non vide requis.
    ///   * après 3 ré-essais épuisés : l'ancienne génération est trop périmée,
    ///     on la remplace avec avertissement.
    /// Exposé via `/health.sessions_filter_generation_swap_accepted_with_mismatch`.
    generation_swap_accepted_with_mismatch:
        std::sync::Mutex<GenerationSwapAcceptedWithMismatchState>,
    /// 2.21.11 (défaut 2 #9 6930315055) — cache `/sessions/catalog`
    /// keyé par `(commit_seq, dataset_ids, scope_hash)`. Évite de
    /// reconstruire `protocol_tree` + `network_elements` à chaque
    /// requête (45 s observés avec 217 sessions). Invalidé
    /// automatiquement dès qu'un dataset publie un nouveau
    /// `commit_seq`. La clé inclut aussi un hash des paramètres de
    /// scope (interfaces/technologies/from/to/run_id) pour que deux
    /// portées différentes ne se partagent pas une entrée.
    sessions_catalog_cache: std::sync::Mutex<SessionsCatalogCache>,
    /// 2.21.13 — instantané des compteurs de `/health`, recalculé en
    /// arrière-plan (`spawn_blocking`). `/health` ne fait plus AUCUNE
    /// E/S ni aucun parse de callflow sur le runtime async.
    health_cache: std::sync::Mutex<Option<(std::time::Instant, Value)>>,
    health_refreshing: std::sync::atomic::AtomicBool,
    /// 2.21.15 (reprise #9 6941147984) — cache `/identities` keyé par
    /// `session_id`, invalidé via `IdentityCacheEntry.signature` (hash
    /// des packet_references du callflow). Évite de relancer tshark
    /// 210 s sur le chemin de requête.
    identity_cache: std::sync::Mutex<BTreeMap<String, IdentityCacheEntry>>,
    #[cfg(test)]
    filter_summary_resolutions: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    filter_flow_resolutions: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    filter_index_rebuilds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    journey_index_rebuilds: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    list_row_cache_builds: std::sync::atomic::AtomicUsize,
}

/// 2.21.11 — entrée de cache + clé composite pour `/sessions/catalog`.
#[derive(Default)]
struct SessionsCatalogCache {
    entry: Option<SessionsCatalogCacheEntry>,
}

#[derive(Clone)]
struct SessionsCatalogCacheEntry {
    /// `(dataset_id, commit_seq)` pour chaque dataset live vu. Si un
    /// dataset_id apparaît/disparaît ou si un commit_seq change, l'entrée
    /// est invalide.
    dataset_signatures: Vec<(String, u64)>,
    /// Hash des paramètres de scope de la requête (interfaces,
    /// technologies, from, to, run_id).
    scope_hash: u64,
    /// `protocol_tree` pré-calculé (JSON).
    protocol_tree: Value,
    /// `network_elements` pré-calculé (JSON).
    network_elements: Value,
}

#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub workspace: PathBuf,
    pub dataset_dir: PathBuf,
    pub callflow_json: PathBuf,
    pub callflow_html: PathBuf,
    pub capture_root: PathBuf,
    pub probe_registry_path: PathBuf,
    pub derived_import_root: PathBuf,
    pub lte_evidence_root: PathBuf,
    pub lte_evidence_bundle_root: PathBuf,
    pub capture_execution_enabled: bool,
    pub operator_token_sha256: Option<String>,
    pub administrator_token_sha256: Option<String>,
    pub continuous_import_enabled: bool,
    pub continuous_native_capture: bool,
    pub continuous_import_source: Option<PathBuf>,
    pub continuous_historical_n2_bootstrap: Option<PathBuf>,
    pub continuous_max_segment_bytes: u64,
    /// Explicit test/reference mode. Operational startup must only expose
    /// datasets recovered by CaptureManager or admitted by LteEvidenceStore.
    pub reference_dataset_enabled: bool,
    /// Per-deployment pseudonym key path. `None` means
    /// `PseudonymKey::resolve_default_path()` (env `OIRAN_PSEUDONYM_KEY_PATH`
    /// or `/var/lib/oiran/pseudonym.key`). Tests set it to a path under their
    /// capture root so they neither touch the real filesystem nor collide
    /// with parallel tests.
    pub pseudonym_key_path: Option<PathBuf>,
    /// Root-only identity evidence, deliberately outside the capture and
    /// publication roots.
    pub identity_vault_path: PathBuf,
}

impl ApiConfig {
    pub fn from_workspace(workspace: &FsPath) -> Self {
        Self {
            workspace: workspace.to_path_buf(),
            dataset_dir: workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1"),
            callflow_json: workspace.join("OIRAN_5G_E2E_CALLFLOW.json"),
            callflow_html: workspace.join("OIRAN_5G_E2E_CALLFLOW.html"),
            capture_root: std::env::var_os("OIRAN_CAPTURE_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| workspace.join("runtime/live-captures")),
            probe_registry_path: std::env::var_os("OIRAN_PROBE_REGISTRY_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| workspace.join("runtime/probe-registry.json")),
            derived_import_root: std::env::var_os("OIRAN_DERIVED_IMPORT_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| workspace.join("benchmarks/E2E_002")),
            lte_evidence_root: std::env::var_os("OIRAN_LTE_EVIDENCE_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| workspace.join("runtime/lte-evidence")),
            lte_evidence_bundle_root: std::env::var_os("OIRAN_LTE_EVIDENCE_BUNDLE_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| workspace.join("runtime/lte-evidence-inbox")),
            capture_execution_enabled: std::env::var("OIRAN_CAPTURE_EXECUTION_ENABLED")
                .is_ok_and(|value| value == "1"),
            operator_token_sha256: std::env::var("OIRAN_OPERATOR_TOKEN_SHA256").ok(),
            administrator_token_sha256: std::env::var("OIRAN_ADMIN_TOKEN_SHA256").ok(),
            continuous_import_enabled: std::env::var("OIRAN_CONTINUOUS_IMPORT_ENABLED")
                .is_ok_and(|value| value == "1"),
            continuous_native_capture: std::env::var("OIRAN_CONTINUOUS_NATIVE_CAPTURE")
                .is_ok_and(|value| value == "1"),
            continuous_import_source: std::env::var_os("OIRAN_CONTINUOUS_IMPORT_SOURCE")
                .map(PathBuf::from),
            continuous_historical_n2_bootstrap: std::env::var_os("OIRAN_CONTINUOUS_BOOTSTRAP_N2")
                .map(PathBuf::from),
            continuous_max_segment_bytes: std::env::var("OIRAN_CONTINUOUS_MAX_SEGMENT_BYTES")
                .ok()
                .map(|value| value.parse::<u64>().unwrap_or(0))
                .unwrap_or(DEFAULT_CONTINUOUS_MAX_SEGMENT_BYTES),
            reference_dataset_enabled: cfg!(test)
                || std::env::var("OIRAN_REFERENCE_DATASET_ENABLED").is_ok_and(|value| value == "1"),
            pseudonym_key_path: None,
            identity_vault_path: std::env::var_os("OIRAN_IDENTITY_VAULT_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_VAULT_DIR).join("vault.json")),
        }
    }
}

fn validate_identity_vault_path(config: &ApiConfig) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }
    let path = &config.identity_vault_path;
    let allowed = path == FsPath::new(DEFAULT_IDENTITY_VAULT_PATH)
        || path.starts_with("/var/tmp/oiran-phantom")
        || path.starts_with(config.workspace.join("runtime"));
    if !allowed || path.parent() == Some(FsPath::new("/var/lib/oiran")) {
        return Err(format!(
            "identity vault path is not isolated path={}",
            path.display()
        ));
    }
    Ok(())
}

fn access_check(path: &FsPath, flags: i32, required: &str) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| {
        format!(
            "ACCESS_CHECK_FAILED path={} mode=UNAVAILABLE required={required} error={error}",
            path.display()
        )
    })?;
    let mode = metadata.permissions().mode() & 0o7777;
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "ACCESS_CHECK_FAILED path={} mode={mode:04o} required={required} error=invalid-path",
            path.display()
        )
    })?;
    if unsafe { libc::access(c_path.as_ptr(), flags) } != 0 {
        return Err(format!(
            "ACCESS_CHECK_FAILED path={} mode={mode:04o} required={required} error={}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn access_check_creatable(path: &FsPath, required: &str) -> Result<(), String> {
    if path.exists() {
        return access_check(path, libc::R_OK | libc::W_OK | libc::X_OK, required);
    }
    let mut ancestor = path.parent();
    while let Some(candidate) = ancestor {
        if candidate.exists() {
            return access_check(candidate, libc::W_OK | libc::X_OK, required).map_err(|_| {
                let mode = fs::metadata(candidate)
                    .map(|metadata| metadata.permissions().mode() & 0o7777)
                    .unwrap_or(0);
                format!(
                    "ACCESS_CHECK_FAILED path={} mode={mode:04o} required={required} requested_path={}",
                    candidate.display(),
                    path.display()
                )
            });
        }
        ancestor = candidate.parent();
    }
    Err(format!(
        "ACCESS_CHECK_FAILED path={} mode=UNAVAILABLE required={required} error=no-existing-parent",
        path.display()
    ))
}

fn access_check_readable_or_creatable(
    path: &FsPath,
    read_required: &str,
    create_required: &str,
) -> Result<(), String> {
    if path.exists() {
        access_check(path, libc::R_OK | libc::X_OK, read_required)
    } else {
        access_check_creatable(path, create_required)
    }
}

fn service_state_access_checks(config: &ApiConfig) -> Result<(), String> {
    for (directory, read_required, create_required) in [
        (
            &config.derived_import_root,
            "derived-import-read",
            "derived-import-create",
        ),
        (
            &config.lte_evidence_root,
            "lte-evidence-read",
            "lte-evidence-create",
        ),
        (
            &config.lte_evidence_bundle_root,
            "lte-evidence-bundle-read",
            "lte-evidence-bundle-create",
        ),
    ] {
        access_check_readable_or_creatable(directory, read_required, create_required)?;
    }
    Ok(())
}

fn startup_access_checks(config: &ApiConfig) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }
    validate_identity_vault_path(config)?;
    access_check(&config.workspace, libc::R_OK | libc::X_OK, "workspace-read")?;
    if config.capture_root.exists() {
        access_check(
            &config.capture_root,
            libc::R_OK | libc::X_OK,
            "capture-root-read",
        )?;
    } else {
        access_check_creatable(&config.capture_root, "capture-root-create")?;
    }
    if let Some(source) = config.continuous_import_source.as_deref() {
        access_check(source, libc::R_OK | libc::X_OK, "continuous-source-read")?;
    }
    let vault_directory = config
        .identity_vault_path
        .parent()
        .ok_or_else(|| "identity vault path has no parent".to_owned())?;
    access_check_creatable(vault_directory, "identity-vault-create")?;
    service_state_access_checks(config)?;
    if config.probe_registry_path.exists() {
        access_check(
            &config.probe_registry_path,
            libc::R_OK | libc::W_OK,
            "probe-registry-read-write",
        )?;
    } else if let Some(parent) = config.probe_registry_path.parent() {
        access_check_creatable(parent, "probe-registry-create")?;
    }
    Ok(())
}

impl AppState {
    pub fn load(config: ApiConfig) -> Result<Self, String> {
        startup_access_checks(&config)?;
        let workspace = config.workspace.canonicalize().map_err(io_error)?;
        if !config.capture_root.starts_with(&workspace)
            && config.capture_root != FsPath::new("/var/lib/oiran/captures")
            && !cfg!(test)
        {
            return Err("capture root escapes workspace".into());
        }
        let capture_manager = CaptureManager::with_pseudonym_key_path(
            config.capture_root.clone(),
            config.capture_execution_enabled,
            config
                .pseudonym_key_path
                .clone()
                .unwrap_or_else(event_schema::PseudonymKey::resolve_default_path),
        )?;
        if !config.probe_registry_path.starts_with(&workspace)
            && !config.probe_registry_path.starts_with("/var/lib/oiran")
            && !cfg!(test)
        {
            return Err("probe registry path escapes the allowlist".into());
        }
        if config.continuous_import_enabled {
            if config.continuous_native_capture && config.continuous_import_source.is_some() {
                return Err("native continuous capture cannot also import collector files".into());
            }
            let continuous = if config.continuous_native_capture {
                if !config.capture_execution_enabled {
                    return Err("native continuous capture requires capture execution".into());
                }
                let mut native = ContinuousImportConfig::native(config.capture_root.clone());
                native.historical_n2_bootstrap = config.continuous_historical_n2_bootstrap.clone();
                native
            } else {
                let source = config
                    .continuous_import_source
                    .clone()
                    .ok_or("OIRAN_CONTINUOUS_IMPORT_SOURCE is required")?;
                let allowed = FsPath::new("/var/lib/docker/volumes/oiran_lab_pcap/_data");
                if source != allowed {
                    return Err(
                        "continuous import source is not the allowlisted lab collector volume"
                            .into(),
                    );
                }
                ContinuousImportConfig::bounded(source)
            };
            let mut continuous = continuous;
            continuous.max_segment_bytes = config.continuous_max_segment_bytes;
            continuous.max_owned_bytes = continuous.max_owned_bytes.max(
                config
                    .continuous_max_segment_bytes
                    .saturating_add(64 * 1024 * 1024),
            );
            capture_manager.start_continuous_import(continuous)?;
        }
        Self::load_with_capture_manager(config, capture_manager)
    }

    fn load_with_capture_manager(
        config: ApiConfig,
        capture_manager: CaptureManager,
    ) -> Result<Self, String> {
        if !config.reference_dataset_enabled {
            return Self::load_operational(config, capture_manager);
        }
        validate_identity_vault_path(&config)?;
        let identity_vault = IdentityVault::load(config.identity_vault_path.clone())?;
        let workspace = config.workspace.canonicalize().map_err(io_error)?;
        let dataset_dir = config.dataset_dir.canonicalize().map_err(io_error)?;
        let callflow_json = config.callflow_json.canonicalize().map_err(io_error)?;
        let html_export = config.callflow_html.canonicalize().map_err(io_error)?;
        let capture_root = config.capture_root;
        let probe_registry = ProbeRegistry::load(config.probe_registry_path)?;
        let derived_import_root = config
            .derived_import_root
            .canonicalize()
            .map_err(io_error)?;
        for path in [&config.lte_evidence_root, &config.lte_evidence_bundle_root] {
            if !path.starts_with(&workspace) && !path.starts_with("/var/lib/oiran") && !cfg!(test) {
                return Err("LTE evidence path escapes the allowlist".into());
            }
            fs::create_dir_all(path).map_err(io_error)?;
        }
        let lte_evidence_store = LteEvidenceStore::new(config.lte_evidence_root.clone())
            .map_err(|error| error.to_string())?;
        let lte_evidence_bundle_root = config
            .lte_evidence_bundle_root
            .canonicalize()
            .map_err(io_error)?;
        if !capture_root.starts_with(&workspace)
            && capture_root != FsPath::new("/var/lib/oiran/captures")
            && !cfg!(test)
        {
            return Err("capture root escapes workspace".into());
        }
        for path in [&dataset_dir, &callflow_json, &html_export] {
            if !path.starts_with(&workspace) {
                return Err(format!("path escapes workspace: {}", path.display()));
            }
        }
        if !derived_import_root.starts_with(&workspace) {
            return Err("derived import root escapes workspace".into());
        }
        let flow_bytes = fs::read(&callflow_json).map_err(io_error)?;
        let flow: CallFlow = serde_json::from_slice(&flow_bytes).map_err(json_error)?;
        let flow_value: Value = serde_json::from_slice(&flow_bytes).map_err(json_error)?;
        let primary_session_id = flow.session_id.clone();
        let manifest: Value = serde_json::from_slice(
            &fs::read(dataset_dir.join("scenario_manifest.json")).map_err(io_error)?,
        )
        .map_err(json_error)?;
        let captures = build_captures(&dataset_dir, &manifest)?;
        let mut flows = BTreeMap::from([(flow.session_id.clone(), flow)]);
        let mut flow_values = BTreeMap::from([(primary_session_id.clone(), flow_value)]);
        let mut flow_paths = BTreeMap::from([(primary_session_id.clone(), callflow_json.clone())]);
        let callflow_dir = dataset_dir.join("callflows");
        if callflow_dir.is_dir() {
            let mut paths = fs::read_dir(&callflow_dir)
                .map_err(io_error)?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                .collect::<Vec<_>>();
            paths.sort();
            if paths.len() > 128 {
                return Err("callflow allowlist exceeds 128 files".into());
            }
            for path in paths {
                let bytes = fs::read(&path).map_err(io_error)?;
                let candidate: CallFlow = serde_json::from_slice(&bytes).map_err(json_error)?;
                let candidate_value: Value = serde_json::from_slice(&bytes).map_err(json_error)?;
                if flows
                    .insert(candidate.session_id.clone(), candidate.clone())
                    .is_some()
                {
                    return Err(format!("duplicate session id {}", candidate.session_id));
                }
                flow_paths.insert(candidate.session_id.clone(), path);
                flow_values.insert(candidate.session_id, candidate_value);
            }
        }
        let events = load_dataset_events(&dataset_dir)?;
        let discovery = discover_sessions(&mut events.clone());
        for session in &discovery.pdu_sessions {
            let represented = flows.values().any(|flow| {
                session
                    .event_ids
                    .iter()
                    .all(|id| flow.events.iter().any(|event| &event.event_id == id))
            });
            if represented {
                continue;
            }
            let context = discovery
                .ue_contexts
                .iter()
                .find(|context| context.context_id == session.ue_context_id);
            let mut selected_ids = session
                .event_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
            if let Some(context) = context {
                selected_ids.extend(context.event_ids.iter().cloned());
            }
            // 2.15.0 (ANR1 #10 6883006379) — étend la sélection
            // avec les PFCP siblings (même `pfcp_sequence` ou
            // `seid`/`f_seid`) pour rattacher la `PFCP Session
            // Establishment Request` que la découverte 5G
            // n'incluait pas dans `session.event_ids`.
            let selected_ids = session_engine::expand_pfcp_session_members(&events, &selected_ids);
            let selected = events
                .iter()
                .filter(|event| selected_ids.contains(&event.event_id))
                .cloned()
                .collect::<Vec<_>>();
            let mut reconstruction = reconstruct(
                selected,
                ReconstructionHints {
                    ue_pseudonym: context.map(|context| context.pseudonym.clone()),
                    ..Default::default()
                },
            );
            reconstruction.session_id = session.session_id.clone();
            for event in &reconstruction.events {
                reconstruction
                    .association
                    .insert(event.event_id.clone(), Association::Session);
            }
            let generated = build_callflow(&reconstruction, Vec::new());
            let generated_value = serde_json::to_value(&generated).map_err(json_error)?;
            flow_values.insert(generated.session_id.clone(), generated_value);
            flows.insert(generated.session_id.clone(), generated);
        }
        for generated in offline_lte_callflows(&events)? {
            if flows.contains_key(&generated.session_id) {
                continue;
            }
            let generated_value = serde_json::to_value(&generated).map_err(json_error)?;
            flow_values.insert(generated.session_id.clone(), generated_value);
            flows.insert(generated.session_id.clone(), generated);
        }
        let dataset_id = manifest
            .get("scenario_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-dataset")
            .to_owned();
        let mut registry = DatasetRegistry::default();
        registry.register(DatasetRecord {
            dataset_id: dataset_id.clone(),
            display_name: dataset_id,
            captures: captures
                .iter()
                .map(|capture| CaptureRecord {
                    capture_id: capture["capture_id"].as_str().unwrap_or("").to_owned(),
                    file_name: capture["name"].as_str().unwrap_or("").to_owned(),
                    capture_point_id: format!(
                        "oiran-vprobe-local-01:{}",
                        capture["interface"].as_str().unwrap_or("UNKNOWN")
                    ),
                    probe_id: "oiran-vprobe-local-01".into(),
                    interface_type: capture["interface"].as_str().unwrap_or("UNKNOWN").into(),
                    start_timestamp: None,
                    end_timestamp: None,
                    sha256: capture["checksum_sha256"].as_str().unwrap_or("").into(),
                    packet_count: capture["packet_count"].as_u64().unwrap_or(0),
                    size_bytes: capture["size_bytes"].as_u64().unwrap_or(0),
                })
                .collect(),
            decoder_versions: flows
                .values()
                .next()
                .map(|flow| flow.decoder_versions.clone())
                .unwrap_or_default(),
            ingestion_status: "INDEXED_READ_ONLY".into(),
            ingestion_generation: 1,
            session_count: flows.len(),
            ue_context_count: discovery.ue_contexts.len(),
            event_count: flow_values
                .values()
                .filter_map(|value| value["accounting"]["source_events"].as_u64())
                .sum::<u64>() as usize,
            background_event_count: flow_values
                .values()
                .filter_map(|value| value["accounting"]["background_events"].as_u64())
                .sum::<u64>() as usize,
            unmatched_event_count: discovery.unmatched_event_ids.len(),
            duplicate_observation_count: discovery.duplicate_observations.len(),
            error_count: 0,
            read_only: true,
        })?;
        // 2.14.7 (ANR1 #10) — read-time patcher : cross-réfère les
        // `CallFlowEvent` chargés avec les `NormalizedEvent` complets
        // de `oiran_events.jsonl` (ports + message_type + procedure_code
        // retenus) et réécrit en mémoire les champs stale introduits
        // par les ingestions pré-2.14.5 (participants « Unknown
        // endpoint », direction heuristique procedureCode, noms NAS
        // mal mappés, procédure S1AP 22 « UnknownS1APProcedure »).
        // Les fichiers sur disque restent intacts — la provenance 2.14.3
        // reste tracée et chaque événement patché porte
        // `read_time_patch.fields`.
        let read_time_patch_counters = Arc::new(read_time_patch::PatchCounters::new());
        let jsonl_path = dataset_dir.join("oiran_events.jsonl");
        if jsonl_path.is_file() {
            match read_time_patch::RawEventIndex::from_jsonl_path(&jsonl_path) {
                Ok(raw_index) => {
                    let map = oiran_endpoint_map();
                    for flow_value in flow_values.values_mut() {
                        if let Some(events) =
                            flow_value.get_mut("events").and_then(Value::as_array_mut)
                        {
                            read_time_patch::patch_flow_events(
                                events,
                                &raw_index,
                                &map,
                                &read_time_patch_counters,
                            );
                            read_time_patch_counters
                                .callflows_loaded
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        json!({
                            "event": "READ_TIME_PATCH_JSONL_UNREADABLE",
                            "path": jsonl_path.display().to_string(),
                            "error": error,
                        })
                    );
                }
            }
        } else {
            eprintln!(
                "{}",
                json!({
                    "event": "READ_TIME_PATCH_JSONL_MISSING",
                    "path": jsonl_path.display().to_string(),
                    "reason": "no oiran_events.jsonl sidecar; stored CallFlowEvent values served as-is",
                })
            );
        }
        let session_filter_index = session_filters::SessionFilterIndex::from_flows(flows.values());
        Ok(Self {
            inner: Arc::new(Inner {
                flows,
                flow_values,
                flow_paths,
                primary_session_id,
                manifest,
                captures,
                registry,
                discovery,
                storage_path: workspace,
                capture_manager,
                continuous_import_enabled: config.continuous_import_enabled,
                probe_registry,
                derived_import_root,
                lte_evidence_store,
                lte_evidence_bundle_root,
                operator_token_sha256: config.operator_token_sha256,
                administrator_token_sha256: config.administrator_token_sha256,
                identity_vault,
                live_traces: live_trace::LiveTraceRegistry::new(),
                throughput: throughput::ThroughputRegistry::new(),
                read_time_patch_counters: read_time_patch_counters.clone(),
                reference_dataset_root: Some(dataset_dir.clone()),
                raw_index_cache: read_time_patch::RawIndexCache::new(
                    read_time_patch::CacheLimits::from_env(),
                    read_time_patch_counters.clone(),
                ),
                compact_index_registry: Arc::new(read_time_patch::CompactJsonlIndexRegistry::new(
                    read_time_patch_counters.clone(),
                )),
                session_filter_signature: std::sync::Mutex::new(None),
                journey_index_cache: std::sync::Mutex::new(None),
                list_row_cache: std::sync::Mutex::new(ListRowCache::new()),
                session_filter_cache_readiness: std::sync::Mutex::new(
                    SessionFilterCacheReadiness::default(),
                ),
                generation_slot: std::sync::RwLock::new(None),
                generation_counter: std::sync::atomic::AtomicU64::new(0),
                generation_swap_refused: std::sync::Mutex::new(
                    GenerationSwapRefusedState::default(),
                ),
                pending_empty_confirmation_until: std::sync::Mutex::new(None),
                generation_swap_retry_scheduled: std::sync::Mutex::new(0),
                generation_swap_accepted_with_mismatch: std::sync::Mutex::new(
                    GenerationSwapAcceptedWithMismatchState::default(),
                ),
                sessions_catalog_cache: std::sync::Mutex::new(SessionsCatalogCache::default()),
                health_cache: std::sync::Mutex::new(None),
                health_refreshing: std::sync::atomic::AtomicBool::new(false),
                identity_cache: std::sync::Mutex::new(BTreeMap::new()),
                #[cfg(test)]
                filter_summary_resolutions: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                filter_flow_resolutions: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                filter_index_rebuilds: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                journey_index_rebuilds: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                list_row_cache_builds: std::sync::atomic::AtomicUsize::new(0),
                session_filter_index: std::sync::RwLock::new(session_filter_index),
            }),
        })
    }

    fn load_operational(
        config: ApiConfig,
        capture_manager: CaptureManager,
    ) -> Result<Self, String> {
        validate_identity_vault_path(&config)?;
        let identity_vault = IdentityVault::load(config.identity_vault_path.clone())?;
        let workspace = config.workspace.canonicalize().map_err(io_error)?;
        let capture_root = config.capture_root;
        if !capture_root.starts_with(&workspace)
            && capture_root != FsPath::new("/var/lib/oiran/captures")
            && !cfg!(test)
        {
            return Err("capture root escapes workspace".into());
        }
        if !config.probe_registry_path.starts_with(&workspace)
            && !config.probe_registry_path.starts_with("/var/lib/oiran")
            && !cfg!(test)
        {
            return Err("probe registry path escapes the allowlist".into());
        }
        let probe_registry = ProbeRegistry::load(config.probe_registry_path)?;
        let derived_import_root = config
            .derived_import_root
            .canonicalize()
            .map_err(io_error)?;
        if !derived_import_root.starts_with(&workspace) && !cfg!(test) {
            return Err("derived import root escapes workspace".into());
        }
        for path in [&config.lte_evidence_root, &config.lte_evidence_bundle_root] {
            if !path.starts_with(&workspace) && !path.starts_with("/var/lib/oiran") && !cfg!(test) {
                return Err("LTE evidence path escapes the allowlist".into());
            }
            fs::create_dir_all(path).map_err(io_error)?;
        }
        let lte_evidence_store = LteEvidenceStore::new(config.lte_evidence_root.clone())
            .map_err(|error| error.to_string())?;
        let lte_evidence_bundle_root = config
            .lte_evidence_bundle_root
            .canonicalize()
            .map_err(io_error)?;
        // 2.14.9 : les compteurs du patcher et du cache partagent le
        // même Arc pour que `/api/v1/version.read_time_patch.cache.*`
        // reflète fidèlement l'activité du LRU.
        let read_time_patch_counters = Arc::new(read_time_patch::PatchCounters::new());
        let raw_index_cache = read_time_patch::RawIndexCache::new(
            read_time_patch::CacheLimits::from_env(),
            read_time_patch_counters.clone(),
        );
        let compact_index_registry = Arc::new(read_time_patch::CompactJsonlIndexRegistry::new(
            read_time_patch_counters.clone(),
        ));
        Ok(Self {
            inner: Arc::new(Inner {
                flows: BTreeMap::new(),
                flow_values: BTreeMap::new(),
                flow_paths: BTreeMap::new(),
                primary_session_id: String::new(),
                manifest: json!({}),
                captures: Vec::new(),
                registry: DatasetRegistry::default(),
                discovery: discover_sessions(&mut Vec::new()),
                storage_path: workspace,
                capture_manager,
                continuous_import_enabled: config.continuous_import_enabled,
                probe_registry,
                derived_import_root,
                lte_evidence_store,
                lte_evidence_bundle_root,
                operator_token_sha256: config.operator_token_sha256,
                administrator_token_sha256: config.administrator_token_sha256,
                identity_vault,
                live_traces: live_trace::LiveTraceRegistry::new(),
                throughput: throughput::ThroughputRegistry::new(),
                read_time_patch_counters,
                reference_dataset_root: None,
                raw_index_cache,
                compact_index_registry,
                session_filter_signature: std::sync::Mutex::new(None),
                journey_index_cache: std::sync::Mutex::new(None),
                list_row_cache: std::sync::Mutex::new(ListRowCache::new()),
                session_filter_cache_readiness: std::sync::Mutex::new(
                    SessionFilterCacheReadiness::default(),
                ),
                generation_slot: std::sync::RwLock::new(None),
                generation_counter: std::sync::atomic::AtomicU64::new(0),
                generation_swap_refused: std::sync::Mutex::new(
                    GenerationSwapRefusedState::default(),
                ),
                pending_empty_confirmation_until: std::sync::Mutex::new(None),
                generation_swap_retry_scheduled: std::sync::Mutex::new(0),
                generation_swap_accepted_with_mismatch: std::sync::Mutex::new(
                    GenerationSwapAcceptedWithMismatchState::default(),
                ),
                sessions_catalog_cache: std::sync::Mutex::new(SessionsCatalogCache::default()),
                health_cache: std::sync::Mutex::new(None),
                health_refreshing: std::sync::atomic::AtomicBool::new(false),
                identity_cache: std::sync::Mutex::new(BTreeMap::new()),
                #[cfg(test)]
                filter_summary_resolutions: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                filter_flow_resolutions: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                filter_index_rebuilds: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                journey_index_rebuilds: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(test)]
                list_row_cache_builds: std::sync::atomic::AtomicUsize::new(0),
                session_filter_index: std::sync::RwLock::new(
                    session_filters::SessionFilterIndex::empty(),
                ),
            }),
        })
    }
}

impl AppState {
    /// 2.10.0 : reconstruit l'index des filtres Session Explorer à
    /// partir des `flows` statiques + des `callflows/` de chaque
    /// dataset publié par le `CaptureManager` (continuous +
    /// derived). Appelé à chaque rafraîchissement opérationnel.
    fn refresh_session_filter_index(&self) {
        let audit = std::env::var_os("OIRAN_SESSIONS_FILTER_PHASE_AUDIT").is_some();
        let started = std::time::Instant::now();
        // 2.18.12 (audit perf) — appelée à CHAQUE page de
        // POST /sessions/filter : relisait et re-parsait tous les call
        // flows (+ exports LTE) à chaque fois. Reconstruction seulement si
        // la signature (sessions + taille/mtime des fichiers) a changé.
        let signature = journey_signature(self);
        if let Ok(last) = self.inner.session_filter_signature.lock() {
            if last.as_ref() == Some(&signature) {
                if audit {
                    eprintln!(
                        "SESSIONS_FILTER_PHASE phase=filter_index cache=hit elapsed_ms={}",
                        started.elapsed().as_millis()
                    );
                }
                return;
            }
        }
        let mut index = session_filters::SessionFilterIndex::empty();
        for flow in self.inner.flows.values() {
            index.upsert_flow(flow);
        }
        for dataset in self.inner.capture_manager.datasets() {
            for session_id in &dataset.session_ids {
                if let Some(flow) = self
                    .inner
                    .capture_manager
                    .callflow(&dataset.dataset_id, session_id)
                {
                    index.upsert_flow(&flow);
                }
            }
        }
        // 2.15.7 — /sessions lists the LTE evidence store too; the filter
        // index did not, so « Afficher toutes les sessions » (POST
        // /sessions/filter) returned 173 sessions against 174 for GET
        // /sessions (ANR1 #10, gate pagination 2.16.0/2.5.1). Same source,
        // same bound (page 1, 100 per run) as `sessions()`.
        if let Ok(catalog) = self.inner.lte_evidence_store.catalog() {
            for manifest in catalog {
                let Ok(page) = self
                    .inner
                    .lte_evidence_store
                    .session_page(&manifest.run_id, 1, 100)
                else {
                    continue;
                };
                for record in page["data"].as_array().into_iter().flatten() {
                    let Some(session_id) = record.get("session_id").and_then(Value::as_str) else {
                        continue;
                    };
                    if let Ok(Some(flow)) = self
                        .inner
                        .lte_evidence_store
                        .callflow_for_export_by_session(session_id)
                    {
                        index.upsert_flow(&flow);
                    }
                }
            }
        }
        if let Ok(mut last) = self.inner.session_filter_signature.lock() {
            *last = Some(signature);
        }
        if let Ok(mut guard) = self.inner.session_filter_index.write() {
            *guard = index;
        }
        #[cfg(test)]
        self.inner
            .filter_index_rebuilds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if audit {
            eprintln!(
                "SESSIONS_FILTER_PHASE phase=filter_index cache=rebuild elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
    }
}

fn build_captures(dataset_dir: &FsPath, manifest: &Value) -> Result<Vec<Value>, String> {
    let captures = manifest
        .get("captures")
        .and_then(Value::as_array)
        .ok_or("manifest.captures missing")?;
    captures
        .iter()
        .map(|capture| {
            let file = capture
                .get("file")
                .and_then(Value::as_str)
                .ok_or("capture file missing")?;
            let metadata = fs::metadata(dataset_dir.join(file)).map_err(io_error)?;
            let interface = capture.get("interface").and_then(Value::as_str).unwrap_or("UNKNOWN");
            let protocol = match interface {
                "N2" => "NGAP",
                "N3" => "GTP-U",
                "N4" => "PFCP",
                "SBI" => "SBI-HTTP2",
                "S1-MME" => "S1AP",
                "S11" => "GTPv2-C",
                "S1-U" => "GTP-U",
                "S5-C" => "GTPv2-C",
                "S5-U" => "GTP-U",
                "S6a" => "Diameter",
                "Sxab" => "PFCP",
                // 2.11.0 (devmat) : IMS plane.
                "IMS" => "SIP + RTP",
                _ => "UNKNOWN",
            };
            Ok(json!({
                "capture_id": format!("sha256:{}", capture.get("sha256").and_then(Value::as_str).unwrap_or("")),
                "name": file,
                "interface": interface,
                "protocol": protocol,
                "checksum_sha256": capture.get("sha256"),
                "packet_count": capture.get("packets"),
                "decoded_messages": capture.get("decoded_messages"),
                "size_bytes": metadata.len(),
                "source": "CERTIFIED_DATASET_COPY",
                "status": "VALIDATED_READ_ONLY"
            }))
        })
        .collect()
}

pub fn router(state: AppState, frontend_dist: Option<PathBuf>) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/auth/me", get(auth_me))
        .route("/modules", get(modules))
        .route("/probes", get(probes).post(create_probe))
        .route("/probes/:id", get(probe))
        .route("/probes/:id/interfaces", get(probe_interfaces))
        .route("/interfaces", get(interfaces))
        .route("/metrics", get(metrics))
        .route("/storage/safety", get(storage_safety))
        .route(
            "/live/traces",
            get(live_trace::list).post(live_trace::create),
        )
        .route(
            "/live/traces/:id",
            axum::routing::delete(live_trace::remove),
        )
        .route("/live/traces/:id/markers", post(live_trace::marker))
        .route("/live/traces/:id/stream", get(live_trace::stream))
        // 2.21.78 (ordre #9 7013448739) — débit live par session,
        // indépendant de la live trace. SSE : un event
        // `throughput_bucket` par (qfi, direction) par seconde + un
        // event `gap` à chaque octet perdu en rotation. Pas de pseudo,
        // pas d'identité : `:id` est un `session_id` opaque déjà
        // exposé par `/sessions` et `/sessions/filter`.
        .route(
            "/sessions/:id/throughput/stream",
            get(throughput::stream_for_session),
        )
        .route(
            "/live/traces/:id/sessions",
            get(live_trace::sessions_for_trace),
        )
        .route("/audit", get(live_trace::audit))
        .route("/datasets", get(datasets))
        .route("/datasets/import-derived", post(import_derived_dataset))
        .route("/lte/evidence/import", post(import_lte_evidence))
        .route("/lte/evidence/:run_id", get(lte_evidence_status))
        .route("/lte/evidence/:run_id/sessions", get(lte_evidence_sessions))
        .route(
            "/lte/evidence/:run_id/sessions/:session_id/callflow",
            get(lte_evidence_callflow),
        )
        .route("/lte/evidence/:run_id/exports", post(export_lte_evidence))
        .route("/datasets/:id", get(dataset))
        .route("/datasets/:id/sessions", get(dataset_sessions))
        .route("/ues", get(ues))
        .route("/ues/:id", get(ue))
        .route("/ues/:id/sessions", get(ue_sessions))
        .route("/captures", get(captures))
        .route("/capture-groups", get(capture_groups))
        .route("/capture-groups/:id", get(capture_group))
        .route("/captures/:id", get(capture))
        .route("/captures/:id/context", get(capture_context))
        .route("/captures/:id/metrics", get(capture_metrics))
        .route("/captures/:id/download", get(capture_download_policy))
        .route("/captures/validate", post(validate_capture))
        .route("/captures/start", post(start_capture))
        .route("/captures/:id/stop", post(stop_capture))
        .route("/sessions", get(sessions))
        .route("/sessions/filter", post(sessions_filter))
        .route("/sessions/available_causes", get(sessions_available_causes))
        // 2.19.0 — catalog + columns (ANR1 p900 2.7.0 en dépend).
        .route("/sessions/catalog", get(sessions_catalog))
        // 2.19.1 — explorateur de protocoles.
        .route("/sessions/catalog/search", get(sessions_catalog_search))
        .route("/sessions/catalog/param", get(sessions_catalog_param))
        .route("/sessions/columns", post(sessions_columns))
        .route("/sessions/:id", get(session))
        .route("/sessions/:id/procedures", get(session_procedures))
        .route("/sessions/:id/events", get(session_events))
        .route("/sessions/:id/callflow", get(session_callflow))
        .route("/sessions/:id/correlations", get(session_correlations))
        .route("/sessions/:id/identities", get(session_identities))
        .route("/subscribers", get(subscribers))
        .route("/subscribers/:pseudo/journey", get(subscriber_journey))
        .route("/subscribers/:pseudo/tmsi", get(subscriber_tmsi))
        // 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-04) — fuite L2d prouvée :
        // la valeur en clair (IMSI/MSISDN/IMEI) voyageait dans l'URL query
        // string → journaux HTTP, historique navigateur. Nouvelle route
        // POST avec `value` dans le body. Ancienne GET désactivée (410
        // Gone, sans écho de la valeur). Pagination `page` + `page_size`
        // restent côté body (pas de query string du tout).
        .route("/identities", get(identity_lookup_gone))
        .route("/identities/lookup", post(identity_lookup))
        .route("/events/:id", get(event))
        .route("/events/:id/provenance", get(provenance))
        .route("/packets", get(packets))
        .route("/packets/:id", get(packet))
        .route(
            "/packets/:capture_id/:packet_number/dissect",
            get(packet_dissect),
        )
        .route("/correlation/edges", get(correlation_edges))
        .route("/correlation/rules", get(correlation_rules))
        .route("/exports/callflow/:id", get(export_callflow))
        .with_state(state.clone());
    let mut app = Router::new().nest("/api/v1", api).fallback(api_not_found);
    if let Some(dist) = frontend_dist {
        let index = dist.join("index.html");
        app = app.fallback_service(ServeDir::new(dist).not_found_service(ServeFile::new(index)));
    }
    app.layer(from_fn(static_cache_middleware))
        .layer(CompressionLayer::new().gzip(true).br(true))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
}

/// 2.9.0 (#9): per-path Cache-Control for the SPA's static tree. The
/// ANR2 probe measured hashed `/assets/*` under the global `no-store`,
/// forcing every reload to re-download the full bundle (~0.87 GiB/h
/// per browser combined with the dataset poll). Fingerprinted asset
/// filenames are safe to cache for a year; the HTML entry point stays
/// `no-cache` so a fresh deploy's shell is picked up on the next
/// navigation. API JSON and any other response keep the global
/// `no-store` default assigned by `SetResponseHeaderLayer::if_not_present`.
async fn static_cache_middleware(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    let mut response = next.run(req).await;
    let value = if path.starts_with("/assets/") || path.contains("/assets/") {
        Some("public, max-age=31536000, immutable")
    } else if path == "/" || path == "/index.html" || path.ends_with("/index.html") {
        Some("no-cache")
    } else {
        None
    };
    if let Some(cache_control) = value {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(cache_control),
        );
    }
    response
}

fn primary_flow(state: &AppState) -> Option<&CallFlow> {
    state.inner.flows.get(&state.inner.primary_session_id)
}

fn flow_for<'a>(state: &'a AppState, id: &str) -> Option<&'a CallFlow> {
    state.inner.flows.get(id)
}

fn flow_value_for<'a>(state: &'a AppState, id: &str) -> Option<&'a Value> {
    state.inner.flow_values.get(id)
}

fn flow_path_for<'a>(state: &'a AppState, id: &str) -> Option<&'a FsPath> {
    state.inner.flow_paths.get(id).map(PathBuf::as_path)
}

/// 2.14.7 (ANR1 #10) — miroir de `live_probe::endpoint_map()`.
/// Exposé ici pour que le patcher à la lecture consomme la même table
/// IP → NF que l'ingestion ; une seule source de vérité.
fn oiran_endpoint_map() -> HashMap<String, String> {
    live_probe::endpoint_map()
}

/// 2.14.11 (ANR1 #10 6860508699) — applique le patcher à une tranche
/// d'événements en RAM via l'index compact pré-construit.
///
/// La 2.14.9 relisait `oiran_events.jsonl` en entier à chaque cache
/// miss (35 s pour 2 Go → ~60 s pour 3,4 Go côté prod, inutilisable).
/// La 2.14.11 construit UNE fois, au démarrage et en arrière-plan,
/// un index compact `hash(event_id) → byte offset` par fichier
/// JSONL de ce `dataset_root`. Les workers sont spawnés ici, au
/// premier appel sur un root : `ensure_tracking` est idempotent, et
/// `claim_build` garantit qu'un seul worker tokio démarre par
/// `CompactJsonlIndex`. Les mises à jour incrémentales
/// (`extend_from_tail`) ont lieu toutes les
/// `COMPACT_INDEX_POLL_SECONDS` secondes jusqu'à l'arrêt du service.
///
/// Statut retourné à l'appelant :
/// - `Applied` : le patch a été appliqué, les compteurs
///   `events_patched_*` et la provenance `read_time_patch.fields`
///   sur chaque événement reflètent la correction.
/// - `IndexBuilding` : l'index n'est pas encore prêt, la réponse
///   est servie SANS correction ; le handler ajoute
///   `read_time_patch.status = "index_building"` sur la réponse.
/// - `NotApplicable` : items vide ou aucun event_id cherchable ;
///   le handler NE MARQUE PAS la réponse.
fn apply_read_time_patch(
    state: &AppState,
    items: &mut Vec<Value>,
    dataset_root: &std::path::Path,
    session_id: &str,
) -> read_time_patch::PatchStatus {
    let _ = session_id; // conservé pour les logs futurs, plus de cache LRU par session en 2.14.11.
    if items.is_empty() {
        return read_time_patch::PatchStatus::NotApplicable;
    }
    let wanted: std::collections::HashSet<String> = items
        .iter()
        .filter_map(|event| event.get("event_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect();
    if wanted.is_empty() {
        return read_time_patch::PatchStatus::NotApplicable;
    }
    let bundle = state
        .inner
        .compact_index_registry
        .ensure_tracking(dataset_root);
    // Spawn des workers de construction / d'extension (idempotent).
    spawn_compact_index_workers(&state.inner.compact_index_registry, &bundle);
    if !bundle.all_ready() {
        state
            .inner
            .read_time_patch_counters
            .index_building_responses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return read_time_patch::PatchStatus::IndexBuilding;
    }
    let scoped = read_time_patch::scoped_index_from_compact(
        &bundle,
        &wanted,
        &state.inner.read_time_patch_counters,
    );
    let map = oiran_endpoint_map();
    read_time_patch::patch_flow_events(items, &scoped, &map, &state.inner.read_time_patch_counters);
    read_time_patch::PatchStatus::Applied
}

/// 2.14.11 — intervalle entre deux passes `extend_from_tail` sur
/// chaque index compact. `oiran_events.jsonl` étant append-only, la
/// passe lit uniquement les octets ajoutés depuis la dernière
/// `last_offset`. Override via `OIRAN_READ_TIME_PATCH_INDEX_POLL_SECS`
/// (tests → 1s, prod → 30s par défaut).
fn compact_index_poll_seconds() -> u64 {
    std::env::var("OIRAN_READ_TIME_PATCH_INDEX_POLL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30)
}

/// 2.14.11 — spawn, pour chaque `CompactJsonlIndex` du bundle qui
/// n'a pas encore été réclamé, un worker tokio :
///   1. `build_initial()` (streaming complet du fichier).
///   2. Boucle `extend_from_tail()` toutes les
///      `compact_index_poll_seconds` secondes.
///   3. `snapshot_into_counters` après chaque passe pour que
///      `/api/v1/version.read_time_patch.index.*` reflète la
///      progression.
/// La construction est faite dans `spawn_blocking` pour ne pas
/// bloquer le runtime ; les polls suivants aussi (la lecture
/// streaming peut toucher plusieurs centaines de MiB).
fn spawn_compact_index_workers(
    registry: &Arc<read_time_patch::CompactJsonlIndexRegistry>,
    bundle: &Arc<read_time_patch::DatasetIndexes>,
) {
    let mut to_build: Vec<Arc<read_time_patch::CompactJsonlIndex>> = Vec::new();
    if let Some(flat) = &bundle.flat {
        if flat.claim_build() {
            to_build.push(flat.clone());
        }
    }
    for shard in &bundle.shards {
        if shard.claim_build() {
            to_build.push(shard.clone());
        }
    }
    // 2.15.4 — préchauffe le cache PFCP du dataset en arrière-plan, pour que
    // le premier /events ou /callflow n'ait pas à relire tous les shards.
    if let Some(first) = to_build.first() {
        let path = first.path().to_path_buf();
        let root = if path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("event-shards")
        {
            path.parent()
                .and_then(|p| p.parent())
                .map(std::path::Path::to_path_buf)
        } else {
            path.parent().map(std::path::Path::to_path_buf)
        };
        if let Some(root) = root {
            tokio::task::spawn_blocking(move || {
                let _ = read_time_patch::cached_pfcp_index(&root);
            });
        }
    }
    for index in to_build {
        let registry_clone = registry.clone();
        let poll_secs = compact_index_poll_seconds();
        tokio::task::spawn(async move {
            // Build initial en blocking (une seule fois par fichier).
            let index_for_build = index.clone();
            let registry_for_build = registry_clone.clone();
            let build_outcome = tokio::task::spawn_blocking(move || {
                let outcome = index_for_build.build_initial();
                registry_for_build.snapshot_into_counters();
                outcome
            })
            .await;
            match build_outcome {
                Ok(Ok(())) => {
                    eprintln!(
                        "{}",
                        json!({
                            "event": "READ_TIME_PATCH_INDEX_READY",
                            "path": index.path().display().to_string(),
                            "entries": index.entries(),
                            "bytes_estimate": index.bytes_estimate(),
                            "build_ms": index.build_ms(),
                        })
                    );
                }
                Ok(Err(error)) => {
                    eprintln!(
                        "{}",
                        json!({
                            "event": "READ_TIME_PATCH_INDEX_BUILD_FAILED",
                            "path": index.path().display().to_string(),
                            "error": error,
                        })
                    );
                    return;
                }
                Err(join_error) => {
                    eprintln!(
                        "{}",
                        json!({
                            "event": "READ_TIME_PATCH_INDEX_BUILD_PANICKED",
                            "path": index.path().display().to_string(),
                            "error": join_error.to_string(),
                        })
                    );
                    return;
                }
            }
            // Boucle d'extension append-only.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(poll_secs)).await;
                let index_for_tail = index.clone();
                let registry_for_tail = registry_clone.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(error) = index_for_tail.extend_from_tail() {
                        eprintln!(
                            "{}",
                            json!({
                                "event": "READ_TIME_PATCH_INDEX_EXTEND_FAILED",
                                "path": index_for_tail.path().display().to_string(),
                                "error": error,
                            })
                        );
                    }
                    registry_for_tail.snapshot_into_counters();
                })
                .await;
            }
        });
    }
}

fn live_flow_for(state: &AppState, id: &str) -> Option<(String, CallFlow)> {
    state
        .inner
        .capture_manager
        .datasets()
        .into_iter()
        .find_map(|dataset| {
            dataset
                .session_ids
                .iter()
                .any(|session_id| session_id == id)
                .then(|| {
                    state
                        .inner
                        .capture_manager
                        .callflow(&dataset.dataset_id, id)
                        .map(|flow| (dataset.dataset_id, flow))
                })
                .flatten()
        })
}

/// 2.21.13 — calcul des compteurs de `/health` (lourd : relit les
/// callflows de chaque session). Exécuté UNIQUEMENT en `spawn_blocking`.
fn compute_health_counters(state: &AppState) -> Value {
    // Reference mode populates `Inner.flows / Inner.manifest / Inner.discovery`
    // at startup. Operational mode leaves them empty by design and projects
    // its liveness via `capture_manager.dataset(CONTINUOUS_DATASET_ID)`.
    //
    // 2.7.19 (issue #9 part 2): /health MUST source its continuous counters
    // from the SAME LiveDataset that produced the latest
    // `dataset_manifest.json`. The 2.7.17 implementation summed across
    // `capture_manager.datasets().iter()`, so a recovered-failed capture
    // registered under its own dataset id added its event and session
    // counts on top of the continuous dataset (ANR2 lab: continuous
    // published 25 537/8, a residual recovered-dataset added 402/2 →
    // /health reported 25 939/10 while `dataset_manifest.json` on disk
    // stayed at 25 537/8). Reading the single continuous dataset here
    // keeps /health and the on-disk manifest trivially identical.
    let mut source_events = state
        .inner
        .flows
        .values()
        .map(|flow| flow.accounting.source_events)
        .sum::<usize>();
    let mut published_session_count = state.inner.flows.len();
    let mut ue_context_count = state.inner.discovery.ue_contexts.len();
    let mut dataset = state.inner.manifest.get("scenario_id").cloned();
    if published_session_count == 0 {
        if let Some(live) = state
            .inner
            .capture_manager
            .dataset(live_probe::CONTINUOUS_DATASET_ID)
        {
            source_events = source_events.saturating_add(live.event_count);
            published_session_count =
                published_session_count.saturating_add(live.session_ids.len());
            if let Some(discovery) = &live.discovery {
                ue_context_count = ue_context_count.saturating_add(discovery.ue_contexts.len());
            }
            if dataset.is_none() {
                dataset = Some(Value::String(live.dataset_id.clone()));
            }
        }
    }
    let queryable_session_count = queryable_session_ids(state).len();
    json!({
        "dataset":dataset,
        "source_events":source_events,
        // Same union as an unfiltered GET /sessions. The narrower continuous
        // manifest count is named explicitly instead of overloading this key.
        "session_count":queryable_session_count,
        "queryable_session_count":queryable_session_count,
        "published_session_count":published_session_count,
        "ue_context_count":ue_context_count,
        "capabilities":{"live_capture":true,"capture_control":state.inner.capture_manager.execution_enabled(),"session_analysis":true,"multi_session":true,"dataset_registry":true,"packet_analysis":true,"exports":true,"future_sse":false}
    })
}

/// 2.21.13 — durée de validité de l'instantané `/health`.
const HEALTH_SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(5);
/// 2.21.13 — attente max du tout premier calcul avant de répondre sans compteurs.
/// 2.21.22 (FAIL lab 2.21.21 : 5 réponses `/health` à 1,66–2,01 s pendant
/// `counters_status=computing`) — en production `/health` n'attend JAMAIS :
/// sans instantané il répond aussitôt `computing`, et l'instantané est
/// amorcé au démarrage (`warm_health_snapshot`). L'attente n'existe que sous
/// `cfg(test)`, où les tests lisent les compteurs dès le premier appel.
const HEALTH_FIRST_COMPUTE_WAIT: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(2)
} else {
    std::time::Duration::ZERO
};

/// 2.21.22 — amorce l'instantané `/health` au démarrage du service, en
/// arrière-plan, pour que le premier `/health` ait déjà ses compteurs.
pub fn warm_health_snapshot(state: &AppState) {
    spawn_health_refresh(state);
}

fn spawn_health_refresh(state: &AppState) {
    use std::sync::atomic::Ordering;
    if state.inner.health_refreshing.swap(true, Ordering::AcqRel) {
        return; // un recalcul est déjà en cours
    }
    let state = state.clone();
    tokio::task::spawn_blocking(move || {
        let counters = compute_health_counters(&state);
        *state.inner.health_cache.lock().unwrap() = Some((std::time::Instant::now(), counters));
        state.inner.health_refreshing.store(false, Ordering::Release);
    });
}

/// 2.21.13 (ANR1 #10 6931550052 : 20/20 `/health` en timeout pendant un
/// `/identities` froid) — `/health` lisait et parsait le callflow JSON de
/// CHAQUE session (`queryable_session_ids`) sur le runtime async : sous
/// la charge tshark + plafond mémoire, > 5 s par appel. Désormais :
/// instantané servi depuis la mémoire, recalculé en arrière-plan ; un
/// instantané périmé est servi tel quel avec son âge (`counters_age_ms`),
/// jamais en silence ; au tout premier appel, attente ≤ 2 s puis réponse
/// `counters_status = "computing"`.
async fn health(State(state): State<AppState>) -> Json<Value> {
    health_response(&state, HEALTH_FIRST_COMPUTE_WAIT).await
}

async fn health_response(state: &AppState, first_wait: std::time::Duration) -> Json<Value> {
    let state = state.clone();
    let snapshot = |state: &AppState| state.inner.health_cache.lock().unwrap().clone();
    let mut current = snapshot(&state);
    let stale = current
        .as_ref()
        .map(|(at, _)| at.elapsed() >= HEALTH_SNAPSHOT_TTL)
        .unwrap_or(true);
    if stale {
        spawn_health_refresh(&state);
    }
    if current.is_none() {
        let deadline = std::time::Instant::now() + first_wait;
        while current.is_none() && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            current = snapshot(&state);
        }
    }
    let mut data = json!({
        "status":"healthy",
        "mode":"LIVE_CAPTURE_CAPABLE_EXECUTION_GATED",
    });
    match current {
        Some((at, counters)) => {
            if let (Some(target), Some(source)) = (data.as_object_mut(), counters.as_object()) {
                for (key, value) in source {
                    target.insert(key.clone(), value.clone());
                }
                target.insert("counters_status".into(), json!(if at.elapsed() >= HEALTH_SNAPSHOT_TTL { "stale" } else { "fresh" }));
                target.insert("counters_age_ms".into(), json!(at.elapsed().as_millis() as u64));
            }
        }
        None => {
            data["counters_status"] = json!("computing");
        }
    }
    // 2.21.30 (ordre #9 6952054201) — quarantaine persistante des
    // segments décodage échoué : exposer `{count, items[]}` dans
    // `/health` pour que l'opérateur voie quels segments sont
    // définitivement exclus des cycles. `items` est capée à 32 (plus
    // récent en premier) pour ne pas gonfler la payload de health ;
    // le journal complet reste sur disque.
    let quarantine_snapshot = state.inner.capture_manager.quarantined_segments_snapshot();
    let count = quarantine_snapshot.len();
    let mut items: Vec<Value> = quarantine_snapshot
        .into_iter()
        .map(|((source_path, source_size_bytes, source_sha256), entry)| {
            json!({
                "source_path": source_path,
                "source_size_bytes": source_size_bytes,
                "source_sha256": source_sha256,
                "error_code": entry.error_code,
                "quarantined_epoch_ms": entry.quarantined_epoch_ms,
            })
        })
        .collect();
    items.sort_by(|a, b| {
        b["quarantined_epoch_ms"]
            .as_u64()
            .cmp(&a["quarantined_epoch_ms"].as_u64())
    });
    items.truncate(32);
    data["quarantined_segments"] = json!({
        "count": count,
        "items": items,
    });
    // 2.21.54 (ordre #9 6987366620 — raccord HTTP du carry HPACK) :
    // expose `hpack_carry_metrics_snapshot()` sous `data.hpack_carry`
    // pour que l'opérateur voie, par interface SBI, le nombre de
    // connexions suivies / reprises / évincées et le nombre
    // d'invalidations (fail-closed). Vide si aucun cycle SBI n'a
    // encore tourné.
    let hpack_snapshot = state.inner.capture_manager.hpack_carry_metrics_snapshot();
    let hpack_items: Vec<Value> = hpack_snapshot
        .iter()
        .map(|(iface, m)| {
            json!({
                "interface": iface,
                "connections_tracked": m.connections_tracked,
                "connections_resumed": m.connections_resumed,
                "connections_evicted": m.connections_evicted,
                "invalidations": m.invalidations,
                "off_ring_segments_decoded": m.off_ring_segments_decoded,
                "last_cycle_epoch_ms": m.last_cycle_epoch_ms,
            })
        })
        .collect();
    data["hpack_carry"] = json!({
        "interface_count": hpack_items.len(),
        "by_interface": hpack_items,
    });
    // 2.21.88 (ordre #9 7017408187) — expose les alertes de récupération
    // d'état collectées par `recover_registry` au démarrage de la
    // probe. Un `job.json` invalide récupéré depuis `.prev` apparaît
    // sous `kind: "JOB_JSON_RECOVERED_FROM_PREV"` ; un job dont les
    // deux versions sont perdues apparaît sous
    // `kind: "JOB_JSON_UNRECOVERABLE"` — l'opérateur a alors la seule
    // trace durable de l'écart. Vide si aucune corruption détectée.
    let recovery_warnings = state.inner.capture_manager.recovery_warnings_snapshot();
    let recovery_items: Vec<Value> = recovery_warnings
        .iter()
        .map(|warning| {
            json!({
                "capture_id": warning.capture_id,
                "kind": warning.kind,
                "detail": warning.detail,
                "epoch_ms": warning.epoch_ms,
            })
        })
        .collect();
    data["recovery_warnings"] = json!({
        "count": recovery_items.len(),
        "items": recovery_items,
    });
    // 2.21.92 (défaut bloquant ANR1 #10 7035121536) — compteur et dernière
    // occurrence d'un refus de bascule du double tampon READY. `total > 0`
    // signifie qu'au moins une génération candidate a été rejetée pour
    // préserver l'ancienne ; `last_reason` + `last_candidate_session_count`
    // + `last_published_session_count` donnent l'écart observé.
    let retries_scheduled_total = state
        .inner
        .generation_swap_retry_scheduled
        .lock()
        .map(|n| *n)
        .unwrap_or(0);
    let swap_refused = state
        .inner
        .generation_swap_refused
        .lock()
        .map(|g| {
            json!({
                "total": g.total,
                "last_epoch_ms": g.last_epoch_ms,
                "last_reason": g.last_reason,
                "last_candidate_session_count": g.last_candidate_session_count,
                "last_reference_session_count": g.last_reference_session_count,
                "last_trigger": g.last_trigger,
                "retries_scheduled_total": retries_scheduled_total,
            })
        })
        .unwrap_or_else(|_| {
            json!({"total": 0, "retries_scheduled_total": retries_scheduled_total})
        });
    data["sessions_filter_generation_swap_refused"] = swap_refused;
    // 2.21.94 (défaut bloquant prod ANR1 #10 7040235279) — bascules acceptées
    // malgré un écart (no_previous_generation / retries_exhausted). `total > 0`
    // signifie qu'au moins une liste légèrement écartée a été servie plutôt que
    // de renvoyer 503 permanent.
    let swap_accepted_with_mismatch = state
        .inner
        .generation_swap_accepted_with_mismatch
        .lock()
        .map(|g| {
            json!({
                "total": g.total,
                "last_epoch_ms": g.last_epoch_ms,
                "last_reason": g.last_reason,
                "last_candidate_session_count": g.last_candidate_session_count,
                "last_reference_session_count": g.last_reference_session_count,
                "last_trigger": g.last_trigger,
                "last_scenario": g.last_scenario,
            })
        })
        .unwrap_or_else(|_| json!({"total": 0}));
    data["sessions_filter_generation_swap_accepted_with_mismatch"] = swap_accepted_with_mismatch;
    ok(data)
}

async fn version(State(state): State<AppState>) -> Json<Value> {
    let flow = primary_flow(&state);
    ok(json!({
        "platform_core":PLATFORM_VERSION,"backend_api":API_VERSION,"web_frontend":WEB_FRONTEND_VERSION,
        "event_schema":"1.2.0","callflow_schema":flow.map(|value|value.schema_version.as_str()).unwrap_or("UNKNOWN"),
        "session_engine":session_engine::VERSION,"correlation_engine":correlation_engine::VERSION,"dataset_registry":dataset_registry::VERSION,
        "disk_safety":disk_safety::VERSION,
        "decoders":oiran_decode::installed_decoder_versions(),
        // 2.14.7 (ANR1 #10) — compteurs du patcher à la lecture.
        // La gate ANR1 vérifie que `callflows_loaded > 0` et que
        // `events_patched.{source_participant,direction,message_name}`
        // reflètent le nombre d'événements stale corrigés.
        "read_time_patch": state.inner.read_time_patch_counters.as_json()
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Viewer,
    Operator,
    Administrator,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Administrator => "administrator",
        }
    }
    fn can_control(self) -> bool {
        matches!(self, Self::Operator | Self::Administrator)
    }
}

fn role_from_headers(state: &AppState, headers: &HeaderMap) -> Role {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
    else {
        return Role::Viewer;
    };
    let digest = sha256_hex(token.as_bytes());
    if state.inner.administrator_token_sha256.as_deref() == Some(digest.as_str()) {
        Role::Administrator
    } else if state.inner.operator_token_sha256.as_deref() == Some(digest.as_str()) {
        Role::Operator
    } else {
        Role::Viewer
    }
}

fn require_operator(state: &AppState, headers: &HeaderMap) -> Result<Role, Response> {
    let role = role_from_headers(state, headers);
    if role.can_control() {
        Ok(role)
    } else {
        Err(api_error(
            StatusCode::FORBIDDEN,
            "OPERATOR_REQUIRED",
            "an authenticated Operator or Administrator is required",
        ))
    }
}

fn require_operator_csrf(state: &AppState, headers: &HeaderMap) -> Result<Role, Response> {
    let role = require_operator(state, headers)?;
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            api_error(
                StatusCode::FORBIDDEN,
                "CSRF_REQUIRED",
                "a valid CSRF proof header is required",
            )
        })?;
    let expected = sha256_hex(format!("oiran-csrf-v1:{bearer}").as_bytes());
    let supplied = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if supplied != Some(expected.as_str()) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REQUIRED",
            "a valid CSRF proof header is required",
        ));
    }
    Ok(role)
}

async fn auth_me(State(state): State<AppState>, headers: HeaderMap) -> Json<Value> {
    let role = role_from_headers(&state, &headers);
    let mut permissions = vec![
        "platform.read",
        "captures.read",
        "sessions.read",
        "packets.read",
        "correlation.read",
        "exports.read",
    ];
    if role.can_control() {
        permissions.extend([
            "captures.validate",
            "captures.start",
            "captures.stop",
            "probes.create",
        ]);
    }
    ok(json!({
        "authenticated":role != Role::Viewer,"role":role.name(),"permissions":permissions,
        "capture_control":role.can_control(),
        "capture_execution_enabled":state.inner.capture_manager.execution_enabled(),
        "reason":if role == Role::Viewer { "PUBLIC_VIEWER_OR_INVALID_TOKEN" } else { "SERVER_VERIFIED_BEARER" }
    }))
}

async fn storage_safety(State(state): State<AppState>) -> Json<Value> {
    let policy = Policy::default();
    let sample = measure_path(&state.inner.storage_path);
    let decision = assess(sample.clone(), policy);
    let requested = policy
        .max_file_bytes
        .saturating_mul(u64::from(policy.max_files));
    let budget = capture_budget(sample.clone(), requested, policy);
    ok(json!({
        "filesystem": sample.ok().map(|value| json!({
            "total_bytes": value.total_bytes,
            "used_bytes": value.used_bytes(),
            "available_bytes": value.available_bytes,
            "usage_percent": value.usage_percent(),
            "total_inodes": value.total_inodes,
            "available_inodes": value.available_inodes
        })),
        "decision": decision,
        "budget": budget,
        "rotation": rotation_plan(policy),
        "policy": policy,
        "capture_job": {"state":state.inner.capture_manager.list().last().map(|job| format!("{:?}",job.state).to_ascii_uppercase()).unwrap_or_else(||"IDLE".into()),"active":state.inner.capture_manager.list().iter().any(|job|job.state.active()),"writes_enabled":state.inner.capture_manager.execution_enabled()},
        "monitoring": {"poll_interval_ms":policy.polling_interval_ms,"event_driven_limit":"RESERVED_WRITE_BUDGET","failure_mode":"FAIL_CLOSED"}
    }))
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// 2.9.8 (#9 comment 6725097122): choose which `CaptureJob` feeds
/// `/metrics` pending/state fields. ANR2 observed in production that
/// the pre-2.9.8 handler filtered to `CaptureState::Capturing`
/// alone, so a BLOCKED continuous-import job (backpressure trip)
/// silently collapsed to `pending_segments=0` even though
/// `job.json` still reported the real backlog. This selector keeps
/// the same "prefer the active job" behaviour as the pre-2.9.8
/// path and falls back to the most recent BLOCKED / COMPLETED /
/// FAILED job — every state that legitimately carries a final
/// `metrics.pending_segments` number. Pure function so the
/// behaviour is unit-testable.
pub fn select_metrics_source_job<'a>(
    jobs: &'a [live_probe::CaptureJob],
) -> Option<&'a live_probe::CaptureJob> {
    if let Some(active) = jobs
        .iter()
        .filter(|job| job.state == live_probe::CaptureState::Capturing)
        .max_by_key(|job| job.started_epoch_ms.unwrap_or(job.created_epoch_ms))
    {
        return Some(active);
    }
    jobs.iter()
        .filter(|job| {
            matches!(
                job.state,
                live_probe::CaptureState::Blocked
                    | live_probe::CaptureState::Completed
                    | live_probe::CaptureState::CompletedEmpty
                    | live_probe::CaptureState::Failed
                    | live_probe::CaptureState::Processing
                    | live_probe::CaptureState::Stopping
            )
        })
        .max_by_key(|job| {
            job.ended_epoch_ms
                .or(job.started_epoch_ms)
                .unwrap_or(job.created_epoch_ms)
        })
}

fn host_memory() -> Value {
    let mut total = None;
    let mut available = None;
    for line in fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
    {
        let bytes = line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value.saturating_mul(1024));
        if line.starts_with("MemTotal:") {
            total = bytes;
        } else if line.starts_with("MemAvailable:") {
            available = bytes;
        }
    }
    json!({"total_bytes":total,"available_bytes":available,"used_bytes":total.zip(available).map(|(total,available)|total.saturating_sub(available))})
}

async fn metrics(State(state): State<AppState>) -> Json<Value> {
    // 2.21.17 (audit handlers lot 2 #9 6944132663) — mesure fs
    // (measure_path, /proc/loadavg) + iteration flows + capture_manager.
    // Déport dans spawn_blocking pour ne pas bloquer le runtime async.
    tokio::task::spawn_blocking(move || metrics_blocking(&state))
        .await
        .unwrap_or_else(|_| Json(json!({"error": "metrics handler panicked"})))
}

fn metrics_blocking(state: &AppState) -> Json<Value> {
    let sample = measure_path(&state.inner.storage_path).ok();
    let source_events = state
        .inner
        .flows
        .values()
        .map(|flow| flow.accounting.source_events)
        .sum::<usize>();
    let decode_errors = state
        .inner
        .flow_values
        .values()
        .filter_map(|flow| flow["events"].as_array())
        .flatten()
        .filter(|event| {
            event["decoding_status"] == "MALFORMED"
                || event["errors"]
                    .as_array()
                    .is_some_and(|errors| !errors.is_empty())
        })
        .count();
    let load = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let load_one = load
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok());
    let jobs = state.inner.capture_manager.list();
    let active = jobs
        .iter()
        .filter(|job| job.state == live_probe::CaptureState::Capturing)
        .collect::<Vec<_>>();
    // 2.9.8 (#9 comment 6725097122): a BLOCKED continuous-import
    // job (backpressure, disk-safety, derived-output limit) must
    // surface its pending work and stop reason on `/metrics` — not
    // silently fall back to 0 because `Capturing` is empty. ANR2
    // observed this exact masking: `/metrics pending=0` while
    // `job.json pending=1` on a BLOCKED job. We prefer the active
    // job when one exists (same shape as pre-2.9.8) and fall back
    // to the most recent BLOCKED/COMPLETED job so pending/failure
    // numbers remain visible. The `source_job` carries both the
    // metrics and the state label for the client.
    let source_job = select_metrics_source_job(&jobs);
    let latest_metrics = source_job.map(|job| &job.metrics);
    let capture_state_label = source_job.map(|job| match job.state {
        live_probe::CaptureState::Created => "CREATED",
        live_probe::CaptureState::Validating => "VALIDATING",
        live_probe::CaptureState::Ready => "READY",
        live_probe::CaptureState::Starting => "STARTING",
        live_probe::CaptureState::Capturing => "CAPTURING",
        live_probe::CaptureState::Stopping => "STOPPING",
        live_probe::CaptureState::Processing => "PROCESSING",
        live_probe::CaptureState::Completed => "COMPLETED",
        live_probe::CaptureState::CompletedEmpty => "COMPLETED_EMPTY",
        live_probe::CaptureState::Failed => "FAILED",
        live_probe::CaptureState::Blocked => "BLOCKED",
    });
    let capture_stop_reason = source_job.and_then(|job| job.stop_reason.clone());
    let capture_error = source_job.and_then(|job| job.error.clone());
    let live_datasets = state.inner.capture_manager.datasets();
    let active_ue_ips = live_datasets
        .iter()
        .filter(|dataset| {
            active.iter().any(|job| {
                job.capture_id == dataset.capture_id
                    && job.started_epoch_ms == dataset.capture_started_epoch_ms
            })
        })
        .flat_map(|dataset| dataset.active_ue_ips.iter().cloned())
        .collect::<std::collections::BTreeSet<_>>();
    let live_sessions = active_ue_ips.len();
    let live_events = live_datasets
        .iter()
        .map(|dataset| dataset.event_count)
        .sum::<usize>();
    ok(json!({
        "observed_at_epoch_s":epoch_seconds(),"mode":if active.is_empty(){"HISTORICAL_DATASET_ANALYSIS"}else{"LIVE_CAPTURE"},
        "packet_rate_pps":latest_metrics.map(|m|m.packets_per_second),"bitrate_bps":latest_metrics.map(|m|m.bits_per_second),"decode_rate_eps":latest_metrics.map(|m|m.decode_events_per_second),
        "packet_drops":latest_metrics.and_then(|m|m.packet_drops),"capture_queue_utilization_percent":latest_metrics.and_then(|m|m.queue_occupancy_percent),
        // 2.21.68 (ordre #9 7006248573) : séparation stock vs file.
        // `capture_queue_utilization_percent` reste pour back-compat UI
        // mais sourcée sur la VRAIE `queue_occupancy_percent` (0-100 %).
        // Le stock part dans `capture_owned_bytes_percent` SANS clamp
        // (peut dépasser 100 % — c'est la vérité). ANR2 7005944378 §2 :
        // 562 % jadis masqués par `.min(100.0)` sont désormais lisibles.
        "capture_owned_bytes_percent":latest_metrics.and_then(|m|m.owned_bytes_percent),
        "active_captures":active.len(),"active_sessions":live_sessions,"historical_sessions":state.inner.flows.len(),
        "historical_events":source_events,"live_events":live_events,"decode_errors":decode_errors,
        "last_ingested_epoch_ms":latest_metrics.and_then(|m|m.last_ingested_epoch_ms),
        "segments_ingested":latest_metrics.map(|m|m.segments_ingested).unwrap_or(0),
        // 2.9.8 (#9 comment 6725097122): read pending_* off
        // `source_job` — active first, else the most recent
        // BLOCKED/Completed job — so a BLOCKED continuous-import
        // worker never silently reports 0. `capture_state` and
        // `capture_stop_reason` make the state explicit; the client
        // can diagnose the stall without a separate `/jobs` call.
        // 2.11.1 (devmat, revue ANR1 #10 comment 6778895992 2.10.4
        // rollback) : TOUS les compteurs pending/open/zero sont
        // présents dès le démarrage (défaut `0` ou `[]`), jamais
        // `null`. ANR1 a observé `pending_segment_paths=null`,
        // `open_segments=null`, `zero_event_segments=null` sur
        // 2.10.4 parce que (a) ces champs n'étaient tout simplement
        // pas exposés par le handler et (b) `latest_metrics.map`
        // laisse `null` quand le job n'a pas encore produit de
        // sample. Le patch 2.11.1 unwrap toujours vers `0` / `[]`.
        "pending_segments":latest_metrics.map(|m|m.pending_segments).unwrap_or(0),
        "closed_not_ingested_segments":latest_metrics.map(|m|m.closed_not_ingested_segments).unwrap_or(0),
        "pending_fingerprints":latest_metrics.map(|m|m.pending_fingerprints).unwrap_or(0),
        "pending_stability_segments":latest_metrics.map(|m|m.pending_stability_segments).unwrap_or(0),
        "pending_batch_segments":latest_metrics.map(|m|m.pending_batch_segments).unwrap_or(0),
        "pending_segment_paths":latest_metrics.map(|m|m.pending_segment_paths.clone()).unwrap_or_default(),
        "open_segments":latest_metrics.map(|m|m.open_segments).unwrap_or(0),
        "open_segment_paths":latest_metrics.map(|m|m.open_segment_paths.clone()).unwrap_or_default(),
        "zero_event_segments":latest_metrics.map(|m|m.zero_event_segments).unwrap_or(0),
        "zero_event_segment_paths":latest_metrics.map(|m|m.zero_event_segment_paths.clone()).unwrap_or_default(),
        "orphan_fingerprints_recovered":latest_metrics.map(|m|m.orphan_fingerprints_recovered).unwrap_or(0),
        // 2.21.68 (ordre #9 7006248573) : segments quarantinés visibles
        // dans le dernier scan (PCAPNG tronqués, décodeurs en échec, etc.).
        // Sortis de `pending_segments` : ils ne sont plus en attente mais
        // en dette de quarantaine, exposée séparément pour l'opérateur.
        "quarantined_segments":latest_metrics.map(|m|m.quarantined_segments).unwrap_or(0),
        "quarantined_segment_paths":latest_metrics.map(|m|m.quarantined_segment_paths.clone()).unwrap_or_default(),
        "capture_state":capture_state_label,
        "capture_stop_reason":capture_stop_reason,
        "capture_error":capture_error,
        "ingestion_failures":latest_metrics.map(|m|m.ingestion_failures).unwrap_or(0),
        "last_packet_epoch_ms":latest_metrics.and_then(|m|m.last_packet_epoch_ms),
        "fresh_packet_count":latest_metrics.map(|m|m.fresh_packet_count).unwrap_or(0),
        "active_ue_ips":active_ue_ips,
        "cpu":{"usage_percent":Value::Null,"load_one":load_one,"logical_cpus":std::thread::available_parallelism().map(|value|value.get()).unwrap_or(1)},
        "memory":host_memory(),
        "disk":sample.map(|value|json!({"usage_percent":value.usage_percent(),"available_bytes":value.available_bytes,"available_inodes":value.available_inodes})),
        "interfaces":[
            {"interface":"NG-C","capture_interface":"N2","state":if active.is_empty(){"REFERENCE_ONLY"}else{"INGESTING"},"packet_rate_pps":Value::Null},
            {"interface":"SBI","capture_interface":"SBI","state":if active.is_empty(){"REFERENCE_ONLY"}else{"INGESTING"},"packet_rate_pps":Value::Null},
            {"interface":"N4","capture_interface":"N4","state":if active.is_empty(){"REFERENCE_ONLY"}else{"INGESTING"},"packet_rate_pps":Value::Null},
            {"interface":"NG-U","capture_interface":"N3","state":if active.is_empty(){"REFERENCE_ONLY"}else{"INGESTING"},"packet_rate_pps":Value::Null}
        ]
    }))
}

async fn modules() -> Json<Value> {
    ok(json!([
        module(
            "overview",
            "2.0.0-dev",
            "/overview",
            "Overview",
            "overview",
            ["platform.read"],
            true
        ),
        module(
            "probe-manager",
            "2.0.0-dev",
            "/operations/probes",
            "Probe Manager",
            "operations",
            ["captures.read"],
            true
        ),
        module(
            "session-explorer",
            "2.0.0-dev",
            "/investigation/sessions",
            "Session Explorer",
            "investigation",
            ["sessions.read"],
            true
        ),
        module(
            "callflow-viewer",
            "2.0.0-dev",
            "/investigation/callflow",
            "Call Flow Viewer",
            "investigation",
            ["callflow.read"],
            true
        ),
        module(
            "correlation-studio",
            "2.0.0-dev",
            "/investigation/correlation",
            "Correlation Studio",
            "investigation",
            ["correlation.read"],
            true
        ),
        module(
            "packet-analyzer",
            "2.0.0-dev",
            "/analysis/packets",
            "Packet Analyzer",
            "analysis",
            ["packets.read"],
            true
        ),
        module(
            "export-reports",
            "2.0.0-dev",
            "/reports/exports",
            "Export & Reports",
            "reports",
            ["exports.read"],
            true
        ),
        module(
            "live-monitoring",
            "2.0.0-dev",
            "/reports/monitoring",
            "Live Monitoring",
            "reports",
            ["metrics.read"],
            true
        ),
        module(
            "settings",
            "1.0.0-dev",
            "/platform/settings",
            "Settings",
            "platform",
            ["platform.read"],
            true
        ),
        module(
            "module-versions",
            "1.0.0-dev",
            "/platform/versions",
            "Module Versions",
            "platform",
            ["platform.read"],
            true
        )
    ]))
}

fn module<const N: usize>(
    id: &str,
    version: &str,
    route: &str,
    label: &str,
    section: &str,
    permissions: [&str; N],
    enabled: bool,
) -> Value {
    let permissions = permissions.into_iter().collect::<Vec<_>>();
    json!({"module_id":id,"module_version":version,"compatible_core_api":"^2.0","required_capabilities":[],"route":route,"navigation":{"label":label,"section":section},"permissions":permissions,"feature_flags":{},"enabled":enabled})
}

fn measured_local_heartbeat_epoch_s(state: &AppState) -> Option<u64> {
    state
        .inner
        .capture_manager
        .list()
        .into_iter()
        .filter_map(|job| {
            job.metrics
                .last_packet_epoch_ms
                .into_iter()
                .chain(job.metrics.last_ingested_epoch_ms)
                .max()
        })
        .max()
        .map(|epoch_ms| epoch_ms / 1_000)
}

fn probe_online(last_heartbeat_epoch_s: Option<u64>, now_epoch_s: u64) -> bool {
    last_heartbeat_epoch_s.is_some_and(|heartbeat| {
        now_epoch_s >= heartbeat
            && now_epoch_s.saturating_sub(heartbeat) <= HEARTBEAT_ONLINE_WINDOW_SECONDS
    })
}

/// 2.9.3-fu1 (devmat #9) : porte unifiée. Le vProbe local EST le
/// processus API — pas de battement HTTP indépendant. Si une capture
/// est active côté local, l'online est vrai par définition (l'API
/// répond donc la sonde est joignable). Les sondes distantes passent
/// par la porte battement 15 s inchangée.
fn probe_is_reachable(
    local: bool,
    active_capture: bool,
    last_heartbeat_epoch_s: Option<u64>,
    now_epoch_s: u64,
) -> bool {
    if local && active_capture {
        true
    } else {
        probe_online(last_heartbeat_epoch_s, now_epoch_s)
    }
}

fn probe_value(state: &AppState, record: &ProbeRecord) -> Value {
    let packets = state
        .inner
        .captures
        .iter()
        .filter_map(|capture| capture["packet_count"].as_u64())
        .sum::<u64>();
    let jobs = state.inner.capture_manager.list();
    let local = record.probe_id == "oiran-vprobe-local-01";
    let active = local
        .then(|| jobs.iter().find(|job| job.state.active()))
        .flatten();
    let discovered = local
        .then(|| capture_interfaces_with_roles(state, &record.probe_id))
        .unwrap_or_default();
    let measured = local
        .then(|| measured_local_heartbeat_epoch_s(state))
        .flatten();
    let last_heartbeat_epoch_s = record.last_heartbeat_epoch_s.max(measured);
    // 2.9.3-fu1 (devmat #9) : porte unifiée via probe_is_reachable —
    // voir doc sur la fonction. Pour le local, `active.state.active()`
    // suffit à affirmer que la sonde répond.
    let active_capture = active.map(|job| job.state.active()).unwrap_or(false);
    let online = probe_is_reachable(
        local,
        active_capture,
        last_heartbeat_epoch_s,
        epoch_seconds(),
    );
    let lifecycle = if last_heartbeat_epoch_s.is_none() && !online {
        "PENDING"
    } else if online {
        "ONLINE"
    } else {
        "DEGRADED"
    };
    json!({
        "probe_id":record.probe_id,"name":record.name,"host":record.host,"mgmt_ip":record.mgmt_ip,"site":record.site,
        "probe_type":record.probe_type,"version":PLATFORM_VERSION,"health":lifecycle,"online":online,
        "api_state":if online {"API_CONNECTED"} else {"API_DISCONNECTED"},"probe_state":format!("PROBE_{lifecycle}"),
        "connected_interfaces":discovered.iter().filter(|item|item.available).map(|item|item.interface.clone()).collect::<Vec<_>>(),
        "capture_state":active.map(|job|format!("{:?}",job.state).to_ascii_uppercase()).unwrap_or_else(||"IDLE".into()),"last_heartbeat_epoch_s":last_heartbeat_epoch_s,
        "packet_rate_pps":active.map(|job|job.metrics.packets_per_second),"decode_rate_eps":active.map(|job|job.metrics.decode_events_per_second),"packet_drops":active.and_then(|job|job.metrics.packet_drops),
        "cpu_usage_percent":Value::Null,"memory_usage_bytes":Value::Null,"disk_usage_percent":Value::Null,
        "historical_packet_count":if local {Some(packets)} else {None},"distributed":!local,"telemetry_status":lifecycle,
        "capture_control_available":local && state.inner.capture_manager.execution_enabled(),
        "live_sessions_available":local && state.inner.capture_manager.datasets().iter().any(|dataset|!dataset.session_ids.is_empty())
    })
}

async fn probes(State(state): State<AppState>) -> Json<Value> {
    ok(json!(state
        .inner
        .probe_registry
        .list()
        .iter()
        .map(|record| probe_value(&state, record))
        .collect::<Vec<_>>()))
}

async fn create_probe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ProbeInput>,
) -> Response {
    if let Err(response) = require_operator_csrf(&state, &headers) {
        return response;
    }
    match state.inner.probe_registry.create(input) {
        Ok(record) => (StatusCode::CREATED, ok(probe_value(&state, &record))).into_response(),
        Err(ProbeCreateError::Duplicate) => api_error(
            StatusCode::CONFLICT,
            "PROBE_ALREADY_EXISTS",
            "probe_id already exists",
        ),
        Err(ProbeCreateError::Invalid) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_PROBE_SCHEMA",
            "probe payload failed validation",
        ),
        Err(ProbeCreateError::Storage) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PROBE_REGISTRY_WRITE_FAILED",
            "probe registry could not be updated",
        ),
    }
}

async fn probe(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    state
        .inner
        .probe_registry
        .get(&id)
        .map(|record| ok(probe_value(&state, &record)).into_response())
        .unwrap_or_else(|| api_error(StatusCode::NOT_FOUND, "PROBE_NOT_FOUND", "unknown probe id"))
}

async fn probe_interfaces(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if state.inner.probe_registry.get(&id).is_none() {
        return api_error(StatusCode::NOT_FOUND, "PROBE_NOT_FOUND", "unknown probe id");
    }
    ok(json!(capture_interfaces_with_roles(&state, &id))).into_response()
}

async fn interfaces(State(state): State<AppState>) -> Json<Value> {
    let items = capture_interfaces_with_roles(&state, "oiran-vprobe-local-01").into_iter().map(|item| json!({
        "interface":item.interface,"role":item.role,"protocol":item.protocol,"capture_point":item.capture_point,
        "device":item.device,"source":"oiran-vprobe-local-01","status":if item.available{"AVAILABLE"}else{"UNAVAILABLE"},
        "packet_count":Value::Null,"file_size":Value::Null,"capture_start":Value::Null,"capture_end":Value::Null,
        "live_capture_available":item.available && state.inner.capture_manager.execution_enabled(),"reason":item.reason
    })).collect::<Vec<_>>();
    ok(json!(items))
}

fn capture_interfaces_with_roles(
    state: &AppState,
    probe_id: &str,
) -> Vec<live_probe::CaptureInterface> {
    let Some(record) = state.inner.probe_registry.get(probe_id) else {
        return Vec::new();
    };
    if probe_id == "oiran-vprobe-local-01" {
        return state
            .inner
            .capture_manager
            .interfaces()
            .into_iter()
            .map(|mut interface| {
                interface.role = record
                    .interfaces
                    .iter()
                    .find(|registered| {
                        registered.interface == interface.device
                            || registered.interface == interface.interface
                    })
                    .map(|registered| registered.role.clone());
                interface
            })
            .collect();
    }
    record
        .interfaces
        .into_iter()
        .map(|interface| live_probe::CaptureInterface {
            interface: interface.interface.clone(),
            role: Some(interface.role.clone()),
            device: interface.interface,
            protocol: protocol_for_role(&interface.role).into(),
            capture_point: format!("{} registry", record.site),
            bpf_filter: interface.bpf_filter,
            available: false,
            operstate: "PENDING".into(),
            reason: Some("HEARTBEAT_NOT_OBSERVED".into()),
        })
        .collect()
}

fn protocol_for_role(role: &str) -> &'static str {
    match role {
        "N2" => "NGAP / SCTP",
        "N3" => "GTP-U / UDP",
        "N4" => "PFCP / UDP",
        "S1" => "S1AP / SCTP",
        "N6" => "IP",
        _ => "UNKNOWN",
    }
}

fn parse_session_identity(session_id: &str) -> (String, String) {
    let without_technology = session_id.strip_prefix("5g-").unwrap_or(session_id);
    if let Some((ue, pdu)) = without_technology.rsplit_once("-pdu-") {
        (ue.to_owned(), pdu.to_owned())
    } else {
        ("UNKNOWN_UE".into(), "UNKNOWN".into())
    }
}

fn primary_context_id(state: &AppState, pdu_session_id: &str) -> Option<String> {
    let ran = state.inner.manifest["identifiers"]["ran_ue_ngap_id"].to_string();
    let amf = state.inner.manifest["identifiers"]["amf_ue_ngap_id"].to_string();
    let manifest_pdu = state.inner.manifest["identifiers"]["pdu_session_id"].to_string();
    if pdu_session_id != manifest_pdu {
        return None;
    }
    state
        .inner
        .discovery
        .ue_contexts
        .iter()
        .find(|context| {
            context.ran_ue_ngap_id.as_deref() == Some(ran.as_str())
                && context.amf_ue_ngap_id.as_deref() == Some(amf.as_str())
        })
        .map(|context| context.context_id.clone())
}

fn discovered_session_for_flow<'a>(
    state: &'a AppState,
    flow: &CallFlow,
) -> Option<&'a session_engine::DiscoveredPduSession> {
    state
        .inner
        .discovery
        .pdu_sessions
        .iter()
        .find(|session| session.session_id == flow.session_id)
        .or_else(|| {
            state.inner.discovery.pdu_sessions.iter().find(|session| {
                !session.event_ids.is_empty()
                    && session
                        .event_ids
                        .iter()
                        .all(|id| flow.events.iter().any(|event| &event.event_id == id))
            })
        })
}

fn ue_summary(state: &AppState, context: &session_engine::DiscoveredUeContext) -> Value {
    let primary = primary_context_id(
        state,
        &state.inner.manifest["identifiers"]["pdu_session_id"].to_string(),
    )
    .as_deref()
        == Some(context.context_id.as_str());
    let session_count = state
        .inner
        .flows
        .values()
        .map(|flow| session_summary(state, flow))
        .filter(|summary| summary["ue_context_id"] == context.context_id)
        .count();
    json!({
        "ue_context_id":context.context_id,
        "ue_pseudonym":if primary { "UE-A" } else { context.pseudonym.as_str() },
        "ran_ue_ngap_id":context.ran_ue_ngap_id,
        "amf_ue_ngap_id":context.amf_ue_ngap_id,
        "ran_endpoint":context.ran_endpoint,
        "amf_endpoint":context.amf_endpoint,
        "association_id":context.association_id,
        "lifecycle_generation":context.lifecycle_generation,
        "state":context.state,
        "first_timestamp_ns":context.first_timestamp_ns.to_string(),
        "last_timestamp_ns":context.last_timestamp_ns.to_string(),
        "event_count":context.event_ids.len(),
        "session_count":session_count
    })
}

fn live_ue_summary(
    dataset: &live_probe::LiveDataset,
    context: &session_engine::DiscoveredUeContext,
) -> Value {
    let session_count = dataset
        .discovery
        .as_ref()
        .map(|discovery| {
            discovery
                .pdu_sessions
                .iter()
                .filter(|session| session.ue_context_id == context.context_id)
                .count()
        })
        .unwrap_or(0);
    json!({
        "ue_context_id":context.context_id,"ue_pseudonym":context.pseudonym,
        "ran_ue_ngap_id":context.ran_ue_ngap_id,"amf_ue_ngap_id":context.amf_ue_ngap_id,
        "ran_endpoint":context.ran_endpoint,"amf_endpoint":context.amf_endpoint,
        "association_id":context.association_id,"lifecycle_generation":context.lifecycle_generation,
        "state":context.state,"first_timestamp_ns":context.first_timestamp_ns.to_string(),
        "last_timestamp_ns":context.last_timestamp_ns.to_string(),"event_count":context.event_ids.len(),
        "session_count":session_count,"dataset_id":dataset.dataset_id,"dataset_kind":"CAPTURED_LIVE"
    })
}

#[derive(Deserialize, Default, Clone)]
struct ListQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    search: Option<String>,
    interface: Option<String>,
    protocol: Option<String>,
    association: Option<String>,
    sort: Option<String>,
    order: Option<String>,
    dataset_id: Option<String>,
    dataset_kind: Option<String>,
    ue_id: Option<String>,
    technology: Option<String>,
    status: Option<String>,
    capture_id: Option<String>,
    event_id: Option<String>,
    packet_number: Option<u64>,
}

#[derive(Deserialize, Default, Clone)]
struct CallflowQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

fn dataset_values(state: &AppState) -> Vec<Value> {
    let mut items = state
        .inner
        .registry
        .list()
        .into_iter()
        .filter_map(|record| serde_json::to_value(record).ok())
        .map(|mut value| {
            let dataset_id = value["dataset_id"].as_str().unwrap_or("UNKNOWN");
            let session_ids = state
                .inner
                .flows
                .values()
                .filter(|flow| session_summary(state, flow)["dataset_id"] == dataset_id)
                .map(|flow| Value::String(flow.session_id.clone()))
                .collect::<Vec<_>>();
            let packet_count = value["captures"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|capture| capture["packet_count"].as_u64())
                .sum::<u64>();
            let object = value
                .as_object_mut()
                .expect("dataset record serializes as object");
            object.insert("dataset_kind".into(), Value::String("HISTORICAL".into()));
            object.insert("source".into(), Value::String("CERTIFIED_REFERENCE".into()));
            object.insert("technology".into(), Value::String("5G SA".into()));
            object.insert("session_ids".into(), Value::Array(session_ids));
            object.insert("packet_count".into(), Value::from(packet_count));
            object.insert(
                "normalized_event_count".into(),
                object.get("event_count").cloned().unwrap_or(Value::from(0)),
            );
            object.insert(
                "pdu_session_count".into(),
                object
                    .get("session_count")
                    .cloned()
                    .unwrap_or(Value::from(0)),
            );
            object.insert("capture_start_timestamp".into(), Value::Null);
            object.insert("capture_end_timestamp".into(), Value::Null);
            object.insert("accounting_status".into(), Value::String("COMPLETE".into()));
            value
        })
        .collect::<Vec<_>>();
    items.extend(
        state
            .inner
            .capture_manager
            .datasets()
            .into_iter()
            .filter_map(|dataset| {
                let job = state.inner.capture_manager.get(&dataset.capture_id);
                let packet_count = dataset
                    .decode_reports
                    .values()
                    .map(|report| report.packets)
                    .sum::<usize>();
                let decode_errors = dataset
                    .decode_reports
                    .values()
                    .map(|report| {
                        report.transport_errors + report.sctp_errors + report.incomplete_sctp
                    })
                    .sum::<usize>();
                let recovered = dataset.dataset_id.starts_with("recovered-dataset-");
                let derived = dataset.dataset_id.starts_with("derived-");
                let active_contexts = job
                    .as_ref()
                    .filter(|item| {
                        item.state == live_probe::CaptureState::Capturing
                            && item.started_epoch_ms == dataset.capture_started_epoch_ms
                    })
                    .map(|_| dataset.active_pdu_contexts.len())
                    .unwrap_or(0);
                let active_session_ids = if active_contexts > 0 {
                    dataset
                        .active_pdu_contexts
                        .iter()
                        .map(|context| context.session_id.clone())
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                let historical_contexts = dataset
                    .session_ids
                    .iter()
                    .filter(|session_id| !active_session_ids.contains(session_id))
                    .count();
                let (interface_type, size_bytes) = capture_observation(job.as_ref());
                Some(json!({
                    "dataset_id":dataset.dataset_id,
                    "display_name":dataset.dataset_id,
                    "dataset_kind":if derived {"DERIVED"} else if recovered {"RECOVERED"} else {"CAPTURED_LIVE"},
                    "source":if derived {"OFFLINE_DERIVED_REPLAY"} else if recovered {"OFFLINE_RECOVERY"} else {"LIVE_CAPTURE"},
                    "technology":technology_for_live_dataset(&dataset, job.as_ref()),
                    "capture_id":dataset.capture_id,
                    "captures":[{"capture_id":dataset.capture_id,"probe_id":job.as_ref().map(|item|item.probe_id.as_str()).unwrap_or("oiran-vprobe-local-01"),"interface_type":interface_type,"packet_count":packet_count,"size_bytes":size_bytes}],
                    "capture_start_timestamp":job.as_ref().and_then(|item|item.started_epoch_ms),
                    "capture_end_timestamp":job.as_ref().and_then(|item|item.ended_epoch_ms),
                    "ingestion_status":dataset.state,
                    "ingestion_generation":1,
                    "session_count":if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID {active_contexts} else {dataset.session_ids.len()},
                    "session_ids":if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID {active_session_ids} else {dataset.session_ids.clone()},
                    "historical_context_session_count":if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID {historical_contexts} else {0},
                    "ue_context_count":dataset.discovery.as_ref().map(|value|value.ue_contexts.len()),
                    "pdu_session_count":if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID {active_contexts} else {dataset.session_ids.len()},
                    "event_count":dataset.event_count,
                    "normalized_event_count":dataset.event_count,
                    "packet_count":packet_count,
                    "background_event_count":dataset.discovery.as_ref().map(|value|value.background_event_ids.len()),
                    "unmatched_event_count":dataset.discovery.as_ref().map(|value|value.unmatched_event_ids.len()),
                    "duplicate_observation_count":dataset.discovery.as_ref().map(|value|value.duplicate_observations.len()),
                    "error_count":decode_errors,
                    "decode_reports":dataset.decode_reports,
                    "checksums":dataset.checksums,
                    "decoder_versions":{},
                    "accounting_status":"INCREMENTAL_DEDUPLICATED",
                    "capture_started_epoch_ms":dataset.capture_started_epoch_ms,
                    "last_packet_epoch_ms":dataset.last_packet_epoch_ms,
                    "fresh_packet_count":dataset.fresh_packet_count,
                    "active_ue_ips":dataset.active_ue_ips,
                    "active_pdu_contexts":dataset.active_pdu_contexts,
                    "read_only":true
                }))
            }),
    );
    if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
        items.extend(
            catalog
                .into_iter()
                .map(|manifest| lte_dataset_summary(&manifest)),
        );
    }
    items
}

/// 2.9.0 (#9): the `/datasets` list view. Produces the same items as
/// `dataset_values` with the heavy per-plane payloads removed:
///
/// * `decode_reports` — 503 KiB on the ANR2 production probe. Available
///   on `GET /datasets/{id}`.
/// * `checksums` — 204 KiB on the same probe. Also moved to the single
///   dataset endpoint.
/// * `active_pdu_contexts` — the full object graph (packet references
///   per context) is replaced by a scalar count; the full list stays on
///   `GET /datasets/{id}`.
///
/// The lightweight response combined with the ETag/304 flow kills the
/// ~0.87 GiB/h/browser bandwidth ANR2 measured under the 3 s dataset
/// poll.
fn dataset_summary_values(state: &AppState) -> Vec<Value> {
    let mut items = dataset_values(state);
    for item in &mut items {
        if let Some(object) = item.as_object_mut() {
            object.remove("decode_reports");
            object.remove("checksums");
            if let Some(contexts) = object.remove("active_pdu_contexts") {
                let count = contexts.as_array().map(Vec::len).unwrap_or(0);
                object.insert("active_pdu_context_count".into(), Value::from(count));
            }
        }
    }
    items
}

fn technology_from_interfaces<'a>(interfaces: impl Iterator<Item = &'a str>) -> &'static str {
    let observed = interfaces.collect::<Vec<_>>();
    if observed
        .iter()
        .any(|value| matches!(*value, "S1-MME" | "S11" | "S1-U"))
    {
        "LTE"
    } else if observed
        .iter()
        .any(|value| matches!(*value, "N2" | "N3" | "N4" | "SBI"))
    {
        "5G SA"
    } else {
        "UNKNOWN"
    }
}

// 2.9.2 (#9 Analyzer T5): dataset-continuous-lab-import used to report
// `technology: UNKNOWN` until `decode_reports` had its first plane entry
// — so the Analyzer top-bar aggregated "UNKNOWN / LTE" while the open
// session was already 5G SA. Prefer the plane-observed inference, then
// fall back to the declared capture job profile (`POLARIS_5G_SA_*` →
// 5G SA, `POLARIS_LTE_*` → LTE). Never claim 5G or LTE without a signal
// from one of these two sources.
fn technology_for_live_dataset(
    dataset: &live_probe::LiveDataset,
    job: Option<&live_probe::CaptureJob>,
) -> &'static str {
    technology_for_live_fallback(
        dataset.decode_reports.keys().map(String::as_str),
        job.map(|item| item.profile.as_str()),
    )
}

fn technology_for_live_fallback<'a>(
    planes: impl Iterator<Item = &'a str>,
    profile: Option<&str>,
) -> &'static str {
    let inferred = technology_from_interfaces(planes);
    if inferred != "UNKNOWN" {
        return inferred;
    }
    match profile {
        Some(profile) if profile.contains("5G_SA") => "5G SA",
        Some(profile) if profile.contains("LTE") => "LTE",
        _ => "UNKNOWN",
    }
}

fn lte_dataset_summary(manifest: &LteDatasetManifest) -> Value {
    json!({
        "dataset_id":manifest.dataset_id,
        "display_name":manifest.dataset_id,
        "dataset_kind":"EVIDENCE",
        "source":"ADMITTED_SANITIZED_EVIDENCE",
        "technology":"LTE",
        "ingestion_status":"IMPORTED",
        "ingestion_generation":1,
        "session_count":manifest.session_ids.len(),
        "session_ids":manifest.session_ids,
        "ue_context_count":Value::Null,
        "pdu_session_count":manifest.session_ids.len(),
        "event_count":manifest.event_count,
        "normalized_event_count":manifest.event_count,
        "packet_count":Value::Null,
        "background_event_count":Value::Null,
        "unmatched_event_count":Value::Null,
        "duplicate_observation_count":Value::Null,
        "error_count":0,
        "decoder_versions":manifest.decoder_versions,
        "accounting_status":"ATOMIC_SANITIZED_IMPORT",
        "sanitization_state":manifest.sanitization_state,
        "read_only":true
    })
}

fn capture_observation(job: Option<&live_probe::CaptureJob>) -> (Option<String>, Option<u64>) {
    (
        job.map(|item| item.interfaces.join(" + ")),
        job.map(|item| item.metrics.storage_bytes),
    )
}

fn dataset_for_capture(state: &AppState, capture_id: &str) -> Option<Value> {
    dataset_values(state).into_iter().find(|dataset| {
        dataset["capture_id"].as_str() == Some(capture_id)
            || dataset["captures"].as_array().is_some_and(|captures| {
                captures
                    .iter()
                    .any(|capture| capture["capture_id"].as_str() == Some(capture_id))
            })
    })
}

fn enrich_capture(state: &AppState, mut capture: Value) -> Value {
    let Some(capture_id) = capture["capture_id"].as_str().map(str::to_owned) else {
        return capture;
    };
    let Some(dataset) = dataset_for_capture(state, &capture_id) else {
        return capture;
    };
    let Some(object) = capture.as_object_mut() else {
        return capture;
    };
    object.insert("dataset_id".into(), dataset["dataset_id"].clone());
    object.insert(
        "dataset_state".into(),
        dataset
            .get("ingestion_status")
            .or_else(|| dataset.get("state"))
            .cloned()
            .unwrap_or(Value::String("UNKNOWN".into())),
    );
    object.insert(
        "dataset_kind".into(),
        Value::String(
            if dataset["dataset_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("derived-"))
            {
                "DERIVED"
            } else if dataset["dataset_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("recovered-dataset-"))
            {
                "RECOVERED"
            } else if dataset.get("capture_id").is_some() {
                "CAPTURED_LIVE"
            } else {
                "HISTORICAL"
            }
            .into(),
        ),
    );
    object.insert(
        "session_ids".into(),
        dataset.get("session_ids").cloned().unwrap_or_else(|| {
            Value::Array(
                state
                    .inner
                    .flows
                    .values()
                    .filter(|flow| {
                        session_summary(state, flow)["dataset_id"] == dataset["dataset_id"]
                    })
                    .map(|flow| Value::String(flow.session_id.clone()))
                    .collect(),
            )
        }),
    );
    if object.get("probe_id").is_none() {
        let probe_id = dataset["captures"]
            .as_array()
            .and_then(|captures| {
                captures
                    .iter()
                    .find(|item| item["capture_id"] == capture_id)
            })
            .and_then(|item| item["probe_id"].as_str())
            .unwrap_or("oiran-vprobe-local-01");
        object.insert("probe_id".into(), Value::String(probe_id.into()));
    }
    capture
}

/// 2.9.0 (#9): the list view now returns a LIGHTWEIGHT dataset
/// summary. The heavy per-plane `decode_reports` (503 KiB on the ANR2
/// production probe) and `checksums` (204 KiB) are moved exclusively to
/// `GET /datasets/{id}`. A weak `ETag` is emitted from the hash of the
/// response body so a client polling every 3 s can re-validate with
/// `If-None-Match` and receive `304 Not Modified` while the dataset
/// list is unchanged.
async fn datasets(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
    headers: HeaderMap,
) -> Response {
    let mut items = dataset_summary_values(&state);
    if let Some(search) = query.search.as_deref() {
        let search = search.to_ascii_lowercase();
        items.retain(|item| item.to_string().to_ascii_lowercase().contains(&search));
    }
    sort_values(
        &mut items,
        query.sort.as_deref().unwrap_or("dataset_id"),
        query.order.as_deref(),
    );
    let payload = paginated(items, &query);
    let body = serde_json::to_vec(&payload.0).unwrap_or_default();
    let etag = format!("W/\"{}\"", &sha256_hex(&body)[..16]);
    if let Some(if_none_match) = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
    {
        if if_none_match == etag {
            let mut response = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .body(Body::empty())
                .unwrap();
            let header_value = HeaderValue::from_str(&etag).unwrap();
            response.headers_mut().insert(header::ETAG, header_value);
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-cache"),
            );
            return response;
        }
    }
    let mut response = (StatusCode::OK, payload).into_response();
    if let Ok(header_value) = HeaderValue::from_str(&etag) {
        response.headers_mut().insert(header::ETAG, header_value);
    }
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    response
}

#[derive(Debug, Deserialize)]
struct DerivedDatasetImportRequest {
    dataset_id: String,
}

async fn import_derived_dataset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DerivedDatasetImportRequest>,
) -> Response {
    let role = match require_operator(&state, &headers) {
        Ok(role) => role,
        Err(response) => return response,
    };
    match state.inner.capture_manager.import_derived_dataset(
        &state.inner.derived_import_root,
        &request.dataset_id,
        role.name(),
    ) {
        Ok(report) => (StatusCode::OK, ok(json!(report))).into_response(),
        Err(error) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "DERIVED_DATASET_IMPORT_REJECTED",
            &error,
        ),
    }
}

async fn import_lte_evidence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LteEvidenceImportPayload>,
) -> Response {
    if let Err(response) = require_operator_csrf(&state, &headers) {
        return response;
    }
    let request = match payload.into_request() {
        Ok(request) => request,
        Err(error) => return lte_evidence_error(error),
    };
    let bundle = state
        .inner
        .lte_evidence_bundle_root
        .join(&request.bundle_id);
    match state.inner.lte_evidence_store.ingest(&bundle, &request) {
        Ok(result) => {
            let status = if result.idempotent {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            (status, ok(json!(result))).into_response()
        }
        Err(error) => lte_evidence_error(error),
    }
}

async fn lte_evidence_status(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> Response {
    match state.inner.lte_evidence_store.import_result(&run_id) {
        Ok(result) => ok(json!(result)).into_response(),
        Err(error) => lte_evidence_error(error),
    }
}

async fn lte_evidence_sessions(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    match state.inner.lte_evidence_store.session_page(
        &run_id,
        query.page.unwrap_or(1),
        query.page_size.unwrap_or(50),
    ) {
        Ok(mut value) => {
            // Keep the LTE pagination wire shape stable while enforcing the
            // same recursive privacy boundary as every other read route.
            sanitize_value(&mut value);
            Json(value).into_response()
        }
        Err(error) => lte_evidence_error(error),
    }
}

async fn lte_evidence_callflow(
    State(state): State<AppState>,
    Path((run_id, session_id)): Path<(String, String)>,
    Query(query): Query<CallflowQuery>,
) -> Response {
    match state.inner.lte_evidence_store.callflow_page(
        &run_id,
        &session_id,
        query.cursor.as_deref(),
        query.limit.unwrap_or(DEFAULT_CALLFLOW_PAGE_EVENTS),
    ) {
        Ok(value) => ok(value).into_response(),
        Err(error) => lte_evidence_error(error),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LteExportRequest {
    export_id: String,
    transformation: String,
}

async fn export_lte_evidence(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<LteExportRequest>,
) -> Response {
    if let Err(response) = require_operator_csrf(&state, &headers) {
        return response;
    }
    match state.inner.lte_evidence_store.export_pending_review(
        &run_id,
        &request.export_id,
        &request.transformation,
    ) {
        Ok(manifest) => (StatusCode::CREATED, ok(json!(manifest))).into_response(),
        Err(error) => lte_evidence_error(error),
    }
}

fn lte_evidence_error(error: LteEvidenceError) -> Response {
    let status = if error.code.contains("CONFLICT") {
        StatusCode::CONFLICT
    } else if error.code.contains("LIMIT_EXCEEDED") || error.code.contains("TOO_LARGE") {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if error.code.contains("UNAVAILABLE") {
        StatusCode::NOT_FOUND
    } else if error.code.contains("WRITE_FAILED")
        || error.code.contains("FINALIZE_FAILED")
        || error.code.contains("SYNC_FAILED")
    {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    api_error(status, error.code, &error.detail)
}

async fn dataset(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    dataset_values(&state)
        .into_iter()
        .find(|dataset| dataset["dataset_id"] == id)
        .map(|value| ok(value).into_response())
        .unwrap_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "DATASET_NOT_FOUND",
                "unknown dataset id",
            )
        })
}

async fn dataset_sessions(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(mut query): Query<ListQuery>,
) -> Response {
    let lte_exists = state
        .inner
        .lte_evidence_store
        .catalog()
        .ok()
        .is_some_and(|items| items.iter().any(|manifest| manifest.dataset_id == id));
    if state.inner.registry.get(&id).is_none()
        && state.inner.capture_manager.dataset(&id).is_none()
        && !lte_exists
    {
        return api_error(
            StatusCode::NOT_FOUND,
            "DATASET_NOT_FOUND",
            "unknown dataset id",
        );
    }
    query.dataset_id = Some(id);
    sessions(State(state), Query(query)).await.into_response()
}

async fn ues(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    // 2.21.19 (audit handlers lot 3 #9 6945061505) — iteration
    // discovery.ue_contexts + capture_manager.datasets() sync. Déport
    // spawn_blocking.
    tokio::task::spawn_blocking(move || ues_blocking(&state, &query))
        .await
        .unwrap_or_else(|_| Json(json!({"error": "ues handler panicked"})))
}

fn ues_blocking(state: &AppState, query: &ListQuery) -> Json<Value> {
    let mut unique = state
        .inner
        .discovery
        .ue_contexts
        .iter()
        .map(|context| (context.context_id.clone(), ue_summary(state, context)))
        .collect::<BTreeMap<_, _>>();
    for dataset in state.inner.capture_manager.datasets() {
        if let Some(discovery) = &dataset.discovery {
            for context in &discovery.ue_contexts {
                unique.insert(
                    context.context_id.clone(),
                    live_ue_summary(&dataset, context),
                );
            }
        }
    }
    let mut items = unique.into_values().collect::<Vec<_>>();
    if let Some(search) = query.search.as_deref() {
        let search = search.to_ascii_lowercase();
        items.retain(|item| item.to_string().to_ascii_lowercase().contains(&search));
    }
    sort_values(
        &mut items,
        query.sort.as_deref().unwrap_or("first_timestamp_ns"),
        query.order.as_deref(),
    );
    paginated(items, query)
}

async fn ue(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    // 2.21.19 — iteration capture_manager.datasets() + discovery sync.
    tokio::task::spawn_blocking(move || {
        if let Some(value) = state
            .inner
            .discovery
            .ue_contexts
            .iter()
            .find(|context| context.context_id == id)
            .map(|context| ok(ue_summary(&state, context)).into_response())
        {
            return value;
        }
        for dataset in state.inner.capture_manager.datasets() {
            if let Some(context) = dataset.discovery.as_ref().and_then(|discovery| {
                discovery
                    .ue_contexts
                    .iter()
                    .find(|context| context.context_id == id)
            }) {
                return ok(live_ue_summary(&dataset, context)).into_response();
            }
        }
        api_error(
            StatusCode::NOT_FOUND,
            "UE_NOT_FOUND",
            "unknown UE context id",
        )
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UE_HANDLER_FAILED",
            "ue handler panicked",
        )
    })
}

async fn ue_sessions(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(mut query): Query<ListQuery>,
) -> Response {
    let historical = state
        .inner
        .discovery
        .ue_contexts
        .iter()
        .any(|context| context.context_id == id);
    let live = state
        .inner
        .capture_manager
        .datasets()
        .iter()
        .any(|dataset| {
            dataset.discovery.as_ref().is_some_and(|discovery| {
                discovery
                    .ue_contexts
                    .iter()
                    .any(|context| context.context_id == id)
            })
        });
    if !historical && !live {
        return api_error(
            StatusCode::NOT_FOUND,
            "UE_NOT_FOUND",
            "unknown UE context id",
        );
    }
    query.ue_id = Some(id);
    sessions(State(state), Query(query)).await.into_response()
}

async fn captures(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    let mut items = state
        .inner
        .captures
        .clone()
        .into_iter()
        .map(|capture| enrich_capture(&state, capture))
        .collect::<Vec<_>>();
    items.extend(
        state
            .inner
            .capture_manager
            .list()
            .into_iter()
            .filter_map(|job| serde_json::to_value(job).ok())
            .map(|capture| enrich_capture(&state, capture)),
    );
    if let Some(search) = query.search.as_deref() {
        let q = search.to_ascii_lowercase();
        items.retain(|x| x.to_string().to_ascii_lowercase().contains(&q));
    }
    if let Some(interface) = query.interface.as_deref() {
        items.retain(|x| x["interface"] == interface);
    }
    sort_values(
        &mut items,
        query.sort.as_deref().unwrap_or("name"),
        query.order.as_deref(),
    );
    paginated(items, &query)
}

async fn capture_groups(State(state): State<AppState>) -> Json<Value> {
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for job in state.inner.capture_manager.list() {
        let id = job
            .capture_group_id
            .clone()
            .unwrap_or_else(|| job.capture_id.clone());
        groups
            .entry(id)
            .or_default()
            .push(serde_json::to_value(job).unwrap_or(Value::Null));
    }
    ok(json!(groups
        .into_iter()
        .map(|(capture_group_id, jobs)| json!({
            "capture_group_id":capture_group_id,
            "jobs":jobs,
        }))
        .collect::<Vec<_>>()))
}

async fn capture_group(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let jobs = state
        .inner
        .capture_manager
        .list()
        .into_iter()
        .filter(|job| job.capture_group_id.as_deref() == Some(id.as_str()) || job.capture_id == id)
        .collect::<Vec<_>>();
    if jobs.is_empty() {
        return api_error(
            StatusCode::NOT_FOUND,
            "CAPTURE_GROUP_NOT_FOUND",
            "unknown capture group id",
        );
    }
    ok(json!({"capture_group_id":id,"jobs":jobs})).into_response()
}

async fn capture(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(job) = state.inner.capture_manager.get(&id) {
        return ok(enrich_capture(
            &state,
            serde_json::to_value(job).unwrap_or(Value::Null),
        ))
        .into_response();
    }
    state
        .inner
        .captures
        .iter()
        .find(|x| x["capture_id"] == id)
        .cloned()
        .map(|x| ok(enrich_capture(&state, x)).into_response())
        .unwrap_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "CAPTURE_NOT_FOUND",
                "unknown capture id",
            )
        })
}

async fn capture_download_policy(Path(_id): Path<String>) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error":"DOWNLOAD_POLICY_PENDING"})),
    )
        .into_response()
}

async fn capture_context(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let capture = if let Some(job) = state.inner.capture_manager.get(&id) {
        serde_json::to_value(job).unwrap_or(Value::Null)
    } else if let Some(capture) = state
        .inner
        .captures
        .iter()
        .find(|capture| capture["capture_id"] == id)
        .cloned()
    {
        capture
    } else {
        return api_error(
            StatusCode::NOT_FOUND,
            "CAPTURE_NOT_FOUND",
            "unknown capture id",
        );
    };
    let capture = enrich_capture(&state, capture);
    let dataset = dataset_for_capture(&state, &id);
    let session_ids = capture["session_ids"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let resolution = if dataset.is_none() {
        "DATASET_UNAVAILABLE"
    } else if session_ids.is_empty() {
        "NO_RECONSTRUCTED_SESSIONS"
    } else {
        "SESSIONS_AVAILABLE"
    };
    ok(json!({
        "capture": capture,
        "dataset": dataset,
        "resolution": resolution,
        "session_ids": session_ids,
        "reason": if resolution == "DATASET_UNAVAILABLE" {
            "No registered dataset is associated with this capture."
        } else if resolution == "NO_RECONSTRUCTED_SESSIONS" {
            "The dataset is valid but contains no evidence sufficient to reconstruct a session."
        } else {
            "The exact capture and dataset context resolved successfully."
        }
    }))
    .into_response()
}

async fn capture_metrics(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    state
        .inner
        .capture_manager
        .get(&id)
        .map(|job| {
            ok(json!({"capture_id":job.capture_id,"state":job.state,"metrics":job.metrics}))
                .into_response()
        })
        .unwrap_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "CAPTURE_NOT_FOUND",
                "unknown live capture id",
            )
        })
}

async fn validate_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CaptureRequest>,
) -> Response {
    let role = match require_operator(&state, &headers) {
        Ok(role) => role,
        Err(response) => return response,
    };
    let result = state.inner.capture_manager.validate(&request);
    ok(json!({"authorization":role.name(),"validation":result})).into_response()
}

async fn start_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CaptureRequest>,
) -> Response {
    let role = match require_operator(&state, &headers) {
        Ok(role) => role,
        Err(response) => return response,
    };
    match state.inner.capture_manager.start(request, role.name()) {
        Ok(job) => (
            StatusCode::ACCEPTED,
            Json(json!({"data":job,"meta":{"api_version":API_VERSION}})),
        )
            .into_response(),
        Err(error) => api_error(StatusCode::CONFLICT, "CAPTURE_START_BLOCKED", &error),
    }
}

async fn stop_capture(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let role = match require_operator(&state, &headers) {
        Ok(role) => role,
        Err(response) => return response,
    };
    match state.inner.capture_manager.stop(&id, role.name()) {
        Ok(job) => ok(serde_json::to_value(job).unwrap_or(Value::Null)).into_response(),
        Err(error) if error.contains("not found") => {
            api_error(StatusCode::NOT_FOUND, "CAPTURE_NOT_FOUND", &error)
        }
        Err(error) => api_error(StatusCode::CONFLICT, "CAPTURE_STOP_BLOCKED", &error),
    }
}

fn session_summary(state: &AppState, flow: &CallFlow) -> Value {
    let (parsed_ue, parsed_pdu) = parse_session_identity(&flow.session_id);
    let is_lte = flow.technology == "LTE";
    let discovered = discovered_session_for_flow(state, flow);
    let context = discovered.and_then(|session| {
        state
            .inner
            .discovery
            .ue_contexts
            .iter()
            .find(|context| context.context_id == session.ue_context_id)
    });
    let pdu_session_id = if is_lte {
        "EPS".to_owned()
    } else {
        discovered
            .map(|session| session.pdu_session_id.clone())
            .unwrap_or(parsed_pdu)
    };
    let ue_pseudonym = if is_lte {
        flow.session_id.replacen("lte-session-", "LTE-UE-", 1)
    } else if parsed_ue == "UNKNOWN_UE" {
        context
            .map(|context| context.pseudonym.clone())
            .unwrap_or(parsed_ue)
    } else {
        parsed_ue
    };
    let decoded = flow
        .events
        .iter()
        .filter(|event| {
            event.association == Association::Session && event.decoding_status == "DECODED"
        })
        .count();
    let partial = flow
        .events
        .iter()
        .filter(|event| {
            event.association == Association::Session && event.decoding_status == "PARTIAL"
        })
        .count();
    let duration_ns = flow
        .events
        .first()
        .and_then(|first| first.timestamp_ns.parse::<i128>().ok())
        .zip(
            flow.events
                .last()
                .and_then(|last| last.timestamp_ns.parse::<i128>().ok()),
        )
        .map(|(first, last)| last.saturating_sub(first).max(0))
        .unwrap_or(0);
    let ue_context_id = context
        .map(|context| context.context_id.clone())
        .or_else(|| primary_context_id(state, &pdu_session_id))
        .unwrap_or_else(|| format!("ue-context-for-{}", flow.session_id));
    let state_name = if flow.events.iter().any(|event| event.protocol == "GTP-U") {
        "ACTIVE_WITH_USER_PLANE"
    } else if flow
        .events
        .iter()
        .any(|event| event.message_name.contains("Release"))
    {
        "RELEASED"
    } else {
        "INCOMPLETE"
    };
    let serving_node = flow
        .participants
        .iter()
        .find(|participant| matches!(participant.role.as_str(), "gNB" | "eNB"))
        .map(|participant| {
            format!(
                "{} {}",
                participant.role,
                participant
                    .addresses
                    .first()
                    .map(String::as_str)
                    .unwrap_or("")
            )
            .trim()
            .to_owned()
        })
        .unwrap_or_else(|| "UNKNOWN".into());
    // 2.14.4 (ANR2 ladder écart 4) : la colonne AMF/MME de l'UI lisait
    // `serving_node`, qui contient toujours le RAN (eNB/gNB). On expose
    // désormais deux champs distincts, résolus depuis la même liste de
    // participants, pour que l'UI puisse afficher gNB/eNB d'un côté et
    // AMF/MME de l'autre. `serving_node` est maintenu pour la compat
    // arrière mais devient équivalent à `serving_ran_node`.
    let serving_ran_node = serving_node.clone();
    let core_node = flow
        .participants
        .iter()
        .find(|participant| matches!(participant.role.as_str(), "AMF" | "MME"))
        .map(|participant| {
            format!(
                "{} {}",
                participant.role,
                participant
                    .addresses
                    .first()
                    .map(String::as_str)
                    .unwrap_or("")
            )
            .trim()
            .to_owned()
        })
        .unwrap_or_else(|| "UNKNOWN".into());
    json!({
        "session_id":flow.session_id,"dataset_id":state.inner.manifest.get("scenario_id"),"ue_context_id":ue_context_id,
        "dataset_kind":"HISTORICAL",
        "technology":flow.technology,"ue_pseudonym":ue_pseudonym,"pdu_session_id":pdu_session_id,"serving_node":serving_node,"serving_ran_node":serving_ran_node,"core_node":core_node,
        "procedure":flow.procedures.iter().filter(|procedure| procedure.name!="Background / Lifecycle").map(|procedure|procedure.name.as_str()).collect::<Vec<_>>().join(" + "),
        "start_timestamp":flow.start_timestamp,"end_timestamp":flow.end_timestamp,"interfaces":flow.interfaces,"message_count":flow.accounting.session_events,
        "duration_ns":duration_ns.to_string(),
        "source_event_count":flow.accounting.source_events,"background_event_count":flow.accounting.background_events,"correlation_status":flow.correlation_status.get("E2E"),
        "decode_completeness":{"decoded":decoded,"partial":partial,"unresolved_fields":flow.unresolved_fields},"state":state_name
    })
}

fn live_session_summary(dataset: &live_probe::LiveDataset, flow: &CallFlow) -> Value {
    let started_ns = dataset
        .capture_started_epoch_ms
        .map(|value| i128::from(value) * 1_000_000);
    let fresh_flow = started_ns.is_some_and(|started| {
        flow.events.iter().any(|event| {
            event.protocol == "GTP-U"
                && event
                    .timestamp_ns
                    .parse::<i128>()
                    .is_ok_and(|timestamp| timestamp >= started)
        })
    });
    let discovered = dataset.discovery.as_ref().and_then(|discovery| {
        discovery
            .pdu_sessions
            .iter()
            .find(|session| session.session_id == flow.session_id)
    });
    let runtime = dataset
        .active_pdu_contexts
        .iter()
        .find(|context| context.session_id == flow.session_id);
    let context = discovered.and_then(|session| {
        dataset
            .discovery
            .as_ref()?
            .ue_contexts
            .iter()
            .find(|context| context.context_id == session.ue_context_id)
    });
    let decoded = flow
        .events
        .iter()
        .filter(|event| {
            event.association == Association::Session && event.decoding_status == "DECODED"
        })
        .count();
    let partial = flow
        .events
        .iter()
        .filter(|event| {
            event.association == Association::Session && event.decoding_status == "PARTIAL"
        })
        .count();
    let serving_node = flow
        .participants
        .iter()
        .find(|participant| matches!(participant.role.as_str(), "gNB" | "eNB"))
        .map(|participant| {
            format!(
                "{} {}",
                participant.role,
                participant
                    .addresses
                    .first()
                    .map(String::as_str)
                    .unwrap_or("")
            )
            .trim()
            .to_owned()
        })
        .unwrap_or_else(|| "UNKNOWN".into());
    // 2.14.4 (ANR2 ladder écart 4) : la colonne AMF/MME de l'UI lisait
    // `serving_node`, qui contient toujours le RAN (eNB/gNB). On expose
    // désormais deux champs distincts, résolus depuis la même liste de
    // participants, pour que l'UI puisse afficher gNB/eNB d'un côté et
    // AMF/MME de l'autre. `serving_node` est maintenu pour la compat
    // arrière mais devient équivalent à `serving_ran_node`.
    let serving_ran_node = serving_node.clone();
    let core_node = flow
        .participants
        .iter()
        .find(|participant| matches!(participant.role.as_str(), "AMF" | "MME"))
        .map(|participant| {
            format!(
                "{} {}",
                participant.role,
                participant
                    .addresses
                    .first()
                    .map(String::as_str)
                    .unwrap_or("")
            )
            .trim()
            .to_owned()
        })
        .unwrap_or_else(|| "UNKNOWN".into());
    json!({
        "session_id":flow.session_id,"dataset_id":dataset.dataset_id,"ue_context_id":discovered.map(|session|session.ue_context_id.clone()),
        "dataset_kind":if dataset.dataset_id.starts_with("derived-") {"DERIVED"} else if dataset.dataset_id.starts_with("recovered-dataset-") {"RECOVERED"} else if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID && !fresh_flow {"HISTORICAL"} else {"CAPTURED_LIVE"},
        "technology":flow.technology,"ue_pseudonym":runtime.map(|context|context.internal_ue_id.as_str()).or_else(||context.map(|context|context.pseudonym.as_str())).unwrap_or("UNKNOWN"),"pdu_session_id":runtime.map(|context|context.pdu_session_id.as_str()).or_else(||discovered.map(|session|session.pdu_session_id.as_str())),"serving_node":serving_node,"serving_ran_node":serving_ran_node,"core_node":core_node,
        "procedure":flow.procedures.iter().map(|procedure|procedure.name.as_str()).collect::<Vec<_>>().join(" + "),
        "start_timestamp":flow.start_timestamp,"end_timestamp":flow.end_timestamp,"interfaces":flow.interfaces,
        "message_count":flow.accounting.session_events,"source_event_count":flow.accounting.source_events,
        "background_event_count":flow.accounting.background_events,"correlation_status":flow.correlation_status.get("E2E"),
        "decode_completeness":{"decoded":decoded,"partial":partial,"unresolved_fields":flow.unresolved_fields},
        "runtime_evidence":runtime.map(|context|json!({"observed_epoch_ms":context.observed_epoch_ms,"provenance":context.provenance,"correlation_status":context.correlation_status,"ue_ip":context.ue_ip,"teids":context.teids,"directions":context.directions})),
        "state":if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID && !fresh_flow {"HISTORICAL_CONTEXT"} else if fresh_flow {"ACTIVE_WITH_USER_PLANE"} else {"UNKNOWN"}
    })
}

fn lte_session_summary(manifest: &LteDatasetManifest, session: &LteSession) -> Value {
    let packet_count = session
        .tunnels
        .iter()
        .map(|tunnel| {
            tunnel.uplink_packets + tunnel.downlink_packets + tunnel.unknown_direction_packets
        })
        .sum::<usize>();
    json!({
        "session_id":session.session_id,"dataset_id":manifest.dataset_id,
        "ue_context_id":Value::Null,"dataset_kind":"EVIDENCE","technology":"LTE",
        "ue_pseudonym":session.ue_pseudonym,
        "pdu_session_id":session.eps_bearer_ids.first().cloned(),"serving_node":Value::Null,"serving_ran_node":Value::Null,"core_node":Value::Null,
        "procedure":session.procedures.join(" + "),
        "start_timestamp":session.start_timestamp_ns.to_string(),
        "end_timestamp":session.end_timestamp_ns.to_string(),"interfaces":session.interfaces,
        "message_count":session.event_ids.len(),"duration_ns":session.duration_ns.to_string(),
        "source_event_count":session.event_ids.len(),"background_event_count":Value::Null,
        "correlation_status":"UNKNOWN",
        "decode_completeness":{"decoded":Value::Null,"partial":Value::Null,"unresolved_fields":session.limitations.len()},
        "state":session.state,
        "user_plane_packets":if packet_count == 0 { Value::Null } else { Value::from(packet_count) },
        "limitations":session.limitations
    })
}

/// 2.18.12 — CAUSE RACINE de la lenteur (audit perf Sadok) : chaque
/// requête `/sessions`, `/sessions/filter`, `/sessions/:id`, `/subscribers…`
/// appelait `queryable_flows`, qui CLONE tous les call flows statiques et
/// RELIT + RE-PARSE depuis le disque le JSON de TOUTES les sessions
/// continuous (et l'export de toutes les sessions LTE), uniquement pour
/// construire l'index de parcours abonné. Ouvrir une session = parser les
/// 190 call flows. L'index est désormais mis en cache et reconstruit
/// seulement si la signature change (sessions ajoutées, fichier callflow
/// modifié : un `stat` par fichier, aucune lecture).
fn journey_signature(state: &AppState) -> Vec<String> {
    let mut signature = vec![format!("static:{}", state.inner.flows.len())];
    for dataset in state.inner.capture_manager.datasets() {
        // 2.21.74 — le commit logique fait partie de la génération. Taille
        // et mtime seules peuvent rester identiques lors d'une republication
        // sub-seconde ; dans ce cas `/sessions/filter` ne doit surtout pas
        // considérer les caches de la génération précédente comme READY.
        signature.push(format!(
            "dataset:{}:commit={}:sessions={}",
            dataset.dataset_id,
            state
                .inner
                .capture_manager
                .dataset_commit_seq(&dataset.dataset_id),
            dataset.session_ids.len()
        ));
        for session_id in &dataset.session_ids {
            let file = state
                .inner
                .capture_manager
                .callflow_file_signature(&dataset.dataset_id, session_id)
                .map(|(len, mtime)| format!("{len}:{mtime}"))
                .unwrap_or_default();
            signature.push(format!("{}/{}:{}", dataset.dataset_id, session_id, file));
        }
    }
    if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
        for manifest in catalog {
            signature.push(format!("lte:{}:{}", manifest.run_id, manifest.session_ids.len()));
        }
    }
    signature
}

/// 2.21.3 — clé de cache étendue avec `commit_seq` (publication
/// incrémentale live-probe 0.6.1). Composition : `(len, mtime_ns,
/// commit_seq)`. Change de l'un invalide la ligne — en pratique
/// `commit_seq` bouge AVANT que le mtime du filesystem (NFS/tmpfs)
/// ne se propage, donc les UI reçoivent les sessions « en cours »
/// dans la foulée de la publication, sans attendre le rafraîchissement
/// mtime. Un `commit_seq.txt` absent → 0, comportement iso-2.20.x.
type ListRowCacheSignature = (u64, u128, u64);
type ListRowCache =
    std::collections::HashMap<(String, String), (ListRowCacheSignature, Value, Value)>;
type JourneyCache = Option<(Vec<String>, std::sync::Arc<subscriber_journey::JourneyIndex>)>;

#[derive(Default)]
struct SessionFilterCacheReadiness {
    enforced: bool,
    ready_generation: Option<Vec<String>>,
}

/// 2.21.92 (défaut bloquant ANR1 #10 7035121536) — journal du dernier refus de
/// bascule du double tampon + compteur total. Un refus ne tue pas le process :
/// l'ancienne génération reste servie, et l'opérateur peut comparer le
/// candidat (`last_candidate_session_count`) et la cible
/// (`last_published_session_count`) pour diagnostiquer l'écart.
#[derive(Default, Clone)]
struct GenerationSwapRefusedState {
    total: u64,
    last_epoch_ms: Option<u64>,
    last_reason: Option<String>,
    last_candidate_session_count: Option<u64>,
    last_reference_session_count: Option<u64>,
    last_trigger: Option<String>,
}

/// 2.21.94 (défaut bloquant prod ANR1 #10 7040235279) — journal du dernier
/// swap accepté malgré un écart (la garde n'a pas pu empêcher qu'une liste
/// plus à jour mais signalée remplace une liste périmée). Deux cas : pas de
/// génération précédente (évite 503 permanent) ou 3 ré-essais épuisés.
#[derive(Default, Clone)]
struct GenerationSwapAcceptedWithMismatchState {
    total: u64,
    last_epoch_ms: Option<u64>,
    last_reason: Option<String>,
    last_candidate_session_count: Option<u64>,
    last_reference_session_count: Option<u64>,
    last_trigger: Option<String>,
    last_scenario: Option<String>,
}

/// 2.21.85 (CLAUDE1, ordre #9 7015585561) — snapshot immuable servi
/// par `/sessions/filter` tant qu'une nouvelle génération n'a pas été
/// préchauffée avec succès. Toutes les données servables sont Arc'd ;
/// la route ne fait que `Arc::clone` et lit. Aucune allocation lourde,
/// aucune lecture disque (les lignes pré-rendues sont dans
/// `list_rows`, matérialisées à la fin du prewarm sous
/// `heavy_memory_try_enter_exclusive`).
pub(crate) struct FilterGeneration {
    /// Numéro monotone, incrémenté à chaque swap.
    pub generation: u64,
    /// `commit_seq` max observé sur les datasets live au moment du swap.
    pub commit_seq: u64,
    /// Signature des sources (= `journey_signature(state)`) au moment
    /// du build, pour diagnostic.
    pub signature: Vec<String>,
    /// epoch_ms du swap. Sert à calculer `stale_since_ms` dans la
    /// réponse de la route.
    pub ready_since_ms: u64,
    pub filter_index: Arc<session_filters::SessionFilterIndex>,
    pub journey_index: Arc<subscriber_journey::JourneyIndex>,
    /// Lignes de liste pré-rendues par `(dataset_id, session_id)`.
    /// Alimenté exclusivement par le prewarm sous garde exclusive ;
    /// READY ⇒ `deferred == 0 && missing == 0`, donc TOUTES les sessions
    /// de la génération sont présentes ici. La route interroge cette
    /// HashMap et NE FAIT JAMAIS d'accès disque via
    /// `capture_manager.callflow(...)`.
    pub list_rows: Arc<std::collections::HashMap<(String, String), (Value, Value)>>,
    /// 2.21.85 (CLAUDE1, ordre #9 7016931409, condition 2 "GC-survival") —
    /// index secondaire `session_id → (prebuilt_summary, events_identities)`
    /// construit atomiquement avec `list_rows` au moment du swap. La route
    /// résout chaque ligne de page par `rows_by_session.get(session_id)`
    /// sans jamais consulter `state.inner.capture_manager.datasets()` ni
    /// `callflow(...)` : une génération READY continue donc à servir une
    /// réponse identique même après GC des fichiers du dataset qui l'a
    /// nourrie (préchauffage de la génération suivante échoué → `ready`
    /// reste pointé sur `gen`). Les identités dynamiques (vault +
    /// hydratation tshark) sont rejointes à la lecture comme avant.
    pub rows_by_session: Arc<std::collections::HashMap<String, (Value, Value)>>,
    /// Lower-bound de la taille mémoire de la génération, exposée en
    /// trace `SESSIONS_FILTER_GENERATION_SWAP bytes_estimate=…`.
    pub bytes_estimate: u64,
    /// Nombre de sessions servables (sessions dans `filter_index`).
    pub session_count: u64,
}

impl FilterGeneration {
    pub(crate) fn stale_since_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.ready_since_ms)
    }
}

fn session_filter_cache_is_ready(state: &AppState) -> bool {
    let generation = journey_signature(state);
    state
        .inner
        .session_filter_cache_readiness
        .lock()
        .map(|readiness| {
            !readiness.enforced || readiness.ready_generation.as_ref() == Some(&generation)
        })
        .unwrap_or(false)
}

fn cached_journey_index(state: &AppState) -> std::sync::Arc<subscriber_journey::JourneyIndex> {
    let audit = std::env::var_os("OIRAN_SESSIONS_FILTER_PHASE_AUDIT").is_some();
    let started = std::time::Instant::now();
    let signature = journey_signature(state);
    if let Ok(cache) = state.inner.journey_index_cache.lock() {
        if let Some((cached, index)) = cache.as_ref() {
            if *cached == signature {
                if audit {
                    eprintln!(
                        "SESSIONS_FILTER_PHASE phase=journey_index cache=hit elapsed_ms={}",
                        started.elapsed().as_millis()
                    );
                }
                return index.clone();
            }
        }
    }
    // 2.21.23 (règle #9 6947485672 — audit mémoire des 4 OUVERTS) — le
    // JourneyIndex est désormais construit flow-par-flow : un seul
    // callflow en RAM à la fois, puis libéré après accumulation. Avant
    // 2.21.23, `queryable_flows(state)` chargeait TOUS les callflows
    // simultanément (= OOM lab pour gros datasets, même profil que
    // /packets pré-2.21.21).
    let mut builder = subscriber_journey::JourneyIndex::builder();
    stream_queryable_flows(state, |flow| {
        builder.observe(flow);
    });
    let index = std::sync::Arc::new(builder.finish());
    if let Ok(mut cache) = state.inner.journey_index_cache.lock() {
        *cache = Some((signature, index.clone()));
    }
    #[cfg(test)]
    state
        .inner
        .journey_index_rebuilds
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if audit {
        eprintln!(
            "SESSIONS_FILTER_PHASE phase=journey_index cache=rebuild elapsed_ms={}",
            started.elapsed().as_millis()
        );
    }
    index
}

/// 2.21.56 — construit les deux caches payés auparavant par le premier
/// `/sessions/filter` après une publication. L'appelant tient toujours la
/// garde lourde exclusive : tant que le préchauffage n'est pas terminé, les
/// routes reçoivent un 503 explicite et ne voient jamais un cache partiel.
fn trace_session_filter_prewarm_rss(trigger: &str, phase: &str) {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let proc_kb = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}:")))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    let cgroup_dir = fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                let mut fields = line.splitn(3, ':');
                let _hierarchy = fields.next()?;
                let _controllers = fields.next()?;
                let path = fields.next()?;
                Some(PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')))
            })
        });
    let cgroup_bytes = |name: &str| {
        cgroup_dir
            .as_ref()
            .and_then(|dir| fs::read_to_string(dir.join(name)).ok())
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    let memory_stat = cgroup_dir
        .as_ref()
        .and_then(|dir| fs::read_to_string(dir.join("memory.stat")).ok())
        .unwrap_or_default();
    let stat_bytes = |name: &str| {
        memory_stat
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                (fields.next() == Some(name))
                    .then(|| fields.next())
                    .flatten()
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .unwrap_or(0)
    };
    eprintln!(
        "{}",
        json!({
            "event": "SESSIONS_FILTER_PREWARM_RSS",
            "trigger": trigger,
            "phase": phase,
            "vmrss_kb": proc_kb("VmRSS"),
            "vmhwm_kb": proc_kb("VmHWM"),
            "rss_anon_kb": proc_kb("RssAnon"),
            "rss_file_kb": proc_kb("RssFile"),
            "cgroup_current_bytes": cgroup_bytes("memory.current"),
            "cgroup_peak_bytes": cgroup_bytes("memory.peak"),
            "cgroup_anon_bytes": stat_bytes("anon"),
            "cgroup_file_bytes": stat_bytes("file"),
        })
    );
}

/// 2.21.92 (défaut bloquant ANR1 #10 7035121536) — décide si une bascule du
/// double tampon doit être refusée au vu de l'écart `(session_count candidat,
/// published_session_count observé)`. Fonction pure : tous les autres motifs
/// de refus (verrou empoisonné, cache journey vide, zéro contre zéro après
/// non-vide) ont leur propre code de raison et ne passent pas par ici.
///
/// Règles :
///   * `candidate == published` ⇒ `None` (bascule OK, même quand les deux
///     valent 0 — bootstrapping avant toute publication).
///   * `candidate != published` ⇒ `Some("session_count_mismatch")`.
///     Attrape précisément le défaut observé en recette 2.21.89 :
///     `SESSIONS_FILTER_GENERATION_SWAP generation=2 session_count=0`
///     alors que `/health.published_session_count=325`.
fn swap_refusal_reason(
    candidate_session_count: u64,
    published_session_count: u64,
) -> Option<&'static str> {
    if candidate_session_count != published_session_count {
        Some("session_count_mismatch")
    } else {
        None
    }
}

/// 2.21.92 raffinement (ordre #9 7036719807 trou 1) — décision pour le cas
/// `(0,0)` avec garde « une génération à 0 session ne remplace jamais une
/// génération non vide sur un seul préchauffage » :
///   * `NotApplicable` si `(candidate, published) != (0,0)` (traité ailleurs).
///   * `Accept` si first-boot (`previous_session_count` None) ou la
///     génération précédente valait aussi 0 (régime stable à vide).
///   * `AcceptConfirmed` si la génération précédente avait des sessions mais
///     un `(0,0)` précédent a déjà noté `pending_until` et cette deadline
///     n'est pas dépassée (double observation = confirmation de l'état
///     publié).
///   * `RefuseAndMarkPending` sinon : la génération précédente avait des
///     sessions, c'est le premier `(0,0)` — on refuse et on note une
///     confirmation pending pour la prochaine tentative.
#[derive(Debug, PartialEq, Eq)]
enum EmptyAfterNonemptyDecision {
    NotApplicable,
    Accept,
    AcceptConfirmed,
    RefuseAndMarkPending,
}

fn empty_after_nonempty_decision(
    candidate_session_count: u64,
    published_session_count: u64,
    previous_session_count: Option<u64>,
    pending_until: Option<std::time::Instant>,
    now: std::time::Instant,
    trigger_is_retry: bool,
) -> EmptyAfterNonemptyDecision {
    if !(candidate_session_count == 0 && published_session_count == 0) {
        return EmptyAfterNonemptyDecision::NotApplicable;
    }
    match previous_session_count {
        None | Some(0) => EmptyAfterNonemptyDecision::Accept,
        Some(_) => {
            // 2.21.92 micro-raffinement (ordre #9 7037361185) — un ré-essai
            // qui revoit `(0,0)` tourne 5 s plus tard, possiblement toujours
            // dans la MÊME fenêtre intermédiaire (ex. publication qui
            // s'étire). Il NE DOIT PAS confirmer — il prolonge l'attente.
            // Seul un préchauffage déclenché par une publication terminée
            // (trigger non-retry) peut confirmer la seconde observation.
            if !trigger_is_retry {
                if let Some(until) = pending_until {
                    if now <= until {
                        return EmptyAfterNonemptyDecision::AcceptConfirmed;
                    }
                }
            }
            EmptyAfterNonemptyDecision::RefuseAndMarkPending
        }
    }
}

/// 2.21.92 — compteur de sessions publiées strictement aligné sur
/// `/health.published_session_count` (voir le calcul inline lignes 1462-1480) :
/// `flows.len()` OU, si vide, `continuous.session_ids.len()`. C'est la source
/// que l'opérateur consulte pour « combien de sessions sont publiées ? »,
/// donc la cible de la garde de bascule 2.21.92.
fn published_session_count_snapshot(state: &AppState) -> u64 {
    let flows = state.inner.flows.len() as u64;
    if flows > 0 {
        return flows;
    }
    state
        .inner
        .capture_manager
        .dataset(live_probe::CONTINUOUS_DATASET_ID)
        .map(|live| live.session_ids.len() as u64)
        .unwrap_or(0)
}

/// 2.21.92 (défaut bloquant ANR1 #10 7035121536) — enregistre un refus de
/// bascule du double tampon : incrémente le compteur global et journalise
/// l'event `SESSIONS_FILTER_GENERATION_SWAP_REFUSED` avec les deux compteurs
/// et la raison. Appelé depuis `prewarm_session_filter_caches_locked` dès
/// qu'une condition de rejet est atteinte ; l'ancienne génération reste
/// dans `generation_slot` et continue d'être servie à `/sessions/filter`.
fn record_swap_refused(
    state: &AppState,
    trigger: &str,
    reason: &str,
    candidate_session_count: Option<u64>,
    reference_session_count: Option<u64>,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Ok(mut g) = state.inner.generation_swap_refused.lock() {
        g.total = g.total.saturating_add(1);
        g.last_epoch_ms = Some(now_ms);
        g.last_reason = Some(reason.into());
        g.last_candidate_session_count = candidate_session_count;
        g.last_reference_session_count = reference_session_count;
        g.last_trigger = Some(trigger.into());
    }
    eprintln!(
        "{}",
        json!({
            "event": "SESSIONS_FILTER_GENERATION_SWAP_REFUSED",
            "trigger": trigger,
            "reason": reason,
            "candidate_session_count": candidate_session_count,
            "reference_session_count": reference_session_count,
            "epoch_ms": now_ms,
        })
    );
    // 2.21.92 raffinement (ordre #9 7036719807 trou 2) — nouvelle tentative
    // bornée. Un verrou empoisonné est irrécupérable dans le même process :
    // on ne retente pas. Tous les autres motifs (`session_count_mismatch`,
    // `empty_after_nonempty_unconfirmed`, `journey_index_cache_empty`) sont
    // transitoires : on programme un retry 5 s plus tard, jusqu'à 3 fois.
    let retryable = matches!(
        reason,
        "session_count_mismatch" | "empty_after_nonempty_unconfirmed" | "journey_index_cache_empty"
    );
    if retryable {
        let next_attempt = retry_attempt_from_trigger(trigger) + 1;
        schedule_retry_after_refusal(state, trigger, next_attempt);
    }
}

/// 2.21.92 raffinement — extrait le numéro de tentative d'un trigger comme
/// `"retry-2-after-publication"`. Trigger n'ayant pas le préfixe `retry-` ⇒ 0.
fn retry_attempt_from_trigger(trigger: &str) -> u32 {
    trigger
        .strip_prefix("retry-")
        .and_then(|rest| rest.split_once("-after-").map(|(n, _)| n))
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0)
}

/// 2.21.92 raffinement (ordre #9 7036719807 trou 2) — programme une nouvelle
/// tentative de préchauffage dans 5 s avec un `trigger` construit comme
/// `"retry-{attempt}-after-{from_trigger}"`. Chaque tentative incrémente
/// `generation_swap_retry_scheduled` et log
/// `SESSIONS_FILTER_GENERATION_SWAP_RETRY_SCHEDULED`. Au-delà de 3 tentatives
/// consécutives, on arrête et on attend la prochaine publication (log
/// `SESSIONS_FILTER_GENERATION_SWAP_RETRY_EXHAUSTED`). Sous `cfg(test)` le
/// thread n'est PAS lancé — seule la trace et l'incrément se produisent,
/// pour éviter les side-effects asynchrones dans les tests.
fn schedule_retry_after_refusal(state: &AppState, from_trigger: &str, attempt: u32) {
    if attempt > 3 {
        eprintln!(
            "{}",
            json!({
                "event": "SESSIONS_FILTER_GENERATION_SWAP_RETRY_EXHAUSTED",
                "from_trigger": from_trigger,
                "max_attempts": 3,
            })
        );
        return;
    }
    if let Ok(mut n) = state.inner.generation_swap_retry_scheduled.lock() {
        *n = n.saturating_add(1);
    }
    eprintln!(
        "{}",
        json!({
            "event": "SESSIONS_FILTER_GENERATION_SWAP_RETRY_SCHEDULED",
            "from_trigger": from_trigger,
            "attempt": attempt,
            "delay_s": 5,
        })
    );
    if cfg!(test) {
        // En test : incrément + trace, mais pas de thread réel.
        return;
    }
    let state_clone = state.clone();
    let from_trigger = from_trigger.to_owned();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(5));
        // Même garde que `install_session_filter_cache_prewarm` : si une
        // publication tient le verrou exclusif, on skip — l'observateur
        // prendra le relais à son `upsert_dataset`.
        let Some(_gate) = state_clone
            .inner
            .capture_manager
            .heavy_memory_try_enter_exclusive()
        else {
            eprintln!(
                "{}",
                json!({
                    "event": "SESSIONS_FILTER_GENERATION_SWAP_RETRY_SKIPPED",
                    "from_trigger": from_trigger,
                    "attempt": attempt,
                    "reason": "publication_in_progress",
                })
            );
            return;
        };
        let trigger = format!("retry-{attempt}-after-{from_trigger}");
        prewarm_session_filter_caches_locked(&state_clone, &trigger);
    });
}

/// 2.21.94 (ordre #9 7040291627) — décide si une bascule doit être acceptée
/// MALGRÉ un écart `candidate != reference`. Préserve l'invariant « jamais
/// de 503 permanent sur /sessions/filter à cause de la garde » :
///   * `candidate == 0` ⇒ NE PAS accepter (la règle vide-après-non-vide
///     reste stricte, cf. `empty_after_nonempty_decision`).
///   * `candidate == reference` ⇒ NotApplicable (pas d'écart, pas besoin de
///     ce helper).
///   * pas de génération précédente (`!previous_generation_exists`) ⇒
///     `Some("no_previous_generation")` — on bascule pour servir la liste
///     non vide plutôt que de rester en 503.
///   * 3 ré-essais épuisés (`attempt >= 3`) ⇒ `Some("retries_exhausted")` —
///     une liste à jour et signalée vaut mieux qu'une liste périmée
///     indéfiniment.
///   * sinon (candidat non vide, génération précédente, attempt < 3) ⇒
///     `None` (laisse la boucle de ré-essais faire son travail).
fn should_accept_with_mismatch(
    candidate_session_count: u64,
    reference_session_count: u64,
    attempt: u32,
    previous_generation_exists: bool,
) -> Option<&'static str> {
    if candidate_session_count == 0 {
        return None;
    }
    if candidate_session_count == reference_session_count {
        return None;
    }
    if !previous_generation_exists {
        return Some("no_previous_generation");
    }
    if attempt >= 3 {
        return Some("retries_exhausted");
    }
    None
}

/// 2.21.94 (ordre #9 7040291627) — enregistre une bascule acceptée malgré
/// un écart. Incrémente le compteur global et publie l'événement
/// `SESSIONS_FILTER_GENERATION_SWAP_ACCEPTED_WITH_MISMATCH`.
fn record_swap_accepted_with_mismatch(
    state: &AppState,
    trigger: &str,
    reason: &str,
    scenario: &str,
    candidate_session_count: u64,
    reference_session_count: u64,
) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Ok(mut g) = state.inner.generation_swap_accepted_with_mismatch.lock() {
        g.total = g.total.saturating_add(1);
        g.last_epoch_ms = Some(now_ms);
        g.last_reason = Some(reason.into());
        g.last_candidate_session_count = Some(candidate_session_count);
        g.last_reference_session_count = Some(reference_session_count);
        g.last_trigger = Some(trigger.into());
        g.last_scenario = Some(scenario.into());
    }
    eprintln!(
        "{}",
        json!({
            "event": "SESSIONS_FILTER_GENERATION_SWAP_ACCEPTED_WITH_MISMATCH",
            "trigger": trigger,
            "reason": reason,
            "scenario": scenario,
            "candidate_session_count": candidate_session_count,
            "reference_session_count": reference_session_count,
            "epoch_ms": now_ms,
        })
    );
}

fn prewarm_session_filter_caches_locked(state: &AppState, trigger: &str) {
    trace_session_filter_prewarm_rss(trigger, "before_heap_release");
    live_probe::release_publication_heap_pages();
    trace_session_filter_prewarm_rss(trigger, "after_heap_release");
    let started = std::time::Instant::now();
    state.refresh_session_filter_index();
    let filter_ready_ms = started.elapsed().as_millis();
    let _ = cached_journey_index(state);
    let journey_ready_ms = started.elapsed().as_millis();
    let list_rows = prewarm_live_list_row_cache_locked(state);
    let ready = list_rows.deferred == 0 && list_rows.missing == 0;
    if let Ok(mut readiness) = state.inner.session_filter_cache_readiness.lock() {
        readiness.ready_generation = ready.then(|| journey_signature(state));
    }
    // 2.21.85 (CLAUDE1, ordre #9 7015585561) — swap double-tampon READY.
    // Si et seulement si TOUTES les lignes ont été matérialisées (deferred=0,
    // missing=0), on capture un snapshot cohérent et atomique :
    //   * `filter_index` cloné (BTreeMap deep copy, ≈ 0,8 MB sur 327 sessions),
    //   * `journey_index` partagé en Arc (déjà construit par `cached_journey_index`),
    //   * `list_rows` copiée dans une HashMap indépendante (pour que la route
    //     n'accède JAMAIS au cache mutable ni au disque).
    // Le swap se fait sous `RwLock::write` du `generation_slot` ; les
    // requêtes `/sessions/filter` qui ont déjà fait `Arc::clone` sur la
    // génération précédente la gardent vivante jusqu'à leur retour.
    if ready {
        // 2.21.92 (défaut bloquant ANR1 #10 7035121536) — plus de repli
        // silencieux empty()/default()/unwrap_or_default(). Un verrou qui
        // échoue ou un cache non construit sont des écarts réels : on refuse
        // explicitement la bascule et on sert l'ancienne génération.
        let filter_index_arc = match state.inner.session_filter_index.read() {
            Ok(guard) => Arc::new((*guard).clone()),
            Err(_) => {
                record_swap_refused(
                    state,
                    trigger,
                    "session_filter_index_lock_poisoned",
                    None,
                    None,
                );
                return;
            }
        };
        let journey_index_arc = match state.inner.journey_index_cache.lock() {
            Ok(cache) => match cache.as_ref().map(|(_sig, idx)| idx.clone()) {
                Some(idx) => idx,
                None => {
                    record_swap_refused(
                        state,
                        trigger,
                        "journey_index_cache_empty",
                        None,
                        None,
                    );
                    return;
                }
            },
            Err(_) => {
                record_swap_refused(
                    state,
                    trigger,
                    "journey_index_cache_lock_poisoned",
                    None,
                    None,
                );
                return;
            }
        };
        let list_rows_map: std::collections::HashMap<(String, String), (Value, Value)> =
            match state.inner.list_row_cache.lock() {
                Ok(cache) => cache
                    .iter()
                    .map(|(k, (_sig, summary, extra))| {
                        (k.clone(), (summary.clone(), extra.clone()))
                    })
                    .collect(),
                Err(_) => {
                    record_swap_refused(
                        state,
                        trigger,
                        "list_row_cache_lock_poisoned",
                        None,
                        None,
                    );
                    return;
                }
            };
        let list_rows_arc = Arc::new(list_rows_map);
        // 2.21.85 — projection inverse `session_id → row` pour la condition
        // 2. Chaque session_id n'apparaît qu'une fois dans `list_rows` (clé
        // `(dataset_id, session_id)` et un session_id ne vit que dans un
        // dataset à la fois), on peut collapse sans perte. Si un doublon
        // survenait, on conserve la première entrée observée (deterministe
        // dans l'ordre de l'iterator HashMap du build).
        let mut rows_by_session_map: std::collections::HashMap<String, (Value, Value)> =
            std::collections::HashMap::with_capacity(list_rows_arc.len());
        for ((_dataset_id, session_id), row) in list_rows_arc.iter() {
            rows_by_session_map
                .entry(session_id.clone())
                .or_insert_with(|| row.clone());
        }
        let rows_by_session_arc = Arc::new(rows_by_session_map);
        let bytes_filter = filter_index_arc.estimated_bytes();
        let bytes_journey = (list_rows_arc.len() * std::mem::size_of::<(String, String)>()) as u64
            + list_rows_arc
                .iter()
                .map(|(_, (a, b))| (a.to_string().len() + b.to_string().len()) as u64)
                .sum::<u64>();
        // bytes_journey = estimation combinée journey + list_rows ; le
        // journey_index lui-même est Arc partagé donc son footprint
        // est amorti sur plusieurs générations tant que la signature
        // ne change pas. On conserve une estimation lower-bound.
        let bytes_estimate = bytes_filter.saturating_add(bytes_journey);
        let session_count = filter_index_arc.session_count() as u64;
        // 2.21.92 (défaut bloquant ANR1 #10 7035121536) — garde de bascule :
        // refus si `session_count` diverge de `/health.published_session_count`
        // hors cas « vrai zéro » (bootstrapping avant toute publication).
        // Évite la bascule observée en recette 2.21.89 :
        // `SESSIONS_FILTER_GENERATION_SWAP generation=2 session_count=0`
        // alors que `/health.published_session_count=325`.
        // 2.21.94 (défaut bloquant prod ANR1 #10 7040235279, ordre #9
        // 7040291627) — référence = `queryable_session_ids(state).len()`,
        // la même source que `/health.session_count` et que le `total` de
        // `/sessions/filter`. L'ancienne référence `published_session_count`
        // (flows OU continuous) sous-comptait les autres datasets capturés,
        // ce qui faisait refuser à tort une génération cohérente en prod
        // (329 interrogeables vs 327 publiées, 503 permanent).
        let reference_session_count = queryable_session_ids(state).len() as u64;
        // 2.21.92 raffinement (ordre #9 7036719807 trou 1) — règle
        // « empty_after_nonempty_unconfirmed » via la fonction pure
        // `empty_after_nonempty_decision`.
        let previous_session_count = state
            .inner
            .generation_slot
            .read()
            .ok()
            .and_then(|slot| slot.as_ref().map(|g| g.session_count));
        let previous_generation_exists = previous_session_count.is_some();
        let pending_until = state
            .inner
            .pending_empty_confirmation_until
            .lock()
            .ok()
            .and_then(|lock| *lock);
        let now = std::time::Instant::now();
        let trigger_is_retry = trigger.starts_with("retry-");
        let retry_attempt = retry_attempt_from_trigger(trigger);
        match empty_after_nonempty_decision(
            session_count,
            reference_session_count,
            previous_session_count,
            pending_until,
            now,
            trigger_is_retry,
        ) {
            EmptyAfterNonemptyDecision::RefuseAndMarkPending => {
                if let Ok(mut lock) = state.inner.pending_empty_confirmation_until.lock() {
                    *lock = Some(now + std::time::Duration::from_secs(30));
                }
                record_swap_refused(
                    state,
                    trigger,
                    "empty_after_nonempty_unconfirmed",
                    Some(0),
                    Some(0),
                );
                return;
            }
            EmptyAfterNonemptyDecision::AcceptConfirmed => {
                if let Ok(mut lock) = state.inner.pending_empty_confirmation_until.lock() {
                    *lock = None;
                }
            }
            EmptyAfterNonemptyDecision::Accept | EmptyAfterNonemptyDecision::NotApplicable => {}
        }
        // 2.21.94 (ordre #9 7040291627) — l'écart détecté par
        // `swap_refusal_reason` ne doit pas provoquer de 503 permanent sur
        // `/sessions/filter`. Deux cas acceptent la bascule avec avertissement
        // (`SESSIONS_FILTER_GENERATION_SWAP_ACCEPTED_WITH_MISMATCH`) plutôt que
        // de refuser pour toujours : (a) pas de génération précédente —
        // sinon la route reste en 503 jusqu'à la prochaine publication ; (b)
        // ré-essais épuisés — une liste à jour et signalée vaut mieux qu'une
        // liste périmée indéfiniment. La règle vide-après-non-vide garde sa
        // confirmation stricte (déjà appliquée ci-dessus).
        if let Some(reason) = swap_refusal_reason(session_count, reference_session_count) {
            if let Some(scenario) = should_accept_with_mismatch(
                session_count,
                reference_session_count,
                retry_attempt,
                previous_generation_exists,
            ) {
                record_swap_accepted_with_mismatch(
                    state,
                    trigger,
                    reason,
                    scenario,
                    session_count,
                    reference_session_count,
                );
                // Flux de bascule continue ci-dessous (pas de return).
            } else {
                record_swap_refused(
                    state,
                    trigger,
                    reason,
                    Some(session_count),
                    Some(reference_session_count),
                );
                trace_session_filter_prewarm_rss(trigger, "after_prewarm");
                eprintln!(
                    "{}",
                    json!({
                        "event": "SESSIONS_FILTER_PREWARM_READY",
                        "trigger": trigger,
                        "filter_ready_ms": filter_ready_ms,
                        "journey_ready_ms": journey_ready_ms,
                        "list_rows_cached": list_rows.cached,
                        "list_rows_deferred": list_rows.deferred,
                        "list_rows_missing": list_rows.missing,
                        "index_wait_ms": list_rows.index_wait_ms,
                        "total_ms": started.elapsed().as_millis(),
                        "swap_refused": true,
                    })
                );
                return;
            }
        }
        let commit_seq = state
            .inner
            .capture_manager
            .datasets()
            .iter()
            .map(|d| state.inner.capture_manager.dataset_commit_seq(&d.dataset_id))
            .max()
            .unwrap_or(0);
        let signature_now = journey_signature(state);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let generation_id = state
            .inner
            .generation_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let generation = Arc::new(FilterGeneration {
            generation: generation_id,
            commit_seq,
            signature: signature_now,
            ready_since_ms: now_ms,
            filter_index: filter_index_arc,
            journey_index: journey_index_arc,
            list_rows: list_rows_arc,
            rows_by_session: rows_by_session_arc,
            bytes_estimate,
            session_count,
        });
        if let Ok(mut slot) = state.inner.generation_slot.write() {
            *slot = Some(generation.clone());
        }
        // 2.21.92 raffinement (ordre #9 7036719807 trou 1) — toute bascule
        // réussie efface le jalon de confirmation pending (le pending ne
        // s'applique qu'à la prochaine séquence de `(0,0)` répétés).
        if let Ok(mut lock) = state.inner.pending_empty_confirmation_until.lock() {
            *lock = None;
        }
        eprintln!(
            "{}",
            json!({
                "event": "SESSIONS_FILTER_GENERATION_SWAP",
                "trigger": trigger,
                "generation": generation.generation,
                "commit_seq": generation.commit_seq,
                "session_count": generation.session_count,
                "bytes_estimate": generation.bytes_estimate,
                "ready_since_ms": generation.ready_since_ms,
            })
        );
    }
    eprintln!(
        "{}",
        json!({
            "event": if ready {
                "SESSIONS_FILTER_PREWARM_READY"
            } else {
                "SESSIONS_FILTER_PREWARM_INCOMPLETE"
            },
            "trigger": trigger,
            "filter_ready_ms": filter_ready_ms,
            "journey_ready_ms": journey_ready_ms,
            "list_rows_cached": list_rows.cached,
            "list_rows_deferred": list_rows.deferred,
            "list_rows_missing": list_rows.missing,
            "index_wait_ms": list_rows.index_wait_ms,
            "total_ms": started.elapsed().as_millis(),
        })
    );
    trace_session_filter_prewarm_rss(trigger, "after_prewarm");
}

#[derive(Default)]
struct ListRowPrewarmStats {
    cached: usize,
    deferred: usize,
    missing: usize,
    index_wait_ms: u128,
}

/// 2.21.61 — remplit la partie stable de `ListRowCache` pendant que le
/// verrou lourd exclusif protège encore la publication. Le read-time patch
/// doit être prêt : sinon on déclenche ses workers et on reporte explicitement
/// les lignes ; le callback de la publication suivante réessaiera. Aucun accès
/// au vault et aucun tshark ne sont lancés dans ce chemin.
fn prewarm_live_list_row_cache_locked(state: &AppState) -> ListRowPrewarmStats {
    let mut stats = ListRowPrewarmStats::default();
    for dataset in state.inner.capture_manager.datasets() {
        if let Some(root) = state
            .inner
            .capture_manager
            .dataset_root(&dataset.dataset_id)
        {
            let bundle = state.inner.compact_index_registry.ensure_tracking(&root);
            spawn_compact_index_workers(&state.inner.compact_index_registry, &bundle);
            // 2.21.63 — attendre les workers déjà réclamés sous la garde de
            // publication : la première requête ne doit jamais payer les
            // lignes. La borne explicite empêche un index cassé de bloquer
            // la publication indéfiniment.
            let wait_started = std::time::Instant::now();
            let deadline = wait_started + std::time::Duration::from_secs(120);
            while !bundle.all_ready() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            stats.index_wait_ms = stats
                .index_wait_ms
                .saturating_add(wait_started.elapsed().as_millis());
            if !bundle.all_ready() {
                stats.deferred = stats.deferred.saturating_add(dataset.session_ids.len());
                eprintln!(
                    "{}",
                    json!({
                        "event": "SESSIONS_FILTER_PREWARM_INDEX_TIMEOUT",
                        "dataset_id": dataset.dataset_id,
                        "timeout_ms": 120_000,
                        "deferred_rows": dataset.session_ids.len(),
                    })
                );
                continue;
            }
        }
        for session_id in &dataset.session_ids {
            if cached_live_list_row_base(state, &dataset, session_id).is_some() {
                stats.cached = stats.cached.saturating_add(1);
            } else {
                stats.missing = stats.missing.saturating_add(1);
            }
        }
    }
    stats
}

/// 2.21.56 — branche le préchauffage sur le commit de publication et tente
/// aussi un amorçage avant l'ouverture du listener. Si une publication tient
/// déjà le verrou au démarrage, l'observateur synchrone prend le relais à son
/// `upsert_dataset`; le report est journalisé, jamais silencieux.
pub fn install_session_filter_cache_prewarm(state: &AppState) {
    if let Ok(mut readiness) = state.inner.session_filter_cache_readiness.lock() {
        readiness.enforced = true;
        readiness.ready_generation = None;
    }
    let weak = Arc::downgrade(&state.inner);
    let runtime_handle = tokio::runtime::Handle::try_current().ok();
    state
        .inner
        .capture_manager
        .set_dataset_publish_observer(Some(Arc::new(move || {
            let Some(inner) = weak.upgrade() else {
                eprintln!(
                    "{}",
                    json!({"event": "SESSIONS_FILTER_PREWARM_SKIPPED", "reason": "state_dropped"})
                );
                return;
            };
            let state = AppState { inner };
            let Some(runtime_handle) = runtime_handle.as_ref() else {
                eprintln!(
                    "{}",
                    json!({
                        "event": "SESSIONS_FILTER_PREWARM_SKIPPED",
                        "reason": "tokio_runtime_unavailable"
                    })
                );
                return;
            };
            // L'observateur est appelé par le thread d'import continu. Entrer
            // le runtime capturé au démarrage rend les spawn d'index compacts
            // valides ; sans ceci Tokio panique hors réacteur.
            let _runtime_guard = runtime_handle.enter();
            // `CaptureManager::upsert_dataset` garde désormais l'écriture
            // exclusive depuis l'exposition de la génération jusqu'à la fin
            // de cet observateur. Une seconde prise ici serait un deadlock.
            prewarm_session_filter_caches_locked(&state, "publication");
        })));

    if state.inner.continuous_import_enabled {
        eprintln!(
            "{}",
            json!({
                "event": "SESSIONS_FILTER_PREWARM_DEFERRED",
                "trigger": "startup",
                "reason": "continuous_publication_will_notify"
            })
        );
    } else if let Some(_gate) = state
        .inner
        .capture_manager
        .heavy_memory_try_enter_exclusive()
    {
        prewarm_session_filter_caches_locked(state, "startup");
    } else {
        eprintln!(
            "{}",
            json!({
                "event": "SESSIONS_FILTER_PREWARM_DEFERRED",
                "trigger": "startup",
                "reason": "publication_in_progress"
            })
        );
    }
}

/// 2.21.23 — stream les flows requêtables UN PAR UN. `queryable_flows`
/// reste disponible comme référence pour les tests d'équivalence mais
/// ne doit plus être appelé depuis les handlers (interdit sur routes
/// qui peuvent scaler).
fn stream_queryable_flows(state: &AppState, mut visit: impl FnMut(&CallFlow)) {
    for flow in state.inner.flows.values() {
        visit(flow);
    }
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if let Some(flow) = state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
            {
                visit(&flow);
                // `flow` est drop ici → la RAM allouée est libérée avant
                // le prochain callflow.
            }
        }
    }
    match state.inner.lte_evidence_store.catalog() {
        Ok(catalog) => {
            for manifest in catalog {
                for session_id in manifest.session_ids {
                    match state
                        .inner
                        .lte_evidence_store
                        .callflow_for_export_by_session(&session_id)
                    {
                        Ok(Some(flow)) => visit(&flow),
                        Ok(None) => eprintln!(
                            "STREAM_QUERYABLE_FLOWS_LTE_CALLFLOW_SKIPPED session_id={} reason=manifest_session_not_resolvable",
                            session_id
                        ),
                        Err(error) => eprintln!(
                            "STREAM_QUERYABLE_FLOWS_LTE_CALLFLOW_SKIPPED session_id={} reason={}",
                            session_id, error
                        ),
                    }
                }
            }
        }
        Err(error) => eprintln!("STREAM_QUERYABLE_FLOWS_LTE_CATALOG_SKIPPED reason={}", error),
    }
}

fn queryable_flows(state: &AppState) -> BTreeMap<String, CallFlow> {
    let mut flows = state.inner.flows.clone();
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if let Some(flow) = state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
            {
                flows.insert(session_id.clone(), flow);
            }
        }
    }
    match state.inner.lte_evidence_store.catalog() {
        Ok(catalog) => {
            for manifest in catalog {
                for session_id in manifest.session_ids {
                    match state
                        .inner
                        .lte_evidence_store
                        .callflow_for_export_by_session(&session_id)
                    {
                        Ok(Some(flow)) => {
                            flows.insert(session_id, flow);
                        }
                        Ok(None) => eprintln!(
                            "SUBSCRIBER_JOURNEY_LTE_CALLFLOW_SKIPPED session_id={} reason=manifest_session_not_resolvable",
                            session_id
                        ),
                        Err(error) => eprintln!(
                            "SUBSCRIBER_JOURNEY_LTE_CALLFLOW_SKIPPED session_id={} reason={}",
                            session_id, error
                        ),
                    }
                }
            }
        }
        Err(error) => eprintln!("SUBSCRIBER_JOURNEY_LTE_CATALOG_SKIPPED reason={}", error),
    }
    flows
}

fn queryable_session_ids(state: &AppState) -> BTreeSet<String> {
    let mut ids = state.inner.flows.keys().cloned().collect::<BTreeSet<_>>();
    for dataset in state.inner.capture_manager.datasets() {
        ids.extend(dataset.session_ids.iter().filter_map(|session_id| {
            state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
                .map(|_| session_id.clone())
        }));
    }
    if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
        for manifest in catalog {
            if let Ok(page) = state
                .inner
                .lte_evidence_store
                .session_page(&manifest.run_id, 1, 100)
            {
                if let Some(records) = page["data"].as_array() {
                    ids.extend(records.iter().filter_map(|record| {
                        record
                            .get("session_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    }));
                }
            }
        }
    }
    ids
}

fn decorate_subscriber_summary(
    summary: &mut Value,
    flow: &CallFlow,
    index: &subscriber_journey::JourneyIndex,
) {
    let Some(pseudo) = index.subscriber_for_session(&flow.session_id) else {
        return;
    };
    let sessions = index.sessions(pseudo);
    let Some(position) = sessions
        .iter()
        .position(|session| session.session_id == flow.session_id)
    else {
        return;
    };
    summary["subscriber_pseudonym"] = Value::String(pseudo.to_owned());
    summary["ue_pseudonym"] = Value::String(pseudo.to_owned());
    summary["subscriber_session_count"] = Value::from(sessions.len());
    summary["previous_session_id"] = position
        .checked_sub(1)
        .and_then(|index| sessions.get(index))
        .map(|session| Value::String(session.session_id.clone()))
        .unwrap_or(Value::Null);
    summary["next_session_id"] = sessions
        .get(position + 1)
        .map(|session| Value::String(session.session_id.clone()))
        .unwrap_or(Value::Null);
}

async fn subscribers(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    // 2.21.17 — cached_journey_index parcourt datasets + callflows en
    // synchrone (fs). Déport dans spawn_blocking.
    tokio::task::spawn_blocking(move || {
        let index = cached_journey_index(&state);
        let mut rows = serde_json::to_value(index.subscribers())
            .unwrap_or_else(|_| Value::Array(Vec::new()))
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(search) = query.search.as_deref() {
            let search = search.to_ascii_lowercase();
            rows.retain(|row| row.to_string().to_ascii_lowercase().contains(&search));
        }
        paginated(rows, &query)
    })
    .await
    .unwrap_or_else(|_| Json(json!({"error": "subscribers handler panicked"})))
}

async fn subscriber_journey(State(state): State<AppState>, Path(pseudo): Path<String>) -> Response {
    // 2.21.20 — spawn_blocking pour isoler du runtime async.
    // 2.21.23 — règle #9 6947485672 : plus de `queryable_flows` global.
    // Le JourneyIndex vient du cache streaming (`cached_journey_index`,
    // un seul callflow en RAM à la fois) et les flows nécessaires au
    // rendu (résolution UE context par session) sont chargés à la demande
    // pour le sous-ensemble du subscriber uniquement.
    tokio::task::spawn_blocking(move || subscriber_journey_blocking(&state, &pseudo))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SUBSCRIBER_JOURNEY_FAILED",
                "subscriber_journey handler panicked",
            )
        })
}

fn subscriber_journey_blocking(state: &AppState, pseudo: &str) -> Response {
    let index = cached_journey_index(state);
    let sessions = index.sessions(pseudo);
    if sessions.is_empty() {
        return api_error(
            StatusCode::NOT_FOUND,
            "SUBSCRIBER_NOT_FOUND",
            "subscriber journey not found",
        );
    }
    let sources = queryable_flow_sources(state);
    let mut flows = BTreeMap::<String, CallFlow>::new();
    for session in &sessions {
        if let Some(entries) = sources.get(&session.session_id) {
            if let Some(flow) = find_queryable_callflow(state, &session.session_id, entries) {
                flows.insert(session.session_id.clone(), flow);
            }
        }
    }
    subscriber_journey_render(state, &flows, &index, pseudo, sessions)
}

fn subscriber_journey_render(
    state: &AppState,
    flows: &BTreeMap<String, CallFlow>,
    index: &subscriber_journey::JourneyIndex,
    pseudo: &str,
    sessions: Vec<subscriber_journey::JourneySession>,
) -> Response {
    let sessions = sessions;
    if sessions.is_empty() {
        return api_error(
            StatusCode::NOT_FOUND,
            "SUBSCRIBER_NOT_FOUND",
            "subscriber journey not found",
        );
    }
    let mut contexts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for session in &sessions {
        let context_id = flows
            .get(&session.session_id)
            .and_then(|flow| discovered_session_for_flow(state, flow))
            .map(|session| session.ue_context_id.clone())
            .unwrap_or_else(|| format!("ue-context-for-{}", session.session_id));
        contexts
            .entry(context_id)
            .or_default()
            .push(session.session_id.clone());
    }
    ok(json!({
        "subscriber_pseudonym":pseudo,
        "contexts":contexts.into_iter().map(|(ue_context_id, session_ids)| json!({"ue_context_id":ue_context_id,"session_ids":session_ids})).collect::<Vec<_>>(),
        "sessions":sessions,
        "links":index.links(pseudo),
        "ordering":"capture_id,packet_number,event_id"
    })).into_response()
}

async fn subscriber_tmsi(State(state): State<AppState>, Path(pseudo): Path<String>) -> Response {
    // 2.21.20 — cached_journey_index parcourt flows + callflows.
    tokio::task::spawn_blocking(move || subscriber_tmsi_blocking(&state, &pseudo))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SUBSCRIBER_TMSI_FAILED",
                "subscriber_tmsi handler panicked",
            )
        })
}

fn subscriber_tmsi_blocking(state: &AppState, pseudo: &str) -> Response {
    let index = cached_journey_index(state);
    if index.sessions(pseudo).is_empty() {
        return api_error(
            StatusCode::NOT_FOUND,
            "SUBSCRIBER_NOT_FOUND",
            "subscriber temporary identity chain not found",
        );
    }
    ok(serde_json::to_value(index.tmsi(&pseudo)).unwrap_or(Value::Array(Vec::new())))
        .into_response()
}

/// 2.18.12 — calcul (coûteux) d'une ligne de liste continuous : résumé +
/// patch à la lecture + identités tirées des events (repli + SBI). Le
/// booléen indique si le résultat peut être mis en cache (patch appliqué
/// ou non applicable — pas pendant la construction de l'index).
fn live_list_row(
    state: &AppState,
    dataset: &live_probe::LiveDataset,
    session_id: &str,
    flow: &CallFlow,
) -> (Value, Value, bool) {
    let state = state.clone();
    let mut summary = live_session_summary(dataset, flow);
    // 2.14.8 (ANR1 #10) — patcher à la lecture sur le chemin B
    // (continuous / derived / recovered). On sérialise les
    // events, on patch via le raw JSONL du dataset_root,
    // puis on recalcule serving_node/serving_ran_node/
    // core_node depuis les participants patchés.
    let patched_items: Option<Vec<Value>> = if let Some(dataset_root) = state
        .inner
        .capture_manager
        .dataset_root(&dataset.dataset_id)
    {
        if let Ok(serde_json::Value::Array(mut items)) =
            serde_json::to_value(&flow.events)
        {
            let status =
                apply_read_time_patch(&state, &mut items, &dataset_root, session_id);
            if matches!(status, read_time_patch::PatchStatus::Applied) {
                let (serving_node, serving_ran_node, core_node) =
                    read_time_patch::recompute_session_participants(&items);
                if let Some(object) = summary.as_object_mut() {
                    object.insert("serving_node".into(), Value::String(serving_node));
                    object.insert(
                        "serving_ran_node".into(),
                        Value::String(serving_ran_node),
                    );
                    object.insert("core_node".into(), Value::String(core_node));
                }
            }
            if let Some(label) = status.label() {
                if let Some(object) = summary.as_object_mut() {
                    object.insert(
                        "read_time_patch".into(),
                        json!({
                            "status": label,
                            "version": read_time_patch::PATCH_VERSION,
                        }),
                    );
                }
            }
            Some(items)
        } else {
            None
        }
    } else {
        None
    };
    let mut events_identities = patched_items
        .as_deref()
        .and_then(read_time_patch::extract_identity_summary_from_items)
        .unwrap_or(Value::Null);
    merge_sbi_identities(&mut events_identities, &flow.events);
    let cacheable = !summary["read_time_patch"]["status"]
        .as_str()
        .is_some_and(|status| status.to_ascii_lowercase().contains("build"));
    (summary, events_identities, cacheable)
}

/// 2.18.12 — complète une shape d'identités du vault avec les valeurs
/// tirées des events (MSISDN/IMEI SBI…) quand le vault ne les a pas.
fn fill_missing_identities(identities: &mut Value, fallback: &Value) {
    let (Some(target), Some(source)) = (identities.as_object_mut(), fallback.as_object()) else {
        return;
    };
    for (key, value) in source {
        let missing = target.get(key).map_or(true, |current| {
            current.is_null() || current.as_array().is_some_and(Vec::is_empty)
        });
        if missing && !value.is_null() {
            target.insert(key.clone(), value.clone());
        }
    }
}

fn decorate_subscriber_summary_by_id(
    summary: &mut Value,
    session_id: &str,
    index: &subscriber_journey::JourneyIndex,
) {
    let Some(pseudo) = index.subscriber_for_session(session_id) else {
        return;
    };
    let sessions = index.sessions(pseudo);
    let Some(position) = sessions.iter().position(|session| session.session_id == session_id) else {
        return;
    };
    summary["subscriber_pseudonym"] = Value::String(pseudo.to_owned());
    summary["ue_pseudonym"] = Value::String(pseudo.to_owned());
    summary["subscriber_session_count"] = Value::from(sessions.len());
    summary["previous_session_id"] = position
        .checked_sub(1)
        .and_then(|index| sessions.get(index))
        .map(|session| Value::String(session.session_id.clone()))
        .unwrap_or(Value::Null);
    summary["next_session_id"] = sessions
        .get(position + 1)
        .map(|session| Value::String(session.session_id.clone()))
        .unwrap_or(Value::Null);
}

/// 2.18.12 — ligne de liste d'une session continuous, avec cache par
/// fichier callflow (voir `live_list_row`). Partagée par `GET /sessions`
/// et `POST /sessions/filter`.
fn cached_live_list_row(
    state: &AppState,
    dataset: &live_probe::LiveDataset,
    session_id: &String,
    journey_index: &subscriber_journey::JourneyIndex,
) -> Option<Value> {
    // 2.18.12 (audit perf) — la ligne de liste d'une session
    // continuous (lecture + parse du call flow, patch à la lecture,
    // identités tirées des events) est mise en cache, invalidée par
    // la signature du fichier callflow. Seuls le parcours abonné et
    // le vault (qui évoluent sans que le fichier change) sont
    // recalculés à chaque requête.
    let (mut summary, events_identities) = cached_live_list_row_base(state, dataset, session_id)?;
    decorate_subscriber_summary_by_id(&mut summary, session_id, &journey_index);
    if let Some(object) = summary.as_object_mut() {
        let mut identities = identity_summary_for_session(&state, session_id);
        if identities.is_null() {
            schedule_identity_hydration(&state, session_id);
            identities = events_identities;
        } else {
            fill_missing_identities(&mut identities, &events_identities);
        }
        object.insert("identities".into(), identities);
    }
    Some(summary)
}

/// 2.21.61 — partie stable et cacheable d'une ligne de liste live.
/// Elle exclut volontairement le parcours abonné, le vault et le lancement
/// de l'hydratation tshark : le préchauffage de publication peut donc la
/// construire sans effet de bord, puis chaque requête ajoute les données
/// dynamiques exactement comme avant.
fn cached_live_list_row_base(
    state: &AppState,
    dataset: &live_probe::LiveDataset,
    session_id: &String,
) -> Option<(Value, Value)> {
    let audit = std::env::var_os("OIRAN_SESSIONS_FILTER_PHASE_AUDIT").is_some();
    let started = std::time::Instant::now();
    let key = (dataset.dataset_id.clone(), session_id.clone());
    // 2.21.3 — signature étendue avec `commit_seq` (live-probe 0.6.1).
    // Un bump de la publication incrémentale invalide la ligne même
    // si le mtime filesystem n'a pas encore été propagé (tmpfs/NFS).
    let file_sig = state
        .inner
        .capture_manager
        .callflow_file_signature(&dataset.dataset_id, session_id);
    let commit_seq = state
        .inner
        .capture_manager
        .dataset_commit_seq(&dataset.dataset_id);
    let signature: Option<ListRowCacheSignature> = file_sig.map(|(len, mtime)| (len, mtime, commit_seq));
    let cached = signature.and_then(|signature| {
        state.inner.list_row_cache.lock().ok().and_then(|cache| {
            cache
                .get(&key)
                .filter(|entry| entry.0 == signature)
                .map(|entry| (entry.1.clone(), entry.2.clone()))
        })
    });
    if let Some(hit) = cached {
        if audit {
            eprintln!(
                "SESSIONS_FILTER_ROW phase=cache_hit elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
        return Some(hit);
    }
    #[cfg(test)]
    state
        .inner
        .list_row_cache_builds
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let flow_started = std::time::Instant::now();
    let Some(flow) = state
        .inner
        .capture_manager
        .callflow(&dataset.dataset_id, session_id)
    else {
        return None;
    };
    let flow_ms = flow_started.elapsed().as_millis();
    let build_started = std::time::Instant::now();
    let (summary, events_identities, cacheable) =
        live_list_row(state, dataset, session_id, &flow);
    let build_ms = build_started.elapsed().as_millis();
    if let (Some(signature), true) = (signature, cacheable) {
        if let Ok(mut cache) = state.inner.list_row_cache.lock() {
            cache.insert(key, (signature, summary.clone(), events_identities.clone()));
        }
    }
    if audit {
        eprintln!(
            "SESSIONS_FILTER_ROW phase=cache_miss flow_ms={} build_ms={} total_ms={} cacheable={}",
            flow_ms,
            build_ms,
            started.elapsed().as_millis(),
            cacheable
        );
    }
    Some((summary, events_identities))
}

async fn sessions(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    // 2.21.14 (audit handlers #9 6940906119) — ce handler itère
    // `state.inner.capture_manager.datasets()` puis appelle
    // `cached_live_list_row` qui résout chaque `callflow(dataset, session_id)` :
    // potentiellement N I/O disque + parse JSON. Même profil que
    // `/health` pré-2.21.13. Correctif : déport dans `spawn_blocking`.
    let state_blocking = state.clone();
    let query_blocking = query.clone();
    let result = tokio::task::spawn_blocking(move || {
        let state = state_blocking;
        let query = query_blocking;
        sessions_blocking(&state, &query)
    })
    .await
    .unwrap_or_else(|_| serde_json::json!({"data": [], "meta": {"error": "sessions handler panicked"}}));
    Json(result)
}

/// 2.21.14 — logique synchrone de `/sessions` extraite dans une fonction
/// pure appelée depuis `spawn_blocking`. Aucun `.await` ici ; toutes les
/// opérations (fs::read callflow, parse JSON) restent sur un thread du
/// pool bloquant tokio.
fn sessions_blocking(state: &AppState, query: &ListQuery) -> Value {
    let journey_index = cached_journey_index(state);
    let mut unique = state
        .inner
        .flows
        .values()
        .map(|flow| {
            let mut summary = session_summary(state, flow);
            decorate_subscriber_summary(&mut summary, flow, &journey_index);
            // 2.15.0 (ANR1 #10 6883006379) — identités compactes
            // directement dans la liste /sessions pour que l'UI
            // n'ait pas besoin d'ouvrir chaque session.
            if let Some(object) = summary.as_object_mut() {
                let mut identities = identity_summary_for_session(state, &flow.session_id);
                merge_sbi_identities(&mut identities, &flow.events);
                object.insert("identities".into(), identities);
            }
            (flow.session_id.clone(), summary)
        })
        .collect::<BTreeMap<_, _>>();
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            let Some(summary) = cached_live_list_row(state, &dataset, session_id, &journey_index)
            else {
                continue;
            };
            unique.insert(session_id.clone(), summary);
        }
    }
    if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
        for manifest in catalog {
            if let Ok(page) = state
                .inner
                .lte_evidence_store
                .session_page(&manifest.run_id, 1, 100)
            {
                if let Some(records) = page["data"].as_array() {
                    for record in records {
                        if let Ok(session) = serde_json::from_value::<LteSession>(record.clone()) {
                            let mut summary = lte_session_summary(&manifest, &session);
                            // 2.15.0 (ANR1 #10 6883006379) — identités
                            // compactes.
                            if let Some(object) = summary.as_object_mut() {
                                object.insert(
                                    "identities".into(),
                                    identity_summary_for_session(state, &session.session_id),
                                );
                            }
                            unique.insert(session.session_id.clone(), summary);
                        }
                    }
                }
            }
        }
    }
    let mut items = unique.into_values().collect::<Vec<_>>();
    if let Some(search) = query.search.as_deref() {
        let q = search.to_ascii_lowercase();
        items.retain(|x| x.to_string().to_ascii_lowercase().contains(&q));
    }
    if let Some(dataset) = query.dataset_id.as_deref() {
        items.retain(|item| item["dataset_id"] == dataset);
    }
    if let Some(dataset_kind) = query.dataset_kind.as_deref() {
        items.retain(|item| item["dataset_kind"] == dataset_kind);
    }
    if let Some(ue_id) = query.ue_id.as_deref() {
        items.retain(|item| item["ue_context_id"] == ue_id);
    }
    if let Some(technology) = query.technology.as_deref() {
        items.retain(|item| item["technology"] == technology);
    }
    if let Some(status) = query.status.as_deref() {
        items.retain(|item| item["state"] == status);
    }
    if let Some(interface) = query.interface.as_deref() {
        items.retain(|item| {
            item["interfaces"]
                .as_array()
                .map(|values| values.iter().any(|value| value == interface))
                .unwrap_or(false)
        });
    }
    sort_values(
        &mut items,
        query.sort.as_deref().unwrap_or("start_timestamp"),
        query.order.as_deref(),
    );
    sanitize_all(&mut items);
    paginated_value(items, query)
}

/// 2.21.14 — variante pure Value (hors axum) de `paginated` pour permettre
/// l'appel depuis `sessions_blocking`.
fn paginated_value(items: Vec<Value>, query: &ListQuery) -> Value {
    let Json(value) = paginated(items, query);
    value
}

/// 2.10.0 — `GET /sessions/available_causes` : liste les causes
/// réellement présentes dans le dataset courant avec compteur de
/// sessions touchées. Accessible viewer ; aucune identité en clair
/// dans la réponse (l'index ne stocke que des codes de cause et un
/// compteur). ETag absent — valeur réactive au dataset courant.
async fn sessions_available_causes(State(state): State<AppState>) -> Response {
    state.refresh_session_filter_index();
    let causes = state
        .inner
        .session_filter_index
        .read()
        .map(|index| index.available_causes())
        .unwrap_or_default();
    ok(serde_json::json!({ "causes": causes })).into_response()
}

#[derive(Deserialize, Default)]
struct SessionsFilterRequest {
    #[serde(default)]
    messages: Vec<SessionsFilterMessage>,
    #[serde(default)]
    causes: Vec<SessionsFilterCause>,
    #[serde(default)]
    failures_only: bool,
    /// Optionnel. Rôle d'identité + valeur brute. Serveur hashe
    /// immédiatement avec la clé courante et le label décodeur ;
    /// jamais loggée, jamais stockée, jamais renvoyée.
    #[serde(default)]
    identity: Option<SessionsFilterIdentity>,
    /// 2.10.1 (revue devmat) : pagination curseur sur la clé
    /// canonique `(anchor_capture_id, first_packet_number,
    /// session_id)`. `cursor` est l'opaque renvoyé par
    /// `meta.next_cursor` d'une page précédente ; si absent, on
    /// renvoie la première page.
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    /// 2.19.0 — restreint la projection serveur aux colonnes
    /// demandées. Les colonnes `ALWAYS_PRESENT_COLUMNS` sont
    /// toujours préservées. Un nom hors catalog renvoie 400
    /// `UNKNOWN_COLUMN`. Absent → aucun filtre (comportement
    /// 2.18.x inchangé).
    #[serde(default)]
    columns: Option<Vec<String>>,
    /// 2.19.0 — filtres étendus. Chacun est en OR interne, les
    /// familles sont combinées en AND avec les prédicats 2.10.0
    /// (messages/causes/identity/failures_only).
    #[serde(default)]
    technologies: Vec<String>,
    #[serde(default)]
    dataset_kinds: Vec<String>,
    #[serde(default)]
    states: Vec<String>,
    #[serde(default)]
    correlation_statuses: Vec<String>,
    /// 2.19.1 — prédicats protocolaires sur les events. Chaque
    /// critère cible `{interface?, protocol?, message, param_path?,
    /// op, value|values}`. `combinator` AND (défaut) ou OR les
    /// combine. `matched_criteria` est publié dans chaque ligne.
    #[serde(default)]
    criteria: Vec<session_catalog::FilterCriterion>,
    #[serde(default)]
    combinator: session_catalog::FilterCombinator,
    /// 2.19.1 — restreint aux sessions dont ≥ 1 participant est
    /// dans ce rôle (AMF/SMF/UPF/MME/SGW/PGW/gNB/eNB/…).
    #[serde(default)]
    network_elements: Vec<String>,
    /// 2.19.1 — cadrage horaire par capture. Chaînes en ns
    /// décimales (l'UI convertit). Ordre canonique inchangé.
    #[serde(default)]
    time_window: Option<SessionsFilterTimeWindow>,
    /// 2.19.1 — alternative à `time_window`. Une session passe le
    /// filtre si au moins un de ses `capture_references` matche
    /// `run_id` (exact).
    #[serde(default)]
    run_id: Option<String>,
    /// 2.19.1 — raccourci de recherche. Si la valeur ressemble à
    /// un IMSI (digits only ≥ 14 caractères), le serveur calcule
    /// le pseudonyme SupiOrImsi et l'applique comme identity hint
    /// (operator-only, 403 sinon). Autrement, substring
    /// case-insensitive sur `message_name` et valeurs d'IE.
    #[serde(default)]
    search: Option<String>,
}

#[derive(Deserialize, Default, Debug, Clone)]
struct SessionsFilterTimeWindow {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
}

#[derive(Deserialize)]
struct SessionsFilterMessage {
    name: String,
    #[serde(default)]
    interface: Option<String>,
}

#[derive(Deserialize)]
struct SessionsFilterCause {
    value: String,
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Deserialize)]
struct SessionsFilterIdentity {
    kind: String,
    value: String,
}

/// 2.18.5 (ANR2 #10 6901691533) — `identities` d'une ligne de liste,
/// identique pour `GET /sessions` et `POST /sessions/filter`. p900 ≥ 2.5.1
/// ne lit que `/sessions/filter` : sans ce champ, IMSI/TMSI/IMEI
/// s'affichaient « — », et l'hydratation tshark (déclenchée seulement par
/// `/sessions`) ne démarrait jamais. Vault d'abord ; vide → hydratation en
/// arrière-plan + repli sur les events du call flow ; puis SBI.
fn insert_list_identities(
    state: &AppState,
    summary: &mut Value,
    session_id: &str,
    events: Option<&[callflow_schema::CallFlowEvent]>,
) {
    let mut identities = identity_summary_for_session(state, session_id);
    if identities.is_null() {
        schedule_identity_hydration(state, session_id);
        if let Some(events) = events {
            if let Ok(Value::Array(items)) = serde_json::to_value(events) {
                if let Some(fallback) = read_time_patch::extract_identity_summary_from_items(&items)
                {
                    identities = fallback;
                }
            }
        }
    }
    if let Some(events) = events {
        merge_sbi_identities(&mut identities, events);
    }
    if let Some(object) = summary.as_object_mut() {
        object.insert("identities".into(), identities);
    }
}

/// 2.10.0 — `POST /sessions/filter` : AND logique sur
/// `messages` (par interface optionnelle), `causes` (par domaine
/// optionnel), `failures_only`, et `identity` (operator seulement).
///
/// Contrat vie privée :
/// * Méthode POST : la valeur d'identité n'apparaît jamais dans
///   l'URL, donc jamais dans les logs d'accès ni la history
///   navigateur.
/// * Le serveur calcule
///   `pseudonym(key, identity_kind.pseudo_domain(), value.bytes())`
///   et compare au set de pseudonymes observé par session. La
///   valeur brute est droppée immédiatement après le hash.
/// * Role check : si `identity` est présent et le role est Viewer,
///   on retourne 403 `IDENTITY_FILTER_OPERATOR_REQUIRED` SANS
///   lire la valeur. Un viewer ne peut même pas émettre la requête
///   avec un hint présent.
/// * Réponse : liste de summaries de sessions sanitisée par
///   `sanitize_all`, plus `identity_matched_pseudonym` (le `psn-...`
///   recherché, pas la valeur brute). Si `identity` était absent,
///   ce champ est absent aussi.
async fn sessions_filter(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SessionsFilterRequest>,
) -> Response {
    // 2.21.20 — role_from_headers + cached_journey_index + heavy filter
    // traversal. Wrap entier dans spawn_blocking (headers Send, request Send).
    tokio::task::spawn_blocking(move || sessions_filter_blocking(state, headers, request))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSIONS_FILTER_FAILED",
                "sessions_filter handler panicked",
            )
        })
}

fn sessions_filter_blocking(
    state: AppState,
    headers: HeaderMap,
    request: SessionsFilterRequest,
) -> Response {
    let audit_enabled = std::env::var_os("OIRAN_SESSIONS_FILTER_PHASE_AUDIT").is_some();
    let audit_started = std::time::Instant::now();
    let mut audit_previous = audit_started;
    let mut audit_phase = |phase: &str| {
        if audit_enabled {
            let now = std::time::Instant::now();
            eprintln!(
                "SESSIONS_FILTER_PHASE phase={} phase_ms={} total_ms={}",
                phase,
                now.duration_since(audit_previous).as_millis(),
                now.duration_since(audit_started).as_millis()
            );
            audit_previous = now;
        }
    };
    let role = role_from_headers(&state, &headers);
    if request.identity.is_some() && !role.can_control() {
        return api_error(
            StatusCode::FORBIDDEN,
            "IDENTITY_FILTER_OPERATOR_REQUIRED",
            "identity-scoped session filtering requires an operator bearer",
        );
    }
    // 2.21.85 (CLAUDE1, ordre #9 7015585561) — remplace l'ancien
    // couple `heavy_memory_try_enter` + `session_filter_cache_is_ready`.
    // La route sert désormais UNIQUEMENT la génération READY capturée
    // au dernier swap (snapshot Arc'd) : aucune lecture disque, aucune
    // allocation lourde, aucune contention avec la publication en
    // cours. Seul motif 503 : aucune génération READY n'a été
    // construite depuis le démarrage du process (`generation_slot`
    // vide). Les routes autres (`/sessions/:id/journey`, `/callflow`)
    // continuent d'utiliser `heavy_memory_try_enter` pour l'instant.
    //
    // Back-compat tests : les AppState construits en isolation (sans
    // `install_session_filter_cache_prewarm`) ont `enforced=false` et
    // `generation_slot=None`. Dans ce cas, on retombe sur la route
    // historique (lecture des caches live) pour ne pas casser la
    // batterie de tests existante. En prod,
    // `install_session_filter_cache_prewarm` pose `enforced=true` et
    // la route exige la génération READY.
    let enforcement_active = state
        .inner
        .session_filter_cache_readiness
        .lock()
        .map(|r| r.enforced)
        .unwrap_or(false);
    let generation: Option<Arc<FilterGeneration>> = state
        .inner
        .generation_slot
        .read()
        .ok()
        .and_then(|slot| slot.clone());
    if enforcement_active && generation.is_none() {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "SESSION_FILTER_CACHE_WARMING",
            "no READY generation yet; publication prewarm in progress",
        );
    }
    audit_phase("generation_fetch");
    // Si `generation` est `Some`, on lit depuis l'Arc'd snapshot ; sinon
    // (tests), on retombe sur les caches live (`state.inner.journey_index_cache`,
    // `session_filter_index`, `list_row_cache`) via `cached_journey_index` +
    // `state.inner.session_filter_index.read()`.
    let journey_index = match generation.as_ref() {
        Some(gen) => gen.journey_index.clone(),
        None => {
            state.refresh_session_filter_index();
            cached_journey_index(&state)
        }
    };
    audit_phase("journey_index_from_generation");

    let messages: Vec<(Option<String>, String)> = request
        .messages
        .into_iter()
        .map(|m| (m.interface, m.name))
        .collect();
    let causes: Vec<(Option<String>, String)> = request
        .causes
        .into_iter()
        .map(|c| (c.domain, c.value))
        .collect();

    // Calcul du pseudonyme à matcher. La valeur brute vit
    // uniquement dans cette variable locale, consommée par
    // `pseudonym(...)` et jamais relue.
    let (identity_pseudonym, _identity_value_dropped) = match request.identity {
        Some(identity) => {
            let Some(kind) = session_filters::IdentityKind::parse(&identity.kind) else {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "IDENTITY_KIND_UNKNOWN",
                    "identity.kind must be one of supi_or_imsi | imei_or_pei | guti_or_tmsi | s_tmsi",
                );
            };
            if identity.value.is_empty() {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "IDENTITY_VALUE_EMPTY",
                    "identity.value must be a non-empty string",
                );
            }
            let key = state.inner.capture_manager.pseudonym_key();
            let pseudo = event_schema::pseudonym(
                key.as_ref(),
                kind.pseudo_domain(),
                identity.value.as_bytes(),
            );
            // `identity.value` goes out of scope immediately after
            // this binding — Rust drops the String.
            (Some(pseudo), ())
        }
        None => (None, ()),
    };

    // 2.10.1 (revue devmat) : la clé de tri de pagination est
    // `(anchor_capture_id, first_packet_number, session_id)` —
    // JAMAIS un timestamp. Elle vient de `SessionFilterIndex`,
    // qui l'a calculée à partir des events (capture_id min +
    // packet_number min sur ce capture_id).
    let (matching_keys, sorted_ids): (
        std::collections::BTreeMap<String, (String, u64, String)>,
        Vec<String>,
    ) = {
        // 2.21.85 — lecture depuis l'Arc'd snapshot si enforcement ;
        // sinon (tests), repli sur le cache live en RwLock.
        let fallback_guard;
        let guard: &session_filters::SessionFilterIndex = match generation.as_ref() {
            Some(gen) => &gen.filter_index,
            None => {
                fallback_guard = state
                    .inner
                    .session_filter_index
                    .read()
                    .expect("session_filter_index poisoned");
                &*fallback_guard
            }
        };
        let matching: Vec<String> = guard
            .filter(
                &messages,
                &causes,
                request.failures_only,
                identity_pseudonym.as_deref(),
            )
            .into_iter()
            .map(str::to_owned)
            .collect();
        let keys: std::collections::BTreeMap<String, (String, u64, String)> = matching
            .iter()
            .filter_map(|id| {
                guard
                    .pagination_key(id)
                    .map(|(cap, pkt, sid)| (id.clone(), (cap.to_owned(), pkt, sid.to_owned())))
            })
            .collect();
        let mut rows: Vec<(String, (String, u64, String))> = matching
            .into_iter()
            .filter_map(|id| keys.get(&id).map(|k| (id.clone(), k.clone())))
            .collect();
        rows.sort_by(|a, b| a.1.cmp(&b.1));
        let sorted: Vec<String> = rows.into_iter().map(|(id, _)| id).collect();
        (keys, sorted)
    };

    // Curseur : index à démarrer DANS `sorted_ids`. Si fourni,
    // on cherche le session_id post-curseur strict (clé
    // canonique strictement supérieure).
    // 2.19.1 — `limit=0` est un aperçu : on renvoie meta.total
    // seul, sans construire aucune ligne. `limit=None` conserve le
    // défaut 25. Autres valeurs clampées à [1, 100].
    let limit_requested = request.limit;
    let limit = match limit_requested {
        Some(0) => 0,
        Some(n) => n.clamp(1, 100),
        None => 25,
    };

    // 2.19.0 — valide `columns` tôt (avant tout calcul coûteux) :
    // un nom hors catalog devient 400 UNKNOWN_COLUMN, aucune ligne
    // partielle n'est servie.
    let projected_columns = match request.columns.as_deref() {
        Some(names) => match session_catalog::validate_columns(names) {
            Ok(set) => Some(set),
            Err(unknown) => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "UNKNOWN_COLUMN",
                    &format!("unknown column name: {unknown}"),
                );
            }
        },
        None => None,
    };

    // 2.19.0 — extended filters normalisés en sets (OR interne,
    // AND entre familles).
    let technologies: std::collections::BTreeSet<String> =
        request.technologies.into_iter().collect();
    let dataset_kinds: std::collections::BTreeSet<String> =
        request.dataset_kinds.into_iter().collect();
    let states: std::collections::BTreeSet<String> = request.states.into_iter().collect();
    let correlation_statuses: std::collections::BTreeSet<String> =
        request.correlation_statuses.into_iter().collect();
    // 2.19.1 — prédicats protocolaires + time window + network
    // elements + search + run_id. Validation précoce : opérateur
    // requis si search ressemble à un IMSI (règle vie privée).
    let criteria = request.criteria;
    let combinator = request.combinator;
    for (i, c) in criteria.iter().enumerate() {
        if !matches!(
            c.op.as_str(),
            "eq" | "ne" | "gt" | "lt" | "contains" | "in"
        ) {
            return api_error(
                StatusCode::BAD_REQUEST,
                "UNKNOWN_CRITERION_OP",
                &format!(
                    "criteria[{i}].op must be one of eq|ne|gt|lt|contains|in"
                ),
            );
        }
    }
    let network_elements_scope: std::collections::BTreeSet<String> =
        request.network_elements.into_iter().collect();
    let (from_ns, to_ns) = match &request.time_window {
        Some(window) => (parse_ns(&window.from), parse_ns(&window.to)),
        None => (None, None),
    };
    let run_id_filter = request.run_id.clone();
    let mut free_text_search: Option<String> = None;
    let mut search_pseudonym: Option<String> = None;
    if let Some(raw_search) = request.search.as_deref() {
        let trimmed = raw_search.trim();
        if !trimmed.is_empty() {
            let looks_like_imsi = trimmed.len() >= 14
                && trimmed.len() <= 16
                && trimmed.chars().all(|c| c.is_ascii_digit());
            if looks_like_imsi {
                if !role.can_control() {
                    return api_error(
                        StatusCode::FORBIDDEN,
                        "IDENTITY_FILTER_OPERATOR_REQUIRED",
                        "imsi-shaped search requires an operator bearer",
                    );
                }
                let key = state.inner.capture_manager.pseudonym_key();
                let kind = session_filters::IdentityKind::SupiOrImsi;
                search_pseudonym = Some(event_schema::pseudonym(
                    key.as_ref(),
                    kind.pseudo_domain(),
                    trimmed.as_bytes(),
                ));
                // La valeur brute `trimmed` est droppée ici.
            } else {
                free_text_search = Some(trimmed.to_ascii_lowercase());
            }
        }
    }
    let has_2191_filter = !criteria.is_empty()
        || !network_elements_scope.is_empty()
        || from_ns.is_some()
        || to_ns.is_some()
        || run_id_filter.is_some()
        || free_text_search.is_some()
        || search_pseudonym.is_some();
    let needs_flow_for_match = !criteria.is_empty()
        || !network_elements_scope.is_empty()
        || run_id_filter.is_some()
        || free_text_search.is_some()
        || search_pseudonym.is_some();
    let needs_summary_for_match = !technologies.is_empty()
        || !dataset_kinds.is_empty()
        || !states.is_empty()
        || !correlation_statuses.is_empty();
    let has_extended_filter = !technologies.is_empty()
        || !dataset_kinds.is_empty()
        || !states.is_empty()
        || !correlation_statuses.is_empty()
        || has_2191_filter;

    // Helper local : récupère/construit le summary complet d'une
    // session par id. Jamais d'ajout de clé — retourne None si
    // aucune source ne connaît l'id (session supprimée entre
    // l'index et la résolution).
    // 2.21.85 (CLAUDE1, ordre #9 7016931409, condition 2) — si la
    // génération READY est servie, on prend la ligne pré-rendue dans
    // `gen.rows_by_session` AVANT toute lecture disque. Garantie
    // GC-survival : l'index secondaire est Arc'd avec la génération,
    // il survit à la suppression des fichiers du dataset. Les sources
    // live (`state.inner.flows`, `capture_manager.datasets()` +
    // `cached_live_list_row`, LTE evidence) restent accessibles pour
    // les tests isolés (enforcement off) et les sessions absentes du
    // snapshot (régression de corpus entre l'index et la lecture).
    let resolve_from_generation = |session_id: &str| -> Option<Value> {
        let gen = generation.as_ref()?;
        let (prebuilt_summary, events_identities) = gen.rows_by_session.get(session_id)?;
        let mut summary = prebuilt_summary.clone();
        decorate_subscriber_summary_by_id(&mut summary, session_id, &journey_index);
        if let Some(object) = summary.as_object_mut() {
            let mut identities = identity_summary_for_session(&state, session_id);
            if identities.is_null() {
                schedule_identity_hydration(&state, session_id);
                identities = events_identities.clone();
            } else {
                fill_missing_identities(&mut identities, events_identities);
            }
            object.insert("identities".into(), identities);
        }
        Some(summary)
    };
    let resolve_summary = |session_id: &str| -> Option<Value> {
        if let Some(from_gen) = resolve_from_generation(session_id) {
            return Some(from_gen);
        }
        if let Some(flow) = state.inner.flows.get(session_id) {
            let mut summary = session_summary(&state, flow);
            decorate_subscriber_summary(&mut summary, flow, &journey_index);
            insert_list_identities(&state, &mut summary, &flow.session_id, Some(&flow.events));
            return Some(summary);
        }
        for dataset in state.inner.capture_manager.datasets() {
            let matching_id = dataset
                .session_ids
                .iter()
                .find(|id| id.as_str() == session_id);
            if let Some(owned_id) = matching_id {
                if let Some(summary) =
                    cached_live_list_row(&state, &dataset, owned_id, &journey_index)
                {
                    return Some(summary);
                }
            }
        }
        if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
            for manifest in catalog {
                if let Ok(page) = state
                    .inner
                    .lte_evidence_store
                    .session_page(&manifest.run_id, 1, 100)
                {
                    if let Some(records) = page["data"].as_array() {
                        for record in records {
                            if let Ok(session) = serde_json::from_value::<LteSession>(record.clone())
                            {
                                if session.session_id == session_id {
                                    let mut summary = lte_session_summary(&manifest, &session);
                                    insert_list_identities(
                                        &state,
                                        &mut summary,
                                        &session.session_id,
                                        None,
                                    );
                                    return Some(summary);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    };

    // 2.19.0/2.19.1 — si extended filters présents, on filtre puis on
    // re-trie par clé canonique conservée dans matching_keys (jamais par
    // ts). 2.21.52 : le prédicat `time_window` lit les bornes déjà calculées
    // dans `SessionFilterIndex`, avant toute résolution de callflow ou de
    // summary. L'ordre canonique de sortie reste identique.
    let mut matched_hits_by_session: BTreeMap<String, Vec<session_catalog::CriterionHit>> =
        BTreeMap::new();
    let (effective_sorted_ids, prebuilt_items): (Vec<String>, Option<BTreeMap<String, Value>>) =
        if has_extended_filter {
            let mut built: BTreeMap<String, Value> = BTreeMap::new();
            let mut matching_extended = Vec::new();
            for session_id in &sorted_ids {
                // 2.21.52 : la fenêtre lit les bornes de l'index. Aucun
                // callflow n'est relu pour ce prédicat, y compris sur
                // `limit=0` (aperçu exact).
                if from_ns.is_some() || to_ns.is_some() {
                    // 2.21.85 — lecture depuis l'Arc'd snapshot si
                    // enforcement actif, sinon repli sur le cache live.
                    let overlaps = match generation.as_ref() {
                        Some(gen) => gen
                            .filter_index
                            .overlaps_time_window(session_id, from_ns, to_ns),
                        None => state
                            .inner
                            .session_filter_index
                            .read()
                            .expect("session_filter_index poisoned")
                            .overlaps_time_window(session_id, from_ns, to_ns),
                    };
                    if !overlaps {
                        continue;
                    }
                }
                #[cfg(test)]
                if needs_flow_for_match {
                    state
                        .inner
                        .filter_flow_resolutions
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let flow_for_match: Option<&CallFlow> = if needs_flow_for_match {
                    state.inner.flows.get(session_id)
                } else {
                    None
                };
                let owned_live_flow: Option<CallFlow> =
                    if needs_flow_for_match && flow_for_match.is_none() {
                        live_flow_for(&state, session_id).map(|(_, flow)| flow)
                    } else {
                        None
                    };
                let events_ref: &[callflow_schema::CallFlowEvent] =
                    match (flow_for_match, &owned_live_flow) {
                        (Some(f), _) => f.events.as_slice(),
                        (None, Some(f)) => f.events.as_slice(),
                        _ => &[],
                    };
                let summary = if needs_summary_for_match {
                    let Some(summary) = resolve_summary(session_id) else {
                        continue;
                    };
                    if !passes_extended_filter(
                        &summary,
                        &technologies,
                        &dataset_kinds,
                        &states,
                        &correlation_statuses,
                    ) {
                        continue;
                    }
                    Some(summary)
                } else {
                    None
                };
                // 2.19.1 — filtres protocolaires + time window +
                // run_id + search + network_elements. Besoin des
                // events du flow pour matcher criteria/search.
                let participants_ref: &[callflow_schema::Participant] =
                    match (flow_for_match, &owned_live_flow) {
                        (Some(f), _) => f.participants.as_slice(),
                        (None, Some(f)) => f.participants.as_slice(),
                        _ => &[],
                    };
                let capture_references_ref: &[String] =
                    match (flow_for_match, &owned_live_flow) {
                        (Some(f), _) => f.capture_references.as_slice(),
                        (None, Some(f)) => f.capture_references.as_slice(),
                        _ => &[],
                    };

                // 2.19.1 : network_elements AND entre familles.
                if !network_elements_scope.is_empty() {
                    let has_role = participants_ref.iter().any(|p| {
                        network_elements_scope
                            .iter()
                            .any(|needle| p.role.eq_ignore_ascii_case(needle))
                    });
                    if !has_role {
                        continue;
                    }
                }
                // 2.19.1 : run_id (capture_references porte les ids).
                if let Some(run) = run_id_filter.as_deref() {
                    if !capture_references_ref.iter().any(|r| r == run) {
                        continue;
                    }
                }
                // 2.19.1 : free text search.
                if let Some(needle) = &free_text_search {
                    let hit = events_ref.iter().any(|event| {
                        event.message_name.to_ascii_lowercase().contains(needle)
                            || event
                                .decoded_ie_tree
                                .to_string()
                                .to_ascii_lowercase()
                                .contains(needle)
                    });
                    if !hit {
                        continue;
                    }
                }
                // 2.19.1 : search IMSI → pseudonyme (substring sur
                // decoded_ie_tree, même sémantique que live_trace).
                if let Some(pseudo) = &search_pseudonym {
                    let hit = events_ref.iter().any(|event| {
                        event.decoded_ie_tree.to_string().contains(pseudo)
                    });
                    if !hit {
                        continue;
                    }
                }
                // 2.19.1 : criteria + combinator.
                let (hits, passes) = session_catalog::aggregate_session_hits(
                    events_ref,
                    &criteria,
                    &combinator,
                );
                if !passes {
                    continue;
                }
                if !hits.is_empty() {
                    matched_hits_by_session.insert(session_id.clone(), hits);
                }
                matching_extended.push(session_id.clone());
                if let Some(summary) = summary {
                    built.insert(session_id.clone(), summary);
                }
            }
            let mut rows: Vec<(String, (String, u64, String))> = matching_extended
                .iter()
                .filter_map(|id| matching_keys.get(id).map(|k| (id.clone(), k.clone())))
                .collect();
            rows.sort_by(|a, b| a.1.cmp(&b.1));
            (
                rows.into_iter().map(|(id, _)| id).collect(),
                needs_summary_for_match.then_some(built),
            )
        } else {
            (sorted_ids.clone(), None)
        };
    audit_phase("match_and_order");

    let start_index = match request.cursor.as_deref() {
        None => 0,
        Some(cursor_sid) => match matching_keys.get(cursor_sid) {
            Some(cursor_key) => effective_sorted_ids
                .iter()
                .position(|id| {
                    matching_keys
                        .get(id)
                        .map(|k| k > cursor_key)
                        .unwrap_or(false)
                })
                .unwrap_or(effective_sorted_ids.len()),
            None => {
                // Curseur pointant vers une session qui n'est
                // plus dans le set filtré : traité comme
                // fin-de-flux.
                effective_sorted_ids.len()
            }
        },
    };
    // 2.19.1 — `limit=0` : aperçu, on renvoie meta.total seul.
    if limit == 0 {
        let total = effective_sorted_ids.len();
        let mut response = serde_json::json!({
            "data": Vec::<Value>::new(),
            "meta": {
                "api_version": API_VERSION,
                "limit": 0,
                "total": total,
                "role": role.name(),
                "next_cursor": Value::Null,
                "pagination_key": "(anchor_capture_id, first_packet_number, session_id)",
                "preview": true,
            }
        });
        if let Some(pseudo) = identity_pseudonym.as_deref() {
            response["meta"]["identity_matched_pseudonym"] =
                serde_json::Value::String(pseudo.to_owned());
        }
        if let Some(pseudo) = search_pseudonym.as_deref() {
            response["meta"]["search_matched_pseudonym"] =
                serde_json::Value::String(pseudo.to_owned());
        }
        audit_phase("serialize_preview");
        return match (enforcement_active, generation.as_ref()) {
            (true, Some(gen)) => build_filter_response(response, gen),
            _ => (StatusCode::OK, Json(response)).into_response(),
        };
    }

    let page_ids: Vec<&str> = effective_sorted_ids
        .iter()
        .skip(start_index)
        .take(limit)
        .map(String::as_str)
        .collect();
    let next_cursor: Option<&str> =
        if start_index + page_ids.len() < effective_sorted_ids.len() {
            page_ids.last().copied()
        } else {
            None
        };

    // Reconstitue les summaries sessions pour les ids de la
    // page. Même ordre canonique qu'au tri (pas de re-sort par
    // `ts` dans cette étape). Fast path : build paresseux par
    // page. Extended filter : on réutilise `prebuilt_items`.
    let page_set: std::collections::BTreeSet<&str> = page_ids.iter().copied().collect();
    let page_construction_started = std::time::Instant::now();
    let list_cache_before = state
        .inner
        .list_row_cache
        .lock()
        .map(|cache| cache.len())
        .unwrap_or(0);
    let mut items_by_id: std::collections::BTreeMap<String, Value> =
        std::collections::BTreeMap::new();
    if let Some(mut prebuilt) = prebuilt_items {
        for session_id in page_ids.iter() {
            if let Some(summary) = prebuilt.remove(*session_id) {
                items_by_id.insert((*session_id).to_owned(), summary);
            }
        }
    } else {
        // 2.21.85 (CLAUDE1, ordre #9 7016931409, condition 2) — si une
        // génération READY est servie, on tire d'abord les lignes
        // pré-rendues de `gen.rows_by_session` (Arc immuable, survit à
        // un GC des fichiers du dataset qui l'a nourrie). On complète
        // ensuite avec `state.inner.flows` qui est un BTreeMap en
        // mémoire (dataset de référence construit à `AppState::load`,
        // jamais GC'd) : ni l'un ni l'autre ne touche le disque.
        // Les lignes live manquantes NE SONT lues du disque que si
        // aucune génération n'est servie (fallback tests isolés).
        for session_id in page_ids.iter() {
            if let Some(summary) = resolve_from_generation(session_id) {
                items_by_id.insert((*session_id).to_owned(), summary);
            }
        }
        for flow in state.inner.flows.values() {
            if page_set.contains(flow.session_id.as_str())
                && !items_by_id.contains_key(flow.session_id.as_str())
            {
                let mut summary = session_summary(&state, flow);
                decorate_subscriber_summary(&mut summary, flow, &journey_index);
                insert_list_identities(
                    &state,
                    &mut summary,
                    &flow.session_id,
                    Some(&flow.events),
                );
                items_by_id.insert(flow.session_id.clone(), summary);
            }
        }
        if generation.is_none() {
            for dataset in state.inner.capture_manager.datasets() {
                for session_id in &dataset.session_ids {
                    if !page_set.contains(session_id.as_str())
                        || items_by_id.contains_key(session_id.as_str())
                    {
                        continue;
                    }
                    if let Some(summary) =
                        cached_live_list_row(&state, &dataset, session_id, &journey_index)
                    {
                        items_by_id.insert(session_id.clone(), summary);
                    }
                }
            }
        }
        if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
            for manifest in catalog {
                if let Ok(page) = state
                    .inner
                    .lte_evidence_store
                    .session_page(&manifest.run_id, 1, 100)
                {
                    if let Some(records) = page["data"].as_array() {
                        for record in records {
                            if let Ok(session) =
                                serde_json::from_value::<LteSession>(record.clone())
                            {
                                if page_set.contains(session.session_id.as_str()) {
                                    let mut summary = lte_session_summary(&manifest, &session);
                                    insert_list_identities(
                                        &state,
                                        &mut summary,
                                        &session.session_id,
                                        None,
                                    );
                                    items_by_id.insert(session.session_id.clone(), summary);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if audit_enabled {
        let list_cache_after = state
            .inner
            .list_row_cache
            .lock()
            .map(|cache| cache.len())
            .unwrap_or(0);
        eprintln!(
            "SESSIONS_FILTER_PAGE_CONSTRUCTION requested_rows={} resolved_rows={} cache_before={} cache_after={} identity_hydrations_running={} elapsed_ms={}",
            page_ids.len(),
            items_by_id.len(),
            list_cache_before,
            list_cache_after,
            IDENTITY_HYDRATION_RUNNING.load(std::sync::atomic::Ordering::Relaxed),
            page_construction_started.elapsed().as_millis()
        );
    }
    audit_phase("page_summaries");
    // Assemble la page DANS l'ordre canonique page_ids — pas
    // de re-sort sur `ts` ou autre après ça.
    let mut data: Vec<Value> = page_ids
        .iter()
        .filter_map(|id| items_by_id.remove(*id))
        .collect();
    // 2.19.0 — projection colonnes (serveur) avant sanitize.
    if let Some(ref requested) = projected_columns {
        for item in data.iter_mut() {
            session_catalog::project_columns(item, requested);
        }
    }
    // 2.19.1 — injecter matched_criteria APRÈS projection : c'est
    // une preuve de match (pas une colonne), toujours publiée
    // quand `criteria` est fourni.
    if !criteria.is_empty() {
        for item in data.iter_mut() {
            let session_id_opt = item["session_id"].as_str().map(str::to_owned);
            let Some(session_id) = session_id_opt else { continue };
            let arr: Vec<Value> = matched_hits_by_session
                .get(&session_id)
                .map(|hits| {
                    hits.iter()
                        .map(session_catalog::criterion_hit_to_json)
                        .collect()
                })
                .unwrap_or_default();
            if let Some(object) = item.as_object_mut() {
                object.insert("matched_criteria".into(), Value::Array(arr));
            }
        }
    }
    sanitize_all(&mut data);

    let total = effective_sorted_ids.len();
    let mut response = serde_json::json!({
        "data": data,
        "meta": {
            "api_version": API_VERSION,
            "limit": limit,
            "total": total,
            "role": role.name(),
            "next_cursor": next_cursor,
            // 2.10.1 : clé de pagination documentée en réponse —
            // reviewers peuvent auditer l'invariant "jamais ts".
            "pagination_key": "(anchor_capture_id, first_packet_number, session_id)",
        }
    });
    if let Some(pseudo) = identity_pseudonym.as_deref() {
        response["meta"]["identity_matched_pseudonym"] =
            serde_json::Value::String(pseudo.to_owned());
    }
    if let Some(pseudo) = search_pseudonym.as_deref() {
        response["meta"]["search_matched_pseudonym"] =
            serde_json::Value::String(pseudo.to_owned());
    }
    if let Some(ref requested) = projected_columns {
        response["meta"]["projected_columns"] = serde_json::to_value(
            requested
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        )
        .unwrap_or(Value::Null);
    }
    if !criteria.is_empty() {
        response["meta"]["criteria_combinator"] = match combinator {
            session_catalog::FilterCombinator::And => Value::String("and".to_owned()),
            session_catalog::FilterCombinator::Or => Value::String("or".to_owned()),
        };
    }
    audit_phase("decorate_page");
    // 2.21.85 — n'ajoute les en-têtes et le `meta.generation/commit_seq/
    // stale_since_ms` QUE lorsque l'enforcement est actif (chemin
    // production avec `install_session_filter_cache_prewarm`). Les
    // tests construits en isolation gardent une réponse strictement
    // identique à 2.21.74.
    match (enforcement_active, generation.as_ref()) {
        (true, Some(gen)) => build_filter_response(response, gen),
        _ => (StatusCode::OK, Json(response)).into_response(),
    }
}

/// 2.21.85 (CLAUDE1, ordre #9 7015585561) — ajoute les champs
/// `generation`, `commit_seq`, `stale_since_ms` au `meta` du body ET
/// les en-têtes `X-Oiran-Generation`, `X-Oiran-Commit-Seq`,
/// `X-Oiran-Stale-Since-Ms`. La p900 (ou tout consommateur CLI) peut
/// afficher « vue t = N s » en lisant soit le body soit les headers.
fn build_filter_response(mut body: Value, generation: &FilterGeneration) -> Response {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let stale_since_ms = generation.stale_since_ms(now_ms);
    if let Some(meta) = body.get_mut("meta").and_then(Value::as_object_mut) {
        meta.insert("generation".into(), json!(generation.generation));
        meta.insert("commit_seq".into(), json!(generation.commit_seq));
        meta.insert("stale_since_ms".into(), json!(stale_since_ms));
    }
    let mut response = (StatusCode::OK, Json(body)).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(&generation.generation.to_string()) {
        response.headers_mut().insert("x-oiran-generation", value);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&generation.commit_seq.to_string()) {
        response.headers_mut().insert("x-oiran-commit-seq", value);
    }
    if let Ok(value) = axum::http::HeaderValue::from_str(&stale_since_ms.to_string()) {
        response.headers_mut().insert("x-oiran-stale-since-ms", value);
    }
    response
}

/// 2.19.0 — AND entre familles (OR interne à chaque famille). Un
/// summary passe le filtre ssi, pour chaque famille non vide, il
/// matche au moins une valeur. Lecture uniquement : aucune
/// mutation du summary.
fn passes_extended_filter(
    summary: &Value,
    technologies: &std::collections::BTreeSet<String>,
    dataset_kinds: &std::collections::BTreeSet<String>,
    states: &std::collections::BTreeSet<String>,
    correlation_statuses: &std::collections::BTreeSet<String>,
) -> bool {
    fn matches_any(set: &std::collections::BTreeSet<String>, value: Option<&str>) -> bool {
        if set.is_empty() {
            return true;
        }
        match value {
            Some(v) => set.contains(v),
            None => false,
        }
    }
    matches_any(technologies, summary["technology"].as_str())
        && matches_any(dataset_kinds, summary["dataset_kind"].as_str())
        && matches_any(states, summary["state"].as_str())
        && matches_any(correlation_statuses, summary["correlation_status"].as_str())
}

/// 2.19.1 — construit un arbre protocolaire à partir des events
/// statiques courants, scopés par (interfaces, technologies,
/// time_window, run_id). Lecture uniquement.
fn build_protocol_tree(
    state: &AppState,
    interfaces_scope: &std::collections::BTreeSet<String>,
    technologies_scope: &std::collections::BTreeSet<String>,
    from_ns: Option<i128>,
    to_ns: Option<i128>,
    run_id: Option<&str>,
) -> session_catalog::ProtocolTreeBuilder {
    let mut builder = session_catalog::ProtocolTreeBuilder::new();
    let feed = |builder: &mut session_catalog::ProtocolTreeBuilder, flow: &CallFlow| {
        if !technologies_scope.is_empty() && !technologies_scope.contains(&flow.technology) {
            return;
        }
        if let Some(run) = run_id {
            if !flow.capture_references.iter().any(|r| r == run) {
                return;
            }
        }
        for participant in &flow.participants {
            for address in &participant.addresses {
                builder.observe_participant(&participant.role, address);
            }
        }
        for event in &flow.events {
            if !interfaces_scope.is_empty() && !interfaces_scope.contains(&event.interface) {
                continue;
            }
            if let Some(from) = from_ns {
                if event.timestamp_ns.parse::<i128>().map_or(false, |ts| ts < from) {
                    continue;
                }
            }
            if let Some(to) = to_ns {
                if event.timestamp_ns.parse::<i128>().map_or(false, |ts| ts > to) {
                    continue;
                }
            }
            builder.observe_event(event);
        }
    };
    // 2.21.10 (défaut 2 #9 6929162657) — en production, `state.inner.flows`
    // est vide (iso-comportement opérationnel ; les flows live sont lus
    // via le capture_manager). Résultat : `protocol_tree=0` et
    // `network_elements=0` sur le dataset réel. Correctif : alimenter
    // aussi le builder depuis les datasets live.
    for flow in state.inner.flows.values() {
        feed(&mut builder, flow);
    }
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if let Some(flow) = state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
            {
                feed(&mut builder, &flow);
            }
        }
    }
    builder
}

/// 2.19.1 — `GET /api/v1/sessions/catalog/search?q=&interfaces=&limit=50`.
/// Recherche insensible à la casse sur messages ET paramètres. Tri par
/// pertinence (exact > préfixe > contient). Jamais de liste figée :
/// 100 % issu de `ProtocolTreeBuilder` construit sur les events réels.
#[derive(Deserialize, Default, Clone)]
struct SessionsCatalogSearchQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    interfaces: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn sessions_catalog_search(
    State(state): State<AppState>,
    Query(query): Query<SessionsCatalogSearchQuery>,
) -> Response {
    // 2.21.20 — build_protocol_tree parcourt datasets + callflows.
    tokio::task::spawn_blocking(move || {
        let needle = match query.q.as_deref() {
            Some(s) if !s.trim().is_empty() => s.trim().to_owned(),
            _ => {
                return api_error(
                    StatusCode::BAD_REQUEST,
                    "SEARCH_QUERY_EMPTY",
                    "query parameter `q` is required and must be non-empty",
                );
            }
        };
        // 2.21.30 (ordres #9 6952054201 + 6952664027) — verrou mémoire
        // du gestionnaire. `build_protocol_tree` parcourt tous les
        // datasets + callflows : coexiste mal avec la publication.
        let Some(_heavy_memory_gate) = state.inner.capture_manager.heavy_memory_try_enter()
        else {
            return heavy_work_in_progress();
        };
        let limit = query.limit.unwrap_or(50).clamp(1, 200);
        let interfaces_scope = parse_csv(&query.interfaces);
        let empty_set = std::collections::BTreeSet::<String>::new();
        let builder =
            build_protocol_tree(&state, &interfaces_scope, &empty_set, None, None, None);
        let results = session_catalog::search_protocol_tree(
            &builder,
            &needle,
            &interfaces_scope,
            limit,
        );
        let total = results.len();
        ok(json!({
            "results": results,
            "query": {
                "q": needle,
                "interfaces": query.interfaces,
                "limit": limit,
            },
            "total": total,
        }))
        .into_response()
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SESSIONS_CATALOG_SEARCH_FAILED",
            "sessions_catalog_search handler panicked",
        )
    })
}

/// 2.19.1 — `GET /api/v1/sessions/catalog/param?interface=&protocol=
/// &message=&param_path=`. Fiche détaillée d'un paramètre
/// observé + ≤ 5 sessions d'exemple.
#[derive(Deserialize, Default)]
struct SessionsCatalogParamQuery {
    interface: String,
    protocol: String,
    message: String,
    param_path: String,
}

async fn sessions_catalog_param(
    State(state): State<AppState>,
    Query(query): Query<SessionsCatalogParamQuery>,
) -> Response {
    for (field, value) in [
        ("interface", &query.interface),
        ("protocol", &query.protocol),
        ("message", &query.message),
        ("param_path", &query.param_path),
    ] {
        if value.trim().is_empty() {
            return api_error(
                StatusCode::BAD_REQUEST,
                "PARAM_QUERY_INCOMPLETE",
                &format!("`{field}` query parameter is required"),
            );
        }
    }
    let empty_set = std::collections::BTreeSet::<String>::new();
    let builder = build_protocol_tree(&state, &empty_set, &empty_set, None, None, None);
    let mut body = match session_catalog::lookup_param(
        &builder,
        &query.interface,
        &query.protocol,
        &query.message,
        &query.param_path,
    ) {
        Some(body) => body,
        None => {
            return api_error(
                StatusCode::NOT_FOUND,
                "PARAM_NOT_OBSERVED",
                "no event in the current scope has observed this parameter",
            );
        }
    };
    // ≤ 5 sessions d'exemple avec preuve {event_id, capture_id, seq}.
    let flows_iter = state.inner.flows.values().map(|flow| {
        (
            flow.session_id.as_str(),
            flow.events.as_slice(),
        )
    });
    let examples = session_catalog::collect_param_example_sessions(
        flows_iter,
        &query.interface,
        &query.protocol,
        &query.message,
        &query.param_path,
        5,
    );
    if let Some(object) = body.as_object_mut() {
        object.insert("example_sessions".into(), Value::Array(examples));
    }
    ok(body).into_response()
}

/// 2.19.1 — query params du GET /sessions/catalog qui scopent la
/// construction de `protocol_tree` + `network_elements`.
#[derive(Deserialize, Default)]
struct SessionsCatalogQuery {
    #[serde(default)]
    interfaces: Option<String>,
    #[serde(default)]
    technologies: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
}

fn parse_csv(opt: &Option<String>) -> std::collections::BTreeSet<String> {
    opt.as_deref()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn parse_ns(opt: &Option<String>) -> Option<i128> {
    // Accepte un entier ns (format canonique dans l'app). L'UI
    // qui souhaite transmettre un RFC3339 convertit côté client ;
    // garder le serveur sans dépendance chrono.
    opt.as_deref().and_then(|raw| raw.trim().parse::<i128>().ok())
}

/// 2.19.0 (liste des filtres + colonnes) + 2.19.1 (protocol_tree +
/// network_elements scopés par query). Lecture seule.
async fn sessions_catalog(
    State(state): State<AppState>,
    Query(query): Query<SessionsCatalogQuery>,
) -> Response {
    state.refresh_session_filter_index();
    let guard = state
        .inner
        .session_filter_index
        .read()
        .expect("session_filter_index poisoned");
    let interfaces_distinct = session_catalog::distinct_interfaces(&guard);
    let messages = session_catalog::distinct_messages(&guard);
    let causes = guard.available_causes();
    let session_count = guard.session_count();
    drop(guard);

    // 2.19.1 — construction du protocol_tree. Scope :
    // interfaces ∈ query.interfaces (si fourni), technology ∈
    // query.technologies (si fourni), timestamp_ns ∈ [from, to]
    // (si fourni), dataset_id == run_id (si fourni). Jamais de
    // re-tri par ts : on filtre event-par-event mais les events
    // restent dans l'ordre fourni par le CallFlow (canonique).
    let interfaces_scope = parse_csv(&query.interfaces);
    let technologies_scope = parse_csv(&query.technologies);
    let from_ns = parse_ns(&query.from);
    let to_ns = parse_ns(&query.to);
    let run_id = query.run_id.clone();

    // 2.21.11 (défaut 2 #9 6930315055) — cache par
    // (commit_seq, dataset_ids, scope). Un hit évite le parcours
    // intégral de 217 call flows (45 s en prod).
    let dataset_signatures: Vec<(String, u64)> = state
        .inner
        .capture_manager
        .datasets()
        .into_iter()
        .map(|dataset| {
            let seq = state
                .inner
                .capture_manager
                .dataset_commit_seq(&dataset.dataset_id);
            (dataset.dataset_id, seq)
        })
        .collect();
    let scope_hash = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        for interface in &interfaces_scope {
            interface.hash(&mut hasher);
        }
        for technology in &technologies_scope {
            technology.hash(&mut hasher);
        }
        from_ns.hash(&mut hasher);
        to_ns.hash(&mut hasher);
        run_id.hash(&mut hasher);
        hasher.finish()
    };
    let cached = {
        let guard = state.inner.sessions_catalog_cache.lock().unwrap();
        guard.entry.as_ref().and_then(|entry| {
            (entry.dataset_signatures == dataset_signatures && entry.scope_hash == scope_hash)
                .then(|| (entry.protocol_tree.clone(), entry.network_elements.clone()))
        })
    };
    let (protocol_tree, network_elements) = if let Some(cached) = cached {
        cached
    } else {
        let builder = build_protocol_tree(
            &state,
            &interfaces_scope,
            &technologies_scope,
            from_ns,
            to_ns,
            run_id.as_deref(),
        );
        let protocol_tree = builder.to_protocol_tree_json();
        let network_elements = builder.to_network_elements_json();
        {
            let mut guard = state.inner.sessions_catalog_cache.lock().unwrap();
            guard.entry = Some(SessionsCatalogCacheEntry {
                dataset_signatures,
                scope_hash,
                protocol_tree: protocol_tree.clone(),
                network_elements: network_elements.clone(),
            });
        }
        (protocol_tree, network_elements)
    };

    let body = json!({
        "columns": session_catalog::columns_catalog(),
        "filters": {
            "interfaces": interfaces_distinct,
            "messages": messages,
            "causes": causes,
            "technologies": ["5G SA", "LTE"],
            "dataset_kinds": [
                "HISTORICAL",
                "CAPTURED_LIVE",
                "EVIDENCE",
                "DERIVED",
                "RECOVERED",
            ],
            "states": [
                "ACTIVE_WITH_USER_PLANE",
                "RELEASED",
                "INCOMPLETE",
                "HISTORICAL_CONTEXT",
                "UNKNOWN",
            ],
            "correlation_statuses": [
                "EXACT",
                "PARTIAL",
                "UNKNOWN",
            ],
            "pseudonym_match": "exact string from decoded IE",
        },
        "always_present_columns": session_catalog::ALWAYS_PRESENT_COLUMNS,
        "session_count": session_count,
        "protocol_tree": protocol_tree,
        "network_elements": network_elements,
        "scope": {
            "interfaces": query.interfaces,
            "technologies": query.technologies,
            "from": query.from,
            "to": query.to,
            "run_id": query.run_id,
        }
    });
    ok(body).into_response()
}

/// 2.19.0 — projection sur une liste d'ids : `{session_ids,
/// columns}`. Les colonnes `ALWAYS_PRESENT_COLUMNS` sont toujours
/// présentes. Les ids inconnus apparaissent dans
/// `meta.missing_session_ids`. Un nom de colonne inconnu → 400
/// `UNKNOWN_COLUMN`.
async fn sessions_columns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<session_catalog::SessionsColumnsRequest>,
) -> Response {
    // 2.21.20 — gros parcours datasets + callflows pour calcul des colonnes.
    tokio::task::spawn_blocking(move || sessions_columns_blocking(state, headers, request))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSIONS_COLUMNS_FAILED",
                "sessions_columns handler panicked",
            )
        })
}

fn sessions_columns_blocking(
    state: AppState,
    headers: HeaderMap,
    request: session_catalog::SessionsColumnsRequest,
) -> Response {
    let role = role_from_headers(&state, &headers);
    let requested_columns = match session_catalog::validate_columns(&request.columns) {
        Ok(set) => set,
        Err(unknown) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                "UNKNOWN_COLUMN",
                &format!("unknown column name: {unknown}"),
            );
        }
    };
    // 2.19.1 — valider les fields PROTOCOLAIRES.
    if let Err(msg) = session_catalog::validate_fields(&request.fields) {
        return api_error(StatusCode::BAD_REQUEST, "INVALID_FIELD", &msg);
    }
    if request.session_ids.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "SESSION_IDS_REQUIRED",
            "session_ids must be a non-empty array",
        );
    }
    // 2.21.30 (ordres #9 6952054201 + 6952664027) — verrou mémoire du
    // gestionnaire. `cached_journey_index` + lookups per session
    // coexistent mal avec la publication.
    let Some(_heavy_memory_gate) = state.inner.capture_manager.heavy_memory_try_enter() else {
        return heavy_work_in_progress();
    };
    let journey_index = cached_journey_index(&state);
    let mut data: Vec<Value> = Vec::with_capacity(request.session_ids.len());
    let mut missing: Vec<String> = Vec::new();
    for session_id in &request.session_ids {
        let summary_opt = resolve_summary_for_columns(&state, session_id, &journey_index);
        match summary_opt {
            Some(mut summary) => {
                session_catalog::project_columns(&mut summary, &requested_columns);
                // 2.19.1 — colonnes protocolaires + preuve.
                if !request.fields.is_empty() {
                    let events: Vec<callflow_schema::CallFlowEvent> =
                        if let Some(flow) = state.inner.flows.get(session_id) {
                            flow.events.clone()
                        } else if let Some((_, live)) = live_flow_for(&state, session_id) {
                            live.events
                        } else {
                            Vec::new()
                        };
                    let mut field_values: Vec<Value> = Vec::new();
                    for field in &request.fields {
                        if let Some(result) =
                            session_catalog::evaluate_field_on_session(&events, field)
                        {
                            field_values.push(session_catalog::field_result_to_json(
                                field, &result,
                            ));
                        }
                    }
                    if let Some(object) = summary.as_object_mut() {
                        object.insert("fields".into(), Value::Array(field_values));
                    }
                }
                data.push(summary);
            }
            None => missing.push(session_id.clone()),
        }
    }
    sanitize_all(&mut data);
    let response = json!({
        "data": data,
        "meta": {
            "api_version": API_VERSION,
            "role": role.name(),
            "projected_columns": requested_columns.iter().cloned().collect::<Vec<_>>(),
            "missing_session_ids": missing,
            "total": data.len(),
            "field_count": request.fields.len(),
        }
    });
    (StatusCode::OK, Json(response)).into_response()
}

/// 2.19.0 — même logique que la résolution dans `sessions_filter`
/// mais non-lambda pour pouvoir être appelée depuis
/// `sessions_columns`.
fn resolve_summary_for_columns(
    state: &AppState,
    session_id: &str,
    journey_index: &subscriber_journey::JourneyIndex,
) -> Option<Value> {
    if let Some(flow) = state.inner.flows.get(session_id) {
        let mut summary = session_summary(state, flow);
        decorate_subscriber_summary(&mut summary, flow, journey_index);
        insert_list_identities(state, &mut summary, &flow.session_id, Some(&flow.events));
        return Some(summary);
    }
    for dataset in state.inner.capture_manager.datasets() {
        let matching_id = dataset
            .session_ids
            .iter()
            .find(|id| id.as_str() == session_id);
        if let Some(owned_id) = matching_id {
            if let Some(summary) = cached_live_list_row(state, &dataset, owned_id, journey_index) {
                return Some(summary);
            }
        }
    }
    if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
        for manifest in catalog {
            if let Ok(page) = state
                .inner
                .lte_evidence_store
                .session_page(&manifest.run_id, 1, 100)
            {
                if let Some(records) = page["data"].as_array() {
                    for record in records {
                        if let Ok(session) = serde_json::from_value::<LteSession>(record.clone()) {
                            if session.session_id == session_id {
                                let mut summary = lte_session_summary(&manifest, &session);
                                insert_list_identities(
                                    state,
                                    &mut summary,
                                    &session.session_id,
                                    None,
                                );
                                return Some(summary);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

async fn session(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    // 2.21.17 — iteration datasets + callflow() + lte catalog en sync.
    tokio::task::spawn_blocking(move || session_blocking(&state, &id))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_FAILED",
                "session handler panicked",
            )
        })
}

fn session_blocking(state: &AppState, id: &str) -> Response {
    let journey_index = cached_journey_index(state);
    if let Some(flow) = flow_for(state, id) {
        let mut summary = session_summary(state, flow);
        decorate_subscriber_summary(&mut summary, flow, &journey_index);
        return ok(json!({"summary":summary,"procedures":flow.procedures,"accounting":flow.accounting,"capture_references":flow.capture_references})).into_response();
    }
    if let Some((dataset_id, flow)) = live_flow_for(state, id) {
        let dataset = state
            .inner
            .capture_manager
            .dataset(&dataset_id)
            .expect("live flow dataset remains registered");
        let mut summary = live_session_summary(&dataset, &flow);
        decorate_subscriber_summary(&mut summary, &flow, &journey_index);
        return ok(json!({"summary":summary,"procedures":flow.procedures,"accounting":flow.accounting,"capture_references":flow.capture_references})).into_response();
    }
    if let Ok(Some((manifest, lte))) = state.inner.lte_evidence_store.find_session(id) {
        let procedures = lte.procedures.iter().enumerate().map(|(index, name)| json!({
            "id":format!("lte-procedure-{index}"),"name":name,"event_ids":[],"status":"OBSERVED"
        })).collect::<Vec<_>>();
        let capture_references = manifest
            .source_capture_sha256
            .keys()
            .map(|plane| format!("capture:{plane}"))
            .collect::<Vec<_>>();
        let mut value = json!({
            "summary":lte_session_summary(&manifest,&lte),"procedures":procedures,
            "accounting":{"source_events":manifest.event_count,"session_events":lte.event_ids.len()},
            "capture_references":capture_references
        });
        sanitize_value(&mut value);
        return ok(value).into_response();
    }
    api_error(
        StatusCode::NOT_FOUND,
        "SESSION_NOT_FOUND",
        "unknown session id",
    )
}

// 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-04) — body JSON pour le POST
// `/identities/lookup`. Mêmes champs que l'ancien query GET, mais la
// valeur `value` (anciennement `q`) ne voyage plus dans l'URL.
#[derive(Deserialize)]
struct IdentityLookupBody {
    value: String,
    #[serde(default = "default_identity_lookup_page")]
    page: usize,
    #[serde(default = "default_identity_lookup_page_size")]
    page_size: usize,
}

fn default_identity_lookup_page() -> usize {
    1
}

fn default_identity_lookup_page_size() -> usize {
    50
}

#[derive(Clone)]
struct PacketIdentityEvidence {
    event_id: String,
    capture_id: String,
    packet_number: u64,
    message_name: String,
    subscriber_pseudonym: Option<String>,
}

const IDENTITY_TSHARK_FIELDS: &[&str] = &[
    "frame.number",
    "e212.imsi",
    "diameter.User-Name",
    "gsm_a.tmsi",
    "3gpp.tmsi",
    "ngap.aMFRegionID",
    "ngap.aMFSetID",
    "ngap.aMFPointer",
    "ngap.fiveG_TMSI",
    "s1ap.mME_Group_ID",
    "s1ap.mME_Code",
    "s1ap.m_TMSI",
    "gsm_a.imei",
    "gsm_a.imeisv",
    "gtpv2.mei",
    "diameter.IMEI",
    "diameter.user_equipment_info.imeisv",
    "e164.msisdn",
    "diameter.MSISDN",
    // 2.15.3 — NAS 5GS (TS 24.501). `e212.imsi` stays empty for a 5G SUCI:
    // TShark 4.2 exposes the null-scheme SUCI as MCC/MNC/MSIN (ANR1 proof
    // #10 6894182928, frame 1217 Registration Request).
    "nas-5gs.mm.suci.supi_fmt",
    "nas-5gs.mm.suci.scheme_id",
    "e212.mcc",
    "e212.mnc",
    "nas-5gs.mm.suci.msin",
    "nas-5gs.5g_tmsi",
    "nas-5gs.mm.imei",
    "nas-5gs.mm.imeisv",
];

/// 2.15.6 — field names known by the installed TShark (`tshark -G fields`),
/// computed once. Empty set = listing unavailable: every field is requested
/// as before.
fn available_identity_fields() -> &'static std::collections::HashSet<String> {
    static FIELDS: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    FIELDS.get_or_init(|| {
        let Ok(output) = Command::new("tshark").args(["-G", "fields"]).output() else {
            return std::collections::HashSet::new();
        };
        if !output.status.success() {
            return std::collections::HashSet::new();
        }
        parse_tshark_field_list(&String::from_utf8_lossy(&output.stdout))
    })
}

/// 2.18.8 — NAS 5GS protégé en intégrité avec chiffrement NULL (NEA0,
/// premier de `ciphering_order` Open5GS en lab) : TShark ne dissèque le
/// contenu (5G-GUTI/5G-TMSI de la Registration Accept, IMEISV de la
/// Security Mode Complete) qu'avec `nas-5gs.null_decipher:TRUE`. Préférence
/// ajoutée seulement si ce TShark la connaît (une préférence inconnue
/// fait échouer la commande entière) — sinon rien, et la raison est
/// journalisée une fois.
fn tshark_nas_null_decipher_supported() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let supported = Command::new("tshark")
            .args(["-G", "defaultprefs"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| tshark_prefs_contain_null_decipher(&String::from_utf8_lossy(&output.stdout)))
            .unwrap_or(false);
        if !supported {
            eprintln!("oiran-api: tshark sans préférence nas-5gs.null_decipher — NAS 5GS NEA0 non dissequé");
        }
        supported
    })
}

fn tshark_prefs_contain_null_decipher(defaultprefs: &str) -> bool {
    defaultprefs
        .lines()
        .any(|line| line.trim_start_matches(['#', ' ']).starts_with("nas-5gs.null_decipher:"))
}

/// `tshark -G fields` lines: `F\t<name>\t<abbrev>\t...` → set of abbrevs.
fn parse_tshark_field_list(stdout: &str) -> std::collections::HashSet<String> {
    stdout
        .lines()
        .filter(|line| line.starts_with("F\t"))
        .filter_map(|line| line.split('\t').nth(2).map(str::to_owned))
        .collect()
}

/// 2.15.3 — SUPI (IMSI) from a null-scheme SUCI as dissected by TShark:
/// only SUPI format 0 (IMSI) with protection scheme 0 (null) is readable;
/// any other scheme is ciphered (ECIES) and yields None.
fn supi_from_null_scheme_suci(
    supi_fmt: &str,
    scheme_id: &str,
    mcc: &str,
    mnc: &str,
    msin: &str,
) -> Option<String> {
    let first = |v: &str| v.split(',').next().unwrap_or("").trim().to_string();
    let (fmt, scheme, mcc, mnc, msin) = (
        first(supi_fmt),
        first(scheme_id),
        first(mcc),
        first(mnc),
        first(msin),
    );
    let digits = |v: &str| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
    let zero = |v: &str| v.parse::<u32>().ok() == Some(0) || v == "0x00" || v == "0x0";
    if !zero(&fmt) || !zero(&scheme) {
        return None;
    }
    if !(digits(&mcc)
        && mcc.len() == 3
        && digits(&mnc)
        && (2..=3).contains(&mnc.len())
        && digits(&msin))
    {
        return None;
    }
    let imsi = format!("{mcc}{mnc}{msin}");
    (imsi.len() <= 15 && imsi.len() >= 14).then_some(imsi)
}

fn session_flow(state: &AppState, id: &str) -> Option<CallFlow> {
    flow_for(state, id)
        .cloned()
        .or_else(|| live_flow_for(state, id).map(|(_, flow)| flow))
        .or_else(|| {
            state
                .inner
                .lte_evidence_store
                .callflow_for_export_by_session(id)
                .ok()
                .flatten()
        })
}

fn resolve_source_path(state: &AppState, source: &str) -> PathBuf {
    let source = PathBuf::from(source);
    if source.is_absolute() {
        source
    } else {
        state.inner.storage_path.join(source)
    }
}

fn decoded_pseudonym(value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => items.iter().find_map(decoded_pseudonym),
        Value::Object(map) => {
            let direct = map
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| matches!(*name, "subscriber_pseudonym" | "imsi_pseudonym"))
                .and_then(|_| map.get("value").and_then(Value::as_str))
                .map(str::to_owned);
            direct.or_else(|| map.values().find_map(decoded_pseudonym))
        }
        _ => None,
    }
}

fn split_field(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn identity_digits(value: &str) -> Option<String> {
    let value = value
        .trim()
        .strip_prefix("imsi-")
        .or_else(|| value.trim().strip_prefix("IMSI-"))
        .unwrap_or(value.trim());
    let digits = value
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    (digits.len() >= 5).then_some(digits)
}

fn canonical_tmsi(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        trimmed
            .parse::<u32>()
            .ok()
            .or_else(|| u32::from_str_radix(trimmed, 16).ok())
    }?;
    Some(format!("0x{parsed:08X}"))
}

fn identity_role(message_name: &str) -> &'static str {
    let lower = message_name.to_ascii_lowercase();
    if [
        "accept",
        "reallocation command",
        "configuration update command",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        "assigned"
    } else {
        "presented"
    }
}

fn push_identity(
    output: &mut Vec<IdentityObservation>,
    evidence: &PacketIdentityEvidence,
    kind: &str,
    value: String,
    value_type: Option<&str>,
    role: &str,
    subscriber_pseudonym: Option<String>,
) {
    push_identity_full(
        output,
        evidence,
        kind,
        value,
        value_type,
        role,
        subscriber_pseudonym,
        None,
    );
}

/// 2.15.2 (ANR1 #10 6885876387, D4, règle Sadok 2026-11-14) —
/// helper interne qui autorise le remplissage de `cleartext`. Appelé
/// uniquement pour les kinds autorisés (IMSI issu de `e212.imsi` =
/// IMSI EPS en clair ou SUPI null-scheme déchiffré par tshark). Les
/// autres kinds (GUTI, TMSI, IMEI, MSISDN) passent par `push_identity`
/// ci-dessus et restent `cleartext: None`.
fn push_identity_full(
    output: &mut Vec<IdentityObservation>,
    evidence: &PacketIdentityEvidence,
    kind: &str,
    value: String,
    value_type: Option<&str>,
    role: &str,
    subscriber_pseudonym: Option<String>,
    cleartext: Option<String>,
) {
    if value.is_empty() {
        return;
    }
    output.push(IdentityObservation {
        session_id: String::new(),
        subscriber_pseudonym,
        kind: kind.into(),
        value,
        value_type: value_type.map(str::to_owned),
        role: role.into(),
        event_id: evidence.event_id.clone(),
        capture_id: evidence.capture_id.clone(),
        packet_number: evidence.packet_number,
        cleartext,
    });
}

fn tshark_identities(
    state: &AppState,
    session_id: &str,
    flow: &CallFlow,
) -> Result<Vec<IdentityObservation>, String> {
    let mut by_file = BTreeMap::<PathBuf, BTreeMap<u64, PacketIdentityEvidence>>::new();
    for event in flow.events.iter().take(4096) {
        let pseudonym = decoded_pseudonym(&event.decoded_ie_tree);
        for reference in &event.packet_references {
            let source = resolve_source_path(state, &reference.source_file);
            if !source.is_file() {
                continue;
            }
            by_file
                .entry(source)
                .or_default()
                .entry(reference.packet_number)
                .or_insert_with(|| PacketIdentityEvidence {
                    event_id: event.event_id.clone(),
                    capture_id: event.capture_id.clone(),
                    packet_number: reference.packet_number,
                    message_name: event.message_name.clone(),
                    subscriber_pseudonym: pseudonym.clone(),
                });
        }
    }
    let mut observations = Vec::new();
    for (source, packets) in by_file {
        let filter = packets
            .keys()
            .map(|number| format!("frame.number == {number}"))
            .collect::<Vec<_>>()
            .join(" || ");
        let mut command = Command::new("tshark");
        command.arg("-n");
        if tshark_nas_null_decipher_supported() {
            command.args(["-o", "nas-5gs.null_decipher:TRUE"]);
        }
        command
            .arg("-r")
            .arg(&source)
            .args(["-Y", &filter, "-T", "fields"]);
        // 2.15.6 — only the fields this TShark knows: an unknown `-e` field
        // makes TShark reject the whole command (TShark 3.6.2 has no
        // `nas-5gs.mm.suci.*`, CLAUDE DEVMAT #10 6895890080 → 500 and no
        // identity at all). Columns are mapped back by field name.
        let available = available_identity_fields();
        let requested: Vec<&str> = IDENTITY_TSHARK_FIELDS
            .iter()
            .copied()
            .filter(|field| available.is_empty() || available.contains(*field))
            .collect();
        for field in &requested {
            command.args(["-e", field]);
        }
        command.args([
            "-E",
            "separator=\t",
            "-E",
            "quote=n",
            "-E",
            "occurrence=a",
            "-E",
            "aggregator=,",
        ]);
        let result = command.output().map_err(|_| "TSHARK_UNAVAILABLE")?;
        if !result.status.success() {
            return Err("TSHARK_DISSECTION_FAILED".into());
        }
        let stdout = String::from_utf8(result.stdout).map_err(|_| "TSHARK_OUTPUT_INVALID")?;
        for line in stdout.lines() {
            let columns = line.split('\t').collect::<Vec<_>>();
            let packet_number = columns.first().and_then(|value| value.parse::<u64>().ok());
            let Some(evidence) = packet_number.and_then(|number| packets.get(&number)) else {
                continue;
            };
            let role = identity_role(&evidence.message_name);
            // index into IDENTITY_TSHARK_FIELDS → column of the requested subset
            let field = |index: usize| {
                IDENTITY_TSHARK_FIELDS
                    .get(index)
                    .and_then(|name| requested.iter().position(|r| r == name))
                    .and_then(|column| columns.get(column).copied())
                    .unwrap_or("")
            };
            let suci_supi =
                supi_from_null_scheme_suci(field(19), field(20), field(21), field(22), field(23));
            for raw in split_field(field(1))
                .chain(split_field(field(2)))
                .chain(suci_supi.as_deref().into_iter())
            {
                if let Some(imsi) = identity_digits(raw) {
                    let pseudo = Some(pseudonym_subscriber_text(
                        state.inner.capture_manager.pseudonym_key().as_ref(),
                        imsi.as_bytes(),
                    ));
                    // 2.15.2 (D4, règle Sadok 2026-11-14) — tshark n'emit
                    // `e212.imsi` qu'une fois l'identité en clair pour
                    // l'Analyzer (IMSI EPS ou SUPI d'un SUCI null-scheme
                    // déchiffré par le dissecteur NAS). Ces deux cas sont
                    // précisément les kinds autorisés à exposer
                    // `IdentityObservation::cleartext` → UI
                    // authentifiée de `/api/v1/sessions*`. GUTI/TMSI/
                    // IMEI ci-dessous restent `cleartext: None`.
                    let cleartext = Some(imsi.clone());
                    push_identity_full(
                        &mut observations,
                        evidence,
                        "imsi",
                        imsi,
                        Some("IMSI"),
                        role,
                        pseudo,
                        cleartext,
                    );
                }
            }
            let tmsi = split_field(field(3))
                .chain(split_field(field(4)))
                .chain(split_field(field(8)))
                .chain(split_field(field(11)))
                .chain(split_field(field(24)))
                .find_map(canonical_tmsi);
            if let Some(m_tmsi) = tmsi {
                let pseudo = evidence.subscriber_pseudonym.clone();
                push_identity(
                    &mut observations,
                    evidence,
                    "m_tmsi",
                    m_tmsi.clone(),
                    Some("M-TMSI"),
                    role,
                    pseudo.clone(),
                );
                let is_5g = !field(8).is_empty();
                let components = if is_5g {
                    [field(5), field(6), field(7), field(8)]
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join("-")
                } else {
                    [field(9), field(10), field(11)]
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect::<Vec<_>>()
                        .join("-")
                };
                let temporary = if components.is_empty() {
                    m_tmsi.clone()
                } else {
                    components
                };
                push_identity(
                    &mut observations,
                    evidence,
                    "s_tmsi",
                    temporary.clone(),
                    Some(if is_5g { "5G-S-TMSI" } else { "S-TMSI" }),
                    role,
                    pseudo.clone(),
                );
                if role == "assigned" {
                    push_identity(
                        &mut observations,
                        evidence,
                        "tmsi",
                        temporary,
                        Some(if is_5g { "5G-GUTI" } else { "GUTI" }),
                        role,
                        pseudo,
                    );
                }
            }
            for raw in split_field(field(12))
                .chain(split_field(field(14)))
                .chain(split_field(field(15)))
                .chain(split_field(field(25)))
            {
                if let Some(imei) = identity_digits(raw) {
                    push_identity(
                        &mut observations,
                        evidence,
                        "imei",
                        imei,
                        Some("IMEI"),
                        role,
                        evidence.subscriber_pseudonym.clone(),
                    );
                }
            }
            for raw in split_field(field(13))
                .chain(split_field(field(16)))
                .chain(split_field(field(26)))
            {
                if let Some(imeisv) = identity_digits(raw) {
                    push_identity(
                        &mut observations,
                        evidence,
                        "imei",
                        imeisv,
                        Some("IMEISV"),
                        role,
                        evidence.subscriber_pseudonym.clone(),
                    );
                }
            }
            for raw in split_field(field(17)).chain(split_field(field(18))) {
                if let Some(msisdn) = identity_digits(raw) {
                    push_identity(
                        &mut observations,
                        evidence,
                        "msisdn",
                        msisdn,
                        Some("MSISDN"),
                        role,
                        evidence.subscriber_pseudonym.clone(),
                    );
                }
            }
        }
    }
    for observation in &mut observations {
        observation.session_id = session_id.to_owned();
    }
    Ok(observations)
}

/// 2.15.3 — background identity hydration for the session list: at most
/// two tshark dissections at a time, each session attempted once per
/// process (failures are not retried in a loop).
static IDENTITY_HYDRATION_SEEN: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashSet<String>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
static IDENTITY_HYDRATION_RUNNING: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
const IDENTITY_HYDRATION_MAX: usize = 2;

fn schedule_identity_hydration(state: &AppState, session_id: &str) {
    use std::sync::atomic::Ordering;
    let Ok(mut seen) = IDENTITY_HYDRATION_SEEN.lock() else {
        return;
    };
    if seen.contains(session_id) {
        return;
    }
    if IDENTITY_HYDRATION_RUNNING.fetch_add(1, Ordering::SeqCst) >= IDENTITY_HYDRATION_MAX {
        IDENTITY_HYDRATION_RUNNING.fetch_sub(1, Ordering::SeqCst);
        return; // retried on a later list request
    }
    seen.insert(session_id.to_owned());
    drop(seen);
    let state = state.clone();
    let session_id = session_id.to_owned();
    std::thread::spawn(move || {
        let _ = hydrate_identities(&state, &session_id);
        IDENTITY_HYDRATION_RUNNING.fetch_sub(1, Ordering::SeqCst);
    });
}

fn hydrate_identities(state: &AppState, session_id: &str) -> Result<(), String> {
    let Some(flow) = session_flow(state, session_id) else {
        return Err("SESSION_NOT_FOUND".into());
    };
    // 2.21.15 (reprise #9 6941147984) — cache par signature de callflow
    // pour éviter de relancer tshark à chaque `/identities`. Un `tshark`
    // froid sur session réf = 210 s ; après fix : miss paye le prix une
    // fois, hit sert en < 10 ms.
    let signature = identity_cache_signature(&flow);
    {
        let guard = state.inner.identity_cache.lock().unwrap();
        if let Some(entry) = guard.get(session_id) {
            if entry.signature == signature {
                let observations = entry.observations.clone();
                drop(guard);
                return state.inner.identity_vault.upsert(observations);
            }
        }
    }
    // 2.21.26 (FAIL lab 2.21.22 : OOM 4,0 G) — le chemin froid (tshark) ne
    // tourne jamais pendant la publication continue ; réponse 503 explicite.
    let Some(_heavy_memory_gate) = state.inner.capture_manager.heavy_memory_try_enter() else {
        return Err("HEAVY_WORK_IN_PROGRESS".into());
    };
    let observations = tshark_identities(state, session_id, &flow)?;
    {
        let mut guard = state.inner.identity_cache.lock().unwrap();
        guard.insert(
            session_id.to_string(),
            IdentityCacheEntry {
                signature,
                observations: observations.clone(),
            },
        );
    }
    state.inner.identity_vault.upsert(observations)
}

/// 2.21.15 — signature d'un `CallFlow` pour invalidation cache
/// `/identities`. On hashe la liste triée de `(source_file,
/// packet_number)` + `event_id` + `capture_id`. Deux callflows
/// identiques → même signature ; un callflow modifié (ajout d'un
/// event, changement d'une référence paquet) change la signature et
/// invalide l'entrée.
fn identity_cache_signature(flow: &CallFlow) -> String {
    use event_schema::sha256_hex;
    let mut items = Vec::new();
    for event in flow.events.iter().take(4096) {
        for reference in &event.packet_references {
            items.push(format!(
                "{}|{}|{}|{}|{}",
                event.event_id,
                event.capture_id,
                reference.source_file,
                reference.packet_number,
                event.message_name,
            ));
        }
    }
    items.sort();
    sha256_hex(items.join("\n").as_bytes())
}

/// 2.21.15 — entrée du cache `identity_cache`.
#[derive(Clone)]
pub(crate) struct IdentityCacheEntry {
    pub(crate) signature: String,
    pub(crate) observations: Vec<IdentityObservation>,
}

/// 2.15.0 (ANR1 #10 6883006379) — résumé compact des identités
/// pour l'inclusion directe dans `/api/v1/sessions`. Garde le
/// même champ naming que `/sessions/:id/identities` (shape vue par
/// l'UI : `imsi`, `imei`, `msisdn`, `tmsi`, `s_tmsi`, `m_tmsi`,
/// `subscriber_pseudonym`) mais SANS les objets `_proof` afin de
/// garder la payload de la liste bornée. Appelé par
/// `session_summary` / `live_session_summary` / `lte_session_summary`
/// pour chaque session de la page `/sessions`.
///
/// Les valeurs sont celles observées par `identity_vault.for_session`
/// — toujours pseudonymisées côté stockage (règle privacy-first du
/// repo). La politique D4 (clear-text SUPI null-scheme + IMSI EPS
/// sous auth UI) est portée par un chemin séparé, pas par ce helper.
fn identity_summary_for_session(state: &AppState, session_id: &str) -> Value {
    let observations = match state.inner.identity_vault.for_session(session_id) {
        Ok(observations) => observations,
        Err(_) => return Value::Null,
    };
    if observations.is_empty() {
        return Value::Null;
    }
    let latest_value = |kind: &str| -> Option<String> {
        observations
            .iter()
            .rev()
            .find(|item| item.kind == kind)
            .map(|item| item.value.clone())
    };
    let all_values = |kind: &str| -> Vec<Value> {
        observations
            .iter()
            .filter(|item| item.kind == kind)
            .map(|item| Value::String(item.value.clone()))
            .collect()
    };
    let subscriber_pseudonym = observations
        .iter()
        .find_map(|item| item.subscriber_pseudonym.clone());
    // 2.15.0 (D4, règle Sadok 2026-11-14) — clear-text accessoire
    // dérivé de l'observation vault la plus récente, **uniquement**
    // pour les kinds autorisés (SUPI d'un SUCI null-scheme + IMSI
    // EPS). Le vault stocke ce clear-text via
    // `IdentityObservation::cleartext` ; l'ingestion decoder-nas
    // décide si elle le remplit en fonction de `protectionScheme`
    // (chaîne de confiance à câbler dans un lot ultérieur). Ici on
    // se contente de LIRE le champ si présent.
    let cleartext_of = |kind: &str| -> Option<String> {
        observations
            .iter()
            .rev()
            .find(|item| item.kind == kind)
            .and_then(|item| item.cleartext.clone())
    };
    json!({
        "imsi": latest_value("imsi"),
        "imsi_cleartext": cleartext_of("imsi"),
        "imei": latest_value("imei"),
        "msisdn": latest_value("msisdn"),
        "tmsi": all_values("tmsi"),
        "s_tmsi": all_values("s_tmsi"),
        "m_tmsi": all_values("m_tmsi"),
        "subscriber_pseudonym": subscriber_pseudonym,
    })
}

/// 2.18.1 — identités SBI (MSISDN via `gpsi`, IMEI/IMEISV via `pei`)
/// publiées par decoder-sbi 2.18.0 dans `session_identifiers`, donc
/// présentes dans `decoded_ie_tree` des events SBI du call flow
/// (`{"name":…,"value":…,"source":"session_identifiers"}`). Première
/// observation dans l'ordre du call flow. Aucune déduction : nom absent
/// → rien.
fn sbi_identity_from_events(
    events: &[callflow_schema::CallFlowEvent],
    name: &str,
) -> Option<(String, String)> {
    events
        .iter()
        .filter(|event| event.protocol.to_ascii_uppercase().starts_with("SBI"))
        .find_map(|event| {
            let items = event.decoded_ie_tree.as_array()?;
            let value = items.iter().find_map(|item| {
                (item["name"] == name)
                    .then(|| item["value"].as_str().map(str::to_owned))
                    .flatten()
                    .filter(|value| !value.is_empty())
            })?;
            let field = |key: &str| {
                items
                    .iter()
                    .find(|item| item["name"] == key)
                    .and_then(|item| item["value"].as_str())
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            };
            let source = match (field("sbi_service"), field("sbi_operation")) {
                (Some(service), Some(operation)) => format!("SBI:{service}:{operation}"),
                (Some(service), None) => format!("SBI:{service}"),
                _ => format!("SBI:{}", event.message_name),
            };
            Some((
                value,
                format!("{source} ({}·{})", event.capture_id, event.event_id),
            ))
        })
}

/// 2.18.1 — complète `identities` (vault / fallback) avec les identités
/// SBI quand le vault ne les porte pas. Le vault garde la priorité.
fn merge_sbi_identities(identities: &mut Value, events: &[callflow_schema::CallFlowEvent]) {
    let msisdn = sbi_identity_from_events(events, "msisdn_pseudonym");
    let imei = sbi_identity_from_events(events, "imei_pseudonym")
        .map(|found| (found, "IMEI"))
        .or_else(|| {
            sbi_identity_from_events(events, "imeisv_pseudonym").map(|found| (found, "IMEISV"))
        });
    if msisdn.is_none() && imei.is_none() {
        return;
    }
    if !identities.is_object() {
        *identities = json!({
            "imsi": null, "imsi_cleartext": null, "imei": null, "msisdn": null,
            "tmsi": [], "s_tmsi": [], "m_tmsi": [], "subscriber_pseudonym": null,
        });
    }
    let Some(object) = identities.as_object_mut() else {
        return;
    };
    if let Some((value, source)) = msisdn {
        if object.get("msisdn").map_or(true, Value::is_null) {
            object.insert("msisdn".into(), Value::String(value));
            object.insert("msisdn_source".into(), Value::String(source));
        }
    }
    if let Some(((value, source), kind)) = imei {
        if object.get("imei").map_or(true, Value::is_null) {
            object.insert("imei".into(), Value::String(value));
            object.insert("imei_type".into(), Value::String(kind.into()));
            object.insert("imei_source".into(), Value::String(source));
        }
    }
}

fn identity_bundle(
    observations: Vec<IdentityObservation>,
    events: &[callflow_schema::CallFlowEvent],
) -> Value {
    let latest = |kind: &str| observations.iter().rev().find(|item| item.kind == kind);
    let evidence = |item: &IdentityObservation| {
        json!({
            "value":item.value,"type":item.value_type,"role":item.role,"event_id":item.event_id,
            "capture_id":item.capture_id,"packet_number":item.packet_number,"cap_seq":format!("{}·{}",item.capture_id,item.packet_number)
        })
    };
    let all = |kind: &str| {
        observations
            .iter()
            .filter(|item| item.kind == kind)
            .map(evidence)
            .collect::<Vec<_>>()
    };
    // 2.18.4 (ANR1 #10) — fallback SBI quand le vault ne porte pas
    // MSISDN / IMEI. Scan en lecture seule des events SBI de la
    // session (vault prioritaire). Preuve séparée en champs
    // (`source`, `event_id`, `capture_id`, `packet_number`,
    // `cap_seq`) pour que l'UI puisse les afficher sans parser une
    // chaîne. `source = "SBI:<service>:<operation>"` quand les deux
    // identifiants sont présents ; `"SBI:<service>"` sinon ;
    // `"SBI:<message_name>"` en dernier recours. Aucune déduction :
    // si aucun event SBI ne porte le pseudonyme recherché, la fn
    // renvoie `None`.
    let sbi_identity = |name: &str| -> Option<(String, Value)> {
        events
            .iter()
            .filter(|event| event.protocol.to_ascii_uppercase().starts_with("SBI"))
            .find_map(|event| {
                let items = event.decoded_ie_tree.as_array()?;
                let value = items.iter().find_map(|item| {
                    (item["name"] == name)
                        .then(|| item["value"].as_str().map(str::to_owned))
                        .flatten()
                        .filter(|v| !v.is_empty())
                })?;
                let field = |key: &str| {
                    items
                        .iter()
                        .find(|item| item["name"] == key)
                        .and_then(|item| item["value"].as_str())
                        .filter(|v| !v.is_empty())
                        .map(str::to_owned)
                };
                let source = match (field("sbi_service"), field("sbi_operation")) {
                    (Some(s), Some(op)) => format!("SBI:{s}:{op}"),
                    (Some(s), None) => format!("SBI:{s}"),
                    _ => format!("SBI:{}", event.message_name),
                };
                let packet = event
                    .packet_references
                    .first()
                    .map(|p| p.packet_number)
                    .unwrap_or(0);
                Some((
                    value,
                    json!({
                        "source": source,
                        "event_id": event.event_id,
                        "capture_id": event.capture_id,
                        "packet_number": packet,
                        "cap_seq": format!("{}·{}", event.capture_id, packet),
                    }),
                ))
            })
    };
    // Vault prioritaire : si l'observation existe dans le vault,
    // on n'interroge pas le SBI.
    let msisdn_vault = latest("msisdn");
    let imei_vault = latest("imei");

    let (msisdn_value, msisdn_proof) = if let Some(item) = msisdn_vault {
        (Some(item.value.clone()), Some(evidence(item)))
    } else if let Some((value, proof)) = sbi_identity("msisdn_pseudonym") {
        (Some(value), Some(proof))
    } else {
        (None, None)
    };

    // IMEI : shape legacy = objet `evidence` directement dans
    // `imei` (vault). En fallback SBI, on reprend le même shape
    // en y ajoutant `source` et en nommant `type` = IMEI/IMEISV
    // selon le préfixe du pseudonyme observé.
    let imei_value: Value = if let Some(item) = imei_vault {
        evidence(item)
    } else if let Some((pseudo_value, mut proof)) = sbi_identity("imei_pseudonym") {
        if let Some(object) = proof.as_object_mut() {
            object.insert("value".into(), Value::String(pseudo_value));
            object.insert("type".into(), Value::String("IMEI".into()));
            object.insert("role".into(), Value::String("sbi-observed".into()));
        }
        proof
    } else if let Some((pseudo_value, mut proof)) = sbi_identity("imeisv_pseudonym") {
        if let Some(object) = proof.as_object_mut() {
            object.insert("value".into(), Value::String(pseudo_value));
            object.insert("type".into(), Value::String("IMEISV".into()));
            object.insert("role".into(), Value::String("sbi-observed".into()));
        }
        proof
    } else {
        Value::Null
    };

    json!({
        "imsi":latest("imsi").map(|item|item.value.clone()),
        "imsi_proof":latest("imsi").map(evidence),
        "msisdn": msisdn_value,
        "msisdn_proof": msisdn_proof,
        "imei": imei_value,
        "tmsi":all("tmsi"),
        "s_tmsi":all("s_tmsi"),
        "m_tmsi":all("m_tmsi"),
        "subscriber_pseudonym":observations.iter().find_map(|item|item.subscriber_pseudonym.clone()),
    })
}

fn operator_envelope(data: Value) -> Response {
    Json(json!({"data":data,"meta":{"api_version":API_VERSION,"identity_access":"operator"}}))
        .into_response()
}

async fn session_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers) {
        return response;
    }
    // 2.21.10 (défaut 3 #9 6929162657) — `hydrate_identities` lance
    // tshark et peut prendre plus de 25 s au premier appel « froid ».
    // Avant 2.21.10 l'appel blocait le runtime async, d'où `/health`
    // qui timeoutait (5 timeouts × 5 s). Déport dans `spawn_blocking`
    // libère la thread du runtime et laisse `/health` répondre.
    let state_for_hydrate = state.clone();
    let id_for_hydrate = id.clone();
    let hydrate_result = tokio::task::spawn_blocking(move || {
        hydrate_identities(&state_for_hydrate, &id_for_hydrate)
    })
    .await;
    let hydrate_result = match hydrate_result {
        Ok(result) => result,
        Err(error) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "IDENTITY_VAULT_FAILED",
                &format!("identity hydrate panicked: {error}"),
            )
        }
    };
    if let Err(error) = hydrate_result {
        return match error.as_str() {
            "SESSION_NOT_FOUND" => api_error(StatusCode::NOT_FOUND, &error, "unknown session id"),
            "TSHARK_UNAVAILABLE" => api_error(
                StatusCode::NOT_IMPLEMENTED,
                &error,
                "packet dissector unavailable",
            ),
            "HEAVY_WORK_IN_PROGRESS" => {
                let mut response = api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &error,
                    "continuous publication in progress, retry later",
                );
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
                response
            }
            _ => api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "IDENTITY_VAULT_FAILED",
                "identity evidence could not be loaded",
            ),
        };
    }
    match state.inner.identity_vault.for_session(&id) {
        Ok(observations) => {
            // 2.18.4 (ANR1 #10) — fournir les events de la session à
            // `identity_bundle` pour que MSISDN / IMEI / IMEISV
            // observés dans les events SBI du call flow soient
            // exposés quand le vault ne les porte pas. Vault
            // prioritaire ; si `session_flow` ne retrouve pas la
            // session (edge case), on tombe sur le bundle vault-only
            // comme avant 2.18.4.
            let events_owned: Vec<callflow_schema::CallFlowEvent> =
                session_flow(&state, &id)
                    .map(|flow| flow.events)
                    .unwrap_or_default();
            operator_envelope(identity_bundle(observations, &events_owned))
        }
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "IDENTITY_VAULT_FAILED",
            "identity evidence could not be loaded",
        ),
    }
}

// 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-04) — ancien `GET /identities?q=`
// était une fuite L2d (valeur en clair dans l'URL → access logs, historique
// navigateur, DevTools réseau). Retourne 410 Gone **sans** echo de la query.
// Le `Link` header pointe vers la route de remplacement.
async fn identity_lookup_gone(headers: HeaderMap) -> Response {
    let mut response = api_error(
        StatusCode::GONE,
        "IDENTITY_LOOKUP_GET_REMOVED",
        "GET /identities is removed; use POST /identities/lookup with the value in the body",
    );
    let _ = headers; // on ne lit volontairement AUCUNE entrée de requête
    response
        .headers_mut()
        .insert("Link", "</api/v1/identities/lookup>; rel=\"successor-version\"".parse().unwrap());
    response
}

async fn identity_lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<IdentityLookupBody>,
) -> Response {
    let role = match require_operator(&state, &headers) {
        Ok(role) => role,
        Err(response) => return response,
    };
    // CSRF requis : la valeur en clair ne doit pas être soumise par un
    // formulaire cross-origin sans jeton.
    if let Err(response) = live_trace::require_csrf(&state, &headers) {
        return response;
    }
    let trimmed = input.value.trim();
    if trimmed.len() < 4 || trimmed.len() > 128 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "IDENTITY_QUERY_INVALID",
            "identity value length is invalid",
        );
    }
    if input.page == 0 || !(1..=100).contains(&input.page_size) {
        return api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "IDENTITY_PAGINATION_INVALID",
            "page must be >= 1 and page_size must be 1..100",
        );
    }
    let matches = match state.inner.identity_vault.lookup(trimmed) {
        Ok(matches) => matches,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "IDENTITY_VAULT_FAILED",
                "identity evidence could not be loaded",
            )
        }
    };
    let total = matches.len();
    let start = input.page_size.saturating_mul(input.page.saturating_sub(1));
    let matches = matches
        .into_iter()
        .skip(start)
        .take(input.page_size)
        .collect::<Vec<_>>();
    let sessions = matches
        .iter()
        .map(|item| item.session_id.clone())
        .collect::<BTreeSet<_>>();
    let subscriber_pseudonym = matches
        .iter()
        .find_map(|item| item.subscriber_pseudonym.clone());
    // 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-08) — audit du lookup :
    // acteur, rôle, pseudonyme dérivé, nombre de résultats, heure.
    // **Jamais** la valeur saisie.
    state.inner.live_traces.audit_lookup(
        role.name(),
        subscriber_pseudonym.as_deref(),
        total,
        epoch_seconds(),
    );
    operator_envelope(
        json!({"sessions":sessions,"subscriber_pseudonym":subscriber_pseudonym,"matches":matches.into_iter().map(|item|json!({
        "session_id":item.session_id,"subscriber_pseudonym":item.subscriber_pseudonym,"type":item.kind,
        "event_id":item.event_id,"capture_id":item.capture_id,"packet_number":item.packet_number
    })).collect::<Vec<_>>(),"pagination":{"page":input.page,"page_size":input.page_size,"total":total} }),
    )
}

async fn session_procedures(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if let Some(flow) = flow_for(&state, &id) {
        return ok(json!(flow.procedures)).into_response();
    }
    if let Some((_dataset, flow)) = live_flow_for(&state, &id) {
        return ok(json!(flow.procedures)).into_response();
    }
    if let Ok(Some((_manifest, lte))) = state.inner.lte_evidence_store.find_session(&id) {
        return ok(json!(lte
            .procedures
            .iter()
            .enumerate()
            .map(|(index, name)| json!({
                "id":format!("lte-procedure-{index}"),"name":name,"event_ids":[],"status":"OBSERVED"
            }))
            .collect::<Vec<_>>()))
        .into_response();
    }
    api_error(
        StatusCode::NOT_FOUND,
        "SESSION_NOT_FOUND",
        "unknown session id",
    )
}

async fn session_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Response {
    // 2.21.16 (audit handlers #9 6941147984) — session_events_blocking
    // lit un callflow JSON du capture_manager, applique le patch
    // read-time, étend avec les PFCP siblings du JSONL raw (fs::read).
    // Tout sur runtime async pré-2.21.16. Correctif : spawn_blocking.
    let state_bl = state.clone();
    let id_bl = id.clone();
    let query_bl = query.clone();
    tokio::task::spawn_blocking(move || session_events_blocking(&state_bl, &id_bl, &query_bl))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_EVENTS_FAILED",
                "session events handler panicked",
            )
        })
}

fn session_events_blocking(state: &AppState, id: &str, query: &ListQuery) -> Response {
    // 2.14.8 (ANR1 #10) — chaque chemin fournit (items, dataset_root
    // optionnel) : A (reference_dataset_enabled) → `state.inner.storage_path`
    // joint à `datasets/<id>` indirect, on résout ici via la config
    // stockée au chargement (`storage_path` pointe sur le workspace,
    // les JSONL sont déjà patchés au démarrage, donc idempotent) ;
    // B (continuous/derived/recovered) → `capture_manager.dataset_root(dataset_id)` ;
    // C (LTE evidence) → pas de JSONL raw cross-référençable, on
    // sert tel quel (les callflows LTE sont produits dans un autre
    // flux et n'ont pas le mélange old/new shards).
    let (mut items, dataset_root): (Vec<Value>, Option<PathBuf>) =
        if let Some(flow_value) = flow_value_for(state, id) {
            // Path A : events déjà patchés à `AppState::load` ; la
            // ré-application depuis le dataset_dir configuré reste
            // idempotente (compteurs inchangés).
            let items = flow_value["events"].as_array().cloned().unwrap_or_default();
            (items, state.inner.reference_dataset_root.clone())
        } else if let Some((dataset_id, flow)) = live_flow_for(state, id) {
            let items = serde_json::to_value(flow.events)
                .ok()
                .and_then(|value| value.as_array().cloned())
                .unwrap_or_default();
            (items, state.inner.capture_manager.dataset_root(&dataset_id))
        } else {
            match state.inner.lte_evidence_store.callflow_page_by_session(
                id,
                None,
                MAX_CALLFLOW_PAGE_EVENTS,
            ) {
                Ok(Some(value)) => (
                    value["events"].as_array().cloned().unwrap_or_default(),
                    None,
                ),
                Ok(None) => {
                    return api_error(
                        StatusCode::NOT_FOUND,
                        "SESSION_NOT_FOUND",
                        "unknown session id",
                    )
                }
                Err(error) => return lte_evidence_error(error),
            }
        };
    // 2.21.118 (ordre #9 7051448601 point 2) — une correction couvre les
    // données stockées : les events persistés d'un dataset d'avant
    // 2.21.91 n'ont pas de `stable_event_key`. Elle est dérivée ici, à la
    // lecture, par la même fonction que `/callflow`, sur la liste
    // persistée dans son ordre de stockage et AVANT tout ajout.
    read_time_patch::backfill_stable_event_keys_in_items(&mut items);
    let patch_status = if let Some(root) = dataset_root.as_deref() {
        apply_read_time_patch(state, &mut items, root, id)
    } else {
        read_time_patch::PatchStatus::NotApplicable
    };
    if let Some(root) = dataset_root.as_deref() {
        let _ = read_time_patch::extend_items_with_pfcp_siblings_from_jsonl(&mut items, root);
    }
    read_time_patch::fill_unknown_participants_by_interface(&mut items);
    filter_events(&mut items, query);
    sanitize_all(&mut items);
    paginated_with_patch_status(items, query, patch_status).into_response()
}

/// 2.21.70 (ordre #9 7006855142) — Charge la liste COMPLÈTE des events
/// persistés d'une session, indépendante de la pagination. Utilisé par
/// `session_callflow_blocking` pour calculer le `session_sibling_count`
/// sur toutes les pages. L'ordre de résolution reflète celui du handler
/// (`flow_path_for` → `flow_value_for` → `capture_manager` →
/// `lte_evidence_store`), de sorte que les deux chemins (page et
/// comptage) voient la MÊME liste persistée.
fn load_persisted_callflow_events(state: &AppState, id: &str) -> Vec<Value> {
    if let Some(path) = flow_path_for(state, id) {
        // Lecture directe du fichier, sans la limite de pagination.
        if let Ok(file) = std::fs::File::open(path) {
            let reader = std::io::BufReader::new(file);
            if let Ok(value) = serde_json::from_reader::<_, Value>(reader) {
                return value
                    .get("events")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
            }
        }
        return Vec::new();
    }
    if let Some(flow_value) = flow_value_for(state, id) {
        return flow_value
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    }
    if let Ok(Some(value)) = state
        .inner
        .capture_manager
        .callflow_page_by_session(id, None, MAX_CALLFLOW_PAGE_EVENTS)
    {
        return value
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    }
    if let Ok(Some(value)) = state
        .inner
        .lte_evidence_store
        .callflow_page_by_session(id, None, MAX_CALLFLOW_PAGE_EVENTS)
    {
        return value
            .get("events")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
    }
    Vec::new()
}

fn callflow_page_from_value(
    source: &Value,
    cursor: Option<&str>,
    limit: usize,
) -> Result<Value, String> {
    if !(1..=MAX_CALLFLOW_PAGE_EVENTS).contains(&limit) {
        return Err("CALLFLOW_LIMIT_INVALID".into());
    }
    // 2.21.102 (défaut ANR1 #9 7044712668, ordre #9 7045732954) —
    // backfill `stable_event_key` à la lecture pour les callflows
    // publiés AVANT 2.21.91 (le champ y est absent). Formule
    // identique à la republication live, ordinal 0-based en ordre
    // d'émission du décodeur (= ordre des events dans le JSON
    // callflow). Pas de réécriture disque.
    let mut owned = source.clone();
    event_schema::backfill_stable_event_keys_in_callflow(&mut owned);
    let source_object = owned.as_object().ok_or("CALLFLOW_READ_FAILED")?;
    let source_events = source_object
        .get("events")
        .and_then(Value::as_array)
        .ok_or("CALLFLOW_READ_FAILED")?;
    let start = if let Some(cursor) = cursor {
        source_events
            .iter()
            .position(|event| event["event_id"] == cursor)
            .map(|index| index + 1)
            .ok_or("CALLFLOW_CURSOR_INVALID")?
    } else {
        0
    };
    let events = source_events
        .iter()
        .skip(start)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let has_more = start.saturating_add(events.len()) < source_events.len();
    let next_cursor = has_more
        .then(|| events.last().and_then(|event| event["event_id"].as_str()))
        .flatten()
        .map(str::to_owned);
    let selected_ids = events
        .iter()
        .filter_map(|event| event["event_id"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut output = source_object
        .iter()
        .filter(|(key, _)| key.as_str() != "events")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    if let Some(procedures) = output.get_mut("procedures").and_then(Value::as_array_mut) {
        for procedure in procedures.iter_mut() {
            if let Some(ids) = procedure["event_ids"].as_array_mut() {
                ids.retain(|id| id.as_str().is_some_and(|id| selected_ids.contains(id)));
            }
        }
        procedures.retain(|procedure| {
            procedure["event_ids"]
                .as_array()
                .is_some_and(|ids| !ids.is_empty())
        });
    }
    if let Some(edges) = output
        .get_mut("correlation_edges")
        .and_then(Value::as_array_mut)
    {
        edges.retain(|edge| {
            ["source_event_id", "target_event_id"].iter().any(|field| {
                edge[*field]
                    .as_str()
                    .is_some_and(|id| selected_ids.contains(id))
            })
        });
    }
    let returned_events = events.len();
    output.insert("events".into(), Value::Array(events));
    output.insert(
        "pagination".into(),
        json!({
            "limit": limit,
            "cursor": cursor,
            "next_cursor": next_cursor,
            "returned_events": returned_events,
            "total_events": source_events.len(),
        }),
    );
    Ok(Value::Object(output))
}

fn callflow_read_error(error: &str) -> Response {
    match error {
        "CALLFLOW_LIMIT_INVALID" => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            error,
            "limit must be between 1 and 256 events",
        ),
        "CALLFLOW_CURSOR_INVALID" => api_error(
            StatusCode::BAD_REQUEST,
            error,
            "cursor does not identify an event in this call flow",
        ),
        _ => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CALLFLOW_READ_FAILED",
            "the persisted call flow could not be read safely",
        ),
    }
}

async fn session_callflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<CallflowQuery>,
) -> Response {
    // 2.21.16 (audit handlers #9 6941147984) — read_callflow_page lit un
    // fichier JSON potentiellement large sur disque + parse. Déport
    // dans spawn_blocking pour ne pas bloquer le runtime async.
    let state_bl = state.clone();
    let id_bl = id.clone();
    let query_bl = query.clone();
    tokio::task::spawn_blocking(move || session_callflow_blocking(&state_bl, &id_bl, &query_bl))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_CALLFLOW_FAILED",
                "session callflow handler panicked",
            )
        })
}

fn session_callflow_blocking(state: &AppState, id: &str, query: &CallflowQuery) -> Response {
    let limit = query.limit.unwrap_or(DEFAULT_CALLFLOW_PAGE_EVENTS);
    if !(1..=MAX_CALLFLOW_PAGE_EVENTS).contains(&limit) {
        return callflow_read_error("CALLFLOW_LIMIT_INVALID");
    }
    let cursor = query.cursor.as_deref();
    let result = if let Some(path) = flow_path_for(state, id) {
        read_callflow_page(path, cursor, limit).map(Some)
    } else if let Some(flow_value) = flow_value_for(state, id) {
        callflow_page_from_value(flow_value, cursor, limit).map(Some)
    } else {
        match state
            .inner
            .capture_manager
            .callflow_page_by_session(id, cursor, limit)
        {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => state
                .inner
                .lte_evidence_store
                .callflow_page_by_session(id, cursor, limit)
                .map_err(|error| error.to_string()),
            Err(error) => Err(error),
        }
    };
    match result {
        Ok(Some(mut value)) => {
            // 2.21.70 (ordre #9 7006855142) — dataset root et clés PFCP
            // de la SESSION COMPLÈTE calculées UNE fois par requête,
            // indépendamment du curseur. Les deux chemins (insertion page 1,
            // comptage total pour toutes les pages) utilisent les MÊMES
            // clés — garantie que `total_events` est cohérent.
            let dataset_root = if flow_value_for(state, id).is_some() {
                state.inner.reference_dataset_root.clone()
            } else {
                live_flow_for(state, id).and_then(|(dataset_id, _)| {
                    state.inner.capture_manager.dataset_root(&dataset_id)
                })
            };
            let session_keys = if dataset_root.is_some() {
                read_time_patch::collect_pfcp_session_keys(
                    &load_persisted_callflow_events(state, id),
                )
            } else {
                read_time_patch::PfcpSessionKeys::default()
            };
            // 2.15.3 — réconciliation PFCP sur la page 1. 2.21.70 : clés
            // de session complète → les siblings sont insérés en page 1
            // même si cette page ne contient pas les events PFCP porteurs.
            let mut pfcp_siblings_added = 0usize;
            if cursor.is_none() {
                if let (Some(root), Some(events)) = (
                    dataset_root.as_deref(),
                    value.get_mut("events").and_then(Value::as_array_mut),
                ) {
                    pfcp_siblings_added =
                        read_time_patch::insert_pfcp_siblings_into_callflow_using_session_keys(
                            events,
                            root,
                            &session_keys,
                        )
                        .unwrap_or_default();
                }
            }
            // 2.21.70 — comptage canonique du sibling count (session
            // entière), indépendant du curseur. Garantit que `total_events`
            // est le MÊME sur toutes les pages. Preuve par test :
            // `multi_page_total_events_is_coherent_and_no_event_id_duplicate_2_21_70`
            // dans `read_time_patch::callflow_pfcp_insert_tests`.
            let session_sibling_count: usize = if let Some(root) = dataset_root.as_deref() {
                read_time_patch::count_pfcp_siblings_for_persisted_events(
                    &load_persisted_callflow_events(state, id),
                    root,
                )
                .unwrap_or(0)
            } else {
                0
            };
            if session_sibling_count > 0 {
                let returned_events = value
                    .get("events")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or_default();
                if let Some(pagination) = value
                    .get_mut("pagination")
                    .and_then(Value::as_object_mut)
                {
                    // `pagination.total_events` est le compte **persisté**
                    // (le reader sous-jacent ne sait rien des siblings).
                    // 2.21.70 : total session = persisté + session_sibling_count,
                    // identique sur toutes les pages.
                    let persisted_total = pagination
                        .get("total_events")
                        .and_then(Value::as_u64)
                        .unwrap_or(returned_events.saturating_sub(pfcp_siblings_added) as u64);
                    let total_events = persisted_total
                        .saturating_add(session_sibling_count as u64);
                    pagination.insert("returned_events".into(), returned_events.into());
                    pagination.insert("total_events".into(), total_events.into());
                }
            }
            if let Some(events) = value.get_mut("events").and_then(Value::as_array_mut) {
                read_time_patch::fill_unknown_participants_by_interface(events);
            }
            sanitize_value(&mut value);
            ok(value).into_response()
        }
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "unknown session id",
        ),
        Err(error) => callflow_read_error(&error),
    }
}

async fn session_correlations(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    // 2.21.19 — flow_for / live_flow_for / lte_evidence_store.callflow_page_by_session sync.
    tokio::task::spawn_blocking(move || session_correlations_blocking(&state, &id))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SESSION_CORRELATIONS_FAILED",
                "session_correlations handler panicked",
            )
        })
}

fn session_correlations_blocking(state: &AppState, id: &str) -> Response {
    let flow = if let Some(flow) = flow_for(state, id) {
        flow.clone()
    } else if let Some((_dataset, flow)) = live_flow_for(state, id) {
        flow
    } else {
        return match state.inner.lte_evidence_store.callflow_page_by_session(
            id,
            None,
            MAX_CALLFLOW_PAGE_EVENTS,
        ) {
            Ok(Some(mut flow)) => {
                let mut value = json!({
                    "status":flow["correlation_status"].take(),
                    "edges":flow["correlation_edges"].take()
                });
                sanitize_value(&mut value);
                ok(value).into_response()
            }
            Ok(None) => api_error(
                StatusCode::NOT_FOUND,
                "SESSION_NOT_FOUND",
                "unknown session id",
            ),
            Err(error) => lte_evidence_error(error),
        };
    };
    let mut value = json!({"status":flow.correlation_status,"edges":flow.correlation_edges});
    sanitize_value(&mut value);
    ok(value).into_response()
}

async fn event(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    find_event(&state, &id)
        .map(|mut x| {
            sanitize_value(&mut x);
            ok(x).into_response()
        })
        .unwrap_or_else(|| api_error(StatusCode::NOT_FOUND, "EVENT_NOT_FOUND", "unknown event id"))
}

async fn provenance(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    find_event(&state,&id).map(|x|{let mut v=json!({"event_id":id,"capture_id":x["capture_id"],"packet_references":x["packet_references"],"raw_payload_reference":x["raw_payload_reference"]});sanitize_value(&mut v);ok(v).into_response()}).unwrap_or_else(||api_error(StatusCode::NOT_FOUND,"EVENT_NOT_FOUND","unknown event id"))
}

/// 2.21.21 — source d'un flow requêtable, résolue sans le charger.
/// Même priorité que `queryable_flows` : la dernière source qui résout gagne
/// (LTE > dataset > mémoire), une source qui ne résout pas laisse la précédente.
enum FlowSource {
    Memory,
    Dataset(String),
    Lte,
}

fn queryable_flow_sources(state: &AppState) -> BTreeMap<String, Vec<FlowSource>> {
    let mut sources = BTreeMap::<String, Vec<FlowSource>>::new();
    for session_id in state.inner.flows.keys() {
        sources.entry(session_id.clone()).or_default().push(FlowSource::Memory);
    }
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            sources
                .entry(session_id.clone())
                .or_default()
                .push(FlowSource::Dataset(dataset.dataset_id.clone()));
        }
    }
    match state.inner.lte_evidence_store.catalog() {
        Ok(catalog) => {
            for manifest in catalog {
                for session_id in manifest.session_ids {
                    sources.entry(session_id).or_default().push(FlowSource::Lte);
                }
            }
        }
        Err(error) => eprintln!("PACKETS_LTE_CATALOG_SKIPPED reason={}", error),
    }
    sources
}

fn load_queryable_flow(state: &AppState, session_id: &str, sources: &[FlowSource]) -> Option<Value> {
    find_queryable_callflow(state, session_id, sources)
        .and_then(|flow| serde_json::to_value(flow).ok())
}

/// 2.21.23 — variante `CallFlow` de `load_queryable_flow` : utilisée par
/// `subscriber_journey_blocking` pour résoudre, à la demande et UN par
/// UN, chaque callflow d'un sous-ensemble de sessions sans matérialiser
/// `queryable_flows` entier.
fn find_queryable_callflow(
    state: &AppState,
    session_id: &str,
    sources: &[FlowSource],
) -> Option<CallFlow> {
    for source in sources.iter().rev() {
        let flow = match source {
            FlowSource::Memory => state.inner.flows.get(session_id).cloned(),
            FlowSource::Dataset(dataset_id) => {
                state.inner.capture_manager.callflow(dataset_id, session_id)
            }
            FlowSource::Lte => match state
                .inner
                .lte_evidence_store
                .callflow_for_export_by_session(session_id)
            {
                Ok(flow) => flow,
                Err(error) => {
                    eprintln!(
                        "SUBSCRIBER_JOURNEY_LTE_CALLFLOW_SKIPPED session_id={} reason={}",
                        session_id, error
                    );
                    None
                }
            },
        };
        if flow.is_some() {
            return flow;
        }
    }
    None
}

/// Parcourt les flows requêtables UN PAR UN (jamais tous en mémoire) et
/// appelle `visit(session_index, event, reference)` pour chaque référence
/// paquet, dans l'ordre exact de l'ancien `packet_values`. `visit` renvoie
/// `false` pour arrêter le parcours.
fn for_each_packet_reference(
    state: &AppState,
    only_sessions: Option<&BTreeSet<usize>>,
    mut visit: impl FnMut(usize, &Value, &Value) -> bool,
) {
    for (index, (session_id, sources)) in queryable_flow_sources(state).iter().enumerate() {
        if only_sessions.is_some_and(|wanted| !wanted.contains(&index)) {
            continue;
        }
        let Some(flow) = load_queryable_flow(state, session_id, sources) else {
            continue;
        };
        for event in flow["events"].as_array().into_iter().flatten() {
            for reference in event["packet_references"].as_array().into_iter().flatten() {
                if !visit(index, event, reference) {
                    return;
                }
            }
        }
    }
}

fn packet_id_for(event: &Value, reference: &Value) -> String {
    let capture_id = event["capture_id"].as_str().unwrap_or("unknown");
    let capture_tag = capture_id
        .strip_prefix("sha256:")
        .unwrap_or(capture_id)
        .chars()
        .take(12)
        .collect::<String>();
    let number = reference["packet_number"].as_u64().unwrap_or(0);
    format!("pkt-{capture_tag}-{number}")
}

fn packet_value_for(event: &Value, reference: &Value) -> Value {
    let capture_id = event["capture_id"].as_str().unwrap_or("unknown");
    let number = reference["packet_number"].as_u64().unwrap_or(0);
    json!({
        "packet_id":packet_id_for(event, reference),"capture_id":capture_id,"event_id":event["event_id"],
        "timestamp":event["timestamp"],"timestamp_ns":event["timestamp_ns"],
        "interface":event["interface"],"protocol":event["protocol"],
        "source":event["source_participant"],"destination":event["destination_participant"],
        "direction":event["direction"],"message_name":event["message_name"],
        "captured_length":reference["captured_length"],"original_length":reference["original_length"],
        "byte_offset":reference["byte_offset"],"packet_number":number,
        "source_file":reference["source_file"],"decode_status":event["decoding_status"],
        "decoder_name":event["decoder_name"],"decoder_version":event["decoder_version"],
        "raw_payload_reference":event["raw_payload_reference"],"information_elements":event["decoded_ie_tree"],
        "raw_bytes":"RESTRICTED_NOT_STORED_IN_EVENT_MODEL"
    })
}

/// Premier paquet (après dédoublonnage par `packet_id`) qui satisfait `matches`.
fn find_packet(state: &AppState, matches: impl Fn(&str, &Value, &Value) -> bool) -> Option<Value> {
    let mut seen = HashSet::<String>::new();
    let mut found = None;
    for_each_packet_reference(state, None, |_, event, reference| {
        let packet_id = packet_id_for(event, reference);
        if !seen.insert(packet_id.clone()) {
            return true;
        }
        if matches(&packet_id, event, reference) {
            found = Some(packet_value_for(event, reference));
            return false;
        }
        true
    });
    found
}

struct PacketKey {
    capture_id: String,
    packet_number: u64,
    /// 2.21.133 — rang dans le paquet : enfant après son parent, puis
    /// ordinal d'émission (`session_engine::emission_ordinal`).
    is_child: bool,
    emission_ordinal: u32,
    event_id: Option<String>,
    packet_id: String,
    session_index: usize,
}

/// `/packets` borné en mémoire : passe 1 = clés légères filtrées, tri canonique
/// (capture_id, packet_number, event_id) ; passe 2 = seuls les paquets de la page
/// sont matérialisés, en rechargeant uniquement leurs sessions.
fn packets_page(state: &AppState, query: &ListQuery) -> Json<Value> {
    let search = query.search.as_deref().map(str::to_ascii_lowercase);
    let mut seen = HashSet::<String>::new();
    let mut keys = Vec::<PacketKey>::new();
    for_each_packet_reference(state, None, |session_index, event, reference| {
        let packet_id = packet_id_for(event, reference);
        if !seen.insert(packet_id.clone()) {
            return true;
        }
        let capture_id = event["capture_id"].as_str().unwrap_or("unknown");
        let packet_number = reference["packet_number"].as_u64().unwrap_or(0);
        if query.capture_id.as_deref().is_some_and(|wanted| wanted != capture_id)
            || query.event_id.as_deref().is_some_and(|wanted| event["event_id"] != wanted)
            || query.packet_number.is_some_and(|wanted| wanted != packet_number)
            || query.interface.as_deref().is_some_and(|wanted| event["interface"] != wanted)
            || query.protocol.as_deref().is_some_and(|wanted| event["protocol"] != wanted)
        {
            return true;
        }
        if let Some(search) = search.as_deref() {
            let text = packet_value_for(event, reference).to_string().to_ascii_lowercase();
            if !text.contains(search) {
                return true;
            }
        }
        keys.push(PacketKey {
            capture_id: capture_id.to_string(),
            packet_number,
            is_child: event["parent_event_id"].as_str().is_some_and(|id| !id.is_empty()),
            emission_ordinal: session_engine::emission_ordinal(
                event["stable_event_key"].as_str().unwrap_or(""),
            ),
            event_id: event["event_id"].as_str().map(str::to_string),
            packet_id,
            session_index,
        });
        true
    });
    drop(seen);
    keys.sort_by(|a, b| {
        a.capture_id
            .cmp(&b.capture_id)
            .then_with(|| a.packet_number.cmp(&b.packet_number))
            .then_with(|| a.is_child.cmp(&b.is_child))
            .then_with(|| a.emission_ordinal.cmp(&b.emission_ordinal))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    let total = keys.len();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(25).clamp(1, 100);
    let start = (page - 1).saturating_mul(page_size);
    let page_keys = keys.into_iter().skip(start).take(page_size).collect::<Vec<_>>();
    let sessions = page_keys.iter().map(|key| key.session_index).collect::<BTreeSet<_>>();
    let wanted = page_keys
        .iter()
        .map(|key| (key.packet_id.clone(), key.session_index))
        .collect::<HashMap<_, _>>();
    let mut built = HashMap::<String, Value>::new();
    if !page_keys.is_empty() {
        for_each_packet_reference(state, Some(&sessions), |session_index, event, reference| {
            let packet_id = packet_id_for(event, reference);
            if wanted.get(&packet_id) == Some(&session_index) && !built.contains_key(&packet_id) {
                built.insert(packet_id, packet_value_for(event, reference));
            }
            built.len() < wanted.len()
        });
    }
    let mut data = page_keys
        .iter()
        .filter_map(|key| built.remove(&key.packet_id))
        .collect::<Vec<_>>();
    sanitize_all(&mut data);
    Json(
        json!({"data":data,"meta":{"page":page,"page_size":page_size,"total":total,"total_pages":total.div_ceil(page_size)}}),
    )
}

fn queryable_flow_values(state: &AppState) -> Vec<Value> {
    queryable_flows(state)
        .into_values()
        .filter_map(|flow| serde_json::to_value(flow).ok())
        .collect()
}

fn capture_is_known(state: &AppState, capture_id: &str) -> bool {
    // 2.21.21 — parcours flow par flow, sans matérialiser tous les flows.
    let mut known = false;
    for (session_id, sources) in queryable_flow_sources(state) {
        let Some(flow) = load_queryable_flow(state, &session_id, &sources) else {
            continue;
        };
        if flow["events"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|event| event["capture_id"] == capture_id)
        {
            known = true;
            break;
        }
    }
    known
}

fn packet_source_path(state: &AppState, packet: &Value) -> Option<PathBuf> {
    let resolved = resolve_source_path(state, packet["source_file"].as_str()?);
    resolved.is_file().then_some(resolved)
}

async fn packets(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    // 2.21.21 — borné en mémoire (OOM 3.7 G en 2.21.19 au lab) et hors runtime.
    tokio::task::spawn_blocking(move || packets_page(&state, &query))
        .await
        .unwrap_or_else(|_| Json(json!({"error": "packets handler panicked"})))
}

async fn packet(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    // 2.21.21 — recherche flow par flow, arrêt au premier match, hors runtime.
    tokio::task::spawn_blocking(move || {
        find_packet(&state, |packet_id, _, _| packet_id == id)
            .map(|mut packet| {
                sanitize_value(&mut packet);
                ok(packet).into_response()
            })
            .unwrap_or_else(|| {
                api_error(
                    StatusCode::NOT_FOUND,
                    "PACKET_NOT_FOUND",
                    "unknown packet id",
                )
            })
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "PACKET_LOOKUP_FAILED",
            "packet handler panicked",
        )
    })
}

async fn packet_dissect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((capture_id, packet_number)): Path<(String, u64)>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers) {
        return response;
    }
    // 2.21.17 — tshark sub-process + fs::read paquets. Déport dans
    // spawn_blocking (sinon le runtime bloque pendant l'invocation tshark).
    tokio::task::spawn_blocking(move || packet_dissect_blocking(&state, &capture_id, packet_number))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "PACKET_DISSECT_FAILED",
                "packet dissect handler panicked",
            )
        })
}

fn packet_dissect_blocking(state: &AppState, capture_id: &str, packet_number: u64) -> Response {
    let packet = find_packet(state, |_, event, reference| {
        event["capture_id"] == capture_id
            && reference["packet_number"].as_u64().unwrap_or(0) == packet_number
    });
    let Some(packet) = packet else {
        return if capture_is_known(state, capture_id) {
            api_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "PACKET_OUT_OF_RANGE",
                "packet number is outside the referenced capture",
            )
        } else {
            api_error(
                StatusCode::NOT_FOUND,
                "CAPTURE_NOT_FOUND",
                "unknown capture id",
            )
        };
    };
    let Some(source) = packet_source_path(state, &packet) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "CAPTURE_SOURCE_NOT_FOUND",
            "capture source is unavailable",
        );
    };
    let filter = format!("frame.number == {packet_number}");
    let result = Command::new("tshark")
        .args(["-n", "-r"])
        .arg(source)
        .args(["-Y", &filter, "-V"])
        .output();
    let Ok(result) = result else {
        return api_error(
            StatusCode::NOT_IMPLEMENTED,
            "TSHARK_UNAVAILABLE",
            "packet dissector unavailable",
        );
    };
    if !result.status.success() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "TSHARK_DISSECTION_FAILED",
            "packet dissection failed",
        );
    }
    if result.stdout.is_empty() {
        return api_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "PACKET_OUT_OF_RANGE",
            "packet number is outside the capture file",
        );
    }
    if result.stdout.len() > 2 * 1024 * 1024 {
        return api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "DISSECTION_TOO_LARGE",
            "packet dissection exceeds the response limit",
        );
    }
    let Ok(dissection) = String::from_utf8(result.stdout) else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "TSHARK_OUTPUT_INVALID",
            "packet dissection is not UTF-8",
        );
    };
    operator_envelope(json!({
        "capture_id":capture_id,
        "packet_number":packet_number,
        "event_id":packet["event_id"],
        "format":"tshark -V",
        "dissection":dissection,
    }))
}

fn find_event(state: &AppState, id: &str) -> Option<Value> {
    queryable_flow_values(state).into_iter().find_map(|flow| {
        flow["events"]
            .as_array()?
            .iter()
            .find(|event| event["event_id"] == id)
            .cloned()
    })
}

async fn correlation_edges(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> Json<Value> {
    // 2.21.20 — iteration flows + correlation_edges + serialize.
    tokio::task::spawn_blocking(move || {
        let mut items = state
            .inner
            .flows
            .values()
            .flat_map(|flow| flow.correlation_edges.iter())
            .filter_map(|edge| serde_json::to_value(edge).ok())
            .collect::<Vec<_>>();
        if let Some(interface) = query.interface.as_deref() {
            items.retain(|x| {
                x["source_interface"] == interface || x["target_interface"] == interface
            });
        }
        sanitize_all(&mut items);
        paginated(items, &query)
    })
    .await
    .unwrap_or_else(|_| Json(json!({"error": "correlation_edges handler panicked"})))
}

async fn correlation_rules() -> Json<Value> {
    ok(json!([
        {"rule_id":"n2-n4-certified-tunnel-bridge","version":"1.0.0","classification":"STRONG","read_only":true,"description":"PDU Session context plus certified tunnel bridge"},
        {"rule_id":"n4-n3-teid-endpoint","version":"1.0.0","classification":"EXACT","read_only":true,"description":"TEID and directional tunnel endpoint equality"}
    ]))
}

#[derive(Deserialize, Default, Clone)]
struct ExportQuery {
    format: Option<String>,
}
async fn export_callflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ExportQuery>,
) -> Response {
    // 2.21.20 — flow_for + flow_value_for + callflow fs writes.
    tokio::task::spawn_blocking(move || export_callflow_blocking(&state, &id, &query))
        .await
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EXPORT_CALLFLOW_FAILED",
                "export_callflow handler panicked",
            )
        })
}

fn export_callflow_blocking(state: &AppState, id: &str, query: &ExportQuery) -> Response {
    let mut value = if let Some(flow) = flow_for(state, id) {
        flow_value_for(&state, &id)
            .cloned()
            .unwrap_or_else(|| serde_json::to_value(flow).unwrap_or(json!({})))
    } else if let Some((_dataset, flow)) = live_flow_for(&state, &id) {
        serde_json::to_value(flow).unwrap_or(json!({}))
    } else {
        match state
            .inner
            .lte_evidence_store
            .callflow_for_export_by_session(&id)
        {
            Ok(Some(flow)) => serde_json::to_value(flow).unwrap_or(json!({})),
            Ok(None) => {
                return api_error(
                    StatusCode::NOT_FOUND,
                    "SESSION_NOT_FOUND",
                    "unknown session id",
                )
            }
            Err(error) => return lte_evidence_error(error),
        }
    };
    let format = query.format.as_deref().unwrap_or("json");
    eprintln!(
        "audit action=callflow_export session={} format={format}",
        id
    );
    sanitize_value(&mut value);
    match format {
        "json" => {
            let bytes = serde_json::to_vec_pretty(&value).unwrap_or_default();
            download(bytes, "application/json", "OIRAN_5G_E2E_CALLFLOW.json")
        }
        "html" => {
            let bytes = serde_json::from_value::<CallFlow>(value)
                .ok()
                .and_then(|flow| callflow_renderer::render(&flow).ok())
                .map(String::into_bytes);
            match bytes {
                Some(bytes) => download(
                    bytes,
                    "text/html; charset=utf-8",
                    &format!("OIRAN_CALLFLOW_{id}.html"),
                ),
                None => api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "EXPORT_UNAVAILABLE",
                    "HTML export unavailable",
                ),
            }
        }
        _ => api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_FORMAT",
            "format must be json or html",
        ),
    }
}

fn download(bytes: Vec<u8>, content_type: &'static str, name: &str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        )
        .body(Body::from(bytes))
        .unwrap_or_else(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "EXPORT_UNAVAILABLE",
                "could not build export response",
            )
        })
}

fn filter_events(items: &mut Vec<Value>, query: &ListQuery) {
    if let Some(x) = query.interface.as_deref() {
        items.retain(|e| e["interface"] == x)
    }
    if let Some(x) = query.protocol.as_deref() {
        items.retain(|e| e["protocol"] == x)
    }
    if let Some(x) = query.association.as_deref() {
        items.retain(|e| e["association"] == x)
    }
    if let Some(x) = query.search.as_deref() {
        let q = x.to_ascii_lowercase();
        items.retain(|e| {
            e["message_name"]
                .as_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains(&q)
        })
    }
    sort_values(
        items,
        query.sort.as_deref().unwrap_or("timestamp_ns"),
        query.order.as_deref(),
    );
}

fn sort_values(items: &mut [Value], field: &str, order: Option<&str>) {
    items.sort_by(|a, b| {
        a.get(field)
            .map(Value::to_string)
            .cmp(&b.get(field).map(Value::to_string))
    });
    if order == Some("desc") {
        items.reverse()
    }
}
fn paginated(mut items: Vec<Value>, query: &ListQuery) -> Json<Value> {
    sanitize_all(&mut items);
    let total = items.len();
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(25).clamp(1, 100);
    let start = (page - 1).saturating_mul(page_size);
    let data = items
        .into_iter()
        .skip(start)
        .take(page_size)
        .collect::<Vec<_>>();
    Json(
        json!({"data":data,"meta":{"page":page,"page_size":page_size,"total":total,"total_pages":total.div_ceil(page_size)}}),
    )
}

/// 2.14.11 (ANR1 #10 6860508699) — variante de `paginated` qui pousse
/// l'état du patcher dans `meta.read_time_patch` :
///   - `status == "applied"` : la session a bien reçu le patch.
///   - `status == "index_building"` : l'index compact n'était pas
///     encore prêt, les events sont servis tels quels (jamais une
///     correction silencieuse).
///   - `NotApplicable` : la fonction n'ajoute pas le champ (comportement
///     identique à `paginated`).
fn paginated_with_patch_status(
    items: Vec<Value>,
    query: &ListQuery,
    status: read_time_patch::PatchStatus,
) -> Json<Value> {
    let Json(mut value) = paginated(items, query);
    if let Some(label) = status.label() {
        if let Some(meta) = value.get_mut("meta").and_then(Value::as_object_mut) {
            meta.insert(
                "read_time_patch".into(),
                json!({
                    "status": label,
                    "version": read_time_patch::PATCH_VERSION,
                }),
            );
        }
    }
    Json(value)
}
fn ok(mut data: Value) -> Json<Value> {
    sanitize_value(&mut data);
    Json(json!({"data":data,"meta":{"api_version":API_VERSION}}))
}

const IDENTITY_LABEL_MARKERS: &[&str] = &[
    "imsi",
    "supi",
    "suci",
    "guti",
    "tmsi",
    "imei",
    "imeisv",
    "msisdn",
    "mobileidentity",
    "ueidentitypseudonym",
    "subscriberidentity",
    "authenticationkey",
    "subscriberkey",
    "securitykey",
    "opc",
];

fn normalized_privacy_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn is_identity_label(value: &str) -> bool {
    let normalized = normalized_privacy_label(value);
    IDENTITY_LABEL_MARKERS
        .iter()
        .any(|marker| normalized.contains(marker))
        || matches!(normalized.as_str(), "pei" | "k")
        || normalized.contains("permanentequipmentidentifier")
}

/// 2.19.1 — point d'entrée public pour le constructeur d'arbre
/// protocolaire : filtre les IEs identité AVANT ingestion. Jamais de
/// dérivation sémantique à partir du nom.
pub fn is_identity_label_pub(value: &str) -> bool {
    is_identity_label(value)
}

fn is_identity_object(value: &Value) -> bool {
    value.as_object().is_some_and(|map| {
        ["name", "type", "field", "key"]
            .iter()
            .filter_map(|key| map.get(*key).and_then(Value::as_str))
            .any(is_identity_label)
    })
}

fn sanitize_all(values: &mut Vec<Value>) {
    values.retain(|value| !is_identity_object(value));
    for value in values {
        sanitize_value(value)
    }
}
fn sanitize_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if ["name", "type", "field", "key"]
                .iter()
                .filter_map(|key| map.get(*key).and_then(Value::as_str))
                .any(is_identity_label)
            {
                map.clear();
                return;
            }
            let identity_keys = map
                .keys()
                .filter(|key| is_identity_label(key))
                .cloned()
                .collect::<Vec<_>>();
            for key in identity_keys {
                map.remove(&key);
            }
            for (key, v) in map.iter_mut() {
                if key == "source_file" {
                    if let Some(path) = v.as_str() {
                        let name = FsPath::new(path)
                            .file_name()
                            .and_then(|x| x.to_str())
                            .unwrap_or("capture.pcapng");
                        let safe_name = if is_identity_label(name)
                            || name
                                .split(|character: char| !character.is_ascii_digit())
                                .any(|part| part.len() >= 14)
                        {
                            "REDACTED.pcapng"
                        } else {
                            name
                        };
                        *v = Value::String(format!("capture://{safe_name}"));
                    }
                } else if key == "identities" {
                    // 2.15.0 (ANR1 #10 6883006379) — le champ
                    // `identities` d'un `session_summary` est
                    // construit par `identity_summary_for_session`
                    // à partir du vault : les valeurs sont déjà
                    // des pseudonymes vault-managed, pas des
                    // identifiants bruts. Les supprimer ici
                    // viderait la payload D3 entière vue par
                    // l'UI. Laisser tel quel ; la sanitization
                    // générique du reste du summary continue de
                    // s'appliquer.
                    continue;
                } else {
                    sanitize_value(v)
                }
            }
        }
        Value::Array(items) => sanitize_all(items),
        Value::String(text) => {
            let lower = text.to_ascii_lowercase();
            if [
                "imsi-", "supi-", "suci-", "5g-guti-", "5g-tmsi-", "imei-", "imeisv", "msisdn",
            ]
            .iter()
            .any(|prefix| lower.contains(prefix))
            {
                *text = "REDACTED".into();
            }
        }
        _ => {}
    }
}

async fn api_not_found() -> Response {
    api_error(
        StatusCode::NOT_FOUND,
        "ROUTE_NOT_FOUND",
        "unknown API route",
    )
}
fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({"error":{"code":code,"message":message},"meta":{"api_version":API_VERSION}})),
    )
        .into_response()
}

/// 2.21.30 (ordres #9 6952054201 + 6952664027) — réponse 503 commune
/// des routes lourdes bornées par
/// `capture_manager.heavy_memory_try_enter()`. Même shape que le chemin
/// froid `/identities` (2.21.28, Sadok) : code `HEAVY_WORK_IN_PROGRESS`,
/// `Retry-After: 60`, message explicite.
fn heavy_work_in_progress() -> Response {
    let mut response = api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "HEAVY_WORK_IN_PROGRESS",
        "continuous publication in progress, retry later",
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, header::HeaderValue::from_static("60"));
    response
}

fn io_error(error: std::io::Error) -> String {
    error.to_string()
}
fn json_error(error: serde_json::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod sbi_identity_wiring_tests {
    use super::*;

    fn event(protocol: &str, items: Value) -> callflow_schema::CallFlowEvent {
        serde_json::from_value(json!({
            "event_id": format!("ev-{protocol}"), "timestamp": "", "timestamp_ns": "0",
            "interface": "SBI", "protocol": protocol, "message_name": "GET am-data",
            "source_participant": "AMF", "destination_participant": "UDM",
            "direction": "REQUEST", "decoded_ie_tree": items,
            "decoding_status": "DECODED", "semantic_status": "OK",
            "association": "SESSION", "procedure_group": "", "packet_references": [],
            "capture_id": "cap-sbi", "decoder_name": "decoder-sbi", "decoder_version": "2.18.0",
            "raw_payload_reference": "", "errors": []
        }))
        .unwrap()
    }

    #[test]
    fn sbi_msisdn_and_imeisv_fill_identities_when_vault_is_empty() {
        let events = vec![event(
            "SBI-HTTP2",
            json!([
                {"name":"sbi_service","value":"nudm-sdm","source":"session_identifiers"},
                {"name":"sbi_operation","value":"am-data","source":"session_identifiers"},
                {"name":"msisdn_pseudonym","value":"msisdn-pseudo-A","source":"session_identifiers"},
                {"name":"imeisv_pseudonym","value":"pei-pseudo-B","source":"session_identifiers"}
            ]),
        )];
        let mut identities = Value::Null;
        merge_sbi_identities(&mut identities, &events);
        assert_eq!(identities["msisdn"], "msisdn-pseudo-A");
        assert_eq!(identities["imei"], "pei-pseudo-B");
        assert_eq!(identities["imei_type"], "IMEISV");
        assert!(identities["msisdn_source"]
            .as_str()
            .unwrap()
            .starts_with("SBI:nudm-sdm:am-data"));
        assert!(identities["imsi"].is_null());
    }

    #[test]
    fn vault_identity_keeps_priority_over_sbi() {
        let events = vec![event(
            "SBI-HTTP2",
            json!([{"name":"msisdn_pseudonym","value":"from-sbi"}]),
        )];
        let mut identities = json!({"imsi":"x","msisdn":"from-vault","imei":null});
        merge_sbi_identities(&mut identities, &events);
        assert_eq!(identities["msisdn"], "from-vault");
        assert!(identities.get("msisdn_source").is_none());
    }

    #[test]
    fn non_sbi_or_absent_identifier_changes_nothing() {
        let events = vec![
            event(
                "NGAP",
                json!([{"name":"msisdn_pseudonym","value":"not-sbi"}]),
            ),
            event("SBI-HTTP2", json!([{"name":"supi_pseudonym","value":"x"}])),
        ];
        let mut identities = Value::Null;
        merge_sbi_identities(&mut identities, &events);
        assert!(identities.is_null());
    }

    /// 2.18.4 (ANR1 #10) — route détail `/sessions/:id/identities` :
    /// quand le vault est vide pour une session mais que les events
    /// SBI du call flow portent `msisdn_pseudonym` / `imeisv_pseudonym`,
    /// `identity_bundle(observations, events)` doit remonter les
    /// valeurs avec preuve séparée (source + event_id + capture_id +
    /// packet_number + cap_seq).
    #[test]
    fn identity_bundle_fills_msisdn_and_imei_from_sbi_when_vault_is_empty_2184() {
        let mut ev = event(
            "SBI-HTTP2",
            json!([
                {"name":"sbi_service","value":"nudm-sdm"},
                {"name":"sbi_operation","value":"am-data"},
                {"name":"msisdn_pseudonym","value":"msisdn-pseudo-A"},
                {"name":"imeisv_pseudonym","value":"pei-pseudo-B"}
            ]),
        );
        ev.packet_references = vec![session_engine::PacketRef {
            source_file: "x".into(),
            packet_number: 42,
            byte_offset: 0,
            interface_id: 0,
            captured_length: 1,
            original_length: 1,
        }];
        let bundle = identity_bundle(Vec::new(), &[ev]);
        // IMSI absent du vault → null.
        assert!(bundle["imsi"].is_null());
        assert!(bundle["imsi_proof"].is_null());
        // MSISDN depuis SBI avec preuve séparée.
        assert_eq!(bundle["msisdn"], "msisdn-pseudo-A");
        let proof = &bundle["msisdn_proof"];
        assert_eq!(proof["source"], "SBI:nudm-sdm:am-data");
        assert_eq!(proof["event_id"], "ev-SBI-HTTP2");
        assert_eq!(proof["capture_id"], "cap-sbi");
        assert_eq!(proof["packet_number"], 42);
        assert_eq!(proof["cap_seq"], "cap-sbi·42");
        // IMEI/IMEISV depuis SBI dans la même shape que le vault
        // (objet evidence), avec `type = IMEISV` et `role = sbi-observed`.
        let imei = &bundle["imei"];
        assert_eq!(imei["value"], "pei-pseudo-B");
        assert_eq!(imei["type"], "IMEISV");
        assert_eq!(imei["role"], "sbi-observed");
        assert_eq!(imei["source"], "SBI:nudm-sdm:am-data");
        assert_eq!(imei["event_id"], "ev-SBI-HTTP2");
        assert_eq!(imei["packet_number"], 42);
    }

    /// 2.18.4 — Vault prioritaire : si une observation `msisdn`
    /// existe dans le vault, l'event SBI doit être IGNORÉ pour ce
    /// kind (pas de fuite SBI quand le vault parle). La preuve est
    /// celle du vault, pas celle du SBI.
    #[test]
    fn identity_bundle_vault_msisdn_takes_priority_over_sbi_2184() {
        let vault = vec![IdentityObservation {
            session_id: "s".into(),
            subscriber_pseudonym: Some("psn-vault".into()),
            kind: "msisdn".into(),
            value: "msisdn-from-vault".into(),
            value_type: Some("MSISDN".into()),
            role: "presented".into(),
            event_id: "evt-vault-1".into(),
            capture_id: "cap-vault".into(),
            packet_number: 7,
            cleartext: None,
        }];
        let ev = event(
            "SBI-HTTP2",
            json!([
                {"name":"sbi_service","value":"nudm-sdm"},
                {"name":"sbi_operation","value":"am-data"},
                {"name":"msisdn_pseudonym","value":"msisdn-pseudo-SBI"}
            ]),
        );
        let bundle = identity_bundle(vault, &[ev]);
        // Vault l'emporte : la valeur et la preuve sont celles du vault.
        assert_eq!(bundle["msisdn"], "msisdn-from-vault");
        assert_eq!(bundle["msisdn_proof"]["value"], "msisdn-from-vault");
        assert_eq!(bundle["msisdn_proof"]["event_id"], "evt-vault-1");
        assert_eq!(bundle["msisdn_proof"]["capture_id"], "cap-vault");
        // Pas de `source` SBI puisque le vault a parlé.
        assert!(bundle["msisdn_proof"]["source"].is_null());
    }

    /// 2.18.4 — Shape inchangée du bundle quand il n'y a rien du
    /// tout (ni vault, ni SBI) : les champs identité valent `null`.
    /// Garantit la non-régression du contrat `/sessions/:id/identities`
    /// pour les sessions sans identité observée.
    #[test]
    fn identity_bundle_without_vault_or_sbi_keeps_null_shape_2184() {
        let bundle = identity_bundle(Vec::new(), &[]);
        assert!(bundle["imsi"].is_null());
        assert!(bundle["imsi_proof"].is_null());
        assert!(bundle["msisdn"].is_null());
        assert!(bundle["msisdn_proof"].is_null());
        assert!(bundle["imei"].is_null());
        assert_eq!(bundle["tmsi"], json!([]));
        assert_eq!(bundle["s_tmsi"], json!([]));
        assert_eq!(bundle["m_tmsi"], json!([]));
        assert!(bundle["subscriber_pseudonym"].is_null());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use capture_helper::{
        CaptureBackend, CaptureHelperClient, CaptureService, CaptureSession, HelperFailure,
        InterfaceId, ServerConfig,
    };
    use http_body_util::BodyExt;
    use live_probe::lte_evidence::LteEvidenceImportRequest;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt;
    #[derive(Clone)]
    struct ValidationOnlyBackend;

    impl CaptureBackend for ValidationOnlyBackend {
        fn initialize(
            &self,
            _interfaces: &[InterfaceId],
        ) -> Result<Box<dyn CaptureSession>, HelperFailure> {
            panic!("ValidateCapture must not initialize packet acquisition")
        }
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("oiran-api-{label}-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn identity_vault_default_is_below_the_dedicated_directory() {
        assert_eq!(DEFAULT_IDENTITY_VAULT_DIR, "/var/lib/oiran/identity-vault");
        assert_eq!(
            DEFAULT_IDENTITY_VAULT_PATH,
            "/var/lib/oiran/identity-vault/vault.json"
        );
        assert_ne!(
            FsPath::new(DEFAULT_IDENTITY_VAULT_PATH).parent(),
            Some(FsPath::new("/var/lib/oiran"))
        );
    }

    #[test]
    fn access_check_failure_reports_exact_path_and_mode() {
        let root = temporary_directory("access-check");
        fs::create_dir_all(&root).unwrap();
        let path = root.join("not-executable");
        fs::write(&path, b"test").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = access_check(&path, libc::X_OK, "executable").unwrap_err();
        assert!(error.contains("ACCESS_CHECK_FAILED"));
        assert!(error.contains(&format!("path={}", path.display())));
        assert!(error.contains("mode=0600"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn existing_read_only_service_state_directories_pass_startup_checks() {
        let root = temporary_directory("service-state-read-only");
        let mut config = ApiConfig::from_workspace(&root);
        config.derived_import_root = root.join("derived");
        config.lte_evidence_root = root.join("lte-store");
        config.lte_evidence_bundle_root = root.join("lte-bundles");
        for path in [
            &config.derived_import_root,
            &config.lte_evidence_root,
            &config.lte_evidence_bundle_root,
        ] {
            fs::create_dir_all(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }

        service_state_access_checks(&config).unwrap();

        for path in [
            &config.derived_import_root,
            &config.lte_evidence_root,
            &config.lte_evidence_bundle_root,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_service_state_directory_in_read_only_parent_is_explicit() {
        // 2.14.5 (ANR1 #10) : le test 2.14.4 utilisait un répertoire parent
        // à mode 0o555 et comptait sur l'échec de `libc::access(parent, W_OK)`
        // pour prouver qu'un dossier d'état absent + parent non-créable
        // remonte une erreur explicite. Sous euid=0 (`unshare -r`, conteneur
        // privilégié, service systemd `User=root`), `libc::access` outrepasse
        // les mode bits pour le bit W_OK → le test recevait Ok(()). Faux
        // positif, pas une garantie.
        //
        // On provoque désormais l'échec par ENOTDIR / EACCES sur X_OK en
        // utilisant un FICHIER comme « parent ». `libc::access(fichier, X_OK)`
        // échoue pour tout utilisateur — y compris root — tant qu'aucun bit
        // d'exécution n'est positionné dans les trois triplets de permissions
        // (POSIX.1-2008 : « If any of the specified access permissions would
        // be denied, access() shall return -1 »). Un fichier régulier créé
        // via `fs::write` avec l'umask courant est systématiquement
        // non-exécutable, et on force explicitement 0o644 pour couper tout
        // doute. Pas de garde `euid==0 → skip` : un garde qui se saute
        // ne garantit rien.
        let root = temporary_directory("service-state-missing");
        let non_directory_parent = root.join("parent-is-a-regular-file");
        fs::write(&non_directory_parent, b"").unwrap();
        fs::set_permissions(&non_directory_parent, fs::Permissions::from_mode(0o644)).unwrap();
        let missing = non_directory_parent.join("missing-derived-import");
        let error = access_check_readable_or_creatable(
            &missing,
            "derived-import-read",
            "derived-import-create",
        )
        .unwrap_err();

        assert!(error.contains("ACCESS_CHECK_FAILED"));
        assert!(error.contains("required=derived-import-create"));
        assert!(error.contains(&format!("requested_path={}", missing.display())));

        fs::remove_file(&non_directory_parent).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    fn test_config(root: &FsPath, label: &str) -> ApiConfig {
        let mut config = ApiConfig::from_workspace(root);
        config.probe_registry_path = temporary_directory(label).join("probe-registry.json");
        let evidence = temporary_directory(&format!("{label}-lte-evidence"));
        config.lte_evidence_root = evidence.join("store");
        config.lte_evidence_bundle_root = evidence.join("inbox");
        let key_dir = temporary_directory(&format!("{label}-pseudonym"));
        config.pseudonym_key_path = Some(key_dir.join("pseudonym.key"));
        let identity_directory = temporary_directory(&format!("{label}-identities"));
        fs::set_permissions(&identity_directory, fs::Permissions::from_mode(0o700)).unwrap();
        config.identity_vault_path = identity_directory.join("identity-vault.json");
        config
    }
    fn state() -> AppState {
        let root = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        AppState::load(test_config(root, "registry-viewer")).unwrap()
    }
    fn operator_state() -> AppState {
        let root = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut config = test_config(root, "registry-operator");
        config.operator_token_sha256 = Some(sha256_hex(b"test-operator-token"));
        AppState::load(config).unwrap()
    }
    fn req(path: &str, _public_access: bool) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }
    async fn json_body(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    /// 2.14.11 (ANR1 #10 6860508699) — garde RAII pour supprimer un
    /// répertoire test MÊME si le test panic. `remove_dir_all` en fin
    /// de fonction ne suffit pas : un `assert!` qui saute laisse 3 GiB
    /// d'artefacts sur disque (incident 2026-11-13). Drop est appelé
    /// par le runtime pendant le dépilement de panic.
    struct AutoRemoveDir {
        path: PathBuf,
    }

    impl AutoRemoveDir {
        fn new(path: PathBuf) -> Self {
            // Parent doit exister et autoriser la création du dossier.
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::create_dir_all(&path);
            Self { path }
        }

        fn path(&self) -> &FsPath {
            self.path.as_path()
        }

        fn as_pathbuf(&self) -> PathBuf {
            self.path.clone()
        }
    }

    impl Drop for AutoRemoveDir {
        fn drop(&mut self) {
            // On ignore l'erreur délibérément : en cas de double-drop
            // ou de dossier déjà nettoyé, pas de panic dans Drop (qui
            // deviendrait un double-panic).
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    /// 2.14.11 — preuve dédiée : même si un test panic APRÈS la
    /// création du capture_root, la garde `AutoRemoveDir` supprime
    /// le répertoire. L'assertion vérifie l'absence du répertoire
    /// APRÈS le panic (via `catch_unwind` + check post-mortem).
    #[test]
    fn auto_remove_dir_cleans_up_even_on_panic() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let path = workspace.join("runtime").join(format!(
            "auto-remove-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // Capture l'emplacement AVANT le panic pour pouvoir vérifier
        // qu'il a disparu APRÈS.
        let probe_path = path.clone();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let guard = AutoRemoveDir::new(path);
            // Marqueur sur disque pour prouver que la cleanup a vu
            // le contenu.
            fs::write(guard.path().join("probe.txt"), b"alive").unwrap();
            assert!(guard.path().join("probe.txt").exists());
            // Panic volontaire. `guard` est encore en scope → Drop
            // s'exécute pendant l'unwind.
            panic!("intentional panic to exercise Drop guard");
        }));
        assert!(outcome.is_err(), "panic must have been caught");
        assert!(
            !probe_path.exists(),
            "AutoRemoveDir did not clean up after panic ; path still present: {}",
            probe_path.display()
        );
    }

    /// 2.14.11 (ANR1 #10 6860508699) — attend que l'index compact
    /// soit `ready=true`. Sans cette attente, les tests du patcher
    /// voient la première requête avec `status=index_building`
    /// (comportement voulu en prod, rendu déterministe ici).
    /// Polling 10 ms, timeout `budget`. Déclenche la construction en
    /// faisant une requête arbitraire si l'index n'est pas encore
    /// tracké.
    async fn wait_for_compact_index_ready(state: &AppState, budget: std::time::Duration) {
        let deadline = std::time::Instant::now() + budget;
        // Si le registre est vide (pas de tracking encore déclenché),
        // frappe /sessions une fois pour forcer ensure_tracking +
        // spawn du worker.
        let mut triggered = false;
        while std::time::Instant::now() < deadline {
            let version = json_body(
                router(state.clone(), None)
                    .oneshot(req("/api/v1/version", true))
                    .await
                    .unwrap(),
            )
            .await;
            let ready = version["data"]["read_time_patch"]["index"]["ready"]
                .as_bool()
                .unwrap_or(false);
            let entries = version["data"]["read_time_patch"]["index"]["entries"]
                .as_u64()
                .unwrap_or(0);
            if ready {
                return;
            }
            if entries == 0 && !triggered {
                // Déclenche le tracking + spawn en appelant un handler
                // qui passe par apply_read_time_patch.
                let _ = router(state.clone(), None)
                    .oneshot(req("/api/v1/sessions?page_size=1", true))
                    .await;
                triggered = true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!(
            "compact index did not become ready within {} ms",
            budget.as_millis()
        );
    }
    fn assert_no_identity_material(value: &Value) {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    assert!(
                        !is_identity_label(key),
                        "identity-bearing key remained: {key}"
                    );
                    assert_no_identity_material(nested);
                }
                if let Some(label) = map.get("name").and_then(Value::as_str) {
                    assert!(!is_identity_label(label), "identity IE remained: {label}");
                }
            }
            Value::Array(items) => items.iter().for_each(assert_no_identity_material),
            Value::String(text) => {
                let lower = text.to_ascii_lowercase();
                for forbidden in [
                    "masked_imeisv=",
                    "imsi-",
                    "supi-",
                    "suci-",
                    "5g-guti-",
                    "5g-tmsi-",
                    "imei-",
                    "msisdn=",
                ] {
                    assert!(!lower.contains(forbidden), "identity value remained");
                }
            }
            _ => {}
        }
    }
    fn lte_import_payload() -> Value {
        json!({
            "schema_version":"oiran.lte-evidence-ingestion.v1",
            "bundle_id":"bundle-synthetic-01",
            "evidence":{
                "schema_version":"oiran-polaris.lte-e2e-evidence.v1",
                "run_id":"lte-run-synthetic-0001",
                "profile_id":"LTE-SRSUE-TEST-01",
                "scenario_id":"lte-e2e-certification-v1",
                "started_at":"2026-10-31T12:00:00Z",
                "ended_at":"2026-10-31T12:00:10Z",
                "final_state":"COMPLETED",
                "steps":[],
                "capture_refs":[],
                "cleanup":{"srsue_stopped":true,"srsenb_stopped":true,"sidecars_removed":true,"epc_healthy":true,"dumpcaps_preserved":true}
            },
            "capture_bindings":[]
        })
    }
    fn lte_polaris_import_envelope() -> Value {
        let oiran_import = lte_import_payload();
        json!({
            "schema_version":"polaris-oiran.lte-import-envelope.v1",
            "provenance":{
                "source":"POLARIS_SERVER_VERIFIED_BUNDLE",
                "published_at_epoch_ms":1793448010000_u64,
                "run_id":"lte-run-synthetic-0001",
                "rat":"LTE",
                "profile_id":"LTE-SRSUE-TEST-01",
                "scenario_id":"lte-e2e-certification-v1",
                "started_at":"2026-10-31T12:00:00Z",
                "ended_at":"2026-10-31T12:00:10Z",
                "capture_ids":[],
                "session_references":[],
                "session_reference_state":"NOT_AVAILABLE_UNTIL_OIRAN_INGESTION"
            },
            "oiran_import":oiran_import
        })
    }
    #[tokio::test]
    async fn unauthenticated_request_is_allowed_read_only() {
        assert_eq!(
            router(state(), None)
                .oneshot(req("/api/v1/health", false))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        )
    }

    #[tokio::test]
    async fn operational_mode_never_preloads_reference_sessions() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut config = test_config(workspace, "operational-real-only");
        config.reference_dataset_enabled = false;
        config.capture_root = temporary_directory("operational-captures");
        let state = AppState::load(config).unwrap();
        assert!(state.inner.flows.is_empty());
        assert!(state.inner.registry.list().is_empty());
        let response = router(state, None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["meta"]["total"], 0);
        assert!(body["data"].as_array().unwrap().is_empty());
    }

    /// 2.15.0 (ANR1 #10 6883006379) — D3 : enrichissement
    /// `identities` compact dans /api/v1/sessions. Pousse une
    /// IdentityObservation sur la session primaire, puis vérifie
    /// que la payload /sessions expose directement les champs
    /// imsi/imei/msisdn/tmsi/s_tmsi/m_tmsi/subscriber_pseudonym
    /// (shape consommée par p900 `observedIdentity`). L'UI n'a
    /// plus besoin d'ouvrir la session pour afficher les
    /// identités dans la liste.
    #[tokio::test]
    async fn sessions_list_exposes_compact_identities_summary_from_vault() {
        let state = state();
        let session_id = state.inner.primary_session_id.clone();
        assert!(
            !session_id.is_empty(),
            "primary session is required for this test"
        );
        state
            .inner
            .identity_vault
            .upsert(vec![
                IdentityObservation {
                    session_id: session_id.clone(),
                    subscriber_pseudonym: Some("psn-test-c330d205adafa233".into()),
                    kind: "imsi".into(),
                    value: "imsi-001010123456789".into(),
                    value_type: Some("IMSI".into()),
                    role: "presented".into(),
                    event_id: "event-imsi-01".into(),
                    capture_id: "cap-identity".into(),
                    packet_number: 1,
                    cleartext: None,
                },
                IdentityObservation {
                    session_id: session_id.clone(),
                    subscriber_pseudonym: Some("psn-test-c330d205adafa233".into()),
                    kind: "s_tmsi".into(),
                    value: "s-tmsi-cafebabe".into(),
                    value_type: Some("S-TMSI".into()),
                    role: "presented".into(),
                    event_id: "event-stmsi-01".into(),
                    capture_id: "cap-identity".into(),
                    packet_number: 2,
                    cleartext: None,
                },
            ])
            .unwrap();
        let response = router(state, None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let sessions = body["data"].as_array().expect("data array");
        let target = sessions
            .iter()
            .find(|item| item["session_id"] == session_id)
            .expect("primary session visible in /sessions");
        let identities = &target["identities"];
        assert!(
            identities.is_object(),
            "identities summary must be a JSON object, got {identities:?}"
        );
        assert_eq!(
            identities["imsi"], "imsi-001010123456789",
            "imsi must be the latest observation value"
        );
        assert_eq!(
            identities["subscriber_pseudonym"], "psn-test-c330d205adafa233",
            "subscriber_pseudonym must be the vault pseudonym"
        );
        let s_tmsi = identities["s_tmsi"]
            .as_array()
            .expect("s_tmsi must be an array");
        assert_eq!(s_tmsi.len(), 1);
        assert_eq!(s_tmsi[0], "s-tmsi-cafebabe");
        // Shape : les kinds absents doivent valoir explicitement
        // null (imei, msisdn) ou tableau vide (tmsi, m_tmsi) —
        // c'est le format que p900 `observedIdentity` consomme.
        assert!(identities["imei"].is_null());
        assert!(identities["msisdn"].is_null());
        assert!(identities["tmsi"].as_array().unwrap().is_empty());
        assert!(identities["m_tmsi"].as_array().unwrap().is_empty());
    }

    /// 2.15.0 (D4, règle Sadok 2026-11-14) — quand l'ingestion
    /// `decoder-nas` détecte un SUCI null-scheme (protectionScheme=0)
    /// ou un IMSI EPS en clair, elle **peut** pousser la valeur
    /// clear-text via `IdentityObservation::cleartext`. Dans ce
    /// cas, `/api/v1/sessions` expose ce clear-text sous la clé
    /// `imsi_cleartext` à côté du `imsi` pseudonymisé. Les kinds
    /// NON autorisés par la règle (GUTI/TMSI/IMEI/MSISDN) n'ont
    /// pas de champ `*_cleartext` : ils restent pseudonymisés
    /// uniformément.
    #[tokio::test]
    async fn sessions_list_exposes_cleartext_imsi_when_vault_stores_it() {
        let state = state();
        let session_id = state.inner.primary_session_id.clone();
        state
            .inner
            .identity_vault
            .upsert(vec![IdentityObservation {
                session_id: session_id.clone(),
                subscriber_pseudonym: Some("psn-null-scheme".into()),
                kind: "imsi".into(),
                value: "imsi-REDACTED-pseudo-abc".into(),
                value_type: Some("IMSI".into()),
                role: "presented".into(),
                event_id: "event-null-scheme-attach".into(),
                capture_id: "cap-null-scheme".into(),
                packet_number: 7,
                // Clear-text autorisé : SUCI null-scheme / IMSI EPS.
                // La chaîne decoder-nas remplira ce champ en lot
                // ultérieur ; le test exerce la plomberie
                // `/sessions` + sanitize.
                cleartext: Some("208010123456789".into()),
            }])
            .unwrap();
        let response = router(state, None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let sessions = body["data"].as_array().expect("data array");
        let target = sessions
            .iter()
            .find(|item| item["session_id"] == session_id)
            .expect("primary session visible");
        let identities = &target["identities"];
        assert!(identities.is_object());
        assert_eq!(
            identities["imsi_cleartext"], "208010123456789",
            "imsi_cleartext must be exposed when vault has a non-null cleartext"
        );
        // Le pseudonyme reste présent — les deux champs cohabitent.
        assert!(
            identities["imsi"].is_string(),
            "imsi pseudo must stay next to cleartext"
        );
        // Aucun *_cleartext pour les autres kinds (GUTI/TMSI/IMEI
        // restent pseudonymisés uniformément par la règle Sadok).
        assert!(
            identities.get("tmsi_cleartext").is_none(),
            "GUTI/TMSI/IMEI must never have a *_cleartext field"
        );
        assert!(identities.get("imei_cleartext").is_none());
        assert!(identities.get("msisdn_cleartext").is_none());
    }

    /// 2.15.0 — garde : si une observation imsi n'a pas de
    /// cleartext (default `None`), la payload `/sessions` **omet**
    /// `imsi_cleartext` (serialize_if = Option::is_none) plutôt
    /// que de le forcer à null. L'UI distingue « cleartext non
    /// disponible » (clé absente) de « cleartext présent mais
    /// vide » (impossible par construction).
    #[tokio::test]
    async fn sessions_list_omits_imsi_cleartext_when_absent() {
        let state = state();
        let session_id = state.inner.primary_session_id.clone();
        state
            .inner
            .identity_vault
            .upsert(vec![IdentityObservation {
                session_id: session_id.clone(),
                subscriber_pseudonym: Some("psn-default".into()),
                kind: "imsi".into(),
                value: "imsi-pseudo-only".into(),
                value_type: Some("IMSI".into()),
                role: "presented".into(),
                event_id: "event-pseudo".into(),
                capture_id: "cap-pseudo".into(),
                packet_number: 1,
                cleartext: None,
            }])
            .unwrap();
        let response = router(state, None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        let body = json_body(response).await;
        let target = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["session_id"] == session_id)
            .expect("primary session visible");
        let identities = &target["identities"];
        assert_eq!(
            identities["imsi_cleartext"],
            Value::Null,
            "imsi_cleartext must be JSON null when vault has None"
        );
    }

    /// 2.15.0 — garde : quand l'identity_vault n'a RIEN observé
    /// pour la session, `identities` doit être `null`, pas un
    /// objet vide. L'UI distingue ainsi « pas d'observation » de
    /// « observation sans valeurs utiles ».
    #[tokio::test]
    async fn sessions_list_identities_is_null_when_vault_empty_for_session() {
        let state = state();
        let session_id = state.inner.primary_session_id.clone();
        let response = router(state, None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        let body = json_body(response).await;
        let sessions = body["data"].as_array().expect("data array");
        let target = sessions
            .iter()
            .find(|item| item["session_id"] == session_id)
            .expect("primary session visible");
        assert!(
            target["identities"].is_null(),
            "identities must be null when vault has no observation, got {:?}",
            target["identities"]
        );
    }

    /// 2.7.19 (issue #9 part 2): /health and the on-disk
    /// `dataset_manifest.json` MUST come from the same LiveDataset. The
    /// ANR2 lab observed /health=25 939/10 while the on-disk manifest
    /// said 25 537/8. Root cause: 2.7.17 /health summed across every
    /// entry of `capture_manager.datasets()`, so a residual
    /// recovered-dataset (402 events / 2 sessions) was added on top of
    /// the continuous one. 2.7.19 /health reads only
    /// `capture_manager.dataset(CONTINUOUS_DATASET_ID)`. This test seeds
    /// a continuous manifest on disk, lets `recover_continuous_dataset_from_disk`
    /// rehydrate it, adds a DIFFERENT recovered dataset in RAM, and
    /// asserts /health still reflects exactly the continuous manifest.
    #[tokio::test]
    async fn health_published_counters_mirror_the_continuous_manifest_exclusively() {
        use live_probe::{CaptureManager, CONTINUOUS_CAPTURE_ID, CONTINUOUS_DATASET_ID};
        use std::fs;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut config = test_config(workspace, "operational-health-coherence");
        config.reference_dataset_enabled = false;
        let capture_root = temporary_directory("health-coherence-captures");
        config.capture_root = capture_root.clone();
        // Pre-seed a continuous dataset: pcap/, dataset/*, matching
        // `validate_dataset_artifacts`.
        let base = capture_root.join(CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        fs::create_dir_all(dataset_dir.join("callflows")).unwrap();
        fs::create_dir_all(base.join("pcap")).unwrap();
        // Shape-match the production artifacts: 24 events across 8
        // sessions, the ratio ANR2 saw in the lab. Numbers are
        // deliberately small so `validate_dataset_artifacts` can count
        // lines without pulling a 50 MiB spool. The invariant we are
        // asserting is coherence between /health and the manifest, which
        // is scale-invariant.
        const EVENT_COUNT: usize = 24;
        const SESSION_COUNT: usize = 8;
        let mut events_bytes = Vec::new();
        for i in 0..EVENT_COUNT {
            use std::io::Write as _;
            let event = serde_json::json!({
                "event_id": format!("evt-{i:04}"),
                "capture_id": "sha256:stub",
                "capture_point_id": "N2",
                "interface": "N2",
                "protocol": "NGAP",
                "message_name": "InitialUEMessage",
                "decoding_status": "DECODED",
                "decoder_name": "stub",
                "decoder_version": "0",
                "raw_payload_reference": "sha256:stub",
                "direction": "RAN_TO_CORE",
                "source_endpoint": {"address": "10.0.0.1", "network_function": "gNB"},
                "destination_endpoint": {"address": "10.0.0.2", "network_function": "AMF"},
                "session_identifiers": [],
                "information_elements": [],
                "packet_references": [{
                    "source_file": format!("/captures/CONT/N2.pcapng"),
                    "packet_number": (i + 1) as u64,
                    "byte_offset": 0,
                    "interface_id": 0,
                    "captured_length": 10,
                    "original_length": 10,
                }],
                "errors": [],
                "timestamp": {
                    "seconds": 1_792_872_462_i64 + i as i64,
                    "nanoseconds": 0_u64,
                    "raw_ticks": 1_792_872_462_000_000_000_u64,
                    "resolution_base": 10,
                    "resolution_exponent": 9,
                    "display": "1792872462.000000000Z"
                }
            });
            writeln!(events_bytes, "{}", event).unwrap();
        }
        fs::write(dataset_dir.join("oiran_events.jsonl"), &events_bytes).unwrap();
        let continuous = serde_json::json!({
            "dataset_id": CONTINUOUS_DATASET_ID,
            "capture_id": CONTINUOUS_CAPTURE_ID,
            "path": format!("runtime/live-captures/{CONTINUOUS_CAPTURE_ID}/dataset"),
            "event_count": EVENT_COUNT,
            "session_ids": (0..SESSION_COUNT).map(|i| format!("sess-{i}")).collect::<Vec<_>>(),
            "decode_reports": {},
            "checksums": {},
            "state": "PUBLISHED",
            "discovery": null,
            "capture_started_epoch_ms": null,
            "last_packet_epoch_ms": null,
            "fresh_packet_count": 0,
            "active_ue_ips": [],
            "active_pdu_contexts": [],
        });
        // Match the session_ids we declared in the manifest with
        // callflow stubs so validate_dataset_artifacts accepts the
        // bundle on re-hydration.
        for i in 0..SESSION_COUNT {
            let stub = serde_json::json!({
                "callflow_id": format!("cf-sess-{i}"),
                "session_id": format!("sess-{i}"),
                "technology": "5G SA",
                "start_timestamp": "0",
                "end_timestamp": "0",
                "participants": [],
                "interfaces": ["N2"],
                "procedures": [],
                "events": [],
                "correlation_edges": [],
                "correlation_status": {},
                "decoder_versions": {},
                "schema_version": "1.2.0",
                "capture_references": [],
                "accounting": {
                    "source_events": 0,
                    "session_events": 0,
                    "background_events": 0,
                    "unmatched_events": 0,
                    "duplicate_events": 0,
                    "extra_events": 0
                },
                "unresolved_fields": 0
            });
            fs::write(
                dataset_dir.join("callflows").join(format!("sess-{i}.json")),
                serde_json::to_vec(&stub).unwrap(),
            )
            .unwrap();
            fs::write(
                dataset_dir.join("callflows").join(format!("sess-{i}.html")),
                b"<html></html>",
            )
            .unwrap();
        }
        fs::write(
            dataset_dir.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&continuous).unwrap(),
        )
        .unwrap();
        let state = AppState::load(config).unwrap();
        let manager = &state.inner.capture_manager;
        // `AppState::load` does not spawn the continuous worker in tests
        // (the lab-allowlisted source dir is production-only), so we hydrate
        // the manifest here explicitly — the production code path is the
        // same `recover_continuous_dataset_from_disk` call inside
        // `start_continuous_import` (`live-probe/src/lib.rs:952-958`).
        manager
            .recover_continuous_dataset_from_disk(&base)
            .expect("hydrate");
        assert!(manager.dataset(CONTINUOUS_DATASET_ID).is_some());
        let live = manager.dataset(CONTINUOUS_DATASET_ID).unwrap();
        assert_eq!(live.event_count, EVENT_COUNT);
        assert_eq!(live.session_ids.len(), SESSION_COUNT);
        // /health must expose the continuous dataset's publication counters
        // independently from the queryable union used by `session_count`.
        // The sum-of-all projection of 2.7.17 would have added a residual
        // dataset's events on top; the publication projection reads only the
        // continuous dataset, so these numbers MUST equal the manifest.
        let response = router(state, None)
            .oneshot(req("/api/v1/health", false))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(body["data"]["source_events"], EVENT_COUNT);
        assert_eq!(body["data"]["session_count"], SESSION_COUNT);
        assert_eq!(body["data"]["published_session_count"], SESSION_COUNT);
        assert_eq!(body["data"]["dataset"], CONTINUOUS_DATASET_ID);
        // Final invariant: /health must match the on-disk manifest on
        // the same fields.
        let on_disk: serde_json::Value =
            serde_json::from_slice(&fs::read(dataset_dir.join("dataset_manifest.json")).unwrap())
                .unwrap();
        assert_eq!(
            body["data"]["source_events"].as_u64().unwrap() as usize,
            on_disk["event_count"].as_u64().unwrap() as usize
        );
        assert_eq!(
            body["data"]["session_count"].as_u64().unwrap() as usize,
            on_disk["session_ids"].as_array().unwrap().len()
        );
        // Sanity check: manager type exposes dataset lookups by id.
        let _ = CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            false,
            capture_root.join(".oiran-pseudonym.key"),
        );
    }

    #[test]
    fn response_sanitizer_removes_identity_fields_and_identity_ies() {
        let mut value = json!({
            "imsi":"synthetic-identity",
            "nested":{"name":"5G-S-TMSI","value":"sensitive","source_file":"/private/a.pcapng"},
            "description":"subscriber imsi-SYNTHETIC",
            "useful":"InitialContextSetupRequest",
            "information_elements":[
                {"name":"MaskedIMEISV","value":"masked_imeisv=opaque"},
                {"name":"RAN-UE-NGAP-ID","value":"42"}
            ]
        });
        sanitize_value(&mut value);
        assert!(value.get("imsi").is_none());
        assert_eq!(value["nested"], json!({}));
        assert_eq!(value["description"], "REDACTED");
        assert_eq!(value["useful"], "InitialContextSetupRequest");
        assert_eq!(value["information_elements"].as_array().unwrap().len(), 1);
        assert_eq!(value["information_elements"][0]["name"], "RAN-UE-NGAP-ID");
        assert!(!value.to_string().contains("IDENTITY_WITHHELD"));

        let mut provenance = json!({"source_file":"/capture/capture-00000000000000.pcapng"});
        sanitize_value(&mut provenance);
        assert_eq!(provenance["source_file"], "capture://REDACTED.pcapng");
    }

    #[tokio::test]
    async fn raw_read_routes_remove_identity_material_for_viewer_and_operator() {
        let fixture = state();
        let raw = flow_value_for(&fixture, "5g-UE-A-pdu-1").unwrap().clone();
        assert!(raw.to_string().contains("MaskedIMEISV"));
        let app = router(fixture, None);
        for route in [
            "/api/v1/datasets?page_size=100",
            "/api/v1/sessions?page_size=100",
            "/api/v1/sessions/5g-UE-A-pdu-1",
            "/api/v1/sessions/5g-UE-A-pdu-1/events?page_size=100",
            "/api/v1/sessions/5g-UE-A-pdu-1/callflow?limit=100",
            "/api/v1/packets?page_size=100",
        ] {
            let response = app.clone().oneshot(req(route, false)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {route}");
            let body = json_body(response).await;
            assert_no_identity_material(&body);
            assert_ne!(body["data"], Value::Null, "useful data missing on {route}");
        }

        let identity_event_id = raw["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|event| event.to_string().contains("MaskedIMEISV"))
            .and_then(|event| event["event_id"].as_str())
            .unwrap();
        for route in [
            format!("/api/v1/events/{identity_event_id}"),
            format!("/api/v1/events/{identity_event_id}/provenance"),
        ] {
            let response = app.clone().oneshot(req(&route, false)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "route {route}");
            assert_no_identity_material(&json_body(response).await);
        }

        let packet_list = app
            .clone()
            .oneshot(req("/api/v1/packets?page_size=100", false))
            .await
            .unwrap();
        let packet_list = json_body(packet_list).await;
        let packet_id = packet_list["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|packet| packet["event_id"] == identity_event_id)
            .and_then(|packet| packet["packet_id"].as_str())
            .unwrap();
        let response = app
            .clone()
            .oneshot(req(&format!("/api/v1/packets/{packet_id}"), false))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_identity_material(&json_body(response).await);

        let export = app
            .clone()
            .oneshot(req(
                "/api/v1/exports/callflow/5g-UE-A-pdu-1?format=json",
                false,
            ))
            .await
            .unwrap();
        assert_eq!(export.status(), StatusCode::OK);
        assert_no_identity_material(&json_body(export).await);

        let export = app
            .clone()
            .oneshot(req(
                "/api/v1/exports/callflow/5g-UE-A-pdu-1?format=html",
                false,
            ))
            .await
            .unwrap();
        assert_eq!(export.status(), StatusCode::OK);
        let html = String::from_utf8(
            export
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(!html.to_ascii_lowercase().contains("maskedimeisv"));
        assert!(!html.to_ascii_lowercase().contains("masked_imeisv"));
        assert!(html.contains("InitialContextSetupRequest"));

        let operator_app = router(operator_state(), None);
        let response = operator_app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sessions/5g-UE-A-pdu-1/callflow?limit=100")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_no_identity_material(&body);
        assert!(body["data"]["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty()));
        assert!(body["data"]["accounting"]["source_events"].is_number());
    }
    #[tokio::test]
    async fn lte_evidence_import_requires_operator_and_csrf() {
        // Exercise the strict outer adapter shape supported alongside the
        // direct request returned by POLARIS 0.28.1.
        let body = serde_json::to_vec(&lte_polaris_import_envelope()).unwrap();
        let unauthenticated = router(state(), None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/lte/evidence/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(unauthenticated).await["error"]["code"],
            "OPERATOR_REQUIRED"
        );

        let missing_csrf = router(operator_state(), None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/lte/evidence/import")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(missing_csrf).await["error"]["code"],
            "CSRF_REQUIRED"
        );

        let export_unauthenticated = router(state(), None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/lte/evidence/lte-run-synthetic-0001/exports")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"export_id":"export-synthetic-01","transformation":"VERIFIED_COPY"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(export_unauthenticated.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(export_unauthenticated).await["error"]["code"],
            "OPERATOR_REQUIRED"
        );
    }

    #[tokio::test]
    async fn lte_evidence_view_routes_are_bounded_and_do_not_fabricate_missing_runs() {
        let app = router(state(), None);
        let missing = app
            .clone()
            .oneshot(req("/api/v1/lte/evidence/lte-run-missing-0001", false))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let invalid_page = app
            .oneshot(req(
                "/api/v1/lte/evidence/lte-run-missing-0001/sessions?page=1&page_size=101",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(invalid_page.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            json_body(invalid_page).await["error"]["code"],
            "LTE_PAGINATION_INVALID"
        );
    }
    #[tokio::test]
    async fn health_reports_real_dataset() {
        let r = router(state(), None)
            .oneshot(req("/api/v1/health", true))
            .await
            .unwrap();
        let v = json_body(r).await;
        // 2.7.18: `source_events` sums `flow.accounting.source_events` across
        // every generated callflow, including the 2.7.16 projection from the
        // live capture manager. With the regenerated dataset it lands at 76.
        assert_eq!(v["data"]["source_events"], 76);
        assert_eq!(v["data"]["capabilities"]["live_capture"], true);
        assert_eq!(v["data"]["capabilities"]["capture_control"], false)
    }

    /// 2.21.30 (ordre #9 6952054201) — `/health` expose la quarantaine
    /// persistante des segments en échec de décodage. Clé opérateur :
    /// `data.quarantined_segments.count` + `data.quarantined_segments.items[]`
    /// avec `(source_path, source_size_bytes, source_sha256, error_code,
    /// quarantined_epoch_ms)`.
    ///
    /// Isolation : construit un `AppState` avec un `capture_root`
    /// temporaire, pour que les autres tests (qui partagent le
    /// workspace) ne polluent pas la quarantaine via disque.
    #[tokio::test]
    async fn health_surfaces_quarantined_segments() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut config = test_config(workspace, "health-quarantine");
        let capture_root = temporary_directory("health-quarantine-captures");
        config.capture_root = capture_root.clone();
        let st = AppState::load(config).unwrap();

        // Sans quarantaine : le bloc est présent mais vide.
        let app = router(st.clone(), None);
        let body = json_body(
            app.clone()
                .oneshot(req("/api/v1/health", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(body["data"]["quarantined_segments"]["count"], 0);
        assert_eq!(
            body["data"]["quarantined_segments"]["items"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        // Quarantinons un segment via l'API publique du gestionnaire.
        let path = "/tmp/synthetic-n2-seg-0001.pcap";
        let size = 1_048_576u64;
        let sha = "a".repeat(64);
        assert!(st.inner.capture_manager.quarantine_segment(
            path,
            size,
            &sha,
            "CONTINUOUS_SEGMENT_DECODE_FAILED: SYNTHETIC",
            1_792_500_000_000,
        ));

        let body = json_body(
            app.oneshot(req("/api/v1/health", true)).await.unwrap(),
        )
        .await;
        assert_eq!(body["data"]["quarantined_segments"]["count"], 1);
        let items = body["data"]["quarantined_segments"]["items"]
            .as_array()
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["source_path"], path);
        assert_eq!(items[0]["source_size_bytes"], size);
        assert_eq!(items[0]["source_sha256"], sha);
        assert_eq!(
            items[0]["error_code"],
            "CONTINUOUS_SEGMENT_DECODE_FAILED: SYNTHETIC"
        );
        assert_eq!(items[0]["quarantined_epoch_ms"], 1_792_500_000_000u64);
    }

    #[tokio::test]
    async fn health_session_count_matches_unfiltered_sessions_union() {
        let app = router(state(), None);
        let health = json_body(
            app.clone()
                .oneshot(req("/api/v1/health", false))
                .await
                .unwrap(),
        )
        .await;
        let sessions = json_body(
            app.oneshot(req("/api/v1/sessions?page_size=100", false))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(health["data"]["session_count"], sessions["meta"]["total"]);
        assert_eq!(
            health["data"]["queryable_session_count"],
            sessions["meta"]["total"]
        );
        assert!(health["data"].get("published_session_count").is_some());
    }

    #[tokio::test]
    async fn version_reports_installed_lte_and_5g_decoders() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/version", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        // 2.7.17: verify the binary reports exactly the Cargo-declared
        // version. No literal here — ANR2 refused 2.7.16 because this
        // assertion still read "2.7.15" after the package bump.
        assert_eq!(value["data"]["backend_api"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["data"]["platform_core"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["data"]["backend_api"], value["data"]["platform_core"]);
        assert_eq!(
            value["data"]["web_frontend"],
            env!("OIRAN_WEB_FRONTEND_VERSION")
        );
        for protocol in [
            "S1AP",
            "NAS-EPS-MM",
            "NAS-EPS-SM",
            "GTPv2-C",
            "GTP-U",
            "NGAP",
            "NAS-5GMM",
            "NAS-5GSM",
            "PFCP",
            "SBI-HTTP2",
        ] {
            assert!(
                value["data"]["decoders"][protocol].is_string(),
                "missing installed decoder {protocol}"
            );
        }
        // 2.14.7 (ANR1 #10) : le patcher à la lecture est exposé dans
        // `/api/v1/version` pour que la gate ANR1 constate qu'il est
        // bien actif. `callflows_loaded` doit être > 0 dès qu'au moins
        // un callflow a été chargé.
        let patch = &value["data"]["read_time_patch"];
        assert_eq!(patch["version"], read_time_patch::PATCH_VERSION);
        assert!(
            patch["callflows_loaded"].as_u64().unwrap_or(0) > 0,
            "read_time_patch.callflows_loaded must be > 0 after reference dataset load"
        );
        assert!(patch["events_seen"].as_u64().is_some());
        assert!(patch["events_patched"]["source_participant"]
            .as_u64()
            .is_some());
        assert!(patch["events_patched"]["destination_participant"]
            .as_u64()
            .is_some());
        assert!(patch["events_patched"]["direction"].as_u64().is_some());
        assert!(patch["events_patched"]["message_name"].as_u64().is_some());
        assert!(patch["events_unresolved_participant"].as_u64().is_some());
        assert!(patch["events_without_raw_counterpart"].as_u64().is_some());
    }

    /// 2.14.7 (ANR1 #10) — E2E HTTP contre une fixture S1-MME
    /// synthétique représentant exactement un callflow stocké par
    /// l'ingestion 2.14.3 (participants « Unknown endpoint »,
    /// direction via fallback procedureCode, message_name mal
    /// mappés). L'API est lancée via `AppState::load` puis une
    /// requête `GET /api/v1/sessions/<id>/events` doit renvoyer la
    /// version corrigée des événements. Prouve que le patcher à la
    /// lecture est effectivement branché sur la route servie, pas
    /// seulement fonctionnellement correct (cf. gate prod ANR1 où
    /// 2.14.5 prouvait les fonctions mais pas la route).
    #[tokio::test]
    async fn read_time_patch_rewrites_s1_mme_stale_fields_on_sessions_events_route() {
        use std::io::Write as _;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dataset_name = format!("read-time-patch-s1mme-{suffix}");
        let dataset_dir = workspace.join("datasets").join(&dataset_name);
        fs::create_dir_all(&dataset_dir).unwrap();
        // 5 événements synthétiques imitant une capture S1-MME 2.14.3 :
        // participants null, port 36412 côté MME / 46859 côté eNB,
        // message_type porteur de l'info brute (procedureCode S1AP ou
        // NAS EMM type).
        let raw_event = |id: &str,
                         parent: Option<&str>,
                         protocol: &str,
                         decoder: &str,
                         message_type: u32,
                         procedure_code: u32,
                         packet: u64,
                         from_enb: bool| {
            let (src, dst, src_port, dst_port) = if from_enb {
                ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
            } else {
                ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
            };
            json!({
                "event_id":id,
                "parent_event_id":parent,
                "capture_id":"sha256:stub","capture_point_id":"S1-MME",
                "timestamp":{"seconds":packet as i64,"nanoseconds":0u64,"raw_ticks":packet,"display":""},
                "interface":"S1-MME","protocol":protocol,
                "message_name":"stale","message_type":message_type,"procedure_code":procedure_code,
                "source_endpoint":{"address":src,"port":src_port,"network_function":null},
                "destination_endpoint":{"address":dst,"port":dst_port,"network_function":null},
                "direction":"UNKNOWN","session_identifiers":[],"information_elements":[],
                "decoding_status":"DECODED","decoder_name":decoder,"decoder_version":"0.2.2",
                "raw_payload_reference":"sha256:stub",
                "packet_references":[{"source_file":"synthetic.pcap","packet_number":packet,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
                "errors":[],
            })
        };
        let raw_events = vec![
            raw_event("evt-01", None, "S1AP", "decoder-s1ap", 0, 12, 23, true),
            raw_event(
                "evt-02",
                Some("evt-01"),
                "NAS-EPS-MM",
                "decoder-nas",
                0x41,
                65,
                23,
                true,
            ),
            raw_event("evt-03", None, "S1AP", "decoder-s1ap", 0, 11, 24, false),
            raw_event(
                "evt-04",
                Some("evt-03"),
                "NAS-EPS-MM",
                "decoder-nas",
                0x5d,
                93,
                24,
                false,
            ),
            raw_event("evt-05", None, "S1AP", "decoder-s1ap", 0, 22, 31, true),
        ];
        let mut jsonl = fs::File::create(dataset_dir.join("oiran_events.jsonl")).unwrap();
        for event in &raw_events {
            writeln!(jsonl, "{}", serde_json::to_string(event).unwrap()).unwrap();
        }
        drop(jsonl);
        // scenario_manifest.json minimal (le loader exige au moins
        // `scenario_id` et `captures` non vide).
        // Fichier capture fictif (le loader vérifie sa présence via
        // `fs::metadata`).
        fs::write(dataset_dir.join("synthetic.pcap"), b"\0").unwrap();
        fs::write(
            dataset_dir.join("scenario_manifest.json"),
            json!({
                "scenario_id":"synthetic-s1mme-read-time-patch",
                "captures":[{
                    "file":"synthetic.pcap",
                    "capture_id":"sha256:stub",
                    "name":"synthetic.pcap",
                    "interface":"S1-MME",
                    "sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "packet_count":5,
                    "size_bytes":1
                }]
            })
            .to_string(),
        )
        .unwrap();
        // callflow.json : participants « Unknown endpoint », directions
        // 2.14.3 (fallback procedureCode), libellés 2.14.3 (Security
        // Mode Complete au lieu de Command, UnknownS1APProcedure au
        // lieu de UECapabilityInfoIndication).
        let callflow = json!({
            "callflow_id":"cf-s1mme-stale",
            "session_id":"session-s1mme-stale",
            "technology":"LTE",
            "start_timestamp":"","end_timestamp":"",
            "participants":[],
            "interfaces":["S1-MME"],
            "procedures":[],
            "events":[
                {"event_id":"evt-01","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"InitialUEMessage","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"RAN_TO_CORE","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"S1 Setup","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-02","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"NAS-EPS-MM","message_name":"Attach Request","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"UNKNOWN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"EPS_ATTACH","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-nas","decoder_version":"0.4.0","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-03","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"DownlinkNASTransport","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"CORE_TO_RAN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"NAS Transport","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-04","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"NAS-EPS-MM","message_name":"Security Mode Complete","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"UNKNOWN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"EPS_SECURITY_MODE","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-nas","decoder_version":"0.4.0","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-05","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"UnknownS1APProcedure","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"RAN_TO_CORE","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"S1 Setup","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]}
            ],
            "correlation_edges":[],
            "correlation_status":{},
            "decoder_versions":{"decoder-s1ap":"0.2.2","decoder-nas":"0.4.0"},
            "schema_version":"1.5.0",
            "capture_references":["sha256:stub"],
            "accounting":{"source_events":5,"session_events":5,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields":0
        });
        let callflow_json_path = dataset_dir.join("callflow.json");
        fs::write(
            &callflow_json_path,
            serde_json::to_vec_pretty(&callflow).unwrap(),
        )
        .unwrap();
        // Config pointée sur la fixture.
        let mut config = test_config(workspace, &format!("registry-{dataset_name}"));
        config.dataset_dir = dataset_dir.clone();
        config.callflow_json = callflow_json_path;
        config.callflow_html = dataset_dir.join("callflow.html");
        fs::write(&config.callflow_html, b"<html>stub</html>").unwrap();

        let state = AppState::load(config).expect("AppState::load succeeds on synthetic fixture");
        let response = router(state.clone(), None)
            .oneshot(req("/api/v1/sessions/session-s1mme-stale/events", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let events = body["data"].as_array().expect("events array");
        assert_eq!(events.len(), 5, "fixture a 5 événements");

        // 1. Participants eNB/MME.
        assert_eq!(events[0]["source_participant"], "eNB");
        assert_eq!(events[0]["destination_participant"], "MME");
        assert_eq!(events[2]["source_participant"], "MME");
        assert_eq!(events[2]["destination_participant"], "eNB");

        // 2. msg04 = Security Mode Command (le 0x5D de TS 24.301), combiné.
        assert_eq!(
            events[3]["message_name"],
            "downlinkNASTransport · Security Mode Command"
        );
        // 3. msg09-like → UECapabilityInfoIndication.
        assert_eq!(events[4]["message_name"], "UECapabilityInfoIndication");

        // 4. Provenance read_time_patch sur chaque événement patché.
        for event in events {
            assert!(
                event.get("read_time_patch").is_some(),
                "read_time_patch missing for {}",
                event["event_id"]
            );
            // 2.14.8 (ANR1 #10) : la version est lue depuis
            // CARGO_PKG_VERSION pour suivre chaque bump du package
            // sans mise à jour manuelle du test.
            assert_eq!(
                event["read_time_patch"]["version"],
                read_time_patch::PATCH_VERSION
            );
        }

        // 5. Compteurs exposés dans /api/v1/version.
        let version = json_body(
            router(state, None)
                .oneshot(req("/api/v1/version", true))
                .await
                .unwrap(),
        )
        .await;
        let patch = &version["data"]["read_time_patch"];
        assert_eq!(patch["version"], read_time_patch::PATCH_VERSION);
        assert!(patch["callflows_loaded"].as_u64().unwrap() >= 1);
        assert!(
            patch["events_patched"]["source_participant"]
                .as_u64()
                .unwrap()
                >= 5
        );
        assert!(patch["events_patched"]["message_name"].as_u64().unwrap() >= 3);

        fs::remove_dir_all(&dataset_dir).ok();
    }

    /// 2.14.8 (ANR1 #10) — E2E HTTP contre une fixture au format
    /// **continuous** (chemin B de la prod ANR1) : `CaptureManager`
    /// avec un `CONTINUOUS_CAPTURE_ID` dataset recovered depuis le
    /// disque, `operational` mode (`reference_dataset_enabled=false`,
    /// `flow_values` vide à `AppState::load_operational`). Le callflow
    /// est servi par `capture_manager.callflow(...)` à chaque
    /// requête via `live_flow_for` / `live_session_summary` — le
    /// chemin exact que 2.14.7 ne couvrait pas (gate prod fail).
    ///
    /// Vérifie que :
    /// 1. GET `/api/v1/sessions/<id>/events` renvoie les événements
    ///    patchés en RAM (participants eNB/MME, msg04 = Security Mode
    ///    Command, msg05 = UECapabilityInfoIndication, provenance
    ///    `read_time_patch.version == CARGO_PKG_VERSION`).
    /// 2. GET `/api/v1/sessions` renvoie un `serving_ran_node = "eNB …"`
    ///    et un `core_node = "MME 10.77.10.10"` recalculés depuis les
    ///    participants patchés.
    /// 3. Le fichier `callflow-generations/generation-…/<id>.json`
    ///    reste BYTE-IDENTIQUE avant / après l'appel HTTP (SHA-256
    ///    identique). Preuve que le patcher n'a rien écrit sur disque.
    /// 4. Les compteurs `/api/v1/version.read_time_patch.*` reflètent
    ///    les événements patchés.
    #[tokio::test]
    async fn read_time_patch_covers_continuous_path_b_without_disk_writes() {
        use live_probe::{CaptureManager, CONTINUOUS_CAPTURE_ID, CONTINUOUS_DATASET_ID};
        use std::io::Write as _;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let capture_root = workspace
            .join("runtime")
            .join(format!("api-read-time-patch-continuous-{suffix}"));
        let base = capture_root.join(CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        let generation_name = format!("generation-{}-0", epoch_seconds());
        let callflows_dir = dataset_dir
            .join("callflow-generations")
            .join(&generation_name);
        let pcap_dir = base.join("pcap");
        fs::create_dir_all(&callflows_dir).unwrap();
        fs::create_dir_all(&pcap_dir).unwrap();

        // 5 raw NormalizedEvents en format « ingestion 2.14.3 »
        // (ports connus, NF=null, endpoint_map ne résolvait pas 10.77.10.*
        // avant 2.11.5).
        let raw_event = |id: &str,
                         parent: Option<&str>,
                         protocol: &str,
                         message_type: u32,
                         procedure_code: u32,
                         packet: u64,
                         from_enb: bool| {
            let (src, dst, src_port, dst_port) = if from_enb {
                ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
            } else {
                ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
            };
            json!({
                "event_id":id,"parent_event_id":parent,
                "capture_id":"sha256:stub","capture_point_id":"S1-MME",
                "timestamp":{"seconds":packet as i64,"nanoseconds":0u64,"raw_ticks":packet,"display":""},
                "interface":"S1-MME","protocol":protocol,
                "message_name":"stale","message_type":message_type,"procedure_code":procedure_code,
                "source_endpoint":{"address":src,"port":src_port,"network_function":null},
                "destination_endpoint":{"address":dst,"port":dst_port,"network_function":null},
                "direction":"UNKNOWN","session_identifiers":[],"information_elements":[],
                "decoding_status":"DECODED","decoder_name":"decoder-s1ap","decoder_version":"0.2.2",
                "raw_payload_reference":"sha256:stub",
                "packet_references":[{"source_file":"S1-MME.pcap-stub","packet_number":packet,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
                "errors":[],
            })
        };
        let raw_events = vec![
            raw_event("evt-01", None, "S1AP", 0, 12, 23, true),
            raw_event("evt-02", Some("evt-01"), "NAS-EPS-MM", 0x41, 65, 23, true),
            raw_event("evt-03", None, "S1AP", 0, 11, 24, false),
            raw_event("evt-04", Some("evt-03"), "NAS-EPS-MM", 0x5d, 93, 24, false),
            raw_event("evt-05", None, "S1AP", 0, 22, 31, true),
        ];
        let jsonl_path = dataset_dir.join("oiran_events.jsonl");
        let mut jsonl = fs::File::create(&jsonl_path).unwrap();
        for event in &raw_events {
            writeln!(jsonl, "{}", serde_json::to_string(event).unwrap()).unwrap();
        }
        drop(jsonl);

        // Callflow 2.14.3 stale persisté dans la génération active.
        let session_id = "lte-session-synthetic-continuous";
        let callflow = json!({
            "callflow_id":format!("cf-{session_id}"),
            "session_id":session_id,
            "technology":"LTE",
            "start_timestamp":"","end_timestamp":"",
            "participants":[],
            "interfaces":["S1-MME"],
            "procedures":[],
            "events":[
                {"event_id":"evt-01","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"InitialUEMessage","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"RAN_TO_CORE","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"S1 Setup","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-02","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"NAS-EPS-MM","message_name":"Attach Request","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"UNKNOWN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"EPS_ATTACH","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-nas","decoder_version":"0.4.0","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-03","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"DownlinkNASTransport","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"CORE_TO_RAN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"NAS Transport","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-04","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"NAS-EPS-MM","message_name":"Security Mode Complete","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"UNKNOWN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"EPS_SECURITY_MODE","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-nas","decoder_version":"0.4.0","raw_payload_reference":"sha256:stub","errors":[]},
                {"event_id":"evt-05","timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"UnknownS1APProcedure","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"RAN_TO_CORE","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"S1 Setup","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]}
            ],
            "correlation_edges":[],
            "correlation_status":{},
            "decoder_versions":{"decoder-s1ap":"0.2.2","decoder-nas":"0.4.0"},
            "schema_version":"1.5.0",
            "capture_references":["sha256:stub"],
            "accounting":{"source_events":5,"session_events":5,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields":0
        });
        let callflow_path = callflows_dir.join(format!("{session_id}.json"));
        fs::write(
            &callflow_path,
            serde_json::to_vec_pretty(&callflow).unwrap(),
        )
        .unwrap();
        fs::write(
            callflows_dir.join(format!("{session_id}.html")),
            b"<html>stub</html>",
        )
        .unwrap();
        // Manifest avec callflows_path pointant vers la génération.
        let manifest = json!({
            "dataset_id": CONTINUOUS_DATASET_ID,
            "capture_id": CONTINUOUS_CAPTURE_ID,
            "path": "runtime/live-captures/continuous-lab-import/dataset",
            "event_count": 5,
            "session_ids": [session_id],
            "decode_reports": {},
            "checksums": {},
            "state": "PARTIAL",
            "callflows_path": format!("callflow-generations/{generation_name}"),
        });
        let manifest_path = dataset_dir.join("dataset_manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // SHA-256 des artefacts callflow + manifest + jsonl AVANT.
        let before_sha = |path: &std::path::Path| sha256_hex(&fs::read(path).unwrap());
        let before_callflow = before_sha(&callflow_path);
        let before_manifest = before_sha(&manifest_path);
        let before_jsonl = before_sha(&jsonl_path);

        // Construction du CaptureManager en operational mode.
        let pseudonym_key_path = base.join(".oiran-pseudonym.key");
        let manager = CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            false,
            pseudonym_key_path,
        )
        .unwrap();
        manager
            .recover_continuous_dataset_from_disk(&base)
            .expect("recover continuous dataset from on-disk manifest");

        // AppState::load_with_capture_manager → mode operational :
        // flow_values vide, les sessions ne viennent QUE de
        // `capture_manager.datasets()`.
        let mut config = test_config(workspace, &format!("registry-continuous-b-{suffix}"));
        config.reference_dataset_enabled = false;
        config.capture_root = capture_root.clone();
        let state = AppState::load_with_capture_manager(config, manager).unwrap();

        // 2.14.11 (ANR1 #10 6860508699) — la construction de l'index
        // compact `event_id → byte offset` est faite en arrière-plan.
        // Première requête : déclenche le spawn et attend la ready
        // state (poll /version). Pour un dataset test (quelques
        // lignes), la construction est milliseconde-order.
        wait_for_compact_index_ready(&state, std::time::Duration::from_secs(10)).await;

        // Sanity : /sessions renvoie la session continue avec core_node
        // recalculé.
        let sessions = json_body(
            router(state.clone(), None)
                .oneshot(req("/api/v1/sessions?page_size=10", true))
                .await
                .unwrap(),
        )
        .await;
        let session = sessions["data"]
            .as_array()
            .expect("sessions array")
            .iter()
            .find(|item| item["session_id"] == session_id)
            .expect("continuous session served");
        assert_eq!(session["core_node"], "MME 10.77.10.10");
        assert_eq!(session["serving_ran_node"], "eNB 10.77.10.20");

        // GET /sessions/<id>/events → events patchés.
        let response = router(state.clone(), None)
            .oneshot(req(&format!("/api/v1/sessions/{session_id}/events"), true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let events = body["data"].as_array().expect("events array");
        assert_eq!(events.len(), 5);
        assert_eq!(events[0]["source_participant"], "eNB");
        assert_eq!(events[0]["destination_participant"], "MME");
        assert_eq!(events[2]["source_participant"], "MME");
        assert_eq!(
            events[3]["message_name"],
            "downlinkNASTransport · Security Mode Command"
        );
        assert_eq!(events[4]["message_name"], "UECapabilityInfoIndication");
        for event in events {
            assert!(
                event.get("read_time_patch").is_some(),
                "missing provenance on {}",
                event["event_id"]
            );
        }

        // Compteurs /api/v1/version.
        let version = json_body(
            router(state.clone(), None)
                .oneshot(req("/api/v1/version", true))
                .await
                .unwrap(),
        )
        .await;
        let patch = &version["data"]["read_time_patch"];
        assert_eq!(patch["version"], read_time_patch::PATCH_VERSION);
        assert!(
            patch["events_patched"]["source_participant"]
                .as_u64()
                .unwrap()
                >= 5
        );

        // Preuve zéro écriture : SHA-256 identiques avant / après HTTP.
        assert_eq!(
            before_callflow,
            before_sha(&callflow_path),
            "callflow.json must stay byte-identical on disk"
        );
        assert_eq!(before_manifest, before_sha(&manifest_path));
        assert_eq!(before_jsonl, before_sha(&jsonl_path));

        fs::remove_dir_all(&capture_root).ok();
    }

    /// 2.15.2 (ANR1 #10 6885876387) — test de régression du FAIL
    /// prod 2.15.0/2.15.1 : la `PFCP Session Establishment Request`
    /// type 50 (`evt-349c72dc0f5510c3`, `pfcp_sequence=2209`) est
    /// dans le shard JSONL de production mais ABSENTE du callflow
    /// persisté sur disque (continuous-lab-import). La Response
    /// (seq=2209) et la Modification (seq=2210) sont dans les
    /// deux. Le fix 2.15.0 pré-publication (`session_engine::
    /// expand_pfcp_session_members`) ne s'applique qu'au chemin
    /// in-memory et ne rattrape pas les callflows déjà écrits.
    ///
    /// Ce test monte un dataset `continuous-lab-import` fidèle au
    /// chemin prod (CaptureManager + manifest + callflow
    /// persisté qui ne contient QUE Response + Modification) et
    /// vérifie que `GET /api/v1/sessions/<id>/events?protocol=PFCP`
    /// renvoie désormais les **3 events** (Request + Response +
    /// Modification), avec `read_time_patch.index.ready=true` au
    /// moment de la requête.
    #[tokio::test]
    async fn prod_pfcp_request_type_50_appears_in_events_even_when_absent_from_callflow() {
        use live_probe::{CaptureManager, CONTINUOUS_CAPTURE_ID, CONTINUOUS_DATASET_ID};
        use std::io::Write as _;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let capture_root_guard = AutoRemoveDir::new(
            workspace
                .join("runtime")
                .join(format!("api-prod-pfcp-request-{suffix}")),
        );
        let capture_root = capture_root_guard.as_pathbuf();
        let base = capture_root.join(CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        let generation_name = format!("generation-{}-0", epoch_seconds());
        let callflows_dir = dataset_dir
            .join("callflow-generations")
            .join(&generation_name);
        let pcap_dir = base.join("pcap");
        fs::create_dir_all(&callflows_dir).unwrap();
        fs::create_dir_all(&pcap_dir).unwrap();

        // 3 events PFCP raw (fidèles au payload ANR1 #10 6883006379).
        // Request type 50 dans le JSONL mais absente du callflow.
        let request_id = "evt-349c72dc0f5510c3";
        let response_id = "evt-104645ebe2174b02";
        let modif_id = "evt-aa1b0ac453b62fd9";
        let raw_request = json!({
            "event_id": request_id,
            "parent_event_id": null,
            "capture_id":"sha256:continuous",
            "capture_point_id":"N4",
            "timestamp":{"seconds":1794673477i64,"nanoseconds":113697742u64,"raw_ticks":1794673477113697742u64,"display":"1794673477.113697742Z"},
            "interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","message_type":50,"procedure_code":null,
            "source_endpoint":{"address":"10.77.23.12","port":8805u16,"network_function":"SMF"},
            "destination_endpoint":{"address":"10.77.23.13","port":8805u16,"network_function":"UPF"},
            "direction":"SMF_TO_UPF",
            "session_identifiers":[
                {"name":"pfcp_sequence","value":"2209","pseudonymized":false},
            ],
            "information_elements":[],
            "pfcp_sequence":"2209",
            "decoding_status":"DECODED","decoder_name":"decoder-pfcp","decoder_version":"0.3.0",
            "raw_payload_reference":"sha256:stub",
            "packet_references":[{"source_file":"N4.pcap-stub","packet_number":1u64,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
            "errors":[],
        });
        let raw_response = json!({
            "event_id": response_id,
            "parent_event_id": null,
            "capture_id":"sha256:continuous",
            "capture_point_id":"N4",
            "timestamp":{"seconds":1794673477i64,"nanoseconds":114281357u64,"raw_ticks":1794673477114281357u64,"display":"1794673477.114281357Z"},
            "interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Response","message_type":51,"procedure_code":null,
            "source_endpoint":{"address":"10.77.23.13","port":8805u16,"network_function":"UPF"},
            "destination_endpoint":{"address":"10.77.23.12","port":8805u16,"network_function":"SMF"},
            "direction":"UPF_TO_SMF",
            "session_identifiers":[
                {"name":"pfcp_sequence","value":"2209","pseudonymized":false},
                {"name":"f_seid","value":"0x0000000000000314","pseudonymized":false},
            ],
            "information_elements":[],
            "pfcp_sequence":"2209",
            "decoding_status":"DECODED","decoder_name":"decoder-pfcp","decoder_version":"0.3.0",
            "raw_payload_reference":"sha256:stub",
            "packet_references":[{"source_file":"N4.pcap-stub","packet_number":2u64,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
            "errors":[],
        });
        let raw_modif = json!({
            "event_id": modif_id,
            "parent_event_id": null,
            "capture_id":"sha256:continuous",
            "capture_point_id":"N4",
            "timestamp":{"seconds":1794673477i64,"nanoseconds":121578185u64,"raw_ticks":1794673477121578185u64,"display":"1794673477.121578185Z"},
            "interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Modification Request","message_type":52,"procedure_code":null,
            "source_endpoint":{"address":"10.77.23.12","port":8805u16,"network_function":"SMF"},
            "destination_endpoint":{"address":"10.77.23.13","port":8805u16,"network_function":"UPF"},
            "direction":"SMF_TO_UPF",
            "session_identifiers":[
                {"name":"pfcp_sequence","value":"2210","pseudonymized":false},
                {"name":"f_seid","value":"0x0000000000000314","pseudonymized":false},
            ],
            "information_elements":[],
            "pfcp_sequence":"2210",
            "decoding_status":"DECODED","decoder_name":"decoder-pfcp","decoder_version":"0.3.0",
            "raw_payload_reference":"sha256:stub",
            "packet_references":[{"source_file":"N4.pcap-stub","packet_number":3u64,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
            "errors":[],
        });
        // JSONL raw contient les 3.
        let jsonl_path = dataset_dir.join("oiran_events.jsonl");
        let mut jsonl = fs::File::create(&jsonl_path).unwrap();
        for event in [&raw_request, &raw_response, &raw_modif] {
            writeln!(jsonl, "{}", serde_json::to_string(event).unwrap()).unwrap();
        }
        drop(jsonl);

        // Callflow persisté ne contient QUE Response + Modification.
        // Shape alignée sur ANR1 (decoded_ie_tree avec pfcp_sequence/F-SEID).
        let session_id = "5g-session-c330d205adafa233";
        let flow_event = |event_id: &str,
                          message_name: &str,
                          direction: &str,
                          decoded_ie_tree: Value,
                          packet: u64| {
            json!({
                "event_id":event_id,"timestamp":"","timestamp_ns":"0","interface":"N4","protocol":"PFCP",
                "message_name":message_name,"source_participant":"SMF","destination_participant":"UPF","direction":direction,
                "decoded_ie_tree":decoded_ie_tree,"decoding_status":"DECODED","semantic_status":"EXACT",
                "association":"SESSION","procedure_group":"PFCP Session",
                "packet_references":[{"source_file":"N4.pcap-stub","packet_number":packet,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
                "capture_id":"sha256:continuous","decoder_name":"decoder-pfcp","decoder_version":"0.3.0",
                "raw_payload_reference":"sha256:stub","errors":[]
            })
        };
        let callflow = json!({
            "callflow_id":format!("cf-{session_id}"),
            "session_id":session_id,
            "technology":"5G SA",
            "start_timestamp":"","end_timestamp":"",
            "participants":[],
            "interfaces":["N4"],
            "procedures":[],
            "events":[
                flow_event(response_id, "PFCP Session Establishment Response", "UPF_TO_SMF", json!([{"name":"pfcp_sequence","value":"2209"},{"name":"F-SEID","value":"f_seid=0x0000000000000314,v4=true,ipv4=10.77.23.13"}]), 2),
                flow_event(modif_id, "PFCP Session Modification Request", "SMF_TO_UPF", json!([{"name":"pfcp_sequence","value":"2210"},{"name":"F-SEID","value":"f_seid=0x0000000000000314,v4=true,ipv4=10.77.23.13"}]), 3),
            ],
            "correlation_edges":[],
            "correlation_status":{},
            "decoder_versions":{"decoder-pfcp":"0.3.0"},
            "schema_version":"1.5.0",
            "capture_references":["sha256:continuous"],
            "accounting":{"source_events":2,"session_events":2,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields":0
        });
        fs::write(
            callflows_dir.join(format!("{session_id}.json")),
            serde_json::to_vec_pretty(&callflow).unwrap(),
        )
        .unwrap();
        fs::write(callflows_dir.join(format!("{session_id}.html")), b"<html/>").unwrap();

        let manifest = json!({
            "dataset_id": CONTINUOUS_DATASET_ID,
            "capture_id": CONTINUOUS_CAPTURE_ID,
            "path": "runtime/live-captures/continuous-lab-import/dataset",
            "event_count": 3,
            "session_ids": [session_id],
            "decode_reports": {},
            "checksums": {},
            "state": "PARTIAL",
            "callflows_path": format!("callflow-generations/{generation_name}"),
        });
        fs::write(
            dataset_dir.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // Construction du CaptureManager (operational mode).
        let pseudonym_key_path = base.join(".oiran-pseudonym.key");
        let manager = CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            false,
            pseudonym_key_path,
        )
        .unwrap();
        manager
            .recover_continuous_dataset_from_disk(&base)
            .expect("recover continuous dataset from on-disk manifest");

        let mut config = test_config(workspace, &format!("registry-pfcp-prod-{suffix}"));
        config.reference_dataset_enabled = false;
        config.capture_root = capture_root.clone();
        let state = AppState::load_with_capture_manager(config, manager).unwrap();

        // Attendre que l'index compact soit prêt (chemin prod :
        // read_time_patch index built in background).
        wait_for_compact_index_ready(&state, std::time::Duration::from_secs(10)).await;

        // Vérif pré-conditions : index.ready=true + capture_id visible.
        let version = json_body(
            router(state.clone(), None)
                .oneshot(req("/api/v1/version", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            version["data"]["read_time_patch"]["index"]["ready"], true,
            "index must be ready before we assert on /events"
        );

        // GET /sessions/<id>/events?protocol=PFCP — gate ANR1.
        let response = router(state.clone(), None)
            .oneshot(req(
                &format!("/api/v1/sessions/{session_id}/events?protocol=PFCP"),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let events = body["data"].as_array().expect("events array");

        // L'assertion qui OBLIGEAIT 2.15.0/2.15.1 à FAIL en prod.
        let event_ids: Vec<&str> = events
            .iter()
            .filter_map(|e| e.get("event_id").and_then(Value::as_str))
            .collect();
        assert!(
            event_ids.contains(&request_id),
            "PFCP Session Establishment Request {} must be present in /events even when absent \
             from the persisted callflow (seen in prod shard JSONL, same pfcp_sequence=2209 \
             as the Response). event_ids observed: {:?}",
            request_id,
            event_ids
        );
        assert_eq!(
            events.len(),
            3,
            "all 3 PFCP events must be served (Request + Response + Modification), got {} : {:?}",
            events.len(),
            event_ids
        );

        // Ordre canonique : Request (packet=1) avant Response (packet=2)
        // avant Modification (packet=3).
        assert_eq!(events[0]["event_id"], request_id);
        assert_eq!(events[1]["event_id"], response_id);
        assert_eq!(events[2]["event_id"], modif_id);

        // 2.21.64 — la route callflow enrichit elle aussi le JSON persisté.
        // Les compteurs de pagination doivent inclure le sibling PFCP ajouté
        // à la lecture, pas rester figés sur les deux events du fichier.
        let callflow_response = router(state.clone(), None)
            .oneshot(req(
                &format!("/api/v1/sessions/{session_id}/callflow?limit=256"),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(callflow_response.status(), StatusCode::OK);
        let callflow_body = json_body(callflow_response).await;
        assert_eq!(callflow_body["data"]["events"].as_array().unwrap().len(), 3);
        assert_eq!(callflow_body["data"]["pagination"]["returned_events"], 3);
        assert_eq!(callflow_body["data"]["pagination"]["total_events"], 3);
    }

    /// 2.15.2 (ANR1 #10 6885876387, D3) — test de régression du FAIL
    /// prod 2.15.0/2.15.1 : `/api/v1/sessions` renvoie `identities:null`
    /// pour une session continuous parce que `hydrate_identities` n'a
    /// jamais tourné sur ce chemin (vault vide). Le fix 2.15.2 ajoute
    /// un fallback `extract_identity_summary_from_items` qui lit les
    /// identités pseudonymisées (subscriber_pseudonym, tmsi_pseudonym,
    /// identity_pseudonym…) directement depuis les events déjà patchés.
    ///
    /// Setup identique au test D6 : dataset continuous reconstitué
    /// à partir d'un `oiran_events.jsonl` + manifest + callflow
    /// persisté. Les events du callflow (shape ANR1) portent les
    /// identifiers NAS normalement produits par `decoder-nas`
    /// (`subscriber_pseudonym`, `tmsi_pseudonym`, `identity_pseudonym`
    /// + `eps_mobile_type_code=3` pour IMEISV). Règle Sadok 2026-11-14
    /// respectée : aucune valeur IMSI/SUPI en clair dans ce chemin
    /// (pas de pcap/tshark en lecture ; clear-text réservé à
    /// `tshark_identities` côté `/sessions/:id/identities`).
    #[tokio::test]
    async fn prod_sessions_list_exposes_identities_from_items_when_vault_empty() {
        use live_probe::{CaptureManager, CONTINUOUS_CAPTURE_ID, CONTINUOUS_DATASET_ID};
        use std::io::Write as _;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let capture_root_guard = AutoRemoveDir::new(
            workspace
                .join("runtime")
                .join(format!("api-prod-d3-identities-{suffix}")),
        );
        let capture_root = capture_root_guard.as_pathbuf();
        let base = capture_root.join(CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        let generation_name = format!("generation-{}-0", epoch_seconds());
        let callflows_dir = dataset_dir
            .join("callflow-generations")
            .join(&generation_name);
        let pcap_dir = base.join("pcap");
        fs::create_dir_all(&callflows_dir).unwrap();
        fs::create_dir_all(&pcap_dir).unwrap();

        let session_id = "5g-session-c330d205adafa233";
        let subscriber_pseudo = "sha256-c330d205adafa233subscriber";
        let tmsi_pseudo = "sha256-tmsi-abcd1234";
        let imei_pseudo = "sha256-imei-ef5678";

        // Un event NAS 5G avec identifiers pseudonymisés (shape alignée
        // sur `decoded_tree_with_identifiers` : union de
        // `information_elements` et `identifiers`).
        let nas_event = json!({
            "event_id":"evt-nas-registration",
            "timestamp":"","timestamp_ns":"0","interface":"N1","protocol":"NAS-5GS-MM",
            "message_name":"Registration Request","source_participant":"UE","destination_participant":"AMF",
            "direction":"RAN_TO_CORE",
            "decoded_ie_tree":[
                {"name":"identity_pseudonym","value":imei_pseudo,"pseudonymized":true},
                {"name":"subscriber_pseudonym","value":subscriber_pseudo,"source":"session_identifiers","pseudonymized":true},
                {"name":"eps_mobile_type_code","value":"3","source":"session_identifiers","pseudonymized":false},
                {"name":"tmsi_pseudonym","value":tmsi_pseudo,"source":"session_identifiers","pseudonymized":true},
            ],
            "decoding_status":"DECODED","semantic_status":"EXACT",
            "association":"SESSION","procedure_group":"5GMM Registration",
            "packet_references":[{"source_file":"N1.pcap-stub","packet_number":1,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
            "capture_id":"sha256:continuous","decoder_name":"decoder-nas","decoder_version":"0.4.1",
            "raw_payload_reference":"sha256:stub","errors":[]
        });
        let callflow = json!({
            "callflow_id":format!("cf-{session_id}"),
            "session_id":session_id,
            "technology":"5G SA",
            "start_timestamp":"","end_timestamp":"",
            "participants":[],
            "interfaces":["N1"],
            "procedures":[],
            "events":[nas_event],
            "correlation_edges":[],
            "correlation_status":{},
            "decoder_versions":{"decoder-nas":"0.4.1"},
            "schema_version":"1.5.0",
            "capture_references":["sha256:continuous"],
            "accounting":{"source_events":1,"session_events":1,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields":0
        });
        fs::write(
            callflows_dir.join(format!("{session_id}.json")),
            serde_json::to_vec_pretty(&callflow).unwrap(),
        )
        .unwrap();
        fs::write(callflows_dir.join(format!("{session_id}.html")), b"<html/>").unwrap();

        // Un JSONL raw minimal (même event NAS) pour que le
        // read_time_patch index soit construit depuis un shard réel.
        let jsonl_path = dataset_dir.join("oiran_events.jsonl");
        let mut jsonl = fs::File::create(&jsonl_path).unwrap();
        let raw_event = json!({
            "event_id":"evt-nas-registration","parent_event_id":null,
            "capture_id":"sha256:continuous","capture_point_id":"N1",
            "timestamp":{"seconds":1794673477i64,"nanoseconds":0u64,"raw_ticks":1794673477000000000u64,"display":"1794673477.000000000Z"},
            "interface":"N1","protocol":"NAS-5GS-MM",
            "message_name":"Registration Request","message_type":65,"procedure_code":null,
            "source_endpoint":{"address":"10.77.1.1","port":0u16,"network_function":"UE"},
            "destination_endpoint":{"address":"10.77.1.2","port":0u16,"network_function":"AMF"},
            "direction":"RAN_TO_CORE",
            "session_identifiers":[
                {"name":"subscriber_pseudonym","value":subscriber_pseudo,"pseudonymized":true},
                {"name":"eps_mobile_type_code","value":"3","pseudonymized":false},
                {"name":"tmsi_pseudonym","value":tmsi_pseudo,"pseudonymized":true},
            ],
            "information_elements":[
                {"name":"identity_pseudonym","value":imei_pseudo,"pseudonymized":true},
            ],
            "decoding_status":"DECODED","decoder_name":"decoder-nas","decoder_version":"0.4.1",
            "raw_payload_reference":"sha256:stub",
            "packet_references":[{"source_file":"N1.pcap-stub","packet_number":1u64,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
            "errors":[],
        });
        writeln!(jsonl, "{}", serde_json::to_string(&raw_event).unwrap()).unwrap();
        drop(jsonl);

        let manifest = json!({
            "dataset_id": CONTINUOUS_DATASET_ID,
            "capture_id": CONTINUOUS_CAPTURE_ID,
            "path": "runtime/live-captures/continuous-lab-import/dataset",
            "event_count": 1,
            "session_ids": [session_id],
            "decode_reports": {},
            "checksums": {},
            "state": "PARTIAL",
            "callflows_path": format!("callflow-generations/{generation_name}"),
        });
        fs::write(
            dataset_dir.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let pseudonym_key_path = base.join(".oiran-pseudonym.key");
        let manager = CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            false,
            pseudonym_key_path,
        )
        .unwrap();
        manager
            .recover_continuous_dataset_from_disk(&base)
            .expect("recover continuous dataset from on-disk manifest");

        let mut config = test_config(workspace, &format!("registry-d3-prod-{suffix}"));
        config.reference_dataset_enabled = false;
        config.capture_root = capture_root.clone();
        let state = AppState::load_with_capture_manager(config, manager).unwrap();
        wait_for_compact_index_ready(&state, std::time::Duration::from_secs(10)).await;

        // 2.21.61 — la réponse chaude doit être strictement identique à la
        // réponse froide, et la première requête après préchauffage ne doit
        // reconstruire aucune ligne. Mutation : retirer
        // `prewarm_live_list_row_cache_locked` de la fonction de préchauffage
        // laisse le cache vide et rend les assertions suivantes rouges.
        let (cold_status, cold_filter) =
            post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(cold_status, StatusCode::OK);
        let cold_bytes = serde_json::to_vec(&cold_filter).unwrap();
        state.inner.list_row_cache.lock().unwrap().clear();
        state
            .inner
            .list_row_cache_builds
            .store(0, std::sync::atomic::Ordering::SeqCst);
        {
            let _gate = state.inner.capture_manager.heavy_memory_enter();
            prewarm_session_filter_caches_locked(&state, "test");
        }
        let builds_after_prewarm = state
            .inner
            .list_row_cache_builds
            .load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(builds_after_prewarm, 1, "prewarm must build the fixture row");
        assert_eq!(state.inner.list_row_cache.lock().unwrap().len(), 1);
        let (warm_status, warm_filter) =
            post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(warm_status, StatusCode::OK);
        assert_eq!(
            serde_json::to_vec(&warm_filter).unwrap(),
            cold_bytes,
            "prewarmed page must be byte-for-byte equivalent to the cold page"
        );
        assert_eq!(
            state
                .inner
                .list_row_cache_builds
                .load(std::sync::atomic::Ordering::SeqCst),
            builds_after_prewarm,
            "first filter request rebuilt a prewarmed list row"
        );

        // Pré-condition : vault VIDE pour cette session (reproduction
        // fidèle du cas prod).
        let vault_observations = state.inner.identity_vault.for_session(session_id).unwrap();
        assert!(
            vault_observations.is_empty(),
            "vault doit être vide pour reproduire le FAIL prod 2.15.0/2.15.1"
        );

        // GET /api/v1/sessions — gate ANR1 : identities non null.
        let response = router(state.clone(), None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let items = body["data"].as_array().expect("sessions array");
        let session = items
            .iter()
            .find(|item| item["session_id"] == session_id)
            .expect("session présente dans /sessions");

        let identities = &session["identities"];
        assert!(
            !identities.is_null(),
            "identities doit être non null après le fix 2.15.2 (D3) : got {identities:?}"
        );
        assert_eq!(
            identities["subscriber_pseudonym"].as_str(),
            Some(subscriber_pseudo),
            "subscriber_pseudonym remonté depuis l'event event déjà patché"
        );
        assert_eq!(
            identities["imei"].as_str(),
            Some(imei_pseudo),
            "IMEI pseudo (identity_pseudonym + eps_mobile_type_code=3)"
        );
        let m_tmsi = identities["m_tmsi"].as_array().expect("m_tmsi array");
        assert!(
            m_tmsi.iter().any(|v| v.as_str() == Some(tmsi_pseudo)),
            "tmsi_pseudonym remonté dans m_tmsi, got {m_tmsi:?}"
        );
        // Règle Sadok 2026-11-14 : aucun clear-text IMSI via ce chemin.
        assert!(
            identities["imsi"].is_null(),
            "imsi doit rester null sans tshark/pcap (règle Sadok)"
        );
        assert!(
            identities["imsi_cleartext"].is_null(),
            "imsi_cleartext doit rester null sans tshark/pcap (règle Sadok)"
        );

        fs::remove_dir_all(&capture_root).ok();
    }

    /// 2.14.11 (ANR1 #10 6860508699) — test de CHARGE. Évolue le test
    /// 2.14.9 pour couvrir le nouvel index compact :
    ///
    /// 1. Génère un JSONL synthétique de taille configurable (≥ 3,4 GiB
    ///    par défaut, soit la taille observée en prod ANR1 ; override
    ///    via `OIRAN_READ_TIME_PATCH_LOAD_TEST_BYTES`).
    /// 2. Démarre `AppState`, qui déclenche la construction en
    ///    arrière-plan de l'index compact sur la première requête.
    /// 3. Attend `/api/v1/version.read_time_patch.index.ready == true`
    ///    avec un timeout de 180 s, en polling 100 ms.
    /// 4. Vérifie l'empreinte RAM via `/proc/self/status` (VmHWM) et
    ///    la taille de l'index (`index.bytes`).
    /// 5. Sert deux sessions, mesure la **latence totale** de chaque
    ///    requête SERVING. Assertion dure : `latency < 500 ms`.
    /// 6. Assertions finales :
    ///       - `VmHWM < 512 MiB` (même borne que 2.14.9).
    ///       - `index.bytes <= CompactJsonlIndex::MEMORY_BUDGET_BYTES`.
    ///       - `index.ready == true`.
    ///       - `index.entries > 0` et `build_ms > 0`.
    ///       - Chaque session sert 3 événements correctement patchés
    ///         (participants en {eNB, MME}).
    ///
    /// Marqué `#[ignore]` : coût disque + temps. Exécution :
    /// ```
    /// OIRAN_READ_TIME_PATCH_LOAD_TEST_BYTES=3600000000 \
    ///   cargo test --release -p oiran-api --lib -- --ignored \
    ///   read_time_patch_compact_index_bounded_and_fast_on_large_jsonl
    /// ```
    #[tokio::test]
    #[ignore = "load test: writes ≥3,4 GiB of synthetic JSONL, run explicitly with --ignored"]
    async fn read_time_patch_compact_index_bounded_and_fast_on_large_jsonl() {
        use std::io::Write as _;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let target_bytes: usize = std::env::var("OIRAN_READ_TIME_PATCH_LOAD_TEST_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(3_400_000_000);
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        // 2.14.11 — garde RAII : cleanup même en cas de panic.
        let capture_root_guard = AutoRemoveDir::new(
            workspace
                .join("runtime")
                .join(format!("api-read-time-patch-load-{suffix}")),
        );
        let capture_root = capture_root_guard.as_pathbuf();
        let base = capture_root.join(live_probe::CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        let generation_name = format!("generation-{}-0", epoch_seconds());
        let callflows_dir = dataset_dir
            .join("callflow-generations")
            .join(&generation_name);
        fs::create_dir_all(&callflows_dir).unwrap();
        fs::create_dir_all(base.join("pcap")).unwrap();

        // Génère 2 sessions ciblées (session-a / session-b), chacune
        // 5 événements au format raw 2.14.3. Puis padding JSONL avec
        // des événements "bruit" portant des event_id qui n'appartiennent
        // à aucune session, jusqu'à atteindre `target_bytes`. Le
        // patcher 2.14.9 doit ignorer tout le bruit à la lecture
        // streaming (extract_event_id puis skip).
        let jsonl_path = dataset_dir.join("oiran_events.jsonl");
        let jsonl_file = fs::File::create(&jsonl_path).unwrap();
        let mut writer = std::io::BufWriter::with_capacity(1024 * 1024, jsonl_file);
        let session_a_events = [
            (0u32, 12u32, 23u64, true), // initialUEMessage eNB→MME
            (0x41, 65, 23, true),       // NAS Attach Request
            (0, 11, 24, false),         // downlinkNASTransport MME→eNB
            (0x5d, 93, 24, false),      // NAS Security Mode Command
            (0, 22, 31, true),          // UECapabilityInfoIndication
        ];
        let session_b_events = [
            (0, 12, 101, true),
            (0x41, 65, 101, true),
            (0, 11, 102, false),
            (0x5d, 93, 102, false),
            (0, 22, 103, true),
        ];
        // 2.14.11 — padding stable pour que chaque ligne synthétique
        // approche la densité prod ANR1 (3 393 914 516 octets /
        // 1 554 682 lignes = 2 183 B/ligne). Sans ce padding, les
        // lignes synthétiques font ~800 B et on génère ~4 M entrées
        // au lieu de ~1,55 M pour 3,4 Go → l'empreinte de l'index
        // scale avec entries et dépasse la mesure attendue sur la
        // densité prod. Chiffre fixé à 1 400 : 800 + 1 400 ≈ 2 200 B.
        const PROD_DENSITY_PADDING: &str =
            "pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad-pad";
        assert!(
            PROD_DENSITY_PADDING.len() >= 1_400,
            "padding must be ≥ 1400 chars to approach prod density"
        );
        let write_event = |writer: &mut dyn std::io::Write,
                           id: &str,
                           parent: Option<&str>,
                           protocol: &str,
                           message_type: u32,
                           procedure_code: u32,
                           packet: u64,
                           from_enb: bool| {
            let (src, dst, src_port, dst_port) = if from_enb {
                ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
            } else {
                ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
            };
            let line = serde_json::json!({
                "event_id":id,"parent_event_id":parent,
                "capture_id":"sha256:stub","capture_point_id":"S1-MME",
                "timestamp":{"seconds":packet as i64,"nanoseconds":0u64,"raw_ticks":packet,"display":""},
                "interface":"S1-MME","protocol":protocol,
                "message_name":"stale","message_type":message_type,"procedure_code":procedure_code,
                "source_endpoint":{"address":src,"port":src_port,"network_function":null},
                "destination_endpoint":{"address":dst,"port":dst_port,"network_function":null},
                "direction":"UNKNOWN","session_identifiers":[],"information_elements":[],
                "decoding_status":"DECODED","decoder_name":"decoder-s1ap","decoder_version":"0.2.2",
                "raw_payload_reference":"sha256:stub",
                "packet_references":[{"source_file":"S1-MME.pcap-stub","packet_number":packet,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
                "errors":[],
                "padding": PROD_DENSITY_PADDING,
            });
            writeln!(writer, "{}", serde_json::to_string(&line).unwrap()).unwrap();
        };
        for (i, (mt, proc, pkt, from_enb)) in session_a_events.iter().enumerate() {
            let id = format!("evt-session-a-{i:02}");
            let parent = if i == 1 {
                Some("evt-session-a-00")
            } else if i == 3 {
                Some("evt-session-a-02")
            } else {
                None
            };
            let protocol = if *mt == 0 { "S1AP" } else { "NAS-EPS-MM" };
            write_event(
                &mut writer,
                &id,
                parent,
                protocol,
                *mt,
                *proc,
                *pkt,
                *from_enb,
            );
        }
        for (i, (mt, proc, pkt, from_enb)) in session_b_events.iter().enumerate() {
            let id = format!("evt-session-b-{i:02}");
            let parent = if i == 1 {
                Some("evt-session-b-00")
            } else if i == 3 {
                Some("evt-session-b-02")
            } else {
                None
            };
            let protocol = if *mt == 0 { "S1AP" } else { "NAS-EPS-MM" };
            write_event(
                &mut writer,
                &id,
                parent,
                protocol,
                *mt,
                *proc,
                *pkt,
                *from_enb,
            );
        }
        // Padding bruyant : événements dont `event_id` n'appartient
        // à aucune session demandée (préfixe `evt-noise-`), donc
        // ignorés par `extract_event_id` + `wanted.contains`.
        let mut noise_bytes = 0usize;
        let mut noise_idx = 0u64;
        while noise_bytes < target_bytes {
            let id = format!("evt-noise-{noise_idx:010}");
            noise_idx += 1;
            let batch_start = noise_idx;
            // Batch de 4 kio pour limiter le coût des calls syscall ;
            // on vérifie la taille tous les 1 024 événements.
            for _ in 0..1024 {
                let id = format!("evt-noise-{noise_idx:010}");
                noise_idx += 1;
                write_event(&mut writer, &id, None, "S1AP", 0, 15, 42, true);
            }
            let _ = batch_start;
            noise_bytes = fs::metadata(&jsonl_path)
                .map(|m| m.len() as usize)
                .unwrap_or(0);
            if noise_bytes == 0 {
                writer.flush().unwrap();
                noise_bytes = fs::metadata(&jsonl_path)
                    .map(|m| m.len() as usize)
                    .unwrap_or(0);
            }
        }
        writer.flush().unwrap();
        drop(writer);
        let jsonl_size = fs::metadata(&jsonl_path).unwrap().len();
        assert!(
            jsonl_size as usize >= target_bytes,
            "JSONL synthetic size {} < target {}",
            jsonl_size,
            target_bytes
        );

        // Callflow 2.14.3 stale pour chaque session.
        let stale_callflow = |session_id: &str, event_prefix: &str| {
            serde_json::json!({
                "callflow_id":format!("cf-{session_id}"),"session_id":session_id,"technology":"LTE",
                "start_timestamp":"","end_timestamp":"",
                "participants":[],"interfaces":["S1-MME"],"procedures":[],
                "events":[
                    {"event_id":format!("{event_prefix}-00"),"timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"InitialUEMessage","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"RAN_TO_CORE","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"S1 Setup","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]},
                    {"event_id":format!("{event_prefix}-03"),"timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"NAS-EPS-MM","message_name":"Security Mode Complete","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"UNKNOWN","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"EPS_SECURITY_MODE","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-nas","decoder_version":"0.4.0","raw_payload_reference":"sha256:stub","errors":[]},
                    {"event_id":format!("{event_prefix}-04"),"timestamp":"","timestamp_ns":"0","interface":"S1-MME","protocol":"S1AP","message_name":"UnknownS1APProcedure","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint","direction":"RAN_TO_CORE","decoded_ie_tree":[],"decoding_status":"DECODED","semantic_status":"EXACT","association":"SESSION","procedure_group":"S1 Setup","packet_references":[],"capture_id":"sha256:stub","decoder_name":"decoder-s1ap","decoder_version":"0.2.2","raw_payload_reference":"sha256:stub","errors":[]}
                ],
                "correlation_edges":[],"correlation_status":{},"decoder_versions":{"decoder-s1ap":"0.2.2","decoder-nas":"0.4.0"},
                "schema_version":"1.5.0","capture_references":["sha256:stub"],
                "accounting":{"source_events":3,"session_events":3,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
                "unresolved_fields":0
            })
        };
        for (session_id, prefix) in [
            ("lte-session-load-a", "evt-session-a"),
            ("lte-session-load-b", "evt-session-b"),
        ] {
            let path = callflows_dir.join(format!("{session_id}.json"));
            fs::write(
                &path,
                serde_json::to_vec_pretty(&stale_callflow(session_id, prefix)).unwrap(),
            )
            .unwrap();
            fs::write(callflows_dir.join(format!("{session_id}.html")), b"<html/>").unwrap();
        }

        let manifest = serde_json::json!({
            "dataset_id": live_probe::CONTINUOUS_DATASET_ID,
            "capture_id": live_probe::CONTINUOUS_CAPTURE_ID,
            "path": "runtime/live-captures/continuous-lab-import/dataset",
            "event_count": 10,
            "session_ids": ["lte-session-load-a", "lte-session-load-b"],
            "decode_reports": {},
            "checksums": {},
            "state": "PARTIAL",
            "callflows_path": format!("callflow-generations/{generation_name}"),
        });
        fs::write(
            dataset_dir.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // VmHWM AVANT.
        let vmhwm = || -> usize {
            let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:") {
                    let kib: usize = rest
                        .trim()
                        .split_whitespace()
                        .next()
                        .unwrap_or("0")
                        .parse()
                        .unwrap_or(0);
                    return kib * 1024;
                }
            }
            0
        };
        let before = vmhwm();

        // Construit le manager et la state.
        let pseudonym_key_path = base.join(".oiran-pseudonym.key");
        let manager = live_probe::CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            false,
            pseudonym_key_path,
        )
        .unwrap();
        manager
            .recover_continuous_dataset_from_disk(&base)
            .expect("recover dataset");
        let mut config = test_config(workspace, &format!("registry-load-{suffix}"));
        config.reference_dataset_enabled = false;
        config.capture_root = capture_root.clone();
        let state = AppState::load_with_capture_manager(config, manager).unwrap();

        // Première requête : déclenche la construction en arrière-plan
        // de l'index compact (spawn tokio). La réponse est servie
        // SANS correction tant que `index.ready == false` ; le handler
        // marque `meta.read_time_patch.status = "index_building"`.
        let trigger_response = router(state.clone(), None)
            .oneshot(req("/api/v1/sessions/lte-session-load-a/events", true))
            .await
            .unwrap();
        assert_eq!(trigger_response.status(), StatusCode::OK);
        let trigger_body = json_body(trigger_response).await;
        let status_at_trigger = trigger_body["meta"]["read_time_patch"]["status"]
            .as_str()
            .unwrap_or("");
        assert!(
            matches!(status_at_trigger, "index_building" | "applied"),
            "first request must expose explicit status, got {status_at_trigger:?}"
        );

        // Attend que l'index compact soit prêt (timeout 180 s, poll
        // 100 ms). ANR1 observait ~35 s pour 2 Go, soit ~60 s pour
        // 3,4 Go ; on laisse une marge 3×.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        let mut ready = false;
        let mut last_index_snapshot: Option<Value> = None;
        while std::time::Instant::now() < deadline {
            let version = json_body(
                router(state.clone(), None)
                    .oneshot(req("/api/v1/version", true))
                    .await
                    .unwrap(),
            )
            .await;
            let index = version["data"]["read_time_patch"]["index"].clone();
            if index["ready"].as_bool().unwrap_or(false) {
                last_index_snapshot = Some(index);
                ready = true;
                break;
            }
            last_index_snapshot = Some(index);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(
            ready,
            "compact index did not become ready within 180s; last snapshot={:?}",
            last_index_snapshot
        );
        let index = last_index_snapshot.expect("index snapshot captured");
        let index_entries = index["entries"].as_u64().unwrap_or(0);
        let index_bytes = index["bytes"].as_u64().unwrap_or(0);
        let index_build_ms = index["build_ms"].as_u64().unwrap_or(0);
        let index_last_offset = index["last_offset"].as_u64().unwrap_or(0);
        assert!(
            index_entries > 0,
            "index.entries must be > 0 after build, got {index_entries}"
        );
        // Spec ANR1 : ≤ 64 MiB pour 1,55 M entrées. Le padding
        // appliqué ci-dessus aligne la densité des lignes synthétiques
        // sur la densité prod (2 183 B/ligne), si bien que 3,4 Go de
        // JSONL donnent ~1,55 M entrées exactement. Assertion dure.
        assert!(
            index_bytes <= read_time_patch::CompactJsonlIndex::MEMORY_BUDGET_BYTES as u64,
            "index.bytes {} > budget {} MiB. Observed: {} entries, bytes/entry={:.2}. Spec: ≤ 64 MiB pour 1,55 M entrées à densité prod.",
            index_bytes,
            read_time_patch::CompactJsonlIndex::MEMORY_BUDGET_BYTES / 1024 / 1024,
            index_entries,
            index_bytes as f64 / index_entries as f64,
        );
        assert!(
            index_build_ms > 0,
            "index.build_ms must be set after build completes"
        );
        assert!(
            index_last_offset > 0,
            "index.last_offset must reflect bytes scanned"
        );
        eprintln!(
            "COMPACT_INDEX entries={} bytes_estimate={} MiB build_ms={} last_offset={} MiB jsonl_size={} MiB",
            index_entries,
            index_bytes / 1024 / 1024,
            index_build_ms,
            index_last_offset / 1024 / 1024,
            jsonl_size / 1024 / 1024,
        );

        // Sert les deux sessions via le patcher (chemin SERVING). Une
        // fois l'index prêt, chaque requête doit descendre sous 500 ms.
        for session_id in ["lte-session-load-a", "lte-session-load-b"] {
            let started = std::time::Instant::now();
            let response = router(state.clone(), None)
                .oneshot(req(&format!("/api/v1/sessions/{session_id}/events"), true))
                .await
                .unwrap();
            let elapsed = started.elapsed();
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            let status = body["meta"]["read_time_patch"]["status"]
                .as_str()
                .unwrap_or("");
            assert_eq!(
                status, "applied",
                "once ready, serving MUST apply the patch (session={session_id})"
            );
            let events = body["data"].as_array().expect("events array");
            assert_eq!(events.len(), 3, "callflow stub expose 3 events / session");
            for event in events {
                let src = event["source_participant"].as_str().unwrap_or("");
                let dst = event["destination_participant"].as_str().unwrap_or("");
                assert!(
                    (src == "eNB" && dst == "MME") || (src == "MME" && dst == "eNB"),
                    "event {} participants not patched: {} → {}",
                    event["event_id"],
                    src,
                    dst
                );
            }
            eprintln!(
                "SERVING session={session_id} latency_ms={} (budget=500 ms)",
                elapsed.as_millis()
            );
            assert!(
                elapsed < std::time::Duration::from_millis(500),
                "session {session_id} served in {} ms (budget 500 ms) — index seek should be < 500 ms sans cache",
                elapsed.as_millis()
            );
        }

        // VmHWM APRÈS. L'empreinte doit rester bornée malgré 3,4 GiB
        // de JSONL écrit : la map `hash(event_id) → byte_offset` fait
        // ~29 MiB pour 1,55 M entrées (mesure par test).
        let after = vmhwm();
        let threshold = 512usize * 1024 * 1024;
        eprintln!(
            "VmHWM before={} MiB, after={} MiB, threshold={} MiB, jsonl_size={} MiB",
            before / 1024 / 1024,
            after / 1024 / 1024,
            threshold / 1024 / 1024,
            jsonl_size / 1024 / 1024,
        );
        assert!(
            after < threshold,
            "VmHWM {} B exceeds 512 MiB threshold (jsonl size {} B)",
            after,
            jsonl_size,
        );

        // Cleanup explicite : `capture_root_guard` est aussi actif en
        // Drop pour couvrir les cas d'early return (panic).
        drop(capture_root_guard);
    }

    fn normalized_lte_event(
        id: &str,
        interface: &str,
        protocol: &str,
        name: &str,
        identifiers: &[(&str, &str)],
        packet: u64,
    ) -> Value {
        json!({
            "event_id": id,
            "capture_id": "sha256:synthetic-lte-api",
            "capture_point_id": format!("offline:{interface}"),
            "timestamp": {
                "seconds": 1_793_448_000_u64,
                "nanoseconds": packet,
                "raw_ticks": 1_793_448_000_000_000_000_u64 + packet,
                "display": format!("2026-10-31T12:00:00.{packet:09}Z")
            },
            "interface": interface,
            "protocol": protocol,
            "message_name": name,
            "source_endpoint": {
                "address": "192.0.2.10",
                "network_function": if interface == "S1-MME" { "eNB" } else { "SGW" }
            },
            "destination_endpoint": {
                "address": "192.0.2.20",
                "network_function": if interface == "S1-MME" { "MME" } else { "eNB" }
            },
            "direction": if interface == "S11" { "DOWNLINK" } else { "UPLINK" },
            "session_identifiers": identifiers.iter().map(|(key, value)| json!({
                "name": key,
                "value": value,
                "pseudonymized": key.contains("pseudonym")
            })).collect::<Vec<_>>(),
            "information_elements": [],
            "decoding_status": "DECODED",
            "decoder_name": protocol,
            "decoder_version": "synthetic-test",
            "raw_payload_reference": format!("sha256:{id}"),
            "packet_references": [{
                "source_file": "synthetic-offline.pcap",
                "packet_number": packet,
                "byte_offset": packet * 64,
                "interface_id": 0,
                "captured_length": 64,
                "original_length": 64
            }],
            "errors": []
        })
    }

    fn ingest_lte_evidence_fixture(state: &AppState, bundle: &FsPath) -> (String, String) {
        let planes = [
            ("S1_MME", "S1-MME", "S1AP", "E-RABSetupResponse"),
            ("S11", "S11", "GTPv2-C", "CreateSessionResponse"),
            ("S1_U", "S1-U", "GTP-U", "G-PDU"),
        ];
        ingest_lte_evidence_fixture_with_planes(state, bundle, &planes)
    }

    fn ingest_lte_evidence_fixture_with_planes(
        state: &AppState,
        bundle: &FsPath,
        planes: &[(&str, &str, &str, &str)],
    ) -> (String, String) {
        let mut capture_refs = Vec::new();
        let mut capture_bindings = Vec::new();
        let mut evidence_refs = Vec::new();
        for (index, (plane, interface, protocol, message)) in planes.iter().enumerate() {
            let source_file = format!("{}.pcapng", plane.to_ascii_lowercase());
            let source_bytes = format!("approved synthetic {plane}").into_bytes();
            fs::write(bundle.join(&source_file), &source_bytes).unwrap();
            let source_sha256 = sha256_hex(&source_bytes);
            let frame = (index + 1) as u64;
            let identifiers = match *plane {
                "S1_MME" => vec![
                    ("enb_ue_s1ap_id", "42"),
                    ("mme_ue_s1ap_id", "84"),
                    ("subscriber_pseudonym", "psn-lte-evidence-test"),
                    ("eps_bearer_identity", "5"),
                    ("erab_teid", "0x01020304"),
                ],
                "S11" => vec![
                    ("subscriber_pseudonym", "psn-lte-evidence-test"),
                    ("bearer_f_teid", "0x01020304"),
                ],
                "S1_U" => vec![("teid", "0x01020304")],
                _ => Vec::new(),
            };
            let mut event = normalized_lte_event(
                &format!("export-{plane}"),
                interface,
                protocol,
                message,
                &identifiers,
                frame,
            );
            // The admission contract consumes the normalized session-engine
            // EventRecord shape, not the richer public event-schema DTO used
            // by other API fixtures.
            event["parent_event_id"] = Value::Null;
            event["timestamp"] = Value::String(format!("2026-10-31T12:00:00.{frame:09}Z"));
            event["timestamp_ns"] = json!(1_793_448_000_000_000_000_u64 + frame);
            event["raw_ticks"] = json!(1_793_448_000_000_000_000_u64 + frame);
            event["source_address"] = Value::String("192.0.2.10".into());
            event["destination_address"] = Value::String("192.0.2.20".into());
            event["source_participant"] =
                Value::String(if *plane == "S1_MME" { "eNB" } else { "SGW" }.into());
            event["destination_participant"] =
                Value::String(if *plane == "S1_MME" { "MME" } else { "eNB" }.into());
            event["identifiers"] = json!(identifiers);
            event["source_json"] = json!({"schema_version":"1.5.0"});
            event["capture_id"] = Value::String(format!("sha256:{source_sha256}"));
            event["decoder_name"] = Value::String((*protocol).into());
            event["packet_references"][0]["source_file"] = Value::String(source_file.clone());
            let events_file = format!("{}.events.jsonl", plane.to_ascii_lowercase());
            let mut events_bytes = serde_json::to_vec(&event).unwrap();
            events_bytes.push(b'\n');
            fs::write(bundle.join(&events_file), &events_bytes).unwrap();
            let evidence_ref = format!("capture:{plane}");
            evidence_refs.push(evidence_ref.clone());
            capture_refs.push(json!({
                "plane":plane,
                "source_file_sha256":source_sha256,
                "decoder_version":"synthetic-test",
                "event_schema_version":"1.5.0",
                "first_frame":frame,
                "last_frame":frame,
                "sanitization_state":"SANITIZED_APPROVED"
            }));
            capture_bindings.push(json!({
                "evidence_ref":evidence_ref,
                "capture_ref_index":index,
                "source_file":source_file,
                "normalized_events_file":events_file,
                "normalized_events_sha256":sha256_hex(&events_bytes),
                "decoder_name":protocol,
                "decoder_version":"synthetic-test",
                "event_schema_version":"1.5.0",
                "endpoint_roles":{"192.0.2.10":"RAN","192.0.2.20":"CORE"}
            }));
        }
        let request: LteEvidenceImportRequest = serde_json::from_value(json!({
            "schema_version":"oiran.lte-evidence-ingestion.v1",
            "bundle_id":"bundle-api-export-01",
            "evidence":{
                "schema_version":"oiran-polaris.lte-e2e-evidence.v1",
                "run_id":"lte-run-api-export-0001",
                "profile_id":"LTE-SRSUE-TEST-01",
                "scenario_id":"lte-e2e-certification-v1",
                "started_at":"2026-10-31T12:00:00Z",
                "ended_at":"2026-10-31T12:00:10Z",
                "final_state":"COMPLETED",
                "steps":[{
                    "index":0,"type":"lte_attach","state":"COMPLETED",
                    "started_at":"2026-10-31T12:00:00Z",
                    "ended_at":"2026-10-31T12:00:10Z","reason_code":null,
                    "evidence_refs":evidence_refs,"measurements":{}
                }],
                "capture_refs":capture_refs,
                "cleanup":{"srsue_stopped":true,"srsenb_stopped":true,
                    "sidecars_removed":true,"epc_healthy":true,"dumpcaps_preserved":true}
            },
            "capture_bindings":capture_bindings
        }))
        .unwrap();
        let result = state
            .inner
            .lte_evidence_store
            .ingest(bundle, &request)
            .unwrap();
        let page = state
            .inner
            .lte_evidence_store
            .session_page(&request.evidence.run_id, 1, 10)
            .unwrap();
        (
            result.dataset_id,
            page["data"][0]["session_id"].as_str().unwrap().to_owned(),
        )
    }

    async fn assert_listed_events_resolve(app: &Router, session_id: &str) -> usize {
        let listed = app
            .clone()
            .oneshot(req(
                &format!("/api/v1/sessions/{session_id}/events?page=1&page_size=100"),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
        let listed = json_body(listed).await;
        let events = listed["data"].as_array().unwrap();
        assert!(!events.is_empty());
        for event in events {
            let event_id = event["event_id"].as_str().unwrap();
            for suffix in ["", "/provenance"] {
                let response = app
                    .clone()
                    .oneshot(req(&format!("/api/v1/events/{event_id}{suffix}"), false))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "listed event must resolve: session={session_id} event={event_id} suffix={suffix}"
                );
            }
        }
        events.len()
    }

    #[tokio::test]
    async fn every_listed_event_resolves_for_5g_full_lte_and_s1_only_lte() {
        let reference = state();
        let reference_session = reference.inner.primary_session_id.clone();
        assert!(
            assert_listed_events_resolve(&router(reference, None), &reference_session).await > 0
        );

        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut full_state =
            AppState::load(test_config(workspace, "event-index-full-lte")).unwrap();
        let full_bundle = temporary_directory("event-index-full-lte-bundle");
        let (_, full_session) = ingest_lte_evidence_fixture(&full_state, &full_bundle);
        assert!(
            assert_listed_events_resolve(&router(full_state.clone(), None), &full_session).await
                >= 3
        );

        let mut seven = full_state
            .inner
            .lte_evidence_store
            .callflow_for_export_by_session(&full_session)
            .unwrap()
            .unwrap();
        seven.session_id = "lte-seven-interface-test".into();
        for (index, interface) in ["S5-C", "S5-U", "Sxab", "S6a"].iter().enumerate() {
            let mut event = seven.events[0].clone();
            event.event_id = format!("lte-seven-extra-{index}");
            event.capture_id = format!("sha256:lte-seven-extra-{index}");
            event.interface = (*interface).into();
            event.protocol = match *interface {
                "S5-C" => "GTPv2-C",
                "S5-U" => "GTP-U",
                "Sxab" => "PFCP",
                _ => "Diameter",
            }
            .into();
            event.packet_references[0].packet_number = 10 + index as u64;
            seven.events.push(event);
        }
        seven.interfaces = ["S1-MME", "S11", "S1-U", "S5-C", "S5-U", "Sxab", "S6a"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        seven.accounting.session_events = seven.events.len();
        seven.accounting.source_events = seven.events.len();
        let seven_id = seven.session_id.clone();
        let seven_value = serde_json::to_value(&seven).unwrap();
        let inner = Arc::get_mut(&mut full_state.inner).unwrap();
        inner.flow_values.insert(seven_id.clone(), seven_value);
        inner.flows.insert(seven_id.clone(), seven);
        let full_app = router(full_state, None);
        let summary = json_body(
            full_app
                .clone()
                .oneshot(req(&format!("/api/v1/sessions/{seven_id}"), false))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            summary["data"]["summary"]["interfaces"]
                .as_array()
                .unwrap()
                .len(),
            7
        );
        assert_eq!(assert_listed_events_resolve(&full_app, &seven_id).await, 7);

        let mut single_state = state();
        let mut single = single_state.inner.flows.values().next().unwrap().clone();
        single.session_id = "lte-s1-only-test".into();
        single.technology = "LTE".into();
        single.events.truncate(1);
        single.events[0].event_id = "lte-s1-only-event".into();
        single.events[0].interface = "S1-MME".into();
        single.events[0].protocol = "S1AP".into();
        single.interfaces = vec!["S1-MME".into()];
        single.accounting.session_events = 1;
        single.accounting.source_events = 1;
        let single_session = single.session_id.clone();
        let single_value = serde_json::to_value(&single).unwrap();
        let inner = Arc::get_mut(&mut single_state.inner).unwrap();
        inner
            .flow_values
            .insert(single_session.clone(), single_value);
        inner.flows.insert(single_session.clone(), single);
        assert_eq!(
            assert_listed_events_resolve(&router(single_state, None), &single_session).await,
            1
        );
    }

    /// 2.21.21 — référence : l'ancien `packet_values` (tous les flows en mémoire).
    fn legacy_packet_values(state: &AppState) -> Vec<Value> {
        let mut packets = BTreeMap::<String, Value>::new();
        for flow in &queryable_flow_values(state) {
            for event in flow["events"].as_array().into_iter().flatten() {
                for reference in event["packet_references"].as_array().into_iter().flatten() {
                    packets
                        .entry(packet_id_for(event, reference))
                        .or_insert_with(|| packet_value_for(event, reference));
                }
            }
        }
        let mut values = packets.into_values().collect::<Vec<_>>();
        values.sort_by(|a, b| {
            a["capture_id"].as_str().cmp(&b["capture_id"].as_str())
                .then_with(|| a["packet_number"].as_u64().cmp(&b["packet_number"].as_u64()))
                .then_with(|| a["event_id"].as_str().cmp(&b["event_id"].as_str()))
        });
        values
    }

    #[test]
    fn packets_page_streams_flows_and_matches_legacy_materialized_listing() {
        let state = operator_state();
        let legacy = legacy_packet_values(&state);
        assert!(legacy.len() > 3, "reference dataset must expose packets");
        let mut query = ListQuery::default();
        query.page_size = Some(2);
        for page in 1..=legacy.len().div_ceil(2) {
            query.page = Some(page);
            let Json(value) = packets_page(&state, &query);
            assert_eq!(value["meta"]["total"].as_u64(), Some(legacy.len() as u64));
            let Json(expected) = paginated(legacy.clone(), &query);
            assert_eq!(value["data"], expected["data"], "page {page}");
        }
        let first = legacy[0].clone();
        query.page = Some(1);
        query.page_size = Some(100);
        query.capture_id = first["capture_id"].as_str().map(str::to_string);
        query.packet_number = first["packet_number"].as_u64();
        let Json(value) = packets_page(&state, &query);
        assert_eq!(value["data"][0]["packet_id"], first["packet_id"]);
        let found = find_packet(&state, |id, _, _| Some(id) == first["packet_id"].as_str())
            .expect("find_packet must resolve a listed packet");
        assert_eq!(found["event_id"], first["event_id"]);
    }

    #[tokio::test]
    async fn packet_dissect_resolves_a_listed_reference_and_classifies_failures() {
        let state = operator_state();
        let packet = find_packet(&state, |_, event, reference| {
            packet_source_path(&state, &packet_value_for(event, reference)).is_some()
        })
            .expect("reference dataset must expose a readable packet source");
        let capture_id = packet["capture_id"].as_str().unwrap();
        let packet_number = packet["packet_number"].as_u64().unwrap();
        let app = router(state, None);
        let operator_request = |uri: String| {
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, "Bearer test-operator-token")
                .body(Body::empty())
                .unwrap()
        };
        let resolved = app
            .clone()
            .oneshot(operator_request(format!(
                "/api/v1/packets/{capture_id}/{packet_number}/dissect"
            )))
            .await
            .unwrap();
        assert_eq!(resolved.status(), StatusCode::OK);

        let out_of_range = app
            .clone()
            .oneshot(operator_request(format!(
                "/api/v1/packets/{capture_id}/{}/dissect",
                u64::MAX
            )))
            .await
            .unwrap();
        assert_eq!(out_of_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            json_body(out_of_range).await["error"]["code"],
            "PACKET_OUT_OF_RANGE"
        );

        let unknown = app
            .oneshot(operator_request(
                "/api/v1/packets/sha256:unknown-capture/1/dissect".into(),
            ))
            .await
            .unwrap();
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json_body(unknown).await["error"]["code"],
            "CAPTURE_NOT_FOUND"
        );

        let mut missing_state = operator_state();
        let mut missing_flow = missing_state.inner.flows.values().next().unwrap().clone();
        missing_flow.session_id = "missing-source-session".into();
        missing_flow.events.truncate(1);
        missing_flow.events[0].event_id = "missing-source-event".into();
        missing_flow.events[0].capture_id = "sha256:missing-source-capture".into();
        missing_flow.events[0].packet_references.truncate(1);
        missing_flow.events[0].packet_references[0].packet_number = 7;
        missing_flow.events[0].packet_references[0].source_file =
            "captures/source-does-not-exist.pcapng".into();
        let missing_id = missing_flow.session_id.clone();
        let missing_value = serde_json::to_value(&missing_flow).unwrap();
        let inner = Arc::get_mut(&mut missing_state.inner).unwrap();
        inner.flow_values.insert(missing_id.clone(), missing_value);
        inner.flows.insert(missing_id, missing_flow);
        let missing = router(missing_state, None)
            .oneshot(operator_request(
                "/api/v1/packets/sha256:missing-source-capture/7/dissect".into(),
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            json_body(missing).await["error"]["code"],
            "CAPTURE_SOURCE_NOT_FOUND"
        );
    }

    #[tokio::test]
    async fn subscribers_include_lte_evidence_alongside_5g_flows() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let config = test_config(workspace, "subscriber-lte-evidence");
        let store_root = config.lte_evidence_root.clone();
        let state = AppState::load(config).unwrap();
        assert!(state
            .inner
            .flows
            .values()
            .any(|flow| flow.technology.contains("5G")));
        let bundle = temporary_directory("subscriber-lte-evidence-bundle");
        ingest_lte_evidence_fixture(&state, &bundle);

        let indexed = queryable_flows(&state);
        assert!(indexed.values().any(|flow| flow.technology == "LTE"));
        assert!(indexed.values().any(|flow| flow.technology.contains("5G")));

        let app = router(state, None);
        let subscribers = json_body(
            app.clone()
                .oneshot(req("/api/v1/subscribers?page_size=100", false))
                .await
                .unwrap(),
        )
        .await;
        assert!(subscribers["data"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()));
        assert!(subscribers["data"].as_array().unwrap().iter().any(|row| {
            row["technologies"]
                .as_array()
                .is_some_and(|values| values.iter().any(|value| value == "LTE"))
        }));

        let health = json_body(
            app.clone()
                .oneshot(req("/api/v1/health", false))
                .await
                .unwrap(),
        )
        .await;
        let sessions = json_body(
            app.oneshot(req("/api/v1/sessions?page_size=100", false))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(health["data"]["session_count"], sessions["meta"]["total"]);

        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn lte_evidence_sessions_and_callflow_exports_apply_privacy_boundary() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let config = test_config(workspace, "lte-export-privacy");
        let store_root = config.lte_evidence_root.clone();
        let state = AppState::load(config).unwrap();
        let bundle = temporary_directory("lte-export-bundle");
        let (dataset_id, session_id) = ingest_lte_evidence_fixture(&state, &bundle);

        // Simulate defense in depth against an already persisted, malformed
        // pseudonym. The read route must not rely only on admission-time checks.
        let sessions_path = store_root
            .join("datasets")
            .join(&dataset_id)
            .join("sessions.jsonl");
        let mut session: Value =
            serde_json::from_str(fs::read_to_string(&sessions_path).unwrap().trim()).unwrap();
        session["ue_pseudonym"] = Value::String("suci-opaque".into());
        fs::write(
            &sessions_path,
            format!("{}\n", serde_json::to_string(&session).unwrap()),
        )
        .unwrap();

        let app = router(state, None);
        let sessions = app
            .clone()
            .oneshot(req(
                "/api/v1/lte/evidence/lte-run-api-export-0001/sessions?page=1&page_size=10",
                false,
            ))
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions = json_body(sessions).await;
        assert_no_identity_material(&sessions);
        assert_eq!(sessions["data"][0]["ue_pseudonym"], "REDACTED");

        let json_export = app
            .clone()
            .oneshot(req(
                &format!("/api/v1/exports/callflow/{session_id}?format=json"),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(json_export.status(), StatusCode::OK);
        let json_export = json_body(json_export).await;
        assert_eq!(json_export["technology"], "LTE");
        assert_no_identity_material(&json_export);

        let html_export = app
            .oneshot(req(
                &format!("/api/v1/exports/callflow/{session_id}?format=html"),
                false,
            ))
            .await
            .unwrap();
        assert_eq!(html_export.status(), StatusCode::OK);
        let html = String::from_utf8(
            html_export
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let lower = html.to_ascii_lowercase();
        assert!(html.contains("E-RABSetupResponse"));
        for forbidden in ["suci-", "supi-", "guti", "tmsi", "imei", "opc"] {
            assert!(
                !lower.contains(forbidden),
                "identity material in HTML: {forbidden}"
            );
        }

        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn api_load_materialises_synthetic_lte_session_without_live_capture() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let source = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let dataset = workspace
            .join("runtime")
            .join(format!("api-lte-offline-{}", epoch_seconds()));
        fs::create_dir_all(&dataset).unwrap();
        for entry in fs::read_dir(&source).unwrap().filter_map(Result::ok) {
            if entry.path().is_file() {
                fs::copy(entry.path(), dataset.join(entry.file_name())).unwrap();
            }
        }
        let mut events = fs::OpenOptions::new()
            .append(true)
            .open(dataset.join("oiran_events.jsonl"))
            .unwrap();
        for value in [
            normalized_lte_event(
                "api-lte-s1ap",
                "S1-MME",
                "S1AP",
                "E-RABSetupResponse",
                &[
                    ("enb_ue_s1ap_id", "42"),
                    ("mme_ue_s1ap_id", "84"),
                    ("imsi_pseudonym", "lte-ue-anon-api"),
                    ("eps_bearer_identity", "5"),
                    ("erab_teid", "0x01020304"),
                ],
                101,
            ),
            normalized_lte_event(
                "api-lte-s11",
                "S11",
                "GTPv2-C",
                "CreateSessionResponse",
                &[
                    ("imsi_pseudonym", "lte-ue-anon-api"),
                    ("bearer_f_teid", "0x01020304"),
                ],
                102,
            ),
            normalized_lte_event(
                "api-lte-s1u",
                "S1-U",
                "GTP-U",
                "G-PDU",
                &[("teid", "0x01020304")],
                103,
            ),
        ] {
            writeln!(events, "{}", serde_json::to_string(&value).unwrap()).unwrap();
        }
        drop(events);
        let mut config = test_config(workspace, "registry-lte-offline");
        config.dataset_dir = dataset.clone();
        let state = AppState::load(config).unwrap();
        let lte = state
            .inner
            .flows
            .values()
            .find(|flow| flow.technology == "LTE")
            .unwrap();
        assert_eq!(lte.interfaces, vec!["S1-MME", "S1-U", "S11"]);
        assert_eq!(lte.correlation_status["E2E"], "STRONG");
        let response = router(state, None)
            .oneshot(req("/api/v1/sessions?technology=LTE", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["meta"]["total"], 1);
        assert_eq!(value["data"][0]["technology"], "LTE");
        assert!(value["data"][0]["ue_pseudonym"]
            .as_str()
            .unwrap()
            .starts_with("LTE-UE-"));
        fs::remove_dir_all(dataset).unwrap();
    }

    fn probe_payload(probe_id: &str) -> Value {
        json!({
            "probe_id": probe_id,
            "probe_type": "virtual",
            "name": "Lab probe",
            "host": "probe-host",
            "mgmt_ip": "192.0.2.10",
            "site": "lab-a",
            "interfaces": [{
                "interface": "eth0",
                "role": "N2",
                "bpf_filter": "sctp port 38412"
            }]
        })
    }

    fn create_probe_request(payload: Value) -> Request<Body> {
        let csrf = sha256_hex(b"oiran-csrf-v1:test-operator-token");
        Request::builder()
            .method("POST")
            .uri("/api/v1/probes")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-operator-token")
            .header(CSRF_HEADER, csrf)
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn probe_heartbeat_is_null_without_measured_liveness() {
        let value = json_body(
            router(state(), None)
                .oneshot(req("/api/v1/probes", true))
                .await
                .unwrap(),
        )
        .await;
        assert!(value["data"][0]["last_heartbeat_epoch_s"].is_null());
    }

    /// 2.9.3-fu1 (devmat #9) : le local vProbe était reporté `online=false`
    /// alors que `capture_state=CAPTURING` — parce que le calcul ne lisait
    /// que `last_heartbeat_epoch_s`, et sur un flux lent `last_packet_epoch_ms`
    /// peut dépasser la fenêtre 15 s. Avec `probe_is_reachable`, le local +
    /// capture active implique `online=true` par définition.
    #[test]
    fn probe_is_reachable_asserts_local_capturing_probe_online_regardless_of_heartbeat() {
        // local + active → online even with no heartbeat at all
        assert!(probe_is_reachable(true, true, None, 1000));
        // local + active → online even when the last heartbeat is ancient
        assert!(probe_is_reachable(true, true, Some(0), 1000));
        // local + inactive → fall back to heartbeat window (same as before)
        assert!(!probe_is_reachable(true, false, None, 1000));
        assert!(!probe_is_reachable(true, false, Some(0), 1000));
        assert!(probe_is_reachable(true, false, Some(990), 1000));
        // distant probe NEVER gets the local short-circuit — heartbeat only
        assert!(!probe_is_reachable(false, true, None, 1000));
        assert!(!probe_is_reachable(false, true, Some(0), 1000));
        assert!(probe_is_reachable(false, false, Some(990), 1000));
    }

    #[tokio::test]
    async fn probe_online_is_false_without_a_real_heartbeat() {
        let value = json_body(
            router(state(), None)
                .oneshot(req("/api/v1/probes", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(value["data"][0]["online"], false);
        assert_eq!(value["data"][0]["probe_state"], "PROBE_PENDING");
    }

    #[test]
    fn measured_heartbeat_outside_native_segment_window_is_not_online() {
        assert!(probe_online(Some(100), 115));
        assert!(!probe_online(Some(100), 116));
    }

    #[test]
    fn absent_capture_observation_serializes_as_null_not_fabricated_defaults() {
        let (interface_type, size_bytes) = capture_observation(None);
        let value = json!({"interface_type":interface_type,"size_bytes":size_bytes});
        assert!(value["interface_type"].is_null());
        assert!(value["size_bytes"].is_null());
    }

    #[tokio::test]
    async fn operator_can_create_a_persistent_pending_probe_in_a_private_registry() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let registry_root = temporary_directory("registry-persistence");
        let registry_path = registry_root.join("probes.json");
        let mut config = test_config(workspace, "registry-persistence");
        config.probe_registry_path = registry_path.clone();
        config.operator_token_sha256 = Some(sha256_hex(b"test-operator-token"));
        config.pseudonym_key_path =
            Some(temporary_directory("registry-persistence-pseudonym").join("pseudonym.key"));
        let state = AppState::load(config.clone()).unwrap();
        let response = router(state, None)
            .oneshot(create_probe_request(probe_payload("lab-probe-01")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let value = json_body(response).await;
        assert_eq!(value["data"]["probe_state"], "PROBE_PENDING");
        assert_eq!(value["data"]["online"], false);
        assert_eq!(
            fs::metadata(&registry_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let reloaded = AppState::load(config).unwrap();
        assert!(reloaded.inner.probe_registry.get("lab-probe-01").is_some());
    }

    #[tokio::test]
    async fn duplicate_probe_id_returns_conflict() {
        let app = router(operator_state(), None);
        assert_eq!(
            app.clone()
                .oneshot(create_probe_request(probe_payload("duplicate-probe")))
                .await
                .unwrap()
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            app.oneshot(create_probe_request(probe_payload("duplicate-probe")))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn invalid_probe_schema_returns_unprocessable_entity() {
        let response = router(operator_state(), None)
            .oneshot(create_probe_request(probe_payload("UP")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn probe_creation_requires_csrf_proof() {
        let response = router(operator_state(), None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/probes")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::from(
                        serde_json::to_vec(&probe_payload("csrf-probe")).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(response).await["error"]["code"], "CSRF_REQUIRED");
    }

    #[tokio::test]
    async fn probe_creation_requires_operator_role() {
        let response = router(state(), None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/probes")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&probe_payload("viewer-probe")).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await["error"]["code"],
            "OPERATOR_REQUIRED"
        );
    }

    #[tokio::test]
    async fn capture_interfaces_expose_registry_role_or_null() {
        let value = json_body(
            router(state(), None)
                .oneshot(req("/api/v1/interfaces", true))
                .await
                .unwrap(),
        )
        .await;
        let interfaces = value["data"].as_array().unwrap();
        assert_eq!(
            interfaces
                .iter()
                .find(|item| item["interface"] == "N2")
                .unwrap()["role"],
            "N2"
        );
        assert!(interfaces
            .iter()
            .find(|item| item["interface"] == "SBI")
            .unwrap()["role"]
            .is_null());
    }

    #[tokio::test]
    async fn raw_capture_download_is_forbidden_by_pending_policy() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/captures/any-id/download", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            json_body(response).await,
            json!({"error":"DOWNLOAD_POLICY_PENDING"})
        );
    }

    /// 2.14.6 (ANR1 #10) — ce test instancie un vrai thread d'import
    /// continu qui travaille sur `/tmp`. Sous une exécution `cargo test`
    /// non `--test-threads=1`, les autres tests parallèles de la suite
    /// peuvent saturer le pool d'I/O du runner et faire dériver le
    /// polling à 10 s (deadline historique, conservée telle quelle par
    /// ANR1). On sérialise ce test via un `std::sync::Mutex` statique
    /// contre lui-même et contre les futurs tests `continuous_*` de
    /// `apps/api`. L'échéance n'est PAS allongée (règle ANR1 : « pas
    /// d'augmentation d'échéance sans mesure »).
    ///
    /// L'échec au premier assert produit désormais un message
    /// diagnostique structuré : état observé (segments_ingested,
    /// job state), temps écoulé réel, nombre de scans effectués.
    #[tokio::test]
    async fn continuous_capture_state_and_incremental_sessions_are_truthful() {
        // Garde sérielle : tout autre test `continuous_*` ajouté à
        // `apps/api/src/lib.rs` doit acquérir ce même lock pour éviter
        // que les threads d'import continu ne se partagent le pool
        // d'I/O.
        static CONTINUOUS_TEST_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serial = CONTINUOUS_TEST_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let source = temporary_directory("collector");
        let capture_root = temporary_directory("captures");
        let fixture = workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        for interface in ["N2", "N3", "N4"] {
            let directory = source.join(interface);
            fs::create_dir_all(&directory).unwrap();
            fs::copy(
                fixture.join(format!("{interface}.pcapng")),
                directory.join("segment.pcapng"),
            )
            .unwrap();
        }
        // 2.8.3 (#9 comment 6696366882): a lone segment per interface is
        // the still-live dumpcap target under the closed-proof contract.
        // Prove closure via the rotation-watcher JSONL so the three
        // test segments become eligible.
        {
            use std::io::Write as _;
            let mut file = fs::File::create(source.join("capture-rotation.jsonl")).unwrap();
            for plane in ["n2", "n3", "n4"] {
                writeln!(
                    file,
                    r#"{{"timestamp":"2026-11-07T00:00:00Z","interface":"br-oiran-{plane}","plane":"{plane}","exit_code":0,"packets_captured":0,"packets_dropped":0}}"#
                )
                .unwrap();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        let mut config = test_config(workspace, "registry-continuous");
        config.capture_root = capture_root.clone();
        // 2.14.6 (ANR1 #10) : le worker d'import continu réévalue
        // `capture_budget(measure_path(&self.root), …)` à chaque segment
        // (`live-probe/src/lib.rs:3428`). Sans cet override, un runner
        // dont le disque dépasse 98 % (policy.stop_percent par défaut)
        // rend `CONTINUOUS_SEGMENT_PENDING_DISK_SAFETY` et le job
        // bascule en `Blocked` → `active_captures = 0` au lieu de 1.
        // On applique une politique permissive AVANT de confier le
        // manager à `AppState` (le thread spawné par
        // `start_continuous_import` lit `self.policy` à la clone).
        let permissive_continuous_policy = live_probe::disk_safety::Policy {
            information_percent: 100,
            warning_percent: 100,
            stop_percent: 100,
            hard_limit_percent: 100,
            max_file_bytes: 256 * 1024 * 1024,
            max_files: 8,
            max_job_seconds: 15 * 60,
            max_concurrent_jobs: 1,
            polling_interval_ms: 1_000,
            reserve_bytes: 0,
        };
        let mut manager = live_probe::CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            config.capture_execution_enabled,
            capture_root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        manager.set_policy_for_tests(permissive_continuous_policy);
        let state = AppState::load_with_capture_manager(config, manager).unwrap();
        state
            .inner
            .capture_manager
            .start_continuous_import(live_probe::ContinuousImportConfig {
                source_root: source,
                scan_interval: std::time::Duration::from_millis(200),
                stable_age: std::time::Duration::from_millis(200),
                max_owned_bytes: 128 * 1024 * 1024,
                max_segment_bytes: 64 * 1024 * 1024,
                max_segments: 8,
                native_segment_seconds: None,
                historical_n2_bootstrap: None,
                runtime_pdu_evidence: None,
                vtap_out_dirs: Vec::new(),
            })
            .unwrap();
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(10);
        let mut scans = 0u32;
        while state
            .inner
            .capture_manager
            .get(live_probe::CONTINUOUS_CAPTURE_ID)
            .is_some_and(|job| job.metrics.segments_ingested < 3)
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            scans += 1;
        }
        let final_job = state
            .inner
            .capture_manager
            .get(live_probe::CONTINUOUS_CAPTURE_ID);
        let final_segments_ingested = final_job
            .as_ref()
            .map(|job| job.metrics.segments_ingested)
            .unwrap_or_default();
        let final_state = final_job
            .as_ref()
            .map(|job| format!("{:?}", job.state))
            .unwrap_or_else(|| "JOB_MISSING".into());
        let elapsed_ms = started.elapsed().as_millis();
        let diag = move |expected: &'static str| -> String {
            format!(
                "continuous import diagnostic: {expected}; segments_ingested={final_segments_ingested} (expected ≥3); job state={final_state}; elapsed_ms={elapsed_ms} (deadline=10_000); scans_performed={scans}"
            )
        };
        let app = router(state.clone(), None);
        let metrics = json_body(
            app.clone()
                .oneshot(req("/api/v1/metrics", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            metrics["data"]["active_captures"],
            1,
            "{}",
            diag("active_captures != 1")
        );
        assert_eq!(metrics["data"]["active_sessions"], 0);
        assert_eq!(metrics["data"]["fresh_packet_count"], 0);
        assert_eq!(metrics["data"]["active_ue_ips"], json!([]));
        assert_eq!(metrics["data"]["segments_ingested"], 3);
        assert!(metrics["data"]["last_ingested_epoch_ms"].is_number());
        let probes = json_body(
            app.clone()
                .oneshot(req("/api/v1/probes", true))
                .await
                .unwrap(),
        )
        .await;
        assert!(probes["data"][0]["last_heartbeat_epoch_s"].is_number());
        assert_eq!(probes["data"][0]["online"], true);
        let sessions = json_body(
            app.oneshot(req("/api/v1/sessions?dataset_kind=CAPTURED_LIVE", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(sessions["meta"]["total"], 0);
        state
            .inner
            .capture_manager
            .stop(live_probe::CONTINUOUS_CAPTURE_ID, "operator")
            .unwrap();
    }
    #[tokio::test]
    async fn sessions_preserve_accounting() {
        let r = router(state(), None)
            .oneshot(req("/api/v1/sessions", true))
            .await
            .unwrap();
        let v = json_body(r).await;
        assert_eq!(v["data"][0]["message_count"], 26);
        assert_eq!(v["data"][0]["background_event_count"], 28);
        let decoded = v["data"][0]["decode_completeness"]["decoded"]
            .as_u64()
            .unwrap();
        let partial = v["data"][0]["decode_completeness"]["partial"]
            .as_u64()
            .unwrap();
        assert_eq!(decoded + partial, 26)
    }
    #[tokio::test]
    async fn event_pagination_and_filter_work() {
        let r = router(state(), None)
            .oneshot(req(
                "/api/v1/sessions/5g-UE-A-pdu-1/events?interface=N3&page_size=3",
                true,
            ))
            .await
            .unwrap();
        let v = json_body(r).await;
        assert_eq!(v["meta"]["total"], 10);
        assert_eq!(v["data"].as_array().unwrap().len(), 3)
    }
    #[tokio::test]
    async fn provenance_is_sanitized() {
        let fixture = state();
        let id = primary_flow(&fixture).unwrap().events[0].event_id.clone();
        let r = router(state(), None)
            .oneshot(req(&format!("/api/v1/events/{id}/provenance"), true))
            .await
            .unwrap();
        let v = json_body(r).await;
        assert!(v["data"]["packet_references"][0]["source_file"]
            .as_str()
            .unwrap()
            .starts_with("capture://"))
    }
    #[tokio::test]
    async fn correlations_are_exact_dataset_edges() {
        let r = router(state(), None)
            .oneshot(req("/api/v1/correlation/edges?page_size=100", true))
            .await
            .unwrap();
        let v = json_body(r).await;
        assert_eq!(v["meta"]["total"], 12)
    }
    #[tokio::test]
    async fn invalid_id_is_controlled() {
        assert_eq!(
            router(state(), None)
                .oneshot(req("/api/v1/sessions/not-real", true))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        )
    }
    #[tokio::test]
    async fn export_is_available_without_token() {
        let app = router(state(), None);
        assert_eq!(
            app.clone()
                .oneshot(req("/api/v1/exports/callflow/5g-UE-A-pdu-1", false))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.oneshot(req("/api/v1/exports/callflow/5g-UE-A-pdu-1", true))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        )
    }

    #[tokio::test]
    async fn derived_dataset_import_requires_operator_and_accepts_no_paths() {
        let body = || Body::from(r#"{"dataset_id":"derived-not-present"}"#);
        let viewer = Request::builder()
            .method("POST")
            .uri("/api/v1/datasets/import-derived")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body())
            .unwrap();
        assert_eq!(
            router(operator_state(), None)
                .oneshot(viewer)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let operator = Request::builder()
            .method("POST")
            .uri("/api/v1/datasets/import-derived")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-operator-token")
            .body(body())
            .unwrap();
        let response = router(operator_state(), None)
            .oneshot(operator)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let value = json_body(response).await;
        assert_eq!(value["error"]["message"], "DERIVED_IMPORT_SOURCE_NOT_FOUND");
    }

    #[tokio::test]
    async fn dataset_and_ue_registry_are_exposed() {
        let app = router(state(), None);
        let datasets = json_body(
            app.clone()
                .oneshot(req("/api/v1/datasets?page_size=100", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(datasets["meta"]["total"], 1);
        // 2.7.18: with the dataset regenerated via oiran-decode 0.6.0, the
        // on-wire counts are 24 N2 + 30 N4 + 10 N3 = 64 events; the
        // registry sums the per-flow accounting (primary + auto-generated
        // + session-engine reconstruction) at 76. pcapng packet counts are
        // unchanged (same captures).
        assert_eq!(datasets["data"][0]["event_count"], 76);
        assert_eq!(datasets["data"][0]["dataset_kind"], "HISTORICAL");
        assert_eq!(datasets["data"][0]["source"], "CERTIFIED_REFERENCE");
        assert_eq!(datasets["data"][0]["packet_count"], 78);
        // 2.7.18: discovery now yields the primary 5g-UE-A-pdu-1 plus one
        // auto-generated callflow for the PDU session re-discovered on the
        // regenerated events (different event_ids than the shipped callflow
        // JSON, so `represented` at apps/api/src/lib.rs:300-308 is false).
        assert_eq!(datasets["data"][0]["session_count"], 2);
        assert_eq!(datasets["data"][0]["session_ids"][0], "5g-UE-A-pdu-1");
        let ues = json_body(
            app.oneshot(req("/api/v1/ues?page_size=100", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(ues["meta"]["total"], 2);
    }

    #[tokio::test]
    async fn capture_context_resolves_exact_dataset_and_sessions() {
        let fixture = state();
        let capture_id = fixture.inner.captures[0]["capture_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let response = router(fixture, None)
            .oneshot(req(&format!("/api/v1/captures/{capture_id}/context"), true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(
            value["data"]["dataset"]["dataset_id"],
            "OIRAN_5G_PDU_SESSION_DATA_V1"
        );
        assert_eq!(value["data"]["resolution"], "SESSIONS_AVAILABLE");
        assert_eq!(value["data"]["session_ids"][0], "5g-UE-A-pdu-1");
        assert_eq!(
            value["data"]["capture"]["dataset_id"],
            "OIRAN_5G_PDU_SESSION_DATA_V1"
        );
    }

    #[tokio::test]
    async fn packet_provenance_filters_resolve_one_exact_packet() {
        let fixture = state();
        let event = primary_flow(&fixture)
            .unwrap()
            .events
            .iter()
            .find(|event| event.protocol == "GTP-U")
            .unwrap();
        let capture_id = event.capture_id.clone();
        let event_id = event.event_id.clone();
        let packet_number = event.packet_references[0].packet_number;
        let response = router(fixture, None)
            .oneshot(req(
                &format!(
                    "/api/v1/packets?capture_id={}&event_id={}&packet_number={}",
                    capture_id, event_id, packet_number
                ),
                true,
            ))
            .await
            .unwrap();
        let value = json_body(response).await;
        assert_eq!(value["meta"]["total"], 1);
        assert_eq!(value["data"][0]["event_id"], event_id);
        assert_eq!(value["data"][0]["packet_number"], packet_number);
    }

    #[tokio::test]
    async fn disk_safety_is_measured_and_capture_remains_unconfigured() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/storage/safety", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert!(value["data"]["filesystem"]["total_bytes"].as_u64().unwrap() > 0);
        assert_eq!(value["data"]["capture_job"]["active"], false);
        assert_eq!(value["data"]["capture_job"]["writes_enabled"], false);
        assert_eq!(value["data"]["policy"]["information_percent"], 95);
        assert_eq!(value["data"]["policy"]["warning_percent"], 97);
        assert_eq!(value["data"]["policy"]["stop_percent"], 98);
        assert_eq!(value["data"]["policy"]["hard_limit_percent"], 98);
        assert_eq!(
            value["data"]["policy"]["reserve_bytes"],
            8 * 1024 * 1024 * 1024_u64
        );
    }

    #[tokio::test]
    async fn procedures_are_scoped_to_requested_session() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/sessions/5g-UE-A-pdu-1/procedures", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["data"].as_array().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn multiple_callflows_remain_independently_addressable() {
        let mut fixture = state();
        let inner = Arc::get_mut(&mut fixture.inner).unwrap();
        let mut second = inner.flows[&inner.primary_session_id].clone();
        second.session_id = "5g-UE-B-pdu-2".into();
        second.callflow_id = "callflow-5g-UE-B-pdu-2".into();
        for event in &mut second.events {
            event.event_id.push_str("-b");
        }
        let mut second_context = inner.discovery.ue_contexts[0].clone();
        second_context.context_id = "uectx-b".into();
        second_context.pseudonym = "UE-B".into();
        second_context.ran_ue_ngap_id = Some("44".into());
        second_context.amf_ue_ngap_id = Some("144".into());
        second_context.event_ids = second
            .events
            .iter()
            .map(|event| event.event_id.clone())
            .collect();
        let mut second_discovered = inner.discovery.pdu_sessions[0].clone();
        second_discovered.session_id = second.session_id.clone();
        second_discovered.ue_context_id = second_context.context_id.clone();
        second_discovered.pdu_session_id = "2".into();
        second_discovered.event_ids = second_context.event_ids.clone();
        inner.discovery.ue_contexts.push(second_context);
        inner.discovery.pdu_sessions.push(second_discovered);
        let second_value = serde_json::to_value(&second).unwrap();
        inner.flows.insert(second.session_id.clone(), second);
        inner
            .flow_values
            .insert("5g-UE-B-pdu-2".into(), second_value);
        let app = router(fixture, None);
        let listed = json_body(
            app.clone()
                .oneshot(req("/api/v1/sessions?page_size=100", true))
                .await
                .unwrap(),
        )
        .await;
        // 2.7.18: with the regenerated oiran_events.jsonl the PDU session
        // discovered from the events no longer exactly maps to the primary
        // callflow.json (different event_ids — events are keyed by the probe
        // ephemeral HMAC which rotated when we re-decoded), so an extra
        // auto-generated callflow appears on top of the shipped primary. The
        // test adds a THIRD synthetic flow, so total=3.
        assert_eq!(listed["meta"]["total"], 3);
        let second_summary = listed["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|summary| summary["session_id"] == "5g-UE-B-pdu-2")
            .unwrap();
        assert_eq!(second_summary["ue_context_id"], "uectx-b");
        assert_eq!(second_summary["pdu_session_id"], "2");
        let page_two = json_body(
            app.clone()
                .oneshot(req(
                    "/api/v1/sessions?page=2&page_size=1&sort=session_id&order=asc&dataset_kind=HISTORICAL",
                    true,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(page_two["meta"]["total"], 3);
        assert_eq!(page_two["meta"]["total_pages"], 3);
        assert_eq!(page_two["data"].as_array().unwrap().len(), 1);
        let unrelated = json_body(
            app.clone()
                .oneshot(req(
                    "/api/v1/sessions?dataset_id=not-the-selected-dataset",
                    true,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(unrelated["meta"]["total"], 0);
        let flow = json_body(
            app.oneshot(req("/api/v1/sessions/5g-UE-B-pdu-2/callflow", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(flow["data"]["session_id"], "5g-UE-B-pdu-2");
    }

    #[tokio::test]
    async fn callflow_route_pages_persisted_events_with_a_bounded_cursor_contract() {
        let app = router(state(), None);
        let first_response = app
            .clone()
            .oneshot(req("/api/v1/sessions/5g-UE-A-pdu-1/callflow?limit=7", true))
            .await
            .unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
        let first = json_body(first_response).await;
        assert_eq!(first["data"]["events"].as_array().unwrap().len(), 7);
        assert_eq!(first["data"]["pagination"]["limit"], 7);
        assert_eq!(first["data"]["pagination"]["total_events"], 54);
        let cursor = first["data"]["pagination"]["next_cursor"]
            .as_str()
            .unwrap()
            .to_owned();
        let first_event = first["data"]["events"][0]["event_id"]
            .as_str()
            .unwrap()
            .to_owned();

        let second = json_body(
            app.clone()
                .oneshot(req(
                    &format!("/api/v1/sessions/5g-UE-A-pdu-1/callflow?limit=7&cursor={cursor}"),
                    true,
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(second["data"]["events"].as_array().unwrap().len(), 7);
        assert_ne!(second["data"]["events"][0]["event_id"], first_event);

        let invalid_cursor = app
            .clone()
            .oneshot(req(
                "/api/v1/sessions/5g-UE-A-pdu-1/callflow?limit=7&cursor=missing-event",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(invalid_cursor.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(invalid_cursor).await["error"]["code"],
            "CALLFLOW_CURSOR_INVALID"
        );

        let oversized = app
            .oneshot(req(
                "/api/v1/sessions/5g-UE-A-pdu-1/callflow?limit=257",
                true,
            ))
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            json_body(oversized).await["error"]["code"],
            "CALLFLOW_LIMIT_INVALID"
        );
    }

    #[tokio::test]
    async fn v2_metrics_are_truthful_about_live_telemetry() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/metrics", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["data"]["mode"], "HISTORICAL_DATASET_ANALYSIS");
        assert_eq!(value["data"]["active_captures"], 0);
        assert_eq!(value["data"]["active_sessions"], 0);
        assert!(value["data"]["packet_rate_pps"].is_null());
        assert_eq!(value["data"]["closed_not_ingested_segments"], 0);
        // 2.7.18: `historical_events` is the per-flow accounting sum, 76 in
        // the regenerated dataset. 64 is the on-wire event count.
        assert_eq!(value["data"]["historical_events"], 76);
    }

    /// 2.9.0 (#9): the dataset list omits the heavy `decode_reports`
    /// and `checksums` payloads so the 3-second poll stops shipping
    /// ~727 KB (503 KB + 204 KB on the ANR2 production probe) on every
    /// tick. The full view remains available at `/datasets/{id}`.
    #[tokio::test]
    async fn datasets_list_is_lightweight_and_full_view_stays_on_single_endpoint() {
        let app = router(state(), None);
        let list = app
            .clone()
            .oneshot(req("/api/v1/datasets", true))
            .await
            .unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let value = json_body(list).await;
        let items = value["data"].as_array().expect("dataset list");
        assert!(!items.is_empty(), "sample dataset must be registered");
        for item in items {
            let object = item.as_object().unwrap();
            assert!(
                !object.contains_key("decode_reports"),
                "list view must not carry decode_reports; got {object:?}"
            );
            assert!(
                !object.contains_key("checksums"),
                "list view must not carry checksums; got {object:?}"
            );
            assert!(
                !object.contains_key("active_pdu_contexts"),
                "list view must not carry active_pdu_contexts; got {object:?}"
            );
        }
        // The full view is still reachable per id for every item in the
        // list (synthetic captures, the registry sample, etc).
        let first_id = items[0]["dataset_id"].as_str().unwrap();
        let single = app
            .clone()
            .oneshot(req(&format!("/api/v1/datasets/{first_id}"), true))
            .await
            .unwrap();
        assert_eq!(single.status(), StatusCode::OK);
        let full = json_body(single).await;
        let body = full["data"].as_object().unwrap();
        // Captured-live datasets keep `decode_reports`/`checksums`
        // objects; the historical sample exposes them as the empty
        // object. Either way the key MUST be present on the single-id
        // route.
        if first_id.starts_with("ue-")
            || first_id.starts_with("derived-")
            || first_id.starts_with("recovered-dataset-")
        {
            assert!(body.contains_key("decode_reports"));
            assert!(body.contains_key("checksums"));
        }
    }

    /// 2.9.0 (#9): the list endpoint emits a weak ETag derived from
    /// the response body hash. A subsequent request carrying
    /// `If-None-Match: <etag>` must receive a 304 Not Modified with
    /// the ETag echoed back and no body — kills the 3 s dataset poll
    /// cost once the view is stable.
    #[tokio::test]
    async fn datasets_list_etag_short_circuits_an_unchanged_poll_with_304() {
        let app = router(state(), None);
        let first = app
            .clone()
            .oneshot(req("/api/v1/datasets", true))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let etag = first
            .headers()
            .get(header::ETAG)
            .expect("ETag on datasets list")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(etag.starts_with("W/\""), "weak ETag expected, got {etag}");
        let revalidate = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/datasets")
                    .header(header::IF_NONE_MATCH, &etag)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revalidate.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            revalidate
                .headers()
                .get(header::ETAG)
                .unwrap()
                .to_str()
                .unwrap(),
            etag,
            "304 must echo the current ETag so the client can keep it"
        );
        assert_eq!(
            revalidate
                .headers()
                .get(header::CACHE_CONTROL)
                .unwrap()
                .to_str()
                .unwrap(),
            "private, no-cache"
        );
        let body = revalidate.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty(), "304 response must have an empty body");
    }

    #[tokio::test]
    async fn v2_packets_preserve_event_and_capture_provenance() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/packets?interface=N3&page_size=100", true))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = json_body(response).await;
        assert_eq!(value["meta"]["total"], 10);
        let packet = &value["data"][0];
        assert!(packet["packet_id"].as_str().unwrap().starts_with("pkt-"));
        assert!(packet["event_id"].as_str().is_some_and(|id| !id.is_empty()));
        assert!(packet["source_file"]
            .as_str()
            .unwrap()
            .starts_with("capture://"));
        assert_eq!(packet["raw_bytes"], "RESTRICTED_NOT_STORED_IN_EVENT_MODEL");
    }

    #[tokio::test]
    async fn live_capture_control_requires_operator_and_execution_gate() {
        let app = router(state(), None);
        let payload = serde_json::to_vec(&CaptureRequest::default()).unwrap();
        let validate = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/captures/validate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(payload.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(validate.status(), StatusCode::FORBIDDEN);

        let authorized = router(operator_state(), None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/captures/validate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::from(payload))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authorized.status(), StatusCode::OK);
        let value = json_body(authorized).await;
        assert_eq!(value["data"]["validation"]["valid"], false);
        assert!(value["data"]["validation"]["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "CAPTURE_EXECUTION_NOT_ENABLED"));

        let start = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/captures/start")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&CaptureRequest::default()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(start.status(), StatusCode::FORBIDDEN);
        assert_eq!(json_body(start).await["error"]["code"], "OPERATOR_REQUIRED");
    }

    /// 2.14.6 (ANR1 #10) — variante déterministe du test
    /// `four_plane_validate_traverses_http_api_and_unix_ipc` : utilise
    /// `InterfaceProbe` injectable et `set_disk_sample_override_for_tests`
    /// pour couper toute dépendance à l'environnement (ponts réseau,
    /// taux de remplissage du disque local). Doit passer partout, en
    /// uid 1001 comme en uid 0, en parallèle comme en sériel.
    #[tokio::test]
    async fn four_plane_validate_traverses_http_api_and_unix_ipc_without_acquisition_unit() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!("{}-{}", std::process::id(), epoch_seconds());
        let manager_root = workspace
            .join("runtime")
            .join(format!("api-four-plane-unit-{suffix}"));
        let helper_root = std::env::temp_dir().join(format!("oiran-four-plane-unit-{suffix}"));
        let interface_root = helper_root.join("interfaces");
        for interface in [
            InterfaceId::N2,
            InterfaceId::Sbi,
            InterfaceId::N4,
            InterfaceId::N3,
        ] {
            fs::create_dir_all(interface_root.join(interface.device())).unwrap();
        }
        let socket = helper_root.join("capture-helper.sock");
        let permissive_server_policy = Policy {
            information_percent: 100,
            warning_percent: 100,
            stop_percent: 100,
            hard_limit_percent: 100,
            max_file_bytes: 256 * 1024 * 1024,
            max_files: 8,
            max_job_seconds: 15 * 60,
            max_concurrent_jobs: 1,
            polling_interval_ms: 1_000,
            reserve_bytes: 0,
        };
        let service = CaptureService::new(
            ServerConfig {
                socket_path: socket.clone(),
                capture_root: helper_root.join("captures"),
                interface_root: interface_root.clone(),
                allowed_client_uid: unsafe { libc::geteuid() },
                allowed_client_gid: Some(unsafe { libc::getegid() }),
                socket_gid: None,
                policy: permissive_server_policy,
            },
            ValidationOnlyBackend,
        )
        .unwrap();
        let listener = service.bind().unwrap();
        let server = service.clone();
        let helper_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server.handle_stream(stream).unwrap();
        });

        // Politique test : tous les seuils de sûreté disque sont relâchés
        // pour que la décision ne dépende pas du taux de remplissage réel
        // du runner. Réserve à 0 pour que `capture_budget` ne compare pas
        // les 8 GiB de réserve par défaut à un volume quasi plein.
        let permissive_policy = live_probe::disk_safety::Policy {
            information_percent: 100,
            warning_percent: 100,
            stop_percent: 100,
            hard_limit_percent: 100,
            max_file_bytes: 256 * 1024 * 1024,
            max_files: 8,
            max_job_seconds: 15 * 60,
            max_concurrent_jobs: 1,
            polling_interval_ms: 1_000,
            reserve_bytes: 0,
        };
        let helper = CaptureHelperClient::new(socket, unsafe { libc::geteuid() });
        let mut manager = CaptureManager::with_helper_and_interface_root(
            manager_root.clone(),
            true,
            helper,
            interface_root,
            manager_root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        // Sonde factice qui expose les 12 interfaces attendues comme
        // disponibles, sans lire `/sys/class/net` ni dépendre des ponts
        // Docker du lab POLARIS.
        manager.set_interface_probe_for_tests(Arc::new(FakeInterfaceProbe::all_available()));
        // Disque simulé à 10 % d'utilisation avec 450 GiB libres, inodes
        // confortables : court-circuite `measure_path(&self.root)` qui
        // dépend du taux de remplissage réel du runner.
        manager.set_disk_sample_override_for_tests(Some(Ok(
            live_probe::disk_safety::FilesystemSample {
                total_bytes: 500 * 1024 * 1024 * 1024,
                available_bytes: 450 * 1024 * 1024 * 1024,
                total_inodes: 10_000_000,
                available_inodes: 9_000_000,
            },
        )));
        manager.set_policy_for_tests(permissive_policy);
        let mut config = test_config(workspace, "registry-four-plane-unit");
        config.capture_root = manager_root.clone();
        config.capture_execution_enabled = true;
        config.operator_token_sha256 = Some(sha256_hex(b"test-operator-token"));
        let app = router(
            AppState::load_with_capture_manager(config, manager).unwrap(),
            None,
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/captures/validate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::from(
                        serde_json::to_vec(&CaptureRequest::default()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["data"]["validation"]["valid"], true,
            "validation blockers: {:?}",
            body["data"]["validation"]["blockers"]
        );
        // 2.9.2 (#9 comment 6710853974): the allowlist carries 11
        // decoder-backed planes (N2/N3/N4/SBI + 7 LTE core planes).
        // 2.11.0 (devmat) : 13ᵉ plane IMS (SIP + RTP) → 12 maintenant.
        assert_eq!(
            body["data"]["validation"]["interfaces"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        helper_thread.join().unwrap();
        let _ = fs::remove_dir_all(manager_root);
        let _ = fs::remove_dir_all(helper_root);
    }

    /// 2.14.6 (ANR1 #10) — variante de laboratoire. Nécessite les ponts
    /// `br-oiran-{n2,n3,n4,sbi,s1m,s1u,s11,s5c,s5u,s6a,sxab,ims}` et
    /// au moins 2 % d'espace disque libre sur le workspace. Marquée
    /// `#[ignore]` pour qu'un `cargo test` ordinaire ne la lance pas
    /// implicitement ; à exécuter avec `cargo test -- --ignored` sur
    /// un hôte de laboratoire POLARIS. Les préconditions sont
    /// vérifiées explicitement au démarrage et produisent un panic
    /// clair quand elles ne sont pas remplies (« un garde qui se saute
    /// ne garde rien » — ANR1).
    #[tokio::test]
    #[ignore = "lab: requires br-oiran-{n2,n3,n4,sbi,…} bridges and ≥2% disk free"]
    async fn four_plane_validate_traverses_http_api_and_unix_ipc_without_acquisition_lab() {
        for bridge in ["br-oiran-n2", "br-oiran-sbi", "br-oiran-n4", "br-oiran-n3"] {
            let sysfs = FsPath::new("/sys/class/net").join(bridge);
            assert!(
                sysfs.is_dir(),
                "PRECONDITION: bridge {sysfs:?} is missing — run POLARIS Control compose stack \
                 before `cargo test -- --ignored four_plane_...lab`"
            );
        }
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let sample = live_probe::disk_safety::measure_path(workspace)
            .expect("PRECONDITION: workspace filesystem is not reachable");
        let usage_bp = sample.usage_basis_points().unwrap_or(10_000);
        assert!(
            usage_bp < 9_800,
            "PRECONDITION: workspace filesystem at {}‱ usage is above the 98% hard-limit \
             (disk-safety rejects new captures) — free space before running this test",
            usage_bp
        );

        let suffix = format!("{}-{}", std::process::id(), epoch_seconds());
        let manager_root = workspace
            .join("runtime")
            .join(format!("api-four-plane-lab-{suffix}"));
        let helper_root = std::env::temp_dir().join(format!("oiran-four-plane-lab-{suffix}"));
        let interface_root = helper_root.join("interfaces");
        for interface in [
            InterfaceId::N2,
            InterfaceId::Sbi,
            InterfaceId::N4,
            InterfaceId::N3,
        ] {
            fs::create_dir_all(interface_root.join(interface.device())).unwrap();
        }
        let socket = helper_root.join("capture-helper.sock");
        let service = CaptureService::new(
            ServerConfig {
                socket_path: socket.clone(),
                capture_root: helper_root.join("captures"),
                interface_root: interface_root.clone(),
                allowed_client_uid: unsafe { libc::geteuid() },
                allowed_client_gid: Some(unsafe { libc::getegid() }),
                socket_gid: None,
                policy: Policy::default(),
            },
            ValidationOnlyBackend,
        )
        .unwrap();
        let listener = service.bind().unwrap();
        let server = service.clone();
        let helper_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            server.handle_stream(stream).unwrap();
        });

        let helper = CaptureHelperClient::new(socket, unsafe { libc::geteuid() });
        let manager = CaptureManager::with_helper_and_interface_root(
            manager_root.clone(),
            true,
            helper,
            PathBuf::from("/sys/class/net"),
            manager_root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        let mut config = test_config(workspace, "registry-four-plane-lab");
        config.capture_root = manager_root.clone();
        config.capture_execution_enabled = true;
        config.operator_token_sha256 = Some(sha256_hex(b"test-operator-token"));
        let app = router(
            AppState::load_with_capture_manager(config, manager).unwrap(),
            None,
        );
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/captures/validate")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::from(
                        serde_json::to_vec(&CaptureRequest::default()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["data"]["validation"]["valid"], true,
            "validation blockers: {:?}",
            body["data"]["validation"]["blockers"]
        );
        assert_eq!(
            body["data"]["validation"]["interfaces"]
                .as_array()
                .unwrap()
                .len(),
            12
        );
        helper_thread.join().unwrap();
        let _ = fs::remove_dir_all(manager_root);
        let _ = fs::remove_dir_all(helper_root);
    }

    /// Sonde factice pour les tests déterministes (cf.
    /// `four_plane_validate_..._unit`). Produit exactement les 12
    /// interfaces publiées par `live_probe::interface_specs()`, toutes
    /// marquées disponibles, operstate "UP", sans toucher au sysfs.
    struct FakeInterfaceProbe {
        interfaces: Vec<live_probe::CaptureInterface>,
    }

    impl FakeInterfaceProbe {
        fn all_available() -> Self {
            Self {
                interfaces: live_probe::interface_specs()
                    .into_iter()
                    .map(|mut interface| {
                        interface.available = true;
                        interface.operstate = "UP".into();
                        interface.reason = None;
                        interface
                    })
                    .collect(),
            }
        }
    }

    impl live_probe::InterfaceProbe for FakeInterfaceProbe {
        fn interfaces(&self) -> Vec<live_probe::CaptureInterface> {
            self.interfaces.clone()
        }
    }

    /// 2.9.2 (#9 Analyzer T5 — comment 6712678520). The continuous lab
    /// import's live dataset reported `technology: UNKNOWN` to the
    /// Analyzer top-bar until a decoded plane landed, so ANR2 saw
    /// "Observed: UNKNOWN / LTE" while the open session was already
    /// 5G SA. The fallback prefers plane-observed inference and only
    /// drops to the declared capture job profile when no plane has been
    /// decoded yet; it must NEVER invent a technology without one of
    /// these two signals.
    #[test]
    fn technology_for_live_fallback_prefers_planes_then_profile_then_unknown() {
        let planes = ["N2", "N4"];
        assert_eq!(
            technology_for_live_fallback(
                planes.iter().copied(),
                Some("POLARIS_LTE_CONTINUOUS_IMPORT"),
            ),
            "5G SA",
            "observed 5G planes outrank the LTE profile fallback"
        );
        assert_eq!(
            technology_for_live_fallback(
                std::iter::empty(),
                Some("POLARIS_5G_SA_CONTINUOUS_IMPORT"),
            ),
            "5G SA",
            "cold dataset derives from the 5G SA profile"
        );
        assert_eq!(
            technology_for_live_fallback(std::iter::empty(), Some("POLARIS_LTE_E2E_SMALL_TRAFFIC"),),
            "LTE",
            "cold dataset derives from the LTE profile"
        );
        assert_eq!(
            technology_for_live_fallback(std::iter::empty(), None),
            "UNKNOWN",
            "no plane and no profile → UNKNOWN (never invented)"
        );
        assert_eq!(
            technology_for_live_fallback(std::iter::empty(), Some("CUSTOM_OPERATOR_PROFILE_42"),),
            "UNKNOWN",
            "unrecognised profile → UNKNOWN (never invented)"
        );
    }

    #[tokio::test]
    async fn v2_public_identity_is_explicitly_viewer_only() {
        let response = router(state(), None)
            .oneshot(req("/api/v1/auth/me", false))
            .await
            .unwrap();
        let value = json_body(response).await;
        assert_eq!(value["data"]["role"], "viewer");
        assert_eq!(value["data"]["capture_control"], false);
        assert_eq!(value["data"]["reason"], "PUBLIC_VIEWER_OR_INVALID_TOKEN");
    }

    fn capture_job_in_state(
        capture_id: &str,
        state: live_probe::CaptureState,
        started: Option<u64>,
        ended: Option<u64>,
        pending: u64,
        stop_reason: Option<&str>,
    ) -> live_probe::CaptureJob {
        let mut metrics = live_probe::CaptureMetrics::default();
        metrics.pending_segments = pending;
        metrics.pending_fingerprints = pending;
        live_probe::CaptureJob {
            capture_id: capture_id.into(),
            probe_id: "probe-local".into(),
            name: capture_id.into(),
            profile: "continuous".into(),
            interfaces: vec!["N2".into(), "N3".into(), "N4".into()],
            state,
            created_epoch_ms: 1_000,
            started_epoch_ms: started,
            ended_epoch_ms: ended,
            owner: "operator".into(),
            metrics,
            output_directory: "/var/lib/oiran/captures".into(),
            dataset_id: None,
            session_ids: vec![],
            error: None,
            stop_reason: stop_reason.map(str::to_string),
            process_ids: vec![],
            helper_results: vec![],
            capture_group_id: None,
            scenario_id: None,
            planes: vec![],
        }
    }

    /// 2.9.8 (#9 comment 6725097122): `select_metrics_source_job`
    /// must prefer a `Capturing` job but fall back to the most
    /// recent BLOCKED job so `/metrics pending_segments` reflects
    /// the ANR2 production state (continuous-import worker in
    /// `Blocked` with `pending=1` on `CONTINUOUS_IMPORT_BACKPRESSURE_LIMIT`).
    #[test]
    fn select_metrics_source_job_prefers_capturing_then_blocked() {
        let active = capture_job_in_state(
            "continuous-lab-import",
            live_probe::CaptureState::Capturing,
            Some(3_000),
            None,
            0,
            None,
        );
        let older_blocked = capture_job_in_state(
            "continuous-lab-import-old",
            live_probe::CaptureState::Blocked,
            Some(1_000),
            Some(1_500),
            7,
            Some("BOUNDED_STORAGE_FULL"),
        );
        let newer_blocked = capture_job_in_state(
            "continuous-lab-import-newer",
            live_probe::CaptureState::Blocked,
            Some(2_000),
            Some(2_500),
            1,
            Some("BOUNDED_STORAGE_FULL"),
        );

        let jobs = vec![older_blocked.clone(), newer_blocked.clone(), active.clone()];
        let chosen = select_metrics_source_job(&jobs).unwrap();
        assert_eq!(chosen.capture_id, "continuous-lab-import");
        assert_eq!(chosen.state, live_probe::CaptureState::Capturing);

        // No Capturing job → fall back to the most recent BLOCKED.
        let jobs_no_active = vec![older_blocked.clone(), newer_blocked.clone()];
        let chosen = select_metrics_source_job(&jobs_no_active).unwrap();
        assert_eq!(chosen.capture_id, "continuous-lab-import-newer");
        assert_eq!(chosen.state, live_probe::CaptureState::Blocked);
        // pending AND stop_reason are exposed — never masked.
        assert_eq!(chosen.metrics.pending_segments, 1);
        assert_eq!(chosen.stop_reason.as_deref(), Some("BOUNDED_STORAGE_FULL"));

        // Empty list: None (handler already encodes as JSON null).
        assert!(select_metrics_source_job(&[]).is_none());
    }

    // ─────────────────────────────────────────────────────────────
    // 2.10.0 (devmat) — Session Explorer filter endpoints (API).
    //
    // Couvre :
    //   * messages — multi-select par interface
    //   * causes — scopées par domain, failures_only
    //   * identity — viewer 403, operator OK, pseudonymisation
    //     côté serveur, aucune identité en clair dans la
    //     réponse / URL
    //   * combinaison AND
    //   * IMSI inconnu → 0 sans leak
    // ─────────────────────────────────────────────────────────────

    async fn post_sessions_filter(
        app_state: &AppState,
        body: Value,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let router = router(app_state.clone(), None);
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/sessions/filter")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder.body(Body::from(body.to_string())).unwrap();
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let payload = json_body(response).await;
        (status, payload)
    }

    #[test]
    fn null_decipher_preference_is_detected_only_when_tshark_lists_it() {
        assert!(tshark_prefs_contain_null_decipher(
            "# Some comment\n#nas-5gs.null_decipher: FALSE\n"
        ));
        assert!(tshark_prefs_contain_null_decipher("nas-5gs.null_decipher: TRUE\n"));
        assert!(!tshark_prefs_contain_null_decipher("#nas-eps.null_decipher: FALSE\n"));
    }

    /// 2.18.12 — l'index de filtrage n'est plus reconstruit à chaque page,
    /// mais une session ajoutée APRÈS un premier appel doit apparaître
    /// (signature invalidée).
    #[tokio::test]
    async fn filter_index_cache_is_invalidated_when_a_session_is_added() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let state = AppState::load(test_config(workspace, "filter-cache-invalidation")).unwrap();
        let (status, before) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(status, StatusCode::OK);
        let before_total = before["meta"]["total"].as_u64().unwrap();
        let signature_before = journey_signature(&state);
        let (_status, again) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(again["meta"]["total"].as_u64().unwrap(), before_total);
        let bundle = temporary_directory("filter-cache-invalidation-bundle");
        let (_dataset_id, lte_session_id) = ingest_lte_evidence_fixture(&state, &bundle);
        assert_ne!(journey_signature(&state), signature_before);
        let (_status, after) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        let ids: Vec<&str> = after["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["session_id"].as_str())
            .collect();
        assert!(ids.contains(&lte_session_id.as_str()), "new LTE session missing after cache");
        assert!(after["meta"]["total"].as_u64().unwrap() > before_total);
    }

    /// 2.21.50 — équivalence de résultat avec la sémantique historique
    /// `time_window` (au moins un event dans [from,to]), tout en prouvant
    /// que les summaries coûteux ne sont plus construits pour les sessions
    /// rejetées par ce prédicat. Mutation : remettre `resolve_summary` avant
    /// le test de fenêtre rend la seconde assertion rouge (> 0).
    #[tokio::test]
    async fn sessions_filter_time_window_prunes_before_summary_with_equivalent_result() {
        use std::sync::atomic::Ordering;

        let state = state();
        let expected: BTreeSet<String> = queryable_flows(&state)
            .into_values()
            .filter(|flow| {
                flow.events
                    .iter()
                    .any(|event| event.timestamp_ns.parse::<i128>().is_ok_and(|ts| ts >= 0))
            })
            .map(|flow| flow.session_id)
            .collect();
        state
            .inner
            .filter_summary_resolutions
            .store(0, Ordering::SeqCst);
        state
            .inner
            .filter_flow_resolutions
            .store(0, Ordering::SeqCst);
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 100,
                "time_window": {
                    "from": "0",
                    "to": i128::MAX.to_string(),
                }
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let actual: BTreeSet<String> = body["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["session_id"].as_str().map(str::to_owned))
            .collect();
        assert_eq!(
            actual, expected,
            "time-window result changed from fixture reference"
        );
        assert_eq!(
            state.inner.filter_flow_resolutions.load(Ordering::SeqCst),
            0,
            "time-window-only filtering must not resolve any callflow"
        );

        state
            .inner
            .filter_summary_resolutions
            .store(0, Ordering::SeqCst);
        state
            .inner
            .filter_flow_resolutions
            .store(0, Ordering::SeqCst);
        let (status, outside) = post_sessions_filter(
            &state,
            json!({
                "limit": 100,
                "time_window": {
                    "from": i128::MAX.to_string(),
                    "to": i128::MAX.to_string(),
                }
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(outside["data"].as_array().unwrap().is_empty());
        assert_eq!(
            state
                .inner
                .filter_summary_resolutions
                .load(Ordering::SeqCst),
            0,
            "out-of-window sessions must be rejected before summary construction"
        );
        assert_eq!(
            state.inner.filter_flow_resolutions.load(Ordering::SeqCst),
            0,
            "mutation guard: restoring per-session flow resolution must make this assertion red"
        );
    }

    /// 2.21.56 — le premier filtre servi ne doit reconstruire aucun des
    /// deux index : ils sont prêts avant l'ouverture du listener (ou dans le
    /// callback de publication). Mutation : retirer l'un des deux appels de
    /// `prewarm_session_filter_caches_locked` incrémente le compteur associé
    /// pendant la requête et rend ce test rouge.
    #[tokio::test]
    async fn session_filter_prewarm_makes_first_request_cache_hot() {
        use std::sync::atomic::Ordering;

        let state = state();
        assert_eq!(state.inner.filter_index_rebuilds.load(Ordering::SeqCst), 0);
        assert_eq!(state.inner.journey_index_rebuilds.load(Ordering::SeqCst), 0);

        install_session_filter_cache_prewarm(&state);
        let filter_rebuilds_after_warm =
            state.inner.filter_index_rebuilds.load(Ordering::SeqCst);
        let journey_rebuilds_after_warm =
            state.inner.journey_index_rebuilds.load(Ordering::SeqCst);
        assert_eq!(filter_rebuilds_after_warm, 1);
        assert_eq!(journey_rebuilds_after_warm, 1);

        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 100,
                "time_window": {
                    "from": "0",
                    "to": i128::MAX.to_string(),
                }
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!body["data"].as_array().unwrap().is_empty());
        assert_eq!(
            state.inner.filter_index_rebuilds.load(Ordering::SeqCst),
            filter_rebuilds_after_warm,
            "first request rebuilt the prewarmed filter index"
        );
        assert_eq!(
            state.inner.journey_index_rebuilds.load(Ordering::SeqCst),
            journey_rebuilds_after_warm,
            "first request rebuilt the prewarmed journey index"
        );
    }

    /// 2.21.63 — avec l'import continu, le préchauffage de démarrage ne doit
    /// jamais concurrencer les structures de publication. Le callback de
    /// publication reste l'unique déclencheur.
    #[test]
    fn continuous_import_defers_startup_filter_prewarm() {
        use std::sync::atomic::Ordering;

        let mut state = state();
        Arc::get_mut(&mut state.inner)
            .expect("test owns the only AppState reference")
            .continuous_import_enabled = true;
        install_session_filter_cache_prewarm(&state);
        assert_eq!(state.inner.filter_index_rebuilds.load(Ordering::SeqCst), 0);
        assert_eq!(state.inner.journey_index_rebuilds.load(Ordering::SeqCst), 0);
    }

    /// 2.18.5 — ANR2 #10 6901691533 : p900 lit /sessions/filter, qui
    /// omettait `identities` → IMSI/TMSI/IMEI « — ». Chaque ligne filtrée
    /// porte la même clé `identities` que GET /sessions.
    #[tokio::test]
    async fn sessions_filter_rows_carry_the_same_identities_as_sessions_list() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let state = AppState::load(test_config(workspace, "filter-identities")).unwrap();
        let list = router(state.clone(), None)
            .oneshot(req("/api/v1/sessions?page_size=100", false))
            .await
            .unwrap();
        let list = json_body(list).await;
        let by_id: std::collections::BTreeMap<String, Value> = list["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row["session_id"].as_str().unwrap().to_owned(), row["identities"].clone()))
            .collect();
        let (status, page) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(status, StatusCode::OK);
        let rows = page["data"].as_array().unwrap();
        assert!(!rows.is_empty());
        for row in rows {
            let id = row["session_id"].as_str().unwrap();
            assert!(
                row.as_object().unwrap().contains_key("identities"),
                "row {id} of /sessions/filter has no identities key"
            );
            // Le filtre peut en savoir plus (repli events) ; jamais moins.
            if let Some(expected) = by_id.get(id).filter(|value| !value.is_null()) {
                assert_eq!(&row["identities"], expected, "identities differ for {id}");
            }
        }
    }

    /// 2.15.7 — ANR1 #10 (gate pagination 2.16.0/2.5.1) : GET /sessions
    /// renvoyait 174 sessions et POST /sessions/filter 173 — l'index du
    /// filtre ignorait le LTE evidence store. Les deux totaux doivent
    /// être égaux, session LTE evidence comprise.
    #[tokio::test]
    async fn sessions_filter_and_sessions_list_cover_the_same_sessions_including_lte_evidence() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let config = test_config(workspace, "filter-vs-list-lte");
        let store_root = config.lte_evidence_root.clone();
        let state = AppState::load(config).unwrap();
        let bundle = temporary_directory("filter-vs-list-lte-bundle");
        let (_dataset_id, lte_session_id) = ingest_lte_evidence_fixture(&state, &bundle);

        let list = router(state.clone(), None)
            .oneshot(req("/api/v1/sessions?page_size=100", false))
            .await
            .unwrap();
        let list = json_body(list).await;
        let mut listed: Vec<String> = list["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["session_id"].as_str().unwrap().to_owned())
            .collect();
        listed.sort();

        let mut filtered: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut body = json!({"limit": 100});
            if let Some(c) = &cursor {
                body["cursor"] = Value::String(c.clone());
            }
            let (status, page) = post_sessions_filter(&state, body, None).await;
            assert_eq!(status, StatusCode::OK);
            for row in page["data"].as_array().unwrap() {
                filtered.push(row["session_id"].as_str().unwrap().to_owned());
            }
            cursor = page["meta"]["next_cursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        filtered.sort();
        assert!(
            listed.contains(&lte_session_id),
            "LTE evidence session must be in GET /sessions"
        );
        assert!(
            filtered.contains(&lte_session_id),
            "LTE evidence session missing from POST /sessions/filter"
        );
        assert_eq!(filtered, listed);

        fs::remove_dir_all(bundle).unwrap();
        fs::remove_dir_all(store_root.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn sessions_filter_message_narrows_result() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "messages": [{"name": "PDUSessionResourceSetupRequest", "interface": "N2"}]
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let data = body["data"].as_array().expect("data array present");
        for item in data {
            // Chaque session retenue DOIT contenir le message
            // demandé (vérifié par l'index), donc son interface
            // de call-flow doit comporter N2.
            let interfaces = item["interfaces"].as_array().cloned().unwrap_or_default();
            assert!(
                interfaces.iter().any(|i| i == "N2"),
                "session {} returned without N2 interface",
                item["session_id"]
            );
        }
    }

    #[tokio::test]
    async fn sessions_filter_viewer_cannot_pass_identity_hint() {
        let state = operator_state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "identity": {"kind": "supi_or_imsi", "value": "imsi-208010001234567"}
            }),
            None, // ← pas de bearer → Viewer
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "IDENTITY_FILTER_OPERATOR_REQUIRED");
        // La réponse n'écho jamais la valeur brute.
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains("imsi-208010001234567"),
            "raw identity leaked in viewer-403 response: {serialized}"
        );
    }

    #[tokio::test]
    async fn sessions_filter_identity_never_echoes_raw_value() {
        let state = operator_state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "identity": {"kind": "supi_or_imsi", "value": "imsi-208010009999999"}
            }),
            Some("test-operator-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains("imsi-208010009999999"),
            "raw identity leaked in operator response: {serialized}"
        );
        // La meta expose le pseudonyme recherché mais jamais la
        // valeur brute.
        assert!(body["meta"]["identity_matched_pseudonym"].is_string());
        let pseudo = body["meta"]["identity_matched_pseudonym"].as_str().unwrap();
        assert!(
            pseudo.starts_with("psn-"),
            "expected psn- prefix, got {pseudo}"
        );
    }

    #[tokio::test]
    async fn sessions_filter_unknown_identity_returns_zero_without_leak() {
        let state = operator_state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "identity": {"kind": "supi_or_imsi", "value": "imsi-999999999999999"}
            }),
            Some("test-operator-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["total"], 0);
        assert_eq!(
            body["data"].as_array().map(|a| a.len()),
            Some(0),
            "unknown IMSI must return zero sessions"
        );
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(
            !serialized.contains("999999999999999"),
            "raw unknown identity leaked: {serialized}"
        );
    }

    #[tokio::test]
    async fn sessions_filter_combines_messages_and_failures_only_and() {
        let state = state();
        // Combinaison large : messages d'enregistrement + échec
        // uniquement. Avec le dataset synthétique embarqué,
        // peut renvoyer 0 ou plus, mais chaque entrée DOIT
        // satisfaire les deux prédicats.
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "messages": [{"name": "Registration Reject"}],
                "failures_only": true,
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let data = body["data"].as_array().expect("data present");
        for item in data {
            // Pas de preuve directe sans re-fetcher la session ;
            // on vérifie au moins l'absence d'identité en clair.
            assert_no_identity_material(item);
        }
    }

    #[tokio::test]
    async fn sessions_available_causes_lists_causes_with_counts() {
        let state = state();
        let router = router(state.clone(), None);
        let request = Request::builder()
            .uri("/api/v1/sessions/available_causes")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let causes = body["data"]["causes"]
            .as_array()
            .expect("causes array present");
        // Shape invariants plus critiques que le compte : chaque
        // cause porte domain, value, is_failure, session_count ≥ 1.
        for cause in causes {
            assert!(cause["domain"].is_string(), "domain missing: {cause}");
            assert!(cause["value"].is_string(), "value missing: {cause}");
            assert!(
                cause["is_failure"].is_boolean(),
                "is_failure missing: {cause}"
            );
            assert!(
                cause["session_count"].as_u64().unwrap_or(0) >= 1,
                "session_count must be >= 1: {cause}"
            );
        }
        // Aucune identité ne doit figurer dans la réponse.
        assert_no_identity_material(&body);
    }

    /// 2.19.0 — `GET /sessions/catalog` expose les 4 familles de
    /// filtres et un catalog de colonnes non vide. Aucune colonne
    /// de type identité en clair.
    #[tokio::test]
    async fn sessions_catalog_exposes_filters_and_columns_without_clear_identities() {
        let state = state();
        let router = router(state.clone(), None);
        let request = Request::builder()
            .uri("/api/v1/sessions/catalog")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let columns = body["data"]["columns"]
            .as_array()
            .expect("columns array present");
        assert!(!columns.is_empty(), "columns catalog must be non-empty");
        for column in columns {
            assert!(column["name"].is_string());
            assert!(column["type"].is_string());
            assert!(column["applies_to"].is_array());
            assert!(column["always_present"].is_boolean());
            let name = column["name"].as_str().unwrap().to_ascii_lowercase();
            // Jamais de nom de colonne portant imsi/supi/msisdn/
            // imei/guti/tmsi/suci/pei en clair (règle Sadok
            // 2026-11-14). Les pseudonymes & le wrapper
            // `identities` sont autorisés.
            for banned in [
                "imsi", "supi", "suci", "msisdn", "imei", "imeisv", "guti", "tmsi",
            ] {
                let is_pseudo_wrap =
                    name.contains("pseudonym") || name.contains("identities");
                assert!(
                    !name.contains(banned) || is_pseudo_wrap,
                    "forbidden clear identity column: {name}"
                );
            }
        }
        let filters = &body["data"]["filters"];
        for family in [
            "interfaces",
            "messages",
            "causes",
            "technologies",
            "dataset_kinds",
            "states",
            "correlation_statuses",
        ] {
            assert!(filters[family].is_array(), "missing filter family: {family}");
        }
        assert_no_identity_material(&body);
    }

    /// 2.19.0 — `POST /sessions/filter` avec `columns` renvoie les
    /// lignes projetées. Les colonnes ALWAYS_PRESENT sont
    /// toujours là, et `meta.projected_columns` reflète la
    /// requête. Aucune identité en clair dans la projection.
    #[tokio::test]
    async fn sessions_filter_with_columns_projects_and_keeps_always_present() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 5,
                "columns": ["state", "procedure", "message_count"],
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let data = body["data"].as_array().expect("data present");
        for item in data {
            // Toujours présentes.
            assert!(item.get("session_id").is_some());
            assert!(item.get("dataset_id").is_some());
            assert!(item.get("dataset_kind").is_some());
            assert!(item.get("technology").is_some());
            // Demandées.
            // (Elles peuvent être présentes OU absentes selon le
            // producteur — mais toute autre colonne doit l'être.)
            let allowed: std::collections::BTreeSet<&str> = [
                "session_id",
                "dataset_id",
                "dataset_kind",
                "technology",
                "state",
                "procedure",
                "message_count",
            ]
            .into_iter()
            .collect();
            if let Value::Object(object) = item {
                for key in object.keys() {
                    assert!(
                        allowed.contains(key.as_str()),
                        "unexpected column after projection: {key}"
                    );
                }
            }
            assert_no_identity_material(item);
        }
        let projected = body["meta"]["projected_columns"]
            .as_array()
            .expect("projected_columns array");
        assert_eq!(projected.len(), 3);
    }

    /// 2.19.0 — un nom de colonne hors catalog déclenche 400
    /// `UNKNOWN_COLUMN` sans leak de données.
    #[tokio::test]
    async fn sessions_filter_with_unknown_column_returns_400_unknown_column() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({"columns": ["not_a_real_column"]}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "UNKNOWN_COLUMN");
    }

    /// 2.19.0 — `POST /sessions/columns` projette pour une liste
    /// d'ids explicite. Les ids inconnus apparaissent dans
    /// `meta.missing_session_ids`. Valide l'empty body → 400.
    #[tokio::test]
    async fn sessions_columns_projects_for_explicit_ids_and_reports_missing() {
        let state = state();
        // Récupère une liste d'ids réels via /sessions/filter.
        let (status, filter_body) =
            post_sessions_filter(&state, json!({"limit": 3}), None).await;
        assert_eq!(status, StatusCode::OK);
        let real_ids: Vec<String> = filter_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["session_id"].as_str().map(str::to_owned))
            .collect();
        if real_ids.is_empty() {
            // Pas de donnée dans le dataset embarqué : encore test
            // sanity du schéma d'erreur.
            let router = router(state.clone(), None);
            let request = Request::builder()
                .method("POST")
                .uri("/api/v1/sessions/columns")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "session_ids": [],
                        "columns": ["state"],
                    })
                    .to_string(),
                ))
                .unwrap();
            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            return;
        }
        let mut ids = real_ids.clone();
        ids.push("session-does-not-exist".to_owned());
        let router = router(state.clone(), None);
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/sessions/columns")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "session_ids": ids,
                    "columns": ["state", "procedure"],
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let data = body["data"].as_array().expect("data array");
        assert_eq!(data.len(), real_ids.len());
        let missing = body["meta"]["missing_session_ids"]
            .as_array()
            .expect("missing_session_ids array");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0], "session-does-not-exist");
        for item in data {
            assert!(item["session_id"].is_string());
            assert!(item["dataset_id"].is_string());
            // Pas d'autres colonnes que ALWAYS_PRESENT + demandées.
            let allowed: std::collections::BTreeSet<&str> = [
                "session_id",
                "dataset_id",
                "dataset_kind",
                "technology",
                "state",
                "procedure",
            ]
            .into_iter()
            .collect();
            if let Value::Object(object) = item {
                for key in object.keys() {
                    assert!(
                        allowed.contains(key.as_str()),
                        "unexpected column after projection: {key}"
                    );
                }
            }
        }
    }

    /// 2.19.0 — filtre étendu `technologies` restreint à 5G SA
    /// (quand des sessions 5G existent) et jamais ne renvoie une
    /// ligne LTE. Vérifie que la projection par défaut inclut
    /// toujours la colonne `technology`.
    #[tokio::test]
    async fn sessions_filter_technologies_restricts_to_5g_sa() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 50,
                "technologies": ["5G SA"],
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        for item in body["data"].as_array().unwrap() {
            assert_eq!(
                item["technology"].as_str().unwrap_or(""),
                "5G SA",
                "row should be 5G SA when filter technologies=[5G SA]"
            );
        }
    }

    /// 2.19.1 — `/sessions/catalog` publie `protocol_tree` et
    /// `network_elements` construits sur les events réels. Aucun
    /// nom d'identité en clair dans la publication.
    #[tokio::test]
    async fn sessions_catalog_publishes_protocol_tree_and_network_elements() {
        let state = state();
        let router = router(state.clone(), None);
        let request = Request::builder()
            .uri("/api/v1/sessions/catalog")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let tree = body["data"]["protocol_tree"]
            .as_array()
            .expect("protocol_tree array present");
        // Dataset embarqué 5G SA : au moins l'interface N2 doit apparaître.
        assert!(
            tree.iter().any(|iface| iface["interface"] == "N2"),
            "protocol_tree must contain observed N2"
        );
        assert!(body["data"]["network_elements"].is_array());
        assert_no_identity_material(&body);
    }

    /// 2.21.11 (défaut 2 #9 6930315055) — le catalogue reconstruisait
    /// le call flow de CHAQUE session de CHAQUE dataset à chaque
    /// requête (45 s observés sur 217 sessions). Le cache keyé par
    /// `(commit_seq, dataset_ids, scope_hash)` doit rendre un 2e
    /// appel STRICTEMENT identique sans aucune reconstruction.
    #[tokio::test]
    async fn sessions_catalog_cache_hits_on_second_call_without_rebuild() {
        let state = state();
        let router = router(state.clone(), None);
        // 1er appel : alimente le cache.
        let first = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sessions/catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = json_body(first).await;
        let first_tree = first_body["data"]["protocol_tree"].clone();
        let first_elements = first_body["data"]["network_elements"].clone();
        // Vérifie que le cache porte bien une entrée.
        {
            let guard = state.inner.sessions_catalog_cache.lock().unwrap();
            assert!(guard.entry.is_some(), "1er appel doit renseigner le cache");
        }
        // 2e appel : identique → cache hit.
        let second = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/sessions/catalog")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_body = json_body(second).await;
        // L'entrée du cache n'a pas été déplacée : même valeurs.
        assert_eq!(second_body["data"]["protocol_tree"], first_tree);
        assert_eq!(second_body["data"]["network_elements"], first_elements);
    }

    /// 2.21.11 (défaut 3 #9 6930315055) — preuve architecturale que
    /// `spawn_blocking` libère le runtime async pendant une tâche
    /// bloquante longue (comme `hydrate_identities` → `tshark`
    /// sub-process). Un timer async concurrent doit continuer de
    /// tourner et se résoudre en « temps normal » (= quelques ms).
    ///
    /// Modèle du scénario `/health` pendant `/identities` froid :
    /// l'ancien code appelait `hydrate_identities` directement sur
    /// la worker thread axum, ce qui bloquait tous les handlers
    /// (incluant `/health`) sur cette thread.
    #[tokio::test]
    async fn spawn_blocking_does_not_starve_async_runtime_for_health_during_slow_identities() {
        use std::time::{Duration, Instant};
        // Modélise `hydrate_identities` lent via `spawn_blocking` (c'est
        // précisément ce que fait `session_identities` depuis 2.21.10).
        let blocking = tokio::task::spawn_blocking(|| {
            std::thread::sleep(Duration::from_millis(500));
            "hydrate done"
        });
        // Pendant ce temps, un handler async rapide (modèle `/health`)
        // doit pouvoir tourner. On mesure qu'il se résout bien en < 100 ms.
        let start = Instant::now();
        let health: &str = async {
            tokio::time::sleep(Duration::from_millis(1)).await;
            "ok"
        }
        .await;
        let health_elapsed = start.elapsed();
        assert_eq!(health, "ok");
        assert!(
            health_elapsed < Duration::from_millis(100),
            "/health doit répondre pendant un hydrate lent — vu {:?}",
            health_elapsed
        );
        // On vérifie quand même que la tâche bloquante termine propre.
        let hydrate = blocking.await.expect("blocking task joined");
        assert_eq!(hydrate, "hydrate done");
    }

    /// 2.21.13 — VRAI test du routeur : `/health` répond vite même quand
    /// le calcul de ses compteurs est bloqué (verrou du cache tenu par un
    /// recalcul simulé), en servant l'instantané existant avec son âge.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_serves_snapshot_without_io_while_counters_refresh_is_slow() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        // 1er appel : calcule l'instantané.
        let first = json_body(app.clone().oneshot(req("/api/v1/health", false)).await.unwrap()).await;
        assert_eq!(first["data"]["counters_status"], "fresh");
        let count = first["data"]["session_count"].clone();
        // Instantané vieilli + recalcul « bloqué » (flag tenu) : /health ne
        // doit faire aucun calcul et répondre aussitôt avec l'état stale.
        {
            let mut guard = st.inner.health_cache.lock().unwrap();
            let (_, v) = guard.clone().unwrap();
            *guard = Some((Instant::now() - Duration::from_secs(60), v));
        }
        st.inner.health_refreshing.store(true, std::sync::atomic::Ordering::SeqCst);
        let start = Instant::now();
        let second = json_body(app.oneshot(req("/api/v1/health", false)).await.unwrap()).await;
        assert!(start.elapsed() < Duration::from_millis(200), "vu {:?}", start.elapsed());
        assert_eq!(second["data"]["counters_status"], "stale");
        assert!(second["data"]["counters_age_ms"].as_u64().unwrap() >= 60_000);
        assert_eq!(second["data"]["session_count"], count);
    }

    /// 2.21.26 (FAIL lab 2.21.22 : OOM) — pendant un travail lourd (publication
    /// continue), le chemin froid `/identities` répond 503 + Retry-After au
    /// lieu de matérialiser en parallèle ; libéré, la route refonctionne.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cold_identities_answer_503_while_continuous_publication_holds_memory_gate() {
        let state = operator_state();
        let session_id = queryable_session_ids(&state).into_iter().next().expect("session");
        let app = router(state.clone(), None);
        let request = |uri: String| {
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, "Bearer test-operator-token")
                .body(Body::empty())
                .unwrap()
        };
        let uri = format!("/api/v1/sessions/{session_id}/identities");
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            let busy = app.clone().oneshot(request(uri.clone())).await.unwrap();
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(busy.headers()[header::RETRY_AFTER], "60");
            let body = json_body(busy).await;
            assert_eq!(body["error"]["code"], "HEAVY_WORK_IN_PROGRESS");
        }
        let free = app.oneshot(request(uri)).await.unwrap();
        assert_ne!(free.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 2.21.85 (CLAUDE1, ordre #9 7015585561) — inversé par rapport à
    /// 2.21.74. Pendant qu'une publication tient `heavy_memory_enter`,
    /// la route sert MAINTENANT la génération READY précédente via
    /// l'Arc'd snapshot si elle existe, et `heavy_memory_try_enter` est
    /// retiré. Ici l'état de test n'appelle pas
    /// `install_session_filter_cache_prewarm` (enforcement off),
    /// donc le fallback lecture-caches-live s'applique : la route
    /// répond 200 pendant la publication.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_filter_serves_previous_generation_during_publication_2_21_85() {
        let state = operator_state();
        let app = router(state.clone(), None);
        let build = || {
            Request::builder()
                .method("POST")
                .uri("/api/v1/sessions/filter")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"limit": 3}).to_string()))
                .unwrap()
        };
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            let response = app.clone().oneshot(build()).await.unwrap();
            // 2.21.85 : plus de 503 pendant la publication si une
            // génération READY est disponible (ici fallback live
            // cache car enforcement off → 200 servi depuis le cache).
            assert_ne!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        let free = app.oneshot(build()).await.unwrap();
        assert_ne!(free.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 2.21.85 (CLAUDE1, ordre #9 7015585561) — inversé par rapport à
    /// 2.21.74. Vider `readiness.ready_generation` ne doit PLUS
    /// provoquer 503 tant que le `generation_slot` conserve une
    /// génération READY. Le double tampon découple « signature
    /// publiée » (ancien compteur) de « génération servable » (Arc'd
    /// snapshot). 503 arrive SEULEMENT si `generation_slot = None`
    /// ET l'enforcement est actif (premier démarrage avant tout
    /// prewarm réussi).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_filter_first_boot_without_any_ready_generation_returns_503_2_21_85() {
        let state = operator_state();
        install_session_filter_cache_prewarm(&state);
        // Force l'état « aucune génération READY ».
        if let Ok(mut slot) = state.inner.generation_slot.write() {
            *slot = None;
        }
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sessions/filter")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"limit": 100}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let payload = json_body(response).await;
        assert_eq!(payload["error"]["code"], "SESSION_FILTER_CACHE_WARMING");

        // Après un prewarm réussi, le slot est rempli et la route répond
        // 200 avec les en-têtes `x-oiran-generation` / `x-oiran-commit-seq` /
        // `x-oiran-stale-since-ms`.
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            prewarm_session_filter_caches_locked(&state, "test-first-boot-prewarm");
        }
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sessions/filter")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"limit": 100}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let gen_header = response
            .headers()
            .get("x-oiran-generation")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        assert!(gen_header >= 1, "generation header absent or 0");
    }

    /// 2.21.85 (CLAUDE1, ordre #9 7016931409, condition 2 "GC-survival") —
    /// publier N (le dataset continuous expose une session + son callflow),
    /// préchauffer → `generation=N` capturé dans `generation_slot`, capturer la
    /// réponse `before`. Puis supprimer le fichier callflow du dataset (= GC
    /// des fichiers de N) et déclencher un préchauffage : `cached_live_list_row_base`
    /// retourne `None` sur la session manquante, `stats.missing > 0`, `ready=false`,
    /// aucun swap. La route doit continuer à répondre `200`, en-tête
    /// `x-oiran-generation=N`, corps identique à `before` (modulo
    /// `meta.stale_since_ms` qui augmente avec le temps écoulé) — preuve qu'elle
    /// lit `gen.rows_by_session` et jamais `callflow(...)` disque.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_filter_serves_generation_after_file_gc_2_21_85() {
        use live_probe::{CaptureManager, CONTINUOUS_CAPTURE_ID, CONTINUOUS_DATASET_ID};
        use std::io::Write as _;
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let capture_root_guard = AutoRemoveDir::new(
            workspace
                .join("runtime")
                .join(format!("api-filter-gc-survival-{suffix}")),
        );
        let capture_root = capture_root_guard.as_pathbuf();
        let base = capture_root.join(CONTINUOUS_CAPTURE_ID);
        let dataset_dir = base.join("dataset");
        let generation_name = format!("generation-{}-0", epoch_seconds());
        let callflows_dir = dataset_dir
            .join("callflow-generations")
            .join(&generation_name);
        let pcap_dir = base.join("pcap");
        fs::create_dir_all(&callflows_dir).unwrap();
        fs::create_dir_all(&pcap_dir).unwrap();

        let session_id = "5g-gc-survival-session";
        let subscriber_pseudo = "sha256-gc-survival-subscriber";

        let nas_event = json!({
            "event_id":"evt-nas-registration",
            "timestamp":"","timestamp_ns":"0","interface":"N1","protocol":"NAS-5GS-MM",
            "message_name":"Registration Request","source_participant":"UE","destination_participant":"AMF",
            "direction":"RAN_TO_CORE",
            "decoded_ie_tree":[
                {"name":"subscriber_pseudonym","value":subscriber_pseudo,"source":"session_identifiers","pseudonymized":true},
            ],
            "decoding_status":"DECODED","semantic_status":"EXACT",
            "association":"SESSION","procedure_group":"5GMM Registration",
            "packet_references":[{"source_file":"N1.pcap-stub","packet_number":1,"byte_offset":0,"interface_id":0,"captured_length":1,"original_length":1}],
            "capture_id":"sha256:continuous","decoder_name":"decoder-nas","decoder_version":"0.4.1",
            "raw_payload_reference":"sha256:stub","errors":[]
        });
        let callflow = json!({
            "callflow_id":format!("cf-{session_id}"),
            "session_id":session_id,
            "technology":"5G SA",
            "start_timestamp":"","end_timestamp":"",
            "participants":[],
            "interfaces":["N1"],
            "procedures":[],
            "events":[nas_event],
            "correlation_edges":[],
            "correlation_status":{},
            "decoder_versions":{"decoder-nas":"0.4.1"},
            "schema_version":"1.5.0",
            "capture_references":["sha256:continuous"],
            "accounting":{"source_events":1,"session_events":1,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields":0
        });
        let callflow_path = callflows_dir.join(format!("{session_id}.json"));
        fs::write(&callflow_path, serde_json::to_vec_pretty(&callflow).unwrap()).unwrap();
        fs::write(callflows_dir.join(format!("{session_id}.html")), b"<html/>").unwrap();

        let jsonl_path = dataset_dir.join("oiran_events.jsonl");
        let mut jsonl = fs::File::create(&jsonl_path).unwrap();
        let raw_event = json!({
            "event_id":"evt-nas-registration","parent_event_id":null,
            "capture_id":"sha256:continuous","capture_point_id":"N1",
            "timestamp":{"seconds":1794673477i64,"nanoseconds":0u64,"raw_ticks":1794673477000000000u64,"display":"1794673477.000000000Z"},
            "interface":"N1","protocol":"NAS-5GS-MM",
            "message_name":"Registration Request","message_type":65,"procedure_code":null,
            "source_endpoint":{"address":"10.77.1.1","port":0u16,"network_function":"UE"},
            "destination_endpoint":{"address":"10.77.1.2","port":0u16,"network_function":"AMF"},
            "direction":"RAN_TO_CORE",
            "session_identifiers":[
                {"name":"subscriber_pseudonym","value":subscriber_pseudo,"pseudonymized":true},
            ],
            "information_elements":[],
            "decoding_status":"DECODED","decoder_name":"decoder-nas","decoder_version":"0.4.1",
            "raw_payload_reference":"sha256:stub",
            "packet_references":[{"source_file":"N1.pcap-stub","packet_number":1u64,"byte_offset":0u64,"interface_id":0u32,"captured_length":1u32,"original_length":1u32}],
            "errors":[],
        });
        writeln!(jsonl, "{}", serde_json::to_string(&raw_event).unwrap()).unwrap();
        drop(jsonl);

        let manifest = json!({
            "dataset_id": CONTINUOUS_DATASET_ID,
            "capture_id": CONTINUOUS_CAPTURE_ID,
            "path": "runtime/live-captures/continuous-lab-import/dataset",
            "event_count": 1,
            "session_ids": [session_id],
            "decode_reports": {},
            "checksums": {},
            "state": "PARTIAL",
            "callflows_path": format!("callflow-generations/{generation_name}"),
        });
        fs::write(
            dataset_dir.join("dataset_manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let pseudonym_key_path = base.join(".oiran-pseudonym.key");
        let manager = CaptureManager::with_pseudonym_key_path(
            capture_root.clone(),
            false,
            pseudonym_key_path,
        )
        .unwrap();
        manager
            .recover_continuous_dataset_from_disk(&base)
            .expect("recover continuous dataset from on-disk manifest");

        let mut config = test_config(workspace, &format!("filter-gc-survival-{suffix}"));
        config.reference_dataset_enabled = false;
        config.capture_root = capture_root.clone();
        let state = AppState::load_with_capture_manager(config, manager).unwrap();
        wait_for_compact_index_ready(&state, std::time::Duration::from_secs(10)).await;
        install_session_filter_cache_prewarm(&state);

        // Prewarm « publication N » sous la garde heavy_memory_enter : la
        // route servira la génération ainsi créée.
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            prewarm_session_filter_caches_locked(&state, "test-gc-survival-N");
        }
        let gen_n = state
            .inner
            .generation_slot
            .read()
            .ok()
            .and_then(|slot| slot.as_ref().map(|g| g.generation))
            .expect("generation N must be ready after successful prewarm");
        assert!(gen_n >= 1, "gen_n should be positive, got {gen_n}");

        let app = router(state.clone(), None);
        let request_body = || {
            Request::builder()
                .method("POST")
                .uri("/api/v1/sessions/filter")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"limit": 100}).to_string()))
                .unwrap()
        };
        let before_response = app.clone().oneshot(request_body()).await.unwrap();
        assert_eq!(before_response.status(), StatusCode::OK);
        let before_gen = before_response
            .headers()
            .get("x-oiran-generation")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .expect("x-oiran-generation header missing before GC");
        assert_eq!(before_gen, gen_n);
        let before_body = json_body(before_response).await;
        let before_data = before_body["data"].clone();
        assert!(
            before_data
                .as_array()
                .map(|rows| rows.iter().any(|row| row["session_id"] == session_id))
                .unwrap_or(false),
            "pre-GC body must contain the published session, got {}",
            before_body
        );

        // "GC des fichiers de N" : supprimer le fichier callflow + html.
        fs::remove_file(&callflow_path).expect("remove callflow .json");
        let _ = fs::remove_file(callflows_dir.join(format!("{session_id}.html")));
        // Et vider le cache de signatures pour que cached_live_list_row_base
        // ne couvre pas accidentellement la session (sinon test invalide).
        state.inner.list_row_cache.lock().unwrap().clear();
        // Préchauffage N+1 : la session est manquante côté disque, prewarm
        // signale `missing > 0 → ready=false`. Aucun swap. `generation_slot`
        // garde la génération N.
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            prewarm_session_filter_caches_locked(&state, "test-gc-survival-Nplus1-fails");
        }
        let gen_after = state
            .inner
            .generation_slot
            .read()
            .ok()
            .and_then(|slot| slot.as_ref().map(|g| g.generation))
            .expect("generation slot must still carry N after failed prewarm");
        assert_eq!(
            gen_after, gen_n,
            "failed prewarm N+1 must not swap; expected gen_n={gen_n}, got {gen_after}"
        );

        // Requête après GC : 200, x-oiran-generation=N, data identique à avant.
        let after_response = app.clone().oneshot(request_body()).await.unwrap();
        assert_eq!(after_response.status(), StatusCode::OK);
        let after_gen = after_response
            .headers()
            .get("x-oiran-generation")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .expect("x-oiran-generation header missing after GC");
        assert_eq!(after_gen, gen_n, "after GC must still serve generation N");
        let after_body = json_body(after_response).await;
        assert_eq!(
            after_body["data"], before_data,
            "data must be byte-identical after GC"
        );
    }

    /// Une génération réellement vide devient READY comme les autres et
    /// conserve le contrat historique `200 { data: [] }`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_filter_ready_empty_generation_stays_200() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let mut config = test_config(workspace, "filter-ready-empty");
        config.reference_dataset_enabled = false;
        config.capture_root = temporary_directory("filter-ready-empty-captures");
        let state = AppState::load(config).unwrap();
        install_session_filter_cache_prewarm(&state);

        let (status, payload) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["meta"]["total"], 0);
        assert!(payload["data"].as_array().unwrap().is_empty());
    }

    /// 2.21.30 — même pattern pour `GET /sessions/catalog/search`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_catalog_search_answers_503_while_continuous_publication_holds_memory_gate() {
        let state = operator_state();
        let app = router(state.clone(), None);
        let build = || {
            Request::builder()
                .uri("/api/v1/sessions/catalog/search?q=Cause")
                .body(Body::empty())
                .unwrap()
        };
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            let busy = app.clone().oneshot(build()).await.unwrap();
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(busy.headers()[header::RETRY_AFTER], "60");
            let body = json_body(busy).await;
            assert_eq!(body["error"]["code"], "HEAVY_WORK_IN_PROGRESS");
        }
        let free = app.oneshot(build()).await.unwrap();
        assert_ne!(free.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 2.21.30 — même pattern pour `POST /sessions/columns`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_columns_answers_503_while_continuous_publication_holds_memory_gate() {
        let state = operator_state();
        let session_id = queryable_session_ids(&state)
            .into_iter()
            .next()
            .expect("session");
        let app = router(state.clone(), None);
        let build = || {
            Request::builder()
                .method("POST")
                .uri("/api/v1/sessions/columns")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"session_ids": [session_id.clone()], "columns": ["state"]}).to_string(),
                ))
                .unwrap()
        };
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            let busy = app.clone().oneshot(build()).await.unwrap();
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(busy.headers()[header::RETRY_AFTER], "60");
            let body = json_body(busy).await;
            assert_eq!(body["error"]["code"], "HEAVY_WORK_IN_PROGRESS");
        }
        let free = app.oneshot(build()).await.unwrap();
        assert_ne!(free.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 2.21.34 (ordre #9 6956890331) — pendant un travail lourd en
    /// mémoire (publication continue), `GET /live/traces/:id/sessions`
    /// répond 503 `HEAVY_WORK_IN_PROGRESS` + `Retry-After: 60` au lieu
    /// de corréler flows + datasets × identity_vault. Libéré, la route
    /// refonctionne. Verrou `capture_manager` per-state → chaque test
    /// est isolé.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_for_trace_answers_503_while_continuous_publication_holds_memory_gate() {
        let state = operator_state();
        let app = router(state.clone(), None);
        // Crée une trace pseudonyme via l'API publique.
        let csrf = sha256_hex(b"oiran-csrf-v1:test-operator-token");
        let create = Request::builder()
            .method("POST")
            .uri("/api/v1/live/traces")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-operator-token")
            .header(CSRF_HEADER, csrf)
            .body(Body::from(
                json!({
                    "key_type": "pseudonym",
                    "value": "psn-live-test-0001",
                    "duration_s": 60,
                    "interfaces": [],
                })
                .to_string(),
            ))
            .unwrap();
        let create_response = app.clone().oneshot(create).await.unwrap();
        assert_eq!(create_response.status(), StatusCode::OK);
        let body = json_body(create_response).await;
        let trace_id = body["data"]["trace_id"].as_str().unwrap().to_owned();

        let build = move || {
            Request::builder()
                .uri(format!("/api/v1/live/traces/{trace_id}/sessions"))
                .body(Body::empty())
                .unwrap()
        };
        {
            let _publication = state.inner.capture_manager.heavy_memory_enter();
            let busy = app.clone().oneshot(build()).await.unwrap();
            assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(busy.headers()[header::RETRY_AFTER], "60");
            let body = json_body(busy).await;
            assert_eq!(body["error"]["code"], "HEAVY_WORK_IN_PROGRESS");
        }
        let free = app.oneshot(build()).await.unwrap();
        assert_ne!(free.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// 2.21.22 (FAIL lab 2.21.21) — sans instantané et avec un calcul en
    /// cours, `/health` en production répond aussitôt `computing`, sans attendre.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_never_waits_for_first_counters_in_production_mode() {
        use std::time::{Duration, Instant};
        let st = state();
        *st.inner.health_cache.lock().unwrap() = None;
        st.inner.health_refreshing.store(true, std::sync::atomic::Ordering::SeqCst);
        let start = Instant::now();
        let Json(value) = health_response(&st, Duration::ZERO).await;
        assert!(start.elapsed() < Duration::from_millis(50), "vu {:?}", start.elapsed());
        assert_eq!(value["data"]["counters_status"], "computing");
        assert_eq!(value["data"]["status"], "healthy");
        st.inner.health_refreshing.store(false, std::sync::atomic::Ordering::SeqCst);
        warm_health_snapshot(&st);
        let deadline = Instant::now() + Duration::from_secs(10);
        while st.inner.health_cache.lock().unwrap().is_none() && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let Json(value) = health_response(&st, Duration::ZERO).await;
        assert_eq!(value["data"]["counters_status"], "fresh");
    }

    /// 2.21.14 (règle #9 6940906119 — audit handlers) — prouve via le
    /// VRAI routeur que `/health` répond pendant qu'un `/sessions` long
    /// est en cours. Avant 2.21.14, `/sessions` itérait
    /// `datasets().callflow()` sur le runtime async : sous charge, le
    /// même profil que `/health` pré-2.21.13.
    ///
    /// Le test exploite le fait que l'instantané `/health` est servi
    /// par le cache mémoire (TTL 5 s) et que `/sessions` est désormais
    /// déporté dans `spawn_blocking` : `/health` doit répondre
    /// quasi-instantanément même pendant l'exécution de `/sessions`.
    #[tokio::test]
    async fn sessions_route_is_spawned_blocking_and_does_not_starve_health_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        // Amorce l'instantané `/health` (cache fresh).
        let _ = app
            .clone()
            .oneshot(req("/api/v1/health", false))
            .await
            .unwrap();
        // Lance `/sessions` en concurrence : va s'exécuter via
        // `spawn_blocking` et laisser le runtime libre pour `/health`.
        let app_sessions = app.clone();
        let sessions_task = tokio::spawn(async move {
            app_sessions
                .oneshot(req("/api/v1/sessions", false))
                .await
                .unwrap()
        });
        // Pendant ce temps, `/health` doit rendre un résultat `fresh` ou
        // `stale` en < 200 ms (pas d'E/S sur le chemin de requête).
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(500),
            "/health should not be starved by /sessions ; observed {:?}",
            elapsed
        );
        let sessions = sessions_task.await.unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
    }

    /// 2.21.15 (reprise #9 6941147984) — `/identities` froid = 210 s sur la
    /// session de référence lab (210 fois > 1 s). Le cache par signature
    /// de callflow évite de relancer tshark au 2e appel. Preuve :
    /// l'entrée `identity_cache` est renseignée après un appel, et une
    /// nouvelle `hydrate_identities()` avec signature inchangée court-
    /// circuite tshark (observations copiées depuis le cache).
    ///
    /// Note : le test n'invoque PAS tshark sur l'hôte de dev (outil
    /// absent dans l'environnement CI standard). Il exerce la logique
    /// cache de `hydrate_identities` en pré-remplissant l'entrée avec
    /// une signature calculée sur un vrai callflow du dataset, puis
    /// vérifie que la 2e passe ne fait AUCUN appel tshark (indicateur :
    /// ne retourne pas `TSHARK_UNAVAILABLE`).
    #[tokio::test]
    async fn identity_cache_short_circuits_tshark_on_matching_signature() {
        let st = state();
        // Prend le premier flow du dataset embarqué, construit sa signature.
        let flow = st
            .inner
            .flows
            .values()
            .next()
            .cloned()
            .expect("embedded dataset has at least one flow");
        let signature = identity_cache_signature(&flow);
        // Pré-remplit le cache pour ce session_id.
        {
            let mut guard = st.inner.identity_cache.lock().unwrap();
            guard.insert(
                flow.session_id.clone(),
                IdentityCacheEntry {
                    signature: signature.clone(),
                    observations: Vec::new(),
                },
            );
        }
        // Appelle hydrate_identities directement : doit frapper le cache.
        // Si tshark était invoqué, on obtiendrait `TSHARK_UNAVAILABLE` sur
        // l'hôte de relecture (binaire absent). Un `Ok(())` prouve le
        // court-circuit.
        let result = hydrate_identities(&st, &flow.session_id);
        assert!(
            result.is_ok(),
            "cache hit must bypass tshark ; got {:?}",
            result
        );
    }

    /// 2.21.15 — signature stable : deux appels sur le même callflow
    /// donnent la même signature SHA-256 ; une modification d'un
    /// event_id invalide l'entrée.
    #[test]
    fn identity_cache_signature_is_stable_and_detects_callflow_mutation() {
        let st = state();
        let flow = st
            .inner
            .flows
            .values()
            .next()
            .cloned()
            .expect("embedded dataset has at least one flow");
        let sig_a = identity_cache_signature(&flow);
        let sig_b = identity_cache_signature(&flow);
        assert_eq!(sig_a, sig_b, "signature must be deterministic");
        let mut mutated = flow.clone();
        if let Some(event) = mutated.events.first_mut() {
            event.event_id = format!("{}-mutated", event.event_id);
            let sig_c = identity_cache_signature(&mutated);
            assert_ne!(
                sig_a, sig_c,
                "a modified event_id must invalidate the cache entry"
            );
        }
    }

    /// 2.21.16 (audit handlers #9 6941147984, point UI `/events`) — prouve
    /// via le VRAI routeur que `/sessions/:id/events` est non-bloquant
    /// pour `/health` même en charge concurrente.
    #[tokio::test]
    async fn session_events_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let session_id = st
            .inner
            .flows
            .keys()
            .next()
            .cloned()
            .expect("embedded dataset has at least one session");
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_events = app.clone();
        let sid = session_id.clone();
        let events_task = tokio::spawn(async move {
            app_events
                .oneshot(req(&format!("/api/v1/sessions/{sid}/events"), false))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(500),
            "/health starved by /events ; elapsed {:?}",
            elapsed
        );
        let events = events_task.await.unwrap();
        assert_eq!(events.status(), StatusCode::OK);
    }

    /// 2.21.16 (audit handlers #9 6941147984, point UI `/callflow`) — même
    /// invariant pour `/sessions/:id/callflow`.
    #[tokio::test]
    async fn session_callflow_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let session_id = st
            .inner
            .flows
            .keys()
            .next()
            .cloned()
            .expect("embedded dataset has at least one session");
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_cf = app.clone();
        let sid = session_id.clone();
        let cf_task = tokio::spawn(async move {
            app_cf
                .oneshot(req(&format!("/api/v1/sessions/{sid}/callflow"), false))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(500),
            "/health starved by /callflow ; elapsed {:?}",
            elapsed
        );
        let cf = cf_task.await.unwrap();
        assert_eq!(cf.status(), StatusCode::OK);
    }

    /// 2.21.17 (audit handlers lot 2 #9 6944132663) — `/metrics` lit
    /// `measure_path(storage_path)`, `/proc/loadavg`, et parcourt les
    /// flows + capture_manager en sync. Preuve de non-blocage via VRAI
    /// routeur.
    #[tokio::test]
    async fn metrics_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_m = app.clone();
        let metrics_task = tokio::spawn(async move {
            app_m.oneshot(req("/api/v1/metrics", false)).await.unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(500),
            "/health starved by /metrics ; elapsed {:?}",
            elapsed
        );
        let metrics = metrics_task.await.unwrap();
        assert_eq!(metrics.status(), StatusCode::OK);
    }

    /// 2.21.17 — `/subscribers` consulte `cached_journey_index` qui
    /// parcourt datasets + callflows. Déport spawn_blocking vérifié
    /// via VRAI routeur.
    #[tokio::test]
    async fn subscribers_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_s = app.clone();
        let sub_task = tokio::spawn(async move {
            app_s.oneshot(req("/api/v1/subscribers", false)).await.unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(500),
            "/health starved by /subscribers ; elapsed {:?}",
            elapsed
        );
        let sub = sub_task.await.unwrap();
        assert_eq!(sub.status(), StatusCode::OK);
    }

    /// 2.21.17 — `/sessions/:id` consulte `flow_for` + `live_flow_for` +
    /// LTE catalog. Déport spawn_blocking vérifié via VRAI routeur.
    #[tokio::test]
    async fn session_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let session_id = st
            .inner
            .flows
            .keys()
            .next()
            .cloned()
            .expect("embedded dataset has at least one session");
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_s = app.clone();
        let sid = session_id.clone();
        let sess_task = tokio::spawn(async move {
            app_s
                .oneshot(req(&format!("/api/v1/sessions/{sid}"), false))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(500),
            "/health starved by /sessions/{{id}} ; elapsed {:?}",
            elapsed
        );
        let sess = sess_task.await.unwrap();
        assert_eq!(sess.status(), StatusCode::OK);
    }

    /// 2.21.19 (audit handlers lot 3 #9 6945061505) — un test VRAI
    /// routeur par route fixée : /ues, /ue/:id, /session_correlations,
    /// /packets. Chaque test lance la route lourde en concurrence et
    /// mesure `/health` qui DOIT répondre en < 500 ms.
    #[tokio::test]
    async fn ues_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_u = app.clone();
        let ues_task = tokio::spawn(async move {
            app_u.oneshot(req("/api/v1/ues", false)).await.unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /ues ; {:?}",
            start.elapsed()
        );
        assert_eq!(ues_task.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ue_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let ue_id = st
            .inner
            .discovery
            .ue_contexts
            .first()
            .map(|context| context.context_id.clone())
            .unwrap_or_else(|| "nonexistent".into());
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_u = app.clone();
        let uid = ue_id.clone();
        let ue_task = tokio::spawn(async move {
            app_u
                .oneshot(req(&format!("/api/v1/ues/{uid}"), false))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /ues/{{id}} ; {:?}",
            start.elapsed()
        );
        let _ = ue_task.await.unwrap(); // 200 ou 404 selon existence
    }

    #[tokio::test]
    async fn session_correlations_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let session_id = st
            .inner
            .flows
            .keys()
            .next()
            .cloned()
            .expect("embedded dataset has at least one session");
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_c = app.clone();
        let sid = session_id.clone();
        let c_task = tokio::spawn(async move {
            app_c
                .oneshot(req(
                    &format!("/api/v1/sessions/{sid}/correlations"),
                    false,
                ))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /sessions/:id/correlations ; {:?}",
            start.elapsed()
        );
        assert_eq!(c_task.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn packets_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_p = app.clone();
        let p_task = tokio::spawn(async move {
            app_p.oneshot(req("/api/v1/packets", false)).await.unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /packets ; {:?}",
            start.elapsed()
        );
        assert_eq!(p_task.await.unwrap().status(), StatusCode::OK);
    }

    /// 2.21.20 — tests VRAI routeur pour les handlers du lot 4.
    #[tokio::test]
    async fn subscriber_tmsi_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_s = app.clone();
        let s_task = tokio::spawn(async move {
            app_s
                .oneshot(req(
                    "/api/v1/subscribers/sha256-nonexistent/tmsi",
                    false,
                ))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /subscribers/.../tmsi ; {:?}",
            start.elapsed()
        );
        let _ = s_task.await.unwrap(); // 404 attendu sur pseudo synthétique
    }

    // 2.21.23 — règle #9 6947485672 : `subscriber_journey` ne doit
    // bloquer ni le runtime (spawn_blocking) ni la mémoire (le
    // JourneyIndex vient du cache streaming ; les flows détaillés sont
    // chargés UN PAR UN uniquement pour les sessions du subscriber).
    #[tokio::test]
    async fn subscriber_journey_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_j = app.clone();
        let j_task = tokio::spawn(async move {
            app_j
                .oneshot(req(
                    "/api/v1/subscribers/sha256-nonexistent/journey",
                    false,
                ))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /subscribers/.../journey ; {:?}",
            start.elapsed()
        );
        let _ = j_task.await.unwrap(); // 404 attendu sur pseudo synthétique
    }

    #[tokio::test]
    async fn sessions_catalog_search_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_s = app.clone();
        let s_task = tokio::spawn(async move {
            app_s
                .oneshot(req("/api/v1/sessions/catalog/search?q=Cause", false))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /sessions/catalog/search ; {:?}",
            start.elapsed()
        );
        assert_eq!(s_task.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn correlation_edges_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_e = app.clone();
        let e_task = tokio::spawn(async move {
            app_e
                .oneshot(req("/api/v1/correlation/edges", false))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /correlation_edges ; {:?}",
            start.elapsed()
        );
        assert_eq!(e_task.await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn export_callflow_route_is_spawned_blocking_real_router() {
        use std::time::{Duration, Instant};
        let st = state();
        let app = router(st.clone(), None);
        let session_id = st
            .inner
            .flows
            .keys()
            .next()
            .cloned()
            .expect("embedded dataset has at least one session");
        let _ = app.clone().oneshot(req("/api/v1/health", false)).await.unwrap();
        let app_x = app.clone();
        let sid = session_id.clone();
        let x_task = tokio::spawn(async move {
            app_x
                .oneshot(req(
                    &format!("/api/v1/sessions/{sid}/export?format=json"),
                    false,
                ))
                .await
                .unwrap()
        });
        let start = Instant::now();
        let health = app.oneshot(req("/api/v1/health", false)).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "/health starved by /sessions/.../export ; {:?}",
            start.elapsed()
        );
        let _ = x_task.await.unwrap();
    }

    /// 2.19.1 — `/sessions/catalog/search?q=` renvoie des matches
    /// triés par pertinence et aucun n'est en clair.
    #[tokio::test]
    async fn sessions_catalog_search_returns_relevance_sorted_results() {
        let state = state();
        let router = router(state.clone(), None);
        let request = Request::builder()
            .uri("/api/v1/sessions/catalog/search?q=Cause")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let results = body["data"]["results"].as_array().expect("results array");
        // Dataset de test porte `Cause` dans NGAP/PFCP → au moins 1 match.
        if !results.is_empty() {
            let first = &results[0];
            assert!(first["interface"].is_string());
            assert!(first["protocol"].is_string());
            assert!(first["message"].is_string());
            assert!(first["occurrences"].is_number());
        }
        assert_no_identity_material(&body);
    }

    /// 2.19.1 — `/sessions/catalog/search` sans `q` → 400
    /// `SEARCH_QUERY_EMPTY`.
    #[tokio::test]
    async fn sessions_catalog_search_without_q_returns_400() {
        let state = state();
        let router = router(state.clone(), None);
        let request = Request::builder()
            .uri("/api/v1/sessions/catalog/search")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["error"]["code"], "SEARCH_QUERY_EMPTY");
    }

    /// 2.19.1 — `/sessions/catalog/param` sur un paramètre observé
    /// retourne la fiche détaillée. Paramètre non observé → 404
    /// `PARAM_NOT_OBSERVED`.
    #[tokio::test]
    async fn sessions_catalog_param_returns_detail_or_404() {
        let state = state();
        let router = router(state.clone(), None);
        // Essai sur un path sûrement inexistant.
        let request = Request::builder()
            .uri("/api/v1/sessions/catalog/param?interface=N2&protocol=NGAP&message=PDUSessionResourceSetupResponse&param_path=NoSuchParamHere")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = json_body(response).await;
        assert_eq!(body["error"]["code"], "PARAM_NOT_OBSERVED");
    }

    /// 2.19.1 — `POST /sessions/filter` avec `limit=0` ne renvoie
    /// aucune ligne, seulement `meta.total` + `meta.preview=true`.
    #[tokio::test]
    async fn sessions_filter_limit_zero_returns_only_total_preview() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 0,
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
        assert!(body["meta"]["total"].as_u64().is_some());
        assert_eq!(body["meta"]["preview"], true);
        // Comparaison : même total que l'appel non-preview.
        let (_, body_full) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(body["meta"]["total"], body_full["meta"]["total"]);
    }

    /// 2.19.1 — `criteria` + `combinator=and` filtre les sessions
    /// et publie `matched_criteria` dans chaque ligne. Vérifie que
    /// chaque hit pointe un event existant (event_id non vide).
    #[tokio::test]
    async fn sessions_filter_criteria_and_publishes_matched_criteria() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 100,
                "combinator": "and",
                "criteria": [
                    {
                        "message": "PDUSessionResourceSetupResponse",
                        "op": "eq",
                        "value": "cause=1",
                        "param_path": "Cause",
                    }
                ],
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["criteria_combinator"], "and");
        for item in body["data"].as_array().unwrap() {
            let hits = item["matched_criteria"].as_array().expect("hits array");
            // Session a passé le filtre AND → ≥ 1 hit.
            assert!(!hits.is_empty());
            for hit in hits {
                assert!(hit["event_id"].is_string());
                assert!(hit["capture_id"].is_string());
                assert!(hit["seq"].is_number());
                assert_eq!(hit["criterion_index"], 0);
            }
        }
    }

    /// 2.19.1 — `combinator=or` passe la session dès qu'un
    /// critère matche.
    #[tokio::test]
    async fn sessions_filter_criteria_or_passes_on_single_match() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "limit": 100,
                "combinator": "or",
                "criteria": [
                    {
                        "message": "DoesNotExistAnywhere",
                        "op": "eq",
                        "value": "_",
                    },
                    {
                        "message": "PDUSessionResourceSetupResponse",
                        "op": "eq",
                        "value": "cause=1",
                        "param_path": "Cause",
                    }
                ],
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["meta"]["criteria_combinator"], "or");
        // Les sessions retournées doivent toutes avoir au moins
        // un match sur l'une des deux critères (hit du 2e).
        for item in body["data"].as_array().unwrap() {
            let hits = item["matched_criteria"].as_array().expect("hits array");
            assert!(hits.iter().any(|h| h["criterion_index"] == 1));
        }
    }

    /// 2.19.1 — `POST /sessions/columns` avec `fields[]` publie
    /// value + proof par session.
    #[tokio::test]
    async fn sessions_columns_fields_publish_value_and_proof() {
        let state = state();
        let (_, filter_body) =
            post_sessions_filter(&state, json!({"limit": 3}), None).await;
        let real_ids: Vec<String> = filter_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|item| item["session_id"].as_str().map(str::to_owned))
            .collect();
        if real_ids.is_empty() {
            return;
        }
        let router = router(state.clone(), None);
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/sessions/columns")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "session_ids": real_ids,
                    "columns": ["state"],
                    "fields": [
                        {
                            "interface": "N2",
                            "protocol": "NGAP",
                            "message": "PDUSessionResourceSetupResponse",
                            "param_path": "Cause",
                            "mode": "last"
                        }
                    ]
                })
                .to_string(),
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        for item in body["data"].as_array().unwrap() {
            let fields = item["fields"].as_array().expect("fields array");
            assert_eq!(fields.len(), 1);
            let field = &fields[0];
            assert_eq!(field["interface"], "N2");
            assert_eq!(field["protocol"], "NGAP");
            assert_eq!(field["mode"], "last");
            // value peut être présent (Value) ou Null si l'event
            // n'a pas été observé — mais le proof est consistant.
            if field["value"].is_null() {
                assert_eq!(field["proof"].as_array().unwrap().len(), 0);
            } else {
                assert!(!field["proof"].as_array().unwrap().is_empty());
                let proof = &field["proof"][0];
                assert!(proof["event_id"].is_string());
                assert!(proof["capture_id"].is_string());
                assert!(proof["seq"].is_number());
            }
        }
        assert_eq!(body["meta"]["field_count"], 1);
    }

    /// 2.19.1 — rétro-compat avec la shape 2.19.0 : `{limit:100}`
    /// seul retourne exactement le même set de lignes qu'en 2.19.0.
    #[tokio::test]
    async fn sessions_filter_body_limit100_remains_retrocompat_with_2_19_0() {
        let state = state();
        let (status, body) = post_sessions_filter(&state, json!({"limit": 100}), None).await;
        assert_eq!(status, StatusCode::OK);
        // meta.pagination_key inchangée.
        assert_eq!(
            body["meta"]["pagination_key"],
            "(anchor_capture_id, first_packet_number, session_id)"
        );
        // matched_criteria ABSENT si criteria vide (compat).
        for item in body["data"].as_array().unwrap() {
            assert!(
                item.get("matched_criteria").is_none()
                    || item["matched_criteria"].as_array().map_or(0, Vec::len) == 0,
                "matched_criteria must not leak when no criteria provided"
            );
        }
    }

    /// 2.19.1 — un critère avec op inconnu → 400 `UNKNOWN_CRITERION_OP`.
    #[tokio::test]
    async fn sessions_filter_unknown_criterion_op_returns_400() {
        let state = state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "criteria": [{
                    "message": "AnyMessage",
                    "op": "like",
                }]
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "UNKNOWN_CRITERION_OP");
    }

    #[tokio::test]
    async fn sessions_filter_pagination_uses_capture_packet_session_not_ts() {
        // 2.10.1 (revue devmat) : la réponse doit documenter
        // explicitement sa clé de pagination et NE JAMAIS
        // contenir `start_timestamp` dans le tri. On vérifie :
        //   * `meta.pagination_key` annonce la clé canonique.
        //   * `meta.next_cursor` existe ou est null (jamais un
        //     ts).
        //   * `data` est trié par (capture_id, …) et la paire
        //     consécutive n'est pas monotone en start_timestamp
        //     seul — ce qui serait la signature d'un tri sur
        //     `ts`.
        let state = state();
        let (status, body) = post_sessions_filter(&state, json!({ "limit": 5 }), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["meta"]["pagination_key"],
            "(anchor_capture_id, first_packet_number, session_id)"
        );
        // next_cursor doit être une string de session_id ou
        // null — JAMAIS un timestamp.
        match &body["meta"]["next_cursor"] {
            Value::Null => {}
            Value::String(cursor) => {
                assert!(
                    !cursor.contains('T') || !cursor.ends_with('Z'),
                    "next_cursor looks like a timestamp (ANR2 rule « jamais ts ») : {cursor}"
                );
            }
            other => panic!("next_cursor must be string or null, got: {other}"),
        }
        // Tri : vérifier que les items retournés sont
        // ordonnés par (capture_id, session_id) — leur
        // start_timestamp n'a aucune garantie de monotonie.
        let data = body["data"].as_array().expect("data array");
        for pair in data.windows(2) {
            let ka = (
                pair[0]["capture_id"].as_str().unwrap_or(""),
                pair[0]["session_id"].as_str().unwrap_or(""),
            );
            let kb = (
                pair[1]["capture_id"].as_str().unwrap_or(""),
                pair[1]["session_id"].as_str().unwrap_or(""),
            );
            assert!(
                ka <= kb,
                "pagination out of canonical order: {ka:?} vs {kb:?}"
            );
        }
    }

    #[tokio::test]
    async fn sessions_filter_cursor_advances_without_duplicates() {
        // 2.10.1 : deux pages consécutives via `cursor` ne
        // doivent pas se chevaucher, ni introduire de session
        // deux fois.
        let state = state();
        let (_, body_a) = post_sessions_filter(&state, json!({ "limit": 1 }), None).await;
        let first = body_a["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|s| s["session_id"].as_str())
            .map(str::to_owned);
        let cursor = body_a["meta"]["next_cursor"].as_str().map(str::to_owned);
        if let (Some(first_id), Some(cursor_val)) = (first, cursor) {
            let (_, body_b) =
                post_sessions_filter(&state, json!({ "limit": 1, "cursor": cursor_val }), None)
                    .await;
            let second = body_b["data"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|s| s["session_id"].as_str())
                .map(str::to_owned);
            if let Some(second_id) = second {
                assert_ne!(
                    first_id, second_id,
                    "cursor must not re-emit the same session_id"
                );
            }
        }
    }

    #[tokio::test]
    async fn sessions_filter_unknown_identity_kind_rejected() {
        let state = operator_state();
        let (status, body) = post_sessions_filter(
            &state,
            json!({
                "identity": {"kind": "not_a_kind", "value": "whatever"}
            }),
            Some("test-operator-token"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "IDENTITY_KIND_UNKNOWN");
    }

    #[tokio::test]
    async fn clear_identity_routes_are_operator_only_and_keep_packet_proof() {
        let viewer = router(state(), None)
            .oneshot(req("/api/v1/sessions/anything/identities", true))
            .await
            .unwrap();
        assert_eq!(viewer.status(), StatusCode::FORBIDDEN);

        let state = operator_state();
        let session_id = state.inner.primary_session_id.clone();
        let synthetic_identity = ["001", "01", "012", "345", "6789"].concat();
        state
            .inner
            .identity_vault
            .upsert(vec![IdentityObservation {
                session_id: session_id.clone(),
                subscriber_pseudonym: Some("psn-test-00101".into()),
                kind: "imsi".into(),
                value: synthetic_identity.clone(),
                value_type: Some("IMSI".into()),
                role: "presented".into(),
                event_id: "event-test-identity".into(),
                capture_id: "capture-test-identity".into(),
                packet_number: 15,
                cleartext: None,
            }])
            .unwrap();
        let response = router(state.clone(), None)
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/sessions/{session_id}/identities"))
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert!(body["data"]["imsi"].is_string());
        assert_eq!(body["meta"]["identity_access"], "operator");

        // 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-04) — ancien GET
        // retourne désormais 410 Gone **sans** echo de la valeur. Nous
        // validons ici que la réponse ne contient PAS la valeur en
        // clair, et que le `Link` header pointe vers le successeur.
        let gone_response = router(state.clone(), None)
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/api/v1/identities?q={synthetic_identity}&page=1&page_size=1"
                    ))
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(gone_response.status(), StatusCode::GONE);
        assert_eq!(
            gone_response
                .headers()
                .get("Link")
                .and_then(|v| v.to_str().ok()),
            Some("</api/v1/identities/lookup>; rel=\"successor-version\"")
        );
        let gone_body = json_body(gone_response).await;
        assert!(
            !gone_body.to_string().contains(&synthetic_identity),
            "410 body must not echo the clear-text value"
        );

        // Le successeur `POST /identities/lookup` prend la valeur dans
        // le corps JSON, jamais dans l'URL.
        let csrf = sha256_hex(b"oiran-csrf-v1:test-operator-token");
        let response = router(state, None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/identities/lookup")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .header(CSRF_HEADER, csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "value": synthetic_identity,
                            "page": 1,
                            "page_size": 1,
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["data"]["sessions"][0], session_id);
        assert_eq!(body["data"]["pagination"]["page"], 1);
        assert_eq!(body["data"]["pagination"]["page_size"], 1);
        assert_eq!(body["data"]["pagination"]["total"], 1);
        assert!(body.to_string().contains("event-test-identity"));
        assert!(body.to_string().contains("\"packet_number\":15"));
    }

    /// 2.21.92 (défaut bloquant ANR1 #10 7035121536) — la logique de garde
    /// est pure : refuse une bascule avec `session_count != published`, ok
    /// sinon (y compris « vrai zéro » 0/0 avant toute publication). Prouve
    /// que le scénario observé en recette (`candidate=0, published=325`)
    /// renvoie bien `session_count_mismatch`.
    #[test]
    fn swap_refusal_reason_catches_empty_candidate_against_published_2_21_92() {
        // Scénario ANR1 : candidate vide alors que /health annonce 325.
        assert_eq!(
            swap_refusal_reason(0, 325),
            Some("session_count_mismatch")
        );
        // Candidat tronqué (ex. 324 contre 325) : attrapé aussi.
        assert_eq!(
            swap_refusal_reason(324, 325),
            Some("session_count_mismatch")
        );
        // Candidat surdimensionné (improbable mais détecté) : attrapé.
        assert_eq!(
            swap_refusal_reason(326, 325),
            Some("session_count_mismatch")
        );
        // Match exact : bascule OK.
        assert_eq!(swap_refusal_reason(325, 325), None);
        // Vrai zéro (bootstrapping) : bascule OK.
        assert_eq!(swap_refusal_reason(0, 0), None);
    }

    /// 2.21.92 — `published_session_count_snapshot` suit strictement la
    /// logique /health.published_session_count : `flows.len()` OR, si vide,
    /// `continuous.session_ids.len()`. Preuve que l'oracle de la garde est
    /// stable sur un `operator_state()` (qui charge le reference dataset en
    /// mode test) : snapshot == flows.len() tant que flows > 0.
    #[test]
    fn published_session_count_snapshot_follows_flows_count_2_21_92() {
        let state = operator_state();
        let flows_count = state.inner.flows.len() as u64;
        let snapshot = published_session_count_snapshot(&state);
        assert_eq!(
            snapshot, flows_count,
            "snapshot doit refléter flows.len() quand > 0"
        );
    }

    /// 2.21.92 — `record_swap_refused` incrémente le compteur global et
    /// publie toutes les coordonnées du refus (trigger, reason, candidate,
    /// published, epoch_ms) dans `generation_swap_refused`.
    #[test]
    fn record_swap_refused_updates_counter_and_last_fields_2_21_92() {
        let state = operator_state();
        {
            let g = state.inner.generation_swap_refused.lock().unwrap();
            assert_eq!(g.total, 0);
            assert!(g.last_reason.is_none());
        }
        record_swap_refused(
            &state,
            "test-publication",
            "session_count_mismatch",
            Some(0),
            Some(325),
        );
        record_swap_refused(
            &state,
            "test-startup",
            "session_filter_index_lock_poisoned",
            None,
            None,
        );
        let g = state.inner.generation_swap_refused.lock().unwrap();
        assert_eq!(g.total, 2);
        assert_eq!(g.last_trigger.as_deref(), Some("test-startup"));
        assert_eq!(
            g.last_reason.as_deref(),
            Some("session_filter_index_lock_poisoned")
        );
        assert_eq!(g.last_candidate_session_count, None);
        assert_eq!(g.last_reference_session_count, None);
        assert!(g.last_epoch_ms.is_some());
    }

    /// 2.21.92 — `/health` expose `sessions_filter_generation_swap_refused`
    /// avec le total et les dernières coordonnées (shape complète, visible
    /// à l'opérateur). Preuve négative : à l'état initial, `total=0` et
    /// aucun `last_*`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_exposes_sessions_filter_generation_swap_refused_counter_2_21_92() {
        let state = operator_state();
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let node = &body["data"]["sessions_filter_generation_swap_refused"];
        assert_eq!(node["total"], 0);
        assert!(node.get("last_reason").map(Value::is_null).unwrap_or(false));
        // Incrémentons le compteur et vérifions la remontée.
        record_swap_refused(
            &state,
            "test-publication",
            "session_count_mismatch",
            Some(0),
            Some(325),
        );
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        let node = &body["data"]["sessions_filter_generation_swap_refused"];
        assert_eq!(node["total"], 1);
        assert_eq!(node["last_reason"], "session_count_mismatch");
        assert_eq!(node["last_trigger"], "test-publication");
        assert_eq!(node["last_candidate_session_count"], 0);
        assert_eq!(node["last_reference_session_count"], 325);
        assert!(node["last_epoch_ms"].as_u64().unwrap_or(0) > 0);
    }

    /// 2.21.92 raffinement (ordre #9 7036719807 trou 1) — la règle
    /// « une génération à 0 session ne remplace jamais une génération non
    /// vide sur un seul préchauffage » encodée par
    /// `empty_after_nonempty_decision` :
    ///   * first-boot (previous None) ⇒ Accept (vrai zéro bootstrap),
    ///   * vrai zéro continu (previous Some(0)) ⇒ Accept,
    ///   * prev non vide, aucun pending ⇒ RefuseAndMarkPending,
    ///   * prev non vide, pending expiré ⇒ RefuseAndMarkPending,
    ///   * prev non vide, pending valide ⇒ AcceptConfirmed,
    ///   * (candidate, published) != (0,0) ⇒ NotApplicable.
    #[test]
    fn empty_after_nonempty_decision_matrix_2_21_92() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        // First-boot : Accept.
        assert_eq!(
            empty_after_nonempty_decision(0, 0, None, None, now, false),
            EmptyAfterNonemptyDecision::Accept
        );
        // Vrai zéro continu : Accept.
        assert_eq!(
            empty_after_nonempty_decision(0, 0, Some(0), None, now, false),
            EmptyAfterNonemptyDecision::Accept
        );
        // Prev non vide, sans pending : refuse + marque pending.
        assert_eq!(
            empty_after_nonempty_decision(0, 0, Some(325), None, now, false),
            EmptyAfterNonemptyDecision::RefuseAndMarkPending
        );
        // Prev non vide, pending valide, trigger non-retry (publication) : AcceptConfirmed.
        assert_eq!(
            empty_after_nonempty_decision(
                0,
                0,
                Some(325),
                Some(now + Duration::from_secs(10)),
                now,
                false,
            ),
            EmptyAfterNonemptyDecision::AcceptConfirmed
        );
        // Prev non vide, pending expiré : refuse à nouveau.
        assert_eq!(
            empty_after_nonempty_decision(
                0,
                0,
                Some(325),
                Some(now - Duration::from_secs(1)),
                now,
                false,
            ),
            EmptyAfterNonemptyDecision::RefuseAndMarkPending
        );
        // (3, 3) match exact : NotApplicable (traité par swap_refusal_reason).
        assert_eq!(
            empty_after_nonempty_decision(3, 3, Some(325), None, now, false),
            EmptyAfterNonemptyDecision::NotApplicable
        );
        // (0, 5) mismatch : NotApplicable (traité par swap_refusal_reason).
        assert_eq!(
            empty_after_nonempty_decision(0, 5, Some(325), None, now, false),
            EmptyAfterNonemptyDecision::NotApplicable
        );
    }

    /// 2.21.92 micro-raffinement (ordre #9 7037361185) — la confirmation du
    /// zéro NE DOIT venir QUE d'une publication terminée (trigger non-retry).
    /// Un ré-essai qui revoit `(0,0)` prolonge l'attente, ne confirme pas :
    /// sinon la 2e observation peut tomber dans la MÊME fenêtre intermédiaire
    /// que la 1re.
    #[test]
    fn empty_after_nonempty_decision_retry_never_confirms_2_21_92() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let pending_valid = Some(now + Duration::from_secs(10));
        // Trigger = ré-essai (retry-after-refusal) : même pending valide,
        // DOIT prolonger l'attente, PAS confirmer.
        assert_eq!(
            empty_after_nonempty_decision(0, 0, Some(325), pending_valid, now, true),
            EmptyAfterNonemptyDecision::RefuseAndMarkPending,
            "un retry NE DOIT PAS confirmer la 2e observation (0,0) : il peut tourner dans la même fenêtre intermédiaire que la 1re"
        );
        // Trigger = publication terminée : confirme.
        assert_eq!(
            empty_after_nonempty_decision(0, 0, Some(325), pending_valid, now, false),
            EmptyAfterNonemptyDecision::AcceptConfirmed,
            "une publication terminée (non-retry) confirme la 2e observation (0,0)"
        );
    }

    /// 2.21.92 raffinement (ordre #9 7036719807 trou 2) —
    /// `retry_attempt_from_trigger` parse le numéro depuis des triggers
    /// comme `"retry-2-after-publication"`. Trigger brut (non-retry) ⇒ 0.
    #[test]
    fn retry_attempt_from_trigger_parses_2_21_92() {
        assert_eq!(retry_attempt_from_trigger("publication"), 0);
        assert_eq!(retry_attempt_from_trigger("startup"), 0);
        assert_eq!(retry_attempt_from_trigger("retry-1-after-publication"), 1);
        assert_eq!(retry_attempt_from_trigger("retry-2-after-retry-1-after-publication"), 2);
        assert_eq!(retry_attempt_from_trigger("retry-3-after-startup"), 3);
        // Malformed : pas de -after- ou numéro invalide.
        assert_eq!(retry_attempt_from_trigger("retry-publication"), 0);
        assert_eq!(retry_attempt_from_trigger("retry-abc-after-x"), 0);
    }

    /// 2.21.92 raffinement (ordre #9 7036719807 trou 2) — `record_swap_refused`
    /// avec une raison retryable programme automatiquement une tentative
    /// (incrément du compteur) ; `*_lock_poisoned` n'est pas retryable.
    /// Sous `cfg(test)`, le thread réel n'est pas lancé — seule la trace et
    /// l'incrément du compteur sont observables.
    #[test]
    fn record_swap_refused_schedules_retry_for_retryable_reasons_2_21_92() {
        let state = operator_state();
        // session_count_mismatch ⇒ retry programmé.
        record_swap_refused(
            &state,
            "publication",
            "session_count_mismatch",
            Some(0),
            Some(325),
        );
        let after_mismatch = *state.inner.generation_swap_retry_scheduled.lock().unwrap();
        assert_eq!(after_mismatch, 1, "mismatch doit programmer 1 retry");
        // empty_after_nonempty_unconfirmed ⇒ retry programmé.
        record_swap_refused(
            &state,
            "publication",
            "empty_after_nonempty_unconfirmed",
            Some(0),
            Some(0),
        );
        let after_empty = *state.inner.generation_swap_retry_scheduled.lock().unwrap();
        assert_eq!(after_empty, 2, "empty_after_nonempty doit programmer 1 retry de plus");
        // *_lock_poisoned ⇒ PAS retryable (irrécupérable intra-process).
        record_swap_refused(
            &state,
            "publication",
            "session_filter_index_lock_poisoned",
            None,
            None,
        );
        let after_poisoned = *state.inner.generation_swap_retry_scheduled.lock().unwrap();
        assert_eq!(after_poisoned, 2, "lock_poisoned NE DOIT PAS programmer de retry");
        // attempt > 3 ⇒ no retry (exhausted).
        record_swap_refused(
            &state,
            "retry-3-after-publication",
            "session_count_mismatch",
            Some(0),
            Some(325),
        );
        let after_exhaust = *state.inner.generation_swap_retry_scheduled.lock().unwrap();
        assert_eq!(
            after_exhaust, 2,
            "attempt=4 (>3) doit s'arrêter avec SWAP_RETRY_EXHAUSTED, pas incrémenter"
        );
    }

    /// 2.21.92 raffinement — `/health.sessions_filter_generation_swap_refused`
    /// expose aussi `retries_scheduled_total` (compteur global des retries
    /// programmés depuis le démarrage).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_exposes_retries_scheduled_total_2_21_92() {
        let state = operator_state();
        record_swap_refused(
            &state,
            "publication",
            "session_count_mismatch",
            Some(0),
            Some(325),
        );
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        let node = &body["data"]["sessions_filter_generation_swap_refused"];
        assert_eq!(node["total"], 1);
        assert_eq!(node["retries_scheduled_total"], 1);
    }

    /// 2.21.92 (défaut bloquant ANR1 #10 7035121536) — sur un state
    /// `operator_state()` où `flows.len() == published_session_count`,
    /// `prewarm` bascule une génération READY sans refus : la garde
    /// `swap_refusal_reason` ne franchit PAS un état cohérent. Reproduit la
    /// preuve négative (bootstrap normal) après installation du correctif.
    /// La reproduction positive (candidate=0 alors que published=N) est
    /// couverte par la logique pure
    /// `swap_refusal_reason_catches_empty_candidate_against_published_2_21_92`
    /// et l'intégration live sous `publication` + concurrence capture_manager
    /// (hors périmètre d'un test unitaire car nécessite un état incohérent
    /// `flows`/`filter_index` forgé via mutations instables d'`Arc<InnerState>`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn prewarm_consistent_state_swaps_without_refusal_2_21_92() {
        let state = operator_state();
        // 2.21.94 (ordre #9 7040291627) — la référence de la garde est
        // désormais `queryable_session_ids(state).len()` (même source que
        // `/health.session_count`) au lieu de `published_session_count_snapshot`.
        let reference = queryable_session_ids(&state).len() as u64;
        install_session_filter_cache_prewarm(&state);
        {
            let _gate = state.inner.capture_manager.heavy_memory_enter();
            prewarm_session_filter_caches_locked(&state, "test-consistent");
        }
        let slot = state
            .inner
            .generation_slot
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|g| (g.generation, g.session_count)));
        let Some((gen, session_count)) = slot else {
            panic!("generation_slot doit être Some après prewarm d'un état cohérent");
        };
        assert!(gen >= 1, "generation doit être positive, got {gen}");
        assert_eq!(
            session_count, reference,
            "session_count de la génération doit matcher queryable_session_ids(state).len()"
        );
        let g = state.inner.generation_swap_refused.lock().unwrap();
        assert_eq!(
            g.total, 0,
            "aucun refus attendu sur un état cohérent flows/filter_index"
        );
        // Et aucune bascule-avec-avertissement non plus (référence match).
        let g2 = state
            .inner
            .generation_swap_accepted_with_mismatch
            .lock()
            .unwrap();
        assert_eq!(g2.total, 0, "aucune bascule avec avertissement attendue");
    }

    /// 2.21.94 (défaut bloquant prod ANR1 #10 7040235279) — fonction pure
    /// `should_accept_with_mismatch` : jamais 503 permanent, mais jamais
    /// bascule à vide par ce chemin.
    #[test]
    fn should_accept_with_mismatch_matrix_2_21_94() {
        // candidate == reference : pas d'écart, pas applicable (None).
        assert_eq!(should_accept_with_mismatch(329, 329, 0, true), None);
        // candidate == 0 : règle vide-après-non-vide reste stricte (None).
        assert_eq!(should_accept_with_mismatch(0, 329, 0, true), None);
        assert_eq!(should_accept_with_mismatch(0, 329, 3, true), None);
        // Pas de génération précédente, candidat non vide : jamais 503
        // permanent → no_previous_generation.
        assert_eq!(
            should_accept_with_mismatch(329, 327, 0, false),
            Some("no_previous_generation")
        );
        // Génération précédente, attempt < 3 : laisse le retry travailler.
        assert_eq!(should_accept_with_mismatch(329, 327, 0, true), None);
        assert_eq!(should_accept_with_mismatch(329, 327, 2, true), None);
        // Génération précédente, attempt >= 3 : recours
        // retries_exhausted.
        assert_eq!(
            should_accept_with_mismatch(329, 327, 3, true),
            Some("retries_exhausted")
        );
        assert_eq!(
            should_accept_with_mismatch(329, 327, 10, true),
            Some("retries_exhausted")
        );
    }

    /// 2.21.94 (défaut bloquant prod ANR1 #10 7040235279) — scénario (a) :
    /// un dataset continu de N publie + un autre dataset de M publie
    /// ⇒ queryable_session_ids(state).len() = N+M = filter_index.session_count().
    /// La garde ne refuse plus (comme en 2.21.92 avec `published_session_count`),
    /// aucune bascule-avec-avertissement, 0 refus.
    ///
    /// Note : `operator_state()` a 2 flows et 0 autre dataset, donc on teste
    /// la propriété "queryable couvre l'union", mais dans sa forme la plus
    /// simple. Un dataset additionnel exigerait `AppState::load_with_capture_manager`
    /// + manifests (hors périmètre d'un test unitaire ; cf. le test gc_survival
    /// 2.21.85 pour un setup live).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reference_is_queryable_session_ids_not_published_2_21_94() {
        let state = operator_state();
        let queryable = queryable_session_ids(&state).len() as u64;
        install_session_filter_cache_prewarm(&state);
        {
            let _gate = state.inner.capture_manager.heavy_memory_enter();
            prewarm_session_filter_caches_locked(&state, "test-reference-queryable");
        }
        let gen_sc = state
            .inner
            .generation_slot
            .read()
            .ok()
            .and_then(|s| s.as_ref().map(|g| g.session_count))
            .expect("generation_slot doit être Some");
        assert_eq!(
            gen_sc, queryable,
            "session_count doit matcher queryable_session_ids"
        );
        let refused = state.inner.generation_swap_refused.lock().unwrap().total;
        let accepted_mm = state
            .inner
            .generation_swap_accepted_with_mismatch
            .lock()
            .unwrap()
            .total;
        assert_eq!(refused, 0, "aucun refus sur état cohérent");
        assert_eq!(accepted_mm, 0, "aucune bascule avec avertissement sur état cohérent");
    }

    /// 2.21.94 (défaut bloquant prod ANR1 #10 7040235279, scénario b) —
    /// premier démarrage avec un écart artificiel : `generation_slot=None`
    /// + écart candidate != reference ⇒ bascule MALGRÉ l'écart avec
    /// événement `SESSIONS_FILTER_GENERATION_SWAP_ACCEPTED_WITH_MISMATCH`
    /// (reason `session_count_mismatch`, scenario `no_previous_generation`).
    /// Jamais 503 permanent.
    #[test]
    fn accept_with_mismatch_no_previous_generation_never_503_2_21_94() {
        let state = operator_state();
        // Simule un écart de référence : forçons une bascule-avec-mismatch
        // directement via le helper enregistreur (la logique de production
        // est couverte par `should_accept_with_mismatch_matrix` + le callsite
        // de `prewarm_session_filter_caches_locked`).
        record_swap_accepted_with_mismatch(
            &state,
            "publication",
            "session_count_mismatch",
            "no_previous_generation",
            329,
            327,
        );
        let g = state
            .inner
            .generation_swap_accepted_with_mismatch
            .lock()
            .unwrap();
        assert_eq!(g.total, 1);
        assert_eq!(g.last_scenario.as_deref(), Some("no_previous_generation"));
        assert_eq!(g.last_candidate_session_count, Some(329));
        assert_eq!(g.last_reference_session_count, Some(327));
        assert_eq!(g.last_reason.as_deref(), Some("session_count_mismatch"));
    }

    /// 2.21.94 (défaut bloquant prod ANR1 #10 7040235279, scénario c) —
    /// `candidate==0` avec `reference>0` et génération précédente ⇒
    /// `should_accept_with_mismatch` retourne None (règle vide stricte
    /// préservée). Les ré-essais sont la bonne mécanique ; attendre une
    /// publication terminée vraie-zéro-confirmée est nécessaire.
    #[test]
    fn accept_with_mismatch_rejects_empty_candidate_2_21_94() {
        // Pas de bascule-avec-avertissement quand candidate=0, quel que
        // soit le nombre de retries déjà épuisés.
        assert_eq!(should_accept_with_mismatch(0, 329, 0, true), None);
        assert_eq!(should_accept_with_mismatch(0, 329, 3, true), None);
        assert_eq!(should_accept_with_mismatch(0, 329, 10, true), None);
        // Même sans génération précédente : candidate=0 ne bascule pas.
        assert_eq!(should_accept_with_mismatch(0, 329, 0, false), None);
    }

    /// 2.21.94 — `/health` expose `sessions_filter_generation_swap_accepted_with_mismatch`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn health_exposes_swap_accepted_with_mismatch_counter_2_21_94() {
        let state = operator_state();
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        let node = &body["data"]["sessions_filter_generation_swap_accepted_with_mismatch"];
        assert_eq!(node["total"], 0);
        assert!(node["last_scenario"].is_null());
        // Enregistre une bascule-avec-avertissement : re-check /health.
        record_swap_accepted_with_mismatch(
            &state,
            "publication",
            "session_count_mismatch",
            "no_previous_generation",
            329,
            327,
        );
        let app = router(state.clone(), None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = json_body(response).await;
        let node = &body["data"]["sessions_filter_generation_swap_accepted_with_mismatch"];
        assert_eq!(node["total"], 1);
        assert_eq!(node["last_reason"], "session_count_mismatch");
        assert_eq!(node["last_scenario"], "no_previous_generation");
        assert_eq!(node["last_candidate_session_count"], 329);
        assert_eq!(node["last_reference_session_count"], 327);
    }

    /// 2.21.95 (défaut recette #10 7039298457, ordre #9 7039438165) —
    /// test de bout en bout par la route `/sessions/:id/callflow`.
    ///
    /// ANR1 a mesuré 0/1738 events portant `stable_event_key` sur 2.21.93
    /// (`CallFlowEvent` ne déclarait pas le champ). Le présent test
    /// exerce la chaîne **complète côté API** :
    ///   1. écrit un `callflow.json` sur disque, dont chaque event
    ///      porte un `stable_event_key` conforme au format publié par
    ///      2.21.91 (`{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}`) ;
    ///   2. configure `AppState` pour ce callflow comme flow primaire
    ///      (`ApiConfig::callflow_json`) ;
    ///   3. appelle `GET /api/v1/sessions/:id/callflow` via router ;
    ///   4. assert **100 %** des events exposés portent `stable_event_key`
    ///      non vide et non équivoque (contient le séparateur `|`).
    ///
    /// Invariant du design : la valeur renvoyée est celle qu'aurait
    /// émise `derive_stable_event_key(basename, iid, pkt, off, protocol,
    /// ordinal)` — la même fonction qu'utilise le flux SSE, donc elle
    /// coïncide par construction pour un même paquet (voir
    /// `oiran-decode::tests/stable_event_key_parity.rs`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_callflow_route_exposes_stable_event_key_on_every_event_2_21_95() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dataset_name = format!("callflow-stable-key-{suffix}");
        let dataset_dir_guard =
            AutoRemoveDir::new(workspace.join("datasets").join(&dataset_name));
        let dataset_dir = dataset_dir_guard.as_pathbuf();
        let session_id = "sess-stable-key-2-21-95";

        // 5 events N2, chacun avec un stable_event_key distinct (différent
        // protocol ou ordinal) — matrice minimale pour prouver l'unicité
        // par event + propagation 1:1.
        let make_event = |event_id: &str,
                          packet_number: u64,
                          byte_offset: u64,
                          protocol: &str,
                          ordinal: u32| {
            let stable_key =
                format!("N2.pcapng|0|{packet_number}|{byte_offset}|{protocol}|{ordinal}");
            json!({
                "event_id": event_id,
                "stable_event_key": stable_key,
                "timestamp": "2026-11-20T10:00:00.000000000Z",
                "timestamp_ns": "0",
                "interface": "N2",
                "protocol": protocol,
                "message_name": "InitialUEMessage",
                "source_participant": "gNB",
                "destination_participant": "AMF",
                "direction": "RAN_TO_CORE",
                "decoded_ie_tree": [],
                "decoding_status": "DECODED",
                "semantic_status": "EXACT",
                "association": "SESSION",
                "procedure_group": "Registration",
                "packet_references": [{
                    "source_file": "/var/lib/oiran/ring/n2/N2.pcapng",
                    "packet_number": packet_number,
                    "byte_offset": byte_offset,
                    "interface_id": 0u32,
                    "captured_length": 64u32,
                    "original_length": 64u32,
                }],
                "capture_id": "sha256:cap-stable-key-test",
                "decoder_name": "decoder-ngap",
                "decoder_version": "0.6.3",
                "raw_payload_reference": "sha256:payload",
                "errors": [],
            })
        };
        let events = json!([
            make_event("evt-ngap-init-01", 7, 40, "NGAP", 0),
            // NAS enfant sur le même paquet → même prefix, protocol+ordinal différents.
            make_event("evt-nas-regreq-01", 7, 40, "NAS-5GS-MM", 1),
            make_event("evt-ngap-init-02", 12, 200, "NGAP", 0),
            make_event("evt-nas-regreq-02", 12, 200, "NAS-5GS-MM", 1),
            make_event("evt-ngap-release-03", 42, 1_024, "NGAP", 0),
        ]);
        let callflow = json!({
            "callflow_id": format!("cf-{session_id}"),
            "session_id": session_id,
            "technology": "5G SA",
            "start_timestamp": "2026-11-20T10:00:00Z",
            "end_timestamp": "2026-11-20T10:00:01Z",
            "participants": [],
            "interfaces": ["N2"],
            "procedures": [],
            "events": events,
            "correlation_edges": [],
            "correlation_status": {},
            "decoder_versions": {"decoder-ngap":"0.6.3","decoder-nas":"0.4.3"},
            "schema_version": "1.5.0",
            "capture_references": ["sha256:cap-stable-key-test"],
            "accounting": {"source_events":5,"session_events":5,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields": 0,
        });
        let callflow_json_path = dataset_dir.join("callflow.json");
        fs::write(
            &callflow_json_path,
            serde_json::to_vec_pretty(&callflow).unwrap(),
        )
        .unwrap();
        fs::write(dataset_dir.join("callflow.html"), b"<html>stub</html>").unwrap();
        fs::write(dataset_dir.join("synthetic.pcap"), b"\0").unwrap();
        fs::write(dataset_dir.join("oiran_events.jsonl"), b"").unwrap();
        fs::write(
            dataset_dir.join("scenario_manifest.json"),
            json!({
                "scenario_id": "callflow-stable-key-2.21.95",
                "captures": [{
                    "file": "synthetic.pcap",
                    "capture_id": "sha256:cap-stable-key-test",
                    "name": "synthetic.pcap",
                    "interface": "N2",
                    "sha256": "0".repeat(64),
                    "packet_count": 1,
                    "size_bytes": 1,
                }]
            })
            .to_string(),
        )
        .unwrap();

        let mut config = test_config(workspace, &format!("registry-{dataset_name}"));
        config.dataset_dir = dataset_dir.clone();
        config.callflow_json = callflow_json_path.clone();
        config.callflow_html = dataset_dir.join("callflow.html");
        config.reference_dataset_enabled = true;
        let state = AppState::load(config)
            .expect("AppState::load succeeds on 2.21.95 callflow fixture");

        let response = router(state, None)
            .oneshot(req(
                &format!("/api/v1/sessions/{session_id}/callflow?limit=100"),
                true,
            ))
            .await
            .unwrap();
        let status = response.status();
        let body = json_body(response).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "expected 200, got {status}; body={body}"
        );
        let events = body["data"]["events"]
            .as_array()
            .expect("data.events array present on /callflow response");
        assert_eq!(events.len(), 5, "fixture a 5 événements");

        // Preuve 1 — 100 % des events portent `stable_event_key` non vide.
        for (idx, event) in events.iter().enumerate() {
            let key = event["stable_event_key"]
                .as_str()
                .expect(&format!("event #{idx} manque stable_event_key"));
            assert!(
                !key.is_empty(),
                "event #{idx} ({}) stable_event_key vide",
                event["event_id"]
            );
            // Format : `{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}`.
            assert_eq!(
                key.matches('|').count(),
                5,
                "format stable_event_key invalide pour event #{idx}: {key}"
            );
            assert!(
                key.starts_with("N2.pcapng|"),
                "basename dumpcap doit préfixer la clé, got {key}"
            );
        }

        // Preuve 2 — unicité par event, invariant 2.21.91 raffinement
        // 7034553419. Chaque event a sa propre `stable_event_key`
        // (parent NGAP + enfant NAS sur même paquet se discriminent
        // via `|protocol|ordinal`).
        let keys: std::collections::BTreeSet<&str> = events
            .iter()
            .filter_map(|e| e["stable_event_key"].as_str())
            .collect();
        assert_eq!(
            keys.len(),
            events.len(),
            "chaque event doit avoir une stable_event_key unique"
        );

        // Preuve 3 — parent NGAP + enfant NAS sur le MÊME paquet
        // partagent le prefix `(basename, iid, pkt, off)` mais
        // diffèrent par `(protocol, ordinal)`. Tiré de la mesure
        // ANR1 originale : le NGAP et le NAS encapsulé sortent sur
        // le même packet_number mais sont deux events distincts.
        let evt_ngap = events
            .iter()
            .find(|e| e["event_id"] == "evt-ngap-init-01")
            .unwrap();
        let evt_nas = events
            .iter()
            .find(|e| e["event_id"] == "evt-nas-regreq-01")
            .unwrap();
        let k_ngap = evt_ngap["stable_event_key"].as_str().unwrap();
        let k_nas = evt_nas["stable_event_key"].as_str().unwrap();
        assert!(k_ngap.starts_with("N2.pcapng|0|7|40|"));
        assert!(k_nas.starts_with("N2.pcapng|0|7|40|"));
        assert_ne!(k_ngap, k_nas, "parent + enfant même paquet, clés distinctes");
    }

    /// 2.21.115 (ordre #9 7050925249, suite de 2.21.112) — à travers le
    /// routeur : une session d'un dataset d'avant 2.21.91 dont un PFCP
    /// frère n'existe que dans le JSONL brut. `GET /sessions/:id/callflow`
    /// et `GET /sessions/:id/events` rendent ce frère AVEC sa
    /// `stable_event_key`, dérivée par la formule commune. Recette
    /// 2.21.104 : 5 PFCP sans clé sur 72 (ANR1 #10 7050183853).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inserted_pfcp_sibling_carries_a_stable_event_key_through_the_router_2_21_115() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dataset_name = format!("callflow-sibling-key-{suffix}");
        let dataset_dir_guard =
            AutoRemoveDir::new(workspace.join("datasets").join(&dataset_name));
        let dataset_dir = dataset_dir_guard.as_pathbuf();
        let session_id = "sess-sibling-key-2-21-115";
        let persisted = |event_id: &str, interface: &str, protocol: &str, message: &str, packet: u64, ie: Value| {
            json!({
                "event_id": event_id,
                "timestamp": "2026-11-20T18:00:00.000000000Z",
                "timestamp_ns": "0",
                "interface": interface,
                "protocol": protocol,
                "message_name": message,
                "source_participant": "UPF",
                "destination_participant": "SMF",
                "direction": "CORE_TO_CORE",
                "decoded_ie_tree": ie,
                "decoding_status": "DECODED",
                "semantic_status": "EXACT",
                "association": "SESSION",
                "procedure_group": "PDU Session",
                "packet_references": [{
                    "source_file": format!("/var/lib/oiran/ring/{}/{}_00007.pcapng",
                        interface.to_ascii_lowercase(), interface.to_ascii_lowercase()),
                    "packet_number": packet,
                    "byte_offset": packet * 100,
                    "interface_id": 0u32,
                    "captured_length": 64u32,
                    "original_length": 64u32,
                }],
                "capture_id": "sha256:pre-2-21-91",
                "decoder_name": "decoder",
                "decoder_version": "0",
                "raw_payload_reference": "sha256:payload",
                "errors": [],
            })
        };
        // Le frère : un vrai PFCP Session Establishment Request du jeu
        // du dépôt, absent du callflow persisté, et sans clé (dataset
        // d'avant 2.21.91).
        let raw_events = fs::read_to_string(
            workspace.join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl"),
        )
        .unwrap();
        let mut sibling: Value = raw_events
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .find(|event| event["message_name"] == "PFCP Session Establishment Request")
            .expect("le jeu porte un PFCP Session Establishment Request");
        sibling.as_object_mut().unwrap().remove("stable_event_key");
        let sibling_id = sibling["event_id"].as_str().unwrap().to_owned();
        let sibling_sequence = sibling["session_identifiers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|id| id["name"] == "pfcp_sequence")
            .and_then(|id| id["value"].as_str())
            .unwrap()
            .to_owned();
        let reference = &sibling["packet_references"][0];
        let expected_sibling_key = event_schema::derive_stable_event_key(
            reference["source_file"].as_str().unwrap(),
            reference["interface_id"].as_u64().unwrap_or(0) as u32,
            reference["packet_number"].as_u64().unwrap(),
            reference["byte_offset"].as_u64().unwrap_or(0),
            "PFCP",
            0,
        );
        let callflow = json!({
            "callflow_id": format!("cf-{session_id}"),
            "session_id": session_id,
            "technology": "5G SA",
            "start_timestamp": "2026-11-20T18:00:00Z",
            "end_timestamp": "2026-11-20T18:00:01Z",
            "participants": [],
            "interfaces": ["N2", "N4"],
            "procedures": [],
            "events": [
                persisted("evt-ngap-01", "N2", "NGAP", "InitialUEMessage", 3, json!([])),
                persisted("evt-pfcp-resp", "N4", "PFCP", "PFCP Session Establishment Response", 8,
                    json!([{"name":"pfcp_sequence","value":sibling_sequence.clone()}])),
            ],
            "correlation_edges": [],
            "correlation_status": {},
            "decoder_versions": {},
            "schema_version": "1.5.0",
            "capture_references": ["sha256:pre-2-21-91"],
            "accounting": {"source_events":2,"session_events":2,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields": 0,
        });
        let callflow_json_path = dataset_dir.join("callflow.json");
        fs::write(&callflow_json_path, serde_json::to_vec_pretty(&callflow).unwrap()).unwrap();
        fs::write(dataset_dir.join("callflow.html"), b"<html>stub</html>").unwrap();
        fs::write(dataset_dir.join("synthetic.pcap"), b"\0").unwrap();
        fs::write(dataset_dir.join("oiran_events.jsonl"), format!("{sibling}\n")).unwrap();
        fs::write(
            dataset_dir.join("scenario_manifest.json"),
            json!({
                "scenario_id": "callflow-sibling-key-2.21.115",
                "captures": [{
                    "file": "synthetic.pcap",
                    "capture_id": "sha256:pre-2-21-91",
                    "name": "synthetic.pcap",
                    "interface": "N2",
                    "sha256": "0".repeat(64),
                    "packet_count": 1,
                    "size_bytes": 1,
                }]
            })
            .to_string(),
        )
        .unwrap();
        let mut config = test_config(workspace, &format!("registry-{dataset_name}"));
        config.dataset_dir = dataset_dir.clone();
        config.callflow_json = callflow_json_path.clone();
        config.callflow_html = dataset_dir.join("callflow.html");
        config.reference_dataset_enabled = true;
        let state = AppState::load(config).expect("AppState::load");
        let mut keys_by_route: Vec<Vec<(String, String)>> = Vec::new();
        for route in ["callflow?limit=100", "events?page_size=100"] {
            let response = router(state.clone(), None)
                .oneshot(req(&format!("/api/v1/sessions/{session_id}/{route}"), true))
                .await
                .unwrap();
            let status = response.status();
            let body = json_body(response).await;
            assert_eq!(status, StatusCode::OK, "{route} body={body}");
            let events = body["data"]["events"]
                .as_array()
                .or_else(|| body["data"]["items"].as_array())
                .or_else(|| body["data"].as_array())
                .unwrap_or_else(|| panic!("{route} : liste d'events introuvable : {body}"));
            let found = events
                .iter()
                .find(|event| event["event_id"] == sibling_id.as_str())
                .unwrap_or_else(|| panic!("{route} : le frère PFCP doit être inséré : {body}"));
            assert_eq!(
                found["stable_event_key"].as_str().unwrap_or(""),
                expected_sibling_key.as_str(),
                "{route} : clé du frère"
            );
            // 2.21.118 — les events PERSISTÉS aussi portent leur clé, sur
            // les deux routes, et les deux routes rendent les mêmes clés.
            let mut keys: Vec<(String, String)> = events
                .iter()
                .map(|event| {
                    (
                        event["event_id"].as_str().unwrap_or("").to_owned(),
                        event["stable_event_key"].as_str().unwrap_or("").to_owned(),
                    )
                })
                .collect();
            keys.sort();
            assert_eq!(keys.len(), 3, "{route} : 2 persistés + 1 frère");
            assert!(
                keys.iter().all(|(_, key)| !key.is_empty()),
                "{route} : chaque event porte une clé : {keys:?}"
            );
            keys_by_route.push(keys);
        }
        assert_eq!(keys_by_route[0], keys_by_route[1], "mêmes clés sur /callflow et /events");
        assert!(keys_by_route[0].contains(&(
            "evt-pfcp-resp".to_owned(),
            "n4_00007.pcapng|0|8|800|PFCP|0".to_owned()
        )));
    }

    /// 2.21.102 (défaut ANR1 #9 7044712668, ordre #9 7045732954 point 2) —
    /// clé sur **données stockées**. Un callflow persisté AVANT
    /// 2.21.91 (le champ `stable_event_key` est ABSENT du JSON disque)
    /// doit, à la lecture par la route `/sessions/:id/callflow`,
    /// rendre 100 % de clés **identiques** à celles qu'aurait émises
    /// une republication live.
    ///
    /// Modélisation :
    ///   1. callflow écrit sur disque sans `stable_event_key` sur
    ///      aucun des 5 events (dont NGAP parent + NAS enfant sur
    ///      le même paquet) — exactement la forme pre-2.21.91 ;
    ///   2. `AppState::load` ; puis `GET /sessions/:id/callflow` ;
    ///   3. 100 % des events renvoyés par la route portent
    ///      `stable_event_key` non vide, dérivée à la LECTURE par
    ///      `backfill_stable_event_keys_in_callflow` ;
    ///   4. chaque clé respecte exactement la formule
    ///      `{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}`
    ///      — identique à celle qu'aurait produite la republication
    ///      (invariant garanti par la fonction `derive_stable_event_key`
    ///      commune).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sessions_callflow_backfills_missing_stable_event_key_from_stored_fixture_2_21_102() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dataset_name = format!("callflow-backfill-{suffix}");
        let dataset_dir_guard =
            AutoRemoveDir::new(workspace.join("datasets").join(&dataset_name));
        let dataset_dir = dataset_dir_guard.as_pathbuf();
        let session_id = "sess-backfill-2-21-102";

        // Fixture pré-2.21.91 : AUCUN event ne porte `stable_event_key`.
        // 5 events dont NGAP parent + NAS enfant sur le même paquet (7, 40).
        let make_pre_2_21_91 = |event_id: &str,
                               packet_number: u64,
                               byte_offset: u64,
                               protocol: &str| {
            json!({
                "event_id": event_id,
                // PAS de `stable_event_key` — dataset pre-2.21.91.
                "timestamp": "2026-11-20T18:00:00.000000000Z",
                "timestamp_ns": "0",
                "interface": "N2",
                "protocol": protocol,
                "message_name": "InitialUEMessage",
                "source_participant": "gNB",
                "destination_participant": "AMF",
                "direction": "RAN_TO_CORE",
                "decoded_ie_tree": [],
                "decoding_status": "DECODED",
                "semantic_status": "EXACT",
                "association": "SESSION",
                "procedure_group": "Registration",
                "packet_references": [{
                    "source_file": "/var/lib/oiran/ring/n2/N2.pcapng",
                    "packet_number": packet_number,
                    "byte_offset": byte_offset,
                    "interface_id": 0u32,
                    "captured_length": 64u32,
                    "original_length": 64u32,
                }],
                "capture_id": "sha256:pre-2-21-91",
                "decoder_name": "decoder-ngap",
                "decoder_version": "0.6.0",
                "raw_payload_reference": "sha256:payload",
                "errors": [],
            })
        };
        let events = json!([
            make_pre_2_21_91("evt-ngap-init-01", 7, 40, "NGAP"),
            make_pre_2_21_91("evt-nas-regreq-01", 7, 40, "NAS-5GS-MM"),
            make_pre_2_21_91("evt-ngap-init-02", 12, 200, "NGAP"),
            make_pre_2_21_91("evt-nas-regreq-02", 12, 200, "NAS-5GS-MM"),
            make_pre_2_21_91("evt-ngap-release-03", 42, 1_024, "NGAP"),
        ]);
        let callflow = json!({
            "callflow_id": format!("cf-{session_id}"),
            "session_id": session_id,
            "technology": "5G SA",
            "start_timestamp": "2026-11-20T18:00:00Z",
            "end_timestamp": "2026-11-20T18:00:01Z",
            "participants": [],
            "interfaces": ["N2"],
            "procedures": [],
            "events": events,
            "correlation_edges": [],
            "correlation_status": {},
            "decoder_versions": {"decoder-ngap":"0.6.0","decoder-nas":"0.4.0"},
            // Schéma pre-2.21.91 (= 1.5.0).
            "schema_version": "1.5.0",
            "capture_references": ["sha256:pre-2-21-91"],
            "accounting": {"source_events":5,"session_events":5,"background_events":0,"unmatched_events":0,"duplicate_events":0,"extra_events":0},
            "unresolved_fields": 0,
        });
        let callflow_json_path = dataset_dir.join("callflow.json");
        fs::write(&callflow_json_path, serde_json::to_vec_pretty(&callflow).unwrap())
            .unwrap();
        fs::write(dataset_dir.join("callflow.html"), b"<html>stub</html>").unwrap();
        fs::write(dataset_dir.join("synthetic.pcap"), b"\0").unwrap();
        fs::write(dataset_dir.join("oiran_events.jsonl"), b"").unwrap();
        fs::write(
            dataset_dir.join("scenario_manifest.json"),
            json!({
                "scenario_id": "callflow-backfill-2.21.102",
                "captures": [{
                    "file": "synthetic.pcap",
                    "capture_id": "sha256:pre-2-21-91",
                    "name": "synthetic.pcap",
                    "interface": "N2",
                    "sha256": "0".repeat(64),
                    "packet_count": 1,
                    "size_bytes": 1,
                }]
            })
            .to_string(),
        )
        .unwrap();

        let mut config = test_config(workspace, &format!("registry-{dataset_name}"));
        config.dataset_dir = dataset_dir.clone();
        config.callflow_json = callflow_json_path.clone();
        config.callflow_html = dataset_dir.join("callflow.html");
        config.reference_dataset_enabled = true;
        let state = AppState::load(config)
            .expect("AppState::load succeeds on pre-2.21.91 callflow fixture");

        let response = router(state, None)
            .oneshot(req(
                &format!("/api/v1/sessions/{session_id}/callflow?limit=100"),
                true,
            ))
            .await
            .unwrap();
        let status = response.status();
        let body = json_body(response).await;
        assert_eq!(status, StatusCode::OK, "body={body}");
        let events_out = body["data"]["events"]
            .as_array()
            .expect("data.events array");
        assert_eq!(events_out.len(), 5);

        // Preuve 1 — 100 % des events exposés portent `stable_event_key`
        // non vide, alors que la fixture disque n'en portait AUCUN.
        for (idx, event) in events_out.iter().enumerate() {
            let key = event["stable_event_key"]
                .as_str()
                .unwrap_or_else(|| panic!("event #{idx} manque stable_event_key : {event}"));
            assert!(!key.is_empty(), "event #{idx} clé vide");
        }

        // Preuve 2 — les valeurs sont strictement identiques à celles
        // qu'aurait produites `derive_stable_event_key` (= republication
        // live). Formule reproduite in situ pour comparaison :
        let expected_keys = vec![
            "N2.pcapng|0|7|40|NGAP|0",
            "N2.pcapng|0|7|40|NAS-5GS-MM|1",
            "N2.pcapng|0|12|200|NGAP|0",
            "N2.pcapng|0|12|200|NAS-5GS-MM|1",
            "N2.pcapng|0|42|1024|NGAP|0",
        ];
        for (idx, (event, expected)) in
            events_out.iter().zip(expected_keys.iter()).enumerate()
        {
            assert_eq!(
                event["stable_event_key"].as_str().unwrap(),
                *expected,
                "event #{idx} ({}) key mismatch",
                event["event_id"]
            );
        }

        // Preuve 3 — unicité par event (parent + enfant sur même
        // paquet se discriminent via `|protocol|ordinal`).
        let keys: std::collections::BTreeSet<&str> = events_out
            .iter()
            .filter_map(|e| e["stable_event_key"].as_str())
            .collect();
        assert_eq!(
            keys.len(),
            events_out.len(),
            "chaque event a sa propre clé après backfill"
        );
    }
}

#[cfg(test)]
mod suci_null_scheme_tests {
    use super::supi_from_null_scheme_suci;

    #[test]
    fn rebuilds_supi_from_anr1_frame_1217_shape() {
        // ANR1 #10 6894182928 : type_id=1, supi_fmt=0, scheme_id=0, MCC 001, MNC 01, MSIN 10 digits.
        assert_eq!(
            supi_from_null_scheme_suci("0", "0", "001", "01", "0000000201").as_deref(),
            Some("001010000000201")
        );
        // aggregated fields keep the first occurrence
        assert_eq!(
            supi_from_null_scheme_suci("0", "0", "001,208", "01,93", "0000000201").as_deref(),
            Some("001010000000201")
        );
    }

    #[test]
    fn refuses_ciphered_or_non_imsi_suci() {
        assert_eq!(
            supi_from_null_scheme_suci("0", "1", "001", "01", "0000000201"),
            None
        ); // ECIES profile A
        assert_eq!(
            supi_from_null_scheme_suci("1", "0", "001", "01", "0000000201"),
            None
        ); // NAI
        assert_eq!(supi_from_null_scheme_suci("", "", "", "", ""), None);
        assert_eq!(supi_from_null_scheme_suci("0", "0", "001", "01", ""), None);
    }
}

#[cfg(test)]
mod tshark_field_list_tests {
    use super::{parse_tshark_field_list, IDENTITY_TSHARK_FIELDS};

    #[test]
    fn keeps_only_fields_known_by_this_tshark() {
        // TShark 3.6.2 shape: no nas-5gs.mm.suci.* (CLAUDE DEVMAT #10 6895890080).
        let listing = "P\tNAS-5GS\tnas-5gs\nF\tIMSI\te212.imsi\tFT_STRING\te212\nF\tMCC\te212.mcc\tFT_UINT16\te212\nF\tFrame\tframe.number\tFT_UINT32\tframe\n";
        let known = parse_tshark_field_list(listing);
        assert!(known.contains("e212.imsi") && known.contains("frame.number"));
        assert!(!known.contains("nas-5gs.mm.suci.msin"));
        let requested: Vec<&str> = IDENTITY_TSHARK_FIELDS
            .iter()
            .copied()
            .filter(|f| known.contains(*f))
            .collect();
        assert_eq!(requested, vec!["frame.number", "e212.imsi", "e212.mcc"]);
    }
}
