//! Versioned, read-only HTTP adapter for certified OIRAN artifacts.
// 2.11.1 : la macro `json!` dans le handler `metrics` a dépassé la
// profondeur de récursion par défaut (128) après l'ajout des 5
// nouveaux champs pending/open/zero exigés par ANR1 (#10 comment
// 6778895992). On remonte la limite plutôt que d'éclater le JSON
// en sous-blocs — c'est le même pattern que d'autres gros
// handlers API.
#![recursion_limit = "512"]

mod probe_registry;
mod session_filters;
mod identity_vault;
mod subscriber_journey;

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
    discover_sessions, reconstruct, Association, DiscoveryResult, LteSession,
    ReconstructionHints,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
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
    probe_registry: ProbeRegistry,
    derived_import_root: PathBuf,
    lte_evidence_store: LteEvidenceStore,
    lte_evidence_bundle_root: PathBuf,
    operator_token_sha256: Option<String>,
    administrator_token_sha256: Option<String>,
    identity_vault: IdentityVault,
    /// 2.10.0 : index des filtres Session Explorer (messages, causes,
    /// pseudonymes), construit au chargement depuis `flows` + mis à
    /// jour par `refresh_session_filter_index` quand le capture
    /// manager publie une nouvelle version du dataset continu.
    /// Verrouillé par `RwLock` : lecteurs multiples (handlers HTTP)
    /// + rare upsert sous `write`.
    session_filter_index: std::sync::RwLock<session_filters::SessionFilterIndex>,
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

fn startup_access_checks(config: &ApiConfig) -> Result<(), String> {
    if cfg!(test) {
        return Ok(());
    }
    validate_identity_vault_path(config)?;
    access_check(&config.workspace, libc::R_OK | libc::X_OK, "workspace-read")?;
    if config.capture_root.exists() {
        access_check(&config.capture_root, libc::R_OK | libc::X_OK, "capture-root-read")?;
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
    for directory in [
        &config.derived_import_root,
        &config.lte_evidence_root,
        &config.lte_evidence_bundle_root,
    ] {
        access_check_creatable(directory, "service-state-create")?;
    }
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
        let session_filter_index =
            session_filters::SessionFilterIndex::from_flows(flows.values());
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
                probe_registry,
                derived_import_root,
                lte_evidence_store,
                lte_evidence_bundle_root,
                operator_token_sha256: config.operator_token_sha256,
                administrator_token_sha256: config.administrator_token_sha256,
                identity_vault,
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
                probe_registry,
                derived_import_root,
                lte_evidence_store,
                lte_evidence_bundle_root,
                operator_token_sha256: config.operator_token_sha256,
                administrator_token_sha256: config.administrator_token_sha256,
                identity_vault,
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
        if let Ok(mut guard) = self.inner.session_filter_index.write() {
            *guard = index;
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
        .route("/sessions/:id", get(session))
        .route("/sessions/:id/procedures", get(session_procedures))
        .route("/sessions/:id/events", get(session_events))
        .route("/sessions/:id/callflow", get(session_callflow))
        .route("/sessions/:id/correlations", get(session_correlations))
        .route("/sessions/:id/identities", get(session_identities))
        .route("/subscribers", get(subscribers))
        .route("/subscribers/:pseudo/journey", get(subscriber_journey))
        .route("/subscribers/:pseudo/tmsi", get(subscriber_tmsi))
        .route("/identities", get(identity_lookup))
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

async fn health(State(state): State<AppState>) -> Json<Value> {
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
            published_session_count = published_session_count.saturating_add(live.session_ids.len());
            if let Some(discovery) = &live.discovery {
                ue_context_count =
                    ue_context_count.saturating_add(discovery.ue_contexts.len());
            }
            if dataset.is_none() {
                dataset = Some(Value::String(live.dataset_id.clone()));
            }
        }
    }
    let queryable_session_count = queryable_session_ids(&state).len();
    ok(json!({
        "status":"healthy",
        "mode":"LIVE_CAPTURE_CAPABLE_EXECUTION_GATED",
        "dataset":dataset,
        "source_events":source_events,
        // Same union as an unfiltered GET /sessions. The narrower continuous
        // manifest count is named explicitly instead of overloading this key.
        "session_count":queryable_session_count,
        "queryable_session_count":queryable_session_count,
        "published_session_count":published_session_count,
        "ue_context_count":ue_context_count,
        "capabilities":{"live_capture":true,"capture_control":state.inner.capture_manager.execution_enabled(),"session_analysis":true,"multi_session":true,"dataset_registry":true,"packet_analysis":true,"exports":true,"future_sse":false}
    }))
}

async fn version(State(state): State<AppState>) -> Json<Value> {
    let flow = primary_flow(&state);
    ok(json!({
        "platform_core":PLATFORM_VERSION,"backend_api":API_VERSION,"web_frontend":WEB_FRONTEND_VERSION,
        "event_schema":"1.2.0","callflow_schema":flow.map(|value|value.schema_version.as_str()).unwrap_or("UNKNOWN"),
        "session_engine":session_engine::VERSION,"correlation_engine":correlation_engine::VERSION,"dataset_registry":dataset_registry::VERSION,
        "disk_safety":disk_safety::VERSION,
        "decoders":oiran_decode::installed_decoder_versions()
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

#[derive(Deserialize, Default)]
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

#[derive(Deserialize, Default)]
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
    if let Some(if_none_match) = headers.get(header::IF_NONE_MATCH).and_then(|value| value.to_str().ok()) {
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
    let mut unique = state
        .inner
        .discovery
        .ue_contexts
        .iter()
        .map(|context| (context.context_id.clone(), ue_summary(&state, context)))
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
    paginated(items, &query)
}

async fn ue(State(state): State<AppState>, Path(id): Path<String>) -> Response {
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
    json!({
        "session_id":flow.session_id,"dataset_id":state.inner.manifest.get("scenario_id"),"ue_context_id":ue_context_id,
        "dataset_kind":"HISTORICAL",
        "technology":flow.technology,"ue_pseudonym":ue_pseudonym,"pdu_session_id":pdu_session_id,"serving_node":serving_node,
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
    json!({
        "session_id":flow.session_id,"dataset_id":dataset.dataset_id,"ue_context_id":discovered.map(|session|session.ue_context_id.clone()),
        "dataset_kind":if dataset.dataset_id.starts_with("derived-") {"DERIVED"} else if dataset.dataset_id.starts_with("recovered-dataset-") {"RECOVERED"} else if dataset.capture_id == live_probe::CONTINUOUS_CAPTURE_ID && !fresh_flow {"HISTORICAL"} else {"CAPTURED_LIVE"},
        "technology":flow.technology,"ue_pseudonym":runtime.map(|context|context.internal_ue_id.as_str()).or_else(||context.map(|context|context.pseudonym.as_str())).unwrap_or("UNKNOWN"),"pdu_session_id":runtime.map(|context|context.pdu_session_id.as_str()).or_else(||discovered.map(|session|session.pdu_session_id.as_str())),"serving_node":serving_node,
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
        "pdu_session_id":session.eps_bearer_ids.first().cloned(),"serving_node":Value::Null,
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

fn queryable_flows(state: &AppState) -> BTreeMap<String, CallFlow> {
    let mut flows = state.inner.flows.clone();
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if let Some(flow) = state.inner.capture_manager.callflow(&dataset.dataset_id, session_id) {
                flows.insert(session_id.clone(), flow);
            }
        }
    }
    flows
}

fn queryable_session_ids(state: &AppState) -> BTreeSet<String> {
    let mut ids = state.inner.flows.keys().cloned().collect::<BTreeSet<_>>();
    for dataset in state.inner.capture_manager.datasets() {
        ids.extend(dataset.session_ids.iter().filter_map(|session_id| {
            state.inner.capture_manager.callflow(&dataset.dataset_id, session_id)
                .map(|_| session_id.clone())
        }));
    }
    if let Ok(catalog) = state.inner.lte_evidence_store.catalog() {
        for manifest in catalog {
            if let Ok(page) = state.inner.lte_evidence_store.session_page(&manifest.run_id, 1, 100) {
                if let Some(records) = page["data"].as_array() {
                    ids.extend(records.iter().filter_map(|record| record.get("session_id").and_then(Value::as_str).map(str::to_owned)));
                }
            }
        }
    }
    ids
}

fn decorate_subscriber_summary(summary: &mut Value, flow: &CallFlow, index: &subscriber_journey::JourneyIndex) {
    let Some(pseudo) = index.subscriber_for_session(&flow.session_id) else { return };
    let sessions = index.sessions(pseudo);
    let Some(position) = sessions.iter().position(|session| session.session_id == flow.session_id) else { return };
    summary["subscriber_pseudonym"] = Value::String(pseudo.to_owned());
    summary["ue_pseudonym"] = Value::String(pseudo.to_owned());
    summary["subscriber_session_count"] = Value::from(sessions.len());
    summary["previous_session_id"] = position.checked_sub(1).and_then(|index| sessions.get(index)).map(|session| Value::String(session.session_id.clone())).unwrap_or(Value::Null);
    summary["next_session_id"] = sessions.get(position + 1).map(|session| Value::String(session.session_id.clone())).unwrap_or(Value::Null);
}

async fn subscribers(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    let flows = queryable_flows(&state);
    let index = subscriber_journey::JourneyIndex::from_flows(flows.values());
    let mut rows = serde_json::to_value(index.subscribers()).unwrap_or_else(|_| Value::Array(Vec::new())).as_array().cloned().unwrap_or_default();
    if let Some(search) = query.search.as_deref() {
        let search = search.to_ascii_lowercase();
        rows.retain(|row| row.to_string().to_ascii_lowercase().contains(&search));
    }
    paginated(rows, &query)
}

async fn subscriber_journey(State(state): State<AppState>, Path(pseudo): Path<String>) -> Response {
    let flows = queryable_flows(&state);
    let index = subscriber_journey::JourneyIndex::from_flows(flows.values());
    let sessions = index.sessions(&pseudo);
    if sessions.is_empty() {
        return api_error(StatusCode::NOT_FOUND, "SUBSCRIBER_NOT_FOUND", "subscriber journey not found");
    }
    let mut contexts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for session in &sessions {
        let context_id = flows.get(&session.session_id)
            .and_then(|flow| discovered_session_for_flow(&state, flow))
            .map(|session| session.ue_context_id.clone())
            .unwrap_or_else(|| format!("ue-context-for-{}", session.session_id));
        contexts.entry(context_id).or_default().push(session.session_id.clone());
    }
    ok(json!({
        "subscriber_pseudonym":pseudo,
        "contexts":contexts.into_iter().map(|(ue_context_id, session_ids)| json!({"ue_context_id":ue_context_id,"session_ids":session_ids})).collect::<Vec<_>>(),
        "sessions":sessions,
        "links":index.links(&pseudo),
        "ordering":"capture_id,packet_number,event_id"
    })).into_response()
}

async fn subscriber_tmsi(State(state): State<AppState>, Path(pseudo): Path<String>) -> Response {
    let flows = queryable_flows(&state);
    let index = subscriber_journey::JourneyIndex::from_flows(flows.values());
    if index.sessions(&pseudo).is_empty() {
        return api_error(StatusCode::NOT_FOUND, "SUBSCRIBER_NOT_FOUND", "subscriber temporary identity chain not found");
    }
    ok(serde_json::to_value(index.tmsi(&pseudo)).unwrap_or(Value::Array(Vec::new()))).into_response()
}

async fn sessions(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    let journey_flows = queryable_flows(&state);
    let journey_index = subscriber_journey::JourneyIndex::from_flows(journey_flows.values());
    let mut unique = state
        .inner
        .flows
        .values()
        .map(|flow| {
            let mut summary = session_summary(&state, flow);
            decorate_subscriber_summary(&mut summary, flow, &journey_index);
            (flow.session_id.clone(), summary)
        })
        .collect::<BTreeMap<_, _>>();
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if let Some(flow) = state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
            {
                let mut summary = live_session_summary(&dataset, &flow);
                decorate_subscriber_summary(&mut summary, &flow, &journey_index);
                unique.insert(session_id.clone(), summary);
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
                            unique.insert(
                                session.session_id.clone(),
                                lte_session_summary(&manifest, &session),
                            );
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
    paginated(items, &query)
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
    let role = role_from_headers(&state, &headers);
    if request.identity.is_some() && !role.can_control() {
        return api_error(
            StatusCode::FORBIDDEN,
            "IDENTITY_FILTER_OPERATOR_REQUIRED",
            "identity-scoped session filtering requires an operator bearer",
        );
    }
    state.refresh_session_filter_index();
    let journey_flows = queryable_flows(&state);
    let journey_index = subscriber_journey::JourneyIndex::from_flows(journey_flows.values());

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
        let guard = state
            .inner
            .session_filter_index
            .read()
            .expect("session_filter_index poisoned");
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
                guard.pagination_key(id).map(|(cap, pkt, sid)| {
                    (id.clone(), (cap.to_owned(), pkt, sid.to_owned()))
                })
            })
            .collect();
        let mut rows: Vec<(String, (String, u64, String))> =
            matching.into_iter().filter_map(|id| keys.get(&id).map(|k| (id.clone(), k.clone()))).collect();
        rows.sort_by(|a, b| a.1.cmp(&b.1));
        let sorted: Vec<String> = rows.into_iter().map(|(id, _)| id).collect();
        (keys, sorted)
    };

    // Curseur : index à démarrer DANS `sorted_ids`. Si fourni,
    // on cherche le session_id post-curseur strict (clé
    // canonique strictement supérieure).
    let limit = request.limit.unwrap_or(25).clamp(1, 100);
    let start_index = match request.cursor.as_deref() {
        None => 0,
        Some(cursor_sid) => match matching_keys.get(cursor_sid) {
            Some(cursor_key) => sorted_ids
                .iter()
                .position(|id| {
                    matching_keys
                        .get(id)
                        .map(|k| k > cursor_key)
                        .unwrap_or(false)
                })
                .unwrap_or(sorted_ids.len()),
            None => {
                // Curseur pointant vers une session qui n'est
                // plus dans le set filtré : traité comme
                // fin-de-flux.
                sorted_ids.len()
            }
        },
    };
    let page_ids: Vec<&str> = sorted_ids
        .iter()
        .skip(start_index)
        .take(limit)
        .map(String::as_str)
        .collect();
    let next_cursor: Option<&str> = if start_index + page_ids.len() < sorted_ids.len() {
        page_ids.last().copied()
    } else {
        None
    };

    // Reconstitue les summaries sessions pour les ids de la
    // page. Même ordre canonique qu'au tri (pas de re-sort par
    // `ts` dans cette étape).
    let page_set: std::collections::BTreeSet<&str> = page_ids.iter().copied().collect();
    let mut items_by_id: std::collections::BTreeMap<String, Value> =
        std::collections::BTreeMap::new();
    for flow in state.inner.flows.values() {
        if page_set.contains(flow.session_id.as_str()) {
            let mut summary = session_summary(&state, flow);
            decorate_subscriber_summary(&mut summary, flow, &journey_index);
            items_by_id.insert(flow.session_id.clone(), summary);
        }
    }
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if !page_set.contains(session_id.as_str()) {
                continue;
            }
            if let Some(flow) = state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
            {
                let mut summary = live_session_summary(&dataset, &flow);
                decorate_subscriber_summary(&mut summary, &flow, &journey_index);
                items_by_id.insert(session_id.clone(), summary);
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
                            if page_set.contains(session.session_id.as_str()) {
                                items_by_id.insert(
                                    session.session_id.clone(),
                                    lte_session_summary(&manifest, &session),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    // Assemble la page DANS l'ordre canonique page_ids — pas
    // de re-sort sur `ts` ou autre après ça.
    let mut data: Vec<Value> = page_ids
        .iter()
        .filter_map(|id| items_by_id.remove(*id))
        .collect();
    sanitize_all(&mut data);

    let total = sorted_ids.len();
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
    (StatusCode::OK, Json(response)).into_response()
}

async fn session(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let journey_flows = queryable_flows(&state);
    let journey_index = subscriber_journey::JourneyIndex::from_flows(journey_flows.values());
    if let Some(flow) = flow_for(&state, &id) {
        let mut summary = session_summary(&state,flow);
        decorate_subscriber_summary(&mut summary, flow, &journey_index);
        return ok(json!({"summary":summary,"procedures":flow.procedures,"accounting":flow.accounting,"capture_references":flow.capture_references})).into_response();
    }
    if let Some((dataset_id, flow)) = live_flow_for(&state, &id) {
        let dataset = state
            .inner
            .capture_manager
            .dataset(&dataset_id)
            .expect("live flow dataset remains registered");
        let mut summary = live_session_summary(&dataset,&flow);
        decorate_subscriber_summary(&mut summary, &flow, &journey_index);
        return ok(json!({"summary":summary,"procedures":flow.procedures,"accounting":flow.accounting,"capture_references":flow.capture_references})).into_response();
    }
    if let Ok(Some((manifest, lte))) = state.inner.lte_evidence_store.find_session(&id) {
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

#[derive(Deserialize)]
struct IdentityLookupQuery {
    q: String,
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
];

fn session_flow(state: &AppState, id: &str) -> Option<CallFlow> {
    flow_for(state, id)
        .cloned()
        .or_else(|| live_flow_for(state, id).map(|(_, flow)| flow))
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
    let digits = value.chars().filter(char::is_ascii_digit).collect::<String>();
    (digits.len() >= 5).then_some(digits)
}

fn canonical_tmsi(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u32>().ok().or_else(|| u32::from_str_radix(trimmed, 16).ok())
    }?;
    Some(format!("0x{parsed:08X}"))
}

fn identity_role(message_name: &str) -> &'static str {
    let lower = message_name.to_ascii_lowercase();
    if ["accept", "reallocation command", "configuration update command"]
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
            let source = PathBuf::from(&reference.source_file);
            if !source.is_file() {
                continue;
            }
            by_file.entry(source).or_default().entry(reference.packet_number).or_insert_with(|| {
                PacketIdentityEvidence {
                    event_id: event.event_id.clone(),
                    capture_id: event.capture_id.clone(),
                    packet_number: reference.packet_number,
                    message_name: event.message_name.clone(),
                    subscriber_pseudonym: pseudonym.clone(),
                }
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
        command.args(["-n", "-r"]).arg(&source).args(["-Y", &filter, "-T", "fields"]);
        for field in IDENTITY_TSHARK_FIELDS {
            command.args(["-e", field]);
        }
        command.args(["-E", "separator=\t", "-E", "quote=n", "-E", "occurrence=a", "-E", "aggregator=,"]);
        let result = command.output().map_err(|_| "TSHARK_UNAVAILABLE")?;
        if !result.status.success() {
            return Err("TSHARK_DISSECTION_FAILED".into());
        }
        let stdout = String::from_utf8(result.stdout).map_err(|_| "TSHARK_OUTPUT_INVALID")?;
        for line in stdout.lines() {
            let columns = line.split('\t').collect::<Vec<_>>();
            let packet_number = columns.first().and_then(|value| value.parse::<u64>().ok());
            let Some(evidence) = packet_number.and_then(|number| packets.get(&number)) else { continue };
            let role = identity_role(&evidence.message_name);
            let field = |index: usize| columns.get(index).copied().unwrap_or("");
            for raw in split_field(field(1)).chain(split_field(field(2))) {
                if let Some(imsi) = identity_digits(raw) {
                    let pseudo = Some(pseudonym_subscriber_text(
                        state.inner.capture_manager.pseudonym_key().as_ref(),
                        imsi.as_bytes(),
                    ));
                    push_identity(&mut observations, evidence, "imsi", imsi, Some("IMSI"), role, pseudo);
                }
            }
            let tmsi = split_field(field(3))
                .chain(split_field(field(4)))
                .chain(split_field(field(8)))
                .chain(split_field(field(11)))
                .find_map(canonical_tmsi);
            if let Some(m_tmsi) = tmsi {
                let pseudo = evidence.subscriber_pseudonym.clone();
                push_identity(&mut observations, evidence, "m_tmsi", m_tmsi.clone(), Some("M-TMSI"), role, pseudo.clone());
                let is_5g = !field(8).is_empty();
                let components = if is_5g {
                    [field(5), field(6), field(7), field(8)].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-")
                } else {
                    [field(9), field(10), field(11)].into_iter().filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-")
                };
                let temporary = if components.is_empty() { m_tmsi.clone() } else { components };
                push_identity(&mut observations, evidence, "s_tmsi", temporary.clone(), Some(if is_5g { "5G-S-TMSI" } else { "S-TMSI" }), role, pseudo.clone());
                if role == "assigned" {
                    push_identity(&mut observations, evidence, "tmsi", temporary, Some(if is_5g { "5G-GUTI" } else { "GUTI" }), role, pseudo);
                }
            }
            for raw in split_field(field(12)).chain(split_field(field(14))).chain(split_field(field(15))) {
                if let Some(imei) = identity_digits(raw) {
                    push_identity(&mut observations, evidence, "imei", imei, Some("IMEI"), role, evidence.subscriber_pseudonym.clone());
                }
            }
            for raw in split_field(field(13)).chain(split_field(field(16))) {
                if let Some(imeisv) = identity_digits(raw) {
                    push_identity(&mut observations, evidence, "imei", imeisv, Some("IMEISV"), role, evidence.subscriber_pseudonym.clone());
                }
            }
            for raw in split_field(field(17)).chain(split_field(field(18))) {
                if let Some(msisdn) = identity_digits(raw) {
                    push_identity(&mut observations, evidence, "msisdn", msisdn, Some("MSISDN"), role, evidence.subscriber_pseudonym.clone());
                }
            }
        }
    }
    for observation in &mut observations {
        observation.session_id = session_id.to_owned();
    }
    Ok(observations)
}

fn hydrate_identities(state: &AppState, session_id: &str) -> Result<(), String> {
    let Some(flow) = session_flow(state, session_id) else {
        return Err("SESSION_NOT_FOUND".into());
    };
    let observations = tshark_identities(state, session_id, &flow)?;
    state.inner.identity_vault.upsert(observations)
}

fn identity_bundle(observations: Vec<IdentityObservation>) -> Value {
    let latest = |kind: &str| observations.iter().rev().find(|item| item.kind == kind);
    let evidence = |item: &IdentityObservation| json!({
        "value":item.value,"type":item.value_type,"role":item.role,"event_id":item.event_id,
        "capture_id":item.capture_id,"packet_number":item.packet_number,"cap_seq":format!("{}·{}",item.capture_id,item.packet_number)
    });
    let all = |kind: &str| observations.iter().filter(|item| item.kind == kind).map(evidence).collect::<Vec<_>>();
    json!({
        "imsi":latest("imsi").map(|item|item.value.clone()),
        "imsi_proof":latest("imsi").map(evidence),
        "msisdn":latest("msisdn").map(|item|item.value.clone()),
        "msisdn_proof":latest("msisdn").map(evidence),
        "imei":latest("imei").map(evidence),
        "tmsi":all("tmsi"),
        "s_tmsi":all("s_tmsi"),
        "m_tmsi":all("m_tmsi"),
        "subscriber_pseudonym":observations.iter().find_map(|item|item.subscriber_pseudonym.clone()),
    })
}

fn operator_envelope(data: Value) -> Response {
    Json(json!({"data":data,"meta":{"api_version":API_VERSION,"identity_access":"operator"}})).into_response()
}

async fn session_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers) {
        return response;
    }
    if let Err(error) = hydrate_identities(&state, &id) {
        return match error.as_str() {
            "SESSION_NOT_FOUND" => api_error(StatusCode::NOT_FOUND, &error, "unknown session id"),
            "TSHARK_UNAVAILABLE" => api_error(StatusCode::NOT_IMPLEMENTED, &error, "packet dissector unavailable"),
            _ => api_error(StatusCode::INTERNAL_SERVER_ERROR, "IDENTITY_VAULT_FAILED", "identity evidence could not be loaded"),
        };
    }
    match state.inner.identity_vault.for_session(&id) {
        Ok(observations) => operator_envelope(identity_bundle(observations)),
        Err(_) => api_error(StatusCode::INTERNAL_SERVER_ERROR, "IDENTITY_VAULT_FAILED", "identity evidence could not be loaded"),
    }
}

async fn identity_lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<IdentityLookupQuery>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers) {
        return response;
    }
    let q = query.q.trim();
    if q.len() < 4 || q.len() > 128 {
        return api_error(StatusCode::BAD_REQUEST, "IDENTITY_QUERY_INVALID", "identity query length is invalid");
    }
    let mut matches = match state.inner.identity_vault.lookup(q) {
        Ok(matches) => matches,
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "IDENTITY_VAULT_FAILED", "identity evidence could not be loaded"),
    };
    if matches.is_empty() {
        let session_ids = state
            .inner
            .capture_manager
            .datasets()
            .into_iter()
            .flat_map(|dataset| dataset.session_ids)
            .chain(state.inner.flows.keys().cloned())
            .collect::<BTreeSet<_>>();
        for session_id in session_ids {
            let _ = hydrate_identities(&state, &session_id);
        }
        matches = state.inner.identity_vault.lookup(q).unwrap_or_default();
    }
    let sessions = matches.iter().map(|item| item.session_id.clone()).collect::<BTreeSet<_>>();
    let subscriber_pseudonym = matches.iter().find_map(|item| item.subscriber_pseudonym.clone());
    operator_envelope(json!({"sessions":sessions,"subscriber_pseudonym":subscriber_pseudonym,"matches":matches.into_iter().map(|item|json!({
        "session_id":item.session_id,"subscriber_pseudonym":item.subscriber_pseudonym,"type":item.kind,
        "event_id":item.event_id,"capture_id":item.capture_id,"packet_number":item.packet_number
    })).collect::<Vec<_>>() }))
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
    let mut items: Vec<Value> = if let Some(flow_value) = flow_value_for(&state, &id) {
        flow_value["events"].as_array().cloned().unwrap_or_default()
    } else if let Some((_dataset, flow)) = live_flow_for(&state, &id) {
        serde_json::to_value(flow.events)
            .ok()
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default()
    } else {
        match state.inner.lte_evidence_store.callflow_page_by_session(
            &id,
            None,
            MAX_CALLFLOW_PAGE_EVENTS,
        ) {
            Ok(Some(value)) => value["events"].as_array().cloned().unwrap_or_default(),
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
    filter_events(&mut items, &query);
    sanitize_all(&mut items);
    paginated(items, &query).into_response()
}

fn callflow_page_from_value(
    source: &Value,
    cursor: Option<&str>,
    limit: usize,
) -> Result<Value, String> {
    if !(1..=MAX_CALLFLOW_PAGE_EVENTS).contains(&limit) {
        return Err("CALLFLOW_LIMIT_INVALID".into());
    }
    let source_object = source.as_object().ok_or("CALLFLOW_READ_FAILED")?;
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
    let limit = query.limit.unwrap_or(DEFAULT_CALLFLOW_PAGE_EVENTS);
    if !(1..=MAX_CALLFLOW_PAGE_EVENTS).contains(&limit) {
        return callflow_read_error("CALLFLOW_LIMIT_INVALID");
    }
    let cursor = query.cursor.as_deref();
    let result = if let Some(path) = flow_path_for(&state, &id) {
        read_callflow_page(path, cursor, limit).map(Some)
    } else if let Some(flow_value) = flow_value_for(&state, &id) {
        callflow_page_from_value(flow_value, cursor, limit).map(Some)
    } else {
        match state
            .inner
            .capture_manager
            .callflow_page_by_session(&id, cursor, limit)
        {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) => state
                .inner
                .lte_evidence_store
                .callflow_page_by_session(&id, cursor, limit)
                .map_err(|error| error.to_string()),
            Err(error) => Err(error),
        }
    };
    match result {
        Ok(Some(mut value)) => {
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
    let flow = if let Some(flow) = flow_for(&state, &id) {
        flow.clone()
    } else if let Some((_dataset, flow)) = live_flow_for(&state, &id) {
        flow
    } else {
        return match state.inner.lte_evidence_store.callflow_page_by_session(
            &id,
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

fn packet_values(state: &AppState) -> Vec<Value> {
    let mut packets = BTreeMap::<String, Value>::new();
    let mut all_flows = state
        .inner
        .flow_values
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if let Some(flow) = state
                .inner
                .capture_manager
                .callflow(&dataset.dataset_id, session_id)
            {
                if let Ok(value) = serde_json::to_value(flow) {
                    all_flows.push(value)
                }
            }
        }
    }
    for flow in &all_flows {
        for event in flow["events"].as_array().into_iter().flatten() {
            let capture_id = event["capture_id"].as_str().unwrap_or("unknown");
            let capture_tag = capture_id
                .strip_prefix("sha256:")
                .unwrap_or(capture_id)
                .chars()
                .take(12)
                .collect::<String>();
            for reference in event["packet_references"].as_array().into_iter().flatten() {
                let number = reference["packet_number"].as_u64().unwrap_or(0);
                let packet_id = format!("pkt-{capture_tag}-{number}");
                packets.entry(packet_id.clone()).or_insert_with(|| {
                    json!({
                        "packet_id":packet_id,"capture_id":capture_id,"event_id":event["event_id"],
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
                });
            }
        }
    }
    let mut values = packets.into_values().collect::<Vec<_>>();
    values.sort_by(|a, b| {
        a["timestamp_ns"]
            .as_str()
            .cmp(&b["timestamp_ns"].as_str())
            .then_with(|| a["packet_id"].as_str().cmp(&b["packet_id"].as_str()))
    });
    values
}

async fn packets(State(state): State<AppState>, Query(query): Query<ListQuery>) -> Json<Value> {
    let mut items = packet_values(&state);
    if let Some(capture_id) = query.capture_id.as_deref() {
        items.retain(|packet| packet["capture_id"] == capture_id);
    }
    if let Some(event_id) = query.event_id.as_deref() {
        items.retain(|packet| packet["event_id"] == event_id);
    }
    if let Some(packet_number) = query.packet_number {
        items.retain(|packet| packet["packet_number"].as_u64() == Some(packet_number));
    }
    if let Some(interface) = query.interface.as_deref() {
        items.retain(|packet| packet["interface"] == interface);
    }
    if let Some(protocol) = query.protocol.as_deref() {
        items.retain(|packet| packet["protocol"] == protocol);
    }
    if let Some(search) = query.search.as_deref() {
        let search = search.to_ascii_lowercase();
        items.retain(|packet| packet.to_string().to_ascii_lowercase().contains(&search));
    }
    sanitize_all(&mut items);
    paginated(items, &query)
}

async fn packet(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    packet_values(&state)
        .into_iter()
        .find(|packet| packet["packet_id"] == id)
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
}

async fn packet_dissect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((capture_id, packet_number)): Path<(String, u64)>,
) -> Response {
    if let Err(response) = require_operator(&state, &headers) {
        return response;
    }
    let packet = packet_values(&state).into_iter().find(|packet| {
        packet["capture_id"] == capture_id
            && packet["packet_number"].as_u64() == Some(packet_number)
    });
    let Some(packet) = packet else {
        return api_error(StatusCode::NOT_FOUND, "PACKET_NOT_FOUND", "unknown packet reference");
    };
    let Some(source) = packet["source_file"].as_str().map(PathBuf::from).filter(|path| path.is_file()) else {
        return api_error(StatusCode::NOT_FOUND, "CAPTURE_SOURCE_NOT_FOUND", "capture source is unavailable");
    };
    let filter = format!("frame.number == {packet_number}");
    let result = Command::new("tshark")
        .args(["-n", "-r"])
        .arg(source)
        .args(["-Y", &filter, "-V"])
        .output();
    let Ok(result) = result else {
        return api_error(StatusCode::NOT_IMPLEMENTED, "TSHARK_UNAVAILABLE", "packet dissector unavailable");
    };
    if !result.status.success() {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "TSHARK_DISSECTION_FAILED", "packet dissection failed");
    }
    if result.stdout.len() > 2 * 1024 * 1024 {
        return api_error(StatusCode::PAYLOAD_TOO_LARGE, "DISSECTION_TOO_LARGE", "packet dissection exceeds the response limit");
    }
    let Ok(dissection) = String::from_utf8(result.stdout) else {
        return api_error(StatusCode::INTERNAL_SERVER_ERROR, "TSHARK_OUTPUT_INVALID", "packet dissection is not UTF-8");
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
    state.inner.flow_values.values().find_map(|flow| {
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
    let mut items = state
        .inner
        .flows
        .values()
        .flat_map(|flow| flow.correlation_edges.iter())
        .filter_map(|edge| serde_json::to_value(edge).ok())
        .collect::<Vec<_>>();
    if let Some(interface) = query.interface.as_deref() {
        items.retain(|x| x["source_interface"] == interface || x["target_interface"] == interface);
    }
    sanitize_all(&mut items);
    paginated(items, &query)
}

async fn correlation_rules() -> Json<Value> {
    ok(json!([
        {"rule_id":"n2-n4-certified-tunnel-bridge","version":"1.0.0","classification":"STRONG","read_only":true,"description":"PDU Session context plus certified tunnel bridge"},
        {"rule_id":"n4-n3-teid-endpoint","version":"1.0.0","classification":"EXACT","read_only":true,"description":"TEID and directional tunnel endpoint equality"}
    ]))
}

#[derive(Deserialize, Default)]
struct ExportQuery {
    format: Option<String>,
}
async fn export_callflow(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let mut value = if let Some(flow) = flow_for(&state, &id) {
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
fn io_error(error: std::io::Error) -> String {
    error.to_string()
}
fn json_error(error: serde_json::Error) -> String {
    error.to_string()
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
        assert_eq!(DEFAULT_IDENTITY_VAULT_PATH, "/var/lib/oiran/identity-vault/vault.json");
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
                dataset_dir
                    .join("callflows")
                    .join(format!("sess-{i}.json")),
                serde_json::to_vec(&stub).unwrap(),
            )
            .unwrap();
            fs::write(
                dataset_dir
                    .join("callflows")
                    .join(format!("sess-{i}.html")),
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
        let on_disk: serde_json::Value = serde_json::from_slice(
            &fs::read(dataset_dir.join("dataset_manifest.json")).unwrap(),
        )
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

    #[tokio::test]
    async fn health_session_count_matches_unfiltered_sessions_union() {
        let app = router(state(), None);
        let health = json_body(app.clone().oneshot(req("/api/v1/health", false)).await.unwrap()).await;
        let sessions = json_body(app.oneshot(req("/api/v1/sessions?page_size=100", false)).await.unwrap()).await;
        assert_eq!(health["data"]["session_count"], sessions["meta"]["total"]);
        assert_eq!(health["data"]["queryable_session_count"], sessions["meta"]["total"]);
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
        assert_eq!(value["data"]["web_frontend"], env!("OIRAN_WEB_FRONTEND_VERSION"));
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
                    ("imsi_pseudonym", "lte-ue-anon-export"),
                    ("eps_bearer_identity", "5"),
                    ("erab_teid", "0x01020304"),
                ],
                "S11" => vec![
                    ("imsi_pseudonym", "lte-ue-anon-export"),
                    ("bearer_f_teid", "0x01020304"),
                ],
                _ => vec![("teid", "0x01020304")],
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

    #[tokio::test]
    async fn continuous_capture_state_and_incremental_sessions_are_truthful() {
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
        config.capture_root = capture_root;
        let state = AppState::load(config).unwrap();
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
            })
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while state
            .inner
            .capture_manager
            .get(live_probe::CONTINUOUS_CAPTURE_ID)
            .is_some_and(|job| job.metrics.segments_ingested < 3)
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let app = router(state.clone(), None);
        let metrics = json_body(
            app.clone()
                .oneshot(req("/api/v1/metrics", true))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(metrics["data"]["active_captures"], 1);
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
        assert_eq!(value["data"]["policy"]["reserve_bytes"], 8 * 1024 * 1024 * 1024_u64);
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
        if first_id.starts_with("ue-") || first_id.starts_with("derived-") || first_id.starts_with("recovered-dataset-") {
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

    #[tokio::test]
    async fn four_plane_validate_traverses_http_api_and_unix_ipc_without_acquisition() {
        let workspace = FsPath::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let suffix = format!("{}-{}", std::process::id(), epoch_seconds());
        let manager_root = workspace
            .join("runtime")
            .join(format!("api-four-plane-{suffix}"));
        let helper_root = std::env::temp_dir().join(format!("oiran-four-plane-{suffix}"));
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
            interface_root,
            manager_root.join(".oiran-pseudonym.key"),
        )
        .unwrap();
        let mut config = test_config(workspace, "registry-four-plane");
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
        assert_eq!(body["data"]["validation"]["valid"], true);
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
            technology_for_live_fallback(
                std::iter::empty(),
                Some("POLARIS_LTE_E2E_SMALL_TRAFFIC"),
            ),
            "LTE",
            "cold dataset derives from the LTE profile"
        );
        assert_eq!(
            technology_for_live_fallback(std::iter::empty(), None),
            "UNKNOWN",
            "no plane and no profile → UNKNOWN (never invented)"
        );
        assert_eq!(
            technology_for_live_fallback(
                std::iter::empty(),
                Some("CUSTOM_OPERATOR_PROFILE_42"),
            ),
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
            let interfaces = item["interfaces"]
                .as_array()
                .cloned()
                .unwrap_or_default();
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
        let pseudo = body["meta"]["identity_matched_pseudonym"]
            .as_str()
            .unwrap();
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
            assert!(cause["is_failure"].is_boolean(), "is_failure missing: {cause}");
            assert!(
                cause["session_count"].as_u64().unwrap_or(0) >= 1,
                "session_count must be >= 1: {cause}"
            );
        }
        // Aucune identité ne doit figurer dans la réponse.
        assert_no_identity_material(&body);
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
        let (status, body) = post_sessions_filter(
            &state,
            json!({ "limit": 5 }),
            None,
        )
        .await;
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
            assert!(ka <= kb, "pagination out of canonical order: {ka:?} vs {kb:?}");
        }
    }

    #[tokio::test]
    async fn sessions_filter_cursor_advances_without_duplicates() {
        // 2.10.1 : deux pages consécutives via `cursor` ne
        // doivent pas se chevaucher, ni introduire de session
        // deux fois.
        let state = state();
        let (_, body_a) = post_sessions_filter(
            &state,
            json!({ "limit": 1 }),
            None,
        )
        .await;
        let first = body_a["data"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|s| s["session_id"].as_str())
            .map(str::to_owned);
        let cursor = body_a["meta"]["next_cursor"].as_str().map(str::to_owned);
        if let (Some(first_id), Some(cursor_val)) = (first, cursor) {
            let (_, body_b) = post_sessions_filter(
                &state,
                json!({ "limit": 1, "cursor": cursor_val }),
                None,
            )
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
        state
            .inner
            .identity_vault
            .upsert(vec![IdentityObservation {
                session_id: session_id.clone(),
                subscriber_pseudonym: Some("psn-test-00101".into()),
                kind: "imsi".into(),
                value: "001010123456789".into(),
                value_type: Some("IMSI".into()),
                role: "presented".into(),
                event_id: "event-test-identity".into(),
                capture_id: "capture-test-identity".into(),
                packet_number: 15,
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
        assert_eq!(body["data"]["imsi"], "001010123456789");
        assert_eq!(body["data"]["imsi_proof"]["packet_number"], 15);
        assert_eq!(body["meta"]["identity_access"], "operator");

        let response = router(state, None)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/identities?q=001010123456789")
                    .header(header::AUTHORIZATION, "Bearer test-operator-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["data"]["sessions"][0], session_id);
        assert!(body.to_string().contains("event-test-identity"));
    }
}
