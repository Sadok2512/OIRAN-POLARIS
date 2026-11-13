//! 2.14.7 (ANR1 #10) — read-time rewrite of stale `CallFlowEvent`
//! fields using the richer raw `NormalizedEvent` records retained in
//! `oiran_events.jsonl`. The patcher does NOT mutate any file on disk:
//! only the in-memory `flow_values` map served by
//! `/api/v1/sessions/<id>/events`.
//!
//! The patcher is the "one source of truth" for the three ingestion-time
//! heuristics introduced by the 2.14.5 lot — it calls the exact public
//! helpers exposed by the decoder crates:
//!
//! - [`oiran_decode::infer_sctp_network_function`] (SCTP port-based
//!   `network_function` fallback: 36412 ↔ MME/eNB, 38412 ↔ AMF/gNB).
//! - [`decoder_s1ap::infer_direction_from_network_functions`] (direction
//!   derived strictly from the SCTP transport).
//! - [`decoder_s1ap::message_name`] (TS 36.413 §9.1 procedure table,
//!   procedureCode × PduKind).
//! - [`decoder_s1ap::combined_message_name`] (`<S1AP procedure> · <NAS>`).
//! - [`decoder_nas::mm_eps_name`] (TS 24.301 §9.8.1 EMM message types,
//!   notably 0x5D Security mode command).
//!
//! Every patched event carries a `read_time_patch` object recording the
//! patcher version and the list of fields that were rewritten. Idempotent
//! by design: an event already consistent with the 2.14.7 helpers is not
//! modified and is not counted.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use event_schema::Endpoint;
use serde_json::{json, Value};

/// Version exposée sur chaque objet `read_time_patch` et dans
/// `/api/v1/version.read_time_patch.version`. Suit systématiquement
/// la version Cargo d'`oiran-api` : chaque bump du package met à
/// jour le marqueur de provenance et permet à la gate ANR1 de
/// distinguer les événements patchés par la version courante des
/// événements patchés par une version antérieure. Lu depuis
/// `env!("CARGO_PKG_VERSION")`, jamais écrit en dur.
pub const PATCH_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Snapshot of patch activity since the service started. Shared via
/// `Arc`; every field is atomic for lock-free reads from `/version`.
#[derive(Debug, Default)]
pub struct PatchCounters {
    pub callflows_loaded: AtomicU64,
    pub events_seen: AtomicU64,
    pub events_patched_source_participant: AtomicU64,
    pub events_patched_destination_participant: AtomicU64,
    pub events_patched_direction: AtomicU64,
    pub events_patched_message_name: AtomicU64,
    /// Events whose SCTP transport did not resolve to a known
    /// `network_function` (participant stays explicitly
    /// `"Unknown endpoint"`, ouvert et comptable).
    pub events_unresolved_participant: AtomicU64,
    /// Events where the JSONL did not expose a raw `NormalizedEvent`
    /// to cross-reference (e.g., the sidecar `oiran_events.jsonl` is
    /// absent). Surfaced so the gate cannot pass silently.
    pub events_without_raw_counterpart: AtomicU64,
    /// 2.14.9 (ANR1 #10 6859228701) — compteurs du cache LRU des
    /// indexes raw par session. Exposés sous
    /// `/api/v1/version.read_time_patch.cache.*`.
    pub cache_bytes: AtomicU64,
    pub cache_sessions: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_evictions: AtomicU64,
    /// 2.14.11 (ANR1 #10 6860508699) — compteurs de l'index compact
    /// construit UNE fois au démarrage (en flux, en arrière-plan)
    /// pour que la lecture d'une session ne relise pas
    /// `oiran_events.jsonl` en entier (3,4 Go côté prod ANR1 → ~60 s
    /// par cache miss en 2.14.9). Exposés sous
    /// `/api/v1/version.read_time_patch.index.*`.
    pub index_entries: AtomicU64,
    pub index_bytes: AtomicU64,
    pub index_build_ms: AtomicU64,
    pub index_last_offset: AtomicU64,
    pub index_ready: AtomicBool,
    /// Nombre de requêtes servies sans patch parce que l'index
    /// n'était pas prêt (réponse marquée `read_time_patch.status =
    /// "index_building"`). Jamais une correction silencieuse.
    pub index_building_responses: AtomicU64,
    /// Nombre de collisions hash (event_id → u64) détectées à la
    /// lecture ; pour chaque collision l'événement cible n'est PAS
    /// patché. Conservé à 0 en prod (p ≈ 10⁻⁷ pour 1,55 M entrées).
    pub index_hash_collisions: AtomicU64,
    /// Nombre d'événements pour lesquels l'index a fourni un offset
    /// ET la lecture par seek a produit la raw Value correspondante.
    pub index_hits: AtomicU64,
    /// Nombre d'événements cherchés mais absents de l'index (session
    /// qui porte des events antérieurs à la construction initiale et
    /// non capturés par l'extension append-only — rare, signale un
    /// désalignement).
    pub index_misses: AtomicU64,
}

impl PatchCounters {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_json(&self) -> Value {
        json!({
            "version": PATCH_VERSION,
            "callflows_loaded": self.callflows_loaded.load(Ordering::Relaxed),
            "events_seen": self.events_seen.load(Ordering::Relaxed),
            "events_patched": {
                "source_participant": self
                    .events_patched_source_participant
                    .load(Ordering::Relaxed),
                "destination_participant": self
                    .events_patched_destination_participant
                    .load(Ordering::Relaxed),
                "direction": self.events_patched_direction.load(Ordering::Relaxed),
                "message_name": self.events_patched_message_name.load(Ordering::Relaxed),
            },
            "events_unresolved_participant": self
                .events_unresolved_participant
                .load(Ordering::Relaxed),
            "events_without_raw_counterpart": self
                .events_without_raw_counterpart
                .load(Ordering::Relaxed),
            "cache": {
                "bytes": self.cache_bytes.load(Ordering::Relaxed),
                "sessions": self.cache_sessions.load(Ordering::Relaxed),
                "hits": self.cache_hits.load(Ordering::Relaxed),
                "misses": self.cache_misses.load(Ordering::Relaxed),
                "evictions": self.cache_evictions.load(Ordering::Relaxed),
            },
            "index": {
                "entries": self.index_entries.load(Ordering::Relaxed),
                "bytes": self.index_bytes.load(Ordering::Relaxed),
                "build_ms": self.index_build_ms.load(Ordering::Relaxed),
                "last_offset": self.index_last_offset.load(Ordering::Relaxed),
                "ready": self.index_ready.load(Ordering::Relaxed),
                "building_responses": self.index_building_responses.load(Ordering::Relaxed),
                "hash_collisions": self.index_hash_collisions.load(Ordering::Relaxed),
                "hits": self.index_hits.load(Ordering::Relaxed),
                "misses": self.index_misses.load(Ordering::Relaxed),
            },
        })
    }
}

/// 2.14.9 (ANR1 #10 6859228701) — bornes configurables du cache LRU.
/// Par défaut : 16 sessions, 64 MiB. Override via `OIRAN_READ_TIME_PATCH_CACHE_SESSIONS`
/// et `OIRAN_READ_TIME_PATCH_CACHE_BYTES`. Les valeurs à 0 désactivent
/// la limite correspondante (dangereux en prod ; prévu pour les tests).
#[derive(Clone, Copy, Debug)]
pub struct CacheLimits {
    pub max_sessions: usize,
    pub max_bytes: usize,
}

impl CacheLimits {
    pub const DEFAULT_SESSIONS: usize = 16;
    pub const DEFAULT_BYTES: usize = 64 * 1024 * 1024;

    pub fn from_env() -> Self {
        let max_sessions = std::env::var("OIRAN_READ_TIME_PATCH_CACHE_SESSIONS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_SESSIONS);
        let max_bytes = std::env::var("OIRAN_READ_TIME_PATCH_CACHE_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_BYTES);
        Self {
            max_sessions,
            max_bytes,
        }
    }
}

/// 2.14.9 (ANR1 #10 6859228701) — cache LRU borné des index raw par
/// (dataset_root canonicalized, session_id). L'implémentation est
/// volontairement simple (VecDeque + HashMap, O(k) par promotion) pour
/// garder le code lisible : le volume de clés est borné par
/// `max_sessions` (par défaut 16).
///
/// Chaque entrée porte une estimation du poids en octets de l'index
/// (serialization length des Value conservés). `insert` évince
/// LRU-first jusqu'à ce que `cache_bytes <= max_bytes` et
/// `cache_sessions <= max_sessions`.
pub struct RawIndexCache {
    limits: CacheLimits,
    entries: Mutex<RawIndexCacheInner>,
    counters: Arc<PatchCounters>,
}

struct RawIndexCacheInner {
    by_key: HashMap<(PathBuf, String), CacheEntry>,
    order: VecDeque<(PathBuf, String)>,
    bytes: usize,
}

#[derive(Clone)]
struct CacheEntry {
    index: Arc<RawEventIndex>,
    weight_bytes: usize,
}

impl RawIndexCache {
    pub fn new(limits: CacheLimits, counters: Arc<PatchCounters>) -> Self {
        Self {
            limits,
            entries: Mutex::new(RawIndexCacheInner {
                by_key: HashMap::new(),
                order: VecDeque::new(),
                bytes: 0,
            }),
            counters,
        }
    }

    /// Résout l'index pour une session. Si absent du cache, construit
    /// un `RawEventIndex` scoped à l'ensemble d'`event_ids` demandé
    /// (lecture streaming du JSONL + shards, allocation bornée au
    /// sous-ensemble des événements de la session). Retourne None
    /// si l'I/O échoue.
    pub fn resolve(
        &self,
        dataset_root: &Path,
        session_id: &str,
        wanted_event_ids: &HashSet<String>,
    ) -> Option<Arc<RawEventIndex>> {
        let key_root = dataset_root
            .canonicalize()
            .unwrap_or_else(|_| dataset_root.to_path_buf());
        let key = (key_root.clone(), session_id.to_string());
        {
            let mut inner = self.entries.lock().ok()?;
            if let Some(entry) = inner.by_key.get(&key).cloned() {
                self.counters.cache_hits.fetch_add(1, Ordering::Relaxed);
                // Promotion : déplace la clé au bout de `order` (le plus
                // récemment utilisé). Coût O(|order|) bornés par
                // `max_sessions`.
                inner.order.retain(|existing| existing != &key);
                inner.order.push_back(key.clone());
                return Some(entry.index);
            }
        }
        self.counters.cache_misses.fetch_add(1, Ordering::Relaxed);
        let built = match RawEventIndex::from_dataset_root_for_event_ids(
            dataset_root,
            wanted_event_ids,
        ) {
            Ok(index) => index,
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({
                        "event": "READ_TIME_PATCH_INDEX_UNAVAILABLE",
                        "dataset_root": dataset_root.display().to_string(),
                        "session_id": session_id,
                        "wanted_events": wanted_event_ids.len(),
                        "error": error,
                    })
                );
                return None;
            }
        };
        let weight_bytes = built.estimated_bytes();
        let index = Arc::new(built);
        let mut inner = self.entries.lock().ok()?;
        inner.by_key.insert(
            key.clone(),
            CacheEntry {
                index: index.clone(),
                weight_bytes,
            },
        );
        inner.order.push_back(key);
        inner.bytes = inner.bytes.saturating_add(weight_bytes);
        self.enforce_limits(&mut inner);
        self.counters
            .cache_sessions
            .store(inner.by_key.len() as u64, Ordering::Relaxed);
        self.counters
            .cache_bytes
            .store(inner.bytes as u64, Ordering::Relaxed);
        Some(index)
    }

    fn enforce_limits(&self, inner: &mut RawIndexCacheInner) {
        while inner.by_key.len() > self.limits.max_sessions.max(1)
            || inner.bytes > self.limits.max_bytes.max(1)
        {
            let Some(victim) = inner.order.pop_front() else {
                break;
            };
            if let Some(entry) = inner.by_key.remove(&victim) {
                inner.bytes = inner.bytes.saturating_sub(entry.weight_bytes);
                self.counters.cache_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn snapshot_bytes(&self) -> usize {
        self.entries.lock().map(|inner| inner.bytes).unwrap_or(0)
    }

    pub fn snapshot_sessions(&self) -> usize {
        self.entries
            .lock()
            .map(|inner| inner.by_key.len())
            .unwrap_or(0)
    }
}

/// Index of raw `NormalizedEvent` records parsed from one
/// `oiran_events.jsonl`, keyed by `event_id`. Each value is the raw
/// JSON object; the patcher reads the port, procedure_code and
/// message_type from it. Reading the file once per flow keeps the cost
/// linear in events.
pub struct RawEventIndex {
    by_event_id: HashMap<String, Value>,
}

impl RawEventIndex {
    pub fn from_jsonl_path(path: &Path) -> Result<Self, String> {
        let mut by_event_id = HashMap::new();
        Self::ingest_jsonl_filtered(path, None, &mut by_event_id)?;
        Ok(Self { by_event_id })
    }

    /// 2.14.8 (ANR1 #10) — construction depuis un `dataset_root` qui
    /// contient `oiran_events.jsonl` ET/OU des event shards sous
    /// `event-shards/*.jsonl`. Charge TOUS les événements du dataset.
    /// **Non borné en mémoire** : réservé aux tests ou aux datasets
    /// dont la taille est connue a priori. La prod utilise
    /// `from_dataset_root_for_event_ids` qui filtre à la lecture.
    pub fn from_dataset_root(dataset_root: &Path) -> Result<Self, String> {
        Self::from_dataset_root_filtered(dataset_root, None)
    }

    /// 2.14.9 (ANR1 #10 6859228701) — construction scoped à un
    /// ensemble d'`event_ids`. Les lignes JSONL dont `event_id` n'est
    /// PAS dans `wanted` sont rejetées à la volée : l'allocation
    /// finale est bornée à `wanted.len()` événements et ne dépend
    /// pas de la taille du JSONL source. C'est le constructeur
    /// utilisé par le serving ANR1 (prod, 2.7 GiB de JSONL, 46
    /// sessions) : une session ouverte charge ~16 événements → ~16
    /// KiB au lieu de ~2 GiB.
    pub fn from_dataset_root_for_event_ids(
        dataset_root: &Path,
        wanted: &HashSet<String>,
    ) -> Result<Self, String> {
        Self::from_dataset_root_filtered(dataset_root, Some(wanted))
    }

    fn from_dataset_root_filtered(
        dataset_root: &Path,
        wanted: Option<&HashSet<String>>,
    ) -> Result<Self, String> {
        let mut by_event_id = HashMap::new();
        let flat = dataset_root.join("oiran_events.jsonl");
        if flat.is_file() {
            Self::ingest_jsonl_filtered(&flat, wanted, &mut by_event_id)?;
            if let Some(wanted) = wanted {
                if by_event_id.len() >= wanted.len() {
                    // Fast path : tous les événements demandés ont été
                    // trouvés dans le JSONL racine, inutile de scanner
                    // les event-shards.
                    return Ok(Self { by_event_id });
                }
            }
        }
        let shards_dir = dataset_root.join("event-shards");
        if shards_dir.is_dir() {
            let mut shard_paths: Vec<PathBuf> = std::fs::read_dir(&shards_dir)
                .map_err(|error| error.to_string())?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .and_then(|value| value.to_str())
                        .is_some_and(|value| value == "jsonl")
                })
                .collect();
            shard_paths.sort();
            for shard_path in shard_paths {
                Self::ingest_jsonl_filtered(&shard_path, wanted, &mut by_event_id)?;
                if let Some(wanted) = wanted {
                    if by_event_id.len() >= wanted.len() {
                        break;
                    }
                }
            }
        }
        Ok(Self { by_event_id })
    }

    fn ingest_jsonl_filtered(
        path: &Path,
        wanted: Option<&HashSet<String>>,
        out: &mut HashMap<String, Value>,
    ) -> Result<(), String> {
        let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
        let reader = BufReader::new(file);
        for (line_number, line) in reader.lines().enumerate() {
            let line = line.map_err(|error| error.to_string())?;
            if line.trim().is_empty() {
                continue;
            }
            // Short-cut streaming : extraire `event_id` via une regex
            // minimaliste AVANT de parser la Value entière, pour que
            // 99 % des lignes d'un JSONL multi-sessions ne paient pas
            // la désérialisation serde_json (allocation lourde) quand
            // leur event_id n'appartient pas à la session demandée.
            let event_id = match extract_event_id(&line) {
                Some(id) => id,
                None => continue,
            };
            if let Some(wanted) = wanted {
                if !wanted.contains(event_id) {
                    continue;
                }
            }
            let value: Value = serde_json::from_str(&line).map_err(|error| {
                format!(
                    "{}:{}: invalid JSONL: {error}",
                    path.display(),
                    line_number + 1
                )
            })?;
            out.insert(event_id.to_string(), value);
        }
        Ok(())
    }

    /// 2.14.9 — estimation du poids mémoire de l'index pour piloter
    /// le LRU. Approximation par la longueur sérialisée de chaque
    /// Value (overhead de l'allocation `serde_json::Value` ~2-3× en
    /// pratique, mais l'approximation suffit pour borner la croissance).
    pub fn estimated_bytes(&self) -> usize {
        self.by_event_id
            .iter()
            .map(|(key, value)| key.len() + value.to_string().len())
            .sum()
    }

    pub fn get(&self, event_id: &str) -> Option<&Value> {
        self.by_event_id.get(event_id)
    }

    pub fn len(&self) -> usize {
        self.by_event_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_event_id.is_empty()
    }
}

/// 2.14.9 — extraction lexicale rapide de l'`event_id` d'une ligne
/// JSONL sans allouer la Value entière. Utilisé par l'ingestion
/// filtrée pour que 99 % des lignes d'un JSONL multi-sessions soient
/// rejetées avant la désérialisation serde_json complète. La règle
/// cherche le premier token `"event_id"` suivi d'un `:` puis une
/// chaîne JSON `"..."` (pas d'échappement complexe attendu ; le
/// publisher écrit des ids safe : `evt-<hex>`, cf. decoder-s1ap).
fn extract_event_id(line: &str) -> Option<&str> {
    let key = line.find("\"event_id\"")?;
    let after = &line[key + "\"event_id\"".len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn endpoint_from_raw(value: Option<&Value>) -> (Option<Endpoint>, Option<u16>) {
    let object = match value.and_then(Value::as_object) {
        Some(object) => object,
        None => return (None, None),
    };
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let port = object
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok());
    let nf = object
        .get("network_function")
        .and_then(Value::as_str)
        .map(str::to_string);
    let endpoint = Endpoint {
        address,
        port,
        network_function: nf,
    };
    (Some(endpoint), port)
}

fn kind_from_u32(value: u32) -> decoder_s1ap::PduKind {
    match value {
        1 => decoder_s1ap::PduKind::SuccessfulOutcome,
        2 => decoder_s1ap::PduKind::UnsuccessfulOutcome,
        _ => decoder_s1ap::PduKind::Initiating,
    }
}

fn kind_from_ngap_u32(value: u32) -> decoder_ngap::PduKind {
    match value {
        1 => decoder_ngap::PduKind::SuccessfulOutcome,
        2 => decoder_ngap::PduKind::UnsuccessfulOutcome,
        _ => decoder_ngap::PduKind::Initiating,
    }
}

/// 2.14.9 (ANR1 #10) — nom canonique de la procédure porteuse, S1AP
/// (TS 36.413) ou NGAP (TS 38.413). Les deux appelées à la même
/// signature mais via deux tables disjointes. Une seule source de
/// vérité par protocole (les fonctions publiques des décodeurs).
fn s1ap_name_for(raw: &Value) -> Option<String> {
    let protocol = raw.get("protocol").and_then(Value::as_str)?;
    let code = raw
        .get("procedure_code")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())?;
    let kind_number = raw
        .get("message_type")
        .and_then(Value::as_u64)
        .map(|value| value as u32)
        .unwrap_or(0);
    match protocol {
        "S1AP" => Some(decoder_s1ap::message_name(code, kind_from_u32(kind_number))),
        "NGAP" => Some(
            decoder_ngap::message_name(code, kind_from_ngap_u32(kind_number)).to_string(),
        ),
        _ => None,
    }
}

fn nas_name_for(raw: &Value, parent_name: &str) -> Option<String> {
    let protocol = raw.get("protocol").and_then(Value::as_str)?;
    let (is_eps, is_sm, is_fiveg) = match protocol {
        "NAS-EPS-MM" | "NasEpsMm" => (true, false, false),
        "NAS-EPS-SM" | "NasEpsSm" => (true, true, false),
        "NAS-5GMM" | "Nas5gmm" => (false, false, true),
        "NAS-5GSM" | "Nas5gsm" => (false, true, true),
        _ => return None,
    };
    let message_type = raw
        .get("message_type")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    // 2.14.7-2.14.9 (ANR1 #10) : `message_type == 0` sur un
    // événement NAS enfant signale un NAS chiffré. Placeholder
    // publique uniforme « NAS chiffré » (remplace « Protected EPS
    // EMM message », « Protected 5GMM message », etc.).
    let nas_name: &str = if message_type == 0 {
        "NAS chiffré"
    } else if is_fiveg {
        // TS 24.501 §9.7 — même table que decoder-nas à l'ingestion.
        if is_sm {
            decoder_nas::sm_name_5g(message_type as u8).0
        } else {
            decoder_nas::mm_name(message_type as u8).0
        }
    } else if is_eps {
        // TS 24.301 §9.8 — mm_eps_name (table auditée en 2.14.5).
        // L'extension SM EPS n'est pas exposée publiquement ; on y
        // retombe dans la variante MM par défaut quand le décodeur
        // d'ingestion renvoie "NAS-EPS-SM" sans entrée dédiée côté
        // mm_eps_name. Les captures lab n'exposent pas de SM EPS
        // dédié → aucun impact prod observé.
        let _ = is_sm;
        decoder_nas::mm_eps_name(message_type as u8).0
    } else {
        return None;
    };
    Some(decoder_s1ap::combined_message_name(parent_name, nas_name))
}

/// Patch a vector of `CallFlowEvent` values in place. Returns the
/// number of events that were actually modified.
pub fn patch_flow_events(
    events: &mut Vec<Value>,
    raw_index: &RawEventIndex,
    endpoint_map: &HashMap<String, String>,
    counters: &Arc<PatchCounters>,
) -> usize {
    let mut rewritten = 0usize;
    for event in events.iter_mut() {
        counters.events_seen.fetch_add(1, Ordering::Relaxed);
        let event_id = event.get("event_id").and_then(Value::as_str).unwrap_or("");
        let raw = match raw_index.get(event_id) {
            Some(raw) => raw.clone(),
            None => {
                counters
                    .events_without_raw_counterpart
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        if patch_one(event, &raw, raw_index, endpoint_map, counters) {
            rewritten += 1;
        }
    }
    rewritten
}

fn patch_one(
    event: &mut Value,
    raw: &Value,
    raw_index: &RawEventIndex,
    endpoint_map: &HashMap<String, String>,
    counters: &Arc<PatchCounters>,
) -> bool {
    let interface = raw
        .get("interface")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let (source_opt, source_port) = endpoint_from_raw(raw.get("source_endpoint"));
    let (destination_opt, destination_port) = endpoint_from_raw(raw.get("destination_endpoint"));
    let mut source = match source_opt {
        Some(endpoint) => endpoint,
        None => return false,
    };
    let mut destination = match destination_opt {
        Some(endpoint) => endpoint,
        None => return false,
    };
    // 1) IP map (production endpoint_map) — ne remplit que si vide.
    if source.network_function.is_none() {
        source.network_function = endpoint_map.get(&source.address).cloned();
    }
    if destination.network_function.is_none() {
        destination.network_function = endpoint_map.get(&destination.address).cloned();
    }
    // 2) Port-based SCTP fallback — même fonction que l'ingestion
    //    (oiran-decode).
    if let (Some(src_port), Some(dst_port)) = (source_port, destination_port) {
        oiran_decode::infer_sctp_network_function(
            interface.as_str(),
            &mut source,
            &mut destination,
            src_port,
            dst_port,
        );
    }
    // 3) Direction via les deux NF — même fonction que decoder-s1ap
    //    (strict transport, pas de fallback procedureCode).
    let new_direction = decoder_s1ap::infer_direction_from_network_functions(
        source.network_function.as_deref(),
        destination.network_function.as_deref(),
    );

    // 4) message_name : d'abord le parent S1AP recalculé, puis le NAS
    //    combiné pour les enfants.
    let parent_s1ap_name = raw
        .get("parent_event_id")
        .and_then(Value::as_str)
        .and_then(|parent_id| raw_index.get(parent_id))
        .and_then(s1ap_name_for);
    let new_message_name = if let Some(parent_name) = parent_s1ap_name.as_deref() {
        nas_name_for(raw, parent_name)
    } else {
        s1ap_name_for(raw)
    };

    // Publier les nouvelles valeurs si elles diffèrent (idempotent).
    let mut patched_fields: Vec<&'static str> = Vec::new();

    let new_source = source
        .network_function
        .clone()
        .unwrap_or_else(|| "Unknown endpoint".to_string());
    let new_destination = destination
        .network_function
        .clone()
        .unwrap_or_else(|| "Unknown endpoint".to_string());

    let event_object = match event.as_object_mut() {
        Some(object) => object,
        None => return false,
    };

    // 2.14.8 (ANR1 #10) — enrichissement idempotent : expose
    // `source_address` / `destination_address` sur l'événement patché
    // pour que `recompute_session_participants` puisse reconstruire
    // `core_node = "MME 10.77.10.10"` depuis l'IP raw. CallFlowEvent
    // ne stocke pas ces champs, ils viennent du raw JSONL. Pas de
    // provenance pour un simple ajout d'adresse (le participant est
    // déjà tracé via `read_time_patch.fields`).
    if !source.address.is_empty() {
        event_object.insert(
            "source_address".into(),
            Value::String(source.address.clone()),
        );
    }
    if !destination.address.is_empty() {
        event_object.insert(
            "destination_address".into(),
            Value::String(destination.address.clone()),
        );
    }

    let old_source = event_object
        .get("source_participant")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if old_source != new_source {
        event_object.insert(
            "source_participant".into(),
            Value::String(new_source.clone()),
        );
        counters
            .events_patched_source_participant
            .fetch_add(1, Ordering::Relaxed);
        patched_fields.push("source_participant");
    }
    if new_source == "Unknown endpoint" {
        counters
            .events_unresolved_participant
            .fetch_add(1, Ordering::Relaxed);
    }

    let old_destination = event_object
        .get("destination_participant")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if old_destination != new_destination {
        event_object.insert(
            "destination_participant".into(),
            Value::String(new_destination),
        );
        counters
            .events_patched_destination_participant
            .fetch_add(1, Ordering::Relaxed);
        patched_fields.push("destination_participant");
    }

    let new_direction_str = match new_direction {
        event_schema::Direction::RanToCore => "RAN_TO_CORE",
        event_schema::Direction::CoreToRan => "CORE_TO_RAN",
        _ => "UNKNOWN",
    };
    let old_direction = event_object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    // On n'écrase la direction que si on dispose d'un transport résolu :
    // sinon on respecte la valeur stockée (évite d'écraser une bonne
    // direction héritée d'une autre heuristique par « UNKNOWN »).
    if new_direction != event_schema::Direction::Unknown && old_direction != new_direction_str {
        event_object.insert(
            "direction".into(),
            Value::String(new_direction_str.to_string()),
        );
        counters
            .events_patched_direction
            .fetch_add(1, Ordering::Relaxed);
        patched_fields.push("direction");
    }

    if let Some(new_name) = new_message_name {
        let old_name = event_object
            .get("message_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if old_name != new_name {
            event_object.insert("message_name".into(), Value::String(new_name));
            counters
                .events_patched_message_name
                .fetch_add(1, Ordering::Relaxed);
            patched_fields.push("message_name");
        }
    }

    if !patched_fields.is_empty() {
        event_object.insert(
            "read_time_patch".into(),
            json!({
                "version": PATCH_VERSION,
                "fields": patched_fields,
            }),
        );
        true
    } else {
        false
    }
}

/// 2.14.8 (ANR1 #10) — à partir des `source_participant` et
/// `destination_participant` (éventuellement patchés) de chaque
/// événement, recalcule les 3 synthèses exposées dans le `session_summary` :
///
/// - `serving_ran_node` : premier participant avec un rôle ∈ {eNB, gNB}.
/// - `core_node` : premier participant avec un rôle ∈ {MME, AMF}.
/// - `serving_node` : alias conservé pour compat 2.14.3, égal à
///   `serving_ran_node`.
///
/// Les trois sont retournés au format « ROLE ADRESSE » (ex. « MME
/// 10.77.10.10 ») ou « UNKNOWN » si aucun participant ne colle. La
/// fonction s'applique sur une copie `Value` ; l'appelant la ré-injecte
/// dans la session summary.
pub fn recompute_session_participants(events: &[Value]) -> (String, String, String) {
    use std::collections::BTreeMap;
    let mut participants: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for event in events {
        for (role_key, address_key) in [
            ("source_participant", "source_address"),
            ("destination_participant", "destination_address"),
        ] {
            let role = event.get(role_key).and_then(Value::as_str).unwrap_or("");
            if role.is_empty() || role == "Unknown endpoint" {
                continue;
            }
            let address = event
                .get(address_key)
                .and_then(Value::as_str)
                .unwrap_or("");
            let entry = participants.entry(role.to_string()).or_default();
            if !address.is_empty() && !entry.iter().any(|existing| existing == address) {
                entry.push(address.to_string());
            }
        }
    }
    let first = |roles: &[&str]| -> String {
        for role in roles {
            if let Some(addresses) = participants.get(*role) {
                let address = addresses.first().map(String::as_str).unwrap_or("");
                return format!("{role} {address}").trim().to_string();
            }
        }
        "UNKNOWN".to_string()
    };
    let serving_ran_node = first(&["gNB", "eNB"]);
    let core_node = first(&["AMF", "MME"]);
    let serving_node = serving_ran_node.clone();
    (serving_node, serving_ran_node, core_node)
}

// =====================================================================
// 2.14.11 (ANR1 #10 6860508699) — Compact JSONL byte-offset index.
//
// Why : la 2.14.9 relit `oiran_events.jsonl` en entier à chaque session
// non cachée (35 s / 2 Go → ~60 s / 3,4 Go côté prod). On construit à la
// place, UNE fois au démarrage et EN ARRIÈRE-PLAN, un index compact
// `event_id → byte_offset` (RAM only, aucune écriture disque). Chaque
// lecture de session fait alors seek + read ciblé sur les lignes utiles.
//
// Budget RAM : HashMap<u64, u64> + Vec<u64> empaqueté. Pour 1,55 M
// entrées → ~29 MiB mesurés, bien sous les 64 MiB du cahier des charges.
//
// Append-only : `oiran_events.jsonl` ne grossit qu'en ajout. Un worker
// relit depuis `last_offset` toutes les `POLL_INTERVAL_SECS` pour
// étendre l'index sans tout re-scanner.
//
// Pas prêt : `apply_read_time_patch` retourne `PatchStatus::IndexBuilding`,
// le handler marque `read_time_patch.status = "index_building"` sur la
// réponse. Aucune correction silencieuse.
// =====================================================================

/// Hash lexical rapide de l'`event_id` → u64. La probabilité de
/// collision pour 1,55 M entrées sous un hash 64 bits est de l'ordre
/// de 10⁻⁷ (borne d'anniversaire). Si la lecture par seek renvoie un
/// `event_id` différent de celui demandé, la détection est faite
/// côté `get_raw_value` et comptée dans `index_hash_collisions`.
fn hash_event_id(event_id: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    event_id.hash(&mut hasher);
    hasher.finish()
}

/// Statut d'application du patcher sur une tranche d'événements.
/// Exposé à l'appelant pour qu'il puisse marquer explicitement la
/// réponse (`read_time_patch.status = "index_building"`) quand le
/// patch a été SKIP. Jamais une correction partielle silencieuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchStatus {
    /// Le patcher a bien reçu un `RawEventIndex` et l'a appliqué. Le
    /// nombre d'événements effectivement patchés est reflété dans
    /// `PatchCounters.events_patched_*` et sur chaque événement via
    /// `read_time_patch.fields`.
    Applied,
    /// L'index compact n'était pas encore prêt — réponse servie SANS
    /// correction. Le handler ajoute `read_time_patch.status =
    /// "index_building"` sur la réponse.
    IndexBuilding,
    /// Rien à faire (pas de dataset_root, items vide, pas d'event_ids
    /// cherchables). Le handler N'AJOUTE PAS de status — la réponse
    /// est la même qu'avant 2.14.11.
    NotApplicable,
}

impl PatchStatus {
    /// Label stable exposé dans les réponses JSON. `None` signifie
    /// que le handler NE DOIT PAS ajouter de champ status (cas
    /// `NotApplicable`).
    pub fn label(self) -> Option<&'static str> {
        match self {
            PatchStatus::Applied => Some("applied"),
            PatchStatus::IndexBuilding => Some("index_building"),
            PatchStatus::NotApplicable => None,
        }
    }
}

/// Index compact d'un fichier `*.jsonl` : hash(event_id) → byte offset
/// de la ligne source. Construit en flux au démarrage (en arrière-plan),
/// étendu de manière incrémentale depuis `last_offset` (append-only).
pub struct CompactJsonlIndex {
    path: PathBuf,
    by_hash: Mutex<HashMap<u64, u64>>,
    last_offset: AtomicU64,
    ready: AtomicBool,
    build_ms: AtomicU64,
    entries: AtomicU64,
    bytes_estimate: AtomicU64,
    hash_collisions: AtomicU64,
    /// Flag d'idempotence du spawn : `claim_build()` renvoie `true`
    /// exactement une fois pour qu'un seul worker background se lance
    /// par index. Les appels suivants renvoient `false`.
    build_spawned: AtomicBool,
}

impl CompactJsonlIndex {
    /// Bornes publiques pour le test de charge et la gate prod.
    pub const MEMORY_BUDGET_BYTES: usize = 64 * 1024 * 1024;

    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            by_hash: Mutex::new(HashMap::new()),
            last_offset: AtomicU64::new(0),
            ready: AtomicBool::new(false),
            build_ms: AtomicU64::new(0),
            entries: AtomicU64::new(0),
            bytes_estimate: AtomicU64::new(0),
            hash_collisions: AtomicU64::new(0),
            build_spawned: AtomicBool::new(false),
        }
    }

    /// Réclame le droit de spawner le worker de build initial.
    /// Idempotent : renvoie `true` exactement une fois. L'appelant
    /// (API) utilise ce flag pour ne spawner qu'un seul tokio task
    /// par fichier indexé.
    pub fn claim_build(&self) -> bool {
        self.build_spawned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn entries(&self) -> u64 {
        self.entries.load(Ordering::Relaxed)
    }

    pub fn bytes_estimate(&self) -> u64 {
        self.bytes_estimate.load(Ordering::Relaxed)
    }

    pub fn build_ms(&self) -> u64 {
        self.build_ms.load(Ordering::Relaxed)
    }

    pub fn last_offset(&self) -> u64 {
        self.last_offset.load(Ordering::Relaxed)
    }

    /// Construction initiale (streaming). Marque `ready=true` à la
    /// fin ; `build_ms` est la durée totale. Non bloquant côté
    /// serving : appelé par un worker background.
    pub fn build_initial(&self) -> Result<(), String> {
        let started = Instant::now();
        self.extend_from_offset(0)?;
        let elapsed = started.elapsed().as_millis() as u64;
        self.build_ms.store(elapsed, Ordering::Relaxed);
        self.ready.store(true, Ordering::Release);
        Ok(())
    }

    /// Extension append-only depuis `last_offset`. Sûr à appeler
    /// répétitivement. `oiran_events.jsonl` est append-only (confirmé
    /// par les commentaires `live-probe/src/lib.rs:6787`), donc les
    /// offsets déjà indexés restent valides.
    pub fn extend_from_tail(&self) -> Result<(), String> {
        let from = self.last_offset.load(Ordering::Relaxed);
        self.extend_from_offset(from)
    }

    fn extend_from_offset(&self, from: u64) -> Result<(), String> {
        let mut file = std::fs::File::open(&self.path).map_err(|error| error.to_string())?;
        file.seek(SeekFrom::Start(from))
            .map_err(|error| error.to_string())?;
        let mut reader = BufReader::new(file);
        let mut current_offset = from;
        let mut line_buffer = String::new();
        let mut local_entries: u64 = 0;
        let mut local_bytes: u64 = 0;
        let mut local_collisions: u64 = 0;
        loop {
            line_buffer.clear();
            let bytes_read = reader
                .read_line(&mut line_buffer)
                .map_err(|error| error.to_string())?;
            if bytes_read == 0 {
                break;
            }
            let line_start = current_offset;
            current_offset = current_offset.saturating_add(bytes_read as u64);
            let trimmed = line_buffer.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                continue;
            }
            let Some(event_id) = extract_event_id(trimmed) else {
                continue;
            };
            let key = hash_event_id(event_id);
            let mut map = match self.by_hash.lock() {
                Ok(guard) => guard,
                Err(_) => return Err("compact index mutex poisoned".into()),
            };
            if let Some(previous) = map.insert(key, line_start) {
                if previous != line_start {
                    local_collisions = local_collisions.saturating_add(1);
                }
            } else {
                local_entries = local_entries.saturating_add(1);
                // Approximation stable : u64 clé + u64 valeur + 2 B de
                // métadonnées hashbrown en moyenne avec un load factor
                // ~0,875. 20 B/entrée, mesure confirmée par le test
                // de charge 3,4 Go.
                local_bytes = local_bytes.saturating_add(20);
            }
        }
        self.last_offset.store(current_offset, Ordering::Relaxed);
        if local_entries > 0 {
            self.entries.fetch_add(local_entries, Ordering::Relaxed);
            self.bytes_estimate.fetch_add(local_bytes, Ordering::Relaxed);
        }
        if local_collisions > 0 {
            self.hash_collisions
                .fetch_add(local_collisions, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Lecture ciblée : retourne la raw `Value` de l'événement
    /// correspondant à `event_id`, ou `None` si l'id n'est pas dans
    /// l'index (session partielle) OU si la lecture seek renvoie une
    /// ligne dont `event_id` ne correspond pas (collision hash,
    /// comptée dans `hash_collisions`).
    pub fn get_raw_value(&self, event_id: &str) -> Option<Value> {
        let key = hash_event_id(event_id);
        let offset = {
            let map = self.by_hash.lock().ok()?;
            *map.get(&key)?
        };
        let mut file = std::fs::File::open(&self.path).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).ok()?;
        if bytes_read == 0 {
            return None;
        }
        let trimmed = line.trim_end_matches(['\n', '\r']);
        // Vérification identité : si collision hash, l'`event_id` lu
        // ne sera pas celui demandé → on ne patche pas cet événement.
        let read_id = extract_event_id(trimmed)?;
        if read_id != event_id {
            self.hash_collisions.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        serde_json::from_str(trimmed).ok()
    }

    pub fn hash_collisions(&self) -> u64 {
        self.hash_collisions.load(Ordering::Relaxed)
    }
}

/// Registre des indexes compacts par `dataset_root` canonicalisé.
/// Un worker background est spawné à la première `ensure_tracking`
/// d'un root ; il construit l'index initial puis étend en continu.
///
/// La mise à jour des compteurs partagés `PatchCounters.index_*` se
/// fait depuis ce registre : chaque appel à `snapshot_into_counters`
/// pousse les totaux agrégés (toutes files du root courant).
pub struct CompactJsonlIndexRegistry {
    tracked: Mutex<HashMap<PathBuf, Arc<DatasetIndexes>>>,
    counters: Arc<PatchCounters>,
}

pub struct DatasetIndexes {
    pub flat: Option<Arc<CompactJsonlIndex>>,
    pub shards: Vec<Arc<CompactJsonlIndex>>,
}

impl DatasetIndexes {
    pub fn all_ready(&self) -> bool {
        let flat_ready = self.flat.as_ref().map(|idx| idx.is_ready()).unwrap_or(true);
        let shards_ready = self.shards.iter().all(|idx| idx.is_ready());
        flat_ready && shards_ready
    }

    /// Lookup : essaie d'abord le flat JSONL, puis chaque shard dans
    /// l'ordre de construction. Retourne la première raw Value trouvée.
    pub fn lookup(&self, event_id: &str) -> Option<Value> {
        if let Some(flat) = &self.flat {
            if let Some(value) = flat.get_raw_value(event_id) {
                return Some(value);
            }
        }
        for shard in &self.shards {
            if let Some(value) = shard.get_raw_value(event_id) {
                return Some(value);
            }
        }
        None
    }

    pub fn total_entries(&self) -> u64 {
        let mut total = 0u64;
        if let Some(flat) = &self.flat {
            total = total.saturating_add(flat.entries());
        }
        for shard in &self.shards {
            total = total.saturating_add(shard.entries());
        }
        total
    }

    pub fn total_bytes(&self) -> u64 {
        let mut total = 0u64;
        if let Some(flat) = &self.flat {
            total = total.saturating_add(flat.bytes_estimate());
        }
        for shard in &self.shards {
            total = total.saturating_add(shard.bytes_estimate());
        }
        total
    }

    pub fn max_build_ms(&self) -> u64 {
        let mut max = 0u64;
        if let Some(flat) = &self.flat {
            max = max.max(flat.build_ms());
        }
        for shard in &self.shards {
            max = max.max(shard.build_ms());
        }
        max
    }

    pub fn max_last_offset(&self) -> u64 {
        let mut max = 0u64;
        if let Some(flat) = &self.flat {
            max = max.max(flat.last_offset());
        }
        for shard in &self.shards {
            max = max.max(shard.last_offset());
        }
        max
    }

    pub fn total_hash_collisions(&self) -> u64 {
        let mut total = 0u64;
        if let Some(flat) = &self.flat {
            total = total.saturating_add(flat.hash_collisions());
        }
        for shard in &self.shards {
            total = total.saturating_add(shard.hash_collisions());
        }
        total
    }
}

impl CompactJsonlIndexRegistry {
    pub fn new(counters: Arc<PatchCounters>) -> Self {
        Self {
            tracked: Mutex::new(HashMap::new()),
            counters,
        }
    }

    /// Enregistre un `dataset_root` et retourne son set d'indexes. Si
    /// c'est le premier appel pour ce root, crée les objets
    /// `CompactJsonlIndex` pour `oiran_events.jsonl` + chaque shard
    /// *existant au moment de l'appel* et renvoie le set. Les
    /// workers de construction sont spawnés par
    /// `spawn_background_build` séparément (pour que le constructeur
    /// reste synchrone et sans dépendance tokio ; le callsite side
    /// api::lib.rs choisit quand spawner).
    pub fn ensure_tracking(&self, dataset_root: &Path) -> Arc<DatasetIndexes> {
        let key = dataset_root
            .canonicalize()
            .unwrap_or_else(|_| dataset_root.to_path_buf());
        {
            let guard = self.tracked.lock().unwrap();
            if let Some(existing) = guard.get(&key) {
                return existing.clone();
            }
        }
        let flat_path = dataset_root.join("oiran_events.jsonl");
        let flat = if flat_path.is_file() {
            Some(Arc::new(CompactJsonlIndex::new(flat_path)))
        } else {
            None
        };
        let mut shards: Vec<Arc<CompactJsonlIndex>> = Vec::new();
        let shards_dir = dataset_root.join("event-shards");
        if shards_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&shards_dir) {
                let mut paths: Vec<PathBuf> = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.extension()
                            .and_then(|value| value.to_str())
                            .is_some_and(|value| value == "jsonl")
                    })
                    .collect();
                paths.sort();
                for shard_path in paths {
                    shards.push(Arc::new(CompactJsonlIndex::new(shard_path)));
                }
            }
        }
        let bundle = Arc::new(DatasetIndexes { flat, shards });
        let mut guard = self.tracked.lock().unwrap();
        guard
            .entry(key)
            .or_insert_with(|| bundle.clone())
            .clone()
    }

    /// Pousse l'état agrégé de TOUS les indexes du registre vers les
    /// compteurs partagés. Idempotent ; appelé par le worker après
    /// chaque passe (initial build ou extend_from_tail).
    pub fn snapshot_into_counters(&self) {
        let (entries, bytes, build_ms, last_offset, ready, collisions) = {
            let guard = match self.tracked.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            let mut entries = 0u64;
            let mut bytes = 0u64;
            let mut build_ms = 0u64;
            let mut last_offset = 0u64;
            let mut collisions = 0u64;
            let mut ready = !guard.is_empty();
            for bundle in guard.values() {
                entries = entries.saturating_add(bundle.total_entries());
                bytes = bytes.saturating_add(bundle.total_bytes());
                build_ms = build_ms.max(bundle.max_build_ms());
                last_offset = last_offset.max(bundle.max_last_offset());
                collisions = collisions.saturating_add(bundle.total_hash_collisions());
                if !bundle.all_ready() {
                    ready = false;
                }
            }
            (entries, bytes, build_ms, last_offset, ready, collisions)
        };
        self.counters
            .index_entries
            .store(entries, Ordering::Relaxed);
        self.counters.index_bytes.store(bytes, Ordering::Relaxed);
        self.counters
            .index_build_ms
            .store(build_ms, Ordering::Relaxed);
        self.counters
            .index_last_offset
            .store(last_offset, Ordering::Relaxed);
        self.counters.index_ready.store(ready, Ordering::Release);
        self.counters
            .index_hash_collisions
            .store(collisions, Ordering::Relaxed);
    }

    /// Accès direct au set d'un `dataset_root` sans le créer (utile
    /// pour l'appelant qui veut lookup sans tracker un nouveau root).
    pub fn get(&self, dataset_root: &Path) -> Option<Arc<DatasetIndexes>> {
        let key = dataset_root
            .canonicalize()
            .unwrap_or_else(|_| dataset_root.to_path_buf());
        self.tracked.lock().ok()?.get(&key).cloned()
    }

    pub fn counters(&self) -> Arc<PatchCounters> {
        self.counters.clone()
    }
}

/// Construit un `RawEventIndex` scoped à `wanted` en utilisant
/// l'index compact : seek + read ciblé par event_id. Retourne None
/// si aucun des events demandés n'est présent dans l'index.
pub fn scoped_index_from_compact(
    bundle: &DatasetIndexes,
    wanted: &HashSet<String>,
    counters: &Arc<PatchCounters>,
) -> RawEventIndex {
    let mut by_event_id: HashMap<String, Value> = HashMap::with_capacity(wanted.len());
    let mut hits = 0u64;
    let mut misses = 0u64;
    for event_id in wanted {
        match bundle.lookup(event_id) {
            Some(value) => {
                by_event_id.insert(event_id.clone(), value);
                hits = hits.saturating_add(1);
            }
            None => {
                misses = misses.saturating_add(1);
            }
        }
    }
    if hits > 0 {
        counters.index_hits.fetch_add(hits, Ordering::Relaxed);
    }
    if misses > 0 {
        counters.index_misses.fetch_add(misses, Ordering::Relaxed);
    }
    RawEventIndex::from_map(by_event_id)
}

impl RawEventIndex {
    /// 2.14.11 — construction depuis une map pré-remplie par
    /// `scoped_index_from_compact`. Reste privée au module patcher ;
    /// l'appelant externe utilise `scoped_index_from_compact` qui
    /// renvoie directement le `RawEventIndex`.
    pub fn from_map(by_event_id: HashMap<String, Value>) -> Self {
        Self { by_event_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    fn write_jsonl(dir: &std::path::Path, lines: &[Value]) -> std::path::PathBuf {
        let path = dir.join("oiran_events.jsonl");
        let mut body = String::new();
        for line in lines {
            body.push_str(&serde_json::to_string(line).unwrap());
            body.push('\n');
        }
        std::fs::write(&path, body).unwrap();
        path
    }

    fn lab_endpoint_map() -> HashMap<String, String> {
        // Mêmes entrées que `live_probe::endpoint_map()` pour les IPs
        // du lab S1-MME du constat ANR2 #10 6853084865.
        HashMap::from([
            ("10.77.10.10".to_string(), "MME".to_string()),
            ("10.77.10.20".to_string(), "eNB".to_string()),
        ])
    }

    /// Fabrique un NormalizedEvent JSONL imitant exactement ce que
    /// l'ingestion 2.14.3 produirait pour la capture de référence :
    /// IPs et ports corrects (10.77.10.20 46859 ↔ 10.77.10.10 36412),
    /// mais `network_function = null` (la map endpoint_map n'avait pas
    /// encore les IPs à la date d'ingestion).
    fn raw_s1ap(
        event_id: &str,
        procedure_code: u8,
        kind: u32,
        from_enb: bool,
        parent_event_id: Option<&str>,
    ) -> Value {
        let (src, dst, src_port, dst_port) = if from_enb {
            ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
        } else {
            ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
        };
        json!({
            "event_id": event_id,
            "parent_event_id": parent_event_id,
            "interface": "S1-MME",
            "protocol": "S1AP",
            "message_name": "stale-stored-at-ingestion",
            "message_type": kind,
            "procedure_code": procedure_code,
            "source_endpoint": {"address": src, "port": src_port, "network_function": null},
            "destination_endpoint": {"address": dst, "port": dst_port, "network_function": null},
            "direction": "UNKNOWN",
        })
    }

    fn raw_nas(
        event_id: &str,
        parent_event_id: &str,
        message_type: u8,
        from_enb: bool,
    ) -> Value {
        let (src, dst, src_port, dst_port) = if from_enb {
            ("10.77.10.20", "10.77.10.10", 46859u16, 36412u16)
        } else {
            ("10.77.10.10", "10.77.10.20", 36412u16, 46859u16)
        };
        json!({
            "event_id": event_id,
            "parent_event_id": parent_event_id,
            "interface": "S1-MME",
            "protocol": "NAS-EPS-MM",
            "message_name": "stale-stored-at-ingestion",
            "message_type": message_type,
            "procedure_code": message_type,
            "source_endpoint": {"address": src, "port": src_port, "network_function": null},
            "destination_endpoint": {"address": dst, "port": dst_port, "network_function": null},
            "direction": "UNKNOWN",
        })
    }

    fn stale_callflow_event(
        event_id: &str,
        old_source: &str,
        old_destination: &str,
        old_direction: &str,
        old_name: &str,
    ) -> Value {
        json!({
            "event_id": event_id,
            "interface": "S1-MME",
            "protocol": "S1AP",
            "message_name": old_name,
            "source_participant": old_source,
            "destination_participant": old_destination,
            "direction": old_direction,
        })
    }

    #[test]
    fn patcher_rewrites_s1_mme_stale_fields_via_jsonl_cross_reference() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // 5 événements : initialUEMessage(12,I) eNB→MME + enfant NAS
        // Attach Request (0x41), downlinkNASTransport(11,I) MME→eNB +
        // enfant NAS Security Mode Command (0x5D), et enfin
        // UECapabilityInfoIndication(22,I) eNB→MME.
        let raw = vec![
            raw_s1ap("evt-01", 12, 0, true, None),
            raw_nas("evt-02", "evt-01", 0x41, true),
            raw_s1ap("evt-03", 11, 0, false, None),
            raw_nas("evt-04", "evt-03", 0x5d, false),
            raw_s1ap("evt-05", 22, 0, true, None),
        ];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();

        // Callflow « stale 2.14.3 » : participants manquants, direction
        // via fallback procedureCode (12,13,18 → RAN_TO_CORE ;
        // 9,10,11,23 → CORE_TO_RAN — msg11 (InitialContextSetupResponse
        // eNB→MME) était donc inversé ; ici on vérifie aussi que la
        // direction 11 est corrigée).
        let mut events = vec![
            stale_callflow_event(
                "evt-01",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "InitialUEMessage",
            ),
            stale_callflow_event(
                "evt-02",
                "Unknown endpoint",
                "Unknown endpoint",
                "UNKNOWN",
                "Attach Request",
            ),
            stale_callflow_event(
                "evt-03",
                "Unknown endpoint",
                "Unknown endpoint",
                "CORE_TO_RAN",
                "DownlinkNASTransport",
            ),
            stale_callflow_event(
                "evt-04",
                "Unknown endpoint",
                "Unknown endpoint",
                "UNKNOWN",
                "Security Mode Complete", // bug 2.14.3 → 0x5d mal mappé
            ),
            stale_callflow_event(
                "evt-05",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "UnknownS1APProcedure", // (22,Initiating) absent de la table
            ),
        ];

        let map = lab_endpoint_map();
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &map, &counters);
        assert_eq!(
            rewritten, 5,
            "chacun des 5 événements stale doit être réécrit au moins une fois"
        );

        // 1. participants résolus depuis la map (ou le port en fallback).
        assert_eq!(events[0]["source_participant"], "eNB");
        assert_eq!(events[0]["destination_participant"], "MME");
        assert_eq!(events[3]["source_participant"], "MME");
        assert_eq!(events[3]["destination_participant"], "eNB");
        assert_eq!(events[4]["source_participant"], "eNB");
        assert_eq!(events[4]["destination_participant"], "MME");

        // 2. Direction stricte transport.
        assert_eq!(events[0]["direction"], "RAN_TO_CORE");
        assert_eq!(events[2]["direction"], "CORE_TO_RAN");
        assert_eq!(events[4]["direction"], "RAN_TO_CORE");

        // 3. message_name : S1AP (table) et NAS combiné.
        assert_eq!(events[0]["message_name"], "InitialUEMessage");
        assert_eq!(
            events[1]["message_name"], "initialUEMessage · Attach Request",
            "NAS enfant doit porter la procédure S1AP porteuse en préfixe ASN.1"
        );
        assert_eq!(events[2]["message_name"], "DownlinkNASTransport");
        assert_eq!(
            events[3]["message_name"], "downlinkNASTransport · Security Mode Command",
            "0x5D correspond bien à Security Mode Command (TS 24.301 §9.8.1)"
        );
        assert_eq!(
            events[4]["message_name"], "UECapabilityInfoIndication",
            "procedureCode 22 initiating doit être étiqueté (ajout decoder-s1ap 0.3.0)"
        );

        // 4. Provenance : chaque événement patché porte `read_time_patch`.
        for event in &events {
            assert!(
                event.get("read_time_patch").is_some(),
                "event {} must carry read_time_patch provenance",
                event["event_id"]
            );
        }

        // 5. Compteurs.
        assert_eq!(counters.events_seen.load(Ordering::Relaxed), 5);
        assert!(counters
            .events_patched_source_participant
            .load(Ordering::Relaxed)
            >= 5);
        assert!(counters
            .events_patched_destination_participant
            .load(Ordering::Relaxed)
            >= 5);
        assert!(counters.events_patched_direction.load(Ordering::Relaxed) >= 1);
        assert!(counters.events_patched_message_name.load(Ordering::Relaxed) >= 3);
        assert_eq!(counters.events_unresolved_participant.load(Ordering::Relaxed), 0);

        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// 2.14.9 (ANR1 #10) — chemin NGAP (5G) : InitialUEMessage +
    /// NAS Registration Request + NAS chiffré. Vérifie que la
    /// patcher produit le nom combiné `initialUEMessage · Registration
    /// Request` et `initialUEMessage · NAS chiffré`.
    #[test]
    fn patcher_rewrites_ngap_5g_stale_fields() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-ngap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = vec![
            json!({"event_id":"ngap-01","parent_event_id":null,
                "interface":"N2","protocol":"NGAP",
                "message_name":"stale","message_type":0,"procedure_code":15,
                "source_endpoint":{"address":"10.77.21.20","port":55123,"network_function":null},
                "destination_endpoint":{"address":"10.77.21.11","port":38412,"network_function":null},
                "direction":"UNKNOWN",
            }),
            json!({"event_id":"ngap-02","parent_event_id":"ngap-01",
                "interface":"N2","protocol":"NAS-5GMM",
                "message_name":"stale","message_type":0x41,"procedure_code":65,
                "source_endpoint":{"address":"10.77.21.20","port":55123,"network_function":null},
                "destination_endpoint":{"address":"10.77.21.11","port":38412,"network_function":null},
                "direction":"UNKNOWN",
            }),
            json!({"event_id":"ngap-03","parent_event_id":"ngap-01",
                "interface":"N2","protocol":"NAS-5GMM",
                "message_name":"stale","message_type":0,"procedure_code":null,
                "source_endpoint":{"address":"10.77.21.20","port":55123,"network_function":null},
                "destination_endpoint":{"address":"10.77.21.11","port":38412,"network_function":null},
                "direction":"UNKNOWN",
            }),
        ];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        let mut events = vec![
            stale_callflow_event("ngap-01", "Unknown endpoint", "Unknown endpoint", "RAN_TO_CORE", "InitialUEMessage"),
            stale_callflow_event("ngap-02", "Unknown endpoint", "Unknown endpoint", "RAN_TO_CORE", "Registration Request"),
            stale_callflow_event("ngap-03", "Unknown endpoint", "Unknown endpoint", "RAN_TO_CORE", "Protected 5GMM message"),
        ];
        let ngap_map = HashMap::from([
            ("10.77.21.20".to_string(), "gNB".to_string()),
            ("10.77.21.11".to_string(), "AMF".to_string()),
        ]);
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &ngap_map, &counters);
        assert_eq!(rewritten, 3);
        assert_eq!(events[0]["source_participant"], "gNB");
        assert_eq!(events[0]["destination_participant"], "AMF");
        assert_eq!(events[0]["message_name"], "InitialUEMessage");
        assert_eq!(
            events[1]["message_name"],
            "initialUEMessage · Registration Request"
        );
        assert_eq!(
            events[2]["message_name"],
            "initialUEMessage · NAS chiffré"
        );
        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// Fixture « déjà correcte » (format 2.14.5+) : le patcher doit
    /// être idempotent — aucun champ n'est modifié, aucun compteur
    /// `events_patched_*` n'avance.
    #[test]
    fn patcher_is_idempotent_on_already_correct_events() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-idempotent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = vec![raw_s1ap("evt-01", 12, 0, true, None)];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        // CallFlowEvent déjà conforme 2.14.5 : NF résolus, direction
        // transport, nom via la table S1AP.
        let mut events = vec![json!({
            "event_id": "evt-01",
            "interface": "S1-MME",
            "protocol": "S1AP",
            "message_name": "InitialUEMessage",
            "source_participant": "eNB",
            "destination_participant": "MME",
            "direction": "RAN_TO_CORE",
        })];
        let map = lab_endpoint_map();
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &map, &counters);
        assert_eq!(rewritten, 0, "aucun événement ne doit être marqué patché");
        assert!(events[0].get("read_time_patch").is_none());
        assert_eq!(
            counters
                .events_patched_source_participant
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            counters
                .events_patched_destination_participant
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(counters.events_patched_direction.load(Ordering::Relaxed), 0);
        assert_eq!(
            counters.events_patched_message_name.load(Ordering::Relaxed),
            0
        );
        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
