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
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
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
        let built =
            match RawEventIndex::from_dataset_root_for_event_ids(dataset_root, wanted_event_ids) {
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
                self.counters
                    .cache_evictions
                    .fetch_add(1, Ordering::Relaxed);
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
/// 2.21.18 (ANR2 #10, FAIL 2.21.16 : 724 `UnsupportedSbiOperation`
/// servis) — les events SBI stockés ont été nommés à l'ingestion par le
/// catalogue de l'époque. On reclasse à la lecture, avec la MÊME fonction
/// que le décodeur (`decoder_sbi::classify_sanitized_operation`), sur
/// l'URI anonymisée et la méthode stockées sur l'event brut. Ne touche que
/// les events nommés `UnsupportedSbiOperation…` ; sans correspondance, le
/// libellé d'origine est conservé (jamais d'invention).
fn sbi_name_for(raw: &Value) -> Option<String> {
    if raw.get("protocol").and_then(Value::as_str) != Some("SBI-HTTP2") {
        return None;
    }
    let current = raw.get("message_name").and_then(Value::as_str)?;
    if !current.starts_with("UnsupportedSbiOperation") {
        return None;
    }
    let ies = raw.get("information_elements").and_then(Value::as_array)?;
    let ie = |name: &str| {
        ies.iter()
            .find(|item| item.get("name").and_then(Value::as_str) == Some(name))
            .and_then(|item| item.get("value").and_then(Value::as_str))
    };
    decoder_sbi::classify_sanitized_operation(ie("Request URI (sanitized)")?, ie("HTTP method"))
}

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
        "NGAP" => {
            Some(decoder_ngap::message_name(code, kind_from_ngap_u32(kind_number)).to_string())
        }
        _ => None,
    }
}

/// 2.14.12 (ANR1 #10 6867204663) — nom NAS brut (sans parent), même
/// tables TS 24.301 / TS 24.501 que l'ingestion (`decoder-nas`).
/// Retourne `None` si le protocole n'est pas une variante NAS
/// reconnue. Un `message_type == 0` sur un événement NAS signale un
/// NAS chiffré → `"NAS chiffré"` (même règle que la combinaison via
/// parent).
fn nas_name_only(raw: &Value) -> Option<String> {
    let protocol = raw.get("protocol").and_then(Value::as_str)?;
    let (is_eps, is_sm, is_fiveg) = match protocol {
        "NAS-EPS-MM" | "NasEpsMm" => (true, false, false),
        "NAS-EPS-SM" | "NasEpsSm" => (true, true, false),
        "NAS-5GMM" | "Nas5gmm" => (false, false, true),
        "NAS-5GSM" | "Nas5gsm" => (false, true, true),
        _ => return None,
    };
    let message_type = raw.get("message_type").and_then(Value::as_u64).unwrap_or(0);
    if message_type == 0 {
        return Some("NAS chiffré".to_string());
    }
    let nas_name: &str = if is_fiveg {
        // TS 24.501 §9.7 — même table que decoder-nas à l'ingestion.
        if is_sm {
            decoder_nas::sm_name_5g(message_type as u8).0
        } else {
            decoder_nas::mm_name(message_type as u8).0
        }
    } else if is_eps {
        // TS 24.301 §9.8 — mm_eps_name (table auditée en 2.14.5).
        // L'extension SM EPS n'est pas exposée publiquement ; on
        // retombe dans la variante MM par défaut quand le décodeur
        // d'ingestion renvoie "NAS-EPS-SM" sans entrée dédiée côté
        // mm_eps_name. Les captures lab n'exposent pas de SM EPS
        // dédié → aucun impact prod observé.
        let _ = is_sm;
        decoder_nas::mm_eps_name(message_type as u8).0
    } else {
        return None;
    };
    Some(nas_name.to_string())
}

fn nas_name_for(raw: &Value, parent_name: &str) -> Option<String> {
    let nas_name = nas_name_only(raw)?;
    Some(decoder_s1ap::combined_message_name(parent_name, &nas_name))
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

    // 4) message_name : trois chemins, par ordre de spécificité.
    //    a) NAS avec parent S1AP/NGAP résolu dans l'index → nom
    //       combiné « procédure · NAS » (ex. `downlinkNASTransport
    //       · Security Mode Command`).
    //    b) Événement S1AP ou NGAP lui-même → nom de la procédure.
    //    c) 2.14.12 (ANR1 #10 6867204663) — NAS **sans** parent
    //       dans le JSONL : on recalcule le nom NAS seul via les
    //       mêmes fonctions uniques que l'ingestion
    //       (`mm_eps_name`, `mm_name`, `sm_name_5g`). Sans ce
    //       fallback, un NAS orphelin (observé en prod sur l'event
    //       04, 0x5D) restait sur son libellé stale de 2.14.3.
    let parent_s1ap_name = raw
        .get("parent_event_id")
        .and_then(Value::as_str)
        .and_then(|parent_id| raw_index.get(parent_id))
        .and_then(s1ap_name_for);
    let new_message_name = if let Some(parent_name) = parent_s1ap_name.as_deref() {
        nas_name_for(raw, parent_name)
    } else {
        s1ap_name_for(raw)
            .or_else(|| nas_name_only(raw))
            .or_else(|| sbi_name_for(raw))
    };

    // Publier les nouvelles valeurs si elles diffèrent (idempotent).
    let mut patched_fields: Vec<&'static str> = Vec::new();

    // 2.21.166 (ordre cœur #9 7135745591, piège relevé dans l'audit #9
    // 7134885713) — un participant déjà nommé (à la publication, ou par la
    // trace live) n'est plus remplacé par « Unknown endpoint » quand l'event
    // brut ne sait pas mieux. Le patch ne fait que nommer ou corriger un nom
    // par un autre nom, jamais effacer.
    let known_participant = |field: &str| -> Option<String> {
        event
            .get(field)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty() && *name != "Unknown endpoint")
            .map(str::to_string)
    };
    let new_source = source
        .network_function
        .clone()
        .or_else(|| known_participant("source_participant"))
        .unwrap_or_else(|| "Unknown endpoint".to_string());
    let new_destination = destination
        .network_function
        .clone()
        .or_else(|| known_participant("destination_participant"))
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
            let address = event.get(address_key).and_then(Value::as_str).unwrap_or("");
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
        let mut reader = BufReader::new(&file);
        let mut current_offset = from;
        let mut advised_offset = from;
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
            if current_offset.saturating_sub(advised_offset) >= 16 * 1024 * 1024 {
                advise_read_range(
                    &file,
                    advised_offset,
                    current_offset.saturating_sub(advised_offset),
                );
                advised_offset = current_offset;
            }
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
        advise_read_range(
            &file,
            advised_offset,
            current_offset.saturating_sub(advised_offset),
        );
        self.last_offset.store(current_offset, Ordering::Relaxed);
        if local_entries > 0 {
            self.entries.fetch_add(local_entries, Ordering::Relaxed);
            self.bytes_estimate
                .fetch_add(local_bytes, Ordering::Relaxed);
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
        guard.entry(key).or_insert_with(|| bundle.clone()).clone()
    }

    /// 2.21.177 (refus ANR1 #10 7146440592) — comme `ensure_tracking`, mais
    /// LIÉ à la génération publiée : `expected` est la liste exacte des
    /// fichiers d'events du manifeste en vigueur (en mémoire, aucun
    /// `read_dir`). Si le jeu d'index suivi ne couvre pas exactement ces
    /// fichiers — un shard écrit par une publication ultérieure, ou un
    /// shard retiré —, il est REMPLACÉ par un jeu neuf sur ces fichiers, qui
    /// se construit alors à froid (`all_ready() == false` jusque-là).
    pub fn ensure_tracking_for(&self, dataset_root: &Path, expected: &[PathBuf]) -> Arc<DatasetIndexes> {
        let key = dataset_root
            .canonicalize()
            .unwrap_or_else(|_| dataset_root.to_path_buf());
        let mut wanted: Vec<PathBuf> = expected.to_vec();
        wanted.sort();
        let covers = |bundle: &DatasetIndexes| {
            let mut tracked: Vec<PathBuf> = bundle
                .flat
                .iter()
                .chain(bundle.shards.iter())
                .map(|index| index.path().to_path_buf())
                .collect();
            tracked.sort();
            tracked == wanted
        };
        {
            let guard = self.tracked.lock().unwrap();
            if let Some(existing) = guard.get(&key) {
                if covers(existing) {
                    return existing.clone();
                }
            }
        }
        let flat_path = dataset_root.join("oiran_events.jsonl");
        let mut flat = None;
        let mut shards = Vec::new();
        for path in wanted.clone() {
            if path == flat_path {
                flat = Some(Arc::new(CompactJsonlIndex::new(path)));
            } else {
                shards.push(Arc::new(CompactJsonlIndex::new(path)));
            }
        }
        let bundle = Arc::new(DatasetIndexes { flat, shards });
        let mut guard = self.tracked.lock().unwrap();
        match guard.get(&key) {
            Some(existing) if covers(existing) => existing.clone(),
            _ => {
                guard.insert(key, bundle.clone());
                bundle
            }
        }
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

/// 2.15.2 (ANR1 #10 6885876387) — réconciliation à la lecture
/// des events PFCP de la session avec le JSONL raw du dataset.
/// Le callflow persisté sur disque (chemin prod CONTINUOUS) peut
/// ne pas contenir la `PFCP Session Establishment Request` type
/// 50 alors que le shard JSONL la porte avec le même
/// `pfcp_sequence` ou `seid`/`f_seid` qu'une Response/Modification
/// déjà rattachée à la session. Fix 2.15.0 côté pré-publication
/// (`session_engine::expand_pfcp_session_members`) ne prenait que
/// sur le chemin in-memory ; les callflows déjà persistés avant
/// 2.15.0 restent sans la Request → ANR1 FAIL 2.15.0 + 2.15.1.
///
/// Cette fonction fait le fix **à la lecture** (côté
/// `/api/v1/sessions/:id/events`) : on collecte les
/// `pfcp_sequence`/`seid` des events PFCP déjà dans `items`,
/// puis on scanne en streaming `oiran_events.jsonl` +
/// `event-shards/*.jsonl` du dataset_root pour tirer tout event
/// PFCP partageant ces clés et non déjà présent par `event_id`.
///
/// Garanties :
/// - Ordre canonique `(capture_id, packet_number, event_id)`
///   garanti si des events sont ajoutés.
/// - `f_seid = 0x0000000000000000` (placeholder nul partagé)
///   n'est **jamais** considéré comme un match.
/// - Short-circuit si aucun event PFCP n'a de clé connue :
///   on ne scanne pas le JSONL (zéro I/O).
/// - Retourne le nombre d'events ajoutés (0 = pas de sibling,
///   comportement idempotent).
/// 2.21.70 (ordre #9 7006855142) — Clés PFCP d'une **session complète**,
/// extraites d'une liste d'events persistés. Utilisées par les deux
/// entrées d'enrichissement (`extend_items_*` + `count_*`) pour que les
/// pages 1 et 2+ reposent sur les MÊMES clés et que `total_events`
/// reste cohérent.
#[derive(Default, Debug, Clone)]
pub struct PfcpSessionKeys {
    pub known_sequences: BTreeSet<String>,
    pub known_seids: BTreeSet<String>,
    pub known_interfaces: BTreeSet<String>,
    pub known_event_ids: BTreeSet<String>,
}

/// 2.21.70 — Collecte les clés PFCP (sequence, seid, interface, event_id)
/// de la liste d'events fournie. Idempotent, pure, pas d'I/O.
pub fn collect_pfcp_session_keys(items: &[Value]) -> PfcpSessionKeys {
    let mut keys = PfcpSessionKeys::default();
    for item in items.iter() {
        if let Some(id) = item.get("event_id").and_then(Value::as_str) {
            keys.known_event_ids.insert(id.to_owned());
        }
        if item.get("protocol").and_then(Value::as_str) != Some("PFCP") {
            continue;
        }
        if !is_pfcp_node_message(item) {
            collect_pfcp_keys(item, &mut keys.known_sequences, &mut keys.known_seids);
        }
        if let Some(interface) = pfcp_interface_of(item) {
            keys.known_interfaces.insert(interface);
        }
    }
    keys
}

pub fn extend_items_with_pfcp_siblings_from_jsonl(
    items: &mut Vec<Value>,
    dataset_root: &Path,
) -> Result<usize, String> {
    // Chemin historique : les clés sont extraites des `items` passés.
    // Utile quand on enrichit directement un callflow complet en mémoire.
    // Pour la pagination 2.21.70, utiliser
    // `extend_items_with_pfcp_siblings_using_session_keys` à la place.
    let session_keys = collect_pfcp_session_keys(items);
    extend_items_with_pfcp_siblings_using_session_keys(items, dataset_root, &session_keys)
}

/// 2.21.70 (ordre #9 7006855142) — Variante de
/// `extend_items_with_pfcp_siblings_from_jsonl` qui prend les clés de la
/// session EN AMONT (collectées sur la liste persistée complète) plutôt
/// que de les déduire des `items` à enrichir. Permet à la pagination
/// d'inserter les siblings en page 1 même si cette page ne contient
/// pas les events PFCP porteurs des clés (cas ANR2 : limit petit).
pub fn extend_items_with_pfcp_siblings_using_session_keys(
    items: &mut Vec<Value>,
    dataset_root: &Path,
    session_keys: &PfcpSessionKeys,
) -> Result<usize, String> {
    let shards = pfcp_manifest_shards(dataset_root)?;
    extend_items_with_pfcp_siblings_for_shards(items, dataset_root, &shards, session_keys)
}

pub fn pfcp_manifest_shards(root: &Path) -> Result<Vec<live_probe::EventShard>, String> {
    #[derive(serde::Deserialize)]
    struct Manifest {
        #[serde(default)]
        event_shards: Vec<live_probe::EventShard>,
    }
    match std::fs::read(root.join("dataset_manifest.json")) {
        Ok(bytes) => serde_json::from_slice::<Manifest>(&bytes)
            .map(|manifest| manifest.event_shards)
            .map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.to_string()),
    }
}

pub fn extend_items_with_pfcp_siblings_for_shards(
    items: &mut Vec<Value>,
    dataset_root: &Path,
    shards: &[live_probe::EventShard],
    session_keys: &PfcpSessionKeys,
) -> Result<usize, String> {
    let known_sequences = &session_keys.known_sequences;
    let known_seids = &session_keys.known_seids;
    let known_interfaces = &session_keys.known_interfaces;
    // `known_event_ids` doit inclure CEUX de la session complète ET
    // ceux déjà présents dans `items` (déduplication serrée).
    let mut known_event_ids: BTreeSet<String> = session_keys.known_event_ids.clone();
    for item in items.iter() {
        if let Some(id) = item.get("event_id").and_then(Value::as_str) {
            known_event_ids.insert(id.to_owned());
        }
    }
    if known_sequences.is_empty() && known_seids.is_empty() {
        return Ok(0);
    }
    let mut keys: BTreeSet<String> = known_sequences.iter().map(|s| format!("seq:{s}")).collect();
    keys.extend(known_seids.iter().map(|s| format!("seid:{s}")));
    let index = cached_pfcp_index_for_shards(dataset_root, shards)?;
    let candidates = pfcp_events_for_keys(&index, &keys);
    let mut added = 0usize;
    for value in candidates.iter() {
        let Some(event_id) = value.get("event_id").and_then(Value::as_str) else {
            continue;
        };
        if event_id.is_empty() || known_event_ids.contains(event_id) || is_pfcp_node_message(value)
        {
            continue;
        }
        let same_interface = match pfcp_interface_of(value) {
            Some(interface) => known_interfaces.contains(&interface),
            None => known_interfaces.is_empty(),
        };
        if same_interface && pfcp_event_matches(value, known_sequences, known_seids) {
            known_event_ids.insert(event_id.to_owned());
            // 2.21.115 (ordre #9 7050925249) — un frère PFCP lu dans le
            // JSONL brut d'un dataset d'avant 2.21.91 n'a pas de
            // `stable_event_key` : elle est posée ici, pour les deux
            // routes qui étendent une session (`/events` et `/callflow`).
            let mut sibling = value.clone();
            stamp_stable_event_key_if_missing(items, &mut sibling);
            items.push(sibling);
            added += 1;
        }
    }
    if added > 0 {
        items.sort_by(|a, b| canonical_sort_tuple(a).cmp(&canonical_sort_tuple(b)));
    }
    Ok(added)
}

/// 2.21.70 (ordre #9 7006855142) — Compte les siblings PFCP du JSONL
/// pour la **session entière**, à partir de la liste PERSISTÉE complète
/// (indépendant du curseur de pagination). Renvoie le nombre de
/// candidats qui seraient ajoutés par `extend_items_with_pfcp_siblings_
/// from_jsonl`, sans muter la liste. Permet à `/callflow` d'annoncer
/// un `total_events` cohérent sur **toutes les pages** : jusqu'à
/// 2.21.69, le total n'était bump qu'en page 1 (quand les siblings
/// sont effectivement insérés), laissant les pages 2+ annoncer le
/// seul total persisté. Noté en revue cœur 7006855142 §CLAUDE2.
pub fn count_pfcp_siblings_for_persisted_events(
    events: &[Value],
    dataset_root: &Path,
) -> Result<usize, String> {
    let shards = pfcp_manifest_shards(dataset_root)?;
    count_pfcp_siblings_for_shards(events, dataset_root, &shards)
}

pub fn count_pfcp_siblings_for_shards(
    events: &[Value],
    dataset_root: &Path,
    shards: &[live_probe::EventShard],
) -> Result<usize, String> {
    let mut scratch = events.to_vec();
    let before = scratch.len();
    let keys = collect_pfcp_session_keys(&scratch);
    extend_items_with_pfcp_siblings_for_shards(&mut scratch, dataset_root, shards, &keys)?;
    Ok(scratch.len().saturating_sub(before))
}

/// 2.18.8 — messages PFCP de NŒUD (TS 29.244 §7.4 : Heartbeat,
/// Association Setup/Update/Release, Node Report, PFD Management,
/// Version Not Supported). Ils ne portent pas de SEID et leur
/// `pfcp_sequence` est un compteur de nœud : ils n'appartiennent à aucune
/// session (constat Sadok : ladder d'une session rempli de « PFCP
/// Heartbeat Request/Response »). Jamais rattachés, jamais utilisés
/// comme clé.
fn is_pfcp_node_message(item: &Value) -> bool {
    let name = item
        .get("message_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    ["heartbeat", "association", "node report", "pfd management", "version not supported"]
        .iter()
        .any(|needle| name.contains(needle))
}

/// Interface d'un event PFCP (shape callflow `interface` ou JSONL brut
/// `interface` / `interface_id`), normalisée en majuscules.
fn pfcp_interface_of(item: &Value) -> Option<String> {
    ["interface", "interface_id", "interface_type"]
        .iter()
        .find_map(|key| item.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_uppercase)
}

fn collect_pfcp_keys(item: &Value, sequences: &mut BTreeSet<String>, seids: &mut BTreeSet<String>) {
    // Top-level `pfcp_sequence` (shape JSONL raw de production).
    if let Some(seq) = item.get("pfcp_sequence").and_then(Value::as_str) {
        if !seq.is_empty() {
            sequences.insert(seq.to_owned());
        }
    }
    // `session_identifiers` (shape JSONL raw).
    if let Some(ids) = item.get("session_identifiers").and_then(Value::as_array) {
        for id in ids {
            let name = id.get("name").and_then(Value::as_str).unwrap_or("");
            let value = id.get("value").and_then(Value::as_str).unwrap_or("");
            if value.is_empty() {
                continue;
            }
            match name {
                "pfcp_sequence" => {
                    sequences.insert(value.to_owned());
                }
                "seid" | "f_seid" if value != "0x0000000000000000" => {
                    seids.insert(value.to_owned());
                }
                _ => {}
            }
        }
    }
    // `decoded_ie_tree` (shape callflow persisté, payload ANR1
    // #10 6883006379 : `{"name":"F-SEID","value":"f_seid=0x314,...}`).
    if let Some(tree) = item.get("decoded_ie_tree").and_then(Value::as_array) {
        for entry in tree {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let raw = entry.get("value").and_then(Value::as_str).unwrap_or("");
            if raw.is_empty() {
                continue;
            }
            match name {
                "pfcp_sequence" => {
                    sequences.insert(raw.to_owned());
                }
                "F-SEID" | "f_seid" | "seid" => {
                    let seid_val = raw
                        .split(',')
                        .next()
                        .map(|part| {
                            part.trim_start_matches("f_seid=")
                                .trim_start_matches("seid=")
                        })
                        .unwrap_or("");
                    if seid_val != "0x0000000000000000" && !seid_val.is_empty() {
                        seids.insert(seid_val.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
}

fn canonical_sort_tuple(item: &Value) -> (String, u64, String) {
    let capture_id = item
        .get("capture_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let packet_number = item
        .get("packet_references")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("packet_number").and_then(Value::as_u64))
        .or_else(|| item.get("packet_number").and_then(Value::as_u64))
        .unwrap_or(0);
    let event_id = item
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    (capture_id, packet_number, event_id)
}

fn pfcp_event_matches(
    value: &Value,
    known_sequences: &BTreeSet<String>,
    known_seids: &BTreeSet<String>,
) -> bool {
    if let Some(seq) = value.get("pfcp_sequence").and_then(Value::as_str) {
        if known_sequences.contains(seq) {
            return true;
        }
    }
    if let Some(ids) = value.get("session_identifiers").and_then(Value::as_array) {
        for id in ids {
            let name = id.get("name").and_then(Value::as_str).unwrap_or("");
            let val = id.get("value").and_then(Value::as_str).unwrap_or("");
            if val.is_empty() {
                continue;
            }
            if name == "pfcp_sequence" && known_sequences.contains(val) {
                return true;
            }
            if (name == "seid" || name == "f_seid")
                && val != "0x0000000000000000"
                && known_seids.contains(val)
            {
                return true;
            }
        }
    }
    false
}

/// 2.15.5 — index LÉGER des events PFCP d'un dataset : pour chaque event,
/// seulement (fichier, offset) rangé par clé `pfcp_sequence` / `seid`.
/// 2.15.4 gardait tous les events PFCP complets en mémoire → OOM à 4 Gio
/// (MemoryMax) au premier /events en prod (ANR1 #10 6895136076). Les
/// quelques lignes qui correspondent sont relues sur disque à la demande.
#[derive(Clone)]
pub struct PfcpIndex {
    files: Vec<PathBuf>,
    by_key: std::collections::HashMap<String, Vec<(u32, u64)>>,
    entries: usize,
    /// 2.18.10 — octets déjà indexés par fichier (même ordre que `files`),
    /// toujours en fin de ligne complète.
    scanned: Vec<u64>,
}

impl PfcpIndex {
    pub fn entries(&self) -> usize {
        self.entries
    }
}

type PfcpCache =
    std::collections::HashMap<PathBuf, (Vec<(PathBuf, u64, u128)>, std::sync::Arc<PfcpIndex>)>;
static PFCP_EVENT_CACHE: std::sync::LazyLock<std::sync::Mutex<PfcpCache>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(PfcpCache::new()));
/// Un seul constructeur à la fois (préchauffage et 1re requête ne doivent
/// pas construire l'index deux fois en parallèle).
static PFCP_INDEX_BUILD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn dataset_jsonl_files(
    dataset_root: &Path,
    shards: &[live_probe::EventShard],
) -> Vec<(PathBuf, u64, u128)> {
    let paths: Vec<PathBuf> = if shards.is_empty() {
        let flat = dataset_root.join("oiran_events.jsonl");
        flat.is_file().then_some(flat).into_iter().collect()
    } else {
        shards.iter().map(|shard| dataset_root.join(&shard.path)).collect()
    };
    paths
        .into_iter()
        .map(|path| {
            let meta = std::fs::metadata(&path).ok();
            let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let mtime = meta
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            (path, len, mtime)
        })
        .collect()
}

/// Clés de jointure d'un event PFCP brut : `seq:<n>` et `seid:<0x..>`.
fn pfcp_keys(value: &Value) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(seq) = value.get("pfcp_sequence").and_then(Value::as_str) {
        if !seq.is_empty() {
            keys.push(format!("seq:{seq}"));
        }
    }
    if let Some(ids) = value.get("session_identifiers").and_then(Value::as_array) {
        for id in ids {
            let name = id.get("name").and_then(Value::as_str).unwrap_or("");
            let val = id.get("value").and_then(Value::as_str).unwrap_or("");
            if val.is_empty() {
                continue;
            }
            match name {
                "pfcp_sequence" => keys.push(format!("seq:{val}")),
                "seid" | "f_seid" if val != "0x0000000000000000" => {
                    keys.push(format!("seid:{val}"))
                }
                _ => {}
            }
        }
    }
    keys.sort();
    keys.dedup();
    keys
}

pub fn cached_pfcp_index(dataset_root: &Path) -> Result<std::sync::Arc<PfcpIndex>, String> {
    let shards = pfcp_manifest_shards(dataset_root)?;
    cached_pfcp_index_for_shards(dataset_root, &shards)
}

pub fn cached_pfcp_index_for_shards(
    dataset_root: &Path,
    shards: &[live_probe::EventShard],
) -> Result<std::sync::Arc<PfcpIndex>, String> {
    let signature = dataset_jsonl_files(dataset_root, shards);
    let lookup = |signature: &Vec<(PathBuf, u64, u128)>| {
        PFCP_EVENT_CACHE.lock().ok().and_then(|cache| {
            cache
                .get(dataset_root)
                .filter(|(sig, _)| sig == signature)
                .map(|(_, index)| index.clone())
        })
    };
    if let Some(index) = lookup(&signature) {
        return Ok(index);
    }
    let _guard = PFCP_INDEX_BUILD
        .lock()
        .map_err(|_| "PFCP_INDEX_LOCK_POISONED".to_string())?;
    if let Some(index) = lookup(&signature) {
        return Ok(index);
    }
    // 2.18.10 (ANR2 #10 : 1er /callflow 19,7 s) — le dataset continuous
    // est en append : la signature (taille, mtime) change à chaque lot
    // publié et l'index était reconstruit EN ENTIER (relecture de tout le
    // JSONL). Désormais on reprend l'index précédent et on n'indexe que
    // les octets ajoutés ; reconstruction complète seulement si un
    // fichier a rétréci (rotation / réécriture).
    let previous = PFCP_EVENT_CACHE
        .lock()
        .ok()
        .and_then(|mut cache| cache.remove(dataset_root))
        .map(|(_, index)| std::sync::Arc::try_unwrap(index).unwrap_or_else(|shared| (*shared).clone()));
    let mut index = match previous {
        Some(previous) if pfcp_index_can_extend(&previous, &signature) => previous,
        _ => PfcpIndex {
            files: Vec::new(),
            by_key: std::collections::HashMap::new(),
            entries: 0,
            scanned: Vec::new(),
        },
    };
    for (path, _, _) in &signature {
        let file_idx = match index.files.iter().position(|known| known == path) {
            Some(position) => position,
            None => {
                index.files.push(path.clone());
                index.scanned.push(0);
                index.files.len() - 1
            }
        };
        let from = index.scanned[file_idx];
        let (scanned, added) = scan_pfcp_file(path, file_idx as u32, from, &mut index.by_key)?;
        index.scanned[file_idx] = scanned;
        index.entries += added;
    }
    let index = std::sync::Arc::new(index);
    if let Ok(mut cache) = PFCP_EVENT_CACHE.lock() {
        cache.insert(dataset_root.to_path_buf(), (signature, index.clone()));
    }
    Ok(index)
}

/// Un index peut être étendu si aucun fichier déjà indexé n'a rétréci
/// ni disparu.
fn pfcp_index_can_extend(index: &PfcpIndex, signature: &[(PathBuf, u64, u128)]) -> bool {
    index.files.iter().zip(&index.scanned).all(|(path, scanned)| {
        signature
            .iter()
            .find(|(candidate, _, _)| candidate == path)
            .is_some_and(|(_, len, _)| len >= scanned)
    })
}

/// Indexe les lignes PFCP complètes de `path` à partir de l'octet `from`.
/// Retourne (nouvel octet de reprise, nombre d'events PFCP indexés). Une
/// dernière ligne sans `\n` (écriture en cours) n'est pas consommée.
fn scan_pfcp_file(
    path: &Path,
    file_idx: u32,
    from: u64,
    by_key: &mut std::collections::HashMap<String, Vec<(u32, u64)>>,
) -> Result<(u64, usize), String> {
    use std::io::{Seek, SeekFrom};
    let mut file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    file.seek(SeekFrom::Start(from)).map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(&file);
    let mut offset = from;
    let mut advised_offset = from;
    let mut added = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        let read = std::io::BufRead::read_line(&mut reader, &mut line)
            .map_err(|error| error.to_string())?;
        if read == 0 || !line.ends_with('\n') {
            break;
        }
        let start = offset;
        offset += read as u64;
        if offset.saturating_sub(advised_offset) >= 16 * 1024 * 1024 {
            advise_read_range(
                &file,
                advised_offset,
                offset.saturating_sub(advised_offset),
            );
            advised_offset = offset;
        }
        if !line.contains("\"protocol\":\"PFCP\"") {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line.trim_end()) else {
            continue;
        };
        let keys = pfcp_keys(&value);
        drop(value);
        if keys.is_empty() {
            continue;
        }
        added += 1;
        for key in keys {
            by_key.entry(key).or_default().push((file_idx, start));
        }
    }
    advise_read_range(
        &file,
        advised_offset,
        offset.saturating_sub(advised_offset),
    );
    Ok((offset, added))
}

#[cfg(target_family = "unix")]
fn advise_read_range(file: &std::fs::File, offset: u64, len: u64) {
    use std::os::fd::AsRawFd;

    let _ = unsafe {
        libc::posix_fadvise(
            file.as_raw_fd(),
            offset.min(i64::MAX as u64) as libc::off_t,
            len.min(i64::MAX as u64) as libc::off_t,
            libc::POSIX_FADV_DONTNEED,
        )
    };
}

#[cfg(not(target_family = "unix"))]
fn advise_read_range(_file: &std::fs::File, _offset: u64, _len: u64) {}

/// Relit sur disque les events PFCP qui partagent une clé connue.
fn pfcp_events_for_keys(index: &PfcpIndex, keys: &BTreeSet<String>) -> Vec<Value> {
    use std::io::{Seek, SeekFrom};
    let mut positions: BTreeSet<(u32, u64)> = BTreeSet::new();
    for key in keys {
        if let Some(found) = index.by_key.get(key) {
            positions.extend(found.iter().copied());
        }
    }
    let mut out = Vec::new();
    for (file_idx, offset) in positions {
        let Some(path) = index.files.get(file_idx as usize) else {
            continue;
        };
        let Ok(mut file) = std::fs::File::open(path) else {
            continue;
        };
        if file.seek(SeekFrom::Start(offset)).is_err() {
            continue;
        }
        let mut line = String::new();
        if std::io::BufRead::read_line(&mut BufReader::new(file), &mut line).is_ok() {
            if let Ok(value) = serde_json::from_str::<Value>(line.trim_end()) {
                out.push(value);
            }
        }
    }
    out
}

#[allow(dead_code)]
fn scan_jsonl_for_pfcp_siblings(
    path: &Path,
    items: &mut Vec<Value>,
    known_event_ids: &mut BTreeSet<String>,
    known_sequences: &BTreeSet<String>,
    known_seids: &BTreeSet<String>,
) -> Result<usize, String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let reader = BufReader::new(file);
    let mut added = 0usize;
    for line in reader.lines() {
        let line = line.map_err(|error| error.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        // Short-circuit : skip si pas PFCP via match string.
        if !line.contains("\"protocol\":\"PFCP\"") {
            continue;
        }
        let value: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event_id = match value.get("event_id").and_then(Value::as_str) {
            Some(id) if !id.is_empty() => id.to_owned(),
            _ => continue,
        };
        if known_event_ids.contains(&event_id) {
            continue;
        }
        let mut matched = false;
        // Top-level pfcp_sequence.
        if let Some(seq) = value.get("pfcp_sequence").and_then(Value::as_str) {
            if known_sequences.contains(seq) {
                matched = true;
            }
        }
        // session_identifiers.
        if !matched {
            if let Some(ids) = value.get("session_identifiers").and_then(Value::as_array) {
                for id in ids {
                    let name = id.get("name").and_then(Value::as_str).unwrap_or("");
                    let val = id.get("value").and_then(Value::as_str).unwrap_or("");
                    if val.is_empty() {
                        continue;
                    }
                    if name == "pfcp_sequence" && known_sequences.contains(val) {
                        matched = true;
                        break;
                    }
                    if (name == "seid" || name == "f_seid")
                        && val != "0x0000000000000000"
                        && known_seids.contains(val)
                    {
                        matched = true;
                        break;
                    }
                }
            }
        }
        if matched {
            known_event_ids.insert(event_id);
            items.push(value);
            added += 1;
        }
    }
    Ok(added)
}

/// 2.15.3 — `/callflow` : la PFCP Session Establishment Request (type 50)
/// présente dans le JSONL mais absente du callflow persisté est réinsérée
/// (ANR1 #10 6893754032 : /events PASS, ladder FAIL car p900 lit
/// /callflow). Chaque event récupéré est converti au format callflow
/// (participants, timestamp_ns, decoded_ie_tree) et placé juste AVANT le
/// premier event PFCP qui partage son `pfcp_sequence` (la Response) : on
/// ne retrie pas tout le callflow, son ordre existant est conservé.
pub fn insert_pfcp_siblings_into_callflow(
    events: &mut Vec<Value>,
    dataset_root: &Path,
) -> Result<usize, String> {
    // Chemin historique : clés dérivées des `events` passés. Pour la
    // pagination 2.21.70, passer par `insert_pfcp_siblings_into_callflow_using_session_keys`.
    let session_keys = collect_pfcp_session_keys(events);
    insert_pfcp_siblings_into_callflow_using_session_keys(events, dataset_root, &session_keys)
}

/// 2.21.70 (ordre #9 7006855142) — Variante utilisée par la pagination
/// `/callflow` : les clés PFCP proviennent de la session COMPLÈTE
/// (`collect_pfcp_session_keys(full_persisted_events)`), pas de la
/// page restreinte reçue. Permet d'insérer les siblings en page 1
/// MÊME quand cette page ne contient pas les events PFCP porteurs des
/// clés (cas limit petit → pages 2+ servent les events PFCP, mais la
/// page 1 doit déjà exposer les siblings comme avant).
pub fn insert_pfcp_siblings_into_callflow_using_session_keys(
    events: &mut Vec<Value>,
    dataset_root: &Path,
    session_keys: &PfcpSessionKeys,
) -> Result<usize, String> {
    let shards = pfcp_manifest_shards(dataset_root)?;
    insert_pfcp_siblings_into_callflow_for_shards(events, dataset_root, &shards, session_keys)
}

pub fn insert_pfcp_siblings_into_callflow_for_shards(
    events: &mut Vec<Value>,
    dataset_root: &Path,
    shards: &[live_probe::EventShard],
    session_keys: &PfcpSessionKeys,
) -> Result<usize, String> {
    let known: BTreeSet<String> = events
        .iter()
        .filter_map(|e| e.get("event_id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let mut scratch = events.clone();
    extend_items_with_pfcp_siblings_for_shards(&mut scratch, dataset_root, shards, session_keys)?;
    let mut added = 0usize;
    for raw in scratch.into_iter().filter(|e| {
        e.get("event_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !known.contains(id))
    }) {
        let mut converted = raw_event_to_callflow_event(&raw);
        // 2.21.112 (recette 2.21.104, ANR1 #10 7050183853 : 5 PFCP sans
        // clé sur 72) — un frère PFCP vient du JSONL brut et est inséré
        // APRÈS la dérivation de clé du callflow persisté : il doit
        // recevoir sa `stable_event_key` ici.
        stamp_stable_event_key_if_missing(events, &mut converted);
        let seq = pfcp_sequence_of(&converted);
        let position = seq
            .as_deref()
            .and_then(|seq| {
                events.iter().position(|e| {
                    e.get("protocol").and_then(Value::as_str) == Some("PFCP")
                        && pfcp_sequence_of(e).as_deref() == Some(seq)
                })
            })
            .unwrap_or(events.len());
        events.insert(position, converted);
        added += 1;
    }
    Ok(added)
}

/// Premier `packet_references` d'un event : `(source_file, interface_id,
/// packet_number, byte_offset)`.
fn first_packet_reference(event: &Value) -> Option<(String, u32, u64, u64)> {
    let packet = event
        .get("packet_references")
        .and_then(Value::as_array)
        .and_then(|list| list.first())
        .and_then(Value::as_object)?;
    Some((
        packet
            .get("source_file")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        packet.get("interface_id").and_then(Value::as_u64).unwrap_or(0) as u32,
        packet.get("packet_number").and_then(Value::as_u64).unwrap_or(0),
        packet.get("byte_offset").and_then(Value::as_u64).unwrap_or(0),
    ))
}

/// 2.21.118 (ordre #9 7051448601 point 2) — dérive `stable_event_key`
/// à la lecture sur une liste d'events persistés, par la MÊME fonction
/// que le callflow (`event_schema::backfill_stable_event_keys_in_callflow`),
/// sans copier la liste. À appeler sur les events persistés, dans leur
/// ordre de stockage, AVANT d'y insérer des frères. Retourne
/// `(clés posées, events sans référence de paquet)`.
pub fn backfill_stable_event_keys_in_items(items: &mut Vec<Value>) -> (usize, usize) {
    let mut wrapper = serde_json::json!({ "events": Value::Array(std::mem::take(items)) });
    let counts = event_schema::backfill_stable_event_keys_in_callflow(&mut wrapper);
    if let Some(Value::Array(events)) = wrapper.get_mut("events").map(Value::take) {
        *items = events;
    }
    counts
}

/// 2.21.112 — pose `stable_event_key` sur un event inséré à la lecture
/// s'il n'en porte pas. Même formule que
/// `event_schema::backfill_stable_event_keys_in_callflow` :
/// `{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}`, l'ordinal étant
/// le nombre d'events de `existing` déjà rattachés au même paquet. Un
/// event sans `packet_references` reste sans clé. Retourne `true` si
/// une clé a été posée.
fn stamp_stable_event_key_if_missing(existing: &[Value], event: &mut Value) -> bool {
    let has_key = event
        .get("stable_event_key")
        .and_then(Value::as_str)
        .is_some_and(|key| !key.is_empty());
    if has_key {
        return false;
    }
    let Some(reference) = first_packet_reference(event) else {
        return false;
    };
    let ordinal = existing
        .iter()
        .filter(|other| first_packet_reference(other).as_ref() == Some(&reference))
        .count() as u32;
    let protocol = event
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let key = event_schema::derive_stable_event_key(
        &reference.0,
        reference.1,
        reference.2,
        reference.3,
        &protocol,
        ordinal,
    );
    match event.as_object_mut() {
        Some(object) => {
            object.insert("stable_event_key".into(), Value::String(key));
            true
        }
        None => false,
    }
}

fn pfcp_sequence_of(event: &Value) -> Option<String> {
    if let Some(seq) = event.get("pfcp_sequence").and_then(Value::as_str) {
        return Some(seq.to_owned());
    }
    for key in ["session_identifiers", "decoded_ie_tree"] {
        if let Some(list) = event.get(key).and_then(Value::as_array) {
            for item in list {
                if item.get("name").and_then(Value::as_str) == Some("pfcp_sequence") {
                    if let Some(v) = item.get("value").and_then(Value::as_str) {
                        return Some(v.to_owned());
                    }
                }
            }
        }
    }
    None
}

/// Raw JSONL event (endpoints, structured timestamp, session_identifiers)
/// → callflow event shape read by the UI ladder. Fields already in the
/// callflow shape are kept as they are.
pub fn raw_event_to_callflow_event(raw: &Value) -> Value {
    let mut out = raw.clone();
    let Some(object) = out.as_object_mut() else {
        return out;
    };
    let nf = |key: &str| {
        raw.get(key)
            .and_then(|e| e.get("network_function"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if !object.contains_key("source_participant") {
        if let Some(v) = nf("source_endpoint") {
            object.insert("source_participant".into(), Value::String(v));
        }
    }
    if !object.contains_key("destination_participant") {
        if let Some(v) = nf("destination_endpoint") {
            object.insert("destination_participant".into(), Value::String(v));
        }
    }
    if !object.contains_key("timestamp_ns") {
        if let Some(ticks) = raw
            .get("timestamp")
            .and_then(|t| t.get("raw_ticks"))
            .and_then(Value::as_u64)
        {
            object.insert("timestamp_ns".into(), Value::String(ticks.to_string()));
        }
    }
    if raw.get("timestamp").is_some_and(Value::is_object) {
        object.insert("timestamp".into(), Value::String(String::new()));
    }
    if !object.contains_key("decoded_ie_tree") {
        let mut tree: Vec<Value> = raw
            .get("information_elements")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if let Some(ids) = raw.get("session_identifiers").and_then(Value::as_array) {
            for id in ids {
                if let (Some(name), Some(value)) = (
                    id.get("name").and_then(Value::as_str),
                    id.get("value").and_then(Value::as_str),
                ) {
                    tree.push(serde_json::json!({"name": name, "source": "session_identifiers", "value": value}));
                }
            }
        }
        object.insert("decoded_ie_tree".into(), Value::Array(tree));
    }
    object
        .entry("association")
        .or_insert_with(|| Value::String("SESSION".into()));
    object
        .entry("procedure_group")
        .or_insert_with(|| Value::String("PFCP Session".into()));
    out
}

/// 2.15.2 (ANR1 #10 6885876387, D3) — résumé compact des identités
/// extrait **des events déjà présents** (après `apply_read_time_patch`
/// et `extend_items_with_pfcp_siblings_from_jsonl`) pour alimenter
/// `/api/v1/sessions` quand le vault est vide (cas prod : la session
/// continuous n'a jamais déclenché `hydrate_identities` via tshark).
///
/// La shape renvoyée est volontairement alignée sur celle produite par
/// `identity_summary_for_session(state, session_id)` côté lib.rs :
/// `imsi`, `imsi_cleartext`, `imei`, `msisdn`, `tmsi`, `s_tmsi`,
/// `m_tmsi`, `subscriber_pseudonym`. Les valeurs retournées sont
/// extraites des champs déjà pseudonymisés par le décodeur (nom
/// canonique dans `session_identifiers` ou `decoded_ie_tree`) :
///
/// - `subscriber_pseudonym` : première occurrence trouvée
///   (NAS pseudonym 5GS/EPS, cf. decoder-nas).
/// - `tmsi_pseudonym` / `*_pseudonym` : remonté dans `m_tmsi`
///   (pseudonymisé, règle Sadok 2026-11-14).
/// - `identity_pseudonym` + `eps_mobile_type_code=2|3` : IMEI/IMEISV
///   pseudonymisé → kind `imei` (digits non disponibles depuis
///   l'event JSONL raw).
///
/// Clear-text IMSI/SUPI : **jamais** rempli par ce chemin
/// (règle Sadok : clear-text réservé à la voie
/// vault ← `tshark_identities`, qui dispose du pcap). Le champ
/// `imsi_cleartext` reste donc `null` quand on tire de ce helper.
///
/// Retourne `None` si aucune identité pseudonyme n'est trouvée (cas
/// d'une session purement PFCP sans NAS) : dans ce cas le caller
/// laisse `identities` à `null` (comportement 2.15.0/2.15.1 préservé).
pub fn extract_identity_summary_from_items(items: &[Value]) -> Option<Value> {
    let mut subscriber_pseudonym: Option<String> = None;
    let mut imei_pseudonym: Option<String> = None;
    let mut m_tmsi_pseudonyms: BTreeSet<String> = BTreeSet::new();
    let mut s_tmsi_pseudonyms: BTreeSet<String> = BTreeSet::new();
    let mut guti_pseudonyms: BTreeSet<String> = BTreeSet::new();

    for item in items {
        let eps_mobile_type_code = find_named_value(item, "eps_mobile_type_code")
            .and_then(|value| value.parse::<u8>().ok());
        for (name, value) in iter_named_pairs(item) {
            match name {
                "subscriber_pseudonym" | "imsi_pseudonym" => {
                    if subscriber_pseudonym.is_none() {
                        subscriber_pseudonym = Some(value.to_owned());
                    }
                }
                "tmsi_pseudonym" => {
                    m_tmsi_pseudonyms.insert(value.to_owned());
                }
                "s_tmsi_pseudonym" | "5g_s_tmsi_pseudonym" => {
                    s_tmsi_pseudonyms.insert(value.to_owned());
                }
                "guti_pseudonym" | "5g_guti_pseudonym" => {
                    guti_pseudonyms.insert(value.to_owned());
                }
                "identity_pseudonym" => {
                    if matches!(eps_mobile_type_code, Some(2) | Some(3)) && imei_pseudonym.is_none()
                    {
                        imei_pseudonym = Some(value.to_owned());
                    }
                }
                _ => {}
            }
        }
    }

    if subscriber_pseudonym.is_none()
        && imei_pseudonym.is_none()
        && m_tmsi_pseudonyms.is_empty()
        && s_tmsi_pseudonyms.is_empty()
        && guti_pseudonyms.is_empty()
    {
        return None;
    }

    let to_array =
        |set: BTreeSet<String>| -> Vec<Value> { set.into_iter().map(Value::String).collect() };
    Some(serde_json::json!({
        "imsi": Value::Null,
        "imsi_cleartext": Value::Null,
        "imei": imei_pseudonym,
        "msisdn": Value::Null,
        "tmsi": to_array(guti_pseudonyms),
        "s_tmsi": to_array(s_tmsi_pseudonyms),
        "m_tmsi": to_array(m_tmsi_pseudonyms),
        "subscriber_pseudonym": subscriber_pseudonym,
    }))
}

fn iter_named_pairs(item: &Value) -> Vec<(&str, &str)> {
    let mut out: Vec<(&str, &str)> = Vec::new();
    for key in [
        "session_identifiers",
        "decoded_ie_tree",
        "information_elements",
    ] {
        let Some(items) = item.get(key).and_then(Value::as_array) else {
            continue;
        };
        for entry in items {
            let name = entry.get("name").and_then(Value::as_str).unwrap_or("");
            let value = entry.get("value").and_then(Value::as_str).unwrap_or("");
            if !name.is_empty() && !value.is_empty() {
                out.push((name, value));
            }
        }
    }
    out
}

fn find_named_value<'a>(item: &'a Value, needle: &str) -> Option<&'a str> {
    for (name, value) in iter_named_pairs(item) {
        if name == needle {
            return Some(value);
        }
    }
    None
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

    fn raw_nas(event_id: &str, parent_event_id: &str, message_type: u8, from_enb: bool) -> Value {
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
        assert!(
            counters
                .events_patched_source_participant
                .load(Ordering::Relaxed)
                >= 5
        );
        assert!(
            counters
                .events_patched_destination_participant
                .load(Ordering::Relaxed)
                >= 5
        );
        assert!(counters.events_patched_direction.load(Ordering::Relaxed) >= 1);
        assert!(counters.events_patched_message_name.load(Ordering::Relaxed) >= 3);
        assert_eq!(
            counters
                .events_unresolved_participant
                .load(Ordering::Relaxed),
            0
        );

        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// 2.14.12 (ANR1 #10 6867204663) — cas prod observé : un
    /// événement NAS 0x5D (Security Mode Command) qui existe dans le
    /// JSONL **sans** parent S1AP (`parent_event_id = null`). Avant
    /// 2.14.12, `patch_one` ne recalculait le libellé NAS que via le
    /// nom combiné « procédure · NAS » — un NAS orphelin tombait
    /// dans `s1ap_name_for` qui retourne `None` pour un protocole
    /// `NAS-EPS-MM`, laissant le libellé stale « Security Mode
    /// Complete » (bug 2.14.3 pré-2.14.4). Le fallback
    /// `nas_name_only` doit maintenant produire « Security Mode
    /// Command » (TS 24.301 §9.8.1 table 9.8.1.1).
    #[test]
    fn patcher_rewrites_nas_eps_without_parent() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-nas-orphan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Évt NAS 0x5D sans parent_event_id (observé en prod sur
        // l'event 04 des sessions lte-session-81c8e02939b8f868 et
        // lte-session-7d5a9620319218ed, ANR1 #10 6867204663).
        let raw = vec![json!({
            "event_id": "evt-04",
            "parent_event_id": null,
            "interface": "S1-MME",
            "protocol": "NAS-EPS-MM",
            "message_name": "stale",
            "message_type": 0x5d,
            "procedure_code": 0x5d,
            "source_endpoint": {"address":"10.77.10.10","port":36412,"network_function":null},
            "destination_endpoint": {"address":"10.77.10.20","port":46859,"network_function":null},
            "direction": "UNKNOWN",
        })];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        let mut events = vec![stale_callflow_event(
            "evt-04",
            "Unknown endpoint",
            "Unknown endpoint",
            "UNKNOWN",
            "Security Mode Complete", // bug 2.14.3 : 0x5d mal mappé
        )];
        let map = lab_endpoint_map();
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &map, &counters);
        assert_eq!(rewritten, 1);
        assert_eq!(
            events[0]["message_name"], "Security Mode Command",
            "NAS orphelin 0x5d doit porter le nom NAS SEUL via mm_eps_name"
        );
        assert_eq!(events[0]["source_participant"], "MME");
        assert_eq!(events[0]["destination_participant"], "eNB");
        // Provenance : read_time_patch.fields doit contenir
        // message_name (règle du lot 2.14.12).
        let fields = events[0]["read_time_patch"]["fields"]
            .as_array()
            .expect("fields");
        assert!(
            fields.iter().any(|v| v.as_str() == Some("message_name")),
            "read_time_patch.fields doit inclure message_name, got {:?}",
            fields
        );
        std::fs::remove_file(&jsonl_path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    /// 2.14.12 (ANR1 #10 6867204663) — même règle pour 5G : un NAS
    /// 5GMM orphelin (sans parent NGAP) doit porter son nom NAS seul
    /// via `mm_name(5G)`. Cas : Registration Request (0x41) orphelin
    /// → « Registration Request ». Cas NAS chiffré (message_type=0) →
    /// « NAS chiffré ».
    #[test]
    fn patcher_rewrites_nas_5gmm_without_parent() {
        let dir = std::env::temp_dir().join(format!(
            "oiran-read-time-patch-nas-5g-orphan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let raw = vec![
            json!({
                "event_id": "ngap-nas-01",
                "parent_event_id": null,
                "interface": "N2",
                "protocol": "NAS-5GMM",
                "message_name": "stale",
                "message_type": 0x41,
                "procedure_code": 0x41,
                "source_endpoint": {"address":"10.77.21.20","port":55123,"network_function":null},
                "destination_endpoint": {"address":"10.77.21.11","port":38412,"network_function":null},
                "direction": "UNKNOWN",
            }),
            json!({
                "event_id": "ngap-nas-02",
                "parent_event_id": null,
                "interface": "N2",
                "protocol": "NAS-5GMM",
                "message_name": "stale",
                "message_type": 0,
                "procedure_code": null,
                "source_endpoint": {"address":"10.77.21.20","port":55123,"network_function":null},
                "destination_endpoint": {"address":"10.77.21.11","port":38412,"network_function":null},
                "direction": "UNKNOWN",
            }),
        ];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        let mut events = vec![
            stale_callflow_event(
                "ngap-nas-01",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "Registration stale",
            ),
            stale_callflow_event(
                "ngap-nas-02",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "Protected 5GMM message",
            ),
        ];
        let ngap_map = HashMap::from([
            ("10.77.21.20".to_string(), "gNB".to_string()),
            ("10.77.21.11".to_string(), "AMF".to_string()),
        ]);
        let counters = Arc::new(PatchCounters::new());
        let rewritten = patch_flow_events(&mut events, &index, &ngap_map, &counters);
        assert_eq!(rewritten, 2);
        assert_eq!(
            events[0]["message_name"], "Registration Request",
            "NAS-5GMM 0x41 orphelin doit être étiqueté par mm_name (TS 24.501 §9.7)"
        );
        assert_eq!(
            events[1]["message_name"], "NAS chiffré",
            "NAS orphelin avec message_type=0 → placeholder NAS chiffré"
        );
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
            stale_callflow_event(
                "ngap-01",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "InitialUEMessage",
            ),
            stale_callflow_event(
                "ngap-02",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "Registration Request",
            ),
            stale_callflow_event(
                "ngap-03",
                "Unknown endpoint",
                "Unknown endpoint",
                "RAN_TO_CORE",
                "Protected 5GMM message",
            ),
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
        assert_eq!(events[2]["message_name"], "initialUEMessage · NAS chiffré");
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

    /// 2.15.2 (ANR1 #10 6885876387, D3) — `extract_identity_summary_from_items`
    /// doit remonter `subscriber_pseudonym`, `tmsi_pseudonym`,
    /// `identity_pseudonym` (via `eps_mobile_type_code=3`) depuis
    /// `decoded_ie_tree` / `session_identifiers` / `information_elements`.
    #[test]
    fn extract_identity_summary_remonte_pseudonymes_depuis_items() {
        let items = vec![json!({
            "event_id":"evt-nas",
            "session_identifiers":[
                {"name":"subscriber_pseudonym","value":"sha256-sub","pseudonymized":true},
                {"name":"eps_mobile_type_code","value":"3","pseudonymized":false},
                {"name":"tmsi_pseudonym","value":"sha256-tmsi","pseudonymized":true},
            ],
            "information_elements":[
                {"name":"identity_pseudonym","value":"sha256-imei","pseudonymized":true},
            ],
        })];
        let summary = extract_identity_summary_from_items(&items).expect("summary");
        assert_eq!(summary["subscriber_pseudonym"], "sha256-sub");
        assert_eq!(summary["imei"], "sha256-imei");
        let m_tmsi = summary["m_tmsi"].as_array().unwrap();
        assert_eq!(m_tmsi.len(), 1);
        assert_eq!(m_tmsi[0], "sha256-tmsi");
        // Règle Sadok 2026-11-14 : IMSI / clear-text jamais via ce chemin.
        assert!(summary["imsi"].is_null());
        assert!(summary["imsi_cleartext"].is_null());
    }

    /// Règle Sadok 2026-11-14 : `identity_pseudonym` avec
    /// `eps_mobile_type_code=1` (IMSI) ne doit **pas** être remonté
    /// dans `imei` — c'est un cas d'identité subscriber, pas device.
    #[test]
    fn extract_identity_summary_ignore_identity_pseudonym_pour_eps_type_code_1() {
        let items = vec![json!({
            "event_id":"evt-nas-eps",
            "decoded_ie_tree":[
                {"name":"identity_pseudonym","value":"sha256-sub","pseudonymized":true},
                {"name":"eps_mobile_type_code","value":"1","source":"session_identifiers","pseudonymized":false},
            ],
        })];
        let summary = extract_identity_summary_from_items(&items);
        assert!(
            summary.is_none(),
            "aucune identité device/subscriber pseudo nommée explicitement → None"
        );
    }

    #[test]
    fn extract_identity_summary_retourne_none_quand_aucun_pseudo() {
        let items = vec![json!({
            "event_id":"evt-pfcp",
            "session_identifiers":[
                {"name":"pfcp_sequence","value":"2209","pseudonymized":false},
            ],
        })];
        assert!(extract_identity_summary_from_items(&items).is_none());
    }

    /// 2.21.39 (ordre #9 6965054336) — le reclassement à la lecture
    /// 2.21.18 doit couvrir **automatiquement** le stock pré-2.21.39 :
    /// les events stockés avec `UnsupportedSbiOperation…` dont l'URI
    /// correspond à l'une des 2 nouvelles entrées catalogue 2.21.39
    /// (`/nnrf-nfm/.../subscriptions` et `/nnrf-nfm/.../nf-status-notify`)
    /// doivent être reclassés en `NFStatusSubscribe` / `NFStatusUnsubscribe`
    /// / `NFStatusUpdate` / `NFStatusNotify`, sans réingestion.
    #[test]
    fn stored_sbi_events_are_reclassified_at_read_time_for_new_catalogue_entries_2_21_39() {
        let dir = std::env::temp_dir().join(format!("rtp-sbi-2-21-39-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sbi = |id: &str, method: &str, uri: &str| {
            json!({
                "event_id": id, "parent_event_id": null, "interface": "SBI",
                "protocol": "SBI-HTTP2",
                "message_name": "UnsupportedSbiOperation [conn=x/stream=1]",
                "source_endpoint": {"address":"10.77.20.20","port":40000,"network_function":"AMF"},
                "destination_endpoint": {"address":"10.77.20.30","port":7777,"network_function":"NRF"},
                "direction": "UNKNOWN",
                "information_elements": [
                    {"name":"HTTP method","value":method},
                    {"name":"Request URI (sanitized)","value":uri}
                ]
            })
        };
        let raw = vec![
            sbi("sbi-nfsub-post", "POST", "/nnrf-nfm/v1/subscriptions"),
            sbi("sbi-nfsub-del",  "DELETE", "/nnrf-nfm/v1/subscriptions/4e8f1a7c-0000-4000-8000-000000000001"),
            sbi("sbi-nfsub-pat",  "PATCH",  "/nnrf-nfm/v1/subscriptions/4e8f1a7c-0000-4000-8000-000000000002"),
            sbi("sbi-nfnotify",   "POST",   "/nnrf-nfm/v1/nf-status-notify"),
        ];
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        let mut events = vec![
            stale_callflow_event("sbi-nfsub-post", "AMF", "NRF", "UNKNOWN", "UnsupportedSbiOperation [conn=x/stream=1]"),
            stale_callflow_event("sbi-nfsub-del",  "AMF", "NRF", "UNKNOWN", "UnsupportedSbiOperation [conn=x/stream=1]"),
            stale_callflow_event("sbi-nfsub-pat",  "AMF", "NRF", "UNKNOWN", "UnsupportedSbiOperation [conn=x/stream=1]"),
            stale_callflow_event("sbi-nfnotify",   "AMF", "NRF", "UNKNOWN", "UnsupportedSbiOperation [conn=x/stream=1]"),
        ];
        let counters = Arc::new(PatchCounters::new());
        patch_flow_events(&mut events, &index, &lab_endpoint_map(), &counters);
        assert_eq!(events[0]["message_name"].as_str(), Some("NFStatusSubscribe"));
        assert_eq!(events[1]["message_name"].as_str(), Some("NFStatusUnsubscribe"));
        assert_eq!(events[2]["message_name"].as_str(), Some("NFStatusUpdate"));
        assert_eq!(events[3]["message_name"].as_str(), Some("NFStatusNotify"));
        // Preuve de mutation : si une URI ne correspond à aucune entrée du
        // catalogue, le libellé stocké est conservé (jamais d'invention).
        // On remplace `write_jsonl` par une URI non catalogue et on vérifie
        // le non-changement.
        let raw_unknown = vec![sbi("sbi-unknown", "POST", "/nzzz-made-up/v1/does-not-exist")];
        let unknown_dir = dir.join("unknown");
        std::fs::create_dir_all(&unknown_dir).unwrap();
        let jsonl_unknown = write_jsonl(&unknown_dir, &raw_unknown);
        let idx_unknown = RawEventIndex::from_jsonl_path(&jsonl_unknown).unwrap();
        let mut unknown_events = vec![stale_callflow_event(
            "sbi-unknown",
            "AMF",
            "NRF",
            "UNKNOWN",
            "UnsupportedSbiOperation [conn=x/stream=99]",
        )];
        patch_flow_events(&mut unknown_events, &idx_unknown, &lab_endpoint_map(), &counters);
        assert!(unknown_events[0]["message_name"]
            .as_str()
            .unwrap()
            .starts_with("UnsupportedSbiOperation"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2.21.18 — un event SBI stocké `UnsupportedSbiOperation…` est
    /// reclassé à la lecture avec la MÊME fonction que le décodeur ;
    /// une URI inconnue garde son libellé (jamais d'invention).
    #[test]
    fn sbi_unsupported_events_are_reclassified_at_read_time_with_decoder_catalogue() {
        let dir = std::env::temp_dir().join(format!("rtp-sbi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sbi = |id: &str, method: &str, uri: &str| {
            json!({
                "event_id": id, "parent_event_id": null, "interface": "SBI",
                "protocol": "SBI-HTTP2",
                "message_name": "UnsupportedSbiOperation [conn=x/stream=1]",
                "source_endpoint": {"address":"10.77.20.20","port":40000,"network_function":"AMF"},
                "destination_endpoint": {"address":"10.77.20.30","port":7777,"network_function":"UDM"},
                "direction": "UNKNOWN",
                "information_elements": [
                    {"name":"HTTP method","value":method},
                    {"name":"Request URI (sanitized)","value":uri}
                ]
            })
        };
        let raw = vec![
            sbi("sbi-1", "POST", "/nnrf-disc/v1/nf-instances"),
            sbi("sbi-2", "GET", "/nzzz-unknown/v1/whatever"),
        ];
        let expected = decoder_sbi::classify_sanitized_operation("/nnrf-disc/v1/nf-instances", Some("POST"));
        let jsonl_path = write_jsonl(&dir, &raw);
        let index = RawEventIndex::from_jsonl_path(&jsonl_path).unwrap();
        let mut events = vec![
            stale_callflow_event("sbi-1", "AMF", "UDM", "UNKNOWN", "UnsupportedSbiOperation [conn=x/stream=1]"),
            stale_callflow_event("sbi-2", "AMF", "UDM", "UNKNOWN", "UnsupportedSbiOperation [conn=x/stream=1]"),
        ];
        let counters = Arc::new(PatchCounters::new());
        patch_flow_events(&mut events, &index, &lab_endpoint_map(), &counters);
        match expected {
            Some(name) => assert_eq!(events[0]["message_name"], name),
            None => panic!("le catalogue SBI doit connaître nnrf-disc POST"),
        }
        assert!(events[1]["message_name"].as_str().unwrap().starts_with("UnsupportedSbiOperation"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2.21.166 (ordre cœur #9 7135745591) — un participant nommé à la
    /// publication SURVIT au patch à la lecture quand l'event brut ne sait
    /// pas mieux (adresses absentes de la table, pas de fonction réseau).
    /// Avant 2.21.166 il était remplacé par « Unknown endpoint ».
    #[test]
    fn a_named_participant_survives_the_read_time_patch_2_21_166() {
        let raw = |event_id: &str| {
            json!({
                "event_id": event_id,
                "interface": "SBI",
                "protocol": "SBI",
                "message_name": "POST /nudm-sdm/v2",
                "source_endpoint": {"address": "192.0.2.10", "port": 7777},
                "destination_endpoint": {"address": "192.0.2.11", "port": 7777},
            })
        };
        let mut by_event_id = HashMap::new();
        by_event_id.insert("evt-named".to_string(), raw("evt-named"));
        by_event_id.insert("evt-unknown".to_string(), raw("evt-unknown"));
        let index = RawEventIndex::from_map(by_event_id);
        let mut events = vec![
            json!({"event_id": "evt-named", "interface": "SBI", "protocol": "SBI",
                   "message_name": "POST /nudm-sdm/v2",
                   "source_participant": "AMF", "destination_participant": "UDM"}),
            json!({"event_id": "evt-unknown", "interface": "SBI", "protocol": "SBI",
                   "message_name": "POST /nudm-sdm/v2",
                   "source_participant": "Unknown endpoint", "destination_participant": ""}),
        ];
        let counters = Arc::new(PatchCounters::new());
        patch_flow_events(&mut events, &index, &HashMap::new(), &counters);
        assert_eq!(events[0]["source_participant"], "AMF", "{}", events[0]);
        assert_eq!(events[0]["destination_participant"], "UDM", "{}", events[0]);
        // Sans nom connu nulle part, « Unknown endpoint » reste, comptable.
        assert_eq!(events[1]["source_participant"], "Unknown endpoint");
        assert_eq!(events[1]["destination_participant"], "Unknown endpoint");
    }
}

#[cfg(test)]
mod callflow_pfcp_insert_tests {
    use super::*;
    use serde_json::json;

    /// 2.21.70 (ordre #9 7006855142) — `count_pfcp_siblings_for_persisted_events`
    /// doit retourner EXACTEMENT le delta ajouté par
    /// `insert_pfcp_siblings_into_callflow` quand les deux sont appelés
    /// sur les MÊMES events persistés + le MÊME dataset_root. Preuve
    /// d'équivalence : le comptage ne mute pas la liste et ne scanne pas
    /// différemment du chemin d'insertion.
    #[test]
    fn count_pfcp_siblings_matches_insert_pfcp_siblings_delta_2_21_70() {
        let dir = std::env::temp_dir().join(format!("rtp-count-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 3 siblings PFCP partagent des sequences/seid connus par la
        // session, un 4e appartient à une autre session (interface N4
        // mais sequence inconnue) — non compté.
        let sibling_a = json!({"event_id":"evt-sib-a","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","pfcp_sequence":"100",
            "session_identifiers":[{"name":"pfcp_sequence","value":"100"}],
            "timestamp":{"seconds":1,"nanoseconds":0,"raw_ticks":1u64,"display":"x"},
            "source_endpoint":{"address":"10.0.0.1","port":8805,"network_function":"SMF"},
            "destination_endpoint":{"address":"10.0.0.2","port":8805,"network_function":"UPF"}});
        let sibling_b = json!({"event_id":"evt-sib-b","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Deletion Request","pfcp_sequence":"101",
            "session_identifiers":[{"name":"pfcp_sequence","value":"101"}],
            "timestamp":{"seconds":1,"nanoseconds":0,"raw_ticks":2u64,"display":"x"},
            "source_endpoint":{"address":"10.0.0.1","port":8805,"network_function":"SMF"},
            "destination_endpoint":{"address":"10.0.0.2","port":8805,"network_function":"UPF"}});
        let sibling_other = json!({"event_id":"evt-sib-other","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","pfcp_sequence":"999",
            "session_identifiers":[{"name":"pfcp_sequence","value":"999"}]});
        std::fs::write(
            dir.join("oiran_events.jsonl"),
            format!("{}\n{}\n{}\n", sibling_a, sibling_b, sibling_other),
        )
        .unwrap();
        // Les events persistés contiennent des PFCP responses qui
        // référencent les mêmes pfcp_sequence que les siblings a/b.
        let persisted = vec![
            json!({"event_id":"evt-ngap","protocol":"NGAP","interface":"N2","message_name":"InitialUEMessage"}),
            json!({"event_id":"evt-resp-a","protocol":"PFCP","interface":"N4","message_name":"PFCP Session Establishment Response",
                "decoded_ie_tree":[{"name":"pfcp_sequence","value":"100"}]}),
            json!({"event_id":"evt-resp-b","protocol":"PFCP","interface":"N4","message_name":"PFCP Session Deletion Response",
                "decoded_ie_tree":[{"name":"pfcp_sequence","value":"101"}]}),
        ];
        let count = count_pfcp_siblings_for_persisted_events(&persisted, &dir).unwrap();
        let mut scratch = persisted.clone();
        let delta = insert_pfcp_siblings_into_callflow(&mut scratch, &dir).unwrap();
        assert_eq!(
            count, delta,
            "count helper must match insert delta ; count={count} delta={delta}"
        );
        assert_eq!(count, 2, "exactly 2 siblings (a + b), not the 'other' session's PFCP");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2.21.112 (recette 2.21.104, ANR1 #10 7050183853 : une session
    /// ancienne rend 67 events sur 72 avec `stable_event_key`, 5 PFCP
    /// sans) — un frère PFCP inséré à la lecture depuis le JSONL brut
    /// reçoit sa clé, par la même formule que le reste du callflow.
    /// Avant correctif : clé absente. Un frère sans `packet_references`
    /// reste sans clé, et un frère qui en porte déjà une la garde.
    #[test]
    fn inserted_pfcp_siblings_carry_a_stable_event_key_2_21_112() {
        let dir = std::env::temp_dir().join(format!(
            "rtp-sibling-key-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let sibling = |id: &str, seq: &str, packet: u64, extra: Value| {
            let mut event = json!({"event_id":id,"capture_id":"c","interface":"N4","protocol":"PFCP",
                "message_name":"PFCP Session Establishment Request","pfcp_sequence":seq,
                "session_identifiers":[{"name":"pfcp_sequence","value":seq}],
                "timestamp":{"seconds":1,"nanoseconds":0,"raw_ticks":packet,"display":"x"},
                "source_endpoint":{"address":"10.0.0.1","port":8805,"network_function":"SMF"},
                "destination_endpoint":{"address":"10.0.0.2","port":8805,"network_function":"UPF"}});
            for (key, value) in extra.as_object().unwrap() {
                event[key] = value.clone();
            }
            event
        };
        let reference = |packet: u64| {
            json!([{"source_file":"/ring/n4/n4_00007.pcapng","interface_id":0,
                "packet_number":packet,"byte_offset":packet * 100}])
        };
        let with_packet = sibling("evt-sib-a", "100", 7, json!({"packet_references": reference(7)}));
        let without_packet = sibling("evt-sib-b", "101", 8, json!({}));
        let already_keyed = sibling(
            "evt-sib-c",
            "102",
            9,
            json!({"packet_references": reference(9), "stable_event_key": "kept|0|9|900|PFCP|0"}),
        );
        std::fs::write(
            dir.join("oiran_events.jsonl"),
            format!("{}\n{}\n{}\n", with_packet, without_packet, already_keyed),
        )
        .unwrap();
        let response = |id: &str, seq: &str| {
            json!({"event_id":id,"protocol":"PFCP","interface":"N4",
                "message_name":"PFCP Session Establishment Response",
                "stable_event_key":"n4_00007.pcapng|0|1|100|PFCP|0",
                "decoded_ie_tree":[{"name":"pfcp_sequence","value":seq}]})
        };
        let mut events = vec![
            response("evt-resp-a", "100"),
            response("evt-resp-b", "101"),
            response("evt-resp-c", "102"),
        ];
        let added = insert_pfcp_siblings_into_callflow(&mut events, &dir).unwrap();
        assert_eq!(added, 3);
        let key_of = |id: &str| {
            events
                .iter()
                .find(|e| e["event_id"] == id)
                .and_then(|e| e.get("stable_event_key"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(
            key_of("evt-sib-a"),
            event_schema::derive_stable_event_key("/ring/n4/n4_00007.pcapng", 0, 7, 700, "PFCP", 0),
            "clé dérivée par la formule commune"
        );
        assert_eq!(key_of("evt-sib-c"), "kept|0|9|900|PFCP|0", "clé existante gardée");
        assert_eq!(key_of("evt-sib-b"), "", "sans packet_references : pas de clé inventée");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2.21.70 (ordre #9 7006855142) — Invariant pagination multi-pages :
    /// pour un callflow persisté de N events + K siblings PFCP (ajoutés
    /// à la page 1 par `insert_pfcp_siblings_into_callflow`), toutes
    /// les pages doivent annoncer `total_events = N + K` et la somme
    /// des `returned_events` sur toutes les pages doit égaler N + K
    /// SANS doublon d'`event_id`. Simulé ici au niveau de la session
    /// (sans spawner le serveur axum) via `count_pfcp_siblings_for_persisted_events`
    /// + pagination manuelle sur la liste persistée.
    #[test]
    fn multi_page_total_events_is_coherent_and_no_event_id_duplicate_2_21_70() {
        use std::collections::BTreeSet;
        let dir = std::env::temp_dir().join(format!("rtp-multipage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 1 sibling PFCP ajouté hors persisté.
        let sibling = json!({"event_id":"evt-sib","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","pfcp_sequence":"42",
            "session_identifiers":[{"name":"pfcp_sequence","value":"42"}],
            "timestamp":{"seconds":1,"nanoseconds":0,"raw_ticks":42u64,"display":"x"},
            "source_endpoint":{"address":"10.0.0.1","port":8805,"network_function":"SMF"},
            "destination_endpoint":{"address":"10.0.0.2","port":8805,"network_function":"UPF"}});
        std::fs::write(dir.join("oiran_events.jsonl"), format!("{}\n", sibling)).unwrap();
        // 5 events persistés dont 1 PFCP response porteuse de la seq 42.
        let persisted = vec![
            json!({"event_id":"e0","protocol":"NGAP","interface":"N2","message_name":"InitialUEMessage"}),
            json!({"event_id":"e1","protocol":"NGAP","interface":"N2","message_name":"InitialContextSetupRequest"}),
            json!({"event_id":"e2","protocol":"PFCP","interface":"N4","message_name":"PFCP Session Establishment Response",
                "decoded_ie_tree":[{"name":"pfcp_sequence","value":"42"}]}),
            json!({"event_id":"e3","protocol":"NGAP","interface":"N2","message_name":"InitialContextSetupResponse"}),
            json!({"event_id":"e4","protocol":"NGAP","interface":"N2","message_name":"UEContextReleaseCommand"}),
        ];
        // Compte canonique au niveau session (nouveau comportement
        // 2.21.70) : indépendant de la page.
        let siblings_count = count_pfcp_siblings_for_persisted_events(&persisted, &dir).unwrap();
        assert_eq!(siblings_count, 1);
        let session_total = persisted.len() + siblings_count; // = 6

        // Simule la pagination server-side : page 1 reçoit les siblings
        // (insertés par `insert_pfcp_siblings_into_callflow`), pages 2+
        // ne servent QUE des events persistés.
        let limit = 2usize;
        // 2.21.70 : page 1 utilise les clés de la SESSION COMPLÈTE,
        // pas de la page restreinte. L'ancienne fonction
        // `insert_pfcp_siblings_into_callflow` (clés dérivées des page
        // events) renvoyait 0 siblings quand la page ne contenait pas
        // les events PFCP porteurs (régression noté par le cœur).
        let session_keys = collect_pfcp_session_keys(&persisted);
        let mut page_1 = persisted.iter().take(limit).cloned().collect::<Vec<_>>();
        let delta = insert_pfcp_siblings_into_callflow_using_session_keys(
            &mut page_1,
            &dir,
            &session_keys,
        )
        .unwrap();
        assert_eq!(delta, 1, "page 1 doit recevoir le sibling via les clés de session");
        let total_events_page_1 = (persisted.len() + siblings_count) as u64;
        let returned_page_1 = page_1.len();

        // Page 2 et 3 : persisted events seulement, total_events = session_total.
        let page_2 = persisted.iter().skip(limit).take(limit).cloned().collect::<Vec<_>>();
        let page_3 = persisted.iter().skip(2 * limit).cloned().collect::<Vec<_>>();
        let total_events_page_2 = session_total as u64;
        let total_events_page_3 = session_total as u64;

        // Invariant 1 : total_events CONSTANT sur toutes les pages.
        assert_eq!(total_events_page_1, total_events_page_2);
        assert_eq!(total_events_page_2, total_events_page_3);
        assert_eq!(total_events_page_1, session_total as u64);

        // Invariant 2 : sum(returned_events) = total_events.
        let returned_sum = returned_page_1 + page_2.len() + page_3.len();
        assert_eq!(
            returned_sum as u64, total_events_page_1,
            "sum des returned_events doit égaler total_events ; sum={returned_sum} total={total_events_page_1}"
        );

        // Invariant 3 : aucun doublon d'event_id entre pages.
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for page in [&page_1, &page_2, &page_3] {
            for event in page.iter() {
                let id = event["event_id"].as_str().unwrap().to_owned();
                assert!(
                    seen.insert(id.clone()),
                    "event_id {id} dupliqué entre pages"
                );
            }
        }
        // Le sibling fait partie du set global.
        assert!(seen.contains("evt-sib"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_request_is_converted_and_placed_before_its_response() {
        let dir = std::env::temp_dir().join(format!("rtp-cf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // ANR1 #10 6885876387 shape: Request type 50 only in the JSONL.
        let request = json!({
            "event_id":"evt-349c72dc0f5510c3","capture_id":"sha256:continuous","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","message_type":50,
            "timestamp":{"seconds":1,"nanoseconds":0,"raw_ticks":1794673477113697742u64,"display":"x"},
            "source_endpoint":{"address":"10.77.23.12","port":8805,"network_function":"SMF"},
            "destination_endpoint":{"address":"10.77.23.13","port":8805,"network_function":"UPF"},
            "session_identifiers":[{"name":"pfcp_sequence","value":"2209","pseudonymized":false}],
            "information_elements":[],"pfcp_sequence":"2209"
        });
        std::fs::write(dir.join("oiran_events.jsonl"), format!("{}\n", request)).unwrap();
        let mut events = vec![
            json!({"event_id":"evt-ngap","protocol":"NGAP","interface":"N2","message_name":"InitialUEMessage"}),
            json!({"event_id":"evt-104645ebe2174b02","protocol":"PFCP","interface":"N4","message_name":"PFCP Session Establishment Response",
                   "decoded_ie_tree":[{"name":"pfcp_sequence","source":"session_identifiers","value":"2209"}]}),
            json!({"event_id":"evt-aa1b0ac453b62fd9","protocol":"PFCP","interface":"N4","message_name":"PFCP Session Modification Request",
                   "decoded_ie_tree":[{"name":"pfcp_sequence","source":"session_identifiers","value":"2210"}]}),
        ];
        let added = insert_pfcp_siblings_into_callflow(&mut events, &dir).unwrap();
        assert_eq!(added, 1);
        let ids: Vec<&str> = events
            .iter()
            .map(|e| e["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            ids,
            vec![
                "evt-ngap",
                "evt-349c72dc0f5510c3",
                "evt-104645ebe2174b02",
                "evt-aa1b0ac453b62fd9"
            ]
        );
        let req = &events[1];
        assert_eq!(req["source_participant"], "SMF");
        assert_eq!(req["destination_participant"], "UPF");
        assert_eq!(req["timestamp_ns"], "1794673477113697742");
        // idempotent
        assert_eq!(
            insert_pfcp_siblings_into_callflow(&mut events, &dir).unwrap(),
            0
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod pfcp_interface_guard_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pfcp_index_extends_on_append_and_skips_a_partial_last_line() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("rtp-inc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oiran_events.jsonl");
        let line = |id: &str, seq: &str| {
            json!({"event_id":id,"protocol":"PFCP","interface":"N4","message_name":"PFCP Session Establishment Request",
                "pfcp_sequence":seq}).to_string()
        };
        std::fs::write(&path, format!("{}\n", line("e1", "1"))).unwrap();
        let first = cached_pfcp_index(&dir).unwrap();
        assert_eq!(first.entries(), 1);
        let scanned_before = first.scanned[0];
        drop(first);
        // ajout d'une ligne complète + d'une ligne en cours d'écriture
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        write!(file, "{}\n{}", line("e2", "2"), &line("e3", "3")[..20]).unwrap();
        drop(file);
        let second = cached_pfcp_index(&dir).unwrap();
        assert_eq!(second.entries(), 2, "seule la ligne complète est indexée");
        assert!(second.scanned[0] > scanned_before);
        let found = pfcp_events_for_keys(&second, &["seq:2".to_string()].into_iter().collect());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["event_id"], "e2");
        drop(second);
        // rotation : fichier réécrit plus court → reconstruction complète
        std::fs::write(&path, format!("{}\n", line("e9", "9"))).unwrap();
        let third = cached_pfcp_index(&dir).unwrap();
        assert_eq!(third.entries(), 1);
        assert_eq!(pfcp_events_for_keys(&third, &["seq:9".to_string()].into_iter().collect()).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pfcp_heartbeat_sharing_the_sequence_is_never_pulled_into_a_session() {
        let dir = std::env::temp_dir().join(format!("rtp-hb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let request = json!({"event_id":"evt-req","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","pfcp_sequence":"9",
            "session_identifiers":[{"name":"pfcp_sequence","value":"9"}]});
        let heartbeat = json!({"event_id":"evt-hb","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Heartbeat Request","pfcp_sequence":"9",
            "session_identifiers":[{"name":"pfcp_sequence","value":"9"}]});
        std::fs::write(dir.join("oiran_events.jsonl"), format!("{}\n{}\n", request, heartbeat)).unwrap();
        let mut events = vec![json!({"event_id":"evt-resp","protocol":"PFCP","interface":"N4",
            "message_name":"PFCP Session Establishment Response",
            "decoded_ie_tree":[{"name":"pfcp_sequence","source":"session_identifiers","value":"9"}]})];
        insert_pfcp_siblings_into_callflow(&mut events, &dir).unwrap();
        let ids: Vec<&str> = events.iter().map(|e| e["event_id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["evt-req", "evt-resp"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sxab_pfcp_with_same_sequence_is_not_pulled_into_a_5g_n4_session() {
        let dir = std::env::temp_dir().join(format!("rtp-if-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let n4_request = json!({"event_id":"evt-n4-req","capture_id":"c","interface":"N4","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","pfcp_sequence":"7",
            "session_identifiers":[{"name":"pfcp_sequence","value":"7"},{"name":"f_seid","value":"0x0000000000000001"}]});
        let sxab_same_seq = json!({"event_id":"evt-sxab-req","capture_id":"c","interface":"Sxab","protocol":"PFCP",
            "message_name":"PFCP Session Establishment Request","pfcp_sequence":"7",
            "session_identifiers":[{"name":"pfcp_sequence","value":"7"},{"name":"f_seid","value":"0x0000000000000001"}]});
        std::fs::write(
            dir.join("oiran_events.jsonl"),
            format!("{}\n{}\n", n4_request, sxab_same_seq),
        )
        .unwrap();
        let mut events = vec![json!({"event_id":"evt-n4-resp","protocol":"PFCP","interface":"N4",
            "message_name":"PFCP Session Establishment Response",
            "decoded_ie_tree":[{"name":"pfcp_sequence","source":"session_identifiers","value":"7"}]})];
        let added = insert_pfcp_siblings_into_callflow(&mut events, &dir).unwrap();
        let ids: Vec<&str> = events.iter().map(|e| e["event_id"].as_str().unwrap()).collect();
        assert_eq!(added, 1);
        assert_eq!(ids, vec!["evt-n4-req", "evt-n4-resp"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod pfcp_cache_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cold_pfcp_session_reads_only_the_served_shards_2_21_182() {
        let dir = std::env::temp_dir().join(format!("rtp-cold-pfcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = dir.as_path();
        std::fs::create_dir_all(root.join("event-shards")).unwrap();
        let mut shards = Vec::new();
        for name in ["first", "second", "retired"] {
            let path = format!("event-shards/{name}.jsonl");
            let event = json!({
                "event_id": name, "capture_id": name, "protocol": "PFCP",
                "interface": "N4", "pfcp_sequence": "7",
                "message_name": "PFCP Session Establishment Request"
            });
            let bytes = format!("{event}\n");
            std::fs::write(root.join(&path), &bytes).unwrap();
            if name != "retired" {
                shards.push(json!({
                    "path": path, "sha256": name, "bytes": bytes.len(), "event_count": 1
                }));
            }
        }
        std::fs::write(
            root.join("dataset_manifest.json"),
            json!({"event_shards": shards}).to_string(),
        ).unwrap();
        let mut events = vec![json!({
            "event_id": "response", "protocol": "PFCP", "interface": "N4",
            "message_name": "PFCP Session Establishment Response",
            "decoded_ie_tree": [{"name": "pfcp_sequence", "source": "session_identifiers", "value": "7"}]
        })];
        let start = std::time::Instant::now();
        let added = extend_items_with_pfcp_siblings_from_jsonl(&mut events, root).unwrap();
        eprintln!("cold_pfcp_access_ms={:.3}", start.elapsed().as_secs_f64() * 1000.0);
        let ids: BTreeSet<_> = events.iter().map(|event| event["event_id"].as_str().unwrap()).collect();
        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(ids, BTreeSet::from(["first", "second", "response"]));
        assert_eq!(added, 2);
    }

    #[test]
    fn registered_pfcp_shards_override_disk_and_evict_retired_offsets() {
        let root = std::env::temp_dir().join(format!("rtp-registered-pfcp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("event-shards")).unwrap();
        let shards: Vec<_> = ["active", "retired"].into_iter().map(|name| {
            let path = format!("event-shards/{name}.jsonl");
            let event = json!({"event_id":name,"protocol":"PFCP","pfcp_sequence":"7"});
            let body = format!("{event}\n");
            std::fs::write(root.join(&path), &body).unwrap();
            live_probe::EventShard {
                path, sha256: name.into(), bytes: body.len() as u64,
                event_count: 1, capture_ends: Default::default(),
            }
        }).collect();
        std::fs::write(
            root.join("dataset_manifest.json"),
            json!({"event_shards": shards}).to_string(),
        ).unwrap();
        let keys = BTreeSet::from(["seq:7".to_owned()]);
        let both = cached_pfcp_index_for_shards(&root, &shards).unwrap();
        assert_eq!(pfcp_events_for_keys(&both, &keys).len(), 2);

        let active = cached_pfcp_index_for_shards(&root, &shards[..1]).unwrap();
        let events = pfcp_events_for_keys(&active, &keys);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["event_id"], "active");
        assert!(root.join(&shards[1].path).is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn index_keeps_only_offsets_and_rereads_matching_lines() {
        let dir =
            std::env::temp_dir().join(format!("rtp-cache-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let req = |id: &str, seq: &str| json!({"event_id":id,"protocol":"PFCP","pfcp_sequence":seq,"message_name":"PFCP Session Establishment Request"});
        let other = json!({"event_id":"evt-ngap","protocol":"NGAP"});
        std::fs::write(
            dir.join("oiran_events.jsonl"),
            format!("{}\n{}\n", other, req("evt-a", "1")),
        )
        .unwrap();
        let first = cached_pfcp_index(&dir).unwrap();
        assert_eq!(first.entries(), 1);
        let again = cached_pfcp_index(&dir).unwrap();
        assert!(
            std::sync::Arc::ptr_eq(&first, &again),
            "unchanged files must reuse the index"
        );
        let keys: BTreeSet<String> = ["seq:1".to_string()].into_iter().collect();
        let found = pfcp_events_for_keys(&first, &keys);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["event_id"], "evt-a");
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(
            dir.join("oiran_events.jsonl"),
            format!("{}\n{}\n{}\n", other, req("evt-a", "1"), req("evt-b", "2")),
        )
        .unwrap();
        assert_eq!(cached_pfcp_index(&dir).unwrap().entries(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod pfcp_index_memory_probe {
    /// 2.15.5 — sonde mémoire manuelle (ignorée par défaut) :
    /// `OIRAN_PFCP_PROBE_DIR=<dir> cargo test --release -- --ignored pfcp_index_memory_probe`
    #[test]
    #[ignore]
    fn build_index_on_dir() {
        let dir = std::env::var("OIRAN_PFCP_PROBE_DIR").expect("OIRAN_PFCP_PROBE_DIR");
        let index = super::cached_pfcp_index(std::path::Path::new(&dir)).unwrap();
        eprintln!("pfcp_index_entries={}", index.entries());
    }
}

/// 2.18.9 — dernier recours pour les participants restés « Unknown
/// endpoint » (constat Sadok : ladder LTE d'une seule colonne « Unknown
/// endpoint » ; sessions du LTE evidence store sans JSONL raw → aucun
/// patch IP/port possible). On ne devine rien au-delà de ce que
/// l'interface 3GPP impose : chaque interface relie exactement deux
/// rôles (TS 23.401 / 23.501), et la direction déjà publiée
/// (`RAN_TO_CORE`, `CORE_TO_RAN`, `UPLINK`, `DOWNLINK`, `REQUEST`,
/// `RESPONSE`) — ou, pour un NAS sans direction, le sens normatif du
/// message (TS 24.301 / 24.501) — dit lequel est la source. Direction
/// inconnue et message non classé → on laisse « Unknown endpoint ».
/// Retourne le nombre d'events résolus.
pub fn fill_unknown_participants_by_interface(events: &mut [Value]) -> usize {
    let mut resolved = 0;
    for event in events.iter_mut() {
        let unknown = |key: &str| {
            event
                .get(key)
                .and_then(Value::as_str)
                .map_or(true, |value| value.is_empty() || value == "Unknown endpoint")
        };
        if !(unknown("source_participant") || unknown("destination_participant")) {
            continue;
        }
        let interface = event.get("interface").and_then(Value::as_str).unwrap_or("").to_ascii_uppercase();
        let Some((ran_side, core_side)) = interface_roles(&interface) else {
            continue;
        };
        let direction = event.get("direction").and_then(Value::as_str).unwrap_or("").to_ascii_uppercase();
        let message = event.get("message_name").and_then(Value::as_str).unwrap_or("");
        let from_ran = match direction.as_str() {
            "RAN_TO_CORE" | "UPLINK" | "UE_TO_NETWORK" => Some(true),
            "CORE_TO_RAN" | "DOWNLINK" | "NETWORK_TO_UE" => Some(false),
            _ => nas_message_is_uplink(message),
        };
        let Some(from_ran) = from_ran else { continue };
        let (source, destination) = if from_ran { (ran_side, core_side) } else { (core_side, ran_side) };
        let Some(object) = event.as_object_mut() else { continue };
        let mut changed = false;
        for (key, value) in [("source_participant", source), ("destination_participant", destination)] {
            let is_unknown = object
                .get(key)
                .and_then(Value::as_str)
                .map_or(true, |current| current.is_empty() || current == "Unknown endpoint");
            if is_unknown {
                object.insert(key.into(), Value::String(value.into()));
                changed = true;
            }
        }
        if changed {
            object.insert(
                "participant_source".into(),
                Value::String("interface_roles".into()),
            );
            resolved += 1;
        }
    }
    resolved
}

/// (côté « RAN / amont », côté « cœur / aval ») de chaque interface.
fn interface_roles(interface: &str) -> Option<(&'static str, &'static str)> {
    Some(match interface {
        "S1-MME" | "S1MME" | "S1AP" => ("eNB", "MME"),
        "S1-U" | "S1U" => ("eNB", "SGW-U"),
        "S11" => ("MME", "SGW-C"),
        "S5-C" | "S5C" | "S5/S8-C" => ("SGW-C", "PGW-C"),
        "S5-U" | "S5U" => ("SGW-U", "PGW-U"),
        "SXA" => ("SGW-C", "SGW-U"),
        "SXB" => ("PGW-C", "PGW-U"),
        "S6A" => ("MME", "HSS"),
        "N2" => ("gNB", "AMF"),
        "N3" => ("gNB", "UPF"),
        "N4" => ("SMF", "UPF"),
        _ => return None,
    })
}

/// Sens normatif d'un message NAS sans direction publiée : `Some(true)`
/// = UE → réseau, `Some(false)` = réseau → UE, `None` = non classé.
fn nas_message_is_uplink(message: &str) -> Option<bool> {
    let name = message.to_ascii_lowercase();
    const UPLINK: &[&str] = &[
        "attach request", "attach complete", "authentication response", "authentication failure",
        "security mode complete", "security mode reject", "identity response", "detach request",
        "tracking area update request", "tracking area update complete", "service request",
        "registration request", "registration complete", "esm information response",
        "pdn connectivity request", "ul nas transport", "uplink nas transport",
        "activate default eps bearer context accept", "pdu session establishment request",
        "initialuemessage", "initial ue message",
    ];
    const DOWNLINK: &[&str] = &[
        "attach accept", "attach reject", "authentication request", "authentication reject",
        "security mode command", "identity request", "detach accept", "tracking area update accept",
        "service reject", "registration accept", "registration reject", "esm information request",
        "activate default eps bearer context request", "dl nas transport", "downlink nas transport",
        "emm information", "configuration update command", "pdu session establishment accept",
    ];
    if DOWNLINK.iter().any(|needle| name.contains(needle)) {
        Some(false)
    } else if UPLINK.iter().any(|needle| name.contains(needle)) {
        Some(true)
    } else {
        None
    }
}

#[cfg(test)]
mod interface_roles_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unknown_lte_participants_resolve_from_interface_and_direction() {
        let mut events = vec![
            json!({"interface":"S1-MME","direction":"RAN_TO_CORE","message_name":"InitialUEMessage · Attach Request","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint"}),
            json!({"interface":"S1-MME","direction":"UNKNOWN","message_name":"Authentication Request","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint"}),
            json!({"interface":"S1-MME","direction":"UNKNOWN","message_name":"Security Mode Complete","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint"}),
            json!({"interface":"S1-MME","direction":"UNKNOWN","message_name":"UnknownS1APProcedure","source_participant":"Unknown endpoint","destination_participant":"Unknown endpoint"}),
            json!({"interface":"S11","direction":"CORE_TO_RAN","message_name":"Create Session Response","source_participant":"Unknown endpoint","destination_participant":"MME"}),
            json!({"interface":"N2","direction":"RAN_TO_CORE","message_name":"x","source_participant":"gNB 10.0.0.1","destination_participant":"AMF"}),
        ];
        assert_eq!(fill_unknown_participants_by_interface(&mut events), 4);
        assert_eq!((events[0]["source_participant"].as_str(), events[0]["destination_participant"].as_str()), (Some("eNB"), Some("MME")));
        assert_eq!((events[1]["source_participant"].as_str(), events[1]["destination_participant"].as_str()), (Some("MME"), Some("eNB")));
        assert_eq!(events[2]["source_participant"], "eNB");
        // message non classé, direction inconnue → rien deviné
        assert_eq!(events[3]["source_participant"], "Unknown endpoint");
        // participant déjà connu conservé
        assert_eq!(events[4]["source_participant"], "SGW-C");
        assert_eq!(events[4]["destination_participant"], "MME");
        assert_eq!(events[5]["source_participant"], "gNB 10.0.0.1");
    }
}
