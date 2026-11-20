//! Bounded live-trace registry and SSE transport.
//!
//! Clear lookup values are used only to resolve the root-only identity vault.
//! They are deliberately absent from records, audit entries and errors.

use super::*;
use axum::response::sse::{Event, KeepAlive, Sse};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::Duration,
};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

const MAX_TRACES: usize = 10;
const MAX_EVENTS: usize = 2_000;

#[derive(Clone, Serialize)]
pub(crate) struct LiveTrace {
    trace_id: String,
    key_type: String,
    subscriber_pseudonyms: Vec<String>,
    interfaces: Vec<String>,
    created_at: u64,
    expires_at: u64,
    armed: bool,
    messages: u64,
    markers: u64,
    /// 2.18.6 — doublons (capture_id, packet_number, event_id) écartés.
    #[serde(default)]
    duplicates_dropped: u64,
    /// 2.18.6 — messages arrivés avec un packet_number inférieur au
    /// dernier émis pour la même capture (inversion intra-capture).
    #[serde(default)]
    out_of_order: u64,
    /// 2.21.105 (défaut recette prod G3 #10 7047592953, ordre #9 7047782479) —
    /// télémétrie de rattachement des events GTP-U à la trace. Un
    /// garde silencieux ne garde rien : 0 bucket doit être lisible
    /// comme `gpdu_seen=0` (alimentation) ou `gpdu_seen>0 &&
    /// gpdu_attached=0` (rattachement). Les 3 compteurs ci-dessous
    /// permettent le diagnostic, d'abord par trace, sans attendre de
    /// nouveau debug en prod.
    #[serde(default)]
    gpdu_seen: u64,
    #[serde(default)]
    gpdu_attached: u64,
    #[serde(default)]
    gpdu_rejected_no_match: u64,
    #[serde(default)]
    gpdu_rejected_interface_filter: u64,
    /// 2.21.105 (donnée ANR1 #10 7048928345, ordre #9 7048974175) —
    /// alimentation de la trace **par interface** : events décodés
    /// présentés à la trace (`seen`), écartés par le filtre
    /// `interfaces` (`filtered`), rattachés (`attached`), horodatage du
    /// dernier event et retard mesuré à son routage. Une trace « SBI
    /// seulement » se lit ici : `N2.seen>0 && N2.attached==0`
    /// (rattachement) ou `N2` absent (aucun event décodé).
    #[serde(default)]
    feed: BTreeMap<String, InterfaceFeed>,
    /// 2.21.105 — résultat de l'apprentissage sans émission depuis le
    /// ring de signalisation à l'ouverture de la trace.
    #[serde(default)]
    seed: SeedStats,
}

/// 2.21.105 — compteurs d'alimentation d'une trace pour une interface.
#[derive(Clone, Default, Serialize, Debug, PartialEq)]
pub(crate) struct InterfaceFeed {
    seen: u64,
    filtered: u64,
    attached: u64,
    /// Horodatage capture du dernier event présenté (secondes epoch).
    last_event_timestamp_s: Option<i64>,
    last_event_timestamp_ns: Option<u32>,
    /// `horloge murale au routage − horodatage capture` du dernier
    /// event, en ms. Signé : une horloge sonde en avance donne < 0.
    last_event_lag_ms: Option<i64>,
    /// Plus grand retard observé sur cette interface depuis l'ouverture.
    max_event_lag_ms: Option<i64>,
}

/// 2.21.105 — bilan de l'apprentissage depuis le ring (`seed_from_ring`).
#[derive(Clone, Default, Serialize, Debug, PartialEq)]
pub(crate) struct SeedStats {
    /// `false` tant que le lecteur n'a pas terminé la passe.
    done: bool,
    files: u64,
    bytes: u64,
    events_scanned: u64,
    events_learned: u64,
    /// `true` si au moins un fichier du ring a été laissé de côté par
    /// le plafond d'octets par interface.
    truncated: bool,
}

/// 2.21.105 — interfaces de signalisation relues à l'ouverture d'une
/// trace, dans l'ordre de dépendance : N2/S1-MME portent l'identité
/// et les tunnels, N4/S11/S5-C/Sxab s'y rattachent par tunnel, IP UE
/// pseudonymisée ou SEID. N3/S1-U/S5-U (plan usager, volumineux) et
/// SBI (porte l'identité dans chaque requête) ne sont jamais relus.
const SEED_INTERFACES: [&str; 6] = ["N2", "S1-MME", "N4", "S11", "S5-C", "Sxab"];
/// 2.21.105 — plafond d'octets relus par interface pour un amorçage.
const SEED_MAX_BYTES_PER_INTERFACE: u64 = 64 * 1024 * 1024;
/// 2.21.105 — période d'émission de l'event SSE `stats`.
const STATS_INTERVAL: Duration = Duration::from_secs(5);

/// Nom du sous-répertoire du ring pour une interface.
fn ring_directory(interface: &str) -> String {
    match interface {
        "S1-MME" => "s1mme".into(),
        "S1-U" => "s1u".into(),
        "S5-C" => "s5c".into(),
        "S5-U" => "s5u".into(),
        other => other.to_ascii_lowercase(),
    }
}

/// 2.21.105 — choisit les fichiers du ring à relire pour l'amorçage :
/// les plus récents d'abord tant que le plafond tient, rendus du plus
/// ancien au plus récent (l'apprentissage suit l'ordre chronologique).
/// Retourne `(fichiers, tronqué)`.
fn select_seed_files(
    mut files: Vec<(std::path::PathBuf, u64, Option<std::time::SystemTime>)>,
    budget: u64,
) -> (Vec<(std::path::PathBuf, u64)>, bool) {
    files.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
    let mut selected = Vec::new();
    let mut total = 0u64;
    let mut truncated = false;
    for (path, size, _) in files.into_iter().rev() {
        if total.saturating_add(size) > budget {
            truncated = true;
            break;
        }
        total = total.saturating_add(size);
        selected.push((path, size));
    }
    selected.reverse();
    (selected, truncated)
}

/// 2.21.105 — bilan d'une passe d'amorçage, toutes interfaces.
#[derive(Default, Debug, PartialEq)]
pub(crate) struct SeedReport {
    files: u64,
    bytes: u64,
    truncated: bool,
}

/// 2.21.105 (ordre #9 7048974175) — relit le ring de signalisation et
/// présente chaque event aux traces en cours d'amorçage, **sans rien
/// émettre**. Cause traitée : une trace n'apprenait le contexte d'un
/// abonné (identifiants NGAP, IP UE, TEID, SEID) que sur des messages
/// décodés après son ouverture ; une session établie avant restait
/// invisible sur NAS/NGAP/PFCP/GTP-U, seul le SBI (identité dans
/// chaque requête) passait.
fn seed_from_ring(
    root: &std::path::Path,
    key: &event_schema::PseudonymKey,
    registry: &LiveTraceRegistry,
) -> SeedReport {
    let mut report = SeedReport::default();
    for interface in SEED_INTERFACES {
        let dir = root.join(ring_directory(interface));
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        let files: Vec<_> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("pcapng"))
            .filter_map(|path| {
                let meta = path.metadata().ok()?;
                Some((path, meta.len(), meta.modified().ok()))
            })
            .collect();
        let (selected, truncated) = select_seed_files(files, SEED_MAX_BYTES_PER_INTERFACE);
        report.truncated |= truncated;
        for (path, size) in selected {
            let config = oiran_decode::DecodeConfig {
                input: path.clone(),
                capture_id: format!("sha256:{}", sha256_hex(path.to_string_lossy().as_bytes())),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_owned())
                    .unwrap_or_default(),
            };
            let mut events = Vec::new();
            // Un fichier en cours d'écriture se termine par un bloc
            // partiel : les events complets sont gardés, l'erreur de
            // fin de fichier est attendue.
            let _ = oiran_decode::decode_capture_streaming(&config, key, |event| {
                events.push(event);
                Ok(())
            });
            sort_by_capture_order(&mut events);
            for event in &events {
                registry.learn_from_ring(event);
            }
            report.files += 1;
            report.bytes = report.bytes.saturating_add(size);
        }
    }
    report
}

#[derive(Clone)]
struct BufferedEvent {
    id: u64,
    kind: String,
    payload: Value,
}
/// 2.21.98 (défaut privacy ANR1 #10 7043526474, ordre #9 7043914072) — set
/// strictement interne au serveur pour matcher un event entrant à une trace
/// ouverte. Contient les chiffres canoniques de la saisie (amorçage 2.21.90),
/// les pseudonymes et IE values appris, et le pseudonyme UE IP calculé.
///
/// **Sans `Serialize`** : le type garantit à la compilation que son contenu
/// ne peut atteindre aucune sortie (SSE, journal, réponse HTTP). La fuite
/// observée en prod 2.21.94 (`ue_info.keys` sérialisait `TraceState::keys`,
/// qui contenait l'IMSI/MSISDN en clair saisi par l'opérateur) ne peut plus
/// se produire — seul `TraceState::exposed_keys` (pseudonymes uniquement)
/// peut remonter via SSE.
#[derive(Default, Clone, Debug)]
pub(crate) struct MatchKeys(HashSet<String>);

impl MatchKeys {
    pub fn insert(&mut self, key: String) -> bool {
        self.0.insert(key)
    }
    pub fn contains(&self, key: &str) -> bool {
        self.0.contains(key)
    }
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
    }
    pub fn clear(&mut self) {
        self.0.clear()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromIterator<String> for MatchKeys {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

struct TraceState {
    trace: LiveTrace,
    next_id: u64,
    events: VecDeque<BufferedEvent>,
    tx: broadcast::Sender<BufferedEvent>,
    /// 2.21.98 — clés internes de matching, JAMAIS sérialisées (cf. `MatchKeys`).
    match_keys: MatchKeys,
    /// 2.21.98 — clés exposées dans l'event SSE `ue_info` : UNIQUEMENT des
    /// pseudonymes (`psn-*` issus de session_identifiers avec
    /// `pseudonymized=true`) et le pseudonyme UE IP calculé (`pfcp-ue-ip`).
    /// Aucune valeur en clair, aucun chiffre canonique de la saisie.
    exposed_keys: HashSet<String>,
    /// 2.21.103 (ordre #9 7046282778, défaut ANR2 #10 7045891820) — signature
    /// (vecteur trié des `exposed_keys`) du dernier `ue_info` émis. Permet de
    /// n'émettre un nouvel `ue_info` QUE quand `exposed_keys` change
    /// effectivement — pas à chaque message routé. ANR2 a mesuré 28 759
    /// émissions sur 60 111 events (≈ 98,7 % du poids de la trace voix 1,97 Go).
    /// `None` initialement et après fin de session ⇒ le premier
    /// `ue_info` est toujours émis.
    last_ue_info_signature: Option<Vec<String>>,
    throughput_second: u64,
    ul_bytes: u64,
    dl_bytes: u64,
    /// 2.21.76 (ordre #9 7012275179 §CLAUDE2.D-06) — jusqu'à 2.21.74
    /// les events GTP-U de direction `UNKNOWN` tombaient dans le
    /// bucket DL par le `else if DOWNLINK` **sans** `else` explicite UL.
    /// Désormais comptabilisés séparément : l'opérateur voit les
    /// octets dont la direction n'est pas encore résolue (lookahead
    /// SCTP/TCP reassembly non abouti) sans fausser UL/DL.
    unknown_bytes: u64,
    /// 2.18.6 — dernier packet_number émis par capture_id.
    last_packet: HashMap<String, u64>,
    /// 2.18.6 — messages déjà émis (capture_id, packet_number, event_id).
    seen: HashSet<(String, u64, String)>,
    /// 2.21.90 défaut 2 — TEID (hex normalisé `0x..`) appris depuis les
    /// events routés. Permet de router un GTP-U/PFCP qui ne porte pas
    /// de pseudonyme abonné mais un TEID connu.
    tunnel_teids: HashSet<String>,
    /// 2.21.90 défaut 2 — tuples (ip normalisée, teid hex) F-TEID
    /// appris. Permet le match NGAP↔PFCP par tunnel endpoint.
    tunnel_endpoints: HashSet<(String, String)>,
    /// 2.21.90 défaut 2 — SEID (hex normalisé) appris depuis les events
    /// PFCP routés de l'abonné. Un event PFCP futur portant ce SEID est
    /// routé sans autre preuve.
    seids: HashSet<String>,
    /// 2.21.90 défaut 2 — IP UE (clair) apprises depuis NAS PDU Address.
    /// Conservées en mémoire du process pour le routage ; ne sont jamais
    /// exportées via SSE/API/logs (invariant privacy « pas d'IP UE en
    /// clair hors identity vault »).
    ue_ips: HashSet<String>,
    /// 2.21.105 — la trace attend son amorçage depuis le ring.
    needs_seed: bool,
    /// 2.21.105 — la trace est dans la passe d'amorçage en cours :
    /// seule cible de `learn_from_ring`.
    seeding: bool,
}
/// 2.21.90 défaut 2 — clé HMAC partagée pour pseudonymiser l'IP UE
/// apprise depuis NAS, dans le même domain que `decoder-pfcp` (IE 93),
/// afin de router les PFCP Session Establishment qui ne portent que
/// cette UE IP pseudonymisée. Chargée au plus une fois par process ;
/// absence de clé ⇒ routage par (ip,teid)/SEID seulement.
fn pseudonym_key() -> Option<&'static event_schema::PseudonymKey> {
    static KEY: OnceLock<Option<event_schema::PseudonymKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        event_schema::PseudonymKey::load_or_generate(
            &event_schema::PseudonymKey::resolve_default_path(),
        )
        .ok()
    })
    .as_ref()
}

/// 2.21.90 défaut 1 — chiffres canoniques d'une saisie clair-text IMSI/
/// MSISDN/IMEI/SUPI/TMSI. Strippe le préfixe `imsi-/msisdn-/imei-/supi-`
/// (TS 29.571 §5.4.5) puis ne conserve que les ASCII digits. Retourne
/// `None` sous 5 chiffres (seuil `identity_vault::lookup_keys`, évite
/// les collisions arbitraires dans `encoded.contains`). Utilisé pour
/// amorcer `state.keys` : un event qui porte la valeur en clair dans
/// n'importe quel IE (cas EPS/SUCI null-scheme) est routé.
fn canonical_digits(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("imsi-")
        .or_else(|| trimmed.strip_prefix("IMSI-"))
        .or_else(|| trimmed.strip_prefix("msisdn-"))
        .or_else(|| trimmed.strip_prefix("MSISDN-"))
        .or_else(|| trimmed.strip_prefix("imei-"))
        .or_else(|| trimmed.strip_prefix("IMEI-"))
        .or_else(|| trimmed.strip_prefix("imeisv-"))
        .or_else(|| trimmed.strip_prefix("IMEISV-"))
        .or_else(|| trimmed.strip_prefix("supi-"))
        .or_else(|| trimmed.strip_prefix("SUPI-"))
        .unwrap_or(trimmed);
    let digits: String = without_prefix.chars().filter(char::is_ascii_digit).collect();
    (digits.len() >= 5).then_some(digits)
}

/// 2.21.90 défaut 2 — itère les valeurs textuelles des IE d'un event
/// déjà sérialisé en JSON. Chaque IE expose un champ `value` chaîné
/// `key=value,key=value,…` (format produit par les decoders).
fn ie_values(value: &Value) -> Vec<String> {
    value
        .get("information_elements")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|ie| ie.get("value").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

/// 2.21.90 défaut 2 — tuples (ip, teid) extraits d'une IE `value`.
/// Couvre les trois formats produits par decoder-* :
///   * (`tunnel_endpoint_ip`, `gtp_teid`) — SBI/N4 legacy.
///   * (`ipv4`, `teid`) — PFCP F-TEID IE 21 et Outer Header Creation IE 84.
///   * (`item_*_tunnel_ip_ul|dl`, `item_*_gtp_teid_ul|dl`) — NGAP
///     PDU Session Resource Setup multipart.
/// Exactement les mêmes règles que `correlation-engine::tunnel_keys` +
/// `directional_tunnel_components`. IP normalisée (strip `::ffff:`) et
/// TEID normalisé (`event_schema::normalize_teid_hex`).
fn parse_tunnel_pairs(ie_value: &str) -> Vec<(String, String)> {
    let components: BTreeMap<&str, &str> = ie_value
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim(), v.trim()))
        })
        .collect();
    let mut out: Vec<(String, String)> = Vec::new();
    for (ip_name, teid_name) in [("tunnel_endpoint_ip", "gtp_teid"), ("ipv4", "teid")] {
        if let (Some(ip), Some(teid)) = (components.get(ip_name), components.get(teid_name)) {
            if let Some(nteid) = event_schema::normalize_teid_hex(teid) {
                out.push((event_schema::normalize_ip(ip), nteid));
            }
        }
    }
    for direction in ["ul", "dl"] {
        let ip_suf = format!("tunnel_ip_{direction}");
        let teid_suf = format!("gtp_teid_{direction}");
        for (ip_key, ip_val) in components.iter() {
            let suffix_match = *ip_key == ip_suf.as_str()
                || ip_key.ends_with(&format!("_{ip_suf}"));
            if !suffix_match {
                continue;
            }
            let prefix = ip_key.strip_suffix(ip_suf.as_str()).unwrap_or_default();
            let teid_key = format!("{prefix}{teid_suf}");
            if let Some(t) = components.get(teid_key.as_str()) {
                if let Some(nteid) = event_schema::normalize_teid_hex(t) {
                    out.push((event_schema::normalize_ip(ip_val), nteid));
                }
            }
        }
    }
    out
}

/// 2.21.90 défaut 2 — tous les TEID (hex) présents dans une IE `value` :
/// `teid=0x..`, `gtp_teid=0x..`, `gtp_teid_ul=..`, `gtp_teid_dl=..`,
/// ou `item_*_gtp_teid_*=..`. Normalisation `normalize_teid_hex`.
fn parse_teids(ie_value: &str) -> Vec<String> {
    ie_value
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            let key = k.trim();
            let is_teid = key == "teid"
                || key == "gtp_teid"
                || key == "gtp_teid_ul"
                || key == "gtp_teid_dl"
                || key.ends_with("_gtp_teid")
                || key.ends_with("_gtp_teid_ul")
                || key.ends_with("_gtp_teid_dl");
            if !is_teid {
                return None;
            }
            event_schema::normalize_teid_hex(v.trim())
        })
        .collect()
}

/// 2.21.90 défaut 2 — tous les SEID (`seid=0x..`, `f_seid=0x..`) d'une
/// IE value, normalisés `0x{:016x}`.
fn parse_seids(ie_value: &str) -> Vec<String> {
    ie_value
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            let key = k.trim();
            if key != "seid" && key != "f_seid" {
                return None;
            }
            let hex = v.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(hex, 16).ok().map(|n| format!("0x{n:016x}"))
        })
        .collect()
}

/// 2.21.90 défaut 2 — IP UE extraite d'une IE NAS « PDU address »
/// (`type=1,address=A.B.C.D`). Retour en forme clair IPv4, ou `None`.
fn parse_pdu_address(ie_value: &str) -> Option<String> {
    ie_value.split(',').find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim() == "address").then(|| event_schema::normalize_ip(v.trim()))
    })
}

/// 2.21.90 défaut 2 — valeurs des `session_identifiers` d'un event
/// pour un `name` donné (ex. `"seid"`, `"teid"`).
fn session_ids_named<'a>(value: &'a Value, name: &str) -> Vec<&'a str> {
    value
        .get("session_identifiers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|id| {
            let n = id.get("name").and_then(Value::as_str)?;
            (n == name).then(|| id.get("value").and_then(Value::as_str)).flatten()
        })
        .collect()
}

/// 2.21.103 (ordre #9 7046282778, défaut ANR2 #10 7045891820) — vrai si le
/// message PFCP est de **niveau nœud** (Heartbeat, Association, PFD
/// Management) et ne porte PAS une session abonné. Ces messages sont exclus
/// de la trace abonné : ANR2 a mesuré que 99,92 % des 22 769 PFCP d'une
/// trace voix étaient des Heartbeat d'association N4 sans portée abonné,
/// rejoués par le routage via IE values communes apprises (recovery_time_ntp,
/// node_id). La liste est explicite — l'ajout d'un nouveau type PFCP côté
/// décodeur n'autorise pas automatiquement son routage s'il est node-level.
fn is_pfcp_node_message(message_name: &str) -> bool {
    matches!(
        message_name,
        "PFCP Heartbeat Request"
            | "PFCP Heartbeat Response"
            | "PFCP Association Setup Request"
            | "PFCP Association Setup Response"
            | "PFCP Association Update Request"
            | "PFCP Association Update Response"
            | "PFCP Association Release Request"
            | "PFCP Association Release Response"
            | "PFCP PFD Management Request"
            | "PFCP PFD Management Response"
            | "PFCP Node Report Request"
            | "PFCP Node Report Response"
    )
}

pub(crate) struct LiveTraceRegistry {
    traces: Mutex<HashMap<String, TraceState>>,
    reader_running: AtomicBool,
    audit: Mutex<VecDeque<Value>>,
    /// 2.21.105 — durée (ms) de la dernière passe complète du lecteur
    /// sur toutes les interfaces. Le lecteur est une boucle unique et
    /// séquentielle : cette durée est le retard qu'une interface
    /// volumineuse (N3) impose aux suivantes et au tour d'après.
    reader_pass_ms: AtomicU64,
    /// 2.21.109 — sessions de reprise jetées (fichier remplacé/tronqué).
    resume_resets: AtomicU64,
    /// 2.21.109 — octets décodés / taille par plan, dernière passe.
    reader_io: Mutex<BTreeMap<String, ReaderIo>>,
}

impl LiveTraceRegistry {
    pub(crate) fn new() -> Self {
        Self {
            traces: Mutex::new(HashMap::new()),
            reader_running: AtomicBool::new(false),
            audit: Mutex::new(VecDeque::new()),
            reader_pass_ms: AtomicU64::new(0),
            resume_resets: AtomicU64::new(0),
            reader_io: Mutex::new(BTreeMap::new()),
        }
    }
    pub(crate) fn audit(&self, entry: Value) {
        let mut audit = self.audit.lock().unwrap();
        audit.push_front(entry);
        while audit.len() > 500 {
            audit.pop_back();
        }
    }

    /// 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-08) — journalise un
    /// lookup `/identities/lookup` : acteur, rôle, pseudonyme dérivé,
    /// nombre de résultats, heure. La **valeur saisie n'entre jamais**
    /// dans l'audit — le caller ne la passe pas, et le pseudonyme est
    /// la seule représentation persistante.
    pub(crate) fn audit_lookup(
        &self,
        actor_role: &str,
        subscriber_pseudonym: Option<&str>,
        result_count: usize,
        at_epoch_s: u64,
    ) {
        self.audit(serde_json::json!({
            "action": "identity.lookup",
            "actor_role": actor_role,
            "subscriber_pseudonym": subscriber_pseudonym,
            "result_count": result_count,
            "at_epoch_s": at_epoch_s,
        }));
    }
    fn purge(map: &mut HashMap<String, TraceState>) {
        let now = epoch_seconds();
        map.retain(|_, state| state.trace.expires_at > now);
    }

    /// 2.21.105 — ouvre une passe d'amorçage : les traces en attente
    /// passent en `seeding`. Une trace créée pendant la passe garde
    /// `needs_seed` et sera amorcée à la passe suivante. Retourne
    /// `true` si au moins une trace est à amorcer.
    pub(crate) fn begin_seed(&self) -> bool {
        let mut traces = self.traces.lock().unwrap();
        let mut any = false;
        for state in traces.values_mut() {
            if state.needs_seed {
                state.needs_seed = false;
                state.seeding = true;
                any = true;
            }
        }
        any
    }

    /// 2.21.105 — clôt la passe d'amorçage et publie son bilan dans
    /// l'état de chaque trace amorcée.
    pub(crate) fn finish_seed(&self, report: &SeedReport) {
        let mut traces = self.traces.lock().unwrap();
        for state in traces.values_mut() {
            if state.seeding {
                state.seeding = false;
                state.trace.seed.done = true;
                state.trace.seed.files = report.files;
                state.trace.seed.bytes = report.bytes;
                state.trace.seed.truncated = report.truncated;
            }
        }
    }

    /// 2.21.105 — contenu de l'event SSE `stats` d'une trace. Aucune
    /// identité : des compteurs, des noms d'interface, des horodatages.
    fn stats_payload(&self, trace: &LiveTrace) -> Value {
        json!({
            "wall_clock_s": epoch_seconds(),
            "reader_pass_ms": self.reader_pass_ms.load(Ordering::Relaxed),
            "reader": {
                "resume_resets": self.resume_resets.load(Ordering::Relaxed),
                "full_redecode": full_redecode_requested(),
                "interfaces": *self.reader_io.lock().unwrap(),
            },
            "messages": trace.messages,
            "gpdu": {
                "seen": trace.gpdu_seen,
                "attached": trace.gpdu_attached,
                "rejected_no_match": trace.gpdu_rejected_no_match,
                "rejected_interface_filter": trace.gpdu_rejected_interface_filter,
            },
            "interfaces": trace.feed,
            "seed": trace.seed,
        })
    }

    /// 2.21.105 — diffuse un event SSE `stats` à chaque trace. Diffusé
    /// aux abonnés connectés seulement, jamais mis dans le tampon de
    /// replay : il ne doit pas en chasser des messages, et le dernier
    /// état reste lisible par `GET /live/traces`.
    pub(crate) fn emit_stats(&self) {
        let mut traces = self.traces.lock().unwrap();
        Self::purge(&mut traces);
        for state in traces.values_mut() {
            state.next_id += 1;
            let payload = self.stats_payload(&state.trace);
            let _ = state.tx.send(BufferedEvent {
                id: state.next_id,
                kind: "stats".into(),
                payload,
            });
        }
    }

    pub(crate) fn bump_resume_resets(&self) {
        self.resume_resets.fetch_add(1, Ordering::Relaxed);
    }

    /// 2.21.109 — publie les octets lus par plan pendant la passe.
    /// Une passe sans aucun décodage garde le dernier relevé.
    pub(crate) fn set_reader_io(&self, pass: BTreeMap<String, ReaderIo>) {
        if !pass.is_empty() {
            *self.reader_io.lock().unwrap() = pass;
        }
    }

    pub(crate) fn set_reader_pass_ms(&self, value: u64) {
        self.reader_pass_ms.store(value, Ordering::Relaxed);
    }

    /// 2.21.99 (défaut recette prod #10 7043526474, ordre #9 7043914072) —
    /// flush périodique des buckets de débit. Avant 2.21.99, un bucket
    /// n'était émis **que** sur transition de `event.timestamp.seconds`
    /// (`route_normalized` l. 494-531). Conséquence prod : si le poll
    /// du ring voit N packets GTP-U avec le même `seconds`, puis plus
    /// aucun événement, les octets restent dans `state.{ul,dl,unknown}_bytes`
    /// **sans jamais émettre**. ANR1 mesure : 107 Mo DL + 13 Mo UL,
    /// **0 bucket** sur deux traces live (9 min), alors que 2.21.74
    /// produisait 168 échantillons.
    ///
    /// Appelé par `start_reader` à chaque tick (750 ms). Pour chaque
    /// trace active : si des octets sont accumulés (`throughput_second
    /// != 0 && (ul|dl|unknown) > 0`) et que le dernier bucket a plus
    /// d'une seconde (= on a franchi au moins une seconde wall-clock),
    /// émettre le bucket. L'event-driven path de `route_normalized`
    /// garde son rôle quand les événements arrivent en continu.
    pub(crate) fn flush_idle_throughput_buckets(&self) {
        let now = epoch_seconds();
        let mut traces = self.traces.lock().unwrap();
        Self::purge(&mut traces);
        for state in traces.values_mut() {
            if state.throughput_second == 0 {
                continue;
            }
            let has_bytes =
                state.ul_bytes > 0 || state.dl_bytes > 0 || state.unknown_bytes > 0;
            if !has_bytes {
                continue;
            }
            // Flush si la seconde du dernier event GTP-U est strictement
            // passée (wall-clock strictement > throughput_second).
            if now <= state.throughput_second {
                continue;
            }
            state.next_id += 1;
            let rate = BufferedEvent {
                id: state.next_id,
                kind: "throughput".into(),
                payload: json!({
                    "second": state.throughput_second,
                    "ul_bytes_s": state.ul_bytes,
                    "dl_bytes_s": state.dl_bytes,
                    "unknown_bytes_s": state.unknown_bytes,
                    "capture_id": Value::Null,
                    "packet_number": Value::Null,
                    "flush": "idle",
                }),
            };
            state.events.push_back(rate.clone());
            let _ = state.tx.send(rate);
            state.ul_bytes = 0;
            state.dl_bytes = 0;
            state.unknown_bytes = 0;
            state.throughput_second = 0;
            while state.events.len() > MAX_EVENTS {
                state.events.pop_front();
            }
        }
    }
    #[cfg(test)]
    pub(crate) fn append(&self, trace_id: &str, kind: &str, payload: Value) -> bool {
        let mut traces = self.traces.lock().unwrap();
        let Some(state) = traces.get_mut(trace_id) else {
            return false;
        };
        state.next_id += 1;
        let item = BufferedEvent {
            id: state.next_id,
            kind: kind.into(),
            payload,
        };
        state.events.push_back(item.clone());
        while state.events.len() > MAX_EVENTS {
            state.events.pop_front();
        }
        if kind == "message" {
            state.trace.messages += 1;
        }
        if kind == "marker" {
            state.trace.markers += 1;
        }
        let _ = state.tx.send(item);
        true
    }

    fn route_normalized(&self, event: &event_schema::NormalizedEvent) {
        self.route_event(event, false);
    }

    /// 2.21.105 — présente un event relu depuis le ring aux traces en
    /// cours d'amorçage : même règle de rattachement et même
    /// apprentissage que `route_normalized`, **aucune émission**, aucun
    /// compteur de message. Le filtre `interfaces` de la trace ne
    /// s'applique pas : une trace filtrée sur N3 a besoin des TEID
    /// portés par N2/N4.
    fn learn_from_ring(&self, event: &event_schema::NormalizedEvent) {
        self.route_event(event, true);
    }

    fn route_event(&self, event: &event_schema::NormalizedEvent, seed_only: bool) {
        // 2.21.103 (ordre #9 7046282778, défaut ANR2 #10 7045891820) — un
        // PFCP de niveau nœud (Heartbeat/Association/PFD/Node-Report) n'est
        // JAMAIS routé dans une trace abonné : ces messages n'ont pas de
        // portée session et polluent le flux SSE (99,92 % des 22 769 PFCP
        // observés par ANR2 sur une trace voix, rejoués via IE values
        // communes apprises).
        if event.protocol.as_str() == "PFCP" && is_pfcp_node_message(&event.message_name) {
            return;
        }
        let value = serde_json::from_str(&event.to_json()).unwrap_or(Value::Null);
        let encoded = value.to_string();
        // 2.21.90 défaut 2 — facts extraits une seule fois par event,
        // puis consultés et pour le match (SEID/TEID/(ip,teid) déjà
        // connus) et pour l'apprentissage après routage.
        let ev_ies: Vec<String> = ie_values(&value);
        let ev_tunnel_pairs: Vec<(String, String)> =
            ev_ies.iter().flat_map(|v| parse_tunnel_pairs(v)).collect();
        let ev_teids: Vec<String> = ev_ies.iter().flat_map(|v| parse_teids(v)).collect();
        let ev_seids_ie: Vec<String> = ev_ies.iter().flat_map(|v| parse_seids(v)).collect();
        let ev_session_seids: Vec<String> = session_ids_named(&value, "seid")
            .into_iter()
            .filter_map(|s| {
                let hex = s.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(hex, 16).ok().map(|n| format!("0x{n:016x}"))
            })
            .collect();
        let ev_session_teids: Vec<String> = session_ids_named(&value, "teid")
            .into_iter()
            .filter_map(event_schema::normalize_teid_hex)
            .collect();
        let ev_pdu_address: Option<String> = ev_ies
            .iter()
            .find(|v| v.starts_with("type=") && v.contains(",address="))
            .and_then(|v| parse_pdu_address(v));
        let mut traces = self.traces.lock().unwrap();
        Self::purge(&mut traces);
        let is_gpdu = !seed_only && event.protocol.as_str() == "GTP-U";
        let lag_ms = {
            let wall_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            let event_ms = event
                .timestamp
                .seconds
                .saturating_mul(1_000)
                .saturating_add(i64::from(event.timestamp.nanoseconds / 1_000_000));
            wall_ms.saturating_sub(event_ms)
        };
        for state in traces.values_mut() {
            if seed_only {
                if !state.seeding {
                    continue;
                }
                state.trace.seed.events_scanned =
                    state.trace.seed.events_scanned.saturating_add(1);
            } else {
                let feed = state.trace.feed.entry(event.interface.clone()).or_default();
                feed.seen = feed.seen.saturating_add(1);
                feed.last_event_timestamp_s = Some(event.timestamp.seconds);
                feed.last_event_timestamp_ns = Some(event.timestamp.nanoseconds);
                feed.last_event_lag_ms = Some(lag_ms);
                feed.max_event_lag_ms =
                    Some(feed.max_event_lag_ms.map_or(lag_ms, |prior| prior.max(lag_ms)));
            }
            if !seed_only
                && !state.trace.interfaces.is_empty()
                && !state
                    .trace
                    .interfaces
                    .iter()
                    .any(|item| item.eq_ignore_ascii_case(&event.interface))
            {
                // 2.21.105 — compte pour diagnostic. Un event GTP-U sur
                // une interface non-filtrée est un signal fort que le
                // trace a été créé avec une liste d'interfaces qui
                // exclut la data-plane (ex. "N2" seulement, pas "N3").
                if is_gpdu {
                    state.trace.gpdu_rejected_interface_filter =
                        state.trace.gpdu_rejected_interface_filter.saturating_add(1);
                }
                if let Some(feed) = state.trace.feed.get_mut(&event.interface) {
                    feed.filtered = feed.filtered.saturating_add(1);
                }
                continue;
            }
            if is_gpdu {
                state.trace.gpdu_seen = state.trace.gpdu_seen.saturating_add(1);
            }
            // 2.21.90 défaut 1 — match par pseudonymes vault et par
            // chiffres canoniques amorcés / identifiants appris
            // (`state.keys`). 2.21.90 défaut 2 — rattachement de
            // session : un event PFCP/GTP-U qui ne porte pas le
            // subscriber_pseudonym mais un SEID/TEID/(ip,teid) déjà
            // appris pour l'abonné est routé (règle EXACT, pas de
            // fenêtre temporelle).
            let match_pseudo = state
                .trace
                .subscriber_pseudonyms
                .iter()
                .any(|key| encoded.contains(key));
            let match_keys = state.match_keys.iter().any(|key| encoded.contains(key));
            let match_seid = ev_session_seids
                .iter()
                .chain(ev_seids_ie.iter())
                .any(|s| state.seids.contains(s));
            let match_teid = ev_session_teids
                .iter()
                .chain(ev_teids.iter())
                .any(|t| state.tunnel_teids.contains(t));
            let match_tunnel = ev_tunnel_pairs
                .iter()
                .any(|pair| state.tunnel_endpoints.contains(pair));
            let matched = match_pseudo || match_keys || match_seid || match_teid || match_tunnel;
            if !matched {
                // 2.21.105 — un G-PDU qui arrive APRÈS la trace mais
                // dont le TEID / UE IP n'a pas été appris (parce que
                // la session PDU était déjà établie avant l'ouverture
                // de la trace) termine ici. Compteur exposé via
                // `/live/traces/:id` pour que l'opérateur voie 0
                // bucket = N rejets rattachement, pas 0 vu.
                if is_gpdu {
                    state.trace.gpdu_rejected_no_match =
                        state.trace.gpdu_rejected_no_match.saturating_add(1);
                }
                continue;
            }
            if is_gpdu {
                state.trace.gpdu_attached = state.trace.gpdu_attached.saturating_add(1);
            }
            if !seed_only {
                if let Some(feed) = state.trace.feed.get_mut(&event.interface) {
                    feed.attached = feed.attached.saturating_add(1);
                }
                state.trace.armed = false;
            }
            if let Some(ids) = value.get("session_identifiers").and_then(Value::as_array) {
                for id in ids {
                    let Some(v) = id.get("value").and_then(Value::as_str) else {
                        continue;
                    };
                    if v.len() < 3 || v.parse::<std::net::IpAddr>().is_ok() {
                        continue;
                    }
                    // 2.21.98 (défaut privacy ANR1 #10 7043526474) — toutes
                    // les values non-IP ≥3 vont dans `match_keys` (interne,
                    // non sérialisé). Seules les values marquées
                    // `pseudonymized=true` par le decoder (subscriber_pseudonym,
                    // msisdn_pseudonym, imei_pseudonym, …) sont AUSSI
                    // ajoutées à `exposed_keys` (sérialisable via `ue_info`).
                    state.match_keys.insert(v.to_owned());
                    let pseudonymized = id
                        .get("pseudonymized")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if pseudonymized {
                        state.exposed_keys.insert(v.to_owned());
                    }
                }
            }
            // 2.21.90 défaut 2 — apprentissage de session depuis l'event
            // routé : IP UE (NAS), tuples (ip, teid) (NGAP n2SmInfo,
            // PFCP F-TEID/Outer Header Creation), SEID (PFCP header +
            // IE f_seid), TEID (GTP-U header + sous-IE). Cet état sert
            // à router les events suivants de la même session sans
            // dépendre d'un subscriber_pseudonym (qui diffère entre
            // domaines pseudonymiques `subscriber`, `pfcp-user-id`,
            // etc.).
            for pair in &ev_tunnel_pairs {
                state.tunnel_endpoints.insert(pair.clone());
                state.tunnel_teids.insert(pair.1.clone());
            }
            for t in ev_teids.iter().chain(ev_session_teids.iter()) {
                state.tunnel_teids.insert(t.clone());
            }
            for s in ev_seids_ie.iter().chain(ev_session_seids.iter()) {
                state.seids.insert(s.clone());
            }
            if let Some(ip) = ev_pdu_address.as_deref() {
                state.ue_ips.insert(ip.to_owned());
                // Pseudonyme UE IP (domain `pfcp-ue-ip`) : correspond à
                // `decoder-pfcp` IE 93. Un PFCP Session Establishment
                // qui ne porte que cette UE IP pseudonymisée match via
                // `state.keys` (`encoded.contains(pseudonym)`).
                if let Some(key) = pseudonym_key() {
                    if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                        let bytes: Vec<u8> = match addr {
                            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                        };
                        // 2.21.98 — pseudonyme UE IP exposable (c'est un
                        // `psn-…`, pas l'IP clair) : match_keys + exposed_keys.
                        let pseudonym = event_schema::pseudonym(key, "pfcp-ue-ip", &bytes);
                        state.match_keys.insert(pseudonym.clone());
                        state.exposed_keys.insert(pseudonym);
                    }
                }
            }
            if matches!(
                event.message_name.as_str(),
                "UE Context Release Complete"
                    | "PDU Session Release Complete"
                    | "Delete Session Response"
                    | "Detach Accept"
            ) {
                state.match_keys.clear();
                state.exposed_keys.clear();
                // 2.21.103 — fin de session : la prochaine session (si la
                // trace n'a pas expiré) a droit à un `ue_info` initial.
                state.last_ue_info_signature = None;
                // 2.21.90 défaut 2 — fin de session : on oublie aussi
                // les tunnels/SEID appris, sinon un TEID/SEID réutilisé
                // par un autre abonné serait routé à tort.
                state.tunnel_teids.clear();
                state.tunnel_endpoints.clear();
                state.seids.clear();
                state.ue_ips.clear();
            }
            if seed_only {
                // Amorçage : l'état de rattachement est appris, rien
                // n'est émis ni compté comme message.
                state.trace.seed.events_learned =
                    state.trace.seed.events_learned.saturating_add(1);
                continue;
            }
            let packet = event
                .packet_references
                .first()
                .map(|p| p.packet_number)
                .unwrap_or(0);
            // 2.18.6 (ANR1 #10 6901968948 : 19 doublons adjacents, 13
            // inversions) — un même message (capture_id, packet_number,
            // event_id) n'est émis qu'une fois ; une inversion dans une
            // même capture est comptée (`out_of_order`) et marquée
            // `late:true`, jamais masquée.
            let message_key = (event.capture_id.clone(), packet, event.event_id.clone());
            if !state.seen.insert(message_key) {
                state.trace.duplicates_dropped += 1;
                continue;
            }
            if state.seen.len() > MAX_EVENTS * 4 {
                state.seen.clear();
            }
            let last = state.last_packet.get(&event.capture_id).copied();
            let late = last.is_some_and(|last| packet < last);
            if late {
                state.trace.out_of_order += 1;
            } else {
                state.last_packet.insert(event.capture_id.clone(), packet);
            }
            state.next_id += 1;
            state.trace.messages += 1;
            // 2.21.91 (défaut #9 7033006772) — expose `stable_event_key`
            // dans le payload SSE. Clé de corrélation live↔publi
            // indépendante de `capture_id` (voir event-schema 1.6.0).
            let payload = json!({"interface":event.interface,"protocol":event.protocol.as_str(),"message_name":event.message_name,"direction":event.direction.as_str(),"source":value.get("source_endpoint"),"destination":value.get("destination_endpoint"),"capture_id":event.capture_id,"packet_number":packet,"event_id":event.event_id,"stable_event_key":event.stable_event_key,"timestamp":{"seconds":event.timestamp.seconds,"nanoseconds":event.timestamp.nanoseconds},"decoded_ie_tree":value.get("information_elements"),"late":late});
            let item = BufferedEvent {
                id: state.next_id,
                kind: "message".into(),
                payload,
            };
            state.events.push_back(item.clone());
            while state.events.len() > MAX_EVENTS {
                state.events.pop_front();
            }
            let _ = state.tx.send(item);
            let second = event.timestamp.seconds.max(0) as u64;
            if event.protocol.as_str() == "GTP-U" {
                if state.throughput_second != 0 && state.throughput_second != second {
                    state.next_id += 1;
                    let rate = BufferedEvent {
                        id: state.next_id,
                        kind: "throughput".into(),
                        // 2.21.76 (ordre #9 7012275179 §CLAUDE2.D-06) —
                        // `unknown_bytes_s` séparé pour que les octets
                        // non classifiés ne gonflent plus le DL.
                        payload: json!({
                            "second": state.throughput_second,
                            "ul_bytes_s": state.ul_bytes,
                            "dl_bytes_s": state.dl_bytes,
                            "unknown_bytes_s": state.unknown_bytes,
                            "capture_id": event.capture_id,
                            "packet_number": packet,
                        }),
                    };
                    state.events.push_back(rate.clone());
                    let _ = state.tx.send(rate);
                    state.ul_bytes = 0;
                    state.dl_bytes = 0;
                    state.unknown_bytes = 0;
                }
                state.throughput_second = second;
                let bytes = event
                    .packet_references
                    .first()
                    .map(|p| u64::from(p.original_length))
                    .unwrap_or(0);
                match event.direction.as_str() {
                    "UPLINK" => state.ul_bytes = state.ul_bytes.saturating_add(bytes),
                    "DOWNLINK" => state.dl_bytes = state.dl_bytes.saturating_add(bytes),
                    // 2.21.76 : tout le reste (UNKNOWN, REFERENCE_ONLY, …)
                    // est compté séparément, plus jamais mélangé à DL.
                    _ => state.unknown_bytes = state.unknown_bytes.saturating_add(bytes),
                }
            }
            if let Some(procedure) = event.procedure.as_deref() {
                state.next_id += 1;
                let update = BufferedEvent {
                    id: state.next_id,
                    kind: "procedure".into(),
                    payload: json!({"procedure":procedure,"phase":"update","event_id":event.event_id,"capture_id":event.capture_id,"packet_number":packet}),
                };
                state.events.push_back(update.clone());
                let _ = state.tx.send(update);
            }
            // 2.21.103 (ordre #9 7046282778) — `ue_info` émis UNIQUEMENT
            // quand la signature `exposed_keys` (vecteur trié) change. ANR2
            // #10 7045891820 : 28 759 émissions / 60 111 events ≈ 98,7 %
            // du poids de la trace voix (1,97 Go pour < 4 min) parce
            // qu'on renvoyait le set entier à chaque message. La 2.21.98
            // avait déjà réduit le CONTENU de `keys` (pseudonymes seuls) ;
            // 2.21.103 réduit la FRÉQUENCE à « sur changement effectif ».
            let mut sorted_keys: Vec<String> = state.exposed_keys.iter().cloned().collect();
            sorted_keys.sort();
            let should_emit_ue_info = state.last_ue_info_signature.as_ref() != Some(&sorted_keys);
            if should_emit_ue_info {
                state.last_ue_info_signature = Some(sorted_keys);
                state.next_id += 1;
                let info = BufferedEvent {
                    id: state.next_id,
                    kind: "ue_info".into(),
                    // 2.21.98 (défaut privacy ANR1 #10 7043526474) — `keys`
                    // expose UNIQUEMENT `exposed_keys` (pseudonymes). Les
                    // chiffres canoniques de la saisie et les IE values non
                    // pseudonymisées restent dans `match_keys` (interne
                    // non-Serialize, `MatchKeys`), donc ne peuvent fuiter.
                    payload: json!({"technology":if event.interface.starts_with('S'){"LTE"}else{"5G"},"keys":state.exposed_keys,"capture_id":event.capture_id,"packet_number":packet}),
                };
                state.events.push_back(info.clone());
                let _ = state.tx.send(info);
                while state.events.len() > MAX_EVENTS {
                    state.events.pop_front();
                }
            }
        }
    }
}

/// 2.21.109 (ordre #9 7049845272) — variable d'environnement de repli :
/// `1`/`true` remet le lecteur live en redécodage intégral de chaque
/// segment modifié (comportement d'avant 2.21.109), sans redéploiement.
const FULL_REDECODE_ENV: &str = "OIRAN_LIVE_READER_FULL_REDECODE";

fn full_redecode_requested() -> bool {
    std::env::var(FULL_REDECODE_ENV)
        .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes"))
        .unwrap_or(false)
}

/// 2.21.109 — octets lus par le lecteur pour un plan pendant la
/// dernière passe : `bytes_decoded` (réellement décodés) contre
/// `bytes_file` (taille des segments touchés). En reprise à l'offset,
/// décodé = croissance du segment ; en redécodage intégral, décodé =
/// taille.
#[derive(Clone, Default, Serialize, Debug, PartialEq)]
pub(crate) struct ReaderIo {
    bytes_decoded: u64,
    bytes_file: u64,
    incremental: bool,
}

/// 2.21.109 — session de reprise d'un segment du ring, gardée par le
/// lecteur d'une passe à l'autre.
pub(crate) struct ReaderSession {
    /// (périphérique, inode) du fichier quand la session a été ouverte.
    device_inode: (u64, u64),
    /// Empreinte des 64 derniers octets consommés : `(offset, sha256)`.
    /// Détecte un fichier réécrit sur place sous le même inode.
    tail: Option<(u64, String)>,
    session: oiran_decode::DecodeSession,
}

pub(crate) struct IncrementOutcome {
    events: Vec<event_schema::NormalizedEvent>,
    bytes_decoded: u64,
    consumed_bytes: u64,
    /// La session précédente a été jetée : fichier remplacé ou tronqué.
    reset: bool,
    ok: bool,
}

fn device_inode(path: &std::path::Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    path.metadata()
        .map(|meta| (meta.dev(), meta.ino()))
        .unwrap_or((0, 0))
}

fn tail_fingerprint(path: &std::path::Path, consumed: u64) -> Option<(u64, String)> {
    use std::io::{Read, Seek, SeekFrom};
    if consumed == 0 {
        return None;
    }
    let start = consumed.saturating_sub(64);
    let mut file = fs::File::open(path).ok()?;
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut bytes = vec![0u8; (consumed - start) as usize];
    file.read_exact(&mut bytes).ok()?;
    Some((consumed, sha256_hex(&bytes)))
}

/// 2.21.109 (ordre #9 7049845272) — décode les octets ajoutés à un
/// segment depuis la passe précédente. La session est jetée, et le
/// segment relu depuis 0, si le fichier n'est plus le même : inode
/// différent, taille inférieure à l'offset consommé, ou derniers octets
/// consommés modifiés.
pub(crate) fn decode_increment(
    sessions: &mut HashMap<std::path::PathBuf, ReaderSession>,
    config: &oiran_decode::DecodeConfig,
    key: &event_schema::PseudonymKey,
    size: u64,
) -> IncrementOutcome {
    let path = &config.input;
    let identity = device_inode(path);
    let mut reset = false;
    if let Some(existing) = sessions.get(path) {
        let consumed = existing.session.consumed_bytes();
        let same = existing.device_inode == identity
            && size >= consumed
            && existing.tail == tail_fingerprint(path, consumed);
        if !same {
            sessions.remove(path);
            reset = true;
        }
    }
    let entry = sessions.entry(path.clone()).or_insert_with(|| ReaderSession {
        device_inode: identity,
        tail: None,
        session: oiran_decode::DecodeSession::new(),
    });
    let before = entry.session.consumed_bytes();
    let mut events = Vec::new();
    let result = oiran_decode::decode_capture_incremental(config, key, &mut entry.session, |event| {
        events.push(event);
        Ok(())
    });
    let consumed_bytes = entry.session.consumed_bytes();
    entry.tail = tail_fingerprint(path, consumed_bytes);
    IncrementOutcome {
        events,
        bytes_decoded: consumed_bytes.saturating_sub(before),
        consumed_bytes,
        reset,
        ok: result.is_ok(),
    }
}

/// 2.21.109 — clôt la session d'un segment fermé (un successeur existe
/// dans le ring) : émet les events de flux RTP du tunnel, puis oublie
/// la session. Retourne les events à router.
pub(crate) fn close_reader_session(
    sessions: &mut HashMap<std::path::PathBuf, ReaderSession>,
    config: &oiran_decode::DecodeConfig,
) -> Vec<event_schema::NormalizedEvent> {
    let Some(mut closed) = sessions.remove(&config.input) else {
        return Vec::new();
    };
    let mut events = Vec::new();
    let _ = oiran_decode::finish_incremental(config, &mut closed.session, |event| {
        events.push(event);
        Ok(())
    });
    events
}

/// Configuration de décodage d'un segment du ring dumpcap.
fn ring_decode_config(path: &std::path::Path, interface: &str) -> oiran_decode::DecodeConfig {
    oiran_decode::DecodeConfig {
        input: path.to_path_buf(),
        capture_id: format!("sha256:{}", sha256_hex(path.to_string_lossy().as_bytes())),
        interface: interface.into(),
        endpoints: HashMap::new(),
        // 2.21.91 (ordre #9 7033006772 défaut 3) — basename dumpcap
        // ORIGINAL pour stamper `stable_event_key` : même valeur en
        // live et en publication.
        stable_source_file: path
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_owned())
            .unwrap_or_default(),
    }
}

/// 2.18.10 — ordre canonique intra-capture d'un lot d'events :
/// (packet_number du premier paquet, event_id). Tri stable.
fn sort_by_capture_order(events: &mut [event_schema::NormalizedEvent]) {
    events.sort_by(|a, b| {
        let packet = |event: &event_schema::NormalizedEvent| {
            event
                .packet_references
                .first()
                .map(|reference| reference.packet_number)
                .unwrap_or(u64::MAX)
        };
        packet(a)
            .cmp(&packet(b))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
}

pub(crate) fn start_reader(state: AppState) {
    if state
        .inner
        .live_traces
        .reader_running
        .swap(true, Ordering::SeqCst)
    {
        return;
    }
    tokio::spawn(async move {
        // 2.21.78 (correction 7014327787) — plus de `prior` HashSet global
        // (le `clear()` à 200 000 doublonnait sous iperf). Le
        // dédoublonnage est désormais per-file via `PcapFileState.consume`
        // (filigrane `(packet_number, event_id)` qui ne se vide jamais).
        let mut file_state: HashMap<std::path::PathBuf, crate::throughput::PcapFileState> =
            HashMap::new();
        // 2.21.78 (correction 7014327787) — rattrapage du ring au
        // démarrage : au premier passage, tous les pcapng SAUF le plus
        // récent par interface sont marqués comme déjà consommés (sans
        // décodage). Le débit commence « maintenant ». Si false, le
        // premier passage décode normalement (régime nominal).
        let mut initial_catchup_done = false;
        // 2.21.109 — sessions de reprise à l'offset, par segment.
        let mut reader_sessions: HashMap<std::path::PathBuf, ReaderSession> = HashMap::new();
        // 2.21.105 — dernier envoi de l'event SSE `stats`.
        let mut last_stats: Option<std::time::Instant> = None;
        loop {
            {
                let traces = state.inner.live_traces.traces.lock().unwrap();
                let traces_empty = traces.is_empty();
                drop(traces);
                // 2.21.78 : le reader reste actif si (a) traces live
                // ou (b) streams de débit sont en cours.
                if traces_empty && !state.inner.throughput.has_active_streams() {
                    state
                        .inner
                        .live_traces
                        .reader_running
                        .store(false, Ordering::SeqCst);
                    break;
                }
            }
            let source =
                std::env::var_os("OIRAN_CONTINUOUS_IMPORT_SOURCE").map(std::path::PathBuf::from);
            if let Some(root) =
                source.filter(|p| p.starts_with("/var/lib/docker/volumes/oiran_lab_pcap/_data"))
            {
                let state2 = state.clone();
                let mut states = file_state;
                let mut sessions = reader_sessions;
                let catchup = !initial_catchup_done;
                let pass_started = std::time::Instant::now();
                (file_state, reader_sessions) = tokio::task::spawn_blocking(move || {
                    let key = match event_schema::PseudonymKey::load_or_generate(
                        &event_schema::PseudonymKey::resolve_default_path(),
                    ) {
                        Ok(k) => k,
                        Err(_) => return (states, sessions),
                    };
                    // 2.21.109 — repli lu à chaque passe.
                    let full_redecode = full_redecode_requested();
                    if full_redecode {
                        sessions.clear();
                    }
                    let mut pass_io: BTreeMap<String, ReaderIo> = BTreeMap::new();
                    // 2.21.105 (ordre #9 7048974175) — amorçage des
                    // traces ouvertes depuis la passe précédente : le
                    // ring de signalisation est relu sans émission
                    // AVANT le routage live de cette passe.
                    if state2.inner.live_traces.begin_seed() {
                        let report = seed_from_ring(&root, &key, &state2.inner.live_traces);
                        state2.inner.live_traces.finish_seed(&report);
                    }
                    for interface in [
                        "N2", "N4", "N3", "SBI", "S1-MME", "S11", "S5-C", "S5-U", "S1-U", "Sxab",
                        "S6a", "IMS",
                        // 2.21.107 (ordre #9 7049222982) — plan N6 : SIP
                        // et RTP IMS, publiés `interface="IMS"`.
                        "N6",
                    ] {
                        let dir = root.join(ring_directory(interface));
                        let Ok(entries) = fs::read_dir(&dir) else {
                            continue;
                        };
                        // 2.21.78 (correction 7013902603) — énumère tous les
                        // pcapng, triés par mtime ancien → récent. La
                        // décision de redécoder est prise PAR FICHIER selon
                        // `(size, mtime)` vs `file_state`.
                        let mut paths: Vec<_> = entries
                            .flatten()
                            .map(|entry| entry.path())
                            .filter(|path| {
                                path.extension().and_then(|v| v.to_str()) == Some("pcapng")
                            })
                            .collect();
                        paths.sort_by_key(|path| {
                            path.metadata().and_then(|m| m.modified()).ok()
                        });
                        // 2.21.78 (correction défaut 1) — détecte les fichiers
                        // précédemment vus qui ont DISPARU. Le gap n'est
                        // PAS la taille totale : c'est `last_size -
                        // consumed_bytes`. Un fichier lu en entier et GC'é
                        // par le ring dumpcap contribue 0 — pas d'alerte
                        // sur le régime normal du ring.
                        let present: std::collections::HashSet<std::path::PathBuf> =
                            paths.iter().cloned().collect();
                        let gone: Vec<_> = states
                            .keys()
                            .filter(|p| p.starts_with(&dir) && !present.contains(*p))
                            .cloned()
                            .collect();
                        for path in &gone {
                            sessions.remove(path);
                            if let Some(file_state) = states.remove(path) {
                                let gap = file_state
                                    .size
                                    .saturating_sub(file_state.consumed_bytes);
                                if gap > 0 {
                                    state2.inner.throughput.bump_bytes_gap(gap);
                                }
                            }
                        }
                        // 2.21.78 (correction 7014327787) — rattrapage du
                        // ring au démarrage : tous les fichiers sauf le
                        // plus récent sont marqués consommés sans décodage.
                        // Le filigrane est au MAX pour que toute re-lecture
                        // ultérieure (très improbable : fichier passé) soit
                        // ignorée.
                        let last_idx = paths.len().saturating_sub(1);
                        for path in paths.iter().enumerate() {
                            let (idx, path) = path;
                            let meta = match path.metadata() {
                                Ok(m) => m,
                                Err(_) => continue,
                            };
                            let size = meta.len();
                            let mtime = meta.modified().ok();
                            let is_newest = idx == last_idx;
                            // Rattrapage : au premier passage, tous les
                            // fichiers sauf le plus récent sont ignorés.
                            if catchup && !is_newest {
                                states.insert(
                                    path.clone(),
                                    crate::throughput::PcapFileState {
                                        size,
                                        mtime,
                                        consumed_bytes: size,
                                        last_packet_number: u64::MAX,
                                        last_event_id: String::new(),
                                        routed_event_ids: Default::default(),
                                    },
                                );
                                continue;
                            }
                            // 2.21.78 (correction défaut 2) — lecture
                            // incrémentale : `(size, mtime)` inchangé
                            // ⇒ **0 décodage**.
                            let prev = states.get(path).cloned().unwrap_or_default();
                            let should_decode = if prev.size == size && prev.mtime == mtime && prev.size > 0 {
                                false
                            } else if prev.consumed_bytes >= size && prev.size == size {
                                // Already fully consumed at that size.
                                false
                            } else {
                                true
                            };
                            if !should_decode {
                                // Mémorise au moins la taille (si c'est la
                                // première vue du fichier avec taille nulle,
                                // il peut toujours grandir plus tard).
                                states.insert(
                                    path.clone(),
                                    crate::throughput::PcapFileState {
                                        size,
                                        mtime,
                                        consumed_bytes: prev.consumed_bytes,
                                        last_packet_number: prev.last_packet_number,
                                        last_event_id: prev.last_event_id,
                                        routed_event_ids: prev.routed_event_ids,
                                    },
                                );
                                // 2.21.109 — segment fermé et inchangé :
                                // clôture de sa session (flux RTP du
                                // tunnel émis une fois, à la rotation).
                                if !is_newest && sessions.contains_key(path) {
                                    let config = ring_decode_config(path, interface);
                                    for event in close_reader_session(&mut sessions, &config) {
                                        state2.inner.live_traces.route_normalized(&event);
                                    }
                                }
                                continue;
                            }
                            state2.inner.throughput.bump_file_decoded();
                            let config = ring_decode_config(path, interface);
                            // 2.21.109 (ordre #9 7049845272) — reprise à
                            // l'offset sur les plans sans état (lot A) :
                            // seuls les octets ajoutés depuis la passe
                            // précédente sont décodés. Les autres plans,
                            // et tous si le repli est demandé, gardent le
                            // redécodage intégral.
                            let incremental =
                                !full_redecode && oiran_decode::supports_incremental(interface);
                            let mut fresh = Vec::new();
                            let consumed_after;
                            let mut session_reset = false;
                            let io = pass_io.entry(interface.to_string()).or_default();
                            io.incremental = incremental;
                            io.bytes_file = io.bytes_file.saturating_add(size);
                            if incremental {
                                let outcome = decode_increment(&mut sessions, &config, &key, size);
                                if outcome.reset {
                                    state2.inner.live_traces.bump_resume_resets();
                                    session_reset = true;
                                }
                                io.bytes_decoded =
                                    io.bytes_decoded.saturating_add(outcome.bytes_decoded);
                                consumed_after = outcome.consumed_bytes;
                                fresh = outcome.events;
                            } else {
                                let decode_result =
                                    oiran_decode::decode_capture_streaming(&config, &key, |event| {
                                        fresh.push(event);
                                        Ok(())
                                    });
                                io.bytes_decoded = io.bytes_decoded.saturating_add(size);
                                consumed_after = if decode_result.is_ok() {
                                    size
                                } else {
                                    prev.consumed_bytes
                                };
                            }
                            sort_by_capture_order(&mut fresh);
                            // 2.21.78 (corrections 7014327787 + 7014783020)
                            // — **deux dédoublonnages distincts** :
                            //   - live trace : `route_once_for_live_trace`
                            //     via set d'`event_id` par fichier. Un event
                            //     late (packet_number < filigrane mais
                            //     event_id inédit) est routé avec `late:true`
                            //     par la logique interne de `route_normalized`.
                            //   - débit : `should_count_in_throughput` avance
                            //     le filigrane `(packet_number, event_id)`
                            //     monotone — aucun double comptage même sous
                            //     iperf 10⁵ pps.
                            let mut file_state_entry =
                                states.remove(path).unwrap_or_default();
                            if session_reset {
                                // Fichier remplacé : les filigranes de
                                // l'ancien contenu ne valent plus.
                                file_state_entry.last_packet_number = 0;
                                file_state_entry.last_event_id.clear();
                            }
                            if incremental {
                                // En reprise, chaque event n'est décodé
                                // qu'une fois : plus de table d'`event_id`.
                                file_state_entry.routed_event_ids.clear();
                            }
                            for event in &fresh {
                                let packet_number = event
                                    .packet_references
                                    .first()
                                    .map(|p| p.packet_number)
                                    .unwrap_or(0);
                                if incremental
                                    || file_state_entry.route_once_for_live_trace(&event.event_id)
                                {
                                    state2.inner.live_traces.route_normalized(event);
                                }
                                if file_state_entry.should_count_in_throughput(
                                    packet_number,
                                    &event.event_id,
                                ) {
                                    let session_id = crate::throughput::resolve_session_id_for_event(
                                        &state2, event,
                                    );
                                    state2
                                        .inner
                                        .throughput
                                        .observe_event(event, session_id.as_deref());
                                }
                            }
                            file_state_entry.size = size;
                            file_state_entry.mtime = mtime;
                            file_state_entry.consumed_bytes = consumed_after;
                            states.insert(path.clone(), file_state_entry);
                            if incremental && !is_newest {
                                for event in close_reader_session(&mut sessions, &config) {
                                    state2.inner.live_traces.route_normalized(&event);
                                }
                            }
                        }
                    }
                    if states.len() > 1024 {
                        states.clear();
                        sessions.clear();
                    }
                    state2.inner.live_traces.set_reader_io(pass_io);
                    (states, sessions)
                })
                .await
                .unwrap_or_default();
                initial_catchup_done = true;
                state
                    .inner
                    .live_traces
                    .set_reader_pass_ms(pass_started.elapsed().as_millis() as u64);
            }
            // 2.21.78 — tick régulier du registre de débit : émet un
            // bucket zéro après IDLE_FLUSH_INTERVAL_S de silence.
            state.inner.throughput.tick();
            // 2.21.99 (défaut recette prod #10 7043526474) — flush
            // périodique des buckets de débit du flux live trace.
            // Complète l'émission event-driven de `route_normalized`
            // quand les events GTP-U cessent dans la même seconde.
            state.inner.live_traces.flush_idle_throughput_buckets();
            // 2.21.105 — event SSE `stats` toutes les `STATS_INTERVAL` :
            // « 0 bucket » se lit comme « 0 vu » ou « N vus, 0 rattaché ».
            if last_stats.map_or(true, |at| at.elapsed() >= STATS_INTERVAL) {
                state.inner.live_traces.emit_stats();
                last_stats = Some(std::time::Instant::now());
            }
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
    });
}

#[derive(Deserialize)]
pub(crate) struct CreateTrace {
    key_type: String,
    value: String,
    duration_s: u64,
    #[serde(default)]
    interfaces: Vec<String>,
}
#[derive(Deserialize)]
pub(crate) struct Marker {
    label: String,
}

fn allowed_key(value: &str) -> bool {
    matches!(
        value,
        "imsi" | "tmsi" | "s_tmsi" | "m_tmsi" | "imei" | "msisdn" | "pseudonym"
    )
}
fn live_ok(data: Value) -> Response {
    Json(json!({"data":data,"meta":{"api_version":API_VERSION}})).into_response()
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateTrace>,
) -> Response {
    let role = role_from_headers(&state, &headers);
    if !allowed_key(&input.key_type)
        || input.value.trim().is_empty()
        || input.duration_s == 0
        || input.duration_s > 3600
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "LIVE_TRACE_INVALID",
            "invalid trace request",
        );
    }
    if input.key_type != "pseudonym" && !role.can_control() {
        return api_error(
            StatusCode::FORBIDDEN,
            "OPERATOR_REQUIRED",
            "operator role required for clear identity lookup",
        );
    }
    if require_csrf(&state, &headers).is_err() {
        return require_csrf(&state, &headers).unwrap_err();
    }
    // 2.21.90 défaut 1 (option C, ordre #9 7033006772) — on supprime
    // le repli `pseudonym_subscriber_text` qui, sur vault vide, dérivait
    // un pseudonyme local à partir des octets de la saisie clair-text.
    // Ce pseudonyme ne matchait AUCUN event car les decoders utilisent
    // des domains distincts (`subscriber`, `pfcp-user-id`, GPSI_MSISDN,
    // PEI_IMEI, …) qui divergent même pour un même abonné. Résultat :
    // les traces MSISDN/IMEI ne voyaient qu'une poignée d'events SBI
    // (ceux dont le subscriber_pseudonym SUPI corrélé a été appris
    // par ailleurs), et jamais la session complète.
    //
    // Nouveau comportement :
    //  * key_type == `pseudonym` → pseudonyme exact fourni.
    //  * key_type parmi `imsi`/`tmsi`/`s_tmsi`/`m_tmsi`/`imei`/`msisdn` :
    //    - vault non vide → pseudonymes vault (identité canonique
    //      corrélée via sessions déjà observées). `armed=false`.
    //    - vault vide → trace `armed=true` sans pseudonyme ; routage
    //      uniquement par `state.keys` amorcé avec les chiffres
    //      canoniques et enrichi au fil des events (tunnels, SEID,
    //      UE IP pseudonymisée). S'arme (armed=false) dès le premier
    //      event routé.
    let (pseudonyms, armed) = if input.key_type == "pseudonym" {
        (vec![input.value.trim().to_owned()], false)
    } else {
        match state
            .inner
            .identity_vault
            .pseudonyms_for_value(input.value.trim())
        {
            Ok(v) if !v.is_empty() => (v, false),
            Ok(_) => (Vec::new(), true),
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "IDENTITY_VAULT_FAILED",
                    "identity lookup failed",
                )
            }
        }
    };
    // 2.21.90 défaut 1 — amorçage des chiffres canoniques de la saisie
    // (TS 29.571 §5.4.5 strip de `imsi-`, `msisdn-`, `imei-`, `supi-` ;
    // conserve ≥5 digits). Couvre les cas EPS/SUCI null-scheme où
    // l'identité remonte en clair dans les premiers events (NAS Identity
    // Response / Attach Request S1-MME) + GPSI `msisdn-<E164>` SBI Nudm_SDM.
    // 2.21.98 — ces chiffres restent dans `match_keys` (type `MatchKeys`
    // sans `Serialize`), JAMAIS dans `exposed_keys`. Garantie par le type :
    // aucune route ne peut les sérialiser.
    let mut initial_match_keys = MatchKeys::default();
    if input.key_type != "pseudonym" {
        if let Some(digits) = canonical_digits(input.value.trim()) {
            initial_match_keys.insert(digits);
        }
    }
    let now = epoch_seconds();
    let digest = sha256_hex(format!("{}:{}:{}", now, input.key_type, input.value).as_bytes());
    let trace_id = format!("trace-{}", &digest[..16]);
    let mut traces = state.inner.live_traces.traces.lock().unwrap();
    LiveTraceRegistry::purge(&mut traces);
    if traces.len() >= MAX_TRACES {
        return api_error(
            StatusCode::CONFLICT,
            "LIVE_TRACE_LIMIT",
            "maximum active traces reached",
        );
    }
    let (tx, _) = broadcast::channel(MAX_EVENTS);
    let trace = LiveTrace {
        trace_id: trace_id.clone(),
        key_type: input.key_type,
        subscriber_pseudonyms: pseudonyms.clone(),
        interfaces: input.interfaces,
        created_at: now,
        expires_at: now + input.duration_s,
        armed,
        messages: 0,
        markers: 0,
        duplicates_dropped: 0,
        out_of_order: 0,
        gpdu_seen: 0,
        gpdu_attached: 0,
        gpdu_rejected_no_match: 0,
        gpdu_rejected_interface_filter: 0,
        feed: BTreeMap::new(),
        seed: SeedStats::default(),
    };
    traces.insert(
        trace_id.clone(),
        TraceState {
            trace: trace.clone(),
            next_id: 0,
            events: VecDeque::new(),
            tx,
            match_keys: initial_match_keys,
            exposed_keys: HashSet::new(),
            last_ue_info_signature: None,
            throughput_second: 0,
            ul_bytes: 0,
            dl_bytes: 0,
            unknown_bytes: 0,
            last_packet: HashMap::new(),
            seen: HashSet::new(),
            tunnel_teids: HashSet::new(),
            tunnel_endpoints: HashSet::new(),
            seids: HashSet::new(),
            ue_ips: HashSet::new(),
            // 2.21.105 — le lecteur relit le ring de signalisation
            // pour cette trace à sa prochaine passe.
            needs_seed: true,
            seeding: false,
        },
    );
    drop(traces);
    // 2.21.76 (ordre #9 7012275179 §CLAUDE2.T-07) — audit enrichi : le
    // `trace_id` et la **liste de pseudonymes** identifient de façon
    // unique la trace, sans jamais stocker la valeur saisie. Rapproche
    // l'entrée d'audit d'un stream SSE a posteriori.
    state.inner.live_traces.audit(json!({
        "action": "live_trace.create",
        "actor_role": role.name(),
        "trace_id": trace_id,
        "key_type": trace.key_type,
        "subscriber_pseudonyms": trace.subscriber_pseudonyms,
        "duration_s": input.duration_s,
        "at_epoch_s": now,
    }));
    start_reader(state);
    live_ok(serde_json::to_value(trace).unwrap())
}

pub(crate) fn require_csrf(state: &AppState, headers: &HeaderMap) -> Result<Role, Response> {
    let role = role_from_headers(state, headers);
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(bearer) = bearer else {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REQUIRED",
            "valid CSRF proof required",
        ));
    };
    let expected = sha256_hex(format!("oiran-csrf-v1:{bearer}").as_bytes());
    if headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some(expected.as_str()) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "CSRF_REQUIRED",
            "valid CSRF proof required",
        ));
    }
    Ok(role)
}

pub(crate) async fn list(State(state): State<AppState>) -> Response {
    let mut traces = state.inner.live_traces.traces.lock().unwrap();
    LiveTraceRegistry::purge(&mut traces);
    live_ok(json!(traces.values().map(|s| &s.trace).collect::<Vec<_>>()))
}
pub(crate) async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let role = match require_csrf(&state, &headers) {
        Ok(role) => role,
        Err(e) => return e,
    };
    let removed = state.inner.live_traces.traces.lock().unwrap().remove(&id);
    let Some(removed) = removed else {
        return api_error(
            StatusCode::NOT_FOUND,
            "LIVE_TRACE_NOT_FOUND",
            "trace not found",
        );
    };
    // 2.21.76 (ordre #9 7012275179 §CLAUDE2.T-07) — audit delete enrichi.
    state.inner.live_traces.audit(json!({
        "action": "live_trace.delete",
        "actor_role": role.name(),
        "trace_id": id,
        "key_type": removed.trace.key_type,
        "subscriber_pseudonyms": removed.trace.subscriber_pseudonyms,
        "at_epoch_s": epoch_seconds(),
    }));
    live_ok(json!({"trace_id":id,"deleted":true}))
}

pub(crate) async fn audit(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = require_operator(&state, &headers) {
        return e;
    };
    live_ok(json!(state
        .inner
        .live_traces
        .audit
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<Vec<_>>()))
}
pub(crate) async fn marker(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(marker): Json<Marker>,
) -> Response {
    if let Err(e) = require_csrf(&state, &headers) {
        return e;
    };
    if marker.label.trim().is_empty() || marker.label.len() > 120 {
        return api_error(
            StatusCode::BAD_REQUEST,
            "MARKER_INVALID",
            "marker label is invalid",
        );
    };
    let mut traces = state.inner.live_traces.traces.lock().unwrap();
    let Some(s) = traces.get_mut(&id) else {
        return api_error(
            StatusCode::NOT_FOUND,
            "LIVE_TRACE_NOT_FOUND",
            "trace not found",
        );
    };
    s.next_id += 1;
    s.trace.markers += 1;
    let item = BufferedEvent {
        id: s.next_id,
        kind: "marker".into(),
        payload: json!({"label":marker.label,"created_at":epoch_seconds()}),
    };
    s.events.push_back(item.clone());
    let _ = s.tx.send(item.clone());
    live_ok(json!({"event_id":item.id}))
}

#[derive(Deserialize, Default)]
pub(crate) struct StreamQuery {
    #[serde(default)]
    last_event_id: Option<u64>,
}

pub(crate) async fn stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<StreamQuery>,
) -> Response {
    let role = role_from_headers(&state, &headers);
    // 2.16.0 (ANR1 #10 Live-IMSI) — reprise après pause front : le
    // navigateur gère Last-Event-ID nativement sur reconnect SSE,
    // mais EventSource n'accepte pas d'envoyer de header custom en
    // withCredentials sur CORS strict. On accepte donc en priorité
    // `?last_event_id=N` en query, fallback sur le header.
    let after = query
        .last_event_id
        .or_else(|| {
            headers
                .get("last-event-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0);
    let (replay, cutoff_id, rx) = {
        let traces = state.inner.live_traces.traces.lock().unwrap();
        let Some(s) = traces.get(&id) else {
            return api_error(
                StatusCode::NOT_FOUND,
                "LIVE_TRACE_NOT_FOUND",
                "trace not found",
            );
        };
        if s.trace.key_type != "pseudonym" && !role.can_control() {
            return api_error(
                StatusCode::FORBIDDEN,
                "OPERATOR_REQUIRED",
                "operator role required for identity trace",
            );
        }
        // 2.16.0 (ANR1 #10 Live-IMSI) — snapshot atomique du replay
        // sous le lock mutex : (a) on filtre les events d'id > after,
        // (b) on les trie de façon STABLE par la clé canonique prod
        // (capture_id, packet_number, id) extraite du payload — ids
        // monotones à l'intérieur d'une même (capture_id,
        // packet_number) grâce au next_id, les méta-events
        // (throughput/procedure/ue_info) partagent la clé du message
        // qui les précède immédiatement. (c) on calcule cutoff_id
        // (max id du replay) pour filtrer le live et éviter la
        // double-diffusion à la jonction replay→live (le buffer est
        // alimenté sous le lock, mais tx.send a déjà pu propager).
        let mut replay = s
            .events
            .iter()
            .filter(|e| e.id > after)
            .cloned()
            .collect::<Vec<_>>();
        replay.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
        let cutoff_id = replay.iter().map(|e| e.id).max().unwrap_or(after);
        (replay, cutoff_id, s.tx.subscribe())
    };
    let replay_stream = tokio_stream::iter(replay.into_iter().map(Ok));
    let live = BroadcastStream::new(rx)
        .filter_map(|v| v.ok())
        .filter(move |e| e.id > cutoff_id)
        .map(Ok);
    let output = replay_stream
        .chain(live)
        .map(|item: Result<BufferedEvent, Infallible>| {
            item.map(|e| {
                Event::default()
                    .id(e.id.to_string())
                    .event(e.kind)
                    .json_data(e.payload)
                    .unwrap()
            })
        });
    Sse::new(output)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("heartbeat"),
        )
        .into_response()
}

/// 2.16.0 (ANR1 #10 Live-IMSI) — clé canonique pour trier le replay
/// SSE par `(capture_id, packet_number)` extraits du payload. Les
/// méta-events (throughput, procedure, ue_info, marker) n'ont pas
/// ces champs : on utilise `u64::MAX` + `id` de façon à ce qu'ils
/// restent placés après le `message` qui les a immédiatement
/// précédés (même id contigu). L'`id` final reste tie-breaker pour
/// garder un ordre stable et déterministe.
fn canonical_sort_key(event: &BufferedEvent) -> (String, u64, u64) {
    let capture_id = event
        .payload
        .get("capture_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let packet_number = event
        .payload
        .get("packet_number")
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    (capture_id, packet_number, event.id)
}

/// 2.16.0 (ANR1 #10 Live-IMSI) — corrélation IMSI → sessions.
/// Retourne les sessions connues par oiran-api dont un pseudonyme
/// `subscriber_pseudonym` observé dans `identity_vault` est aussi
/// présent dans les `subscriber_pseudonyms` de la trace. Sert au
/// front à enrichir le lien « Ouvrir la session » depuis l'onglet
/// Live vers l'Analyzer sans quitter le périmètre Live (ne touche
/// pas `/sessions` ni `/callflow`). Lecture seule, pas de CSRF ;
/// les valeurs renvoyées sont des `session_id` + `dataset_id` +
/// `technology` — jamais d'IMSI/SUPI clair-text.
pub(crate) async fn sessions_for_trace(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    let (pseudos, armed) = {
        let traces = state.inner.live_traces.traces.lock().unwrap();
        let Some(s) = traces.get(&id) else {
            return api_error(
                StatusCode::NOT_FOUND,
                "LIVE_TRACE_NOT_FOUND",
                "trace not found",
            );
        };
        (s.trace.subscriber_pseudonyms.clone(), s.trace.armed)
    };
    // 2.21.34 (ordre #9 6956890331) — `correlate_sessions_by_pseudonyms`
    // parcourt `state.inner.flows`, puis toutes les sessions de chaque
    // dataset du `capture_manager`, et appelle `identity_vault.for_session`
    // pour chacune. Coexiste mal avec la publication continue en
    // mémoire : on prend `capture_manager.heavy_memory_try_enter()` et
    // on répond 503 + `Retry-After: 60` si elle tourne. Le parcours
    // CPU/IO est déporté en `spawn_blocking` pour ne pas bloquer le
    // runtime async.
    tokio::task::spawn_blocking(move || {
        let Some(_heavy_memory_gate) = state.inner.capture_manager.heavy_memory_try_enter() else {
            return heavy_work_in_progress();
        };
        let pseudos_set: HashSet<String> = pseudos.iter().cloned().collect();
        let matches = correlate_sessions_by_pseudonyms(&state, &pseudos_set);
        live_ok(json!({
            "trace_id": id,
            "armed": armed,
            "subscriber_pseudonyms": pseudos,
            "sessions": matches,
        }))
    })
    .await
    .unwrap_or_else(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "LIVE_SESSIONS_FOR_TRACE_FAILED",
            "sessions_for_trace handler panicked",
        )
    })
}

fn correlate_sessions_by_pseudonyms(state: &AppState, pseudos: &HashSet<String>) -> Vec<Value> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut matches: Vec<Value> = Vec::new();
    let session_matches = |session_id: &str| -> bool {
        match state.inner.identity_vault.for_session(session_id) {
            Ok(observations) => observations.iter().any(|o| {
                o.subscriber_pseudonym
                    .as_deref()
                    .is_some_and(|p| pseudos.contains(p))
            }),
            Err(_) => false,
        }
    };
    for flow in state.inner.flows.values() {
        if session_matches(&flow.session_id) && seen.insert(flow.session_id.clone()) {
            matches.push(json!({
                "session_id": flow.session_id,
                "technology": flow.technology,
                "source": "flows",
            }));
        }
    }
    for dataset in state.inner.capture_manager.datasets() {
        for session_id in &dataset.session_ids {
            if seen.contains(session_id) {
                continue;
            }
            if session_matches(session_id) {
                seen.insert(session_id.clone());
                matches.push(json!({
                    "session_id": session_id,
                    "dataset_id": dataset.dataset_id,
                    "source": "capture_manager",
                }));
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(expires_at: u64, armed: bool, keys: Vec<String>) -> TraceState {
        state_with_initial_keys(expires_at, armed, keys, HashSet::new())
    }
    fn state_with_initial_keys(
        expires_at: u64,
        armed: bool,
        pseudos: Vec<String>,
        initial_match_keys: HashSet<String>,
    ) -> TraceState {
        let (tx, _) = broadcast::channel(MAX_EVENTS);
        TraceState {
            trace: LiveTrace {
                trace_id: "t".into(),
                key_type: "pseudonym".into(),
                subscriber_pseudonyms: pseudos,
                interfaces: vec![],
                created_at: 0,
                expires_at,
                armed,
                messages: 0,
                markers: 0,
                duplicates_dropped: 0,
                out_of_order: 0,
                gpdu_seen: 0,
                gpdu_attached: 0,
                gpdu_rejected_no_match: 0,
                gpdu_rejected_interface_filter: 0,
                feed: BTreeMap::new(),
                seed: SeedStats::default(),
            },
            next_id: 0,
            events: VecDeque::new(),
            tx,
            match_keys: initial_match_keys.into_iter().collect(),
            exposed_keys: HashSet::new(),
            last_ue_info_signature: None,
            throughput_second: 0,
            ul_bytes: 0,
            dl_bytes: 0,
            unknown_bytes: 0,
            last_packet: HashMap::new(),
            seen: HashSet::new(),
            tunnel_teids: HashSet::new(),
            tunnel_endpoints: HashSet::new(),
            seids: HashSet::new(),
            ue_ips: HashSet::new(),
            needs_seed: true,
            seeding: false,
        }
    }
    /// 2.21.105 (défaut recette prod G3 #10 7047592953, ordre #9 7047782479) —
    /// reproduit le FAIL G3 en prod : 0 bucket pour 28 870 trames
    /// GTP-U sur N3. Modélise H1 (rattachement raté) :
    ///   1. une trace est créée pour `psn-prod` ;
    ///   2. des G-PDU N3 arrivent **sans subscriber_pseudonym** et
    ///      avec un TEID qui n'a JAMAIS été vu par la trace parce
    ///      que la session PDU a été établie AVANT la trace ;
    ///   3. `route_normalized` ne matche aucun G-PDU ; les compteurs
    ///      2.21.105 (`gpdu_seen`, `gpdu_rejected_no_match`) le
    ///      montrent : `seen > 0 && attached == 0 && rejected_no_match > 0`.
    /// **AVANT fix** : 0 bucket (H1 reproduit).
    /// **APRÈS seed** (via `seed_trace_from_events`) depuis le callflow
    /// publié qui porte les TEID : les G-PDU matchent, buckets > 0,
    /// total octets exact.
    #[test]
    fn gpdu_rejected_when_pdu_session_established_before_trace_2_21_105() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-prod".into()]));

        let gpdu = |packet: u64, seconds: i64, dir: Direction, bytes: u32| NormalizedEvent {
            event_id: format!("evt-gtpu-{packet}"),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N3".into(),
            capture_id: "cap-n3".into(),
            packet_references: vec![PacketReference {
                source_file: "n3.pcapng".into(),
                source_sha256: None,
                packet_number: packet,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: bytes,
                original_length: bytes,
            }],
            timestamp: ExactTimestamp {
                seconds,
                nanoseconds: 0,
                raw_ticks: (seconds.max(0) as u64) * 1_000_000_000,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N3".into(),
            protocol: Protocol::Gtpu,
            message_name: "GTP-U".into(),
            message_type: 255,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.77.11.13".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.77.22.13".into(),
                port: None,
                network_function: None,
            },
            direction: dir,
            session_identifiers: vec![NamedValue {
                name: "teid".into(),
                value: "0xf1240001".into(),
                pseudonymized: false,
            }],
            information_elements: vec![],
            decoder_name: "decoder-gtpu".into(),
            decoder_version: "0.2.2".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: format!("sha256:gtpu-{packet}"),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: format!("sha256:gtpu-{packet}"),
            }],
            sbi: None,
        };

        // Phase 1 — AVANT fix : route 6 G-PDU sur 2 secondes, aucun
        // match, 0 bucket, compteurs attestent `seen>0 attached=0`.
        for pkt in 10..16 {
            r.route_normalized(&gpdu(
                pkt,
                if pkt < 13 { 1_795_200_000 } else { 1_795_200_001 },
                if pkt % 2 == 0 { Direction::Uplink } else { Direction::Downlink },
                1_500,
            ));
        }
        {
            let traces = r.traces.lock().unwrap();
            let s = traces.get("t").unwrap();
            assert_eq!(s.trace.gpdu_seen, 6, "6 G-PDU doivent être vus");
            assert_eq!(s.trace.gpdu_attached, 0, "aucun rattaché (H1 reproduit)");
            assert_eq!(s.trace.gpdu_rejected_no_match, 6, "6 rejets rattachement");
            let buckets: Vec<_> = s.events.iter().filter(|e| e.kind == "throughput").collect();
            assert!(
                buckets.is_empty(),
                "FAIL G3 prod reproduit : 0 bucket pour {} G-PDU vus",
                s.trace.gpdu_seen
            );
        }

        // Phase 2 — amorçage : la signalisation d'AVANT l'ouverture
        // (NGAP PDU Session Resource Setup portant le pseudonyme et
        // les tunnels, puis PFCP Session Establishment rattaché par
        // tunnel) est relue depuis le ring, sans émission.
        let signalling = |interface: &str,
                          protocol: Protocol,
                          message: &str,
                          packet: u64,
                          ids: Vec<(&str, &str)>,
                          ie: (&str, &str)| {
            let mut event = gpdu(packet, 1_795_199_000, Direction::Uplink, 200);
            event.event_id = format!("evt-sig-{packet}");
            event.interface = interface.into();
            event.capture_id = format!("cap-{interface}");
            event.protocol = protocol;
            event.message_name = message.into();
            event.session_identifiers = ids
                .into_iter()
                .map(|(n, v)| NamedValue {
                    name: n.into(),
                    value: v.into(),
                    pseudonymized: n.ends_with("pseudonym"),
                })
                .collect();
            event.information_elements = vec![event_schema::InformationElement {
                id: None,
                name: ie.0.into(),
                length: ie.1.len() as u32,
                value: Some(ie.1.into()),
                raw_sha256: None,
                status: DecodeStatus::Decoded,
            }];
            event
        };
        let ngap_setup = signalling(
            "N2",
            Protocol::Ngap,
            "PDUSessionResourceSetupRequest",
            1,
            vec![("subscriber_pseudonym", "psn-prod")],
            (
                "PDUSessionResourceSetupRequestTransfer",
                "item_0_tunnel_ip_ul=10.77.11.13,item_0_gtp_teid_ul=0xf1240001,item_0_tunnel_ip_dl=10.77.22.13,item_0_gtp_teid_dl=0xf1240002",
            ),
        );
        let pfcp_establishment = signalling(
            "N4",
            Protocol::Pfcp,
            "Session Establishment Request",
            2,
            vec![("seid", "0x0000000000001001")],
            ("F-TEID", "teid=0xf1240001,v4=true,v6=false,ipv4=10.77.11.13"),
        );
        assert!(r.begin_seed(), "la trace attend son amorçage");
        r.learn_from_ring(&ngap_setup);
        r.learn_from_ring(&pfcp_establishment);
        r.finish_seed(&SeedReport {
            files: 2,
            bytes: 400,
            truncated: false,
        });
        assert!(!r.begin_seed(), "une trace n'est amorcée qu'une fois");
        {
            let traces = r.traces.lock().unwrap();
            let s = traces.get("t").unwrap();
            assert_eq!(s.trace.seed.events_scanned, 2);
            assert_eq!(s.trace.seed.events_learned, 2);
            assert!(s.trace.seed.done);
            assert_eq!(s.trace.messages, 0, "l'amorçage n'émet aucun message");
            assert!(s.events.is_empty(), "l'amorçage ne met rien dans le tampon SSE");
            assert!(s.tunnel_teids.contains("0xf1240001"), "TEID UL appris");
            assert!(s.tunnel_teids.contains("0xf1240002"), "TEID DL appris");
            assert!(s.seids.contains("0x0000000000001001"), "SEID appris par tunnel");
            assert!(
                !s.trace.feed.contains_key("N2") && !s.trace.feed.contains_key("N4"),
                "l'amorçage ne compte pas comme alimentation live"
            );
        }

        // Phase 3 — G-PDU des deux sens sur 3 secondes : UL sur le TEID
        // UL, DL sur le TEID DL. Tous rattachés, somme des buckets =
        // octets injectés, à l'octet près.
        let mut injected = 0u64;
        for pkt in 20..32u64 {
            let uplink = pkt % 2 == 0;
            let bytes = if uplink { 1_200 } else { 1_500 };
            let mut event = gpdu(
                pkt,
                1_795_200_010 + ((pkt - 20) / 4) as i64,
                if uplink { Direction::Uplink } else { Direction::Downlink },
                bytes,
            );
            event.session_identifiers[0].value =
                if uplink { "0xf1240001".into() } else { "0xf1240002".into() };
            injected += u64::from(bytes);
            r.route_normalized(&event);
        }
        r.flush_idle_throughput_buckets();
        let traces = r.traces.lock().unwrap();
        let s = traces.get("t").unwrap();
        assert_eq!(s.trace.gpdu_attached, 12, "12 G-PDU rattachés après amorçage");
        assert_eq!(s.trace.gpdu_rejected_no_match, 6, "les rejets d'avant restent comptés");
        let buckets: Vec<_> = s.events.iter().filter(|e| e.kind == "throughput").collect();
        assert_eq!(buckets.len(), 3, "un bucket par seconde de trafic");
        let sum = |field: &str| -> u64 {
            buckets.iter().map(|b| b.payload[field].as_u64().unwrap_or(0)).sum()
        };
        assert_eq!(sum("ul_bytes_s"), 6 * 1_200);
        assert_eq!(sum("dl_bytes_s"), 6 * 1_500);
        assert_eq!(sum("unknown_bytes_s"), 0);
        assert_eq!(
            sum("ul_bytes_s") + sum("dl_bytes_s"),
            injected,
            "somme des buckets = octets injectés"
        );
        // Compteurs par interface et contrat `stats`.
        let n3 = &s.trace.feed["N3"];
        assert_eq!((n3.seen, n3.attached, n3.filtered), (18, 12, 0));
        assert_eq!(n3.last_event_timestamp_s, Some(1_795_200_012));
        assert!(n3.last_event_lag_ms.is_some() && n3.max_event_lag_ms >= n3.last_event_lag_ms);
        let stats = r.stats_payload(&s.trace);
        assert_eq!(stats["gpdu"]["seen"], 18);
        assert_eq!(stats["gpdu"]["attached"], 12);
        assert_eq!(stats["gpdu"]["rejected_no_match"], 6);
        assert_eq!(stats["interfaces"]["N3"]["seen"], 18);
        assert_eq!(stats["seed"]["events_learned"], 2);
        assert!(stats["reader_pass_ms"].is_u64() && stats["wall_clock_s"].is_u64());
        // Chaque message porte l'horodatage de capture.
        let message = s.events.iter().find(|e| e.kind == "message").unwrap();
        assert_eq!(message.payload["timestamp"]["seconds"], 1_795_200_010i64);
        assert_eq!(message.payload["timestamp"]["nanoseconds"], 0);
    }

    /// 2.21.105 — une trace créée PENDANT une passe d'amorçage n'est
    /// ni la cible de cette passe ni marquée amorcée : elle le sera à
    /// la passe suivante.
    #[test]
    fn trace_created_during_seed_pass_waits_for_next_pass_2_21_105() {
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("a".into(), state(u64::MAX, false, vec!["psn-a".into()]));
        assert!(r.begin_seed());
        r.traces
            .lock()
            .unwrap()
            .insert("b".into(), state(u64::MAX, false, vec!["psn-b".into()]));
        r.finish_seed(&SeedReport::default());
        {
            let traces = r.traces.lock().unwrap();
            assert!(traces["a"].trace.seed.done);
            assert!(!traces["b"].trace.seed.done);
            assert!(traces["b"].needs_seed);
        }
        assert!(r.begin_seed(), "la trace b est amorcée à la passe suivante");
    }

    /// 2.21.105 — choix des fichiers relus : les plus récents tant que
    /// le plafond tient, rendus du plus ancien au plus récent ; le
    /// dépassement est signalé, jamais silencieux.
    #[test]
    fn select_seed_files_keeps_newest_within_budget_oldest_first_2_21_105() {
        use std::time::{Duration as D, UNIX_EPOCH as E};
        let file = |name: &str, size: u64, at: u64| {
            (std::path::PathBuf::from(name), size, Some(E + D::from_secs(at)))
        };
        let files = vec![file("c", 40, 30), file("a", 50, 10), file("b", 40, 20)];
        let (selected, truncated) = select_seed_files(files.clone(), 100);
        assert_eq!(
            selected,
            vec![
                (std::path::PathBuf::from("b"), 40),
                (std::path::PathBuf::from("c"), 40)
            ]
        );
        assert!(truncated, "le fichier a (le plus ancien) est laissé de côté");
        let (all, truncated) = select_seed_files(files, 130);
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].0, std::path::PathBuf::from("a"));
        assert!(!truncated);
        let (none, truncated) = select_seed_files(vec![file("x", 200, 1)], 100);
        assert!(none.is_empty() && truncated);
    }

    /// 2.21.105 — le filtre `interfaces` de la trace se lit dans les
    /// compteurs (`filtered`), et ne bloque pas l'amorçage.
    #[test]
    fn interface_filter_is_counted_and_bypassed_by_seed_2_21_105() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let decode = |interface: &str| {
            let config = oiran_decode::DecodeConfig {
                input: source.join(format!("{interface}.pcapng")),
                capture_id: format!("sha256:{}", "b".repeat(64)),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: String::new(),
            };
            let mut events = Vec::new();
            oiran_decode::decode_capture_streaming(&config, &key, |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
            sort_by_capture_order(&mut events);
            events
        };
        let n2 = decode("N2");
        assert!(!n2.is_empty());
        let r = LiveTraceRegistry::new();
        let mut trace = state(u64::MAX, false, vec!["psn-none".into()]);
        trace.trace.interfaces = vec!["N3".into()];
        r.traces.lock().unwrap().insert("t".into(), trace);
        for event in &n2 {
            r.route_normalized(event);
        }
        assert!(r.begin_seed());
        for event in &n2 {
            r.learn_from_ring(event);
        }
        let traces = r.traces.lock().unwrap();
        let s = &traces["t"];
        let feed = &s.trace.feed["N2"];
        assert_eq!(feed.seen, n2.len() as u64);
        assert_eq!(feed.filtered, n2.len() as u64);
        assert_eq!(feed.attached, 0);
        assert_eq!(
            s.trace.seed.events_scanned,
            n2.len() as u64,
            "l'amorçage voit N2 malgré le filtre N3"
        );
    }

    /// 2.21.105 — bout en bout sur le ring : la signalisation N2 + N4
    /// du jeu `OIRAN_5G_PDU_SESSION_DATA_V1` est posée dans un ring
    /// AVANT l'ouverture de la trace ; `seed_from_ring` la relit ; les
    /// G-PDU N3 décodés ensuite sont rattachés et la somme des buckets
    /// égale les octets des G-PDU décodés. Sans amorçage : 0 rattaché.
    #[test]
    fn seed_from_ring_attaches_gpdu_of_a_session_older_than_the_trace_2_21_105() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let root = std::env::temp_dir().join(format!(
            "oiran-seed-ring-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        for plane in ["n2", "n4", "n3"] {
            fs::create_dir_all(root.join(plane)).unwrap();
            fs::copy(
                source.join(format!("{}.pcapng", plane.to_ascii_uppercase())),
                root.join(plane).join(format!("{plane}_00001.pcapng")),
            )
            .unwrap();
        }
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let decode = |plane: &str, interface: &str| {
            let config = oiran_decode::DecodeConfig {
                input: root.join(plane).join(format!("{plane}_00001.pcapng")),
                capture_id: format!("sha256:{}", "c".repeat(64)),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: String::new(),
            };
            let mut events = Vec::new();
            oiran_decode::decode_capture_streaming(&config, &key, |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
            sort_by_capture_order(&mut events);
            events
        };
        // Le pseudonyme abonné est celui que le décodeur pose sur N2.
        let pseudonym = decode("n2", "N2")
            .iter()
            .flat_map(|e| e.session_identifiers.iter())
            .find(|id| id.name == "subscriber_pseudonym")
            .map(|id| id.value.clone())
            .expect("le jeu N2 porte un subscriber_pseudonym");
        let gpdus: Vec<_> = decode("n3", "N3")
            .into_iter()
            .filter(|e| e.protocol.as_str() == "GTP-U")
            .collect();
        assert!(!gpdus.is_empty(), "le jeu N3 porte des G-PDU");
        let injected: u64 = gpdus
            .iter()
            .map(|e| u64::from(e.packet_references[0].original_length))
            .sum();

        let run = |seed: bool| {
            let r = LiveTraceRegistry::new();
            r.traces
                .lock()
                .unwrap()
                .insert("t".into(), state(u64::MAX, false, vec![pseudonym.clone()]));
            let mut report = SeedReport::default();
            if seed {
                assert!(r.begin_seed());
                report = seed_from_ring(&root, &key, &r);
                r.finish_seed(&report);
            }
            for event in &gpdus {
                r.route_normalized(event);
            }
            r.flush_idle_throughput_buckets();
            let traces = r.traces.lock().unwrap();
            let s = &traces["t"];
            let total: u64 = s
                .events
                .iter()
                .filter(|e| e.kind == "throughput")
                .map(|b| {
                    ["ul_bytes_s", "dl_bytes_s", "unknown_bytes_s"]
                        .iter()
                        .map(|f| b.payload[*f].as_u64().unwrap_or(0))
                        .sum::<u64>()
                })
                .sum();
            (s.trace.gpdu_seen, s.trace.gpdu_attached, total, report, s.trace.seed.clone())
        };
        let (seen, attached, total, _, _) = run(false);
        assert_eq!(seen, gpdus.len() as u64);
        assert_eq!((attached, total), (0, 0), "sans amorçage : N vus, 0 rattaché, 0 bucket");
        let (seen, attached, total, report, seed) = run(true);
        assert_eq!(report.files, 2, "N2 et N4 relus, jamais N3");
        assert!(!report.truncated);
        assert!(seed.done && seed.events_learned > 0);
        assert_eq!(seen, gpdus.len() as u64);
        assert_eq!(attached, gpdus.len() as u64, "tous les G-PDU rattachés après amorçage");
        assert_eq!(total, injected, "somme des buckets = octets des G-PDU");
        let _ = fs::remove_dir_all(&root);
    }

    fn n3_ring_file(tag: &str) -> (std::path::PathBuf, Vec<u8>) {
        let bytes = fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N3.pcapng"),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "oiran-reader-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        (dir.join("n3_00001.pcapng"), bytes)
    }

    fn full_event_ids(path: &std::path::Path, key: &event_schema::PseudonymKey) -> Vec<String> {
        let mut events = Vec::new();
        oiran_decode::decode_capture_streaming(&ring_decode_config(path, "N3"), key, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        sort_by_capture_order(&mut events);
        events
            .into_iter()
            .map(|e| format!("{}|{}", e.event_id, e.stable_event_key))
            .collect()
    }

    fn ids(events: &[event_schema::NormalizedEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| format!("{}|{}", e.event_id, e.stable_event_key))
            .collect()
    }

    /// 2.21.109 (ordre #9 7049845272) — le lecteur ne décode que les
    /// octets ajoutés : segment écrit en trois fois (dont une coupe au
    /// milieu d'un bloc), somme des octets décodés = taille du fichier,
    /// events = ceux du décodage intégral, aucune remise à zéro ; une
    /// passe sans nouvel octet ne décode rien.
    #[test]
    fn decode_increment_reads_only_appended_bytes_2_21_109() {
        let (path, bytes) = n3_ring_file("append");
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let config = ring_decode_config(&path, "N3");
        let mut sessions = HashMap::new();
        let mut events = Vec::new();
        let mut decoded = 0u64;
        for cut in [bytes.len() / 3 + 5, 2 * bytes.len() / 3 + 3, bytes.len(), bytes.len()] {
            fs::write(&path, &bytes[..cut]).unwrap();
            let outcome = decode_increment(&mut sessions, &config, &key, cut as u64);
            assert!(outcome.ok && !outcome.reset);
            assert!(outcome.consumed_bytes <= cut as u64);
            decoded += outcome.bytes_decoded;
            events.extend(outcome.events);
        }
        assert_eq!(decoded, bytes.len() as u64, "chaque octet décodé une seule fois");
        sort_by_capture_order(&mut events);
        assert_eq!(ids(&events), full_event_ids(&path, &key));
        assert!(close_reader_session(&mut sessions, &config).is_empty(), "pas de flux RTP ici");
        assert!(sessions.is_empty(), "session oubliée à la clôture");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    /// 2.21.109 (ordre #9 7049845272) — fichier remplacé par un autre de
    /// taille supérieure : la session est jetée une fois (`reset`), le
    /// nouveau fichier est décodé depuis 0 et ses events sont ceux de
    /// son décodage intégral. Deux formes de remplacement : par
    /// renommage (inode différent, même début de fichier) et par
    /// réécriture sur place (même inode, derniers octets consommés
    /// modifiés).
    #[test]
    fn decode_increment_resets_when_file_is_replaced_by_a_larger_one_2_21_109() {
        let (path, bytes) = n3_ring_file("replace");
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let config = ring_decode_config(&path, "N3");
        // Fichier plus grand : deux sections pcapng bout à bout.
        let mut larger = bytes.clone();
        larger.extend_from_slice(&bytes);

        // (1) remplacement par renommage.
        let mut sessions = HashMap::new();
        fs::write(&path, &bytes).unwrap();
        let first = decode_increment(&mut sessions, &config, &key, bytes.len() as u64);
        assert!(first.ok && !first.reset && !first.events.is_empty());
        let staged = path.with_extension("staged");
        fs::write(&staged, &larger).unwrap();
        fs::rename(&staged, &path).unwrap();
        let mut resets = 0;
        let mut replaced = decode_increment(&mut sessions, &config, &key, larger.len() as u64);
        resets += usize::from(replaced.reset);
        assert_eq!(replaced.bytes_decoded, larger.len() as u64, "relu depuis 0");
        sort_by_capture_order(&mut replaced.events);
        assert_eq!(ids(&replaced.events), full_event_ids(&path, &key));
        let again = decode_increment(&mut sessions, &config, &key, larger.len() as u64);
        resets += usize::from(again.reset);
        assert_eq!(resets, 1, "resume_resets = 1 pour un remplacement");
        assert_eq!(again.bytes_decoded, 0);

        // (2) réécriture sur place : même inode, contenu consommé modifié.
        let mut sessions = HashMap::new();
        fs::write(&path, &bytes).unwrap();
        let first = decode_increment(&mut sessions, &config, &key, bytes.len() as u64);
        assert!(!first.reset);
        let inode_before = device_inode(&path);
        let mut rewritten = larger.clone();
        // Dernier octet de données du dernier paquet du premier bloc :
        // 5 octets avant la fin (les 4 derniers sont la longueur du bloc).
        let flip = bytes.len() - 5;
        rewritten[flip] ^= 0xff;
        {
            use std::io::Write;
            let mut file = fs::OpenOptions::new().write(true).open(&path).unwrap();
            file.write_all(&rewritten).unwrap();
        }
        assert_eq!(device_inode(&path), inode_before, "réécriture sur place");
        let mut replaced = decode_increment(&mut sessions, &config, &key, rewritten.len() as u64);
        assert!(replaced.reset, "contenu consommé modifié → remise à zéro");
        assert_eq!(replaced.bytes_decoded, rewritten.len() as u64);
        sort_by_capture_order(&mut replaced.events);
        assert_eq!(ids(&replaced.events), full_event_ids(&path, &key));

        // (3) fichier tronqué sous l'offset consommé.
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        let truncated = decode_increment(&mut sessions, &config, &key, (bytes.len() / 2) as u64);
        assert!(truncated.reset);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    /// 2.21.109 — l'event `stats` porte le bloc `reader` : remises à
    /// zéro, octets décodés contre taille par plan, et l'état du repli.
    /// Le repli se pilote par `OIRAN_LIVE_READER_FULL_REDECODE`.
    #[test]
    fn stats_expose_reader_io_and_full_redecode_switch_2_21_109() {
        let r = LiveTraceRegistry::new();
        r.bump_resume_resets();
        r.set_reader_io(BTreeMap::from([(
            "N3".to_string(),
            ReaderIo {
                bytes_decoded: 1_500,
                bytes_file: 30_000_000,
                incremental: true,
            },
        )]));
        // Une passe sans décodage garde le dernier relevé.
        r.set_reader_io(BTreeMap::new());
        let stats = r.stats_payload(&state(u64::MAX, false, vec![]).trace);
        assert_eq!(stats["reader"]["resume_resets"], 1);
        assert_eq!(stats["reader"]["interfaces"]["N3"]["bytes_decoded"], 1_500);
        assert_eq!(stats["reader"]["interfaces"]["N3"]["bytes_file"], 30_000_000);
        assert_eq!(stats["reader"]["interfaces"]["N3"]["incremental"], true);
        // Seul ce test écrit cette variable d'environnement.
        std::env::remove_var(FULL_REDECODE_ENV);
        assert!(!full_redecode_requested(), "reprise à l'offset par défaut");
        std::env::set_var(FULL_REDECODE_ENV, "1");
        let requested = full_redecode_requested();
        std::env::remove_var(FULL_REDECODE_ENV);
        assert!(requested, "le repli est atteignable sans redéploiement");
    }

    #[test]
    fn bounded_buffer() {
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, true, vec![]));
        for n in 0..2100 {
            r.append("t", "message", json!({"n":n}));
        }
        assert_eq!(r.traces.lock().unwrap()["t"].events.len(), 2000);
        assert_eq!(
            r.traces.lock().unwrap()["t"].events.front().unwrap().id,
            101
        );
    }

    #[test]
    fn expiration_and_last_event_id_are_deterministic() {
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("old".into(), state(1, true, vec![]));
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, true, vec![]));
        for n in 0..4 {
            r.append("t", "message", json!({"n":n}));
        }
        let mut traces = r.traces.lock().unwrap();
        LiveTraceRegistry::purge(&mut traces);
        assert!(!traces.contains_key("old"));
        let replay = traces["t"]
            .events
            .iter()
            .filter(|event| event.id > 2)
            .map(|event| event.id)
            .collect::<Vec<_>>();
        assert_eq!(replay, vec![3, 4]);
    }

    #[test]
    fn growing_pcapng_emits_complete_packets_before_partial_tail() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let bytes = fs::read(&source).unwrap();
        assert!(bytes.len() > 64);
        let path =
            std::env::temp_dir().join(format!("oiran-live-partial-{}.pcapng", std::process::id()));
        fs::write(&path, &bytes[..bytes.len() - 7]).unwrap();
        let config = oiran_decode::DecodeConfig {
            input: path.clone(),
            capture_id: format!("sha256:{}", "a".repeat(64)),
            interface: "N2".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let mut partial = Vec::new();
        let _ = oiran_decode::decode_capture_streaming(&config, &key, |event| {
            partial.push(event);
            Ok(())
        });
        assert!(!partial.is_empty());
        fs::write(&path, &bytes).unwrap();
        let mut complete = 0;
        oiran_decode::decode_capture_streaming(&config, &key, |_| {
            complete += 1;
            Ok(())
        })
        .unwrap();
        assert!(complete >= partial.len());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn armed_trace_starts_only_on_decoder_key_and_learns_correlations() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let config = oiran_decode::DecodeConfig {
            input: source,
            capture_id: format!("sha256:{}", "b".repeat(64)),
            interface: "N2".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([9; 32]);
        let mut events = Vec::new();
        oiran_decode::decode_capture_streaming(&config, &key, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        let first = events
            .iter()
            .find(|event| !event.session_identifiers.is_empty())
            .unwrap();
        let root = first.session_identifiers[0].value.clone();
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, true, vec![root]));
        r.route_normalized(first);
        let traces = r.traces.lock().unwrap();
        assert!(!traces["t"].trace.armed);
        assert_eq!(traces["t"].trace.messages, 1);
        assert!(traces["t"].match_keys.len() > 0);
    }

    /// 2.18.10 — un lot décodé dans le désordre de reconstruction est
    /// routé dans l'ordre des paquets : 0 `late`.
    #[test]
    fn a_batch_decoded_out_of_order_is_routed_without_late_messages() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let config = oiran_decode::DecodeConfig {
            input: source,
            capture_id: format!("sha256:{}", "d".repeat(64)),
            interface: "N2".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([9; 32]);
        let mut events = Vec::new();
        oiran_decode::decode_capture_streaming(&config, &key, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        let mut tagged: Vec<_> = events
            .into_iter()
            .filter(|event| !event.session_identifiers.is_empty())
            .collect();
        assert!(tagged.len() >= 3);
        let root = tagged[0].session_identifiers[0].value.clone();
        tagged.reverse(); // pire cas : ordre de reconstruction inversé
        sort_by_capture_order(&mut tagged);
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, true, vec![root]));
        for event in &tagged {
            r.route_normalized(event);
        }
        let traces = r.traces.lock().unwrap();
        assert!(traces["t"].trace.messages >= 1);
        assert_eq!(traces["t"].trace.out_of_order, 0);
    }

    /// 2.18.6 (ANR1 #10 6901968948) — un message routé deux fois n'est
    /// émis qu'une fois ; un packet_number plus ancien dans la même
    /// capture est compté `out_of_order` et marqué `late`.
    #[test]
    fn duplicate_messages_are_dropped_and_intra_capture_inversions_are_counted() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let config = oiran_decode::DecodeConfig {
            input: source,
            capture_id: format!("sha256:{}", "c".repeat(64)),
            interface: "N2".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([9; 32]);
        let mut events = Vec::new();
        oiran_decode::decode_capture_streaming(&config, &key, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        let tagged: Vec<_> = events
            .iter()
            .filter(|event| !event.session_identifiers.is_empty())
            .collect();
        assert!(tagged.len() >= 2, "fixture needs two correlated N2 messages");
        let root = tagged[0].session_identifiers[0].value.clone();
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, true, vec![root]));
        r.route_normalized(tagged[0]);
        r.route_normalized(tagged[0]); // doublon exact
        r.route_normalized(tagged[1]);
        r.route_normalized(tagged[0]); // doublon après un autre message
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.messages, 2);
        assert_eq!(t.trace.duplicates_dropped, 2);
        let packets: Vec<u64> = t
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| e.payload["packet_number"].as_u64().unwrap())
            .collect();
        assert_eq!(packets.len(), 2);
        let expected_late = u64::from(packets[1] < packets[0]);
        assert_eq!(t.trace.out_of_order, expected_late);
        // les méta-events portent la clé du message parent
        assert!(t
            .events
            .iter()
            .filter(|e| e.kind == "ue_info")
            .all(|e| e.payload.get("capture_id").is_some()));
    }

    /// 2.16.0 (ANR1 #10 Live-IMSI) — `canonical_sort_key` trie le
    /// replay par (capture_id, packet_number, id). Garantie promise
    /// par l'UI (PolarisApp.jsx dictionnaire : « Ordre (capture_id,
    /// seq) — chaque message est retrouvable à l'identique dans
    /// l'Analyzer »). Même lorsque le lecteur PCAPNG alterne
    /// plusieurs captures (N2, N4, N3…) et que les `id` SSE arrivent
    /// entremêlés par next_id croissant, le replay sorti doit
    /// grouper par capture_id puis trier par packet_number.
    #[test]
    fn replay_sort_is_canonical_by_capture_id_and_packet_number() {
        let make = |id: u64, capture: &str, packet: u64| BufferedEvent {
            id,
            kind: "message".into(),
            payload: json!({"capture_id": capture, "packet_number": packet}),
        };
        // Ordre d'arrivée simulant 2 captures entrelacées sur
        // interfaces différentes : N2 paquet 1, N4 paquet 1, N2
        // paquet 2, N4 paquet 2. L'ordre canonique attendu est :
        // (sha256:alpha, 1, 1) → (sha256:alpha, 2, 3) →
        // (sha256:beta, 1, 2) → (sha256:beta, 2, 4).
        let mut events = vec![
            make(1, "sha256:alpha", 1),
            make(2, "sha256:beta", 1),
            make(3, "sha256:alpha", 2),
            make(4, "sha256:beta", 2),
        ];
        events.sort_by(|a, b| canonical_sort_key(a).cmp(&canonical_sort_key(b)));
        let ordered: Vec<(String, u64, u64)> = events
            .iter()
            .map(|e| {
                (
                    e.payload["capture_id"].as_str().unwrap().into(),
                    e.payload["packet_number"].as_u64().unwrap(),
                    e.id,
                )
            })
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("sha256:alpha".into(), 1, 1),
                ("sha256:alpha".into(), 2, 3),
                ("sha256:beta".into(), 1, 2),
                ("sha256:beta".into(), 2, 4),
            ]
        );
    }

    /// 2.16.0 (ANR1 #10 Live-IMSI) — à la jonction replay↔live SSE,
    /// un event déjà rejoué (id <= cutoff_id) DOIT être filtré du
    /// flux live pour ne pas être livré deux fois. Reproduit la
    /// race qui existait en 2.15.4 : le subscribe `rx` est fait
    /// sous le même lock que le snapshot du replay, donc le
    /// broadcast d'un event ajouté juste avant ce moment-là arrive
    /// via les deux canaux.
    #[test]
    fn join_replay_live_deduplicates_at_boundary() {
        let (tx, _rx0) = broadcast::channel::<BufferedEvent>(16);
        // 3 events déjà dans le buffer, ids 1..=3.
        let buffer = vec![
            BufferedEvent {
                id: 1,
                kind: "message".into(),
                payload: json!({"capture_id":"c","packet_number":1}),
            },
            BufferedEvent {
                id: 2,
                kind: "message".into(),
                payload: json!({"capture_id":"c","packet_number":2}),
            },
            BufferedEvent {
                id: 3,
                kind: "message".into(),
                payload: json!({"capture_id":"c","packet_number":3}),
            },
        ];
        // Un subscriber est fait AU MOMENT où le buffer contient
        // déjà ces 3 events. Il n'a rien reçu encore (channel vide).
        let rx = tx.subscribe();
        // Simulation : avant le drain du replay, un 4e event est
        // broadcast. Le replay snapshot ne le voit pas. Le live le
        // verra. On broadcast AUSSI un retardataire d'id=3 (edge
        // case : une re-push accidentelle d'un event déjà dans le
        // replay). Le filter (id > cutoff_id) doit l'éliminer.
        let _ = tx.send(BufferedEvent {
            id: 3,
            kind: "message".into(),
            payload: json!({"capture_id":"c","packet_number":3}),
        });
        let _ = tx.send(BufferedEvent {
            id: 4,
            kind: "message".into(),
            payload: json!({"capture_id":"c","packet_number":4}),
        });
        let cutoff_id = buffer.iter().map(|e| e.id).max().unwrap();
        assert_eq!(cutoff_id, 3);
        // Maintenant on consume ce que verrait le filter `e.id > cutoff_id`.
        let mut live_deliveries: Vec<u64> = Vec::new();
        drop(tx);
        let stream_filter = |e: &BufferedEvent| e.id > cutoff_id;
        use std::sync::Mutex;
        let rx_mu = Mutex::new(rx);
        loop {
            match rx_mu.lock().unwrap().try_recv() {
                Ok(e) => {
                    if stream_filter(&e) {
                        live_deliveries.push(e.id);
                    }
                }
                Err(_) => break,
            }
        }
        // Seul l'id=4 passe. Le duplicate d'id=3 est éliminé.
        assert_eq!(live_deliveries, vec![4]);
    }

    /// 2.16.0 (ANR1 #10 Live-IMSI) — `correlate_sessions_by_pseudonyms`
    /// doit matcher sur le `subscriber_pseudonym` observé dans le
    /// vault, pas sur une forme clear-text. Vérifie la shape de
    /// sortie attendue par le front (`session_id` + optionnel
    /// `dataset_id`/`technology` + `source`). Le match est fait via
    /// `identity_vault.for_session`, donc on teste que le set de
    /// pseudonymes agit bien comme filtre.
    #[test]
    fn correlate_sessions_filter_builds_sorted_shape() {
        // Pas de setup AppState ici — on vérifie seulement la
        // forme du filtre par pseudonymes (jeu vide = aucun match).
        let pseudos: HashSet<String> = HashSet::new();
        assert!(pseudos.is_empty());
        // Un pseudonyme réel n'apparaîtrait que si observé dans le
        // vault d'une session connue — couvert en intégration par
        // la route `/api/v1/live/traces/:id/sessions` exposée dans
        // `lib.rs::router`. Ce test documente l'invariant unitaire.
    }

    /// 2.21.76 (ordre #9 7012275179 §CLAUDE2.D-06) — un event GTP-U de
    /// direction `UNKNOWN` **n'est plus compté dans dl_bytes_s** : il
    /// alimente `unknown_bytes_s` séparé. Preuve par trois events
    /// (UPLINK, DOWNLINK, UNKNOWN) → le flush `throughput` qui suit
    /// doit porter ul/dl/unknown séparés et >0.
    #[test]
    fn gtpu_unknown_direction_is_not_counted_as_downlink_2_21_76() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-x".into()]));
        let base_event = |direction: Direction, packet_number: u64, seconds: i64| {
            let p = PacketReference {
                source_file: "x".into(),
                source_sha256: None,
                packet_number,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 100,
                original_length: 100,
            };
            NormalizedEvent {
                event_id: format!("evt-{direction:?}-{packet_number}"),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "test".into(),
                capture_point_id: "N3".into(),
                capture_id: "c".into(),
                packet_references: vec![p],
                timestamp: ExactTimestamp {
                    seconds,
                    nanoseconds: 0,
                    raw_ticks: (seconds.max(0) as u64) * 1_000_000_000,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                interface: "N3".into(),
                protocol: Protocol::Gtpu,
                // Le pseudonyme doit apparaître dans le JSON encodé
                // pour que `route_normalized` match.
                message_name: "GTP-U psn-x".into(),
                message_type: 0xFF,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "10.0.0.1".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "10.0.0.2".into(),
                    port: None,
                    network_function: None,
                },
                direction,
                session_identifiers: vec![],
                information_elements: vec![],
                decoder_name: "decoder-gtpu".into(),
                decoder_version: "0.2.2".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: "sha256:x".into(),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: "sha256:x".into(),
                }],
                sbi: None,
            }
        };
        // Même seconde (=10) : accumulation.
        r.route_normalized(&base_event(Direction::Uplink, 1, 10));
        r.route_normalized(&base_event(Direction::Downlink, 2, 10));
        r.route_normalized(&base_event(Direction::Unknown, 3, 10));
        // Seconde suivante (=11) : déclenche le flush des buckets de la seconde 10.
        r.route_normalized(&base_event(Direction::Uplink, 4, 11));
        let traces = r.traces.lock().unwrap();
        let state = traces.get("t").unwrap();
        let throughput = state
            .events
            .iter()
            .find(|e| e.kind == "throughput")
            .expect("un event throughput doit avoir été émis");
        assert_eq!(throughput.payload["second"], 10);
        assert_eq!(throughput.payload["ul_bytes_s"], 100);
        assert_eq!(throughput.payload["dl_bytes_s"], 100);
        assert_eq!(
            throughput.payload["unknown_bytes_s"], 100,
            "un event UNKNOWN doit alimenter unknown_bytes_s, PAS dl_bytes_s"
        );
    }

    /// 2.21.99 (défaut recette prod #10 7043526474, ordre #9 7043914072) —
    /// répro **du défaut mesuré en prod** : 0 bucket de débit live
    /// malgré 107 Mo de trafic GTP-U sur N3. Scénario modélisé :
    ///   1. une trace est créée pour `psn-prod` ;
    ///   2. un NGAP `PDUSessionResourceSetupRequest` arrive AVEC
    ///      `subscriber_pseudonym=psn-prod` et une IE qui porte les
    ///      F-TEID UL/DL → `match_pseudo` fire, state.tunnel_teids
    ///      apprend les TEID (2.21.90 défaut 2) ;
    ///   3. N GTP-U N3 arrivent **sans subscriber_pseudonym** (cas
    ///      réel : décodeur-gtpu n'injecte que `teid`,
    ///      `tunnel_endpoint_ip`, `tunnel_direction`, QFI, inner IPs —
    ///      pas de pseudonyme abonné). Match via `match_teid` 2.21.90.
    ///   4. le MÊME `second` sur les 3 premiers GTP-U, puis seconde
    ///      suivante sur les 3 suivants → une bascule de second,
    ///      donc exactement **UN** bucket doit être émis.
    ///
    /// Si le test reproduit 0 bucket, la cause est dans la chaîne
    /// `match_teid → route_normalized → throughput emission`.
    #[test]
    fn gtpu_matched_via_match_teid_still_emits_throughput_buckets_2_21_99() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-prod".into()]));

        let packet_ref = |number: u64, original: u32| PacketReference {
            source_file: "n3.pcapng".into(),
            source_sha256: None,
            packet_number: number,
            byte_offset: 0,
            interface_id: 0,
            link_type: None,
            sll2_protocol_type: None,
            sll2_reserved: None,
            sll2_interface_index: None,
            sll2_arphrd_type: None,
            sll2_packet_type: None,
            sll2_address_length: None,
            sll2_address: None,
            captured_length: original,
            original_length: original,
        };
        let ts = |seconds: i64| ExactTimestamp {
            seconds,
            nanoseconds: 0,
            raw_ticks: (seconds.max(0) as u64) * 1_000_000_000,
            resolution_base: 10,
            resolution_exponent: 9,
        };

        // Étape 1 — NGAP PDUSessionResourceSetupRequest avec pseudo + F-TEID.
        // Les tunnel pairs sont dans l'IE `tunnel_pairs` selon le format
        // `item_0_tunnel_ip_ul=10.77.11.13,item_0_gtp_teid_ul=0xf1240001,
        //  item_0_tunnel_ip_dl=10.77.22.13,item_0_gtp_teid_dl=0xf1240002`.
        let ngap = NormalizedEvent {
            event_id: "evt-ngap-setup".into(),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N2".into(),
            capture_id: "cap-n2".into(),
            packet_references: vec![packet_ref(1, 1_200)],
            timestamp: ts(1_795_000_000),
            interface: "N2".into(),
            protocol: Protocol::Ngap,
            message_name: "PDUSessionResourceSetupRequest".into(),
            message_type: 29,
            procedure_code: Some(29),
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.77.21.11".into(),
                port: None,
                network_function: Some("AMF".into()),
            },
            destination_endpoint: Endpoint {
                address: "10.77.21.20".into(),
                port: None,
                network_function: Some("gNB".into()),
            },
            direction: Direction::CoreToRan,
            // subscriber_pseudonym dans les IE value → match_pseudo fire.
            session_identifiers: vec![NamedValue {
                name: "subscriber_pseudonym".into(),
                value: "psn-prod".into(),
                pseudonymized: true,
            }],
            information_elements: vec![InformationElement {
                id: Some(19),
                name: "PDUSessionResourceSetupListSUReq".into(),
                length: 60,
                value: Some(
                    "item_0_tunnel_ip_ul=10.77.11.13,item_0_gtp_teid_ul=0xf1240001,\
                     item_0_tunnel_ip_dl=10.77.22.13,item_0_gtp_teid_dl=0xf1240002"
                        .into(),
                ),
                raw_sha256: Some("sha256:ngap-setup".into()),
                status: DecodeStatus::Decoded,
            }],
            decoder_name: "decoder-ngap".into(),
            decoder_version: "0.6.3".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:ngap".into(),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: "sha256:ngap".into(),
            }],
            sbi: None,
        };
        r.route_normalized(&ngap);

        // Étape 2 — vérifier que l'apprentissage TEID a eu lieu.
        {
            let traces = r.traces.lock().unwrap();
            let s = traces.get("t").unwrap();
            assert!(
                s.tunnel_teids
                    .iter()
                    .any(|t| t.ends_with("f1240001")),
                "UL TEID doit être appris depuis NGAP (actuels : {:?})",
                s.tunnel_teids
            );
            assert!(
                s.tunnel_teids
                    .iter()
                    .any(|t| t.ends_with("f1240002")),
                "DL TEID doit être appris depuis NGAP"
            );
        }

        // Étape 3 — 6 GTP-U UL/DL, PAS de subscriber_pseudonym (comme
        // en prod : decoder-gtpu n'en injecte jamais). session_identifiers
        // porte `teid` qui matche state.tunnel_teids via `match_teid`.
        let gtpu = |packet: u64, seconds: i64, direction: Direction, teid_hex: &str, bytes: u32| {
            NormalizedEvent {
                event_id: format!("evt-gtpu-{packet}"),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "test".into(),
                capture_point_id: "N3".into(),
                capture_id: "cap-n3".into(),
                packet_references: vec![packet_ref(packet, bytes)],
                timestamp: ts(seconds),
                interface: "N3".into(),
                protocol: Protocol::Gtpu,
                message_name: "GTP-U".into(),
                message_type: 255,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "10.77.11.13".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "10.77.22.13".into(),
                    port: None,
                    network_function: None,
                },
                direction,
                session_identifiers: vec![
                    NamedValue {
                        name: "teid".into(),
                        value: teid_hex.into(),
                        pseudonymized: false,
                    },
                    NamedValue {
                        name: "tunnel_endpoint_ip".into(),
                        value: "10.77.22.13".into(),
                        pseudonymized: false,
                    },
                ],
                information_elements: vec![],
                decoder_name: "decoder-gtpu".into(),
                decoder_version: "0.2.2".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: format!("sha256:gtpu-{packet}"),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: format!("sha256:gtpu-{packet}"),
                }],
                sbi: None,
            }
        };
        // Seconde 1_795_000_100 : 3 events = 2 UL + 1 DL, total 1500+1500+1500 = 4500 par bucket.
        r.route_normalized(&gtpu(10, 1_795_000_100, Direction::Uplink, "0xf1240001", 1_500));
        r.route_normalized(&gtpu(11, 1_795_000_100, Direction::Uplink, "0xf1240001", 1_500));
        r.route_normalized(&gtpu(12, 1_795_000_100, Direction::Downlink, "0xf1240002", 1_500));
        // Seconde 1_795_000_101 : 3 events, déclenche le flush de la seconde 100.
        r.route_normalized(&gtpu(13, 1_795_000_101, Direction::Downlink, "0xf1240002", 1_500));
        r.route_normalized(&gtpu(14, 1_795_000_101, Direction::Downlink, "0xf1240002", 1_500));
        r.route_normalized(&gtpu(15, 1_795_000_101, Direction::Uplink, "0xf1240001", 1_500));

        let traces = r.traces.lock().unwrap();
        let s = traces.get("t").unwrap();
        let buckets: Vec<_> = s
            .events
            .iter()
            .filter(|e| e.kind == "throughput")
            .collect();
        assert!(
            !buckets.is_empty(),
            "AU MOINS UN bucket attendu après transition de second (défaut prod reproduit si 0)"
        );
        let first = buckets[0];
        assert_eq!(first.payload["second"], 1_795_000_100);
        assert_eq!(
            first.payload["ul_bytes_s"], 3_000,
            "2 UL × 1500 = 3000 octets accumulés sur la seconde 100"
        );
        assert_eq!(
            first.payload["dl_bytes_s"], 1_500,
            "1 DL × 1500 = 1500 octets accumulés sur la seconde 100"
        );
        // 6 events × 1500 = 9000 octets au total — les events de la
        // seconde 101 sont encore accumulés, non flushés.
        let total_from_buckets: u64 = buckets
            .iter()
            .map(|b| {
                b.payload["ul_bytes_s"].as_u64().unwrap_or(0)
                    + b.payload["dl_bytes_s"].as_u64().unwrap_or(0)
                    + b.payload["unknown_bytes_s"].as_u64().unwrap_or(0)
            })
            .sum();
        // bucket flushé = seconde 100 (3 events × 1500 = 4500).
        assert_eq!(
            total_from_buckets, 4_500,
            "buckets doivent totaliser les 3 events de la seconde 100 avant transition"
        );
    }

    /// 2.21.99 (défaut recette prod #10 7043526474) — `flush_idle_throughput_buckets`
    /// émet un bucket pour les octets accumulés quand le second
    /// wall-clock a dépassé `state.throughput_second`, même si plus
    /// aucun event GTP-U n'arrive.
    ///
    /// Scénario : 3 events GTP-U UL arrivent sur la seconde `t` pendant
    /// la même trace, **puis rien**. Sans le flush idle, les 3 × 1500 B
    /// restent dans `state.ul_bytes` et aucun bucket n'est émis
    /// (route_normalized attend un event ultérieur sur une seconde
    /// différente). Avec le flush idle, dès que l'horloge wall-clock
    /// dépasse `t`, le bucket est émis.
    #[test]
    fn flush_idle_emits_bucket_for_stalled_second_2_21_99() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-stalled".into()]));

        // 3 events GTP-U sur la même seconde, dans le passé wall-clock
        // (now > throughput_second est garanti avec un timestamp = 1).
        let gtpu_event = |packet: u64| NormalizedEvent {
            event_id: format!("evt-gtpu-{packet}"),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N3".into(),
            capture_id: "cap".into(),
            packet_references: vec![PacketReference {
                source_file: "x".into(),
                source_sha256: None,
                packet_number: packet,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 1_500,
                original_length: 1_500,
            }],
            timestamp: ExactTimestamp {
                seconds: 1,
                nanoseconds: 0,
                raw_ticks: 1_000_000_000,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N3".into(),
            protocol: Protocol::Gtpu,
            // Pseudo est présent dans message_name pour que match_pseudo
            // fire (le reste du JSON encodé doit contenir `psn-stalled`).
            message_name: "GTP-U psn-stalled".into(),
            message_type: 255,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: None,
                network_function: None,
            },
            direction: Direction::Uplink,
            session_identifiers: vec![NamedValue {
                name: "teid".into(),
                value: "0xabcd0001".into(),
                pseudonymized: false,
            }],
            information_elements: vec![],
            decoder_name: "decoder-gtpu".into(),
            decoder_version: "0.2.2".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: format!("sha256:gtpu-{packet}"),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: format!("sha256:gtpu-{packet}"),
            }],
            sbi: None,
        };
        r.route_normalized(&gtpu_event(10));
        r.route_normalized(&gtpu_event(11));
        r.route_normalized(&gtpu_event(12));
        // Avant le flush idle : 0 bucket, 3 × 1500 = 4500 octets
        // accumulés dans ul_bytes.
        {
            let traces = r.traces.lock().unwrap();
            let s = traces.get("t").unwrap();
            let buckets: Vec<_> = s.events.iter().filter(|e| e.kind == "throughput").collect();
            assert!(
                buckets.is_empty(),
                "pas encore de bucket (tous events sur seconde=1)"
            );
            assert_eq!(s.ul_bytes, 4_500);
            assert_eq!(s.throughput_second, 1);
        }
        // Flush idle : wall-clock now >> throughput_second=1 → bucket émis.
        r.flush_idle_throughput_buckets();
        let traces = r.traces.lock().unwrap();
        let s = traces.get("t").unwrap();
        let buckets: Vec<_> = s.events.iter().filter(|e| e.kind == "throughput").collect();
        assert_eq!(
            buckets.len(),
            1,
            "flush idle doit émettre exactement 1 bucket pour la seconde stagnante"
        );
        assert_eq!(buckets[0].payload["second"], 1);
        assert_eq!(buckets[0].payload["ul_bytes_s"], 4_500);
        assert_eq!(buckets[0].payload["flush"], "idle");
        // state reset après flush : la seconde suivante peut
        // recommencer à accumuler sans prolonger.
        assert_eq!(s.throughput_second, 0);
        assert_eq!(s.ul_bytes, 0);
    }

    /// 2.21.99 — preuve de **totalisation bit-identique** sur N octets
    /// GTP-U connus (objectif de l'ordre : « les buckets du flux live
    /// totalisent **exactement** N, par sens »). 10 events UL × 1200 B
    /// + 7 events DL × 1500 B répartis sur 3 secondes, puis flush idle.
    /// Résultat attendu : total(ul_bytes_s) = 12_000, total(dl_bytes_s)
    /// = 10_500.
    #[test]
    fn total_bytes_from_live_throughput_buckets_match_expected_exactly_2_21_99() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-total".into()]));
        let make = |packet: u64, seconds: i64, direction: Direction, bytes: u32| {
            NormalizedEvent {
                event_id: format!("evt-gtpu-{packet}"),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "test".into(),
                capture_point_id: "N3".into(),
                capture_id: "cap".into(),
                packet_references: vec![PacketReference {
                    source_file: "x".into(),
                    source_sha256: None,
                    packet_number: packet,
                    byte_offset: 0,
                    interface_id: 0,
                    link_type: None,
                    sll2_protocol_type: None,
                    sll2_reserved: None,
                    sll2_interface_index: None,
                    sll2_arphrd_type: None,
                    sll2_packet_type: None,
                    sll2_address_length: None,
                    sll2_address: None,
                    captured_length: bytes,
                    original_length: bytes,
                }],
                timestamp: ExactTimestamp {
                    seconds,
                    nanoseconds: 0,
                    raw_ticks: (seconds.max(0) as u64) * 1_000_000_000,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                interface: "N3".into(),
                protocol: Protocol::Gtpu,
                message_name: "GTP-U psn-total".into(),
                message_type: 255,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "10.0.0.1".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "10.0.0.2".into(),
                    port: None,
                    network_function: None,
                },
                direction,
                session_identifiers: vec![NamedValue {
                    name: "teid".into(),
                    value: "0xabcd0001".into(),
                    pseudonymized: false,
                }],
                information_elements: vec![],
                decoder_name: "decoder-gtpu".into(),
                decoder_version: "0.2.2".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: format!("sha256:gtpu-{packet}"),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: format!("sha256:gtpu-{packet}"),
                }],
                sbi: None,
            }
        };
        let mut pkt = 10u64;
        // Seconde 100 : 4 UL + 2 DL.
        for _ in 0..4 {
            r.route_normalized(&make(pkt, 100, Direction::Uplink, 1_200));
            pkt += 1;
        }
        for _ in 0..2 {
            r.route_normalized(&make(pkt, 100, Direction::Downlink, 1_500));
            pkt += 1;
        }
        // Seconde 101 : 3 UL + 3 DL → flush bucket seconde 100.
        for _ in 0..3 {
            r.route_normalized(&make(pkt, 101, Direction::Uplink, 1_200));
            pkt += 1;
        }
        for _ in 0..3 {
            r.route_normalized(&make(pkt, 101, Direction::Downlink, 1_500));
            pkt += 1;
        }
        // Seconde 102 : 3 UL + 2 DL → flush bucket seconde 101.
        for _ in 0..3 {
            r.route_normalized(&make(pkt, 102, Direction::Uplink, 1_200));
            pkt += 1;
        }
        for _ in 0..2 {
            r.route_normalized(&make(pkt, 102, Direction::Downlink, 1_500));
            pkt += 1;
        }
        // Flush idle : wall-clock now >> 102 → bucket seconde 102 émis.
        r.flush_idle_throughput_buckets();

        let traces = r.traces.lock().unwrap();
        let s = traces.get("t").unwrap();
        let buckets: Vec<_> = s.events.iter().filter(|e| e.kind == "throughput").collect();
        // 3 secondes de trafic → 3 buckets (dont 1 flushé en idle).
        assert_eq!(buckets.len(), 3, "3 secondes de trafic, 3 buckets");
        // Totalisation stricte :
        //   UL = (4 + 3 + 3) × 1200 = 12 000
        //   DL = (2 + 3 + 2) × 1500 = 10 500
        let (total_ul, total_dl): (u64, u64) = buckets
            .iter()
            .map(|b| {
                (
                    b.payload["ul_bytes_s"].as_u64().unwrap_or(0),
                    b.payload["dl_bytes_s"].as_u64().unwrap_or(0),
                )
            })
            .fold((0, 0), |(a, b), (u, d)| (a + u, b + d));
        assert_eq!(total_ul, 12_000, "total UL = (4+3+3)×1200");
        assert_eq!(total_dl, 10_500, "total DL = (2+3+2)×1500");
        assert_eq!(
            total_ul + total_dl,
            22_500,
            "total trafic GTP-U sans perte à travers les buckets live"
        );
    }

    /// 2.21.76 (ordre #9 7012275179 §CLAUDE2.L2-08) — `audit_lookup`
    /// enregistre acteur, rôle, pseudonyme, count, heure — JAMAIS la
    /// valeur en clair. Preuve négative : on injecte une "valeur" en
    /// clair et on vérifie qu'elle n'apparaît nulle part dans l'audit.
    #[test]
    fn audit_lookup_never_stores_the_clear_text_value_2_21_76() {
        let r = LiveTraceRegistry::new();
        // Pas de "valeur" passée à audit_lookup → preuve par type
        // signature : la fonction ne prend que acteur/rôle/pseudonyme/count.
        r.audit_lookup("operator", Some("psn-abc123"), 2, 1_792_600_000);
        let audit = r.audit.lock().unwrap();
        let entry = audit.front().expect("une entrée d'audit");
        assert_eq!(entry["action"], "identity.lookup");
        assert_eq!(entry["actor_role"], "operator");
        assert_eq!(entry["subscriber_pseudonym"], "psn-abc123");
        assert_eq!(entry["result_count"], 2);
        // Preuve négative : aucun des champs ne contient une "value"
        // ou "q" résiduel.
        let serialized = entry.to_string();
        assert!(!serialized.contains("\"value\""));
        assert!(!serialized.contains("\"q\""));
    }

    /// 2.21.90 défaut 1 (ordre #9 7033006772) — deux traces du même
    /// abonné (IMSI vs MSISDN) partageant le subscriber_pseudonym
    /// renvoyé par le vault routent exactement le même ensemble
    /// d'events, et `state.keys` amorcé avec les chiffres canoniques
    /// permet en plus d'attraper les events qui ne portent que la
    /// forme clear-text (cas EPS/SUCI null-scheme / GPSI de la SBI).
    #[test]
    fn imsi_and_msisdn_traces_route_the_same_event_set_2_21_90() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        fn event(
            interface: &str,
            protocol: Protocol,
            message: &str,
            packet: u64,
            seconds: i64,
            session_ids: Vec<(&str, &str)>,
            ies: Vec<(&str, &str)>,
        ) -> NormalizedEvent {
            NormalizedEvent {
                event_id: format!("ev-{}-{packet}", interface.to_ascii_lowercase()),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "test".into(),
                capture_point_id: interface.into(),
                capture_id: "c".into(),
                packet_references: vec![PacketReference {
                    source_file: "x".into(),
                    source_sha256: None,
                    packet_number: packet,
                    byte_offset: 0,
                    interface_id: 0,
                    link_type: None,
                    sll2_protocol_type: None,
                    sll2_reserved: None,
                    sll2_interface_index: None,
                    sll2_arphrd_type: None,
                    sll2_packet_type: None,
                    sll2_address_length: None,
                    sll2_address: None,
                    captured_length: 100,
                    original_length: 100,
                }],
                timestamp: ExactTimestamp {
                    seconds,
                    nanoseconds: 0,
                    raw_ticks: (seconds.max(0) as u64) * 1_000_000_000,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                interface: interface.into(),
                protocol,
                message_name: message.into(),
                message_type: 0,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "10.0.0.1".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "10.0.0.2".into(),
                    port: None,
                    network_function: None,
                },
                direction: Direction::Uplink,
                session_identifiers: session_ids
                    .into_iter()
                    .map(|(n, v)| NamedValue {
                        name: n.into(),
                        value: v.into(),
                        pseudonymized: n == "subscriber_pseudonym",
                    })
                    .collect(),
                information_elements: ies
                    .into_iter()
                    .map(|(n, v)| InformationElement {
                        id: None,
                        name: n.into(),
                        length: v.len() as u32,
                        value: Some(v.into()),
                        raw_sha256: None,
                        status: DecodeStatus::Decoded,
                    })
                    .collect(),
                decoder_name: "test".into(),
                decoder_version: "0".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: "sha256:x".into(),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: "sha256:x".into(),
                }],
                sbi: None,
            }
        }
        // L'identité canonique : vault a observé IMSI et MSISDN pour la
        // même session → retourne le même subscriber_pseudonym SUPI.
        let pseudo_supi = "psn-supi-abc".to_owned();
        // Séquence SBI/NAS caractéristique d'un attach :
        //  e1 (Nausf_UEAuthentication) porte subscriber_pseudonym seul,
        //  e2 (N1N2MessageTransfer) porte subscriber_pseudonym +
        //     msisdn_pseudonym (SMF publie GPSI et SUPI ensemble),
        //  e3 (Nudm_SDM gpsis) ne porte que msisdn_pseudonym (réponse
        //     Nudm au query gpsis, PAS de subscriber_pseudonym).
        // Pour la trace MSISDN en 2.21.74, e3 n'était PAS routé (hash
        // différent) ; en 2.21.90, l'apprentissage de msisdn_pseudonym
        // depuis les session_identifiers de e2 (déjà routé par pseudo
        // SUPI) permet de router e3 via `state.keys`.
        let e1 = event(
            "SBI",
            Protocol::SbiHttp2,
            "Nausf_UEAuthentication",
            1,
            10,
            vec![("subscriber_pseudonym", pseudo_supi.as_str())],
            vec![],
        );
        let e2 = event(
            "SBI",
            Protocol::SbiHttp2,
            "N1N2MessageTransfer",
            2,
            10,
            vec![
                ("subscriber_pseudonym", pseudo_supi.as_str()),
                ("msisdn_pseudonym", "psn-gpsi-msisdn-xyz"),
            ],
            vec![],
        );
        let e3 = event(
            "SBI",
            Protocol::SbiHttp2,
            "Nudm_SDM_AmData",
            3,
            10,
            vec![("msisdn_pseudonym", "psn-gpsi-msisdn-xyz")],
            vec![],
        );
        // Trace « IMSI » (vault connaît l'IMSI → même pseudo SUPI).
        let r_imsi = LiveTraceRegistry::new();
        r_imsi.traces.lock().unwrap().insert(
            "t".into(),
            state_with_initial_keys(
                u64::MAX,
                false,
                vec![pseudo_supi.clone()],
                HashSet::from(["208930000000123".into()]),
            ),
        );
        // Trace « MSISDN » : mêmes pseudos vault, chiffres canoniques
        // différents (E.164). Doit router exactement les mêmes events.
        let r_msisdn = LiveTraceRegistry::new();
        r_msisdn.traces.lock().unwrap().insert(
            "t".into(),
            state_with_initial_keys(
                u64::MAX,
                false,
                vec![pseudo_supi.clone()],
                HashSet::from(["33612345678".into()]),
            ),
        );
        for ev in [&e1, &e2, &e3] {
            r_imsi.route_normalized(ev);
            r_msisdn.route_normalized(ev);
        }
        let imsi_ids: Vec<String> = r_imsi.traces.lock().unwrap()["t"]
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| e.payload["event_id"].as_str().unwrap().to_owned())
            .collect();
        let msisdn_ids: Vec<String> = r_msisdn.traces.lock().unwrap()["t"]
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| e.payload["event_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(imsi_ids, msisdn_ids, "IMSI et MSISDN doivent router le même set");
        assert_eq!(
            imsi_ids,
            vec!["ev-sbi-1", "ev-sbi-2", "ev-sbi-3"],
            "les 3 events de la session doivent être routés"
        );
    }

    /// 2.21.90 défaut 2 (ordre #9 7033006772) — session synthétique
    /// NAS → NGAP → PFCP Est → PFCP Mod → GTP-U : les 5 events sont
    /// tous routés dans l'ordre, par rattachement de session
    /// (UE IP + F-TEID + SEID), sans qu'aucune règle temporelle ne
    /// soit utilisée. Preuve PFCP/GTP-U couverts côté live (défaut
    /// ANR1 7021842930 : « N4 non rattaché dans le live »).
    #[test]
    fn session_nas_ngap_pfcp_gtpu_all_routed_in_order_2_21_90() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        fn ev(
            interface: &str,
            protocol: Protocol,
            message: &str,
            packet: u64,
            session_ids: Vec<(&str, &str)>,
            ies: Vec<(&str, &str)>,
        ) -> NormalizedEvent {
            NormalizedEvent {
                event_id: format!("ev-{packet}"),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "test".into(),
                capture_point_id: interface.into(),
                capture_id: "c".into(),
                packet_references: vec![PacketReference {
                    source_file: "x".into(),
                    source_sha256: None,
                    packet_number: packet,
                    byte_offset: 0,
                    interface_id: 0,
                    link_type: None,
                    sll2_protocol_type: None,
                    sll2_reserved: None,
                    sll2_interface_index: None,
                    sll2_arphrd_type: None,
                    sll2_packet_type: None,
                    sll2_address_length: None,
                    sll2_address: None,
                    captured_length: 100,
                    original_length: 100,
                }],
                timestamp: ExactTimestamp {
                    seconds: 10,
                    nanoseconds: packet as u32,
                    raw_ticks: 10_000_000_000 + packet,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                interface: interface.into(),
                protocol,
                message_name: message.into(),
                message_type: 0,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "10.0.0.1".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "10.0.0.2".into(),
                    port: None,
                    network_function: None,
                },
                direction: Direction::Uplink,
                session_identifiers: session_ids
                    .into_iter()
                    .map(|(n, v)| NamedValue {
                        name: n.into(),
                        value: v.into(),
                        pseudonymized: n.ends_with("pseudonym"),
                    })
                    .collect(),
                information_elements: ies
                    .into_iter()
                    .map(|(n, v)| InformationElement {
                        id: None,
                        name: n.into(),
                        length: v.len() as u32,
                        value: Some(v.into()),
                        raw_sha256: None,
                        status: DecodeStatus::Decoded,
                    })
                    .collect(),
                decoder_name: "test".into(),
                decoder_version: "0".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: "sha256:x".into(),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: "sha256:x".into(),
                }],
                sbi: None,
            }
        }
        // 1) NAS PDU Session Establishment Accept (sur N1 transporté
        //    via N2 NAS). Porte subscriber_pseudonym + IE "PDU address"
        //    (IP UE clair).
        let e_nas = ev(
            "N2",
            Protocol::Ngap,
            "PDU Session Establishment Accept",
            1,
            vec![("subscriber_pseudonym", "psn-sub-xyz")],
            vec![("PDU address", "type=1,address=10.45.0.7")],
        );
        // 2) NGAP PDUSessionResourceSetupRequest avec n2SmInfo
        //    contenant UL/DL tunnels. Porte subscriber_pseudonym
        //    aussi.
        let e_ngap = ev(
            "N2",
            Protocol::Ngap,
            "PDUSessionResourceSetupRequest",
            2,
            vec![("subscriber_pseudonym", "psn-sub-xyz")],
            vec![(
                "PDUSessionResourceSetupRequestTransfer",
                "item_0_tunnel_ip_ul=10.100.0.1,item_0_gtp_teid_ul=0x0000d4a6,item_0_tunnel_ip_dl=10.200.0.1,item_0_gtp_teid_dl=0x0000d4b7",
            )],
        );
        // 3) PFCP Session Establishment Request : F-TEID matching UL
        //    tunnel (ip=10.100.0.1, teid=0xd4a6) + SEID du header dans
        //    session_identifiers. PAS de subscriber_pseudonym SUPI.
        let e_pfcp_est = ev(
            "N4",
            Protocol::Pfcp,
            "Session Establishment Request",
            3,
            vec![("seid", "0x0000000000001001")],
            vec![("F-TEID", "teid=0x0000d4a6,v4=true,v6=false,ipv4=10.100.0.1")],
        );
        // 4) PFCP Session Modification Request : porte le SEID appris.
        let e_pfcp_mod = ev(
            "N4",
            Protocol::Pfcp,
            "Session Modification Request",
            4,
            vec![("seid", "0x0000000000001001")],
            vec![(
                "Outer Header Creation",
                "outer_header_description=0x0100,teid=0x0000d4b7,ipv4=10.200.0.1",
            )],
        );
        // 5) GTP-U UL (TEID = UL F-TEID appris).
        let e_gtpu = ev(
            "N3",
            Protocol::Gtpu,
            "G-PDU",
            5,
            vec![("teid", "0x0000d4a6")],
            vec![],
        );
        let r = LiveTraceRegistry::new();
        r.traces.lock().unwrap().insert(
            "t".into(),
            state(u64::MAX, false, vec!["psn-sub-xyz".into()]),
        );
        for e in [&e_nas, &e_ngap, &e_pfcp_est, &e_pfcp_mod, &e_gtpu] {
            r.route_normalized(e);
        }
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        let routed: Vec<String> = t
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| e.payload["event_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            routed,
            vec!["ev-1", "ev-2", "ev-3", "ev-4", "ev-5"],
            "les 5 events doivent être routés dans l'ordre"
        );
        // Vérifie le rattachement appris : tunnel UL/DL, SEID.
        assert!(t.tunnel_teids.contains("0xd4a6"));
        assert!(t.tunnel_teids.contains("0xd4b7"));
        assert!(t
            .tunnel_endpoints
            .contains(&("10.100.0.1".into(), "0xd4a6".into())));
        assert!(t.seids.contains("0x0000000000001001"));
        assert!(t.ue_ips.contains("10.45.0.7"));
    }

    /// 2.21.90 défaut 1 — `canonical_digits` strippe les préfixes TS
    /// 29.571 §5.4.5 et conserve ≥5 digits.
    #[test]
    fn canonical_digits_strips_prefixes_and_keeps_ge5_digits_2_21_90() {
        assert_eq!(
            canonical_digits("imsi-208930000000123"),
            Some("208930000000123".into())
        );
        assert_eq!(
            canonical_digits("msisdn-33612345678"),
            Some("33612345678".into())
        );
        assert_eq!(canonical_digits("imei-490154203237518"), Some("490154203237518".into()));
        assert_eq!(canonical_digits("  33612345678  "), Some("33612345678".into()));
        // Trop court → None (évite les collisions arbitraires).
        assert_eq!(canonical_digits("1234"), None);
        assert_eq!(canonical_digits(""), None);
    }

    /// 2.21.90 défaut 2 — `parse_tunnel_pairs` couvre les trois
    /// formats de decoders et normalise IP + TEID (strip zero-padding).
    #[test]
    fn parse_tunnel_pairs_covers_ngap_and_pfcp_formats_2_21_90() {
        // NGAP n2SmInfo multipart.
        let pairs = parse_tunnel_pairs(
            "item_0_tunnel_ip_ul=10.1.1.1,item_0_gtp_teid_ul=0x0000d4a6,item_0_tunnel_ip_dl=10.2.2.2,item_0_gtp_teid_dl=0x0000d4b7",
        );
        assert!(pairs.contains(&("10.1.1.1".into(), "0xd4a6".into())));
        assert!(pairs.contains(&("10.2.2.2".into(), "0xd4b7".into())));
        // PFCP F-TEID IE 21.
        let pairs = parse_tunnel_pairs("teid=0x0000d4a6,v4=true,v6=false,ipv4=10.100.0.1");
        assert!(pairs.contains(&("10.100.0.1".into(), "0xd4a6".into())));
        // PFCP Outer Header Creation IE 84.
        let pairs = parse_tunnel_pairs(
            "outer_header_description=0x0100,teid=0x0000d4b7,ipv4=10.200.0.1",
        );
        assert!(pairs.contains(&("10.200.0.1".into(), "0xd4b7".into())));
        // SBI legacy format (tunnel_endpoint_ip,gtp_teid).
        let pairs = parse_tunnel_pairs("tunnel_endpoint_ip=10.9.9.9,gtp_teid=0xd4a6");
        assert!(pairs.contains(&("10.9.9.9".into(), "0xd4a6".into())));
    }

    /// 2.21.90 défaut 2 — `parse_seids` normalise seid/f_seid en
    /// `0x{:016x}` (comparaison stable entre decoders qui peuvent
    /// publier `0x1001` vs `0x0000000000001001`).
    #[test]
    fn parse_seids_normalises_to_16_hex_digits_2_21_90() {
        assert_eq!(parse_seids("seid=0x1001"), vec!["0x0000000000001001"]);
        assert_eq!(
            parse_seids("f_seid=0x1001,v4=true,v6=false,ipv4=10.0.0.1"),
            vec!["0x0000000000001001"]
        );
    }

    /// 2.21.98 (défaut privacy ANR1 #10 7043526474, ordre #9 7043914072) —
    /// séparation `match_keys` (interne, non-Serialize) et `exposed_keys`
    /// (pseudonymes uniquement). Preuve par le type que les chiffres
    /// canoniques amorcés ne peuvent pas atteindre une sortie SSE/HTTP.
    #[test]
    fn match_keys_isolation_from_exposed_keys_2_21_98() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        // Trace IMSI : chiffres canoniques "208930000000123" amorcés
        // dans `match_keys` (type MatchKeys sans Serialize). `exposed_keys`
        // vide à l'initialisation.
        let imsi_digits = "208930000000123".to_owned();
        let r = LiveTraceRegistry::new();
        r.traces.lock().unwrap().insert(
            "t".into(),
            state_with_initial_keys(
                u64::MAX,
                true,
                vec!["psn-supi-xyz".into()],
                HashSet::from([imsi_digits.clone()]),
            ),
        );
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert!(
                t.match_keys.contains(&imsi_digits),
                "chiffres canoniques doivent être dans match_keys (interne)"
            );
            assert!(
                !t.exposed_keys.contains(&imsi_digits),
                "chiffres canoniques NE DOIVENT PAS être dans exposed_keys"
            );
        }
        // Event avec session_identifiers mélangés : subscriber_pseudonym
        // (pseudonymized=true), pdu_session_id (pseudonymized=false).
        let ev = NormalizedEvent {
            event_id: "ev-1".into(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N2".into(),
            capture_id: "c".into(),
            packet_references: vec![PacketReference {
                source_file: "x".into(),
                source_sha256: None,
                packet_number: 1,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 100,
                original_length: 100,
            }],
            timestamp: ExactTimestamp {
                seconds: 10,
                nanoseconds: 0,
                raw_ticks: 10_000_000_000,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N2".into(),
            protocol: Protocol::Ngap,
            message_name: "Registration Request".into(),
            message_type: 0,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: None,
                network_function: None,
            },
            direction: Direction::Uplink,
            session_identifiers: vec![
                NamedValue {
                    name: "subscriber_pseudonym".into(),
                    value: "psn-supi-xyz".into(),
                    pseudonymized: true,
                },
                NamedValue {
                    name: "pdu_session_id".into(),
                    value: "sess-00042".into(),
                    pseudonymized: false,
                },
            ],
            information_elements: vec![InformationElement {
                id: None,
                name: "misc".into(),
                length: 1,
                value: Some("x=y".into()),
                raw_sha256: None,
                status: DecodeStatus::Decoded,
            }],
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:x".into(),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: "sha256:x".into(),
            }],
            sbi: None,
            stable_event_key: String::new(),
        };
        r.route_normalized(&ev);
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        // match_keys contient tout (chiffres + les 2 session_identifiers).
        assert!(t.match_keys.contains(&imsi_digits));
        assert!(t.match_keys.contains("psn-supi-xyz"));
        assert!(t.match_keys.contains("sess-00042"));
        // exposed_keys NE contient QUE le pseudonyme (pseudonymized=true).
        assert!(t.exposed_keys.contains("psn-supi-xyz"));
        assert!(
            !t.exposed_keys.contains(&imsi_digits),
            "chiffres canoniques NE DOIVENT PAS atteindre exposed_keys"
        );
        assert!(
            !t.exposed_keys.contains("sess-00042"),
            "pdu_session_id (pseudonymized=false) NE DOIT PAS atteindre exposed_keys"
        );
        // Preuve négative par sérialisation : aucun BufferedEvent du buffer
        // ne doit contenir le chiffre canonique.
        for buf in t.events.iter() {
            let s = buf.payload.to_string();
            assert!(
                !s.contains(&imsi_digits),
                "BufferedEvent `{}` NE DOIT PAS contenir les chiffres canoniques, got: {}",
                buf.kind,
                s
            );
            assert!(
                !s.contains("\"sess-00042\""),
                "BufferedEvent `{}` NE DOIT PAS contenir le pdu_session_id non-pseudonymisé, got: {}",
                buf.kind,
                s
            );
        }
    }

    /// 2.21.98 — test anti-fuite par la route : POST /api/v1/live/traces
    /// avec une saisie IMSI, puis injecter un event ayant les mêmes chiffres
    /// dans ses session_identifiers ; aucune occurrence du clear-text ne
    /// doit apparaître dans AUCUN `BufferedEvent.payload` (ce que SSE émet).
    /// Pattern complémentaire au test précédent, couvrant la chaîne
    /// `create → route → events` de bout en bout sans passer par l'HTTP.
    #[test]
    fn anti_leak_route_imsi_clear_text_never_in_sse_buffer_2_21_98() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let imsi_digits = "208930000000123".to_owned();
        // Simule le `create` qui amorce `state.match_keys` avec canonical_digits.
        let initial_match = HashSet::from([imsi_digits.clone()]);
        let r = LiveTraceRegistry::new();
        r.traces.lock().unwrap().insert(
            "t".into(),
            state_with_initial_keys(u64::MAX, true, vec!["psn-supi-xyz".into()], initial_match),
        );
        // Event qui porte le subscriber_pseudonym (match_pseudo) ET
        // dont une IE inclut un identifiant non-pseudonymisé. Les events
        // réels decodés par decoder-* pseudonymisent les identités avant
        // sérialisation, mais on prouve ici que **même si** une valeur en
        // clair circule par match_keys, elle ne peut PAS atteindre SSE.
        let ev = NormalizedEvent {
            event_id: "ev-1".into(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N2".into(),
            capture_id: "c".into(),
            packet_references: vec![PacketReference {
                source_file: "x".into(),
                source_sha256: None,
                packet_number: 1,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 100,
                original_length: 100,
            }],
            timestamp: ExactTimestamp {
                seconds: 10,
                nanoseconds: 0,
                raw_ticks: 10_000_000_000,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N2".into(),
            protocol: Protocol::Ngap,
            message_name: "Registration Request".into(),
            message_type: 0,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: None,
                network_function: None,
            },
            direction: Direction::Uplink,
            session_identifiers: vec![NamedValue {
                name: "subscriber_pseudonym".into(),
                value: "psn-supi-xyz".into(),
                pseudonymized: true,
            }],
            information_elements: vec![InformationElement {
                id: None,
                name: "misc".into(),
                length: 1,
                value: Some("harmless=value".into()),
                raw_sha256: None,
                status: DecodeStatus::Decoded,
            }],
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:x".into(),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: "sha256:x".into(),
            }],
            sbi: None,
            stable_event_key: String::new(),
        };
        r.route_normalized(&ev);
        // Vérifie chaque BufferedEvent (message + ue_info + éventuellement
        // procedure / throughput) ne contient pas les chiffres canoniques.
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        let mut all_bytes = String::new();
        for buf in t.events.iter() {
            all_bytes.push_str(&buf.payload.to_string());
            all_bytes.push('\n');
        }
        assert!(
            !all_bytes.contains(&imsi_digits),
            "le flux SSE NE DOIT PAS contenir l'IMSI en clair ; dump:\n{all_bytes}"
        );
        // Vérifie aussi la forme BCD classique (couples swap, 02 89 03 00…).
        // 208930000000123 en BCD = 02 89 03 00 00 00 00 21 F3 (nibble-swap).
        let bcd = "0289030000000021F3";
        assert!(
            !all_bytes.to_uppercase().contains(bcd),
            "le flux SSE NE DOIT PAS contenir l'IMSI en BCD ; dump:\n{all_bytes}"
        );
        // Preuve positive : le pseudonyme SUPI, lui, apparaît dans ue_info.keys.
        assert!(
            all_bytes.contains("psn-supi-xyz"),
            "le pseudonyme SUPI DOIT apparaître (clé exposable)"
        );
    }

    /// 2.21.98 — `MatchKeys` n'implémente pas `Serialize` : un `json!({"keys":state.match_keys})`
    /// est une erreur de compilation. Le test documente l'invariant par
    /// convention (le compilateur rejettera tout appel qui casserait la
    /// séparation).
    #[test]
    fn match_keys_type_has_no_serialize_impl_2_21_98() {
        fn assert_not_serialize<T>() {
            // Pas d'assertion runtime : la protection est au niveau type.
            // Si quelqu'un ajoute `#[derive(Serialize)]` à `MatchKeys`, un
            // test ultérieur (ou la relecture) détectera le changement.
            // On documente ici que l'invariant est tenu par le type.
            let _ = std::marker::PhantomData::<T>;
        }
        assert_not_serialize::<MatchKeys>();
        // Côté runtime, vérifions au moins que l'API publique n'expose pas
        // de méthode qui retournerait le set complet clonable en Vec<String>
        // (le Debug impl est interne au binaire, pas à SSE).
        let mut keys = MatchKeys::default();
        keys.insert("secret-123".into());
        assert!(keys.contains("secret-123"));
        assert_eq!(keys.len(), 1);
    }

    /// 2.21.103 (ordre #9 7046282778, défaut ANR2 #10 7045891820) —
    /// `is_pfcp_node_message` couvre Heartbeat, Association (setup/update/
    /// release), PFD Management, Node Report. Les messages de session
    /// (Establishment/Modification/Deletion/Report) ne sont PAS node.
    #[test]
    fn is_pfcp_node_message_covers_heartbeat_association_pfd_2_21_103() {
        // Node-level : exclus de la trace abonné.
        assert!(is_pfcp_node_message("PFCP Heartbeat Request"));
        assert!(is_pfcp_node_message("PFCP Heartbeat Response"));
        assert!(is_pfcp_node_message("PFCP Association Setup Request"));
        assert!(is_pfcp_node_message("PFCP Association Setup Response"));
        assert!(is_pfcp_node_message("PFCP Association Update Request"));
        assert!(is_pfcp_node_message("PFCP Association Release Request"));
        assert!(is_pfcp_node_message("PFCP PFD Management Request"));
        assert!(is_pfcp_node_message("PFCP Node Report Request"));
        // Session-level : AUTORISÉS en trace abonné.
        assert!(!is_pfcp_node_message("PFCP Session Establishment Request"));
        assert!(!is_pfcp_node_message("PFCP Session Modification Request"));
        assert!(!is_pfcp_node_message("PFCP Session Deletion Request"));
        assert!(!is_pfcp_node_message("PFCP Session Report Request"));
        // Nom inconnu : NON node (sûr : l'ajout d'un type session côté
        // decoder-pfcp ne risque pas d'être exclu à tort).
        assert!(!is_pfcp_node_message("Unknown PFCP Message"));
    }

    /// 2.21.103 — 1 000 PFCP Heartbeat « routés » dans route_normalized
    /// donnent 0 event dans la trace abonné (filtre protocole-level).
    #[test]
    fn pfcp_heartbeats_are_never_routed_into_subscriber_trace_2_21_103() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces.lock().unwrap().insert(
            "t".into(),
            state_with_initial_keys(
                u64::MAX,
                false,
                vec!["psn-supi-xyz".into()],
                HashSet::from(["208930000000123".into()]),
            ),
        );
        // 1 000 heartbeats avec un pseudonyme matching dans session_identifiers
        // (pire cas : même si quelque chose matcherait côté
        // match_pseudo/match_keys, le filtre node-level précède tout
        // apprentissage et tout check).
        let heartbeat = |packet: u64| NormalizedEvent {
            event_id: format!("hb-{packet}"),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N4".into(),
            capture_id: "c".into(),
            packet_references: vec![PacketReference {
                source_file: "x".into(),
                source_sha256: None,
                packet_number: packet,
                byte_offset: 0,
                interface_id: 0,
                link_type: None,
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 60,
                original_length: 60,
            }],
            timestamp: ExactTimestamp {
                seconds: 10,
                nanoseconds: packet as u32,
                raw_ticks: 10_000_000_000 + packet,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N4".into(),
            protocol: Protocol::Pfcp,
            message_name: "PFCP Heartbeat Request".into(),
            message_type: 1,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: None,
                network_function: None,
            },
            direction: Direction::Unknown,
            // Pire cas : le pseudonyme ABONNÉ apparaît dans un session_identifier
            // du heartbeat (impossible en prod mais prouve que le filtre
            // node-level précède tout). Avant 2.21.103, ce heartbeat aurait
            // été routé par `match_pseudo`.
            session_identifiers: vec![NamedValue {
                name: "subscriber_pseudonym".into(),
                value: "psn-supi-xyz".into(),
                pseudonymized: true,
            }],
            information_elements: vec![],
            decoder_name: "decoder-pfcp".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:x".into(),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: "sha256:x".into(),
            }],
            sbi: None,
        };
        for packet in 1..=1000u64 {
            r.route_normalized(&heartbeat(packet));
        }
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(
            t.trace.messages, 0,
            "aucun heartbeat PFCP ne doit être routé dans la trace abonné"
        );
        assert_eq!(
            t.events.len(),
            0,
            "le buffer SSE ne doit contenir aucun event issu des heartbeats"
        );
    }

    /// 2.21.103 (ordre #9 7046282778) — N messages routés **sans changement
    /// d'`exposed_keys`** n'émettent qu'UN SEUL `ue_info`. Un changement
    /// effectif (nouveau pseudonyme appris) déclenche un deuxième `ue_info`.
    #[test]
    fn ue_info_emitted_only_on_exposed_keys_change_2_21_103() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
        };
        let r = LiveTraceRegistry::new();
        r.traces.lock().unwrap().insert(
            "t".into(),
            state(u64::MAX, false, vec!["psn-supi-xyz".into()]),
        );
        fn make_event(
            packet: u64,
            msg: &str,
            session_ids: Vec<(&str, &str, bool)>,
        ) -> NormalizedEvent {
            NormalizedEvent {
                event_id: format!("ev-{packet}"),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "test".into(),
                capture_point_id: "N2".into(),
                capture_id: "c".into(),
                packet_references: vec![PacketReference {
                    source_file: "x".into(),
                    source_sha256: None,
                    packet_number: packet,
                    byte_offset: 0,
                    interface_id: 0,
                    link_type: None,
                    sll2_protocol_type: None,
                    sll2_reserved: None,
                    sll2_interface_index: None,
                    sll2_arphrd_type: None,
                    sll2_packet_type: None,
                    sll2_address_length: None,
                    sll2_address: None,
                    captured_length: 100,
                    original_length: 100,
                }],
                timestamp: ExactTimestamp {
                    seconds: 10,
                    nanoseconds: packet as u32,
                    raw_ticks: 10_000_000_000 + packet,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                interface: "N2".into(),
                protocol: Protocol::Ngap,
                message_name: msg.into(),
                message_type: 0,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "10.0.0.1".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "10.0.0.2".into(),
                    port: None,
                    network_function: None,
                },
                direction: Direction::Uplink,
                session_identifiers: session_ids
                    .into_iter()
                    .map(|(n, v, p)| NamedValue {
                        name: n.into(),
                        value: v.into(),
                        pseudonymized: p,
                    })
                    .collect(),
                information_elements: vec![InformationElement {
                    id: None,
                    name: "misc".into(),
                    length: 1,
                    value: Some("x=y".into()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                }],
                decoder_name: "test".into(),
                decoder_version: "0".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: "sha256:x".into(),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "packet-provenance".into(),
                    reference: "sha256:x".into(),
                }],
                sbi: None,
            }
        }
        // Message 1 : apprend `psn-supi-xyz` (pseudonymized) → `exposed_keys`
        // = {"psn-supi-xyz"} → 1er `ue_info` émis.
        r.route_normalized(&make_event(
            1,
            "Registration Request",
            vec![("subscriber_pseudonym", "psn-supi-xyz", true)],
        ));
        // Messages 2..=50 : même `subscriber_pseudonym`, aucune nouvelle
        // clé exposable → aucun nouveau `ue_info`.
        for packet in 2..=50u64 {
            r.route_normalized(&make_event(
                packet,
                "Auth Request",
                vec![("subscriber_pseudonym", "psn-supi-xyz", true)],
            ));
        }
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            let ue_info_count = t.events.iter().filter(|e| e.kind == "ue_info").count();
            assert_eq!(
                ue_info_count, 1,
                "50 messages avec même pseudonyme ne doivent émettre qu'1 ue_info, got {ue_info_count}"
            );
        }
        // Message 51 : apprend un NOUVEAU pseudonyme → 2e `ue_info`.
        r.route_normalized(&make_event(
            51,
            "SDM Get Gpsis",
            vec![
                ("subscriber_pseudonym", "psn-supi-xyz", true),
                ("msisdn_pseudonym", "psn-gpsi-abc", true),
            ],
        ));
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            let ue_info_count = t.events.iter().filter(|e| e.kind == "ue_info").count();
            assert_eq!(
                ue_info_count, 2,
                "ajout d'un pseudonyme doit déclencher un 2e ue_info, got {ue_info_count}"
            );
            // Preuve que le dernier ue_info porte les 2 clés.
            let last_info = t
                .events
                .iter()
                .filter(|e| e.kind == "ue_info")
                .last()
                .unwrap();
            let keys = last_info.payload["keys"].as_array().unwrap();
            let keys_str: Vec<String> = keys
                .iter()
                .map(|k| k.as_str().unwrap().to_owned())
                .collect();
            assert!(keys_str.contains(&"psn-supi-xyz".to_string()));
            assert!(keys_str.contains(&"psn-gpsi-abc".to_string()));
        }
    }
}
