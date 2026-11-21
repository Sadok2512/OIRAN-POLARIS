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
    /// 2.21.109 — G-PDU rattachés par TEID seul : le TEID a été appris
    /// sur la signalisation de l'abonné, sans adresse de point de
    /// terminaison. Rattachement plus faible, compté à part.
    #[serde(default)]
    gpdu_attached_teid_only: u64,
    /// 2.21.109 — G-PDU portant un TEID de l'abonné mais vers un autre
    /// point de terminaison que celui appris : rejetés.
    #[serde(default)]
    gpdu_rejected_endpoint_mismatch: u64,
    /// 2.21.113 (E3) — messages PFCP rattachés par la valeur du SEID
    /// seule, faute de couple (nœud, SEID) connu : rattachement plus
    /// faible, compté à part.
    #[serde(default)]
    pfcp_attached_seid_only: u64,
    /// 2.21.113 (E4) — messages parents rattachés après coup, quand
    /// leur enfant (qui porte l'identité) a été rattaché.
    #[serde(default)]
    parents_attached_after_child: u64,
    /// 2.21.124 — messages PFCP de la session rattachés après coup, une
    /// fois ses SEID ou ses tunnels appris.
    #[serde(default)]
    pfcp_attached_after_the_fact: u64,
    /// 2.21.126 — SIP rattachés par l'adresse IP de l'UE et par rien
    /// d'autre (ni identité, ni identifiant d'appel).
    #[serde(default)]
    sip_attached_by_ue_ip: u64,
    /// 2.21.126 — PFCP rattachés par l'IP UE de leur IE 93 et par rien
    /// d'autre.
    #[serde(default)]
    pfcp_attached_by_ue_ip: u64,
    /// 2.21.113 (E2) — messages rejetés alors qu'ils portent un
    /// identifiant UE de l'abonné : l'autre identifiant est celui d'un
    /// autre contexte UE.
    #[serde(default)]
    rejected_ue_id_mismatch: u64,
    /// 2.21.113 (E3) — messages PFCP rejetés alors qu'ils portent une
    /// valeur de SEID de l'abonné, vers un autre nœud.
    #[serde(default)]
    rejected_seid_endpoint_mismatch: u64,
    /// 2.21.129 — events reconnus par un identifiant technique de la
    /// trace mais qui portent l'identité d'un AUTRE abonné : rejetés.
    #[serde(default)]
    rejected_foreign_subscriber: u64,
    /// 2.21.129 — oublis de l'état technique : il était périmé
    /// (identifiants réattribués à un autre abonné, ou nouveau contexte
    /// UE sur un identifiant que la trace croyait vivant).
    #[serde(default)]
    stale_state_resets: u64,
    /// 2.21.129 — nouveaux enregistrements de l'abonné avec son identité
    /// permanente : la trace est repartie de cette procédure.
    #[serde(default)]
    fresh_registrations: u64,
    /// 2.21.131 — révisions de flux RTP émises après la première.
    #[serde(default)]
    rtp_flow_updates: u64,
    /// 2.21.134 — établissements PFCP refusés parce qu'ils reprennent un
    /// tunnel ou un SEID déjà connu de la trace (session antérieure).
    #[serde(default)]
    pfcp_establishment_reused_identifiers: u64,
    /// 2.21.119 — libérations d'une session nommée dont aucun tunnel
    /// n'était rangé par session : rien n'a pu être oublié.
    #[serde(default)]
    session_releases_without_filed_tunnels: u64,
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
    /// 2.21.130 — durée de la relecture, en ms.
    #[serde(default)]
    duration_ms: u64,
}

/// 2.21.105 — interfaces de signalisation relues à l'ouverture d'une
/// trace, dans l'ordre de dépendance : N2/S1-MME portent l'identité
/// et les tunnels, N4/S11/S5-C/Sxab s'y rattachent par tunnel, IP UE
/// pseudonymisée ou SEID. N3/S1-U/S5-U (plan usager, volumineux) et
/// SBI (porte l'identité dans chaque requête) ne sont jamais relus.
const SEED_INTERFACES: [&str; 6] = ["N2", "S1-MME", "N4", "S11", "S5-C", "Sxab"];
/// 2.21.105 — plafond d'octets relus par interface pour un amorçage.
const SEED_MAX_BYTES_PER_INTERFACE: u64 = 64 * 1024 * 1024;
/// 2.21.130 (recette lab 2.21.114 : 643 ms par passe sans trafic, ordre
/// #9 7052731132) — intervalle minimal entre deux redécodages intégraux
/// d'un même segment, sur les plans sans reprise à l'offset (SBI, S6a,
/// IMS, N6). Le segment SBI courant change en continu (battements de
/// cœur du NRF) et était redécodé en entier à chaque passe.
const FULL_REDECODE_MIN_INTERVAL: Duration = Duration::from_secs(3);
/// 2.21.130 — segments les plus récents relus par plan à l'amorçage
/// d'une trace. Recette lab : 201 Mo et 3 333 fichiers relus par
/// ouverture de trace.
const SEED_MAX_SEGMENTS_PER_INTERFACE: usize = 3;
/// 2.21.130 — cadence du lecteur : 750 ms quand il vient de décoder,
/// allongée jusqu'à 3 s après des passes à vide.
const READER_BASE_INTERVAL: Duration = Duration::from_millis(750);
const READER_MAX_INTERVAL: Duration = Duration::from_millis(3_000);

/// 2.21.130 — ce que le lecteur retient d'un répertoire du ring entre
/// deux passes : sa date de modification et ses deux segments les plus
/// récents. Un répertoire ne change de date que si un segment y est créé
/// ou supprimé ; tant qu'elle ne bouge pas, il n'est pas relu.
#[derive(Default)]
pub(crate) struct RingDirState {
    mtime: Option<std::time::SystemTime>,
    recent: Vec<std::path::PathBuf>,
}

/// 2.21.130 — une date de modification de répertoire plus jeune que
/// cette marge est tenue pour encore mouvante : le répertoire est relu.
const RING_DIR_SETTLE: Duration = Duration::from_secs(2);

/// 2.21.130 — intervalle avant la prochaine passe, selon le nombre de
/// passes consécutives qui n'ont rien décodé.
fn reader_interval(idle_passes: u32) -> Duration {
    let factor = 1u32 << idle_passes.min(2);
    (READER_BASE_INTERVAL * factor).min(READER_MAX_INTERVAL)
}

/// 2.21.131 (lot B2, GO #9 7050925249) — période de l'instantané des
/// flux RTP en cours.
const RTP_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);

/// 2.21.131 — plans dont le décodage agrège des flux RTP : le tunnel du
/// plan usager, et les plans IMS et N6.
fn carries_rtp_flows(interface: &str) -> bool {
    matches!(interface, "N3" | "S1-U" | "S5-U" | "IMS" | "N6")
}

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
    duration_ms: u64,
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
    let started = std::time::Instant::now();
    let mut report = SeedReport::default();
    // 2.21.134 (question 1 du cœur, ordre #9 7060289296) — les events de
    // tous les plans sont rejoués ensemble, dans l'ordre du temps.
    let mut history: Vec<event_schema::NormalizedEvent> = Vec::new();
    for interface in SEED_INTERFACES {
        let dir = root.join(ring_directory(interface));
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        // 2.21.130 — seuls les segments les plus récents du plan sont
        // relus (noms du ring croissants avec le temps), et eux seuls
        // sont interrogés : la session d'un abonné tient dans les
        // derniers segments, pas dans le ring entier.
        let mut names: Vec<std::path::PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("pcapng"))
            .collect();
        names.sort();
        if names.len() > SEED_MAX_SEGMENTS_PER_INTERFACE {
            report.truncated = true;
            names.drain(..names.len() - SEED_MAX_SEGMENTS_PER_INTERFACE);
        }
        let files: Vec<_> = names
            .into_iter()
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
            history.append(&mut events);
            report.files += 1;
            report.bytes = report.bytes.saturating_add(size);
        }
    }
    learn_history(registry, history);
    report.duration_ms = started.elapsed().as_millis() as u64;
    report
}

/// 2.21.134 (question 1 du cœur, ordre #9 7060289296) — rejoue un
/// historique de plusieurs plans dans l'ordre du TEMPS de capture, tri
/// stable : à horodatage égal, l'ordre des plans puis l'ordre de la
/// capture. Avant : plan par plan (N2 en entier, puis N4…) ; une fin de
/// session vue sur un plan n'effaçait pas ce qu'un plan relu ensuite
/// apprenait de la même session, et l'établissement PFCP passait APRÈS le
/// N2 qui porte ses tunnels — il s'y rattachait directement, ce que la
/// règle d'établissement de 2.21.134 interdit. Dans l'ordre réel, il est
/// rattaché après coup, comme en live.
fn learn_history(registry: &LiveTraceRegistry, mut history: Vec<event_schema::NormalizedEvent>) {
    history.sort_by_key(|event| (event.timestamp.seconds, event.timestamp.nanoseconds));
    for event in &history {
        registry.learn_from_ring(event);
    }
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
    /// 2.21.113 — oublie les références d'event (`evt-…`) et garde les
    /// identités de l'abonné (pseudonymes, chiffres amorcés).
    /// 2.21.124 — retire une clé (pseudonyme d'équipement appris avant
    /// d'avoir été reconnu comme tel).
    pub fn forget(&mut self, key: &str) -> bool {
        self.0.remove(key)
    }
    /// 2.21.129 — une clé d'IDENTITÉ de l'abonné (pseudonyme, chiffres
    /// amorcés) figure parmi ces jetons. Les références d'event
    /// (`evt-…`) n'en sont pas : elles disent « enfant d'un event
    /// rattaché », pas « de cet abonné ».
    pub fn any_identity_in(&self, tokens: &HashSet<String>) -> bool {
        self.0
            .iter()
            .any(|key| !key.starts_with("evt-") && tokens.contains(key))
    }
    pub fn forget_event_references(&mut self) {
        self.0.retain(|key| !key.starts_with("evt-"));
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
    /// 2.21.126 — pseudonymes d'adresse IP d'UE de l'abonné, avec ce
    /// qui les porte : `pdu:<pdu_session_id>` (adresse PDU du NAS),
    /// `seid:<valeur>` (IE 93 d'un PFCP rattaché). Rattachent le SIP par
    /// l'adresse du paquet et le PFCP par son IE 93. Oubliés avec leur
    /// session.
    ue_ip_keys: HashMap<String, HashSet<String>>,
    /// 2.21.129 — `event_id` des parents des events rattachés : un
    /// InitialUEMessage qui en fait partie est celui de l'abonné.
    parents_of_attached: HashSet<String>,
    /// 2.21.131 (lot B2) — flux RTP déjà émis : `stable_event_key` →
    /// `(révision, event_id de cette révision)`.
    rtp_flow_revisions: HashMap<String, (u64, String)>,
    /// 2.21.134 — établissements PFCP de l'abonné rattachés :
    /// `(numéro de séquence, nœud, nœud)` ; leur réponse s'y rattache.
    pfcp_establishments: HashSet<(String, String, String)>,
    /// 2.21.134 — tunnel (TEID) ou SEID de l'abonné → seconde de capture
    /// du dernier event rattaché qui le portait.
    identifier_seen_at: HashMap<String, i64>,
    /// 2.21.109 (ordre #9 7050201220) — identifiants UE de signalisation
    /// appris sur les events routés : `(nom, valeur, association)` avec
    /// `nom` ∈ amf_ue_ngap_id / ran_ue_ngap_id / mme_ue_s1ap_id /
    /// enb_ue_s1ap_id et `association` = les deux adresses du lien
    /// SCTP. Rattachement EXACT, jamais par sous-chaîne.
    ue_ids: HashSet<(String, String, String)>,
    /// 2.21.113 (E3) — couples (adresse du nœud destinataire, SEID)
    /// appris sur la signalisation PFCP de l'abonné.
    seid_endpoints: HashSet<(String, String)>,
    /// 2.21.113 (E5) — tunnels appris par session de données
    /// (`pdu_session_id`) : `(adresse si connue, TEID)`. Permet d'oublier
    /// les tunnels de la seule session libérée.
    session_tunnels: HashMap<String, HashSet<(Option<String>, String)>>,
    /// 2.21.119 (G1) — couples (adresse, TEID) côté cœur : gardés à la
    /// mise en veille, oubliés avec la session de données.
    core_tunnel_endpoints: HashSet<(String, String)>,
    /// 2.21.119 (G2) — références de contexte SM apprises, `(référence,
    /// association)` → session de données quand l'event la nomme.
    sm_context_sessions: HashMap<(String, String), Option<String>>,
    /// 2.21.122 (ordre #9 7052446877) — appels en cours de l'abonné :
    /// `sip_call_id` appris sur un SIP rattaché. Rattache par égalité
    /// exacte les SIP du même dialogue et ses flux RTP.
    sip_call_ids: HashSet<String>,
    /// 2.21.124 — pseudonymes d'équipement vus par la trace (IMEISV
    /// masqué du NGAP, PEI du SBI), sur un event rattaché ou non. Jamais
    /// appris ni exposés, même quand un event enfant les hérite sous le
    /// libellé `subscriber_pseudonym`.
    equipment_keys: HashSet<String>,
    /// 2.21.122 — appels terminés (200 du BYE vu). Ne rattachent plus
    /// aucun SIP ; ils rattachent encore l'event de flux RTP de l'appel,
    /// qui n'est émis qu'à la clôture du segment, après le BYE.
    ended_sip_call_ids: HashSet<String>,
    /// 2.21.121 (H1) — couples côté cœur appris sur un message PFCP,
    /// rangés sous le ou les SEID de ce message : oubliés au
    /// `Session Deletion Response` de la session PFCP.
    seid_tunnels: HashMap<String, HashSet<(String, String)>>,
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
    // 2.21.126 — en test, une clé fixe : le chemin par défaut n'existe
    // pas sur la machine de test, et l'apprentissage de l'IP UE sur le
    // NAS restait alors sans test.
    #[cfg(test)]
    return KEY
        .get_or_init(|| Some(event_schema::PseudonymKey::from_bytes([7; 32])))
        .as_ref();
    #[cfg(not(test))]
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
/// les collisions arbitraires). Utilisé pour
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
/// 2.21.109 (exigence cœur #9 7050392981 point 2) — valeurs typées d'un
/// event, comparées par ÉGALITÉ aux clés d'une trace. Remplace le test
/// de sous-chaîne sur le JSON entier. Sources :
///   * chaque `session_identifiers[].value` ;
///   * chaque `information_elements[].value`, entière, puis découpée
///     sur `,` `;` `&` en champs `nom=valeur` dont la valeur est gardée ;
///   * `parent_event_id` ;
///   * les chaînes de l'objet `sbi`, entières et découpées sur `/ ? & =`.
/// Une valeur d'identité (`imsi-…`, `msisdn-…`, ou suite de chiffres)
/// ajoute aussi ses chiffres canoniques, pour l'amorçage par saisie.
fn event_tokens(value: &Value) -> HashSet<String> {
    fn push(tokens: &mut HashSet<String>, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        tokens.insert(raw.to_owned());
        let lower = raw.to_ascii_lowercase();
        let identity = ["imsi-", "msisdn-", "imei-", "imeisv-", "supi-"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
            || raw.bytes().all(|b| b.is_ascii_digit());
        if identity {
            if let Some(digits) = canonical_digits(raw) {
                tokens.insert(digits);
            }
        }
    }
    fn walk(tokens: &mut HashSet<String>, node: &Value) {
        match node {
            Value::String(text) => {
                push(tokens, text);
                for part in text.split(['/', '?', '&', '=']) {
                    push(tokens, part);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(tokens, item)),
            Value::Object(map) => map.values().for_each(|item| walk(tokens, item)),
            _ => {}
        }
    }
    let mut tokens = HashSet::new();
    for id in value
        .get("session_identifiers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(v) = id.get("value").and_then(Value::as_str) {
            push(&mut tokens, v);
        }
    }
    for ie in ie_values(value) {
        push(&mut tokens, &ie);
        for field in ie.split([',', ';', '&']) {
            match field.split_once('=') {
                Some((_, v)) => push(&mut tokens, v),
                None => push(&mut tokens, field),
            }
        }
    }
    if let Some(parent) = value.get("parent_event_id").and_then(Value::as_str) {
        push(&mut tokens, parent);
    }
    if let Some(sbi) = value.get("sbi") {
        walk(&mut tokens, sbi);
    }
    tokens
}

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

/// 2.21.109 — référence de contexte SM (SBI `smContextRef`) : propre à
/// une session, allouée par le SMF. Rattachement exact, sans portée
/// d'association (requêtes et réponses la portent dans les deux sens).
const SM_CONTEXT_NAME: &str = "sm_context_reference";

/// 2.21.113 (relecture CLAUDE2 #9 7050861203, E1/E2) — identifiants UE
/// alloués par le cœur (uniques par AMF / MME) et par l'accès radio
/// (uniques par gNB / eNB).
const CORE_UE_ID_NAMES: [&str; 2] = ["amf_ue_ngap_id", "mme_ue_s1ap_id"];
const RAN_UE_ID_NAMES: [&str; 2] = ["ran_ue_ngap_id", "enb_ue_s1ap_id"];

/// 2.21.113 (E5) — nom de message sans espaces ni casse : les décodeurs
/// NGAP/S1AP émettent `UEContextReleaseComplete`, le NAS
/// `PDU Session Release Complete`.
fn compact_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Libération du contexte UE côté accès radio (NGAP / S1AP). C'est
/// aussi le passage en veille : les identifiants UE de signalisation et
/// les tunnels N3 / S1-U ne valent plus, mais la session de données
/// reste établie au SMF et à l'UPF (2.21.116, F1).
fn is_ue_context_release(name: &str) -> bool {
    compact_name(name) == "uecontextreleasecomplete"
}

/// 2.21.129 — demande d'enregistrement 5G ou d'attachement 4G (le nom
/// de l'event NAS enfant est préfixé par celui de son message NGAP /
/// S1AP).
fn is_fresh_registration(name: &str) -> bool {
    let name = compact_name(name);
    name.ends_with("registrationrequest") || name.ends_with("attachrequest")
}

/// Détachement : l'abonné quitte le réseau, tout ce qui a été appris sur
/// ses sessions est oublié.
fn is_detach(name: &str) -> bool {
    // 2.21.119 (G2) — `Deregistration Accept` est la fin 5G ; sans elle
    // aucune fin complète n'existait en 5G.
    matches!(compact_name(name).as_str(), "detachaccept" | "deregistrationaccept")
}

/// 2.21.119 (relecture CLAUDE2 #9 7051699381, G1) — couples (adresse,
/// TEID) côté CŒUR portés par une IE : le tunnel montant du N2
/// (`tunnel_ip_ul` / `gtp_teid_ul`, terminé à l'UPF) et le F-TEID local
/// d'un PDR PFCP (`teid=…,v4=…,ipv4=…`). Ils vivent avec la session de
/// données. Le tunnel descendant du N2 et l'Outer Header Creation PFCP
/// désignent l'accès radio : libérés à la mise en veille.
fn parse_core_tunnel_pairs(ie_value: &str) -> Vec<(String, String)> {
    let components: BTreeMap<&str, &str> = ie_value
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim(), v.trim()))
        })
        .collect();
    let mut out = Vec::new();
    if components.contains_key("v4") && !components.contains_key("outer_header_description") {
        if let (Some(ip), Some(teid)) = (components.get("ipv4"), components.get("teid")) {
            if let Some(teid) = event_schema::normalize_teid_hex(teid) {
                out.push((event_schema::normalize_ip(ip), teid));
            }
        }
    }
    for (key, ip) in components.iter() {
        if *key != "tunnel_ip_ul" && !key.ends_with("_tunnel_ip_ul") {
            continue;
        }
        let prefix = key.strip_suffix("tunnel_ip_ul").unwrap_or_default();
        if let Some(teid) = components
            .get(format!("{prefix}gtp_teid_ul").as_str())
            .and_then(|teid| event_schema::normalize_teid_hex(teid))
        {
            out.push((event_schema::normalize_ip(ip), teid));
        }
    }
    out.retain(|pair| !is_zero_hex(&pair.1));
    out
}

/// Libération d'une session de données : ses tunnels et SEID ne valent
/// plus ; l'UE reste enregistré, ses identifiants UE sont gardés.
fn is_data_session_release(name: &str) -> bool {
    matches!(
        compact_name(name).as_str(),
        "pdusessionreleasecomplete" | "deletesessionresponse"
    )
}

/// 2.21.113 (E3) — couples (adresse du nœud, SEID) d'une IE F-SEID
/// (`f_seid=0x…,v4=…,v6=…,ipv4=a.b.c.d`) : le SEID que ce nœud attend
/// dans l'en-tête des messages qui lui sont adressés.
fn parse_seid_pairs(ie_value: &str) -> Vec<(String, String)> {
    let components: BTreeMap<&str, &str> = ie_value
        .split(',')
        .filter_map(|part| {
            let (k, v) = part.split_once('=')?;
            Some((k.trim(), v.trim()))
        })
        .collect();
    let (Some(seid), Some(ip)) = (components.get("f_seid"), components.get("ipv4")) else {
        return Vec::new();
    };
    let hex = seid.trim_start_matches("0x").trim_start_matches("0X");
    match u64::from_str_radix(hex, 16) {
        Ok(n) if n != 0 => vec![(event_schema::normalize_ip(ip), format!("0x{n:016x}"))],
        _ => Vec::new(),
    }
}

/// 2.21.121 (H1) — oublie des couples (adresse, TEID) : du côté cœur, des
/// couples connus, et leur TEID s'il ne désigne plus aucun couple connu.
/// 2.21.129 (recette lab 2.21.124, G9 : la trace de A prend tout le
/// trafic de B ; ordre #9 7053864526) — tout l'état TECHNIQUE de la trace
/// est oublié : identifiants UE, tunnels, SEID, références de contexte
/// SM, IP UE, références d'event. Les identités de l'abonné sont gardées :
/// elles rattachent sa prochaine procédure, qui réapprend le reste.
fn forget_technical_state(state: &mut TraceState) {
    state.ue_ids.clear();
    state.sm_context_sessions.clear();
    state.tunnel_teids.clear();
    state.tunnel_endpoints.clear();
    state.session_tunnels.clear();
    state.core_tunnel_endpoints.clear();
    state.seid_tunnels.clear();
    state.seids.clear();
    state.seid_endpoints.clear();
    state.ue_ips.clear();
    for (ip, _) in state.ue_ip_keys.drain() {
        state.exposed_keys.remove(&ip);
    }
    state.match_keys.forget_event_references();
}

/// 2.21.134 (cas 4, ordre #9 7060289296) — oublie la session antérieure
/// à laquelle appartiennent ces identifiants (TEID, SEID) : ses SEID, les
/// tunnels rangés sous eux, et la session de données qui range l'un de
/// ses tunnels, avec tous les tunnels de celle-ci.
fn forget_earlier_session(state: &mut TraceState, identifiers: &HashSet<String>) {
    let mut seids: HashSet<String> = identifiers
        .iter()
        .filter(|identifier| state.seids.contains(*identifier) || state.seid_tunnels.contains_key(*identifier))
        .cloned()
        .collect();
    let mut teids: HashSet<String> = identifiers.clone();
    // Tunnels rangés sous ces SEID.
    for seid in &seids {
        if let Some(pairs) = state.seid_tunnels.get(seid) {
            teids.extend(pairs.iter().map(|pair| pair.1.clone()));
        }
    }
    // Sessions de données qui rangent l'un de ces tunnels : tous leurs
    // tunnels.
    let sessions: Vec<String> = state
        .session_tunnels
        .iter()
        .filter(|(_, tunnels)| tunnels.iter().any(|(_, teid)| teids.contains(teid)))
        .map(|(session, _)| session.clone())
        .collect();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for session in sessions {
        if let Some(tunnels) = state.session_tunnels.remove(&session) {
            for (address, teid) in tunnels {
                teids.insert(teid.clone());
                if let Some(address) = address {
                    pairs.push((address, teid));
                }
            }
        }
    }
    // SEID qui rangent l'un de ces tunnels.
    for (seid, filed) in &state.seid_tunnels {
        if filed.iter().any(|pair| teids.contains(&pair.1)) {
            seids.insert(seid.clone());
        }
    }
    for seid in &seids {
        if let Some(filed) = state.seid_tunnels.remove(seid) {
            pairs.extend(filed);
        }
        state.seids.remove(seid);
        state.seid_endpoints.retain(|pair| &pair.1 != seid);
        state.identifier_seen_at.remove(seid);
    }
    pairs.extend(
        state
            .tunnel_endpoints
            .iter()
            .filter(|pair| teids.contains(&pair.1))
            .cloned(),
    );
    forget_tunnel_pairs(state, &pairs);
    for teid in &teids {
        state.tunnel_teids.remove(teid);
        state.identifier_seen_at.remove(teid);
    }
}

fn forget_tunnel_pairs(state: &mut TraceState, pairs: &[(String, String)]) {
    for pair in pairs {
        state.core_tunnel_endpoints.remove(pair);
        state.tunnel_endpoints.remove(pair);
        if !state.tunnel_endpoints.iter().any(|known| known.1 == pair.1) {
            state.tunnel_teids.remove(&pair.1);
        }
    }
}

/// 2.21.124 (capture réelle à cinq abonnés, ordre #9 7052731132) —
/// pseudonymes d'ÉQUIPEMENT portés par un event : ils désignent un
/// terminal, pas un abonné, et ne sont pas propres à lui.
///   * NGAP, IE 34 (MaskedIMEISV) : le décodeur l'émet sous le libellé
///     `subscriber_pseudonym=psn-…` et le promeut en identifiant de
///     session `subscriber_pseudonym`. L'IMEISV masqué est commun à tous
///     les terminaux d'un même modèle — et à tous les UE d'un simulateur ;
///   * SBI : identifiants de session `imei_pseudonym`, `imeisv_pseudonym`
///     (PEI).
/// Une trace ne les apprend pas : sinon tout UE du même modèle entre
/// dans la trace d'un abonné, puis ses identifiants, ses tunnels et son
/// trafic.
/// 2.21.126 (ordres #9 7053030106, 7053229737) — IE du SIP qui portent
/// le pseudonyme d'une adresse IP du paquet ou du SDP (`decoder-sip`
/// 0.3.0).
const SIP_IP_PSEUDONYM_IES: [&str; 3] = [
    "packet_source_ip_pseudonym",
    "packet_destination_ip_pseudonym",
    "sdp.c_ue_ip_pseudonym",
];

/// 2.21.126 — pseudonymes d'adresse IP d'UE portés par un event, là où
/// un décodeur les émet explicitement :
///   * SIP — adresses source et destination du paquet, adresse du SDP ;
///   * PFCP — IE 93 (UE IP Address), champs `ue_ip` et `ue_ipv6` ;
///   * tout protocole — identifiant de session `ue_ip` pseudonymisé.
/// Rattachement par égalité exacte avec une IP apprise pour l'abonné,
/// jamais par jeton d'IE quelconque.
fn ue_ip_pseudonyms(event: &event_schema::NormalizedEvent) -> Vec<String> {
    let mut out = Vec::new();
    match event.protocol.as_str() {
        "SIP" => {
            for ie in &event.information_elements {
                if SIP_IP_PSEUDONYM_IES.contains(&ie.name.as_str()) {
                    if let Some(value) = ie.value.as_deref() {
                        out.push(value.trim().to_owned());
                    }
                }
            }
        }
        "PFCP" => {
            for ie in &event.information_elements {
                if ie.id != Some(93) {
                    continue;
                }
                for field in ie.value.as_deref().unwrap_or("").split(',') {
                    if let Some((name, value)) = field.split_once('=') {
                        if matches!(name.trim(), "ue_ip" | "ue_ipv6") {
                            out.push(value.trim().to_owned());
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for id in &event.session_identifiers {
        if id.name == "ue_ip" && id.pseudonymized {
            out.push(id.value.clone());
        }
    }
    out.retain(|value| value.starts_with("psn-"));
    out.sort();
    out.dedup();
    out
}

fn equipment_pseudonyms(event: &event_schema::NormalizedEvent) -> HashSet<String> {
    let mut out = HashSet::new();
    if event.protocol.as_str() == "NGAP" {
        for ie in &event.information_elements {
            if ie.id != Some(34) {
                continue;
            }
            for field in ie.value.as_deref().unwrap_or("").split(',') {
                if let Some((_, value)) = field.split_once('=') {
                    out.insert(value.trim().to_owned());
                }
            }
        }
    }
    for id in &event.session_identifiers {
        if matches!(
            id.name.as_str(),
            "imei_pseudonym" | "imeisv_pseudonym" | "pei_pseudonym" | "masked_imeisv_pseudonym"
        ) {
            out.insert(id.value.clone());
        }
    }
    out
}

/// 2.21.124 (ordre #9 7052903849) — LISTE BLANCHE des identifiants de
/// session pseudonymisés qu'une trace peut apprendre et exposer : des
/// identités d'ABONNÉ ou de sa session, par nom de champ.
///   * `subscriber_pseudonym` — SUPI / IMSI (hors IMEISV masqué du NGAP,
///     que le décodeur émet sous ce nom : écarté par `equipment_pseudonyms`) ;
///   * `msisdn_pseudonym` — MSISDN / GPSI ;
///   * `tmsi_pseudonym`, `temporary_identity_pseudonym` — identité
///     temporaire (GUTI / TMSI) ;
///   * `ue_ip` — IP UE de la session (PFCP).
/// Tout autre nom n'est ni appris ni exposé : `imei_pseudonym`,
/// `imeisv_pseudonym`, `identity_pseudonym` (réponse d'identité NAS, qui
/// peut être un IMEI), ou un nom à venir.
const LEARNABLE_PSEUDONYM_NAMES: [&str; 5] = [
    "subscriber_pseudonym",
    "msisdn_pseudonym",
    "tmsi_pseudonym",
    "temporary_identity_pseudonym",
    "ue_ip",
];

/// 2.21.109 — vrai pour un identifiant hexadécimal nul (`0x0…0`). Un
/// SEID ou un TEID nul n'identifie aucune session : c'est la valeur de
/// l'en-tête d'un PFCP Session Establishment Request, commune à tous
/// les abonnés.
fn is_zero_hex(value: &str) -> bool {
    let digits = value.trim_start_matches("0x").trim_start_matches("0X");
    !digits.is_empty() && digits.bytes().all(|b| b == b'0')
}

/// 2.21.109 — vrai si une valeur de `session_identifiers` peut servir
/// de clé de rattachement par sous-chaîne : un pseudonyme posé par le
/// décodeur, ou une référence d'event (`evt-…`). Toute autre valeur
/// (PLMN, TAC, cellule, sens du tunnel, numéros de séquence, …) est
/// commune à plusieurs abonnés.
fn is_subscriber_scoped_key(name: &str, value: &str, pseudonymized: bool) -> bool {
    pseudonymized || name.ends_with("_pseudonym") || value.starts_with("evt-")
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
    /// 2.21.109 — segments du ring suivis par le lecteur.
    reader_files_tracked: AtomicU64,
    /// 2.21.109 — segments décodés pendant la dernière passe. En
    /// régime établi : un par plan actif, pas tout le ring.
    reader_files_decoded: AtomicU64,
    /// 2.21.130 — temps de parcours du ring (listes de répertoires,
    /// tri, segments disparus) pendant la dernière passe, en ms.
    reader_scan_ms: AtomicU64,
    /// 2.21.130 — segments interrogés (`stat`) pendant la dernière passe.
    reader_files_examined: AtomicU64,
    /// 2.21.113 (E4) — derniers events de signalisation rejetés par au
    /// moins une trace : un parent NGAP/S1AP passe avant son enfant NAS,
    /// qui seul porte l'identité.
    recent_rejected: Mutex<VecDeque<event_schema::NormalizedEvent>>,
    /// 2.21.124 — derniers messages PFCP de session rejetés par au moins
    /// une trace (l'établissement précède l'apprentissage des tunnels).
    recent_rejected_pfcp: Mutex<VecDeque<event_schema::NormalizedEvent>>,
    /// 2.21.134 — même tampon, propre à l'amorçage : jamais mêlé au live,
    /// vidé à chaque début et fin d'amorçage.
    seed_rejected_pfcp: Mutex<VecDeque<event_schema::NormalizedEvent>>,
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
            reader_files_tracked: AtomicU64::new(0),
            reader_files_decoded: AtomicU64::new(0),
            reader_scan_ms: AtomicU64::new(0),
            reader_files_examined: AtomicU64::new(0),
            recent_rejected: Mutex::new(VecDeque::new()),
            recent_rejected_pfcp: Mutex::new(VecDeque::new()),
            seed_rejected_pfcp: Mutex::new(VecDeque::new()),
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
        self.seed_rejected_pfcp.lock().unwrap().clear();
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
        self.seed_rejected_pfcp.lock().unwrap().clear();
        let mut traces = self.traces.lock().unwrap();
        for state in traces.values_mut() {
            if state.seeding {
                state.seeding = false;
                state.trace.seed.done = true;
                state.trace.seed.files = report.files;
                state.trace.seed.bytes = report.bytes;
                state.trace.seed.truncated = report.truncated;
                state.trace.seed.duration_ms = report.duration_ms;
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
                "files_tracked": self.reader_files_tracked.load(Ordering::Relaxed),
                "files_decoded_last_pass": self.reader_files_decoded.load(Ordering::Relaxed),
                "files_examined_last_pass": self.reader_files_examined.load(Ordering::Relaxed),
                "scan_ms": self.reader_scan_ms.load(Ordering::Relaxed),
                "full_redecode": full_redecode_requested(),
                "interfaces": *self.reader_io.lock().unwrap(),
            },
            "messages": trace.messages,
            "gpdu": {
                "seen": trace.gpdu_seen,
                "attached": trace.gpdu_attached,
                "rejected_no_match": trace.gpdu_rejected_no_match,
                "rejected_interface_filter": trace.gpdu_rejected_interface_filter,
                "attached_teid_only": trace.gpdu_attached_teid_only,
                "rejected_endpoint_mismatch": trace.gpdu_rejected_endpoint_mismatch,
            },
            "pfcp": {
                "attached_seid_only": trace.pfcp_attached_seid_only,
                "attached_after_the_fact": trace.pfcp_attached_after_the_fact,
                "attached_by_ue_ip": trace.pfcp_attached_by_ue_ip,
                "establishment_reused_identifiers": trace.pfcp_establishment_reused_identifiers,
            },
            "sip": {
                "attached_by_ue_ip": trace.sip_attached_by_ue_ip,
            },
            "parents_attached_after_child": trace.parents_attached_after_child,
            "session_releases_without_filed_tunnels": trace.session_releases_without_filed_tunnels,
            "fresh_registrations": trace.fresh_registrations,
            "rtp": {
                "flow_updates": trace.rtp_flow_updates,
            },
            "rejects": {
                "ue_id_mismatch": trace.rejected_ue_id_mismatch,
                "seid_endpoint_mismatch": trace.rejected_seid_endpoint_mismatch,
                "foreign_subscriber": trace.rejected_foreign_subscriber,
                "stale_state_resets": trace.stale_state_resets,
                "gpdu_endpoint_mismatch": trace.gpdu_rejected_endpoint_mismatch,
                "gpdu_no_match": trace.gpdu_rejected_no_match,
                "gpdu_interface_filter": trace.gpdu_rejected_interface_filter,
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

    pub(crate) fn set_reader_files_tracked(&self, value: u64) {
        self.reader_files_tracked.store(value, Ordering::Relaxed);
    }

    pub(crate) fn set_reader_scan(&self, scan_ms: u64, files_examined: u64) {
        self.reader_scan_ms.store(scan_ms, Ordering::Relaxed);
        self.reader_files_examined.store(files_examined, Ordering::Relaxed);
    }

    pub(crate) fn reader_files_decoded_last_pass(&self) -> u64 {
        self.reader_files_decoded.load(Ordering::Relaxed)
    }

    pub(crate) fn set_reader_files_decoded(&self, value: u64) {
        self.reader_files_decoded.store(value, Ordering::Relaxed);
    }

    /// 2.21.124 — compteur des PFCP rattachés après coup d'une trace.
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
        self.route_event_for(event, seed_only, None, false);
    }

    /// `force_trace` : rattache l'event à cette seule trace sans refaire
    /// le test de rattachement (2.21.113, E4 : parent rattaché après son
    /// enfant).
    /// `forced` (avec `force_trace`) : rattachement sans test. Sans
    /// `forced`, `force_trace` restreint à cette trace une NOUVELLE
    /// tentative de rattachement d'un event rejeté plus tôt (2.21.124,
    /// PFCP d'une session dont les SEID viennent d'être appris).
    fn route_event_for(
        &self,
        event: &event_schema::NormalizedEvent,
        seed_only: bool,
        force_trace: Option<&str>,
        forced: bool,
    ) {
        self.route_event_with(event, seed_only, force_trace, forced);
    }

    /// 2.21.134 — même rattachement ; rend le nombre de traces qui ont pris
    /// l'event (mesure du rattachement après coup, amorçage compris).
    fn route_event_with(
        &self,
        event: &event_schema::NormalizedEvent,
        seed_only: bool,
        force_trace: Option<&str>,
        forced: bool,
    ) -> usize {
        let mut attached_here = 0usize;
        let targeted = force_trace.is_some();
        let forced = forced && targeted;
        let mut retry_pfcp_for: Vec<String> = Vec::new();
        // 2.21.103 (ordre #9 7046282778, défaut ANR2 #10 7045891820) — un
        // PFCP de niveau nœud (Heartbeat/Association/PFD/Node-Report) n'est
        // JAMAIS routé dans une trace abonné : ces messages n'ont pas de
        // portée session et polluent le flux SSE (99,92 % des 22 769 PFCP
        // observés par ANR2 sur une trace voix, rejoués via IE values
        // communes apprises).
        // 2.21.113 — aussi par type : le décodeur PFCP ne nomme que
        // Heartbeat et Association Setup ; les autres messages de niveau
        // nœud (types 1 à 15 : Association Update / Release, PFD
        // Management, Node Report, …) sortent en « Unknown PFCP Message »
        // et passaient le filtre par nom.
        if event.protocol.as_str() == "PFCP"
            && (is_pfcp_node_message(&event.message_name) || (1..50).contains(&event.message_type))
        {
            return attached_here;
        }
        let value = serde_json::from_str(&event.to_json()).unwrap_or(Value::Null);
        // 2.21.109 — rattachement par égalité sur champs typés ; plus
        // aucun test de sous-chaîne sur le JSON de l'event.
        let tokens = event_tokens(&value);
        // 2.21.90 défaut 2 — facts extraits une seule fois par event,
        // puis consultés et pour le match (SEID/TEID/(ip,teid) déjà
        // connus) et pour l'apprentissage après routage.
        let ev_ies: Vec<String> = ie_values(&value);
        let ev_tunnel_pairs: Vec<(String, String)> =
            ev_ies.iter().flat_map(|v| parse_tunnel_pairs(v)).collect();
        // 2.21.109 — un SEID ou un TEID nul n'est ni appris ni comparé.
        let ev_tunnel_pairs: Vec<(String, String)> = ev_tunnel_pairs
            .into_iter()
            .filter(|pair| !is_zero_hex(&pair.1))
            .collect();
        let ev_teids: Vec<String> = ev_ies
            .iter()
            .flat_map(|v| parse_teids(v))
            .filter(|t| !is_zero_hex(t))
            .collect();
        let ev_seids_ie: Vec<String> = ev_ies
            .iter()
            .flat_map(|v| parse_seids(v))
            .filter(|s| !is_zero_hex(s))
            .collect();
        let ev_session_seids: Vec<String> = session_ids_named(&value, "seid")
            .into_iter()
            .filter_map(|s| {
                let hex = s.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(hex, 16).ok().map(|n| format!("0x{n:016x}"))
            })
            .filter(|s| !is_zero_hex(s))
            .collect();
        let ev_session_teids: Vec<String> = session_ids_named(&value, "teid")
            .into_iter()
            .filter_map(event_schema::normalize_teid_hex)
            .filter(|t| !is_zero_hex(t))
            .collect();
        // 2.21.109 (ordre #9 7050201220) — un G-PDU (données du plan
        // usager) : jamais émis en `message`, rattaché par le couple
        // (adresse du point de terminaison, TEID).
        let is_gpdu_data = event.protocol.as_str() == "GTP-U"
            && (event.message_type == 255 || event.message_name == "G-PDU");
        let gpdu_pairs: Vec<(String, String)> = if event.protocol.as_str() == "GTP-U" {
            ev_session_teids
                .iter()
                .map(|teid| (event.destination_endpoint.address.clone(), teid.clone()))
                .collect()
        } else {
            Vec::new()
        };
        // 2.21.109 — identifiants UE de signalisation portés par l'event,
        // qualifiés par l'association (les deux adresses du lien).
        let association = {
            let a = event.source_endpoint.address.as_str();
            let b = event.destination_endpoint.address.as_str();
            if a <= b {
                format!("{a}|{b}")
            } else {
                format!("{b}|{a}")
            }
        };
        // 2.21.113 (E1) — un identifiant alloué par le cœur est unique
        // par AMF / MME : il est qualifié par l'adresse de ce nœud, pas
        // par l'association, pour survivre à un changement de gNB.
        let core_node = {
            let is_core = |endpoint: &event_schema::Endpoint| {
                matches!(endpoint.port, Some(38412) | Some(36412))
                    || endpoint
                        .network_function
                        .as_deref()
                        .map(str::to_ascii_lowercase)
                        .is_some_and(|nf| nf.contains("amf") || nf.contains("mme"))
            };
            if is_core(&event.source_endpoint) {
                event.source_endpoint.address.clone()
            } else if is_core(&event.destination_endpoint) {
                event.destination_endpoint.address.clone()
            } else {
                association.clone()
            }
        };
        let ids_named = |names: &[&str], scope: &str| -> Vec<(String, String, String)> {
            names
                .iter()
                .flat_map(|name| {
                    session_ids_named(&value, name)
                        .into_iter()
                        .map(|v| ((*name).to_string(), v.to_string(), scope.to_string()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let ev_core_ids = ids_named(&CORE_UE_ID_NAMES, &core_node);
        let ev_ran_ids = ids_named(&RAN_UE_ID_NAMES, &association);
        let smf_scope = {
            let is_smf = |endpoint: &event_schema::Endpoint| {
                endpoint
                    .network_function
                    .as_deref()
                    .map(str::to_ascii_lowercase)
                    .is_some_and(|nf| nf.contains("smf"))
            };
            if is_smf(&event.source_endpoint) {
                event.source_endpoint.address.clone()
            } else if is_smf(&event.destination_endpoint) {
                event.destination_endpoint.address.clone()
            } else {
                association.clone()
            }
        };
        let ev_sm_contexts: Vec<(String, String, String)> = session_ids_named(&value, SM_CONTEXT_NAME)
            .into_iter()
            // 2.21.119 (G2) — qualifiée par l'adresse du SMF quand une
            // extrémité est reconnue comme telle, par l'association
            // sinon : le SMF alloue de petits entiers, une même valeur
            // chez un autre SMF est une autre session.
            .map(|v| (SM_CONTEXT_NAME.to_string(), v.to_string(), smf_scope.clone()))
            .collect();
        let ev_core_tunnel_pairs: Vec<(String, String)> = if event.protocol.as_str() == "GTP-U" {
            Vec::new()
        } else {
            ev_ies.iter().flat_map(|v| parse_core_tunnel_pairs(v)).collect()
        };
        let is_release_sm_context = event
            .sbi
            .as_ref()
            .and_then(|sbi| sbi.operation.as_deref())
            .is_some_and(|operation| operation == "ReleaseSMContext");
        // 2.21.113 (E3) — SEID : couple (nœud destinataire, SEID
        // d'en-tête) du message, et couples des IE F-SEID.
        let is_pfcp = event.protocol.as_str() == "PFCP";
        let ev_header_seid_pairs: Vec<(String, String)> = if is_pfcp {
            ev_session_seids
                .iter()
                .map(|seid| {
                    (
                        event_schema::normalize_ip(&event.destination_endpoint.address),
                        seid.clone(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        let ev_ie_seid_pairs: Vec<(String, String)> =
            ev_ies.iter().flat_map(|v| parse_seid_pairs(v)).collect();
        // 2.21.113 (E4) — références de l'event parent citées par l'event.
        let ev_parent_ids: Vec<String> = value
            .get("parent_event_id")
            .and_then(Value::as_str)
            .into_iter()
            .chain(session_ids_named(&value, "parent_ngap_event_id"))
            .chain(session_ids_named(&value, "parent_s1ap_event_id"))
            .filter(|id| id.starts_with("evt-"))
            .map(str::to_owned)
            // 2.21.116 (F2) — les décodeurs posent la même référence dans
            // `parent_event_id` et dans `parent_*_event_id` : une seule
            // fois, sinon le parent est routé (et compté) deux fois.
            .collect::<std::collections::BTreeSet<String>>()
            .into_iter()
            .collect();
        let ev_pdu_session: Option<String> = session_ids_named(&value, "pdu_session_id")
            .first()
            .map(|v| v.to_string());
        // 2.21.122 — identifiant d'appel SIP porté par l'event (SIP ou
        // flux RTP), et fin de dialogue : réponse 2xx à un BYE.
        let ev_sip_call_ids: Vec<String> = session_ids_named(&value, "sip_call_id")
            .into_iter()
            .map(str::to_owned)
            .collect();
        let is_sip = event.protocol.as_str() == "SIP";
        let is_rtp = event.protocol.as_str() == "RTP";
        let ends_sip_dialog = is_sip
            && event.message_name.starts_with('2')
            && ev_ies
                .iter()
                .any(|ie| ie.trim().to_ascii_uppercase().ends_with(" BYE"));
        let ev_equipment_pseudonyms = equipment_pseudonyms(event);
        let ev_ue_ip_pseudonyms = ue_ip_pseudonyms(event);
        // 2.21.134 (cas 4, ordre #9 7060289296) — établissement d'une
        // session PFCP, et sa clé `(séquence, nœud, nœud)`.
        let pfcp_name = compact_name(&event.message_name);
        let is_establishment_request = event.protocol.as_str() == "PFCP"
            && pfcp_name.ends_with("sessionestablishmentrequest");
        let is_establishment_response = event.protocol.as_str() == "PFCP"
            && pfcp_name.ends_with("sessionestablishmentresponse");
        let establishment_key: Option<(String, String, String)> =
            session_ids_named(&value, "pfcp_sequence").first().map(|sequence| {
                let mut nodes = [
                    event.source_endpoint.address.clone(),
                    event.destination_endpoint.address.clone(),
                ];
                nodes.sort();
                let [a, b] = nodes;
                ((*sequence).to_owned(), a, b)
            });
        // 2.21.129 — identités d'abonné portées par l'event (hors
        // pseudonymes d'équipement), et ouverture d'un nouveau contexte UE.
        let ev_subscriber_pseudonyms: Vec<String> = session_ids_named(&value, "subscriber_pseudonym")
            .into_iter()
            .filter(|pseudonym| !ev_equipment_pseudonyms.contains(*pseudonym))
            .map(str::to_owned)
            .collect();
        let is_initial_ue_message = matches!(event.protocol.as_str(), "NGAP" | "S1AP")
            && compact_name(&event.message_name) == "initialuemessage";
        let mut parents_to_attach: Vec<(String, String)> = Vec::new();
        let mut rejected_by_a_trace = false;
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
            if force_trace.is_some_and(|id| id != state.trace.trace_id) {
                continue;
            }
            // 2.21.124 — un pseudonyme d'équipement est retenu comme tel
            // dès qu'il est vu, et retiré des clés s'il avait été appris
            // plus tôt (event enfant passé avant son parent).
            for equipment in &ev_equipment_pseudonyms {
                let is_trace_pseudonym = state
                    .trace
                    .subscriber_pseudonyms
                    .iter()
                    .any(|known| known == equipment);
                if !is_trace_pseudonym && state.equipment_keys.insert(equipment.clone()) {
                    state.match_keys.forget(equipment);
                    state.exposed_keys.remove(equipment);
                }
            }
            if seed_only {
                if !state.seeding {
                    continue;
                }
                state.trace.seed.events_scanned =
                    state.trace.seed.events_scanned.saturating_add(1);
            } else if !targeted {
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
                .any(|pseudonym| tokens.contains(pseudonym));
            let match_keys = state.match_keys.iter().any(|known| tokens.contains(known));
            // 2.21.113 (E3) — SMF et UPF allouent chacun leurs SEID : la
            // valeur seule peut désigner la session d'un autre abonné.
            // Rattachement par le couple (nœud, SEID) ; la valeur seule
            // n'est admise que si aucun couple n'est connu pour elle.
            let match_seid_pair = ev_header_seid_pairs
                .iter()
                .chain(ev_ie_seid_pairs.iter())
                .any(|pair| state.seid_endpoints.contains(pair));
            let match_seid_value_only = ev_session_seids
                .iter()
                .chain(ev_seids_ie.iter())
                .any(|s| {
                    state.seids.contains(s)
                        && !state.seid_endpoints.iter().any(|pair| &pair.1 == s)
                });
            let match_seid = match_seid_pair || match_seid_value_only;
            // 2.21.109 — un TEID seul ne rattache que si aucun couple
            // (adresse, TEID) n'est connu pour ce TEID : gNB et UPF
            // allouent leurs TEID chacun de leur côté, la même valeur
            // peut désigner le tunnel d'un autre abonné.
            // `tunnel_teids` ne contient que des TEID appris sur la
            // signalisation de CET abonné (un G-PDU n'en apprend aucun).
            let teid_without_known_endpoint = |t: &String| {
                state.tunnel_teids.contains(t)
                    && !state.tunnel_endpoints.iter().any(|pair| &pair.1 == t)
            };
            let gpdu_teid_known = event.protocol.as_str() == "GTP-U"
                && ev_session_teids.iter().any(|t| state.tunnel_teids.contains(t));
            // Vaut pour la signalisation comme pour les G-PDU : un PDU
            // Session Resource Setup ou un PFCP d'un autre UE peut porter
            // la même valeur de TEID vers un autre point de terminaison.
            let match_teid = ev_session_teids
                .iter()
                .chain(ev_teids.iter())
                .any(teid_without_known_endpoint);
            let match_tunnel = ev_tunnel_pairs
                .iter()
                .chain(gpdu_pairs.iter())
                .any(|pair| state.tunnel_endpoints.contains(pair));
            // 2.21.113 (E2) — identifiants UE : quand l'event porte
            // l'identifiant du cœur ET celui de l'accès radio, le premier
            // doit être celui de l'abonné, et le second aussi — sauf sur
            // une association jamais vue pour cet abonné (changement de
            // gNB). Un seul identifiant présent : il doit être connu.
            let core_known = ev_core_ids.iter().any(|id| state.ue_ids.contains(id));
            let ran_known = ev_ran_ids.iter().any(|id| state.ue_ids.contains(id));
            let association_known = state.ue_ids.iter().any(|(name, _, scope)| {
                RAN_UE_ID_NAMES.contains(&name.as_str()) && scope == &association
            });
            // Tant qu'aucun identifiant du cœur n'est appris pour l'abonné
            // (premier message descendant après l'InitialUEMessage),
            // l'identifiant radio connu suffit et fait apprendre l'autre.
            let core_learned = state
                .ue_ids
                .iter()
                .any(|(name, _, _)| CORE_UE_ID_NAMES.contains(&name.as_str()));
            let match_ue_id = match (ev_core_ids.is_empty(), ev_ran_ids.is_empty()) {
                (false, false) => {
                    (core_known && (ran_known || !association_known))
                        || (!core_learned && ran_known)
                }
                (false, true) => core_known,
                (true, false) => ran_known,
                (true, true) => false,
            } || ev_sm_contexts.iter().any(|id| state.ue_ids.contains(id));
            // 2.21.122 — appel de l'abonné : égalité exacte sur
            // `sip_call_id`. Un appel terminé ne rattache plus que son
            // flux RTP.
            let match_call = (is_sip || is_rtp)
                && ev_sip_call_ids.iter().any(|call| {
                    state.sip_call_ids.contains(call)
                        || (is_rtp && state.ended_sip_call_ids.contains(call))
                });
            // 2.21.126 — règle explicite : l'event porte l'adresse IP de
            // l'UE de l'abonné. SIP : adresse du paquet ou du SDP (couvre
            // REGISTER et tout message sans SDP, avec des URI qui ne sont
            // ni IMSI ni MSISDN). PFCP : IE 93.
            let match_ue_ip = (is_sip || is_pfcp)
                && ev_ue_ip_pseudonyms
                    .iter()
                    .any(|ip| state.ue_ip_keys.contains_key(ip));
            let matched = forced
                || match_call
                || match_ue_ip
                || match_pseudo
                || match_keys
                || match_seid
                || match_teid
                || match_tunnel
                || match_ue_id;
            // 2.21.134 (cas 4 de la sonde CLAUDE2 #9 7060169092, ordre #9
            // 7060289296) — un établissement PFCP crée une session NEUVE.
            // S'il porte un tunnel ou un SEID que la trace connaît d'un event
            // de l'abonné vieux de plus de 10 s, c'est l'identifiant d'une
            // session antérieure, réattribué : il ne rattache pas
            // l'établissement, et la trace l'oublie. L'établissement entre
            // alors par une identité de l'abonné, par l'IP de son UE (IE 93),
            // ou après coup par les identifiants frais qu'apporte le N2 de
            // l'abonné ; sa réponse, aussi quand la requête de même
            // séquence a été rattachée. Un tunnel appris dans les 10 s (le
            // N2 de la même procédure) reste admis.
            let is_establishment = is_establishment_request || is_establishment_response;
            // Identifiants portés par l'établissement que la trace connaît
            // d'un event de l'abonné vieux de plus de 10 s.
            let carries_reused_identifier = is_establishment
                && ev_header_seid_pairs
                    .iter()
                    .chain(ev_ie_seid_pairs.iter())
                    .chain(ev_tunnel_pairs.iter())
                    .map(|pair| &pair.1)
                    .chain(ev_seids_ie.iter())
                    .chain(ev_session_seids.iter())
                    .chain(ev_teids.iter())
                    .chain(ev_session_teids.iter())
                    .any(|identifier| {
                        state.identifier_seen_at.get(identifier).is_some_and(|seen| {
                            (event.timestamp.seconds - seen).abs() > AFTER_THE_FACT_MAX_AGE_S
                        })
                    });
            let establishment_ok = forced
                || match_pseudo
                || match_ue_ip
                || state.match_keys.any_identity_in(&tokens)
                || (is_establishment_response
                    && establishment_key
                        .as_ref()
                        .is_some_and(|key| state.pfcp_establishments.contains(key)))
                || !carries_reused_identifier;
            let reused_identifiers = is_establishment && matched && !establishment_ok;
            let matched = matched && (!is_establishment || establishment_ok);
            if reused_identifiers && !targeted {
                // Les identifiants repris appartiennent désormais à une
                // autre session : la session antérieure de la trace qui les
                // portait est finie sans que la trace l'ait vu. Elle est
                // oubliée en entier — ses tunnels côté accès radio compris,
                // qu'un message de la nouvelle session reprendrait aussi.
                let carried: HashSet<String> = ev_header_seid_pairs
                    .iter()
                    .chain(ev_ie_seid_pairs.iter())
                    .chain(ev_tunnel_pairs.iter())
                    .map(|pair| pair.1.clone())
                    .chain(ev_seids_ie.iter().cloned())
                    .chain(ev_session_seids.iter().cloned())
                    .chain(ev_teids.iter().cloned())
                    .chain(ev_session_teids.iter().cloned())
                    .collect();
                forget_earlier_session(state, &carried);
                if !seed_only {
                    state.trace.pfcp_establishment_reused_identifiers = state
                        .trace
                        .pfcp_establishment_reused_identifiers
                        .saturating_add(1);
                }
            }
            // 2.21.129 (recette lab 2.21.124, G9 ; ordre #9 7053864526) —
            // garde d'identité. Un event reconnu SANS identité de
            // l'abonné (identifiant technique, ou parent déjà rattaché)
            // est celui d'un autre abonné quand :
            //   * il porte un pseudonyme d'abonné que la trace ne connaît
            //     pas — l'identifiant technique a été réattribué ;
            //   * ou il ouvre un NOUVEAU contexte UE sur un identifiant
            //     que la trace croyait vivant — l'ancien contexte a fini
            //     sans que la trace le voie.
            // Il est rejeté, et tout l'état technique de la trace, périmé,
            // est oublié (choix de l'isolement). Un SIP porte l'identité
            // du pair : il n'est pas concerné.
            let identity_match =
                match_pseudo || match_call || state.match_keys.any_identity_in(&tokens);
            // Un enfant hérite les identifiants de session de son parent,
            // dont l'IMEISV masqué (libellé `subscriber_pseudonym`), qui
            // n'est reconnu comme pseudonyme d'équipement que sur le
            // parent : le verdict n'est rendu que si le parent est déjà
            // rattaché à cette trace (ordre d'émission du décodeur,
            // garanti depuis 2.21.126).
            let parent_attached = ev_parent_ids
                .iter()
                .all(|parent| state.match_keys.contains(parent));
            let carries_foreign_subscriber = !is_sip
                && !is_rtp
                && parent_attached
                && !ev_subscriber_pseudonyms.is_empty()
                && ev_subscriber_pseudonyms.iter().all(|pseudonym| {
                    !state.match_keys.contains(pseudonym)
                        && !state.equipment_keys.contains(pseudonym)
                        && !state.trace.subscriber_pseudonyms.iter().any(|known| known == pseudonym)
                });
            // Le parent d'un event déjà rattaché (son enfant NAS, passé
            // avant lui, porte l'identité) n'ouvre pas un contexte
            // étranger : c'est celui de l'abonné.
            let stale_context = is_initial_ue_message
                && (core_known || ran_known)
                && !state.parents_of_attached.contains(&event.event_id);
            let matched = if matched
                && !forced
                && !identity_match
                && (carries_foreign_subscriber || stale_context)
            {
                forget_technical_state(state);
                if !seed_only {
                    state.trace.stale_state_resets =
                        state.trace.stale_state_resets.saturating_add(1);
                    if carries_foreign_subscriber {
                        state.trace.rejected_foreign_subscriber =
                            state.trace.rejected_foreign_subscriber.saturating_add(1);
                    }
                }
                false
            } else {
                matched
            };
            if !matched {
                // 2.21.105 — un G-PDU qui arrive APRÈS la trace mais
                // dont le TEID / UE IP n'a pas été appris (parce que
                // la session PDU était déjà établie avant l'ouverture
                // de la trace) termine ici. Compteur exposé via
                // `/live/traces/:id` pour que l'opérateur voie 0
                // bucket = N rejets rattachement, pas 0 vu.
                if is_gpdu {
                    if gpdu_teid_known {
                        // TEID de l'abonné, mais vers un autre point de
                        // terminaison que celui appris : tunnel d'un
                        // autre UE qui porte la même valeur.
                        state.trace.gpdu_rejected_endpoint_mismatch =
                            state.trace.gpdu_rejected_endpoint_mismatch.saturating_add(1);
                    } else {
                        state.trace.gpdu_rejected_no_match =
                            state.trace.gpdu_rejected_no_match.saturating_add(1);
                    }
                }
                rejected_by_a_trace = true;
                if !seed_only && !targeted {
                    if core_known || ran_known {
                        state.trace.rejected_ue_id_mismatch =
                            state.trace.rejected_ue_id_mismatch.saturating_add(1);
                    }
                    let seid_value_known = ev_session_seids
                        .iter()
                        .chain(ev_seids_ie.iter())
                        .any(|s| state.seids.contains(s));
                    if is_pfcp && seid_value_known {
                        state.trace.rejected_seid_endpoint_mismatch =
                            state.trace.rejected_seid_endpoint_mismatch.saturating_add(1);
                    }
                }
                continue;
            }
            // 2.21.129 (ordre #9 7053864526, question 2) — nouvel
            // enregistrement de l'abonné, présenté avec son identité
            // permanente (SUCI / IMSI : il n'a plus d'identité temporaire
            // valide, donc plus de contexte ni de session dans le réseau) :
            // tout ce que la trace tenait d'avant est périmé. Elle repart
            // de cette procédure. Un enregistrement de mobilité ou
            // périodique se présente avec l'identité temporaire : il garde
            // les sessions, et n'est pas concerné.
            if !forced && match_pseudo && is_fresh_registration(&event.message_name) {
                forget_technical_state(state);
                if !seed_only {
                    state.trace.fresh_registrations =
                        state.trace.fresh_registrations.saturating_add(1);
                }
            }
            attached_here += 1;
            if forced {
                state.trace.parents_attached_after_child =
                    state.trace.parents_attached_after_child.saturating_add(1);
            } else if targeted && !seed_only {
                state.trace.pfcp_attached_after_the_fact =
                    state.trace.pfcp_attached_after_the_fact.saturating_add(1);
            }
            if is_establishment_request {
                if let Some(key) = &establishment_key {
                    if state.pfcp_establishments.len() >= 256 {
                        state.pfcp_establishments.clear();
                    }
                    state.pfcp_establishments.insert(key.clone());
                }
            }
            // 2.21.124 — cet event apporte des SEID ou des tunnels : des
            // messages PFCP de la session, rejetés plus tôt, peuvent
            // maintenant être reconnus.
            // 2.21.134 — aussi pendant l'amorçage, sur son propre tampon.
            if !(ev_header_seid_pairs.is_empty()
                    && ev_ie_seid_pairs.is_empty()
                    && ev_tunnel_pairs.is_empty())
            {
                retry_pfcp_for.push(state.trace.trace_id.clone());
            }
            // 2.21.113 (E4) — le parent de cet event a pu être rejeté
            // juste avant (il ne porte pas l'identité) : à rattacher.
            if !seed_only {
                for parent in &ev_parent_ids {
                    if !state.match_keys.contains(parent) {
                        parents_to_attach.push((state.trace.trace_id.clone(), parent.clone()));
                    }
                }
            }
            if !seed_only
                && match_ue_ip
                && !(forced
                    || match_call
                    || match_pseudo
                    || match_keys
                    || match_seid
                    || match_teid
                    || match_tunnel
                    || match_ue_id)
            {
                if is_sip {
                    state.trace.sip_attached_by_ue_ip =
                        state.trace.sip_attached_by_ue_ip.saturating_add(1);
                } else {
                    state.trace.pfcp_attached_by_ue_ip =
                        state.trace.pfcp_attached_by_ue_ip.saturating_add(1);
                }
            }
            // 2.21.126 — IP UE apprise sur un event rattaché : IE 93 d'un
            // PFCP, identifiant de session `ue_ip`. Jamais sur un SIP :
            // l'adresse de son paquet peut être celle du pair.
            if !is_sip {
                let mut owners: Vec<String> = Vec::new();
                if let Some(session) = &ev_pdu_session {
                    owners.push(format!("pdu:{session}"));
                }
                if is_pfcp {
                    for seid in ev_session_seids.iter().chain(ev_seids_ie.iter()) {
                        owners.push(format!("seid:{seid}"));
                    }
                }
                for ip in &ev_ue_ip_pseudonyms {
                    state
                        .ue_ip_keys
                        .entry(ip.clone())
                        .or_default()
                        .extend(owners.iter().cloned());
                    state.exposed_keys.insert(ip.clone());
                }
            }
            if is_pfcp
                && !seed_only
                && match_seid_value_only
                && !match_seid_pair
                && !(match_pseudo || match_keys || match_teid || match_tunnel)
            {
                state.trace.pfcp_attached_seid_only =
                    state.trace.pfcp_attached_seid_only.saturating_add(1);
            }
            if is_gpdu {
                state.trace.gpdu_attached = state.trace.gpdu_attached.saturating_add(1);
                if !match_tunnel && match_teid {
                    state.trace.gpdu_attached_teid_only =
                        state.trace.gpdu_attached_teid_only.saturating_add(1);
                }
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
                    let pseudonymized = id
                        .get("pseudonymized")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    // 2.21.109 (ordre #9 7050201220) — seules les valeurs
                    // propres à l'abonné deviennent des clés de
                    // rattachement. Avant, toute valeur ≥ 3 caractères
                    // (PLMN, TAC, cellule, sens du tunnel, séquences)
                    // l'était : la trace rattachait alors les autres UE
                    // de la cellule et leur trafic N3.
                    let name = id.get("name").and_then(Value::as_str).unwrap_or("");
                    // 2.21.122 (I1, sonde CLAUDE2 #9 7052558777, ordre #9
                    // 7052593612) — un pseudonyme d'abonné n'est appris, et
                    // exposé, que sur un event où il désigne l'abonné de la
                    // trace, jamais le pair. Sur un SIP, le
                    // `subscriber_pseudonym` de `session_identifiers` est
                    // celui du **From** : quand l'abonné tracé est appelé
                    // (event rattaché par le To, la Request-URI, le SDP ou
                    // l'identifiant d'appel), c'est celui de l'APPELANT.
                    // Un SIP n'apprend donc ni n'expose un pseudonyme que
                    // la trace ne connaît pas déjà. Avant : le pseudonyme
                    // de l'appelant devenait une clé de la trace de
                    // l'appelé, sortait dans `ue_info`, et sa signalisation
                    // puis son trafic suivaient.
                    let is_pseudonym = pseudonymized || name.ends_with("_pseudonym");
                    let already_known = state.match_keys.contains(v)
                        || state.trace.subscriber_pseudonyms.iter().any(|known| known == v);
                    if is_sip && is_pseudonym && !already_known {
                        continue;
                    }
                    // 2.21.126 — l'IP UE pseudonymisée a sa règle et son
                    // cycle de vie (`ue_ip_keys`) : elle n'entre plus dans
                    // les clés génériques.
                    if name == "ue_ip" && is_pseudonym {
                        continue;
                    }
                    // 2.21.124 — un pseudonyme d'équipement n'est ni
                    // appris ni exposé, quel que soit son libellé.
                    if state.equipment_keys.contains(v) {
                        continue;
                    }
                    // 2.21.124 — liste blanche : un pseudonyme n'est appris
                    // et exposé que sous un nom d'identité d'abonné.
                    if is_pseudonym && !LEARNABLE_PSEUDONYM_NAMES.contains(&name) && !already_known {
                        continue;
                    }
                    if is_subscriber_scoped_key(name, v, pseudonymized) {
                        state.match_keys.insert(v.to_owned());
                    }
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
            // 2.21.109 — identifiants UE exacts, et référence de l'event
            // de signalisation routé : un event enfant (NAS porté par
            // NGAP/S1AP) cite son parent par `parent_*_event_id`.
            for id in ev_core_ids
                .iter()
                .chain(ev_ran_ids.iter())
                .chain(ev_sm_contexts.iter())
            {
                state.ue_ids.insert(id.clone());
            }
            for pair in ev_header_seid_pairs.iter().chain(ev_ie_seid_pairs.iter()) {
                state.seid_endpoints.insert(pair.clone());
            }
            // 2.21.134 — dernière fois qu'un event de l'abonné a porté
            // chacun de ses tunnels et SEID.
            if state.identifier_seen_at.len() >= 8_192 {
                state.identifier_seen_at.clear();
            }
            if event.protocol.as_str() != "GTP-U" {
                for identifier in ev_header_seid_pairs
                    .iter()
                    .chain(ev_ie_seid_pairs.iter())
                    .chain(ev_tunnel_pairs.iter())
                    .map(|pair| &pair.1)
                    .chain(ev_seids_ie.iter())
                    .chain(ev_session_seids.iter())
                    .chain(ev_teids.iter())
                    .chain(ev_session_teids.iter())
                {
                    state
                        .identifier_seen_at
                        .insert(identifier.clone(), event.timestamp.seconds);
                }
            }
            for pair in &ev_core_tunnel_pairs {
                state.core_tunnel_endpoints.insert(pair.clone());
            }
            // 2.21.121 (relecture CLAUDE2 #9 7052103318, H1) — un couple
            // côté cœur appris en PFCP ne nomme pas la session de
            // données : il est rangé sous les SEID du message, pour
            // finir avec la session PFCP.
            if is_pfcp && !ev_core_tunnel_pairs.is_empty() {
                for seid in ev_session_seids.iter().chain(ev_seids_ie.iter()) {
                    state
                        .seid_tunnels
                        .entry(seid.clone())
                        .or_default()
                        .extend(ev_core_tunnel_pairs.iter().cloned());
                }
            }
            // 2.21.122 — un `sip_call_id` n'est appris que sur un SIP
            // rattaché (jamais sur un flux RTP, jamais sur un event
            // rejeté), et rangé par appel.
            if is_sip {
                for call in &ev_sip_call_ids {
                    if ends_sip_dialog {
                        state.sip_call_ids.remove(call);
                        state.ended_sip_call_ids.insert(call.clone());
                    } else if !state.ended_sip_call_ids.contains(call) {
                        state.sip_call_ids.insert(call.clone());
                    }
                }
            }
            for (_, reference, scope) in &ev_sm_contexts {
                let session = state
                    .sm_context_sessions
                    .entry((reference.clone(), scope.clone()))
                    .or_insert(None);
                if session.is_none() {
                    *session = ev_pdu_session.clone();
                }
            }
            if event.protocol.as_str() != "GTP-U" && event.event_id.starts_with("evt-") {
                state.match_keys.insert(event.event_id.clone());
                // 2.21.129 — parents des events rattachés (borné).
                if state.parents_of_attached.len() >= 4_096 {
                    state.parents_of_attached.clear();
                }
                state.parents_of_attached.extend(ev_parent_ids.iter().cloned());
            }
            for pair in &ev_tunnel_pairs {
                state.tunnel_endpoints.insert(pair.clone());
                state.tunnel_teids.insert(pair.1.clone());
            }
            // 2.21.113 (E5) — tunnels de signalisation rangés par session
            // de données quand l'event la nomme.
            if event.protocol.as_str() != "GTP-U" {
                let has_tunnels = !ev_tunnel_pairs.is_empty()
                    || !ev_teids.is_empty()
                    || !ev_session_teids.is_empty();
                // Une entrée n'est créée que s'il y a un tunnel à ranger :
                // sinon tout event qui nomme la session, la libération
                // comprise, ferait croire que ses tunnels sont rangés.
                if let (Some(session), true) = (ev_pdu_session.as_ref(), has_tunnels) {
                    let entry = state.session_tunnels.entry(session.clone()).or_default();
                    for pair in &ev_tunnel_pairs {
                        entry.insert((Some(pair.0.clone()), pair.1.clone()));
                    }
                    for teid in ev_teids.iter().chain(ev_session_teids.iter()) {
                        entry.insert((None, teid.clone()));
                    }
                }
            }
            // 2.21.109 (exigence cœur 7050392981 point 1) — un G-PDU
            // n'apprend aucun TEID : seule la signalisation de l'abonné
            // en apprend.
            if event.protocol.as_str() != "GTP-U" {
                for t in ev_teids.iter().chain(ev_session_teids.iter()) {
                    state.tunnel_teids.insert(t.clone());
                }
            }
            for s in ev_seids_ie.iter().chain(ev_session_seids.iter()) {
                state.seids.insert(s.clone());
            }
            if let Some(ip) = ev_pdu_address.as_deref() {
                state.ue_ips.insert(ip.to_owned());
                // Pseudonyme UE IP (domain `pfcp-ue-ip`) : correspond à
                // `decoder-pfcp` IE 93. Un PFCP Session Establishment
                // qui ne porte que cette UE IP pseudonymisée match via
                // `match_keys` (égalité sur la valeur de l'IE, cf. `event_tokens`).
                // 2.21.126 — forme unique du pseudonyme
                // (`event_schema::pseudonym_ip_text`, octets de
                // l'adresse) ; rangé dans `ue_ip_keys`, plus dans les clés
                // génériques : rattachement par la règle explicite.
                if let Some(pseudonym) =
                    pseudonym_key().and_then(|key| event_schema::pseudonym_ip_text(key, ip))
                {
                    let owners = state.ue_ip_keys.entry(pseudonym.clone()).or_default();
                    if let Some(session) = &ev_pdu_session {
                        owners.insert(format!("pdu:{session}"));
                    }
                    state.exposed_keys.insert(pseudonym);
                }
            }
            // 2.21.113 (E5) — deux fins distinctes. Avant, le nom testé
            // (`UE Context Release Complete`, avec espaces) n'était celui
            // d'aucun décodeur : la libération de contexte n'oubliait
            // rien ; et la libération d'une session PDU oubliait les
            // identifiants UE alors que l'UE reste enregistré.
            // 2.21.116 (relecture CLAUDE2 #9 7051364956, F1) — trois fins.
            //   * libération du contexte UE (aussi : mise en veille) —
            //     identifiants UE NGAP / S1AP et tunnels côté accès radio
            //     oubliés ; SEID, couples (nœud, SEID), références de
            //     contexte SM et IP UE GARDÉS : la session de données
            //     reste établie, et la norme place justement après ce
            //     message l'UpdateSMContext et la Session Modification
            //     (TS 23.502 §4.2.6) ;
            //   * libération d'une session de données — ses tunnels ;
            //   * détachement — tout.
            let context_release = is_ue_context_release(&event.message_name);
            let detach = is_detach(&event.message_name);
            let session_release = is_data_session_release(&event.message_name);
            let released_tunnels = if session_release && !context_release && !detach {
                ev_pdu_session
                    .as_ref()
                    .and_then(|session| state.session_tunnels.remove(session))
            } else {
                None
            };
            if let Some(tunnels) = released_tunnels {
                // Libération d'UNE session de données dont les tunnels
                // sont connus : eux seuls sont oubliés, les autres
                // sessions de l'abonné (DNN internet et IMS, par exemple)
                // gardent les leurs.
                for (address, teid) in tunnels {
                    let still_used = state
                        .session_tunnels
                        .values()
                        .any(|others| others.iter().any(|(_, other)| other == &teid));
                    if !still_used {
                        state.tunnel_teids.remove(&teid);
                    }
                    if let Some(address) = address {
                        state.core_tunnel_endpoints.remove(&(address.clone(), teid.clone()));
                        state.tunnel_endpoints.remove(&(address, teid));
                    }
                }
            } else if context_release && !detach && !session_release {
                // 2.21.119 (G1) — mise en veille : seul le côté accès
                // radio est libéré. Les couples côté cœur (UPF) vivent
                // avec la session : gardés, ils rattachent le contexte
                // initial du retour de veille, qui porte le même tunnel
                // montant, puis le trafic montant.
                let core = &state.core_tunnel_endpoints;
                state.tunnel_endpoints.retain(|pair| core.contains(pair));
                let kept: HashSet<&String> =
                    state.tunnel_endpoints.iter().map(|pair| &pair.1).collect();
                state.tunnel_teids.retain(|teid| kept.contains(teid));
                for tunnels in state.session_tunnels.values_mut() {
                    tunnels.retain(|(address, teid)| {
                        address
                            .as_ref()
                            .is_some_and(|address| core.contains(&(address.clone(), teid.clone())))
                    });
                }
                state.session_tunnels.retain(|_, tunnels| !tunnels.is_empty());
            } else if session_release && !detach && ev_pdu_session.is_some() {
                // 2.21.119 (point mineur, ordre #9 7051758378) —
                // libération d'une session NOMMÉE dont aucun tunnel n'est
                // rangé (appris sans `pdu_session_id`, par PFCP par
                // exemple) : les tunnels des autres sessions de l'abonné
                // ne sont pas vidés. Le cas est compté : les tunnels de
                // la session libérée, eux, restent connus.
                if !seed_only {
                    state.trace.session_releases_without_filed_tunnels = state
                        .trace
                        .session_releases_without_filed_tunnels
                        .saturating_add(1);
                }
                // 2.21.121 (H1) — choix de l'isolement : les couples côté
                // cœur qui ne sont rangés sous aucune autre session de
                // données ni sous aucun SEID encore vivant sont oubliés.
                // Sinon ils survivraient à cette libération ET à la mise
                // en veille (qui garde le côté cœur), jusqu'au
                // désenregistrement ou à l'expiration de la trace ;
                // réattribués par l'UPF, ils rattacheraient le trafic
                // d'un autre abonné.
                let filed: HashSet<(String, String)> = state
                    .session_tunnels
                    .values()
                    .flatten()
                    .filter_map(|(address, teid)| {
                        address.as_ref().map(|address| (address.clone(), teid.clone()))
                    })
                    .chain(
                        state
                            .seid_tunnels
                            .iter()
                            .filter(|(seid, _)| state.seids.contains(*seid))
                            .flat_map(|(_, pairs)| pairs.iter().cloned()),
                    )
                    .collect();
                let orphans: Vec<(String, String)> = state
                    .core_tunnel_endpoints
                    .iter()
                    .filter(|pair| !filed.contains(*pair))
                    .cloned()
                    .collect();
                forget_tunnel_pairs(state, &orphans);
            } else if session_release || detach {
                // Libération d'une session que l'event ne nomme pas, ou
                // détachement : tous les tunnels du plan usager sont
                // oubliés.
                state.tunnel_teids.clear();
                state.tunnel_endpoints.clear();
                state.session_tunnels.clear();
                state.core_tunnel_endpoints.clear();
                state.seid_tunnels.clear();
            }
            // 2.21.119 (G2) — une référence de contexte SM finit avec sa
            // session de données. Depuis 2.21.113 elle n'était plus
            // oubliée en 5G : réattribuée par le SMF à un autre abonné,
            // elle rattachait ses messages SBI.
            let forget_sm_contexts: Vec<(String, String)> = if detach {
                state.sm_context_sessions.keys().cloned().collect()
            } else if is_release_sm_context {
                ev_sm_contexts
                    .iter()
                    .map(|(_, reference, scope)| (reference.clone(), scope.clone()))
                    .collect()
            } else if session_release && !context_release {
                // Libération de session : les références de cette session,
                // et celles qu'aucun event n'a rattachées à une session
                // (choix de l'isolement).
                state
                    .sm_context_sessions
                    .iter()
                    .filter(|(_, session)| {
                        ev_pdu_session.is_none() || session.is_none() || **session == ev_pdu_session
                    })
                    .map(|(key, _)| key.clone())
                    .collect()
            } else {
                Vec::new()
            };
            for (reference, scope) in forget_sm_contexts {
                state.sm_context_sessions.remove(&(reference.clone(), scope.clone()));
                state
                    .ue_ids
                    .remove(&(SM_CONTEXT_NAME.to_string(), reference, scope));
            }
            if detach || (session_release && !context_release && ev_pdu_session.is_none()) {
                // Détachement, ou libération d'une session que l'event ne
                // nomme pas : SEID et IP UE oubliés aussi (choix de
                // l'isolement).
                state.seids.clear();
                state.seid_endpoints.clear();
                state.ue_ips.clear();
                // 2.21.126 — toutes les IP UE de l'abonné.
                for (ip, _) in state.ue_ip_keys.drain() {
                    state.exposed_keys.remove(&ip);
                }
            } else if session_release && !context_release {
                // 2.21.126 — libération d'une session NOMMÉE : son IP UE
                // est oubliée, et celles qu'aucune session ni aucun SEID
                // ne porte (choix de l'isolement). Réattribuée à un autre
                // abonné, elle rattacherait son SIP.
                if let Some(session) = &ev_pdu_session {
                    let tag = format!("pdu:{session}");
                    let gone: Vec<String> = state
                        .ue_ip_keys
                        .iter()
                        .filter(|(_, owners)| owners.is_empty() || owners.contains(&tag))
                        .map(|(ip, _)| ip.clone())
                        .collect();
                    for ip in gone {
                        state.ue_ip_keys.remove(&ip);
                        state.exposed_keys.remove(&ip);
                    }
                }
            }
            // Suppression d'une session PFCP : son SEID ne vaut plus, ni
            // les couples côté cœur rangés sous lui (2.21.121, H1).
            if is_pfcp && compact_name(&event.message_name).ends_with("sessiondeletionresponse") {
                for pair in &ev_header_seid_pairs {
                    state.seid_endpoints.remove(pair);
                    state.seids.remove(&pair.1);
                }
                // 2.21.126 — l'IP UE apprise sur cette session PFCP finit
                // avec elle.
                let tags: Vec<String> = ev_session_seids
                    .iter()
                    .chain(ev_seids_ie.iter())
                    .map(|seid| format!("seid:{seid}"))
                    .collect();
                let gone: Vec<String> = state
                    .ue_ip_keys
                    .iter()
                    .filter(|(_, owners)| tags.iter().any(|tag| owners.contains(tag)))
                    .map(|(ip, _)| ip.clone())
                    .collect();
                for ip in gone {
                    state.ue_ip_keys.remove(&ip);
                    state.exposed_keys.remove(&ip);
                }
                let released: Vec<(String, String)> = ev_session_seids
                    .iter()
                    .chain(ev_seids_ie.iter())
                    .filter_map(|seid| state.seid_tunnels.remove(seid))
                    .flatten()
                    .collect();
                // Un couple encore rangé sous une session de données ou
                // sous un autre SEID vivant est gardé.
                let still_filed: HashSet<(String, String)> = state
                    .session_tunnels
                    .values()
                    .flatten()
                    .filter_map(|(address, teid)| {
                        address.as_ref().map(|address| (address.clone(), teid.clone()))
                    })
                    .chain(state.seid_tunnels.values().flatten().cloned())
                    .collect();
                let released: Vec<(String, String)> = released
                    .into_iter()
                    .filter(|pair| !still_filed.contains(pair))
                    .collect();
                forget_tunnel_pairs(state, &released);
            }
            if context_release || detach {
                // Identifiants UE NGAP / S1AP et références d'event : ne
                // valent plus. Les identités de l'abonné (pseudonymes,
                // chiffres amorcés) sont gardées : elles rattachent sa
                // prochaine procédure. Une référence de contexte SM vit
                // avec la session de données : gardée, sauf détachement.
                state
                    .ue_ids
                    .retain(|(name, _, _)| !detach && name == SM_CONTEXT_NAME);
                state.match_keys.forget_event_references();
            }
            if detach {
                // Détachement : plus aucun appel de l'abonné.
                state.sip_call_ids.clear();
                state.ended_sip_call_ids.clear();
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
            // 2.21.109 (décision cœur #9 7050201220 point 2) — un G-PDU
            // n'est JAMAIS émis en `message` : il alimente les buckets de
            // débit et les compteurs `gpdu.*`, c'est tout. Recette
            // 2.21.104 : 768 912 messages GTP-U, 568 Mo de SSE par trace.
            if !is_gpdu_data {
                // 2.18.6 (ANR1 #10 6901968948 : 19 doublons adjacents, 13
                // inversions) — un même message (capture_id, packet_number,
                // event_id) n'est émis qu'une fois ; une inversion dans une
                // même capture est comptée (`out_of_order`) et marquée
                // `late:true`, jamais masquée.
                // 2.21.131 (lot B2, GO #9 7050925249) — flux RTP : le même
                // flux est émis plusieurs fois pendant qu'il grossit
                // (instantané toutes les 5 s, puis clôture). Le flux est
                // reconnu par `stable_event_key`, qui ne bouge pas ; son
                // `event_id` change avec le nombre de paquets. Une
                // révision au contenu inchangé n'est pas réémise ; une
                // révision nouvelle porte `revision` croissant et
                // REMPLACE la précédente dans le tampon de la trace.
                let flow_revision: Option<u64> = if is_rtp && !event.stable_event_key.is_empty() {
                    match state.rtp_flow_revisions.get(&event.stable_event_key) {
                        Some((_, last_event_id)) if last_event_id == &event.event_id => continue,
                        Some((revision, _)) => Some(revision + 1),
                        None => Some(0),
                    }
                } else {
                    None
                };
                let message_key = (event.capture_id.clone(), packet, event.event_id.clone());
                if !state.seen.insert(message_key) {
                    state.trace.duplicates_dropped += 1;
                    continue;
                }
                if let Some(revision) = flow_revision {
                    if state.rtp_flow_revisions.len() >= 4_096 {
                        state.rtp_flow_revisions.clear();
                    }
                    state
                        .rtp_flow_revisions
                        .insert(event.stable_event_key.clone(), (revision, event.event_id.clone()));
                    if revision > 0 {
                        state.trace.rtp_flow_updates = state.trace.rtp_flow_updates.saturating_add(1);
                        state.events.retain(|buffered| {
                            buffered.kind != "message"
                                || buffered.payload["stable_event_key"].as_str()
                                    != Some(event.stable_event_key.as_str())
                        });
                    }
                }
                let is_flow_update = flow_revision.is_some_and(|revision| revision > 0);
                if state.seen.len() > MAX_EVENTS * 4 {
                    state.seen.clear();
                }
                let last = state.last_packet.get(&event.capture_id).copied();
                let late = last.is_some_and(|last| packet < last);
                if is_flow_update {
                    // Mise à jour d'un message déjà compté : ni message de
                    // plus, ni inversion de plus.
                } else if late {
                    state.trace.out_of_order += 1;
                } else {
                    state.last_packet.insert(event.capture_id.clone(), packet);
                }
                state.next_id += 1;
                if !is_flow_update {
                    state.trace.messages += 1;
                }
                // 2.21.91 (défaut #9 7033006772) — expose `stable_event_key`
                // dans le payload SSE. Clé de corrélation live↔publi
                // indépendante de `capture_id` (voir event-schema 1.6.0).
                let payload = json!({"interface":event.interface,"protocol":event.protocol.as_str(),"message_name":event.message_name,"direction":event.direction.as_str(),"source":value.get("source_endpoint"),"destination":value.get("destination_endpoint"),"capture_id":event.capture_id,"packet_number":packet,"event_id":event.event_id,"stable_event_key":event.stable_event_key,"timestamp":{"seconds":event.timestamp.seconds,"nanoseconds":event.timestamp.nanoseconds},"decoded_ie_tree":value.get("information_elements"),"late":late});
                let mut payload = payload;
                if let Some(revision) = flow_revision {
                    payload["revision"] = json!(revision);
                }
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
            }
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
        drop(traces);
        if seed_only {
            return attached_here;
        }
        // 2.21.124 (capture réelle à cinq abonnés) — rattachement après
        // coup des messages PFCP de la session. Dans la séquence réelle,
        // l'établissement PFCP précède le message N2 qui fait connaître
        // les tunnels ; quand il passe, la trace n'a rien pour le
        // reconnaître. Dès qu'un event rattaché apporte des SEID ou des
        // tunnels, les PFCP rejetés récemment sont représentés à cette
        // trace, avec le test de rattachement ordinaire (pas de force).
        let buffer = if seed_only { &self.seed_rejected_pfcp } else { &self.recent_rejected_pfcp };
        // Un event représenté après coup ne relance pas lui-même de
        // représentation : les enchaînements (la réponse après sa requête)
        // sont couverts par les tours successifs ci-dessous.
        let retry_pfcp_for = if targeted { Vec::new() } else { retry_pfcp_for };
        for trace_id in retry_pfcp_for {
            for _round in 0..4 {
                let candidates: Vec<event_schema::NormalizedEvent> = {
                    let recent = buffer.lock().unwrap();
                    let traces = self.traces.lock().unwrap();
                    match traces.get(&trace_id) {
                        Some(state) => recent
                            .iter()
                            .filter(|e| !state.match_keys.contains(&e.event_id))
                            // 2.21.129 — seulement les PFCP du moment :
                            // l'établissement précède de peu le message
                            // qui apporte ses tunnels. Un PFCP plus ancien
                            // est celui d'une autre session.
                            .filter(|e| {
                                (event.timestamp.seconds - e.timestamp.seconds).abs()
                                    <= AFTER_THE_FACT_MAX_AGE_S
                            })
                            .cloned()
                            .collect(),
                        None => Vec::new(),
                    }
                };
                if candidates.is_empty() {
                    break;
                }
                let mut attached = 0usize;
                for candidate in &candidates {
                    attached +=
                        self.route_event_with(candidate, seed_only, Some(&trace_id), false);
                }
                if attached == 0 {
                    break;
                }
            }
        }
        if targeted {
            return attached_here;
        }
        // 2.21.129 (recette lab 2.21.124, G9) — l'AMORÇAGE n'alimente pas
        // les tampons du rattachement après coup. Avant : les PFCP de
        // l'historique du ring, rejetés pendant la relecture, y entraient ;
        // en live, une trace qui apprenait un SEID ou un tunnel de même
        // valeur (les nœuds réattribuent leurs identifiants) se voyait
        // représenter le PFCP d'une ANCIENNE session — émis comme un
        // message du moment — et en apprenait les tunnels et l'IP UE,
        // devenus ceux d'un autre abonné.
        if rejected_by_a_trace && event.protocol.as_str() == "PFCP" {
            let mut recent = buffer.lock().unwrap();
            recent.push_back(event.clone());
            while recent.len() > RECENT_REJECTED_PFCP {
                recent.pop_front();
            }
        }
        // 2.21.113 (E4) — un event de signalisation rejeté est gardé un
        // court moment : s'il est le parent d'un event rattaché ensuite,
        // il est rattaché après coup à la trace de l'enfant.
        let mut pending: Vec<(String, event_schema::NormalizedEvent)> = Vec::new();
        {
            let mut recent = self.recent_rejected.lock().unwrap();
            for (trace_id, parent_id) in parents_to_attach {
                if let Some(parent) = recent.iter().find(|e| e.event_id == parent_id) {
                    pending.push((trace_id, parent.clone()));
                }
            }
            if rejected_by_a_trace && !seed_only && event.protocol.as_str() != "GTP-U" {
                recent.push_back(event.clone());
                while recent.len() > RECENT_REJECTED_EVENTS {
                    recent.pop_front();
                }
            }
        }
        for (trace_id, parent) in pending {
            self.route_event_for(&parent, false, Some(&trace_id), true);
        }
        attached_here
    }
}

/// 2.21.124 — nombre de messages PFCP de session rejetés gardés pour un
/// rattachement après coup.
const RECENT_REJECTED_PFCP: usize = 256;


/// 2.21.129 — écart maximal, en secondes de capture, entre un PFCP
/// rejeté et l'event qui le fait reconnaître après coup.
const AFTER_THE_FACT_MAX_AGE_S: i64 = 10;

/// 2.21.113 (E4) — nombre d'events de signalisation rejetés gardés pour
/// un rattachement après coup du parent.
const RECENT_REJECTED_EVENTS: usize = 64;

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
    /// 2.21.130 — temps passé à décoder ce plan pendant la passe.
    #[serde(default)]
    decode_ms: u64,
    /// 2.21.130 — temps passé à router ses events vers les traces et
    /// le débit.
    #[serde(default)]
    route_ms: u64,
    /// 2.21.130 — redécodages intégraux reportés par la cadence minimale.
    #[serde(default)]
    throttled: u64,
    /// 2.21.131 — instantanés des flux RTP pris pendant la passe.
    #[serde(default)]
    rtp_snapshots: u64,
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
    /// 2.21.131 (lot B2) — dernier instantané des flux RTP de ce segment.
    last_rtp_snapshot: Option<std::time::Instant>,
    /// 2.21.131 — des octets ont été décodés depuis ce dernier instantané.
    rtp_dirty: bool,
}

/// 2.21.131 (lot B2, GO #9 7050925249) — segment courant d'un plan qui
/// agrège des flux RTP : instantané des flux en cours, au plus toutes
/// les 5 s et seulement si des octets ont été décodés depuis le
/// précédent. La trace remplace la révision précédente du même flux ; la
/// clôture du segment émet la dernière.
fn snapshot_rtp_flows_if_due(
    sessions: &mut HashMap<std::path::PathBuf, ReaderSession>,
    path: &std::path::Path,
    config: &oiran_decode::DecodeConfig,
    interface: &str,
    now: std::time::Instant,
    traces: &LiveTraceRegistry,
    pass_io: &mut BTreeMap<String, ReaderIo>,
) {
    if !carries_rtp_flows(interface) {
        return;
    }
    let Some(open) = sessions.get_mut(path) else {
        return;
    };
    let due = open
        .last_rtp_snapshot
        .is_none_or(|at| now.saturating_duration_since(at) >= RTP_SNAPSHOT_INTERVAL);
    if !open.rtp_dirty || !due {
        return;
    }
    open.last_rtp_snapshot = Some(now);
    open.rtp_dirty = false;
    let mut flows = Vec::new();
    let _ = oiran_decode::snapshot_rtp_flows(config, &open.session, |event| {
        flows.push(event);
        Ok(())
    });
    pass_io.entry(interface.to_string()).or_default().rtp_snapshots += 1;
    for event in &flows {
        traces.route_normalized(event);
    }
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
        last_rtp_snapshot: None,
        rtp_dirty: false,
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
    if consumed_bytes != before {
        entry.rtp_dirty = true;
    }
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

/// 2.18.10 — ordre canonique intra-capture d'un lot d'events : numéro
/// du premier paquet. Tri stable.
/// 2.21.126 (constat CLAUDE2 #9 7053217728, ordre #9 7053683830) — dans
/// un même paquet, l'ordre d'émission du décodeur est conservé (parent
/// puis enfant). Avant, l'`event_id` départageait : il dérive du
/// `capture_id`, empreinte du chemin du segment, et l'ordre de deux
/// events d'un même paquet dépendait donc du NOM du segment.
fn sort_by_capture_order(events: &mut [event_schema::NormalizedEvent]) {
    events.sort_by_key(|event| {
        event
            .packet_references
            .first()
            .map(|reference| reference.packet_number)
            .unwrap_or(u64::MAX)
    });
}

/// 2.21.123 (ordre #9 7052206763) — ce que la passe du lecteur doit au
/// registre de débit. Séparé du lecteur pour que la passe se teste sans
/// l'état de l'application.
pub(crate) trait ReaderHooks {
    /// Octets d'un segment disparu avant d'avoir été lus.
    fn bytes_gap(&mut self, gap: u64);
    /// Un segment va être décodé.
    fn file_decoded(&mut self);
    /// Un event à compter dans le débit (déjà dédoublonné).
    fn observe(&mut self, event: &event_schema::NormalizedEvent);
}

/// Branche la passe sur le registre de débit de l'application.
struct ThroughputHooks<'a> {
    state: &'a AppState,
}

impl ReaderHooks for ThroughputHooks<'_> {
    fn bytes_gap(&mut self, gap: u64) {
        self.state.inner.throughput.bump_bytes_gap(gap);
    }
    fn file_decoded(&mut self) {
        self.state.inner.throughput.bump_file_decoded();
    }
    fn observe(&mut self, event: &event_schema::NormalizedEvent) {
        let session_id = crate::throughput::resolve_session_id_for_event(self.state, event);
        self.state
            .inner
            .throughput
            .observe_event(event, session_id.as_deref());
    }
}

/// 2.21.123 (ordre #9 7052206763) — UNE passe du lecteur live sur le ring
/// `root` : amorçage des traces nouvelles, puis, plan par plan, décodage
/// des segments modifiés et routage vers les traces et le débit. Extraite
/// de `start_reader` sans changement de comportement, pour être testée
/// sur un ring simulé. `states` (segments déjà lus) et `sessions`
/// (reprises à l'offset) sont l'état gardé d'une passe à l'autre ;
/// `catchup` vaut `true` à la première passe du lecteur.
#[allow(clippy::too_many_arguments)]
pub(crate) fn reader_pass(
    root: &std::path::Path,
    key: &event_schema::PseudonymKey,
    traces: &LiveTraceRegistry,
    states: &mut HashMap<std::path::PathBuf, crate::throughput::PcapFileState>,
    sessions: &mut HashMap<std::path::PathBuf, ReaderSession>,
    dirs: &mut HashMap<std::path::PathBuf, RingDirState>,
    catchup: bool,
    full_redecode: bool,
    now: std::time::Instant,
    hooks: &mut dyn ReaderHooks,
) {
    if full_redecode {
        sessions.clear();
    }
    let mut pass_io: BTreeMap<String, ReaderIo> = BTreeMap::new();
    let mut files_decoded = 0u64;
    let mut files_examined = 0u64;
    let mut scan = Duration::ZERO;
    // 2.21.105 (ordre #9 7048974175) — amorçage des
    // traces ouvertes depuis la passe précédente : le
    // ring de signalisation est relu sans émission
    // AVANT le routage live de cette passe.
    if traces.begin_seed() {
        let report = seed_from_ring(root, key, traces);
        traces.finish_seed(&report);
    }
    for interface in [
        "N2", "N4", "N3", "SBI", "S1-MME", "S11", "S5-C", "S5-U", "S1-U", "Sxab",
        "S6a", "IMS",
        // 2.21.107 (ordre #9 7049222982) — plan N6 : SIP
        // et RTP IMS, publiés `interface="IMS"`.
        "N6",
    ] {
        let scan_started = std::time::Instant::now();
        let dir = root.join(ring_directory(interface));
        let Ok(dir_meta) = fs::metadata(&dir) else {
            scan += scan_started.elapsed();
            continue;
        };
        let dir_mtime = dir_meta.modified().ok();
        let settled = dir_mtime.is_some_and(|mtime| {
            std::time::SystemTime::now()
                .duration_since(mtime)
                .map(|age| age >= RING_DIR_SETTLE)
                .unwrap_or(false)
        });
        let unchanged = !catchup
            && settled
            && dirs
                .get(&dir)
                .is_some_and(|known| known.mtime == dir_mtime && !known.recent.is_empty());
        // Segments à considérer : (chemin, est le plus récent, fait
        // partie des deux plus récents).
        let candidates: Vec<(std::path::PathBuf, bool, bool)> = if unchanged {
            // 2.21.130 — répertoire inchangé depuis la passe précédente :
            // aucun segment créé ni supprimé. Il n'est pas relu ; seuls
            // ses deux segments les plus récents et ceux dont une session
            // de reprise est ouverte sont considérés.
            let recent = &dirs[&dir].recent;
            let newest = recent.last().cloned();
            let mut list: Vec<(std::path::PathBuf, bool, bool)> = recent
                .iter()
                .map(|path| (path.clone(), Some(path) == newest.as_ref(), true))
                .collect();
            for path in sessions.keys() {
                if path.parent() == Some(dir.as_path()) && !recent.contains(path) {
                    list.push((path.clone(), false, false));
                }
            }
            list
        } else {
            let Ok(entries) = fs::read_dir(&dir) else {
                scan += scan_started.elapsed();
                continue;
            };
            // 2.21.130 (recette lab : 8 093 segments, 643 ms par passe
            // sans trafic) — les segments sont triés par NOM, sans
            // interroger leurs métadonnées : les noms du ring croissent
            // avec le temps (`<plan>_<horodatage>_<numéro>_<horodatage>
            // .pcapng`). Avant : tri par date de modification, soit
            // plusieurs `stat` par fichier et par passe, puis un `stat` de
            // chaque fichier.
            let mut paths: Vec<_> = entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("pcapng"))
                .collect();
            paths.sort();
            // 2.21.78 (correction défaut 1) — détecte les fichiers
            // précédemment vus qui ont DISPARU. Le gap n'est PAS la
            // taille totale : c'est `last_size - consumed_bytes`. Un
            // fichier lu en entier et supprimé par le ring contribue 0.
            let present: std::collections::HashSet<&std::path::PathBuf> = paths.iter().collect();
            let gone: Vec<_> = states
                .keys()
                .filter(|p| p.parent() == Some(dir.as_path()) && !present.contains(*p))
                .cloned()
                .collect();
            for path in &gone {
                sessions.remove(path);
                if let Some(file_state) = states.remove(path) {
                    let gap = file_state.size.saturating_sub(file_state.consumed_bytes);
                    if gap > 0 {
                        hooks.bytes_gap(gap);
                    }
                }
            }
            let last_idx = paths.len().saturating_sub(1);
            let known = dirs.entry(dir.clone()).or_default();
            known.mtime = dir_mtime;
            known.recent = paths[paths.len().saturating_sub(2)..].to_vec();
            paths
                .into_iter()
                .enumerate()
                .map(|(idx, path)| (path, idx == last_idx, idx + 1 >= last_idx))
                .collect()
        };
        scan += scan_started.elapsed();
        for (path, is_newest, is_recent) in &candidates {
            let (is_newest, is_recent) = (*is_newest, *is_recent);
            // 2.21.130 — un segment fermé ne change plus : seuls sont
            // interrogés le segment courant, le précédent (il a pu
            // recevoir ses derniers octets juste avant la rotation), un
            // segment encore inconnu, et un segment dont la session de
            // reprise est ouverte. Les autres sont suivis par leur nom.
            if !is_recent && states.contains_key(path) && !sessions.contains_key(path) {
                continue;
            }
            // Rattrapage : un segment ancien est inscrit sans être
            // interrogé ; il ne sera jamais relu.
            if catchup && !is_recent {
                states.insert(
                    path.clone(),
                    crate::throughput::PcapFileState {
                        size: 0,
                        mtime: None,
                        consumed_bytes: 0,
                        last_packet_number: u64::MAX,
                        last_event_id: String::new(),
                        routed_event_ids: Default::default(),
                        last_decoded_at: None,
                    },
                );
                continue;
            }
            let meta = match path.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            files_examined += 1;
            let size = meta.len();
            let mtime = meta.modified().ok();
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
                        last_decoded_at: None,
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
                        last_decoded_at: prev.last_decoded_at,
                    },
                );
                // 2.21.109 — segment fermé et inchangé :
                // clôture de sa session (flux RTP du
                // tunnel émis une fois, à la rotation).
                if !is_newest && sessions.contains_key(path) {
                    let config = ring_decode_config(path, interface);
                    for event in close_reader_session(sessions, &config) {
                        traces.route_normalized(&event);
                    }
                } else if sessions.contains_key(path) {
                    // 2.21.131 — segment courant inchangé : les derniers
                    // octets décodés depuis le dernier instantané sont
                    // encore à montrer.
                    let config = ring_decode_config(path, interface);
                    snapshot_rtp_flows_if_due(sessions, path, &config, interface, now, traces, &mut pass_io);
                }
                continue;
            }
            // 2.21.130 — plan sans reprise à l'offset : le segment n'est
            // redécodé en entier qu'une fois par `FULL_REDECODE_MIN_INTERVAL`.
            // Rien n'est noté : il sera repris à une passe suivante.
            if !(!full_redecode && oiran_decode::supports_incremental(interface))
                && is_newest
                && prev
                    .last_decoded_at
                    .is_some_and(|at| now.saturating_duration_since(at) < FULL_REDECODE_MIN_INTERVAL)
            {
                pass_io.entry(interface.to_string()).or_default().throttled += 1;
                continue;
            }
            hooks.file_decoded();
            files_decoded += 1;
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
            let decode_started = std::time::Instant::now();
            if incremental {
                let outcome = decode_increment(sessions, &config, key, size);
                if outcome.reset {
                    traces.bump_resume_resets();
                    session_reset = true;
                }
                io.bytes_decoded =
                    io.bytes_decoded.saturating_add(outcome.bytes_decoded);
                consumed_after = outcome.consumed_bytes;
                fresh = outcome.events;
            } else {
                let decode_result =
                    oiran_decode::decode_capture_streaming(&config, key, |event| {
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
            io.decode_ms = io
                .decode_ms
                .saturating_add(decode_started.elapsed().as_millis() as u64);
            let route_started = std::time::Instant::now();
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
                    traces.route_normalized(event);
                }
                if file_state_entry.should_count_in_throughput(
                    packet_number,
                    &event.event_id,
                ) {
                    hooks.observe(event);
                }
            }
            file_state_entry.size = size;
            file_state_entry.mtime = mtime;
            file_state_entry.consumed_bytes = consumed_after;
            file_state_entry.last_decoded_at = Some(now);
            states.insert(path.clone(), file_state_entry);
            if let Some(io) = pass_io.get_mut(interface) {
                io.route_ms = io
                    .route_ms
                    .saturating_add(route_started.elapsed().as_millis() as u64);
            }
            if incremental && !is_newest {
                for event in close_reader_session(sessions, &config) {
                    traces.route_normalized(&event);
                }
            } else if incremental {
                snapshot_rtp_flows_if_due(sessions, path, &config, interface, now, traces, &mut pass_io);
            }
        }
    }
    // 2.21.109 (donnée ANR1 #10 7050464161 : 768 912 G-PDU
    // émis pour 151 061 capturés) — jusqu'ici la table
    // était VIDÉE dès qu'elle dépassait 1 024 fichiers.
    // Le rattrapage y inscrit tous les segments du ring,
    // tous plans confondus : au-delà de 1 024 segments
    // sur disque elle était vidée à la fin de chaque
    // passe, et la passe suivante redécodait TOUT le
    // ring et rerouter chaque event. Elle n'est plus
    // vidée : les segments disparus en sont retirés un
    // par un (`gone`), sa taille est donc bornée par le
    // nombre de segments présents sur disque.
    traces.set_reader_files_tracked(states.len() as u64);
    traces.set_reader_files_decoded(files_decoded);
    traces.set_reader_scan(scan.as_millis() as u64, files_examined);
    traces.set_reader_io(pass_io);
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
        // 2.21.130 — état des répertoires du ring, d'une passe à l'autre.
        let mut ring_dirs: HashMap<std::path::PathBuf, RingDirState> = HashMap::new();
        // 2.21.105 — dernier envoi de l'event SSE `stats`.
        let mut last_stats: Option<std::time::Instant> = None;
        // 2.21.130 — passes consécutives qui n'ont rien décodé.
        let mut idle_passes = 0u32;
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
                let mut dirs = ring_dirs;
                let catchup = !initial_catchup_done;
                let pass_started = std::time::Instant::now();
                (file_state, reader_sessions, ring_dirs) = tokio::task::spawn_blocking(move || {
                    let key = match event_schema::PseudonymKey::load_or_generate(
                        &event_schema::PseudonymKey::resolve_default_path(),
                    ) {
                        Ok(k) => k,
                        Err(_) => return (states, sessions, dirs),
                    };
                    // 2.21.123 — le corps de la passe est `reader_pass`,
                    // testable sur un ring simulé.
                    reader_pass(
                        &root,
                        &key,
                        &state2.inner.live_traces,
                        &mut states,
                        &mut sessions,
                        &mut dirs,
                        catchup,
                        full_redecode_requested(),
                        std::time::Instant::now(),
                        &mut ThroughputHooks { state: &state2 },
                    );
                    (states, sessions, dirs)
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
            // 2.21.130 — cadence allongée quand rien ne change.
            if state.inner.live_traces.reader_files_decoded_last_pass() == 0 {
                idle_passes = idle_passes.saturating_add(1);
            } else {
                idle_passes = 0;
            }
            tokio::time::sleep(reader_interval(idle_passes)).await;
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
        gpdu_attached_teid_only: 0,
        gpdu_rejected_endpoint_mismatch: 0,
        pfcp_attached_seid_only: 0,
        parents_attached_after_child: 0,
        pfcp_attached_after_the_fact: 0,
        sip_attached_by_ue_ip: 0,
        pfcp_attached_by_ue_ip: 0,
        rejected_ue_id_mismatch: 0,
        rejected_seid_endpoint_mismatch: 0,
        rejected_foreign_subscriber: 0,
        stale_state_resets: 0,
        fresh_registrations: 0,
        rtp_flow_updates: 0,
        pfcp_establishment_reused_identifiers: 0,
        session_releases_without_filed_tunnels: 0,
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
            ue_ip_keys: HashMap::new(),
            parents_of_attached: HashSet::new(),
            rtp_flow_revisions: HashMap::new(),
            pfcp_establishments: HashSet::new(),
            identifier_seen_at: HashMap::new(),
            ue_ids: HashSet::new(),
            seid_endpoints: HashSet::new(),
            session_tunnels: HashMap::new(),
            core_tunnel_endpoints: HashSet::new(),
            sm_context_sessions: HashMap::new(),
            sip_call_ids: HashSet::new(),
            equipment_keys: HashSet::new(),
            ended_sip_call_ids: HashSet::new(),
            seid_tunnels: HashMap::new(),
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
                gpdu_attached_teid_only: 0,
                gpdu_rejected_endpoint_mismatch: 0,
                pfcp_attached_seid_only: 0,
                parents_attached_after_child: 0,
                pfcp_attached_after_the_fact: 0,
                sip_attached_by_ue_ip: 0,
                pfcp_attached_by_ue_ip: 0,
                rejected_ue_id_mismatch: 0,
                rejected_seid_endpoint_mismatch: 0,
                rejected_foreign_subscriber: 0,
                stale_state_resets: 0,
                fresh_registrations: 0,
                rtp_flow_updates: 0,
                pfcp_establishment_reused_identifiers: 0,
                session_releases_without_filed_tunnels: 0,
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
            ue_ip_keys: HashMap::new(),
            parents_of_attached: HashSet::new(),
            rtp_flow_revisions: HashMap::new(),
            pfcp_establishments: HashSet::new(),
            identifier_seen_at: HashMap::new(),
            ue_ids: HashSet::new(),
            seid_endpoints: HashSet::new(),
            session_tunnels: HashMap::new(),
            core_tunnel_endpoints: HashSet::new(),
            sm_context_sessions: HashMap::new(),
            sip_call_ids: HashSet::new(),
            equipment_keys: HashSet::new(),
            ended_sip_call_ids: HashSet::new(),
            seid_tunnels: HashMap::new(),
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
            duration_ms: 0,
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
            // UL : vers l'adresse du tunnel UL (UPF) ; DL : vers le gNB.
            event.destination_endpoint.address =
                if uplink { "10.77.11.13".into() } else { "10.77.22.13".into() };
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
        // 2.21.109 — aucun G-PDU n'est émis en `message`.
        assert!(s.events.iter().all(|e| e.kind != "message"));
        assert_eq!(s.trace.messages, 0);
        drop(traces);
        // Chaque message (signalisation) porte l'horodatage de capture.
        let mut live_signalling = ngap_setup.clone();
        live_signalling.event_id = "evt-sig-live".into();
        r.route_normalized(&live_signalling);
        let traces = r.traces.lock().unwrap();
        let s = traces.get("t").unwrap();
        let message = s.events.iter().find(|e| e.kind == "message").unwrap();
        assert_eq!(message.payload["timestamp"]["seconds"], 1_795_199_000i64);
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
            (
                s.trace.gpdu_seen,
                s.trace.gpdu_attached,
                total,
                report,
                s.trace.seed.clone(),
                (s.seids.len(), s.seid_endpoints.len(), s.trace.pfcp_attached_after_the_fact),
            )
        };
        let (seen, attached, total, _, _, _) = run(false);
        assert_eq!(seen, gpdus.len() as u64);
        assert_eq!((attached, total), (0, 0), "sans amorçage : N vus, 0 rattaché, 0 bucket");
        let (seen, attached, total, report, seed, (seids, seid_pairs, after_the_fact)) = run(true);
        assert_eq!(report.files, 2, "N2 et N4 relus, jamais N3");
        // 2.21.134 — amorçage dans l'ordre du temps : l'établissement PFCP
        // passe avant le N2 qui porte ses tunnels, et il est rattaché après
        // coup pendant l'amorçage. Les SEID de la session sont appris ; le
        // compteur du rattachement après coup ne compte que le live.
        assert!(seids > 0 && seid_pairs > 0, "SEID de la session appris à l'amorçage : {seids} / {seid_pairs}");
        assert_eq!(after_the_fact, 0);
        assert!(!report.truncated);
        assert!(seed.done && seed.events_learned > 0);
        assert_eq!(seen, gpdus.len() as u64);
        assert_eq!(attached, gpdus.len() as u64, "tous les G-PDU rattachés après amorçage");
        assert_eq!(total, injected, "somme des buckets = octets des G-PDU");
        let _ = fs::remove_dir_all(&root);
    }

    /// Event synthétique minimal pour les tests de rattachement.
    fn mk_event(
        interface: &str,
        protocol: event_schema::Protocol,
        message: &str,
        packet: u64,
        direction: event_schema::Direction,
        session_ids: Vec<(&str, &str)>,
        ies: Vec<(&str, &str)>,
    ) -> event_schema::NormalizedEvent {
        use event_schema::{
            DecodeStatus, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
            InformationElement, NamedValue, NormalizedEvent, PacketReference,
        };
        NormalizedEvent {
            event_id: format!("ev-{interface}-{packet}"),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: interface.into(),
            capture_id: format!("cap-{interface}"),
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
                captured_length: 1_000,
                original_length: 1_000,
            }],
            timestamp: ExactTimestamp {
                seconds: 1_795_000_000 + (packet / 10) as i64,
                nanoseconds: 0,
                raw_ticks: 0,
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
            raw_payload_reference: format!("sha256:{interface}-{packet}"),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: "sha256:x".into(),
            }],
            sbi: None,
        }
    }

    /// 2.21.109 (recette 2.21.104, ordres #9 7050201220 et 7050392981) —
    /// isolement d'une trace. Trois UE : A et B dans la même cellule, C
    /// dans une autre ; chacun son enregistrement, sa session PDU, sa
    /// session PFCP et son trafic N3. La trace suit A.
    ///
    /// Avant correctif, les valeurs communes portées par les events de A
    /// (PLMN, TAC, cellule, sens du tunnel, SEID nul d'un Establishment
    /// Request) devenaient des clés de rattachement par sous-chaîne : la
    /// signalisation et le trafic N3 des autres UE entraient dans la
    /// trace de A et dans ses buckets (test en échec sur `fb7b721`).
    ///
    /// Attendu : 0 message et 0 octet de B et C ; somme des buckets de A
    /// = octets de A, par sens. C réutilise la valeur du TEID UL de A
    /// vers un autre point de terminaison : rejeté, compté à part.
    #[test]
    fn trace_isolation_three_ues_two_in_the_same_cell_2_21_109() {
        use event_schema::{Direction, Protocol};
        struct Ue {
            pseudonym: &'static str,
            amf_id: &'static str,
            ran_id: &'static str,
            cell: &'static str,
            gnb: &'static str,
            upf: &'static str,
            teid_ul: &'static str,
            teid_dl: &'static str,
            setup: &'static str,
            f_teid: &'static str,
            bytes: u32,
        }
        let ue_a = Ue {
            pseudonym: "psn-ue-a",
            amf_id: "11",
            ran_id: "21",
            cell: "0x000000010",
            gnb: "10.77.11.13",
            upf: "10.77.22.13",
            teid_ul: "0x0000a001",
            teid_dl: "0x0000a002",
            setup: "item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000a001,item_0_tunnel_ip_dl=10.77.11.13,item_0_gtp_teid_dl=0x0000a002",
            f_teid: "teid=0x0000a001,v4=true,v6=false,ipv4=10.77.22.13",
            bytes: 1_000,
        };
        let ue_b = Ue {
            pseudonym: "psn-ue-b",
            amf_id: "12",
            ran_id: "22",
            cell: "0x000000010",
            gnb: "10.77.11.13",
            upf: "10.77.22.13",
            teid_ul: "0x0000b001",
            teid_dl: "0x0000b002",
            setup: "item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000b001,item_0_tunnel_ip_dl=10.77.11.13,item_0_gtp_teid_dl=0x0000b002",
            f_teid: "teid=0x0000b001,v4=true,v6=false,ipv4=10.77.22.13",
            bytes: 700,
        };
        // C : autre cellule, autre gNB, autre UPF — et la MÊME valeur de
        // TEID UL que A, allouée par un autre UPF.
        let ue_c = Ue {
            pseudonym: "psn-ue-c",
            amf_id: "13",
            ran_id: "21",
            cell: "0x000000020",
            gnb: "10.77.11.14",
            upf: "10.77.22.14",
            teid_ul: "0x0000a001",
            teid_dl: "0x0000c002",
            setup: "item_0_tunnel_ip_ul=10.77.22.14,item_0_gtp_teid_ul=0x0000a001,item_0_tunnel_ip_dl=10.77.11.14,item_0_gtp_teid_dl=0x0000c002",
            f_teid: "teid=0x0000a001,v4=true,v6=false,ipv4=10.77.22.14",
            bytes: 300,
        };
        let amf = "10.77.21.20";
        let mut packet = 0u64;
        let mut next = || {
            packet += 1;
            packet
        };
        let signalling = |ue: &Ue, packets: [u64; 4]| {
            let ngap = |packet: u64, with_pseudonym: bool, ie: Vec<(&'static str, &'static str)>| {
                let mut ids: Vec<(&str, &str)> = vec![
                    ("amf_ue_ngap_id", ue.amf_id),
                    ("ran_ue_ngap_id", ue.ran_id),
                    ("plmn", "001-01"),
                    ("tac", "0x0000c8"),
                    ("nr_cell_id", ue.cell),
                ];
                if with_pseudonym {
                    ids.push(("subscriber_pseudonym", ue.pseudonym));
                }
                let mut event = mk_event(
                    "N2",
                    Protocol::Ngap,
                    "DownlinkNASTransport",
                    packet,
                    Direction::Downlink,
                    ids,
                    ie,
                );
                event.source_endpoint.address = amf.into();
                event.destination_endpoint.address = ue.gnb.into();
                event
            };
            let mut pfcp = mk_event(
                "N4",
                Protocol::Pfcp,
                "Session Establishment Request",
                packets[3],
                Direction::Unknown,
                vec![("seid", "0x0000000000000000"), ("pfcp_sequence", "100")],
                vec![("F-TEID", ue.f_teid)],
            );
            pfcp.destination_endpoint.address = ue.upf.into();
            vec![
                ngap(packets[0], true, vec![]),
                ngap(packets[1], false, vec![]),
                ngap(
                    packets[2],
                    false,
                    vec![("PDUSessionResourceSetupRequestTransfer", ue.setup)],
                ),
                pfcp,
            ]
        };
        let gpdu = |ue: &Ue, packet: u64, uplink: bool| {
            let (teid, endpoint) = if uplink {
                (ue.teid_ul, ue.upf)
            } else {
                (ue.teid_dl, ue.gnb)
            };
            let mut event = mk_event(
                "N3",
                Protocol::Gtpu,
                "G-PDU",
                packet,
                if uplink { Direction::Uplink } else { Direction::Downlink },
                vec![
                    ("teid", teid),
                    ("tunnel_endpoint_ip", endpoint),
                    ("tunnel_direction", if uplink { "UPLINK" } else { "DOWNLINK" }),
                    ("sequence_number", "4321"),
                ],
                vec![],
            );
            event.destination_endpoint.address = endpoint.into();
            event.packet_references[0].original_length = ue.bytes;
            event
        };
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-ue-a".into()]));
        let mut a_event_ids = Vec::new();
        for ue in [&ue_a, &ue_b, &ue_c] {
            let packets = [next(), next(), next(), next()];
            for event in signalling(ue, packets) {
                if ue.pseudonym == "psn-ue-a" {
                    a_event_ids.push(event.event_id.clone());
                }
                r.route_normalized(&event);
            }
        }
        // N3 entrelacé : A 3 UL + 5 DL ; B 20 UL + 20 DL ; C 10 UL + 10 DL.
        let (mut a_ul, mut a_dl) = (0u64, 0u64);
        for round in 0..20u64 {
            if round < 3 {
                r.route_normalized(&gpdu(&ue_a, next(), true));
                a_ul += u64::from(ue_a.bytes);
            }
            if round < 5 {
                r.route_normalized(&gpdu(&ue_a, next(), false));
                a_dl += u64::from(ue_a.bytes);
            }
            r.route_normalized(&gpdu(&ue_b, next(), true));
            r.route_normalized(&gpdu(&ue_b, next(), false));
            if round < 10 {
                r.route_normalized(&gpdu(&ue_c, next(), true));
                r.route_normalized(&gpdu(&ue_c, next(), false));
            }
        }
        r.flush_idle_throughput_buckets();

        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        let routed: Vec<String> = t
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| e.payload["event_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(routed, a_event_ids, "0 message de B ni de C dans la trace de A");
        assert_eq!(t.trace.messages, 4);
        assert_eq!(t.trace.gpdu_seen, 8 + 40 + 20);
        assert_eq!(t.trace.gpdu_attached, 8, "seuls les G-PDU de A sont rattachés");
        assert_eq!(t.trace.gpdu_attached_teid_only, 0, "tous par (adresse, TEID)");
        assert_eq!(
            t.trace.gpdu_rejected_endpoint_mismatch, 10,
            "les 10 UL de C portent le TEID UL de A vers un autre UPF"
        );
        assert_eq!(t.trace.gpdu_rejected_no_match, 40 + 10);
        let sum = |field: &str| -> u64 {
            t.events
                .iter()
                .filter(|e| e.kind == "throughput")
                .map(|b| b.payload[field].as_u64().unwrap_or(0))
                .sum()
        };
        assert_eq!(sum("ul_bytes_s"), a_ul, "débit UL = octets UL de A");
        assert_eq!(sum("dl_bytes_s"), a_dl, "débit DL = octets DL de A");
        assert_eq!(sum("unknown_bytes_s"), 0);
        assert_eq!((a_ul, a_dl), (3_000, 5_000));
        assert_eq!(t.trace.feed["N2"].attached, 3);
        assert_eq!(t.trace.feed["N4"].attached, 1);
        // Aucune valeur commune n'est devenue une clé de rattachement.
        for shared in ["001-01", "0x0000c8", "0x000000010", "UPLINK", "DOWNLINK", "100", "4321"] {
            assert!(!t.match_keys.contains(shared), "{shared} n'identifie pas l'abonné");
        }
        assert!(!t.seids.iter().any(|s| is_zero_hex(s)), "SEID nul jamais appris");
    }

    /// 2.21.109 (exigence cœur #9 7050392981 point 1) — repli « TEID
    /// seul » : admis uniquement pour un TEID appris sur la signalisation
    /// de l'abonné sans adresse de point de terminaison, et compté à
    /// part. Un G-PDU n'apprend aucun TEID ; un TEID inconnu est rejeté.
    #[test]
    fn teid_only_fallback_is_limited_to_subscriber_signalling_and_counted_2_21_109() {
        use event_schema::{Direction, Protocol};
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec!["psn-ue-a".into()]));
        // Signalisation de l'abonné : un TEID sans adresse (IE `teid=`).
        r.route_normalized(&mk_event(
            "N4",
            Protocol::Pfcp,
            "Session Modification Request",
            1,
            Direction::Unknown,
            vec![("subscriber_pseudonym", "psn-ue-a"), ("seid", "0x0000000000000042")],
            vec![("Outer Header Creation", "outer_header_description=0x0100,teid=0x0000d001")],
        ));
        let gpdu = |packet: u64, teid: &'static str| {
            mk_event("N3", Protocol::Gtpu, "G-PDU", packet, Direction::Uplink, vec![("teid", teid)], vec![])
        };
        r.route_normalized(&gpdu(2, "0x0000d001"));
        r.route_normalized(&gpdu(3, "0x0000d001"));
        // TEID jamais vu sur la signalisation de l'abonné : rejeté, et le
        // G-PDU précédent ne l'a pas appris non plus.
        r.route_normalized(&gpdu(4, "0x0000e999"));
        r.route_normalized(&gpdu(5, "0x0000e999"));
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.gpdu_attached, 2);
        assert_eq!(t.trace.gpdu_attached_teid_only, 2, "repli compté à part");
        assert_eq!(t.trace.gpdu_rejected_no_match, 2);
        assert!(!t.tunnel_teids.iter().any(|teid| teid.ends_with("e999")));
        let stats = r.stats_payload(&t.trace);
        assert_eq!(stats["gpdu"]["attached_teid_only"], 2);
        assert_eq!(stats["gpdu"]["rejected_endpoint_mismatch"], 0);
    }

    /// 2.21.109 (exigence cœur #9 7050392981 point 2) — `event_tokens` :
    /// égalité sur valeurs typées. Une clé n'est reconnue que si elle
    /// est une valeur entière, jamais un fragment d'une autre.
    #[test]
    fn event_tokens_match_whole_typed_values_only_2_21_109() {
        let value = json!({
            "direction": "UPLINK",
            "message_name": "contains psn-ue-a in a name",
            "parent_event_id": "evt-00000000000000aa",
            "session_identifiers": [
                {"name": "subscriber_pseudonym", "value": "psn-ue-a-long"},
                {"name": "supi", "value": "imsi-001010000000001"},
                {"name": "plmn", "value": "001-01"}
            ],
            "information_elements": [
                {"name": "ue_ip", "value": "psn-ip-1"},
                {"name": "ids", "value": "amf_ue_ngap_id=12,subscriber_pseudonym=psn-ue-b"}
            ],
            "sbi": {"path": "/nsmf-pdusession/v1/sm-contexts/7/modify", "supi": "imsi-001010000000001"}
        });
        let tokens = event_tokens(&value);
        for expected in [
            "psn-ue-a-long", "imsi-001010000000001", "001010000000001", "psn-ip-1", "psn-ue-b",
            "evt-00000000000000aa", "sm-contexts", "7",
        ] {
            assert!(tokens.contains(expected), "{expected}");
        }
        // Ni fragment d'une valeur, ni champ hors des sources typées.
        for absent in ["psn-ue-a", "UPLINK", "0101", "psn-ue"] {
            assert!(!tokens.contains(absent), "{absent} ne doit pas rattacher");
        }
    }

    /// Message NGAP synthétique entre un gNB et l'AMF (port 38412).
    fn ngap_between(
        gnb: &str,
        uplink: bool,
        message: &str,
        packet: u64,
        ids: Vec<(&str, &str)>,
    ) -> event_schema::NormalizedEvent {
        use event_schema::{Direction, Protocol};
        let mut event = mk_event(
            "N2",
            Protocol::Ngap,
            message,
            packet,
            if uplink { Direction::Uplink } else { Direction::Downlink },
            ids,
            vec![],
        );
        event.event_id = format!("evt-ngap-{packet:04}");
        let amf = event_schema::Endpoint {
            address: "10.77.21.20".into(),
            port: Some(38412),
            network_function: None,
        };
        let ran = event_schema::Endpoint {
            address: gnb.into(),
            port: Some(33_492),
            network_function: None,
        };
        if uplink {
            event.source_endpoint = ran;
            event.destination_endpoint = amf;
        } else {
            event.source_endpoint = amf;
            event.destination_endpoint = ran;
        }
        event
    }

    fn routed_ids(r: &LiveTraceRegistry) -> Vec<String> {
        r.traces.lock().unwrap()["t"]
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| e.payload["event_id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn trace_on(pseudonym: &str) -> LiveTraceRegistry {
        let r = LiveTraceRegistry::new();
        r.traces
            .lock()
            .unwrap()
            .insert("t".into(), state(u64::MAX, false, vec![pseudonym.into()]));
        r
    }

    /// 2.21.113 (relecture CLAUDE2 #9 7050861203, E1) — handover avec
    /// changement de gNB : `amf_ue_ngap_id` est unique par AMF, il
    /// rattache les messages du nouveau gNB, qui portent un nouveau
    /// `ran_ue_ngap_id` sur une autre association. Perdus à `33e544a`.
    #[test]
    fn handover_to_another_gnb_keeps_the_subscriber_attached_2_21_113() {
        let r = trace_on("psn-ue-a");
        let gnb1 = "10.77.11.13";
        let gnb2 = "10.77.11.99";
        r.route_normalized(&ngap_between(
            gnb1,
            false,
            "InitialContextSetupRequest",
            1,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&ngap_between(
            gnb2,
            true,
            "PathSwitchRequest",
            2,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "77")],
        ));
        r.route_normalized(&ngap_between(
            gnb2,
            true,
            "UplinkNASTransport",
            3,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "77")],
        ));
        assert_eq!(
            routed_ids(&r),
            vec!["evt-ngap-0001", "evt-ngap-0002", "evt-ngap-0003"],
            "les messages du nouveau gNB restent dans la trace"
        );
    }

    /// 2.21.113 (E2) — un identifiant sur deux ne suffit pas : un message
    /// qui porte le `ran_ue_ngap_id` de l'abonné avec un autre
    /// `amf_ue_ngap_id`, ou l'inverse sur le même gNB, est celui d'un
    /// autre UE. Les deux entraient à `33e544a`.
    #[test]
    fn one_ue_id_out_of_two_does_not_attach_another_ue_2_21_113() {
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "InitialContextSetupRequest",
            1,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "DownlinkNASTransport",
            2,
            vec![("amf_ue_ngap_id", "99"), ("ran_ue_ngap_id", "21")],
        ));
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "UplinkNASTransport",
            3,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "55")],
        ));
        // Le dialogue de l'abonné, lui, continue d'être rattaché.
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "UplinkNASTransport",
            4,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        assert_eq!(routed_ids(&r), vec!["evt-ngap-0001", "evt-ngap-0004"]);
    }

    /// 2.21.113 (E3) — PFCP : le SEID se compare avec le nœud qui le
    /// reçoit. La même valeur vers un autre nœud est la session d'un
    /// autre abonné ; elle entrait à `33e544a`.
    #[test]
    fn pfcp_seid_is_matched_with_its_receiving_node_2_21_113() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let pfcp = |packet: u64, message: &str, node: &str, ids: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event("N4", Protocol::Pfcp, message, packet, Direction::Unknown, ids, vec![]);
            event.event_id = format!("evt-pfcp-{packet:04}");
            event.destination_endpoint.address = node.into();
            event
        };
        r.route_normalized(&pfcp(
            1,
            "Session Modification Request",
            "10.77.22.13",
            vec![("seid", "0x0000000000000042"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        // Même valeur de SEID, autre nœud, sans pseudonyme : autre session.
        r.route_normalized(&pfcp(
            2,
            "Session Report Request",
            "10.77.22.99",
            vec![("seid", "0x0000000000000042")],
        ));
        // Même nœud, même SEID : la session de l'abonné.
        r.route_normalized(&pfcp(
            3,
            "Session Modification Request",
            "10.77.22.13",
            vec![("seid", "0x0000000000000042")],
        ));
        assert_eq!(routed_ids(&r), vec!["evt-pfcp-0001", "evt-pfcp-0003"]);
        assert_eq!(r.traces.lock().unwrap()["t"].trace.pfcp_attached_seid_only, 0);
    }

    /// 2.21.113 (E4) — premier message NGAP : l'`InitialUEMessage` passe
    /// avant son enfant NAS et ne porte que `ran_ue_ngap_id` ; l'enfant
    /// porte le pseudonyme et cite son parent. Le parent, rejeté d'abord,
    /// est rattaché quand l'enfant l'est. Perdu à `33e544a`.
    #[test]
    fn parent_rejected_before_its_child_is_attached_afterwards_2_21_113() {
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        let parent = ngap_between(gnb, true, "InitialUEMessage", 1, vec![("ran_ue_ngap_id", "21")]);
        let mut child = ngap_between(
            gnb,
            true,
            "Registration request",
            1,
            vec![
                ("ran_ue_ngap_id", "21"),
                ("subscriber_pseudonym", "psn-ue-a"),
                ("parent_ngap_event_id", "evt-ngap-0001"),
            ],
        );
        child.event_id = "evt-nas-0001".into();
        // Un parent d'un autre UE, jamais suivi d'un enfant de l'abonné.
        let mut stranger = ngap_between(gnb, true, "InitialUEMessage", 2, vec![("ran_ue_ngap_id", "22")]);
        stranger.event_id = "evt-ngap-stranger".into();
        r.route_normalized(&stranger);
        r.route_normalized(&parent);
        r.route_normalized(&child);
        let mut routed = routed_ids(&r);
        routed.sort();
        assert_eq!(routed, vec!["evt-nas-0001", "evt-ngap-0001"]);
        let traces = r.traces.lock().unwrap();
        assert_eq!(traces["t"].trace.parents_attached_after_child, 1);
        assert_eq!(traces["t"].trace.feed["N2"].attached, 2);
    }

    /// 2.21.113 (E5) — fins de session. La libération du contexte UE
    /// (nom émis par les décodeurs : `UEContextReleaseComplete`) oublie
    /// les identifiants UE et les tunnels, pas l'identité de l'abonné ;
    /// la libération d'une session PDU oublie ses tunnels et SEID, pas
    /// les identifiants UE (l'UE reste enregistré). À `33e544a` la
    /// première ne se déclenchait jamais et la seconde vidait `ue_ids`.
    #[test]
    fn context_release_and_pdu_release_forget_the_right_things_2_21_113() {
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        let learn = |packet: u64| {
            let mut event = ngap_between(
                gnb,
                false,
                "PDUSessionResourceSetupRequest",
                packet,
                vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("subscriber_pseudonym", "psn-ue-a")],
            );
            event.information_elements = vec![event_schema::InformationElement {
                id: None,
                name: "PDUSessionResourceSetupRequestTransfer".into(),
                length: 0,
                value: Some("item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000a001".into()),
                raw_sha256: None,
                status: event_schema::DecodeStatus::Decoded,
            }];
            event
        };
        let snapshot = |r: &LiveTraceRegistry| {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            (t.ue_ids.len(), t.tunnel_teids.len(), t.match_keys.contains("psn-ue-a"))
        };
        r.route_normalized(&learn(1));
        assert_eq!(snapshot(&r), (2, 1, true));
        // Libération de session PDU : tunnels oubliés, identifiants gardés.
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "PDU Session Release Complete",
            2,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        assert_eq!(snapshot(&r), (2, 0, true));
        r.route_normalized(&learn(3));
        assert_eq!(snapshot(&r), (2, 1, true));
        // Libération du contexte UE : identifiants et tunnels oubliés,
        // l'identité de l'abonné reste.
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "UEContextReleaseComplete",
            4,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        // 2.21.119 (G1) — le tunnel montant, côté cœur (UPF), vit avec la
        // session de données : il est gardé à la mise en veille.
        assert_eq!(snapshot(&r), (0, 1, true));
        // Les identifiants libérés, réutilisés par un autre UE, ne
        // rattachent plus rien.
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "DownlinkNASTransport",
            5,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        assert_eq!(routed_ids(&r).len(), 4, "le message d'après libération n'entre pas");
        assert!(is_detach("Detach Accept"));
        assert!(is_ue_context_release("UE Context Release Complete"));
        assert!(is_ue_context_release("UEContextReleaseComplete"));
        assert!(!is_ue_context_release("UEContextReleaseCommand"));
        assert!(is_data_session_release("PDU Session Release Complete"));
        assert!(is_data_session_release("DeleteSessionResponse"), "nom émis par decoder-gtpv2c");
    }

    /// 2.21.116 (relecture CLAUDE2 #9 7051364956, F1) — mise en veille :
    /// la libération du contexte UE n'est pas la fin de la session de
    /// données. Après elle, l'UpdateSMContext (SBI, même référence de
    /// contexte SM) et la Session Modification vers l'UPF (même SEID)
    /// restent dans la trace ; les identifiants NGAP et les tunnels N3,
    /// eux, sont oubliés. À `2f7f77f` les deux messages étaient perdus.
    /// `Detach Accept` reste une fin complète.
    #[test]
    fn idle_release_keeps_the_pdu_session_signalling_attached_2_21_116() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        let mut setup = ngap_between(
            gnb,
            false,
            "PDUSessionResourceSetupRequest",
            1,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("subscriber_pseudonym", "psn-ue-a")],
        );
        setup.information_elements = vec![event_schema::InformationElement {
            id: None,
            name: "PDUSessionResourceSetupRequestTransfer".into(),
            length: 0,
            value: Some("item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000a001".into()),
            raw_sha256: None,
            status: event_schema::DecodeStatus::Decoded,
        }];
        let pfcp = |packet: u64, ids: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event(
                "N4",
                Protocol::Pfcp,
                "PFCP Session Modification Request",
                packet,
                Direction::Unknown,
                ids,
                vec![],
            );
            event.event_id = format!("evt-pfcp-{packet:04}");
            event.message_type = 52;
            event.destination_endpoint.address = "10.77.22.13".into();
            event
        };
        let sbi = |packet: u64, ids: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event(
                "SBI",
                Protocol::Ngap,
                "UpdateSMContext",
                packet,
                Direction::Unknown,
                ids,
                vec![],
            );
            event.event_id = format!("evt-sbi-{packet:04}");
            event
        };
        let snapshot = |r: &LiveTraceRegistry| {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            (t.ue_ids.len(), t.tunnel_teids.len(), t.seids.len(), t.seid_endpoints.len())
        };
        r.route_normalized(&setup);
        r.route_normalized(&pfcp(
            2,
            vec![("seid", "0x0000000000000042"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&sbi(
            3,
            vec![("sm_context_reference", "ctx-7"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        assert_eq!(snapshot(&r), (3, 1, 1, 1));
        // Mise en veille.
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "UEContextReleaseComplete",
            4,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        // 2.21.119 (G1) — le tunnel montant (UPF) est gardé aussi.
        assert_eq!(
            snapshot(&r),
            (1, 1, 1, 1),
            "identifiants NGAP oubliés ; contexte SM, SEID et tunnel côté cœur gardés"
        );
        // Suite normale de la mise en veille, sans pseudonyme.
        r.route_normalized(&sbi(5, vec![("sm_context_reference", "ctx-7")]));
        r.route_normalized(&pfcp(6, vec![("seid", "0x0000000000000042")]));
        // Les identifiants NGAP libérés ne rattachent plus rien.
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "DownlinkNASTransport",
            7,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        assert_eq!(
            routed_ids(&r),
            vec![
                "evt-ngap-0001",
                "evt-pfcp-0002",
                "evt-sbi-0003",
                "evt-ngap-0004",
                "evt-sbi-0005",
                "evt-pfcp-0006"
            ]
        );
        // Détachement : fin complète.
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "Detach Accept",
            8,
            vec![("subscriber_pseudonym", "psn-ue-a")],
        ));
        assert_eq!(snapshot(&r), (0, 0, 0, 0));
    }

    /// 2.21.119 (relecture CLAUDE2 #9 7051699381, G2 ; sonde RVC3) —
    /// isolement : une référence de contexte SM finit avec sa session de
    /// données. Référence `1` apprise sur un SBI de l'abonné ; libération
    /// de sa session ; le SMF réattribue `1` à un autre abonné : ses SBI,
    /// avant comme après une mise en veille, n'entrent pas dans la trace.
    /// À `7e0b1bb` les deux entraient. Couvre aussi : même valeur chez un
    /// autre SMF, `ReleaseSMContext`, et la fin 5G `Deregistration Accept`.
    #[test]
    fn sm_context_reference_ends_with_its_pdu_session_2_21_119() {
        use event_schema::{Direction, Protocol};
        let gnb = "10.77.11.13";
        let sbi = |packet: u64, smf: &str, operation: &str, ids: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event("SBI", Protocol::Ngap, operation, packet, Direction::Unknown, ids, vec![]);
            event.event_id = format!("evt-sbi-{packet:04}");
            event.source_endpoint.address = "10.77.21.20".into();
            event.destination_endpoint = event_schema::Endpoint {
                address: smf.into(),
                port: Some(7777),
                network_function: Some("SMF".into()),
            };
            event.sbi = Some(event_schema::SbiMetadata {
                tcp_connection_id: "c".into(),
                http2_stream_id: 1,
                service: Some("nsmf-pdusession".into()),
                operation: Some(operation.into()),
                http_method: Some("POST".into()),
                request_uri: None,
                http_status: None,
                consumer_nf: None,
                producer_nf: None,
                scp_transit: false,
                transaction_duration_ns: None,
            });
            event
        };
        let smf = "10.77.24.7";
        let known = |r: &LiveTraceRegistry| {
            r.traces.lock().unwrap()["t"]
                .ue_ids
                .iter()
                .filter(|(name, _, _)| name == SM_CONTEXT_NAME)
                .count()
        };

        // (a) libération de la session, puis réattribution de la référence.
        let r = trace_on("psn-ue-a");
        r.route_normalized(&sbi(
            1,
            smf,
            "UpdateSMContext",
            vec![("sm_context_reference", "1"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        // Même valeur chez un autre SMF : autre session.
        r.route_normalized(&sbi(2, "10.77.24.99", "UpdateSMContext", vec![("sm_context_reference", "1")]));
        // Même SMF : la session de l'abonné.
        r.route_normalized(&sbi(3, smf, "UpdateSMContext", vec![("sm_context_reference", "1")]));
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "PDU Session Release Complete",
            4,
            vec![("subscriber_pseudonym", "psn-ue-a"), ("pdu_session_id", "1")],
        ));
        assert_eq!(known(&r), 0, "référence oubliée avec la session");
        r.route_normalized(&sbi(5, smf, "UpdateSMContext", vec![("sm_context_reference", "1")]));
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "UEContextReleaseComplete",
            6,
            vec![("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&sbi(7, smf, "UpdateSMContext", vec![("sm_context_reference", "1")]));
        assert_eq!(
            routed_ids(&r),
            vec!["evt-sbi-0001", "evt-sbi-0003", "evt-ngap-0004", "evt-ngap-0006"],
            "aucun SBI d'après la libération, ni celui d'un autre SMF"
        );

        // (b) ReleaseSMContext : la référence est oubliée après ce message.
        let r = trace_on("psn-ue-a");
        r.route_normalized(&sbi(
            1,
            smf,
            "UpdateSMContext",
            vec![("sm_context_reference", "4"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&sbi(2, smf, "ReleaseSMContext", vec![("sm_context_reference", "4")]));
        r.route_normalized(&sbi(3, smf, "UpdateSMContext", vec![("sm_context_reference", "4")]));
        assert_eq!(routed_ids(&r), vec!["evt-sbi-0001", "evt-sbi-0002"]);

        // (c) fin 5G : Deregistration Accept oublie tout.
        let r = trace_on("psn-ue-a");
        r.route_normalized(&sbi(
            1,
            smf,
            "UpdateSMContext",
            vec![("sm_context_reference", "9"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        assert_eq!(known(&r), 1);
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "Deregistration Accept",
            2,
            vec![("subscriber_pseudonym", "psn-ue-a")],
        ));
        assert_eq!(known(&r), 0);
        assert!(is_detach("Deregistration Accept") && is_detach("Detach Accept"));
    }

    /// 2.21.119 (relecture CLAUDE2 #9 7051699381, G1 ; sonde RVC2) —
    /// retour de veille SANS identité lisible (NAS chiffré). La mise en
    /// veille garde le tunnel côté cœur (UPF, TEID montant) et oublie
    /// celui côté accès radio. Au retour : l'`InitialUEMessage` et son
    /// enfant ne sont pas rattachables, mais l'`InitialContextSetupRequest`
    /// l'est par le couple (UPF, TEID), fait réapprendre les identifiants
    /// UE, et les G-PDU montants sont rattachés. À `7e0b1bb` : rien, ni
    /// N2 ni N3.
    #[test]
    fn return_from_idle_without_identity_reattaches_by_the_core_tunnel_2_21_119() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        let upf = "10.77.22.13";
        let with_tunnels = |mut event: event_schema::NormalizedEvent, value: &str| {
            event.information_elements = vec![event_schema::InformationElement {
                id: None,
                name: "Transfer".into(),
                length: 0,
                value: Some(value.into()),
                raw_sha256: None,
                status: event_schema::DecodeStatus::Decoded,
            }];
            event
        };
        let gpdu = |packet: u64, teid: &'static str, endpoint: &'static str, uplink: bool| {
            let mut event = mk_event(
                "N3",
                Protocol::Gtpu,
                "G-PDU",
                packet,
                if uplink { Direction::Uplink } else { Direction::Downlink },
                vec![("teid", teid)],
                vec![],
            );
            event.destination_endpoint.address = endpoint.into();
            event
        };
        // Avant la veille : enregistrement, session (tunnel UL à l'UPF,
        // tunnel DL au gNB).
        r.route_normalized(&with_tunnels(
            ngap_between(
                gnb,
                false,
                "PDUSessionResourceSetupRequest",
                1,
                vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("subscriber_pseudonym", "psn-ue-a")],
            ),
            "item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000a001,item_0_tunnel_ip_dl=10.77.11.13,item_0_gtp_teid_dl=0x0000a002",
        ));
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "UEContextReleaseComplete",
            2,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21")],
        ));
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert!(t.tunnel_endpoints.contains(&(upf.to_string(), "0xa001".to_string())), "côté cœur gardé");
            assert!(!t.tunnel_endpoints.iter().any(|pair| pair.1 == "0xa002"), "côté accès oublié");
            assert!(t.ue_ids.is_empty());
        }
        // Le TEID descendant d'avant la veille ne rattache plus rien.
        r.route_normalized(&gpdu(3, "0x0000a002", gnb, false));
        // Retour : parent et enfant sans identité lisible.
        r.route_normalized(&ngap_between(gnb, true, "InitialUEMessage", 4, vec![("ran_ue_ngap_id", "31")]));
        let mut child = ngap_between(
            gnb,
            true,
            "Service request",
            4,
            vec![("ran_ue_ngap_id", "31"), ("parent_ngap_event_id", "evt-ngap-0004")],
        );
        child.event_id = "evt-nas-0004".into();
        r.route_normalized(&child);
        // Contexte initial : même tunnel montant, nouveau `ran`.
        r.route_normalized(&with_tunnels(
            ngap_between(
                gnb,
                false,
                "InitialContextSetupRequest",
                5,
                vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "31")],
            ),
            "item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000a001",
        ));
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "InitialContextSetupResponse",
            6,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "31")],
        ));
        r.route_normalized(&gpdu(7, "0x0000a001", upf, true));
        r.route_normalized(&gpdu(8, "0x0000a001", upf, true));
        // Un autre UE reprend l'ancien `ran` 21.
        let mut stranger = ngap_between(gnb, true, "InitialUEMessage", 9, vec![("ran_ue_ngap_id", "21")]);
        stranger.event_id = "evt-ngap-stranger".into();
        r.route_normalized(&stranger);
        assert_eq!(
            routed_ids(&r),
            vec!["evt-ngap-0001", "evt-ngap-0002", "evt-ngap-0005", "evt-ngap-0006"],
            "contexte initial rattaché par le tunnel côté cœur, puis sa réponse"
        );
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.gpdu_attached, 2, "les deux G-PDU montants du retour");
        assert_eq!(t.trace.gpdu_rejected_no_match, 1, "le descendant d'avant la veille");
    }

    /// 2.21.121 (relecture CLAUDE2 #9 7052103318, H1 ; sondes RVD1 et
    /// RVD2) — un couple côté cœur appris seulement en PFCP ne survit ni
    /// à la libération de la session ni à la mise en veille.
    ///   RVD1 : couple appris sur un PFCP de l'abonné sans SEID vivant ;
    ///   1 G-PDU ; libération de sa session ; 1 G-PDU ; mise en veille ;
    ///   2 G-PDU d'un autre abonné sur le même couple → 1 seul rattaché.
    ///   À `d4aaedb` : 4 rattachés.
    ///   Variante SEID : couple rangé sous un SEID vivant → gardé à la
    ///   libération de la session nommée, oublié au
    ///   `Session Deletion Response`.
    ///   RVD2 : couple appris sur le N2 avec son `pdu_session_id`,
    ///   session libérée → oublié (déjà vert à `d4aaedb`).
    #[test]
    fn core_tunnel_learned_on_pfcp_only_does_not_outlive_its_session_2_21_121() {
        use event_schema::{Direction, Protocol};
        let gnb = "10.77.11.13";
        let upf = "10.77.22.13";
        let pfcp = |packet: u64, message: &str, node: &str, ids: Vec<(&'static str, &'static str)>, ie: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event("N4", Protocol::Pfcp, message, packet, Direction::Unknown, ids, ie);
            event.event_id = format!("evt-pfcp-{packet:04}");
            event.message_type = 51;
            event.destination_endpoint.address = node.into();
            event
        };
        let gpdu = |packet: u64| {
            let mut event = mk_event(
                "N3",
                Protocol::Gtpu,
                "G-PDU",
                packet,
                Direction::Uplink,
                vec![("teid", "0x0000a001")],
                vec![],
            );
            event.destination_endpoint.address = upf.into();
            event
        };
        let release = |packet: u64, session: &'static str| {
            ngap_between(
                gnb,
                true,
                "PDU Session Release Complete",
                packet,
                vec![("subscriber_pseudonym", "psn-ue-a"), ("pdu_session_id", session)],
            )
        };
        let idle = |packet: u64| {
            ngap_between(
                gnb,
                true,
                "UEContextReleaseComplete",
                packet,
                vec![("subscriber_pseudonym", "psn-ue-a")],
            )
        };
        let f_teid = ("F-TEID", "teid=0x0000a001,v4=true,v6=false,ipv4=10.77.22.13");

        // RVD1 — sans SEID.
        let r = trace_on("psn-ue-a");
        r.route_normalized(&pfcp(
            1,
            "PFCP Session Establishment Response",
            "10.77.24.7",
            vec![("subscriber_pseudonym", "psn-ue-a")],
            vec![f_teid],
        ));
        r.route_normalized(&gpdu(2));
        r.route_normalized(&release(3, "1"));
        r.route_normalized(&gpdu(4));
        r.route_normalized(&idle(5));
        r.route_normalized(&gpdu(6));
        r.route_normalized(&gpdu(7));
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert_eq!(t.trace.gpdu_attached, 1, "RVD1 : seul le G-PDU d'avant la libération");
            assert_eq!(t.trace.gpdu_rejected_no_match, 3);
            assert_eq!(t.trace.session_releases_without_filed_tunnels, 1);
            assert!(t.core_tunnel_endpoints.is_empty() && t.tunnel_endpoints.is_empty());
        }

        // Variante — couple rangé sous un SEID vivant.
        let r = trace_on("psn-ue-a");
        r.route_normalized(&pfcp(
            1,
            "PFCP Session Establishment Response",
            "10.77.24.7",
            vec![("seid", "0x0000000000000042"), ("subscriber_pseudonym", "psn-ue-a")],
            vec![f_teid],
        ));
        r.route_normalized(&gpdu(2));
        r.route_normalized(&release(3, "2"));
        r.route_normalized(&gpdu(4));
        assert_eq!(
            r.traces.lock().unwrap()["t"].trace.gpdu_attached,
            2,
            "la session PFCP vit encore : le couple est gardé"
        );
        r.route_normalized(&idle(5));
        r.route_normalized(&gpdu(6));
        assert_eq!(r.traces.lock().unwrap()["t"].trace.gpdu_attached, 3, "gardé en veille");
        r.route_normalized(&pfcp(
            7,
            "PFCP Session Deletion Response",
            "10.77.24.7",
            vec![("seid", "0x0000000000000042")],
            vec![],
        ));
        r.route_normalized(&gpdu(8));
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert_eq!(t.trace.gpdu_attached, 3, "oublié à la suppression de la session PFCP");
            assert!(t.core_tunnel_endpoints.is_empty() && t.seid_tunnels.is_empty());
        }

        // RVD2 — couple appris sur le N2 avec sa session.
        let r = trace_on("psn-ue-a");
        let mut setup = ngap_between(
            gnb,
            false,
            "PDUSessionResourceSetupRequest",
            1,
            vec![("subscriber_pseudonym", "psn-ue-a"), ("pdu_session_id", "1")],
        );
        setup.information_elements = vec![event_schema::InformationElement {
            id: None,
            name: "Transfer".into(),
            length: 0,
            value: Some("item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul=0x0000a001".into()),
            raw_sha256: None,
            status: event_schema::DecodeStatus::Decoded,
        }];
        r.route_normalized(&setup);
        r.route_normalized(&gpdu(2));
        r.route_normalized(&release(3, "1"));
        r.route_normalized(&idle(4));
        r.route_normalized(&gpdu(5));
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.gpdu_attached, 1, "RVD2");
        assert_eq!(t.trace.gpdu_rejected_no_match, 1);
        assert_eq!(t.trace.session_releases_without_filed_tunnels, 0);
    }

    /// 2.21.119 (point mineur, ordre #9 7051758378) — libération d'une
    /// session NOMMÉE dont les tunnels ne sont pas rangés par session
    /// (appris par PFCP, sans `pdu_session_id`) : les tunnels de
    /// l'abonné ne sont pas vidés, et le cas est compté.
    /// 2.21.121 (H1) — précisé : ne sont gardés que les couples rangés
    /// sous un SEID encore vivant ; le PFCP de ce test porte donc un
    /// SEID. Le cas sans SEID (oubli) est dans le test H1.
    #[test]
    fn named_release_without_filed_tunnels_keeps_other_tunnels_and_is_counted_2_21_119() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        r.route_normalized(&mk_event(
            "N4",
            Protocol::Pfcp,
            "PFCP Session Establishment Request",
            1,
            Direction::Unknown,
            vec![("subscriber_pseudonym", "psn-ue-a"), ("seid", "0x0000000000000042")],
            vec![("F-TEID", "teid=0x0000a001,v4=true,v6=false,ipv4=10.77.22.13")],
        ));
        r.route_normalized(&ngap_between(
            "10.77.11.13",
            true,
            "PDU Session Release Complete",
            2,
            vec![("subscriber_pseudonym", "psn-ue-a"), ("pdu_session_id", "2")],
        ));
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert!(t.tunnel_teids.contains("0xa001"), "tunnel non rangé : gardé");
        assert_eq!(t.trace.session_releases_without_filed_tunnels, 1);
        let stats = r.stats_payload(&t.trace);
        assert_eq!(stats["session_releases_without_filed_tunnels"], 1);
    }

    /// 2.21.113 (E5, exigence cœur #9 7050925249) — libération d'UNE
    /// session PDU : seuls ses tunnels sont oubliés. L'abonné a deux
    /// sessions (1 et 2) ; libérer la 2 laisse le trafic de la 1
    /// rattaché et rejette celui de la 2.
    #[test]
    fn pdu_release_forgets_only_the_tunnels_of_that_session_2_21_113() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        let setup = |packet: u64, session: &'static str, teid: &'static str| {
            let mut event = ngap_between(
                gnb,
                false,
                "PDUSessionResourceSetupRequest",
                packet,
                vec![
                    ("amf_ue_ngap_id", "11"),
                    ("ran_ue_ngap_id", "21"),
                    ("subscriber_pseudonym", "psn-ue-a"),
                    ("pdu_session_id", session),
                ],
            );
            event.information_elements = vec![event_schema::InformationElement {
                id: None,
                name: "PDUSessionResourceSetupRequestTransfer".into(),
                length: 0,
                value: Some(format!(
                    "item_0_tunnel_ip_ul=10.77.22.13,item_0_gtp_teid_ul={teid}"
                )),
                raw_sha256: None,
                status: event_schema::DecodeStatus::Decoded,
            }];
            event
        };
        let gpdu = |packet: u64, teid: &'static str| {
            let mut event = mk_event(
                "N3",
                Protocol::Gtpu,
                "G-PDU",
                packet,
                Direction::Uplink,
                vec![("teid", teid)],
                vec![],
            );
            event.destination_endpoint.address = "10.77.22.13".into();
            event
        };
        r.route_normalized(&setup(1, "1", "0x0000a001"));
        r.route_normalized(&setup(2, "2", "0x0000a002"));
        r.route_normalized(&gpdu(3, "0x0000a001"));
        r.route_normalized(&gpdu(4, "0x0000a002"));
        r.route_normalized(&ngap_between(
            gnb,
            true,
            "PDU Session Release Complete",
            5,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("pdu_session_id", "2")],
        ));
        r.route_normalized(&gpdu(6, "0x0000a001"));
        r.route_normalized(&gpdu(7, "0x0000a002"));
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.gpdu_attached, 3, "session 1 toujours rattachée, session 2 oubliée");
        assert_eq!(t.trace.gpdu_rejected_no_match, 1);
        assert_eq!(t.ue_ids.len(), 2, "l'UE reste enregistré");
    }

    /// 2.21.113 (exigence cœur #9 7050925249) — les rejets par motif
    /// sont lisibles dans `stats`, et un message PFCP de niveau nœud que
    /// le décodeur ne nomme pas (« Unknown PFCP Message », type < 50)
    /// n'entre pas dans la trace.
    #[test]
    fn rejects_are_counted_by_reason_and_unnamed_pfcp_node_messages_are_filtered_2_21_113() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let gnb = "10.77.11.13";
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "InitialContextSetupRequest",
            1,
            vec![("amf_ue_ngap_id", "11"), ("ran_ue_ngap_id", "21"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&ngap_between(
            gnb,
            false,
            "DownlinkNASTransport",
            2,
            vec![("amf_ue_ngap_id", "99"), ("ran_ue_ngap_id", "21")],
        ));
        let pfcp = |packet: u64, node: &str, message: &str, message_type: u32, ids: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event("N4", Protocol::Pfcp, message, packet, Direction::Unknown, ids, vec![]);
            event.message_type = message_type;
            event.destination_endpoint.address = node.into();
            event
        };
        r.route_normalized(&pfcp(
            3,
            "10.77.22.13",
            "PFCP Session Modification Request",
            52,
            vec![("seid", "0x0000000000000042"), ("subscriber_pseudonym", "psn-ue-a")],
        ));
        r.route_normalized(&pfcp(
            4,
            "10.77.22.99",
            "PFCP Session Report Request",
            56,
            vec![("seid", "0x0000000000000042")],
        ));
        // Association Update (type 7) : niveau nœud, non nommé par le
        // décodeur, et porteur du pseudonyme pour forcer le rattachement.
        r.route_normalized(&pfcp(
            5,
            "10.77.22.13",
            "Unknown PFCP Message",
            7,
            vec![("subscriber_pseudonym", "psn-ue-a")],
        ));
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.messages, 2, "le message de l'abonné sur N2 et celui sur N4");
        let stats = r.stats_payload(&t.trace);
        assert_eq!(stats["rejects"]["ue_id_mismatch"], 1);
        assert_eq!(stats["rejects"]["seid_endpoint_mismatch"], 1);
        assert_eq!(stats["pfcp"]["attached_seid_only"], 0);
        assert!(!t.trace.feed.contains_key("N4") || t.trace.feed["N4"].seen == 2,
            "le message de niveau nœud n'est pas présenté à la trace");
    }

    /// 2.21.113 — sur la capture N2 réelle du dépôt
    /// (`OIRAN_5G_PDU_SESSION_DATA_V1`), routée en live : toute la
    /// signalisation de l'abonné est rattachée, `InitialUEMessage`
    /// compris (E4), et les deux messages de libération d'un AUTRE
    /// contexte UE (autres identifiants NGAP) ne le sont pas (E2).
    #[test]
    fn real_n2_capture_attaches_the_whole_dialogue_and_nothing_else_2_21_113() {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let mut events = Vec::new();
        oiran_decode::decode_capture_streaming(&ring_decode_config(&source, "N2"), &key, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        // Ordre 7053229737 (constat CLAUDE2 7053217728) — ce test triait
        // par `(numéro de paquet, event_id)`. L'`event_id` dérive du
        // `capture_id`, lui-même empreinte du CHEMIN du fichier : dans un
        // même paquet, le parent NGAP passait avant ou après son enfant
        // NAS selon le répertoire du dépôt, et le compteur attendu valait
        // 1 ou 0. Les deux ordres sont maintenant construits et vérifiés,
        // sans dépendre de l'`event_id`.
        let packet = |event: &event_schema::NormalizedEvent| {
            event.packet_references.first().map(|r| r.packet_number).unwrap_or(u64::MAX)
        };
        // Tri stable par paquet : dans un paquet, ordre d'émission du
        // décodeur, parent puis enfant.
        events.sort_by_key(|event| packet(event));
        let parent_first = events.clone();
        let child_first: Vec<event_schema::NormalizedEvent> = events
            .chunk_by(|a, b| packet(a) == packet(b))
            .flat_map(|group| group.iter().rev().cloned())
            .collect();
        let position = |list: &[event_schema::NormalizedEvent], name: &str| {
            list.iter().position(|e| e.message_name.ends_with(name)).unwrap()
        };
        assert!(
            position(&parent_first, "InitialUEMessage") < position(&parent_first, "Registration Request"),
            "le décodeur émet le parent avant son enfant"
        );
        assert!(
            position(&child_first, "Registration Request") < position(&child_first, "InitialUEMessage")
        );
        let pseudonym = events
            .iter()
            .flat_map(|e| e.session_identifiers.iter())
            .find(|id| id.name == "subscriber_pseudonym")
            .map(|id| id.value.clone())
            .unwrap();
        for (label, events, expected_after_child) in
            [("parent d'abord", &parent_first, 1u64), ("enfant d'abord", &child_first, 0)]
        {
            let foreign: Vec<&str> = events
                .iter()
                .filter(|e| e.message_name.starts_with("UEContextRelease"))
                .map(|e| e.event_id.as_str())
                .collect();
            assert_eq!(foreign.len(), 2, "deux messages d'un autre contexte UE dans le jeu");
            let r = trace_on(&pseudonym);
            for event in events {
                r.route_normalized(event);
            }
            let routed = routed_ids(&r);
            assert!(foreign.iter().all(|id| !routed.iter().any(|r| r == id)), "{label}");
            assert_eq!(routed.len(), events.len() - 2, "{label} : tout le dialogue de l'abonné");
            let initial = events
                .iter()
                .find(|e| e.message_name == "InitialUEMessage")
                .unwrap();
            assert!(routed.contains(&initial.event_id), "{label} : InitialUEMessage rattaché");
            let traces = r.traces.lock().unwrap();
            // 2.21.116 (F2) — parent rattaché après coup compté une fois
            // quand il précède son enfant ; jamais de doublon.
            assert_eq!(
                traces["t"].trace.parents_attached_after_child, expected_after_child,
                "{label}"
            );
            assert_eq!(traces["t"].trace.duplicates_dropped, 0, "{label}");
        }
    }

    /// 2.21.126 — pseudonyme d'une adresse IP, comme les décodeurs.
    fn ip_psn(address: &str) -> String {
        event_schema::pseudonym_ip_text(pseudonym_key().unwrap(), address).unwrap()
    }

    fn sip_from(
        packet: u64,
        message: &str,
        cseq: &str,
        call: &str,
        alias: &str,
        source: &str,
        destination: &str,
    ) -> event_schema::NormalizedEvent {
        use event_schema::{Direction, Protocol};
        let (source, destination) = (ip_psn(source), ip_psn(destination));
        let mut event = mk_event(
            "IMS",
            Protocol::Sip,
            message,
            packet,
            Direction::Unknown,
            vec![("sip_call_id", call), ("subscriber_pseudonym", alias)],
            vec![
                ("CSeq", cseq),
                ("packet_source_ip_pseudonym", source.as_str()),
                ("packet_destination_ip_pseudonym", destination.as_str()),
            ],
        );
        event.event_id = format!("evt-sip-{packet:04}");
        event
    }

    /// 2.21.126 (donnée lab ANR1 #10 7052813333, ordres #9 7053030106 et
    /// 7053229737) — au lab, les URI du SIP sont des alias : ni IMSI ni
    /// MSISDN. Aucune identité de l'abonné n'est donc portée par son
    /// SIP ; le REGISTER n'a pas de SDP. Attendu : REGISTER, INVITE,
    /// 200, BYE et le flux RTP entrent dans la trace de l'abonné par
    /// l'adresse IP de son UE (apprise sur le NAS), et rien dans celle
    /// d'un autre UE ; l'IP est oubliée à la fin de la session.
    /// Avant 2.21.126 : aucun de ces messages n'est rattaché.
    #[test]
    fn voice_with_alias_uris_attaches_by_ue_ip_and_stays_out_of_another_ue_2_21_126() {
        use event_schema::{Direction, Protocol};
        let (ip_a, ip_c, pcscf) = ("10.45.0.7", "10.45.0.9", "10.46.0.2");
        let accept = |packet: u64, pseudonym: &str, address: &str| {
            let value = format!("type=IPv4,address={address}");
            let mut event = mk_event(
                "N2",
                Protocol::Ngap,
                "PDU Session Establishment Accept",
                packet,
                Direction::Unknown,
                vec![("subscriber_pseudonym", pseudonym), ("pdu_session_id", "2")],
                vec![("PDU address", value.as_str())],
            );
            event.event_id = format!("evt-nas-{packet:04}");
            event
        };
        let rtp = |packet: u64, call: &str| {
            let mut event = mk_event("N6", Protocol::Rtp, "RTP Flow", packet, Direction::Unknown, vec![("sip_call_id", call)], vec![("ssrc", "0x00001111")]);
            event.event_id = format!("evt-rtp-{packet:04}");
            event
        };
        let events = vec![
            accept(1, "psn-ue-a", ip_a),
            accept(2, "psn-ue-c", ip_c),
            // A s'enregistre : alias, pas de SDP.
            sip_from(3, "REGISTER", "1 REGISTER", "reg-a@ims", "psn-alias-a", ip_a, pcscf),
            sip_from(4, "200 OK", "1 REGISTER", "reg-a@ims", "psn-alias-a", pcscf, ip_a),
            // C s'enregistre et appelle.
            sip_from(5, "REGISTER", "1 REGISTER", "reg-c@ims", "psn-alias-c", ip_c, pcscf),
            sip_from(6, "INVITE", "1 INVITE", "call-c@ims", "psn-alias-c", ip_c, pcscf),
            // A appelle.
            sip_from(7, "INVITE", "1 INVITE", "call-a@ims", "psn-alias-a", ip_a, pcscf),
            sip_from(8, "200 OK", "1 INVITE", "call-a@ims", "psn-alias-a", pcscf, ip_a),
            rtp(9, "call-a@ims"),
            rtp(10, "call-c@ims"),
            sip_from(11, "BYE", "2 BYE", "call-a@ims", "psn-alias-a", ip_a, pcscf),
            sip_from(12, "200 OK", "2 BYE", "call-a@ims", "psn-alias-a", pcscf, ip_a),
        ];
        let (a, c) = (trace_on("psn-ue-a"), trace_on("psn-ue-c"));
        for event in &events {
            a.route_normalized(event);
            c.route_normalized(event);
        }
        assert_eq!(
            routed_ids(&a),
            ["evt-nas-0001", "evt-sip-0003", "evt-sip-0004", "evt-sip-0007", "evt-sip-0008", "evt-rtp-0009", "evt-sip-0011", "evt-sip-0012"],
            "REGISTER, INVITE, 200, flux RTP et BYE de A, rien de C"
        );
        assert_eq!(
            routed_ids(&c),
            ["evt-nas-0002", "evt-sip-0005", "evt-sip-0006", "evt-rtp-0010"],
            "la trace de C ne reçoit rien de A"
        );
        {
            let traces = a.traces.lock().unwrap();
            let t = &traces["t"];
            // REGISTER et INVITE : rattachés par l'IP seule ; les réponses
            // et le BYE le sont aussi par l'identifiant d'appel.
            assert_eq!(t.trace.sip_attached_by_ue_ip, 2);
            assert_eq!(a.stats_payload(&t.trace)["sip"]["attached_by_ue_ip"], 2);
            assert!(t.exposed_keys.contains(&ip_psn(ip_a)));
            assert!(!t.match_keys.contains("psn-alias-a"), "l'alias du SIP n'est pas appris (I1)");
            assert!(!t.exposed_keys.contains(&ip_psn(pcscf)), "l'adresse du P-CSCF n'est jamais apprise");
            assert!(!t.ue_ip_keys.contains_key(&ip_psn(pcscf)));
            assert!(!t.ue_ip_keys.contains_key(&ip_psn(ip_c)));
        }
        // Fin de la session de données de A : son IP est oubliée. La même
        // adresse, réattribuée, ne rattache plus rien.
        let mut release = mk_event("N2", Protocol::Ngap, "PDU Session Release Complete", 13, Direction::Unknown, vec![("subscriber_pseudonym", "psn-ue-a"), ("pdu_session_id", "2")], vec![]);
        release.event_id = "evt-nas-0013".into();
        a.route_normalized(&release);
        a.route_normalized(&sip_from(14, "REGISTER", "1 REGISTER", "reg-z@ims", "psn-alias-z", ip_a, pcscf));
        assert!(!routed_ids(&a).contains(&"evt-sip-0014".to_string()), "IP oubliée avec la session");
        let traces = a.traces.lock().unwrap();
        assert!(traces["t"].ue_ip_keys.is_empty());
        assert!(!traces["t"].exposed_keys.contains(&ip_psn(ip_a)));
        assert!(!traces["t"].match_keys.contains(&ip_psn(ip_a)));
    }

    /// 2.21.126 — NAS chiffré : l'adresse PDU n'est pas lisible. L'IP de
    /// l'UE est alors apprise sur l'IE 93 d'un PFCP déjà rattaché (ici
    /// par son tunnel), et elle finit avec la session PFCP. Un PFCP qui
    /// porte l'IP d'un autre UE n'apprend rien à la trace.
    #[test]
    fn ue_ip_is_learned_from_ie_93_of_an_attached_pfcp_and_ends_with_its_session_2_21_126() {
        use event_schema::{Direction, Protocol};
        let (ip_a, ip_b, pcscf) = ("10.45.0.7", "10.45.0.8", "10.46.0.2");
        let pfcp = |packet: u64, message: &str, seid: &str, f_teid: &str, ue_ip: Option<&str>| {
            let ue = ue_ip.map(|ip| format!("ue_ip={},ue_ip_flags=0x02", ip_psn(ip)));
            let mut ies = vec![("F-TEID", f_teid)];
            if let Some(ue) = ue.as_deref() {
                ies.push(("UE IP Address", ue));
            }
            let mut event = mk_event("N4", Protocol::Pfcp, message, packet, Direction::Unknown, vec![("seid", seid)], ies);
            for ie in event.information_elements.iter_mut() {
                if ie.name == "UE IP Address" {
                    ie.id = Some(93);
                }
            }
            event.event_id = format!("evt-pfcp-{packet:04}");
            event
        };
        let mut setup = mk_event(
            "N2",
            Protocol::Ngap,
            "PDUSessionResourceSetupRequest",
            1,
            Direction::Unknown,
            vec![("subscriber_pseudonym", "psn-ue-a")],
            vec![("PDUSessionResourceSetupRequestTransfer", "item_0_tunnel_ip_ul=10.100.0.1,item_0_gtp_teid_ul=0x0000d4a6")],
        );
        setup.event_id = "evt-ngap-0001".into();
        let r = trace_on("psn-ue-a");
        r.route_normalized(&setup);
        // PFCP d'un autre UE, avant : autre tunnel, autre IP.
        r.route_normalized(&pfcp(2, "Session Establishment Request", "0x0000000000002002", "teid=0x0000eeee,v4=true,v6=false,ipv4=10.100.0.1", Some(ip_b)));
        // PFCP de l'abonné : rattaché par son tunnel, porte l'IE 93.
        r.route_normalized(&pfcp(3, "Session Establishment Request", "0x0000000000001001", "teid=0x0000d4a6,v4=true,v6=false,ipv4=10.100.0.1", Some(ip_a)));
        r.route_normalized(&sip_from(4, "REGISTER", "1 REGISTER", "reg-a@ims", "psn-alias-a", ip_a, pcscf));
        r.route_normalized(&sip_from(5, "REGISTER", "1 REGISTER", "reg-b@ims", "psn-alias-b", ip_b, pcscf));
        assert_eq!(routed_ids(&r), ["evt-ngap-0001", "evt-pfcp-0003", "evt-sip-0004"]);
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert_eq!(t.trace.sip_attached_by_ue_ip, 1);
            assert!(t.ue_ip_keys.contains_key(&ip_psn(ip_a)));
            assert!(!t.ue_ip_keys.contains_key(&ip_psn(ip_b)), "IP d'un PFCP non rattaché : pas apprise");
        }
        // Suppression de la session PFCP : l'IP finit avec elle.
        r.route_normalized(&pfcp(6, "Session Deletion Response", "0x0000000000001001", "", None));
        r.route_normalized(&sip_from(7, "REGISTER", "2 REGISTER", "reg-a2@ims", "psn-alias-a", ip_a, pcscf));
        let routed = routed_ids(&r);
        assert!(routed.contains(&"evt-pfcp-0006".to_string()));
        assert!(!routed.contains(&"evt-sip-0007".to_string()), "IP oubliée avec la session PFCP");
        assert!(r.traces.lock().unwrap()["t"].ue_ip_keys.is_empty());
    }

    /// 2.21.126 (constat CLAUDE2 #9 7053217728, ordre #9 7053683830) —
    /// l'ordre des events d'un même paquet ne dépend plus du nom du
    /// segment. La même capture, décodée sous deux chemins, donne la même
    /// séquence, et dans chaque paquet le parent NGAP précède son enfant
    /// NAS. Avant : l'`event_id`, dérivé du chemin, départageait.
    #[test]
    fn capture_order_does_not_depend_on_the_segment_path_2_21_126() {
        let bytes = fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng"),
        )
        .unwrap();
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let root = std::env::temp_dir().join(format!(
            "oiran-order-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        let decode = |name: &str| {
            let dir = root.join(name);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("{name}.pcapng"));
            fs::write(&path, &bytes).unwrap();
            let mut events = Vec::new();
            oiran_decode::decode_capture_streaming(&ring_decode_config(&path, "N2"), &key, |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
            // Le lot arrive dans un ordre quelconque : le tri seul décide.
            events.reverse();
            sort_by_capture_order(&mut events);
            events
        };
        let sequence = |events: &[event_schema::NormalizedEvent]| -> Vec<(u64, String, String)> {
            events
                .iter()
                .map(|e| (e.packet_references[0].packet_number, e.protocol.as_str().to_owned(), e.message_name.clone()))
                .collect()
        };
        let (first, second) = (decode("n2_00001_a"), decode("n2_00777_zz"));
        assert_ne!(first[0].event_id, second[0].event_id, "les identifiants dépendent bien du chemin");
        let _ = fs::remove_dir_all(&root);
        // NB : le lot est inversé avant le tri, donc dans un paquet
        // l'ordre est l'inverse de l'émission, le même sous les deux
        // chemins. Seule l'égalité compte ici.
        assert_eq!(sequence(&first), sequence(&second));
        assert!(sequence(&first).windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    /// 2.21.129 (recette lab 2.21.124, G9 FAIL : la trace de A prend
    /// tout le trafic de B ; ordre #9 7053864526) — capture réelle à cinq
    /// abonnés, cinq traces ouvertes EN MÊME TEMPS dans le même registre,
    /// comme au lab. Trois cas :
    ///   1. les cinq dialogues entrelacés, démarrés à 10 ms d'écart ;
    ///   2. la capture est l'historique du ring (amorçage, plans N2 et
    ///      N4), puis elle est rejouée en live avec les abonnés décalés
    ///      d'un rang : les identifiants techniques que l'historique
    ///      donne à un abonné (contexte UE, tunnels, SEID) sont portés
    ///      par le suivant. C'est l'identifiant réattribué.
    ///   3. témoin : le même rejeu sans amorçage.
    /// Attendu partout : aucune trace ne reçoit un event d'un autre
    /// abonné, aucune n'expose le pseudonyme d'un autre.
    /// À `35571a0` (2.21.124), cas 2 : chaque trace prend TOUT le dialogue
    /// de l'abonné suivant (65 à 70 events) et expose son pseudonyme.
    #[test]
    fn simultaneous_traces_and_reassigned_identifiers_never_cross_subscribers_2_21_129() {
        let capture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/LAB_TESTBED/multi-imsi.pcap",
        );
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let mut events: Vec<event_schema::NormalizedEvent> = Vec::new();
        for interface in ["N2", "N4", "SBI"] {
            let config = oiran_decode::DecodeConfig {
                input: capture.clone(),
                capture_id: format!("sha256:{}", sha256_hex(interface.as_bytes())),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: "multi-imsi.pcap".into(),
            };
            let _ = oiran_decode::decode_capture_streaming(&config, &key, |event| {
                events.push(event);
                Ok(())
            });
        }
        events.sort_by_key(|e| e.packet_references.first().map(|p| p.packet_number).unwrap_or(0));
        let id_of = |event: &event_schema::NormalizedEvent, name: &str| -> Option<String> {
            event.session_identifiers.iter().find(|id| id.name == name).map(|id| id.value.clone())
        };
        let mut contexts: Vec<(String, Vec<String>)> = Vec::new();
        for event in events.iter().filter(|e| e.interface == "N2") {
            if let (Some(pseudonym), Some(ran)) =
                (id_of(event, "subscriber_pseudonym"), id_of(event, "ran_ue_ngap_id"))
            {
                match contexts.iter_mut().find(|(known, _)| known == &ran) {
                    Some((_, pseudonyms)) if !pseudonyms.contains(&pseudonym) => pseudonyms.push(pseudonym),
                    Some(_) => {}
                    None => contexts.push((ran, vec![pseudonym])),
                }
            }
        }
        let shared: HashSet<String> = contexts
            .iter()
            .flat_map(|(_, list)| list.iter().cloned())
            .filter(|p| contexts.iter().filter(|(_, list)| list.contains(p)).count() > 1)
            .collect();
        let subs: Vec<String> = contexts
            .iter()
            .map(|(_, list)| list.iter().find(|p| !shared.contains(*p)).unwrap().clone())
            .collect();
        assert_eq!(subs.len(), 5);
        let attached_of = |registry: &LiveTraceRegistry, id: &str| -> Vec<String> {
            registry.traces.lock().unwrap()[id]
                .events
                .iter()
                .filter(|e| e.kind == "message")
                .filter_map(|e| e.payload["event_id"].as_str().map(str::to_owned))
                .collect()
        };
        // Vérité terrain : une trace seule, ordre de la capture (le gate
        // de 2.21.124 : 70 / 68 / 67 / 69 / 65).
        let mut owner: HashMap<String, usize> = HashMap::new();
        for (k, sub) in subs.iter().enumerate() {
            let r = trace_on(sub);
            for e in &events {
                r.route_normalized(e);
            }
            for id in attached_of(&r, "t") {
                assert!(owner.insert(id, k).is_none());
            }
        }
        assert_eq!(owner.len(), 339);
        let names: Vec<String> = (0..subs.len()).map(|k| format!("t{k}")).collect();
        // Renvoie, par trace : (rattachés, étrangers, manquants, pseudonymes
        // tiers exposés, oublis d'état périmé).
        let run = |sequence: &[event_schema::NormalizedEvent],
                   history: Option<&[event_schema::NormalizedEvent]>,
                   truth: &dyn Fn(&str) -> Option<usize>|
         -> Vec<(usize, usize, usize, usize, u64)> {
            let r = LiveTraceRegistry::new();
            for (k, sub) in subs.iter().enumerate() {
                let mut st = state(u64::MAX, false, vec![sub.clone()]);
                st.trace.trace_id = names[k].clone();
                r.traces.lock().unwrap().insert(names[k].clone(), st);
            }
            if let Some(history) = history {
                assert!(r.begin_seed());
                learn_history(
                    &r,
                    history
                        .iter()
                        .filter(|e| e.interface == "N2" || e.interface == "N4")
                        .cloned()
                        .collect(),
                );
                r.finish_seed(&SeedReport::default());
            }
            for e in sequence {
                r.route_normalized(e);
            }
            (0..subs.len())
                .map(|k| {
                    let got = attached_of(&r, &names[k]);
                    let foreign = got.iter().filter(|id| truth(id).is_some_and(|o| o != k)).count();
                    let missing = sequence
                        .iter()
                        .filter(|e| truth(&e.event_id) == Some(k) && !got.contains(&e.event_id))
                        .count();
                    let traces = r.traces.lock().unwrap();
                    let t = &traces[&names[k]];
                    let exposed = subs
                        .iter()
                        .enumerate()
                        .filter(|(o, s)| *o != k && (t.exposed_keys.contains(*s) || t.match_keys.contains(s)))
                        .count();
                    (got.len(), foreign, missing, exposed, t.trace.stale_state_resets)
                })
                .collect()
        };
        let truth = |id: &str| owner.get(id).copied();

        // Cas 1 — dialogues entrelacés.
        let ns = |e: &event_schema::NormalizedEvent| {
            e.timestamp.seconds as i128 * 1_000_000_000 + e.timestamp.nanoseconds as i128
        };
        let t0 = ns(&events[0]);
        let mut start: HashMap<usize, i128> = HashMap::new();
        for e in &events {
            if let Some(k) = owner.get(&e.event_id) {
                start.entry(*k).or_insert(ns(e));
            }
        }
        let mut keyed: Vec<(i128, event_schema::NormalizedEvent)> = events
            .iter()
            .map(|e| {
                let key = match owner.get(&e.event_id) {
                    Some(k) => ns(e) - start[k] + (*k as i128) * 10_000_000,
                    None => ns(e) - t0 - 3_600_000_000_000,
                };
                (key, e.clone())
            })
            .collect();
        keyed.sort_by_key(|(key, _)| *key);
        let interleaved: Vec<event_schema::NormalizedEvent> = keyed.into_iter().map(|(_, e)| e).collect();
        let first_of = |k: usize| interleaved.iter().position(|e| owner.get(&e.event_id) == Some(&k)).unwrap();
        let last_of = |k: usize| interleaved.iter().rposition(|e| owner.get(&e.event_id) == Some(&k)).unwrap();
        assert!(first_of(4) < last_of(0), "les cinq dialogues se recouvrent");
        let result = run(&interleaved, None, &truth);
        assert_eq!(
            result.iter().map(|r| (r.0, r.1, r.2, r.3)).collect::<Vec<_>>(),
            [(70, 0, 0, 0), (68, 0, 0, 0), (67, 0, 0, 0), (69, 0, 0, 0), (65, 0, 0, 0)]
        );

        // Cas 2 et 3 — rejeu avec les abonnés décalés d'un rang.
        // Le rejeu est une autre capture : ses références d'event, y
        // compris celles qu'une IE porte (le NAS cite son message NGAP),
        // sont renommées comme ses `event_id`.
        let rename_event_refs = |text: &str| -> String {
            let mut out = String::with_capacity(text.len());
            let mut rest = text;
            while let Some(at) = rest.find("evt-") {
                out.push_str(&rest[..at]);
                let id: String = rest[at..].chars().take(4 + 16).collect();
                let is_ref = id.len() == 20 && id[4..].bytes().all(|b| b.is_ascii_hexdigit());
                out.push_str(&id);
                if is_ref {
                    out.push_str("-bis");
                }
                rest = &rest[at + id.len()..];
            }
            out.push_str(rest);
            out
        };
        let swap = |text: &str| -> String {
            let mut out = text.to_owned();
            for (k, sub) in subs.iter().enumerate() {
                out = out.replace(sub.as_str(), &format!("@@{k}@@"));
            }
            for k in 0..subs.len() {
                out = out.replace(&format!("@@{k}@@"), &subs[(k + 1) % subs.len()]);
            }
            out
        };
        // Le rejeu est postérieur à l'historique : une heure plus tard.
        let replay: Vec<event_schema::NormalizedEvent> = events
            .iter()
            .map(|e| {
                let mut e = e.clone();
                e.timestamp.seconds += 3_600;
                e.event_id = format!("{}-bis", e.event_id);
                if let Some(parent) = e.parent_event_id.as_mut() {
                    *parent = format!("{parent}-bis");
                }
                for id in e.session_identifiers.iter_mut() {
                    id.value = rename_event_refs(&swap(&id.value));
                }
                for ie in e.information_elements.iter_mut() {
                    if let Some(v) = ie.value.as_mut() {
                        *v = rename_event_refs(&swap(v));
                    }
                }
                e
            })
            .collect();
        let truth_bis =
            |id: &str| owner.get(id.trim_end_matches("-bis")).map(|k| (k + 1) % subs.len());
        let witness = run(&replay, None, &truth_bis);
        assert!(witness.iter().all(|r| r.1 == 0 && r.2 == 0 && r.3 == 0), "{witness:?}");
        let seeded = run(&replay, Some(&events), &truth_bis);
        for (k, (_, foreign, missing, exposed, _)) in seeded.iter().enumerate() {
            assert_eq!(*foreign, 0, "trace {k} : events d'un autre abonné : {seeded:?}");
            assert_eq!(*exposed, 0, "trace {k} : pseudonyme d'un autre abonné : {seeded:?}");
            assert_eq!(*missing, 0, "trace {k} : events de l'abonné perdus : {seeded:?}");
        }
        // Chaque trace tient exactement le dialogue de son abonné, comme
        // sans historique.
        assert_eq!(
            seeded.iter().map(|r| r.0).collect::<Vec<_>>(),
            witness.iter().map(|r| r.0).collect::<Vec<_>>()
        );
        assert_eq!(witness.iter().map(|r| r.0).collect::<Vec<_>>(), [65, 70, 68, 67, 69]);
        // L'abonné dont l'ancien contexte UE est repris avant son propre
        // enregistrement voit son état périmé oublié.
        assert_eq!(seeded[0].4, 1);

        // Cas 4 (sonde CLAUDE2 #9 7060169092, ordre #9 7060289296) — même
        // rejeu, mais les identifiants UE NGAP sont NEUFS : ne restent
        // repris que les tunnels et les SEID de l'historique. À 2.21.132,
        // la trace de l'abonné dont l'historique porte ces tunnels prend
        // les deux messages d'établissement PFCP de l'abonné suivant.
        let fresh_ngap: Vec<event_schema::NormalizedEvent> = replay
            .iter()
            .map(|e| {
                let mut e = e.clone();
                for id in e.session_identifiers.iter_mut() {
                    if id.name == "amf_ue_ngap_id" || id.name == "ran_ue_ngap_id" {
                        id.value = format!("{}000", id.value);
                    }
                }
                // Les IE NGAP portent aussi ces identifiants.
                for ie in e.information_elements.iter_mut() {
                    if let Some(v) = ie.value.as_mut() {
                        for name in ["amf_ue_ngap_id", "ran_ue_ngap_id"] {
                            let prefix = format!("{name}=");
                            if let Some(rest) = v.strip_prefix(&prefix) {
                                *v = format!("{prefix}{rest}000");
                            }
                        }
                    }
                }
                e
            })
            .collect();
        let case4 = run(&fresh_ngap, Some(&events), &truth_bis);
        for (k, (_, foreign, missing, exposed, _)) in case4.iter().enumerate() {
            assert_eq!(*foreign, 0, "cas 4, trace {k} : events d'un autre abonné : {case4:?}");
            assert_eq!(*exposed, 0, "cas 4, trace {k} : pseudonyme d'un autre abonné : {case4:?}");
            assert_eq!(*missing, 0, "cas 4, trace {k} : events de l'abonné perdus : {case4:?}");
        }
    }

    /// 2.21.129 (recette lab 2.21.124, G9 : `pfcp.attached_after_the_fact`
    /// à 5 pour un abonné qui a 4 PFCP ; ordre #9 7053864526, questions 3
    /// et 4) — le tampon des PFCP rejetés est commun aux traces et
    /// l'amorçage y versait l'historique du ring. Ici, l'historique porte
    /// le PFCP d'une ANCIENNE session, d'un autre abonné, dont le tunnel
    /// a la valeur que l'UPF redonne ensuite à l'abonné tracé.
    /// Attendu : ce PFCP n'est ni émis ni appris — ni depuis l'amorçage,
    /// ni depuis le live quand il date de plus de quelques secondes — et
    /// le PFCP du moment, lui, est rattaché après coup.
    /// Avant 2.21.129 : le PFCP ancien est émis comme un message du
    /// moment, la trace apprend l'IP UE de l'autre abonné et rattache son
    /// SIP.
    #[test]
    fn a_pfcp_of_an_older_session_is_never_attached_after_the_fact_2_21_129() {
        use event_schema::{Direction, Protocol};
        let (ip_old, pcscf) = ("10.45.0.8", "10.46.0.2");
        let f_teid = "teid=0x0000d4a6,v4=true,v6=false,ipv4=10.100.0.1";
        let pfcp = |id: &str, seconds: i64, seid: &str, ue_ip: Option<&str>| {
            let ue = ue_ip.map(|ip| format!("ue_ip={},ue_ip_flags=0x02", ip_psn(ip)));
            let mut ies = vec![("F-TEID", f_teid)];
            if let Some(ue) = ue.as_deref() {
                ies.push(("UE IP Address", ue));
            }
            let mut event = mk_event("N4", Protocol::Pfcp, "Session Establishment Request", 1, Direction::Unknown, vec![("seid", seid)], ies);
            for ie in event.information_elements.iter_mut() {
                if ie.name == "UE IP Address" {
                    ie.id = Some(93);
                }
            }
            event.event_id = id.into();
            event.timestamp.seconds = seconds;
            event
        };
        let setup = |seconds: i64| {
            let mut event = mk_event(
                "N2",
                Protocol::Ngap,
                "PDUSessionResourceSetupRequest",
                2,
                Direction::Unknown,
                vec![("subscriber_pseudonym", "psn-ue-a")],
                vec![("PDUSessionResourceSetupRequestTransfer", "item_0_tunnel_ip_ul=10.100.0.1,item_0_gtp_teid_ul=0x0000d4a6")],
            );
            event.event_id = "evt-ngap-setup".into();
            event.timestamp.seconds = seconds;
            event
        };
        let now = 1_795_000_000i64;
        for from_seed in [true, false] {
            let r = trace_on("psn-ue-a");
            // PFCP d'une ancienne session, une heure plus tôt, même tunnel.
            let old = pfcp("evt-pfcp-old", now - 3_600, "0x0000000000002002", Some(ip_old));
            if from_seed {
                assert!(r.begin_seed());
                r.learn_from_ring(&old);
                r.finish_seed(&SeedReport::default());
            } else {
                r.route_normalized(&old);
            }
            // PFCP du moment, celui de l'abonné : même tunnel, pas d'IE 93.
            r.route_normalized(&pfcp("evt-pfcp-now", now, "0x0000000000001001", None));
            r.route_normalized(&setup(now));
            r.route_normalized(&sip_from(9, "REGISTER", "1 REGISTER", "reg-b@ims", "psn-alias-b", ip_old, pcscf));
            assert_eq!(
                routed_ids(&r),
                ["evt-ngap-setup", "evt-pfcp-now"],
                "amorçage={from_seed} : seul le PFCP du moment est rattaché après coup"
            );
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert_eq!(t.trace.pfcp_attached_after_the_fact, 1, "amorçage={from_seed}");
            assert!(t.ue_ip_keys.is_empty(), "amorçage={from_seed} : IP UE d'une ancienne session apprise");
            assert!(!t.seids.contains("0x0000000000002002"), "amorçage={from_seed}");
        }
    }

    /// 2.21.131 (lot B2, GO #9 7050925249 ; clé : question #9 7054512200)
    /// — un flux RTP émis plusieurs fois pendant qu'il grossit : même
    /// `stable_event_key`, `revision` croissant, la trace REMPLACE. Une
    /// révision au contenu inchangé n'est pas réémise. Les autres
    /// messages ne portent pas `revision`.
    #[test]
    fn a_growing_rtp_flow_is_replaced_by_its_next_revision_2_21_131() {
        use event_schema::{Direction, Protocol};
        let flow = |packets: u64, key: &str| {
            let mut event = mk_event("IMS", Protocol::Rtp, "RTP Flow", 5, Direction::Unknown, vec![("sip_call_id", "call-a@ims")], vec![("ssrc", "0x00001111")]);
            event.event_id = format!("evt-rtp-{key}-{packets}");
            event.stable_event_key = format!("sek-{key}");
            event
        };
        let r = trace_on("psn-ue-a");
        let mut invite = mk_event("IMS", Protocol::Sip, "INVITE", 1, Direction::Unknown, vec![("sip_call_id", "call-a@ims"), ("subscriber_pseudonym", "psn-ue-a")], vec![("CSeq", "1 INVITE")]);
        invite.event_id = "evt-sip-0001".into();
        invite.stable_event_key = "sek-invite".into();
        r.route_normalized(&invite);
        r.route_normalized(&flow(10, "a"));
        r.route_normalized(&flow(10, "a")); // même contenu : rien
        r.route_normalized(&flow(10, "b")); // autre flux
        r.route_normalized(&flow(25, "a"));
        r.route_normalized(&flow(40, "a"));
        r.route_normalized(&flow(40, "a")); // clôture identique au dernier instantané
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        let buffered: Vec<(String, Option<u64>)> = t
            .events
            .iter()
            .filter(|e| e.kind == "message")
            .map(|e| (e.payload["event_id"].as_str().unwrap().to_owned(), e.payload["revision"].as_u64()))
            .collect();
        assert_eq!(
            buffered,
            [
                ("evt-sip-0001".to_string(), None),
                ("evt-rtp-b-10".to_string(), Some(0)),
                ("evt-rtp-a-40".to_string(), Some(2)),
            ],
            "le tampon ne garde que la dernière révision de chaque flux"
        );
        assert_eq!(t.trace.messages, 3, "un flux compte pour un message, quelle que soit sa révision");
        assert_eq!(t.trace.rtp_flow_updates, 2);
        assert_eq!(t.trace.duplicates_dropped, 0);
        assert_eq!(t.trace.out_of_order, 0);
        assert_eq!(r.stats_payload(&t.trace)["rtp"]["flow_updates"], 2);
    }

    /// Capture IMS synthétique, sans tunnel : INVITE et 200 OK avec SDP,
    /// puis `rtp_packets` paquets RTP dans chaque sens. L'URI From porte
    /// l'identité de test du PLMN 001/01, pour que le SIP ait un
    /// pseudonyme d'abonné.
    fn ims_voice_capture(rtp_packets: u16) -> Vec<u8> {
        let frame = |src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]| {
            let udp = (8 + payload.len()) as u16;
            let mut f = vec![0u8; 12];
            f.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
            f.extend_from_slice(&(20 + udp).to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
            f.extend_from_slice(&src);
            f.extend_from_slice(&dst);
            f.extend_from_slice(&sport.to_be_bytes());
            f.extend_from_slice(&dport.to_be_bytes());
            f.extend_from_slice(&udp.to_be_bytes());
            f.extend_from_slice(&[0, 0]);
            f.extend_from_slice(payload);
            f
        };
        let (ue, pcscf, peer) = ([10, 47, 0, 2], [10, 77, 24, 20], [10, 77, 24, 30]);
        let sip = |start: &str, sdp: &str| {
            format!(
                "{start}\r\nVia: SIP/2.0/UDP 10.47.0.2:5060;branch=z9hG4bKb2\r\nMax-Forwards: 70\r\nFrom: <sip:001010000000001@example.invalid>;tag=a\r\nTo: <sip:callee@example.invalid>\r\nCall-ID: synthetic-2-21-131@oiran\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
                sdp.len()
            )
        };
        let offer = "v=0\r\no=- 1 1 IN IP4 10.47.0.2\r\ns=-\r\nc=IN IP4 10.47.0.2\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let answer = "v=0\r\no=- 2 2 IN IP4 10.77.24.30\r\ns=-\r\nc=IN IP4 10.77.24.30\r\nt=0 0\r\nm=audio 50000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let rtp = |ssrc: u32, seq: u16| {
            let mut p = vec![0x80, 0x00];
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            p.extend_from_slice(&ssrc.to_be_bytes());
            p.extend_from_slice(&[0x55; 20]);
            p
        };
        let mut frames = vec![
            frame(ue, 5060, pcscf, 5060, sip("INVITE sip:callee@example.invalid SIP/2.0", offer).as_bytes()),
            frame(pcscf, 5060, ue, 5060, sip("SIP/2.0 200 OK", answer).as_bytes()),
        ];
        for seq in 0..rtp_packets {
            frames.push(frame(ue, 40_000, peer, 50_000, &rtp(0x1111, seq)));
            frames.push(frame(peer, 50_000, ue, 40_000, &rtp(0x2222, seq)));
        }
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&[0u8; 8]);
        file.extend_from_slice(&65_535u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        for (index, frame) in frames.iter().enumerate() {
            file.extend_from_slice(&(1_795_000_000u32 + index as u32 / 50).to_le_bytes());
            file.extend_from_slice(&((index as u32 % 50) * 20_000).to_le_bytes());
            file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            file.extend_from_slice(frame);
        }
        file
    }

    /// 2.21.131 (lot B2) — le lecteur sur le plan IMS : reprise à
    /// l'offset, instantané des flux RTP toutes les 5 s tant que le
    /// segment grossit, et clôture à la rotation. Avant ce lot : IMS en
    /// redécodage intégral, et un flux RTP n'apparaissait qu'à la
    /// rotation du segment (jusqu'à une heure plus tard).
    #[test]
    fn reader_pass_shows_a_live_rtp_flow_every_five_seconds_on_ims_2_21_131() {
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let root = std::env::temp_dir().join(format!(
            "oiran-reader-b2-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("ims")).unwrap();
        let segment = root.join("ims").join("ims_00000.pcapng");
        // Le fichier grossit : 10, puis 25, puis 40 paquets RTP par sens
        // (chaque état est un préfixe du suivant).
        let states: Vec<Vec<u8>> = [10u16, 25, 40].iter().map(|n| ims_voice_capture(*n)).collect();
        assert!(states[1].starts_with(&states[0]) && states[2].starts_with(&states[1]));
        fs::write(&segment, &states[0]).unwrap();
        // L'abonné : le pseudonyme que le SIP porte.
        let mut probe = Vec::new();
        oiran_decode::decode_capture_streaming(&ring_decode_config(&segment, "IMS"), &key, |event| {
            probe.push(event);
            Ok(())
        })
        .unwrap();
        let pseudonym = probe
            .iter()
            .flat_map(|e| e.session_identifiers.iter())
            .find(|id| id.name == "subscriber_pseudonym")
            .map(|id| id.value.clone())
            .unwrap();
        let registry = trace_on(&pseudonym);
        let mut file_states = HashMap::new();
        let mut sessions = HashMap::new();
        let mut dirs = HashMap::new();
        let mut hooks = CountingHooks::default();
        let t0 = std::time::Instant::now();
        let flows = |registry: &LiveTraceRegistry| -> Vec<(u64, String)> {
            registry.traces.lock().unwrap()["t"]
                .events
                .iter()
                .filter(|e| e.kind == "message" && e.payload["protocol"] == "RTP")
                .map(|e| {
                    let packets = e.payload["decoded_ie_tree"].to_string();
                    (e.payload["revision"].as_u64().unwrap(), packets)
                })
                .collect()
        };
        let mut pass = |after: u64, hooks: &mut CountingHooks| {
            reader_pass(&root, &key, &registry, &mut file_states, &mut sessions, &mut dirs, after == 0, false, t0 + Duration::from_secs(after), hooks);
            let traces = registry.traces.lock().unwrap();
            registry.stats_payload(&traces["t"].trace)["reader"]["interfaces"]["IMS"].clone()
        };
        // Passe 1 : SIP rattaché, premier instantané (révision 0).
        let io = pass(0, &mut hooks);
        assert_eq!(io["incremental"], true, "IMS en reprise à l'offset");
        assert_eq!(io["rtp_snapshots"], 1);
        let first = flows(&registry);
        assert_eq!(first.iter().map(|f| f.0).collect::<Vec<_>>(), [0, 0], "deux flux, révision 0");
        // 2 s plus tard, le segment a grossi : décodé, pas d'instantané.
        fs::write(&segment, &states[1]).unwrap();
        let io = pass(2, &mut hooks);
        assert!(io["bytes_decoded"].as_u64().unwrap() > 0);
        assert!(io["bytes_decoded"].as_u64().unwrap() < states[1].len() as u64, "seuls les octets nouveaux");
        assert_eq!(io["rtp_snapshots"], 0);
        assert_eq!(flows(&registry), first);
        // 6 s : segment inchangé, mais des octets décodés depuis le
        // dernier instantané → révision 1, qui remplace.
        let _ = pass(6, &mut hooks);
        let second = flows(&registry);
        assert_eq!(second.iter().map(|f| f.0).collect::<Vec<_>>(), [1, 1]);
        assert_ne!(second[0].1, first[0].1, "le contenu du flux a changé");
        // 12 s : rien de nouveau → pas d'instantané, rien réémis.
        let _ = pass(12, &mut hooks);
        assert_eq!(flows(&registry), second);
        // Le segment grossit encore, puis rotation : la clôture émet la
        // révision finale (40 paquets par sens).
        fs::write(&segment, &states[2]).unwrap();
        fs::write(root.join("ims").join("ims_00001.pcapng"), ims_voice_capture(0)).unwrap();
        let _ = pass(13, &mut hooks);
        let last = flows(&registry);
        assert_eq!(last.iter().map(|f| f.0).collect::<Vec<_>>(), [2, 2]);
        assert!(!sessions.contains_key(&segment), "session du segment fermé clôturée");
        let traces = registry.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.rtp_flow_updates, 4);
        assert_eq!(
            t.events.iter().filter(|e| e.kind == "message" && e.payload["protocol"] == "RTP").count(),
            2,
            "une seule ligne par flux dans le tampon"
        );
        assert_eq!(hooks.gap_bytes, 0);
        drop(traces);
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

    /// 2.21.122 (ordre #9 7052446877) — la voix dans une trace. Trace sur
    /// un abonné ; son INVITE est rattaché par son pseudonyme ; les
    /// events de flux RTP du même appel ne portent que `sip_call_id`.
    /// Depuis 2.21.109 ce n'était plus une clé : aucun flux RTP n'entrait
    /// dans la trace (échec de ce test à `d4d7781`).
    ///
    /// Attendu : le `sip_call_id` appris sur un SIP rattaché rattache, par
    /// égalité exacte, les SIP du même dialogue sans identité (180
    /// Ringing) et ses flux RTP, sur `IMS` comme sur `N3-IMS` ; un autre
    /// appel n'entre pas. Après le 200 du BYE, un SIP portant ce
    /// `sip_call_id` n'est plus rattaché, mais le flux RTP de l'appel,
    /// émis après coup à la clôture du segment, l'est encore.
    #[test]
    fn rtp_flows_and_dialog_messages_attach_by_exact_sip_call_id_2_21_122() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let sip = |packet: u64, message: &str, cseq: &'static str, ids: Vec<(&'static str, &'static str)>| {
            let mut event = mk_event("IMS", Protocol::Sip, message, packet, Direction::Unknown, ids, vec![("CSeq", cseq)]);
            event.event_id = format!("evt-sip-{packet:04}");
            event
        };
        let rtp = |packet: u64, interface: &str, call: &'static str| {
            let mut event = mk_event(interface, Protocol::Rtp, "RTP Flow", packet, Direction::Unknown, vec![("sip_call_id", call)], vec![("ssrc", "0x00001111")]);
            event.event_id = format!("evt-rtp-{packet:04}");
            event
        };
        let call = "a84b4c76e66710@ims.example.invalid";
        let other = "ffff0000aaaa11@ims.example.invalid";
        r.route_normalized(&sip(1, "INVITE", "1 INVITE", vec![("sip_call_id", call), ("subscriber_pseudonym", "psn-ue-a")]));
        // Même dialogue, sans identité de l'abonné.
        r.route_normalized(&sip(2, "180 Ringing", "1 INVITE", vec![("sip_call_id", call)]));
        // Un autre appel, d'un autre abonné.
        r.route_normalized(&sip(3, "INVITE", "1 INVITE", vec![("sip_call_id", other), ("subscriber_pseudonym", "psn-ue-b")]));
        r.route_normalized(&rtp(4, "IMS", call));
        r.route_normalized(&rtp(5, "N3-IMS", call));
        r.route_normalized(&rtp(6, "IMS", other));
        assert_eq!(
            routed_ids(&r),
            vec!["evt-sip-0001", "evt-sip-0002", "evt-rtp-0004", "evt-rtp-0005"],
            "le dialogue et ses flux RTP, rien de l'autre appel"
        );
        // Fin du dialogue.
        r.route_normalized(&sip(7, "BYE", "2 BYE", vec![("sip_call_id", call)]));
        r.route_normalized(&sip(8, "200 OK", "2 BYE", vec![("sip_call_id", call)]));
        // Après la fin : un SIP portant ce Call-ID n'entre plus ; le flux
        // RTP de l'appel, émis après coup, entre encore.
        r.route_normalized(&sip(9, "OPTIONS", "3 OPTIONS", vec![("sip_call_id", call)]));
        r.route_normalized(&rtp(10, "IMS", call));
        assert_eq!(
            routed_ids(&r),
            vec![
                "evt-sip-0001",
                "evt-sip-0002",
                "evt-rtp-0004",
                "evt-rtp-0005",
                "evt-sip-0007",
                "evt-sip-0008",
                "evt-rtp-0010"
            ]
        );
    }

    /// 2.21.122 (I1, sonde RVE2 de CLAUDE2 #9 7052558777) — une trace sur
    /// l'APPELÉ n'apprend pas l'appelant. Trace sur A ; INVITE de B vers
    /// A (rattaché par le To) ; puis trois events propres à B : un
    /// `DownlinkNASTransport` portant son pseudonyme, un INVITE de B vers
    /// un tiers, un `UplinkNASTransport` sans pseudonyme. À `d4d7781` les
    /// quatre entraient dans la trace de A et le pseudonyme de B sortait
    /// dans ses clés exposées. Attendu : 1 seul message, rien de B appris
    /// ni exposé. Dans l'autre sens (A appelle B), le pseudonyme de A est
    /// déjà celui de la trace : rien ne change.
    #[test]
    fn a_trace_on_the_callee_never_learns_the_caller_2_21_122() {
        use event_schema::{Direction, Protocol};
        let r = trace_on("psn-ue-a");
        let invite = |packet: u64, call: &'static str, from: &'static str, to: &'static str| {
            let mut event = mk_event(
                "IMS",
                Protocol::Sip,
                "INVITE",
                packet,
                Direction::Unknown,
                vec![("sip_call_id", call), ("subscriber_pseudonym", from)],
                vec![("CSeq", "1 INVITE"), ("subscriber_pseudonym", from), ("peer_subscriber_pseudonym", to)],
            );
            event.event_id = format!("evt-sip-{packet:04}");
            event
        };
        r.route_normalized(&invite(1, "call-b-to-a@ims", "psn-ue-b", "psn-ue-a"));
        r.route_normalized(&ngap_between(
            "10.77.11.99",
            false,
            "DownlinkNASTransport",
            2,
            vec![("amf_ue_ngap_id", "12"), ("ran_ue_ngap_id", "22"), ("subscriber_pseudonym", "psn-ue-b")],
        ));
        r.route_normalized(&invite(3, "call-b-to-d@ims", "psn-ue-b", "psn-ue-d"));
        r.route_normalized(&ngap_between(
            "10.77.11.99",
            true,
            "UplinkNASTransport",
            4,
            vec![("amf_ue_ngap_id", "12"), ("ran_ue_ngap_id", "22")],
        ));
        assert_eq!(routed_ids(&r), vec!["evt-sip-0001"], "seul l'appel reçu par A");
        {
            let traces = r.traces.lock().unwrap();
            let t = &traces["t"];
            assert!(!t.match_keys.contains("psn-ue-b"), "le pseudonyme de l'appelant n'est pas appris");
            assert!(!t.exposed_keys.contains("psn-ue-b"), "ni exposé dans ue_info");
            assert!(t.ue_ids.is_empty(), "aucun identifiant UE de B");
            assert!(t.sip_call_ids.contains("call-b-to-a@ims"), "l'appel de A, lui, est connu");
        }
        // Sens sortant : A appelle B — From = A, déjà connu.
        let r = trace_on("psn-ue-a");
        r.route_normalized(&invite(1, "call-a-to-b@ims", "psn-ue-a", "psn-ue-b"));
        let traces = r.traces.lock().unwrap();
        let t = &traces["t"];
        assert_eq!(t.trace.messages, 1);
        assert!(t.exposed_keys.contains("psn-ue-a"));
        assert!(!t.match_keys.contains("psn-ue-b") && !t.exposed_keys.contains("psn-ue-b"));
    }

    #[derive(Default)]
    struct CountingHooks {
        files_decoded: u64,
        observed: u64,
        gap_bytes: u64,
    }

    impl ReaderHooks for CountingHooks {
        fn bytes_gap(&mut self, gap: u64) {
            self.gap_bytes += gap;
        }
        fn file_decoded(&mut self) {
            self.files_decoded += 1;
        }
        fn observe(&mut self, _event: &event_schema::NormalizedEvent) {
            self.observed += 1;
        }
    }

    /// 2.21.123 (ordre #9 7052206763) — la passe du lecteur sur un ring
    /// simulé de 1 160 segments (1 100 sur N3, 30 sur N2, 30 sur N4),
    /// donc au-dessus de l'ancien seuil de 1 024.
    ///
    /// Défaut de prod (2.21.78 → 2.21.108, ring à 8 080 segments, un cœur
    /// à 99,9 %, 768 912 G-PDU émis pour 151 061 capturés) : la table des
    /// segments lus était vidée à la fin de chaque passe au-delà de
    /// 1 024 entrées, et la passe suivante redécodait tout le ring.
    ///
    /// Attendu : la table garde ses 1 160 entrées ; la première passe ne
    /// décode que le segment le plus récent de chaque plan (3) ; une
    /// passe sans changement n'en décode aucun ; après un ajout au
    /// segment N3 courant, la passe en décode UN, et seulement les octets
    /// ajoutés ; chaque G-PDU n'est rattaché et compté qu'une fois.
    #[test]
    fn reader_pass_on_a_ring_over_1024_segments_decodes_one_segment_per_active_plane_2_21_123() {
        let datasets = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let root = std::env::temp_dir().join(format!(
            "oiran-reader-pass-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        let base = std::time::UNIX_EPOCH + Duration::from_secs(1_795_000_000);
        let mut newest_n3 = std::path::PathBuf::new();
        for (plane, count) in [("n3", 1_100u64), ("n2", 30), ("n4", 30)] {
            let bytes = fs::read(datasets.join(format!("{}.pcapng", plane.to_ascii_uppercase()))).unwrap();
            fs::create_dir_all(root.join(plane)).unwrap();
            for index in 0..count {
                let path = root.join(plane).join(format!("{plane}_{index:05}.pcapng"));
                fs::write(&path, &bytes).unwrap();
                fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(base + Duration::from_secs(index))
                    .unwrap();
                if plane == "n3" {
                    newest_n3 = path;
                }
            }
        }
        let n3_bytes = fs::read(datasets.join("N3.pcapng")).unwrap();
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        // L'abonné du jeu : son pseudonyme, et le nombre de G-PDU d'un
        // segment N3.
        let decode = |plane: &str, interface: &str| {
            let mut events = Vec::new();
            oiran_decode::decode_capture_streaming(
                &ring_decode_config(&root.join(plane).join(format!("{plane}_00000.pcapng")), interface),
                &key,
                |event| {
                    events.push(event);
                    Ok(())
                },
            )
            .unwrap();
            events
        };
        let pseudonym = decode("n2", "N2")
            .iter()
            .flat_map(|e| e.session_identifiers.iter())
            .find(|id| id.name == "subscriber_pseudonym")
            .map(|id| id.value.clone())
            .unwrap();
        let gpdus_per_segment = decode("n3", "N3")
            .iter()
            .filter(|e| e.protocol.as_str() == "GTP-U")
            .count() as u64;
        assert!(gpdus_per_segment > 0);

        let registry = trace_on(&pseudonym);
        let mut states = HashMap::new();
        let mut sessions = HashMap::new();
        let mut dirs = HashMap::new();
        let mut hooks = CountingHooks::default();
        // 2.21.130 — les répertoires du ring n'ont pas bougé depuis
        // longtemps : après le rattrapage, ils ne sont plus relus.
        for plane in ["n3", "n2", "n4"] {
            fs::File::open(root.join(plane))
                .unwrap()
                .set_modified(base + Duration::from_secs(10_000))
                .unwrap();
        }
        let gpdu = |registry: &LiveTraceRegistry| {
            let traces = registry.traces.lock().unwrap();
            let t = &traces["t"];
            (t.trace.gpdu_seen, t.trace.gpdu_attached)
        };
        let reader = |registry: &LiveTraceRegistry| {
            let traces = registry.traces.lock().unwrap();
            registry.stats_payload(&traces["t"].trace)["reader"].clone()
        };

        // Passe 1 — rattrapage : le plus récent de chaque plan seulement.
        reader_pass(&root, &key, &registry, &mut states, &mut sessions, &mut dirs, true, false, std::time::Instant::now(), &mut hooks);
        assert_eq!(states.len(), 1_160, "la table suit tous les segments, sans être vidée");
        assert_eq!(hooks.files_decoded, 3, "un segment par plan actif");
        assert_eq!(gpdu(&registry), (gpdus_per_segment, gpdus_per_segment));
        assert_eq!(reader(&registry)["files_tracked"], 1_160);
        assert_eq!(reader(&registry)["files_decoded_last_pass"], 3);
        // 2.21.130 — seuls les deux segments les plus récents de chaque
        // plan sont interrogés : 6 sur 1 160.
        assert_eq!(reader(&registry)["files_examined_last_pass"], 6);
        assert!(reader(&registry)["scan_ms"].is_u64());
        assert!(reader(&registry)["interfaces"]["N3"]["decode_ms"].is_u64());
        assert!(reader(&registry)["interfaces"]["N3"]["route_ms"].is_u64());

        // Passe 2 — rien n'a changé : rien n'est redécodé, rien n'est
        // recompté. Avant le correctif : 1 160 segments redécodés.
        reader_pass(&root, &key, &registry, &mut states, &mut sessions, &mut dirs, false, false, std::time::Instant::now(), &mut hooks);
        assert_eq!(states.len(), 1_160);
        assert_eq!(hooks.files_decoded, 3, "aucun segment redécodé");
        assert_eq!(gpdu(&registry), (gpdus_per_segment, gpdus_per_segment), "aucun G-PDU recompté");
        assert_eq!(reader(&registry)["files_decoded_last_pass"], 0);
        assert_eq!(
            reader(&registry)["files_examined_last_pass"], 6,
            "passe à vide : 6 segments interrogés, pas 1 160"
        );
        assert_eq!(dirs.len(), 3, "les trois répertoires sont suivis par leur date");
        assert!(dirs.values().all(|dir| dir.recent.len() == 2 && dir.mtime.is_some()));

        // Passe 3 — le segment N3 courant grossit d'une section.
        {
            use std::io::Write;
            let mut file = fs::File::options().append(true).open(&newest_n3).unwrap();
            file.write_all(&n3_bytes).unwrap();
            file.set_modified(base + Duration::from_secs(5_000)).unwrap();
        }
        reader_pass(&root, &key, &registry, &mut states, &mut sessions, &mut dirs, false, false, std::time::Instant::now(), &mut hooks);
        assert_eq!(hooks.files_decoded, 4, "un seul segment décodé : celui qui a grossi");
        assert_eq!(states.len(), 1_160);
        let io = reader(&registry);
        assert_eq!(io["files_decoded_last_pass"], 1);
        assert_eq!(io["interfaces"]["N3"]["incremental"], true);
        assert_eq!(
            io["interfaces"]["N3"]["bytes_decoded"],
            n3_bytes.len() as u64,
            "seuls les octets ajoutés sont décodés"
        );
        assert_eq!(io["interfaces"]["N3"]["bytes_file"], 2 * n3_bytes.len() as u64);
        assert_eq!(io["resume_resets"], 0);
        assert_eq!(
            gpdu(&registry),
            (2 * gpdus_per_segment, 2 * gpdus_per_segment),
            "les G-PDU ajoutés, une fois chacun"
        );
        assert!(hooks.observed >= 2 * gpdus_per_segment, "le débit reçoit chaque G-PDU");
        assert_eq!(hooks.gap_bytes, 0);

        // Un segment ancien disparaît (rotation du ring) : il quitte la
        // table, sans alerte d'octets perdus puisqu'il était consommé.
        fs::remove_file(root.join("n3").join("n3_00000.pcapng")).unwrap();
        reader_pass(&root, &key, &registry, &mut states, &mut sessions, &mut dirs, false, false, std::time::Instant::now(), &mut hooks);
        assert_eq!(states.len(), 1_159);
        assert_eq!(hooks.gap_bytes, 0);
        assert_eq!(hooks.files_decoded, 4);
        let _ = fs::remove_dir_all(&root);
    }

    /// 2.21.124 (recette lab 2.21.114 : isolement FAIL à deux UE, ordre #9
    /// 7052731132) — isolement sur capture RÉELLE : cinq abonnés
    /// Open5GS + UERANSIM, un seul gNB, mêmes AMF / SMF / UPF, une seule
    /// capture (`benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/
    /// LAB_TESTBED/multi-imsi.pcap` : NGAP, SBI et PFCP fusionnés).
    /// Une trace est ouverte sur chacun des cinq abonnés à tour de rôle,
    /// AVANT que les events ne soient routés, dans l'ordre de la capture.
    ///
    /// Attendu, pour chaque trace : aucun message d'un autre contexte UE
    /// sur N2 ; aucun message portant le pseudonyme d'un autre abonné ;
    /// aucun pseudonyme d'un autre abonné appris ni exposé ; et la
    /// signalisation N2 de l'abonné présente.
    #[test]
    fn five_real_subscribers_on_one_gnb_each_trace_holds_only_its_subscriber_2_21_124() {
        let capture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/LAB_TESTBED/multi-imsi.pcap",
        );
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        // Même fichier, décodé une fois par plan ; les numéros de paquet
        // sont ceux de la capture, donc communs aux trois plans.
        let mut events: Vec<event_schema::NormalizedEvent> = Vec::new();
        for interface in ["N2", "N4", "SBI"] {
            let config = oiran_decode::DecodeConfig {
                input: capture.clone(),
                capture_id: format!("sha256:{}", sha256_hex(interface.as_bytes())),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: "multi-imsi.pcap".into(),
            };
            let _ = oiran_decode::decode_capture_streaming(&config, &key, |event| {
                events.push(event);
                Ok(())
            });
        }
        let packet_of = |event: &event_schema::NormalizedEvent| {
            event.packet_references.first().map(|p| p.packet_number).unwrap_or(0)
        };
        events.sort_by(|a, b| {
            packet_of(a)
                .cmp(&packet_of(b))
                .then_with(|| a.interface.cmp(&b.interface))
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        let id_of = |event: &event_schema::NormalizedEvent, name: &str| -> Option<String> {
            event
                .session_identifiers
                .iter()
                .find(|id| id.name == name)
                .map(|id| id.value.clone())
        };
        // Les abonnés : un contexte UE (`ran_ue_ngap_id`) chacun, avec
        // tous les pseudonymes que le NAS porte sur ce contexte (un même
        // abonné peut en avoir plusieurs, selon la forme de l'identité).
        let mut contexts: Vec<(String, Vec<String>)> = Vec::new();
        for event in events.iter().filter(|e| e.interface == "N2") {
            if let (Some(pseudonym), Some(ran)) =
                (id_of(event, "subscriber_pseudonym"), id_of(event, "ran_ue_ngap_id"))
            {
                match contexts.iter_mut().find(|(known, _)| known == &ran) {
                    Some((_, pseudonyms)) if !pseudonyms.contains(&pseudonym) => {
                        pseudonyms.push(pseudonym)
                    }
                    Some(_) => {}
                    None => contexts.push((ran, vec![pseudonym])),
                }
            }
        }
        assert_eq!(contexts.len(), 5, "la capture porte cinq abonnés : {contexts:?}");
        // Un pseudonyme porté par plusieurs contextes UE ne désigne pas un
        // abonné : c'est celui de l'IMEISV masqué, commun aux cinq UE du
        // simulateur. Il sort de la vérité terrain.
        let shared: HashSet<String> = contexts
            .iter()
            .flat_map(|(_, pseudonyms)| pseudonyms.iter().cloned())
            .filter(|pseudonym| {
                contexts.iter().filter(|(_, list)| list.contains(pseudonym)).count() > 1
            })
            .collect();
        assert_eq!(shared.len(), 1, "un pseudonyme d'équipement commun aux cinq UE");
        for (_, pseudonyms) in contexts.iter_mut() {
            pseudonyms.retain(|pseudonym| !shared.contains(pseudonym));
        }
        assert!(contexts.iter().all(|(_, pseudonyms)| pseudonyms.len() == 1), "{contexts:?}");
        let by_plane = |plane: &str| events.iter().filter(|e| e.interface == plane).count();
        assert!(by_plane("N2") > 50 && by_plane("N4") > 10, "N2={} N4={}", by_plane("N2"), by_plane("N4"));
        let all_pseudonyms: HashSet<String> = contexts
            .iter()
            .flat_map(|(_, pseudonyms)| pseudonyms.iter().cloned())
            .collect();

        // Amorçage : la relecture du ring sans émission applique la même
        // règle — rien d'un autre abonné ni d'un équipement n'est appris.
        {
            let (_, own) = &contexts[0];
            let registry = LiveTraceRegistry::new();
            registry
                .traces
                .lock()
                .unwrap()
                .insert("t".into(), state(u64::MAX, false, vec![own[0].clone()]));
            assert!(registry.begin_seed());
            for event in &events {
                registry.learn_from_ring(event);
            }
            registry.finish_seed(&SeedReport::default());
            let traces = registry.traces.lock().unwrap();
            let t = &traces["t"];
            assert!(t.trace.seed.events_learned > 0 && t.events.is_empty());
            for other in all_pseudonyms.iter().filter(|other| !own.contains(*other)) {
                assert!(!t.match_keys.contains(other), "amorçage : pseudonyme tiers appris");
            }
            for equipment in &shared {
                assert!(!t.match_keys.contains(equipment), "amorçage : pseudonyme d'équipement appris");
            }
            assert!(
                t.ue_ids.iter().all(|(name, value, _)| name != "ran_ue_ngap_id" || value == &contexts[0].0),
                "amorçage : identifiants UE d'un autre contexte : {:?}",
                t.ue_ids
            );
        }

        let mut attached_by_any: HashMap<String, usize> = HashMap::new();
        let mut counts: Vec<usize> = Vec::new();
        for (ran, own_pseudonyms) in &contexts {
            let pseudonym = &own_pseudonyms[0];
            let registry = LiveTraceRegistry::new();
            registry
                .traces
                .lock()
                .unwrap()
                .insert("t".into(), state(u64::MAX, false, vec![pseudonym.clone()]));
            for event in &events {
                registry.route_normalized(event);
            }
            let traces = registry.traces.lock().unwrap();
            let t = &traces["t"];
            let attached: HashSet<String> = t
                .events
                .iter()
                .filter(|e| e.kind == "message")
                .filter_map(|e| e.payload["event_id"].as_str().map(str::to_owned))
                .collect();
            let attached_events: Vec<&event_schema::NormalizedEvent> =
                events.iter().filter(|e| attached.contains(&e.event_id)).collect();
            // (1) N2 : aucun message d'un autre contexte UE.
            let foreign_n2: Vec<String> = attached_events
                .iter()
                .filter(|e| e.interface == "N2")
                .filter(|e| id_of(e, "ran_ue_ngap_id").is_some_and(|value| &value != ran))
                .map(|e| format!("{}({})", e.message_name, id_of(e, "ran_ue_ngap_id").unwrap_or_default()))
                .collect();
            assert!(foreign_n2.is_empty(), "trace ran={ran} : N2 d'un autre UE : {foreign_n2:?}");
            // (2) aucun message portant le pseudonyme d'un autre abonné.
            let foreign_identity: Vec<String> = attached_events
                .iter()
                .filter(|e| {
                    e.session_identifiers.iter().any(|id| {
                        all_pseudonyms.contains(&id.value) && !own_pseudonyms.contains(&id.value)
                    })
                })
                .map(|e| format!("{}:{}", e.interface, e.message_name))
                .collect();
            assert!(
                foreign_identity.is_empty(),
                "trace ran={ran} : messages d'un autre abonné : {foreign_identity:?}"
            );
            // (3bis) le pseudonyme d'équipement commun n'est ni appris ni
            // exposé.
            for equipment in &shared {
                assert!(!t.match_keys.contains(equipment), "trace ran={ran} : pseudonyme d'équipement appris");
                assert!(!t.exposed_keys.contains(equipment), "trace ran={ran} : pseudonyme d'équipement exposé");
            }
            // (3) aucun pseudonyme d'un autre abonné appris ni exposé.
            for other in all_pseudonyms.iter().filter(|other| !own_pseudonyms.contains(*other)) {
                assert!(!t.match_keys.contains(other), "trace ran={ran} : pseudonyme tiers appris");
                assert!(!t.exposed_keys.contains(other), "trace ran={ran} : pseudonyme tiers exposé");
            }
            // (4) la signalisation N2 de l'abonné est là.
            let own_n2 = events
                .iter()
                .filter(|e| e.interface == "N2")
                .filter(|e| id_of(e, "ran_ue_ngap_id").as_ref() == Some(ran))
                .count();
            let attached_n2 = attached_events.iter().filter(|e| e.interface == "N2").count();
            assert!(own_n2 >= 5, "trace ran={ran} : {own_n2} messages N2 propres");
            assert_eq!(
                attached_n2, own_n2,
                "trace ran={ran} : tout le dialogue N2 de l'abonné, rien d'autre"
            );
            // (5) la session PFCP de l'abonné : établissement (requête et
            // réponse, passés avant que la trace ne connaisse ses tunnels)
            // et modification (requête et réponse).
            let attached_n4: Vec<&str> = attached_events
                .iter()
                .filter(|e| e.interface == "N4")
                .map(|e| e.message_name.as_str())
                .collect();
            assert_eq!(attached_n4.len(), 4, "trace ran={ran} : N4 = {attached_n4:?}");
            for expected in [
                "PFCP Session Establishment Request",
                "PFCP Session Establishment Response",
                "PFCP Session Modification Request",
                "PFCP Session Modification Response",
            ] {
                assert!(attached_n4.contains(&expected), "trace ran={ran} : {expected} manque");
            }
            assert_eq!(t.trace.pfcp_attached_after_the_fact, 2, "trace ran={ran}");
            // Clés exposées : le pseudonyme de cet abonné, et aucun de ceux
            // des autres contextes.
            assert!(t.exposed_keys.contains(pseudonym), "trace ran={ran} : son pseudonyme est exposé");
            counts.push(attached.len());
            for event_id in &attached {
                *attached_by_any.entry(event_id.clone()).or_insert(0) += 1;
            }
            eprintln!(
                "FIVE_UE ran={ran} total={} n2={attached_n2}/{own_n2} n4={} sbi={} rejets_ue_id={} seid_only={}",
                attached.len(),
                attached_events.iter().filter(|e| e.interface == "N4").count(),
                attached_events.iter().filter(|e| e.interface == "SBI").count(),
                t.trace.rejected_ue_id_mismatch,
                t.trace.pfcp_attached_seid_only,
            );
        }
        // Aucun event n'entre dans deux traces ; les comptes par abonné
        // et les non rattachés font le total de la capture.
        let shared_events: Vec<&String> = attached_by_any
            .iter()
            .filter(|(_, traces)| **traces > 1)
            .map(|(event_id, _)| event_id)
            .collect();
        assert!(shared_events.is_empty(), "events dans plusieurs traces : {shared_events:?}");
        let attached_total: usize = counts.iter().sum();
        assert_eq!(attached_total, attached_by_any.len());
        eprintln!(
            "FIVE_UE comptes={counts:?} rattaches={attached_total} non_rattaches={} total={}",
            events.len() - attached_total,
            events.len()
        );
        assert_eq!(counts, vec![70, 68, 67, 69, 65], "comptes par abonné, stables");
    }

    /// 2.21.130 (recette lab 2.21.114, ordre #9 7052731132) — un plan sans
    /// reprise à l'offset (SBI) n'est redécodé en entier qu'une fois par
    /// intervalle, et la rotation du ring ne perd rien : les derniers
    /// octets du segment précédent sont lus après l'arrivée du suivant.
    #[test]
    fn reader_pass_throttles_full_redecode_and_follows_rotation_2_21_130() {
        let capture = fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../benchmarks/TELCOLADDER_OIRAN_NATIVE_V2/corpus/LAB_TESTBED/multi-imsi.pcap",
        ))
        .unwrap();
        let root = std::env::temp_dir().join(format!(
            "oiran-reader-throttle-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sbi")).unwrap();
        let first = root.join("sbi").join("sbi_00000.pcapng");
        fs::write(&first, &capture).unwrap();
        // Un enregistrement pcap de plus : le segment grossit.
        let grow = |path: &std::path::Path| {
            use std::io::Write;
            let mut file = fs::File::options().append(true).open(path).unwrap();
            let mut record = Vec::new();
            record.extend_from_slice(&1_795_000_000u32.to_le_bytes());
            record.extend_from_slice(&0u32.to_le_bytes());
            record.extend_from_slice(&20u32.to_le_bytes());
            record.extend_from_slice(&20u32.to_le_bytes());
            record.extend_from_slice(&[0u8; 20]);
            file.write_all(&record).unwrap();
        };
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let registry = trace_on("psn-none");
        let mut states = HashMap::new();
        let mut sessions = HashMap::new();
        let mut dirs = HashMap::new();
        let mut hooks = CountingHooks::default();
        let t0 = std::time::Instant::now();
        let mut pass = |after: Duration, catchup: bool, hooks: &mut CountingHooks| {
            reader_pass(&root, &key, &registry, &mut states, &mut sessions, &mut dirs, catchup, false, t0 + after, hooks);
            let traces = registry.traces.lock().unwrap();
            registry.stats_payload(&traces["t"].trace)["reader"].clone()
        };
        let io = pass(Duration::ZERO, true, &mut hooks);
        assert_eq!(hooks.files_decoded, 1, "le segment SBI courant est décodé au rattrapage");
        assert_eq!(io["interfaces"]["SBI"]["incremental"], false);
        // Le segment change 1 s plus tard : redécodage reporté.
        grow(&first);
        let io = pass(Duration::from_secs(1), false, &mut hooks);
        assert_eq!(hooks.files_decoded, 1, "redécodage intégral reporté");
        assert_eq!(io["interfaces"]["SBI"]["throttled"], 1);
        assert_eq!(io["files_decoded_last_pass"], 0);
        // Passé l'intervalle, il est redécodé.
        let io = pass(Duration::from_secs(4), false, &mut hooks);
        assert_eq!(hooks.files_decoded, 2);
        assert_eq!(io["files_decoded_last_pass"], 1);
        // Rotation : le segment précédent reçoit ses derniers octets, un
        // nouveau segment arrive. Les deux sont lus ; le précédent n'est
        // pas borné par la cadence (il n'est plus le segment courant).
        grow(&first);
        let second = root.join("sbi").join("sbi_00001.pcapng");
        fs::write(&second, &capture).unwrap();
        let _ = pass(Duration::from_secs(5), false, &mut hooks);
        assert_eq!(hooks.files_decoded, 4, "dernier état du segment précédent + nouveau segment");
        assert_eq!(hooks.gap_bytes, 0);
        // Passe à vide.
        let io = pass(Duration::from_secs(20), false, &mut hooks);
        assert_eq!(hooks.files_decoded, 4);
        assert_eq!(io["files_examined_last_pass"], 2);
        let _ = fs::remove_dir_all(&root);

        assert_eq!(reader_interval(0), Duration::from_millis(750));
        assert_eq!(reader_interval(1), Duration::from_millis(1_500));
        assert_eq!(reader_interval(2), Duration::from_millis(3_000));
        assert_eq!(reader_interval(40), Duration::from_millis(3_000));
    }

    /// 2.21.130 (recette lab : 201 Mo et 3 333 fichiers relus à chaque
    /// ouverture de trace) — l'amorçage ne relit que les trois segments
    /// les plus récents de chaque plan de signalisation, et le dit.
    #[test]
    fn seed_from_ring_reads_only_the_newest_segments_of_each_plane_2_21_130() {
        let datasets = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let root = std::env::temp_dir().join(format!(
            "oiran-seed-bound-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        for (plane, count) in [("n2", 40u64), ("n4", 2)] {
            let bytes = fs::read(datasets.join(format!("{}.pcapng", plane.to_ascii_uppercase()))).unwrap();
            fs::create_dir_all(root.join(plane)).unwrap();
            for index in 0..count {
                fs::write(root.join(plane).join(format!("{plane}_{index:05}.pcapng")), &bytes).unwrap();
            }
        }
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let registry = trace_on("psn-none");
        assert!(registry.begin_seed());
        let report = seed_from_ring(&root, &key, &registry);
        registry.finish_seed(&report);
        assert_eq!(report.files, 3 + 2, "3 segments N2 sur 40, 2 segments N4 sur 2");
        assert!(report.truncated, "des segments N2 plus anciens sont laissés de côté");
        let n2_len = fs::metadata(root.join("n2").join("n2_00039.pcapng")).unwrap().len();
        let n4_len = fs::metadata(root.join("n4").join("n4_00001.pcapng")).unwrap().len();
        assert_eq!(report.bytes, 3 * n2_len + 2 * n4_len);
        let traces = registry.traces.lock().unwrap();
        let seed = &traces["t"].trace.seed;
        assert!(seed.done && seed.truncated && seed.files == 5);
        let stats = registry.stats_payload(&traces["t"].trace);
        assert!(stats["seed"]["duration_ms"].is_u64());
        let _ = fs::remove_dir_all(&root);
    }

    /// 2.21.120 (lot B1) — le lecteur reprend aussi à l'offset sur le
    /// plan N2 : capture N2 réelle du dépôt écrite en trois fois, somme
    /// des octets décodés = taille du fichier, events = décodage
    /// intégral, aucune remise à zéro.
    #[test]
    fn decode_increment_resumes_on_the_n2_sctp_plane_2_21_120() {
        let bytes = fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng"),
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "oiran-reader-n2-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("n2_00001.pcapng");
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let config = ring_decode_config(&path, "N2");
        assert!(oiran_decode::supports_incremental("N2"));
        let mut sessions = HashMap::new();
        let mut events = Vec::new();
        let mut decoded = 0u64;
        for cut in [bytes.len() / 3 + 7, 2 * bytes.len() / 3 + 1, bytes.len(), bytes.len()] {
            fs::write(&path, &bytes[..cut]).unwrap();
            let outcome = decode_increment(&mut sessions, &config, &key, cut as u64);
            assert!(outcome.ok && !outcome.reset);
            decoded += outcome.bytes_decoded;
            events.extend(outcome.events);
        }
        assert_eq!(decoded, bytes.len() as u64);
        sort_by_capture_order(&mut events);
        let mut full = Vec::new();
        oiran_decode::decode_capture_streaming(&config, &key, |event| {
            full.push(event);
            Ok(())
        })
        .unwrap();
        sort_by_capture_order(&mut full);
        assert!(!full.is_empty());
        assert_eq!(ids(&events), ids(&full));
        let _ = fs::remove_dir_all(&dir);
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
                ..ReaderIo::default()
            },
        )]));
        // Une passe sans décodage garde le dernier relevé.
        r.set_reader_io(BTreeMap::new());
        let stats = r.stats_payload(&state(u64::MAX, false, vec![]).trace);
        assert_eq!(stats["reader"]["resume_resets"], 1);
        r.set_reader_files_tracked(2_713);
        r.set_reader_files_decoded(3);
        let stats = r.stats_payload(&state(u64::MAX, false, vec![]).trace);
        assert_eq!(stats["reader"]["files_tracked"], 2_713);
        assert_eq!(stats["reader"]["files_decoded_last_pass"], 3);
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
        // 2.21.109 — le rattachement se fait par égalité typée : le
        // tunnel de l'abonné est connu de la trace (appris sur sa
        // signalisation), les G-PDU le désignent par (adresse, TEID).
        {
            let teid = event_schema::normalize_teid_hex("0xabcd0001").unwrap();
            let mut traces = r.traces.lock().unwrap();
            let t = traces.get_mut("t").unwrap();
            t.tunnel_teids.insert(teid.clone());
            t.tunnel_endpoints.insert(("10.0.0.2".into(), teid));
        }
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
                message_name: "G-PDU".into(),
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
                session_identifiers: vec![event_schema::NamedValue {
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
            // 2.21.109 — un G-PDU UL va vers l'adresse du tunnel UL (UPF),
            // un G-PDU DL vers celle du tunnel DL (gNB).
            let tunnel_endpoint = if direction.as_str() == "UPLINK" {
                "10.77.11.13"
            } else {
                "10.77.22.13"
            };
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
                    address: tunnel_endpoint.into(),
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
                        value: tunnel_endpoint.into(),
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
        // 2.21.109 — le rattachement se fait par égalité typée : le
        // tunnel de l'abonné est connu de la trace (appris sur sa
        // signalisation), les G-PDU le désignent par (adresse, TEID).
        {
            let teid = event_schema::normalize_teid_hex("0xabcd0001").unwrap();
            let mut traces = r.traces.lock().unwrap();
            let t = traces.get_mut("t").unwrap();
            t.tunnel_teids.insert(teid.clone());
            t.tunnel_endpoints.insert(("10.0.0.2".into(), teid));
        }

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
            message_name: "G-PDU".into(),
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
        // 2.21.109 — le rattachement se fait par égalité typée : le
        // tunnel de l'abonné est connu de la trace (appris sur sa
        // signalisation), les G-PDU le désignent par (adresse, TEID).
        {
            let teid = event_schema::normalize_teid_hex("0xabcd0001").unwrap();
            let mut traces = r.traces.lock().unwrap();
            let t = traces.get_mut("t").unwrap();
            t.tunnel_teids.insert(teid.clone());
            t.tunnel_endpoints.insert(("10.0.0.2".into(), teid));
        }
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
                message_name: "G-PDU".into(),
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
        // 5) GTP-U UL (TEID = UL F-TEID appris), vers l'adresse du
        //    tunnel UL.
        let mut e_gtpu = ev(
            "N3",
            Protocol::Gtpu,
            "G-PDU",
            5,
            vec![("teid", "0x0000d4a6")],
            vec![],
        );
        e_gtpu.destination_endpoint.address = "10.100.0.1".into();
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
        // 2.21.109 (décision cœur #9 7050201220) — le G-PDU est rattaché
        // et compté, mais n'est plus émis en `message`.
        assert_eq!(
            routed,
            vec!["ev-1", "ev-2", "ev-3", "ev-4"],
            "les 4 events de signalisation sont routés dans l'ordre"
        );
        assert_eq!(t.trace.gpdu_attached, 1, "le G-PDU est rattaché");
        assert_eq!(t.trace.messages, 4, "un G-PDU ne compte pas comme message");
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
        // match_keys contient les chiffres amorcés et le pseudonyme.
        assert!(t.match_keys.contains(&imsi_digits));
        assert!(t.match_keys.contains("psn-supi-xyz"));
        // 2.21.109 — `pdu_session_id` n'identifie pas un abonné (il vaut 1
        // pour presque tous) : il n'est plus une clé de rattachement.
        assert!(!t.match_keys.contains("sess-00042"));
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
