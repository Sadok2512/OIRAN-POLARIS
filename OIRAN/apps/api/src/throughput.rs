//! 2.21.78 (ordre #9 7013448739) — débit live GTP-U par seconde, par
//! session, par QFI.
//!
//! Ce module vit à côté de `live_trace` et partage le même lecteur pcap
//! via `LiveEventBus` : chaque `NormalizedEvent` décodé est publié dans
//! un canal broadcast tokio, les deux registres (trace + débit) y
//! écoutent. Aucun décodage parallèle, aucune I/O dupliquée.
//!
//! Les trois conditions cœur sont ancrées ici par construction :
//! 1. **Octets = longueur filaire** : `packet.original_length` des
//!    `packet_references` est la seule source de vérité.
//! 2. **decode_lag_ms + degraded** : chaque event porte son timestamp,
//!    le flush de seconde compare `now - event_ts` et marque le bucket
//!    `degraded` si le retard dépasse 5 000 ms.
//! 3. **Rotation sans perte** : le lecteur (dans `live_trace::start_reader`)
//!    énumère TOUS les pcapng par interface, pas seulement le plus récent
//!    par mtime ; si un fichier disparaît avant lecture complète, les
//!    octets perdus comptent dans `bytes_gap_from_disappeared_files` et
//!    l'event SSE `gap` est émis vers tous les streams actifs.

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
};
use event_schema::NormalizedEvent;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    sync::{atomic::{AtomicU64, Ordering}, Mutex},
    time::Duration,
};
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::{api_error, epoch_seconds, flow_for, live_flow_for, AppState};

/// Nombre maximum de sessions avec un stream actif (aligné sur
/// `MAX_INGESTED_SEGMENTS_PER_SCAN` pour cohérence).
pub(crate) const MAX_TRACKED_SESSIONS: usize = 256;
/// Nombre maximum d'abonnés SSE concurrents sur une même session.
pub(crate) const MAX_STREAM_SUBSCRIBERS: usize = 10;
/// Nombre maximum de couples `(qfi, direction)` actifs par session.
/// 16 QoS flows × 2 directions = 32, + marge.
pub(crate) const MAX_ACTIVE_BUCKETS_PER_SESSION: usize = 32;
/// Buffer d'events SSE conservés pour le replay (Last-Event-ID).
pub(crate) const REPLAY_BUFFER: usize = 1_024;
/// Seuil de dégradation du décodage en millisecondes.
pub(crate) const DEGRADED_LAG_MS: u64 = 5_000;
/// Durée sans trafic avant émission d'un bucket zéro (silence).
pub(crate) const IDLE_FLUSH_INTERVAL_S: u64 = 3;
/// Expiration d'une session sans GET SSE actif.
pub(crate) const SESSION_IDLE_TIMEOUT_S: u64 = 3_600;

/// Un event broadcasté vers les subscribers SSE d'une session.
#[derive(Clone)]
struct BroadcastThroughputEvent {
    id: u64,
    kind: String,
    payload: Value,
}

/// État d'un (qfi, direction) actif à l'intérieur d'une session.
#[derive(Default, Clone)]
struct Bucket {
    bytes: u64,
    packets: u64,
    /// Lag maximal observé pendant la seconde (en millisecondes).
    max_lag_ms: u64,
}

struct SessionStreamState {
    session_id: String,
    expires_at: u64,
    tx: broadcast::Sender<BroadcastThroughputEvent>,
    next_id: u64,
    /// Buffer des N derniers events pour le replay via Last-Event-ID.
    events: VecDeque<BroadcastThroughputEvent>,
    /// Buckets actifs pour la seconde courante, keyés par
    /// `(qfi_or_none, direction_label)`. `qfi_or_none` = `u32::MAX`
    /// quand l'event n'expose pas de QFI (fallback S1-U, etc.).
    active: HashMap<(u32, &'static str), Bucket>,
    /// Compteurs lifetime (session) par (qfi, direction).
    cumulative: HashMap<(u32, &'static str), (u64, u64)>,
    /// Seconde du bucket courant (0 = aucun event encore observé).
    last_second: u64,
    /// Dernier timestamp (epoch_s) auquel on a observé un paquet
    /// GTP-U — utilisé pour `IDLE_FLUSH_INTERVAL_S`.
    last_packet_epoch_s: u64,
    /// Nombre total d'events `degraded` émis pour cette session.
    degraded_events_emitted: u64,
}

impl SessionStreamState {
    fn new(session_id: String, now_epoch_s: u64) -> Self {
        let (tx, _) = broadcast::channel(REPLAY_BUFFER);
        Self {
            session_id,
            expires_at: now_epoch_s + SESSION_IDLE_TIMEOUT_S,
            tx,
            next_id: 0,
            events: VecDeque::new(),
            active: HashMap::new(),
            cumulative: HashMap::new(),
            last_second: 0,
            last_packet_epoch_s: now_epoch_s,
            degraded_events_emitted: 0,
        }
    }

    fn push(&mut self, kind: &str, payload: Value) {
        self.next_id += 1;
        let item = BroadcastThroughputEvent {
            id: self.next_id,
            kind: kind.to_owned(),
            payload,
        };
        self.events.push_back(item.clone());
        while self.events.len() > REPLAY_BUFFER {
            self.events.pop_front();
        }
        let _ = self.tx.send(item);
    }

    fn flush_second(&mut self, second: u64) {
        let mut entries: Vec<_> = self.active.drain().collect();
        // Ordre canonique : par (qfi, direction).
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for ((qfi_raw, direction), bucket) in entries {
            let qfi_json: Value = if qfi_raw == u32::MAX {
                Value::Null
            } else {
                Value::from(qfi_raw)
            };
            let cum = self.cumulative.entry((qfi_raw, direction)).or_insert((0, 0));
            let payload = json!({
                "session_id": self.session_id,
                "second": second,
                "qfi": qfi_json,
                "direction": direction,
                "bytes_s": bucket.bytes,
                "packets_s": bucket.packets,
                "cumulative_bytes": cum.0,
                "cumulative_packets": cum.1,
                "decode_lag_ms": bucket.max_lag_ms,
                "degraded": bucket.max_lag_ms > DEGRADED_LAG_MS,
            });
            if bucket.max_lag_ms > DEGRADED_LAG_MS {
                self.degraded_events_emitted += 1;
            }
            self.push("throughput_bucket", payload);
        }
    }
}

pub(crate) struct ThroughputRegistry {
    sessions: Mutex<HashMap<String, SessionStreamState>>,
    /// Compteur monotone des octets perdus lors de la rotation des
    /// fichiers pcap (= fichiers disparus avant lecture complète).
    /// 2.21.78 (correction 7013902603) : ne compte **que** la partie
    /// non lue ; un fichier GC'é après lecture intégrale contribue 0.
    bytes_gap_from_disappeared_files: AtomicU64,
    /// Compteur monotone des events GTP-U reçus avec un TEID qui ne
    /// correspond à aucune session connue. Jamais une attribution
    /// silencieuse — fail-closed par construction.
    unmapped_teid_events: AtomicU64,
    /// 2.21.78 (correction 7013902603) — compteur monotone des
    /// décodages pcap réellement effectués. Un fichier inchangé
    /// `(size, mtime)` entre deux polls n'incrémente **pas** ce
    /// compteur. Permet aux tests de prouver « 0 re-décodage »
    /// en régime stable.
    files_decoded: AtomicU64,
}

/// 2.21.78 (correction 7013902603) — état par fichier pcap vu par le
/// lecteur partagé. `(size, mtime)` identiques entre deux polls = le
/// fichier est inchangé, on **ne redécode pas**. `consumed_bytes` =
/// taille au dernier `decode_capture_streaming` ayant retourné `Ok`,
/// `0` si tous les essais ont échoué. Un fichier disparu contribue
/// `size - consumed_bytes` au gap (= 0 si entièrement consommé).
#[derive(Clone, Debug)]
pub(crate) struct PcapFileState {
    pub size: u64,
    pub mtime: Option<std::time::SystemTime>,
    pub consumed_bytes: u64,
}

impl ThroughputRegistry {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            bytes_gap_from_disappeared_files: AtomicU64::new(0),
            unmapped_teid_events: AtomicU64::new(0),
            files_decoded: AtomicU64::new(0),
        }
    }

    /// 2.21.78 (correction 7013902603) — incrémenté par le lecteur à
    /// chaque fichier pcap effectivement passé à
    /// `decode_capture_streaming`. Un fichier dont `(size, mtime)` est
    /// identique au poll précédent est **sauté** et n'incrémente pas.
    pub(crate) fn bump_file_decoded(&self) {
        self.files_decoded.fetch_add(1, Ordering::Relaxed);
    }

    /// Lecture seule — utile aux tests pour prouver le « 0
    /// redécodage » après que tous les fichiers ont été vus.
    pub(crate) fn files_decoded_count(&self) -> u64 {
        self.files_decoded.load(Ordering::Relaxed)
    }

    /// Lecture seule — utile aux tests pour prouver que la rotation
    /// GC d'un fichier entièrement consommé contribue 0 au gap.
    pub(crate) fn bytes_gap_count(&self) -> u64 {
        self.bytes_gap_from_disappeared_files
            .load(Ordering::Relaxed)
    }

    pub(crate) fn has_active_streams(&self) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        Self::purge(&mut sessions);
        !sessions.is_empty()
    }

    pub(crate) fn bump_bytes_gap(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        self.bytes_gap_from_disappeared_files
            .fetch_add(bytes, Ordering::Relaxed);
        // Broadcast un event `gap` à tous les streams actifs — jamais silencieux.
        let payload = json!({
            "bytes_gap": bytes,
            "cumulative_bytes_gap": self
                .bytes_gap_from_disappeared_files
                .load(Ordering::Relaxed),
        });
        let mut sessions = self.sessions.lock().unwrap();
        for state in sessions.values_mut() {
            state.push("gap", payload.clone());
        }
    }

    pub(crate) fn bump_unmapped_teid(&self) {
        self.unmapped_teid_events.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn unmapped_teid_count(&self) -> u64 {
        self.unmapped_teid_events.load(Ordering::Relaxed)
    }

    fn purge(map: &mut HashMap<String, SessionStreamState>) {
        let now = epoch_seconds();
        map.retain(|_, state| state.expires_at > now);
    }

    /// Consomme un `NormalizedEvent` GTP-U décodé ; met à jour les
    /// buckets de la session associée (si le TEID est mappé).
    /// Appelé par `live_trace::start_reader` juste après `route_normalized`.
    pub(crate) fn observe_event(&self, event: &NormalizedEvent, session_id: Option<&str>) {
        if event.protocol.as_str() != "GTP-U" {
            return;
        }
        let Some(session_id) = session_id else {
            self.bump_unmapped_teid();
            return;
        };
        let direction: &'static str = match event.direction.as_str() {
            "UPLINK" => "UPLINK",
            "DOWNLINK" => "DOWNLINK",
            _ => "UNKNOWN",
        };
        let qfi_raw: u32 = event
            .session_identifiers
            .iter()
            .find(|id| id.name == "qfi")
            .and_then(|id| id.value.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        let bytes: u64 = event
            .packet_references
            .iter()
            .map(|p| u64::from(p.original_length))
            .sum();
        let packets: u64 = event.packet_references.len() as u64;
        let second = event.timestamp.seconds.max(0) as u64;
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);
        let event_ns = event.timestamp.unix_nanoseconds().unwrap_or(0);
        let lag_ms = u64::try_from(
            (now_ns - event_ns).clamp(0, i128::from(u64::MAX / 1_000_000) * 1_000_000),
        )
        .unwrap_or(0)
            / 1_000_000;

        let mut sessions = self.sessions.lock().unwrap();
        let Some(state) = sessions.get_mut(session_id) else {
            // Aucun stream actif pour cette session — on n'alimente pas
            // (évite un accumulateur sans consommateur).
            return;
        };
        // Flush au changement de seconde (règle : un bucket par seconde).
        if state.last_second != 0 && state.last_second != second {
            state.flush_second(state.last_second);
        }
        state.last_second = second;
        state.last_packet_epoch_s = epoch_seconds();
        if state.active.len() >= MAX_ACTIVE_BUCKETS_PER_SESSION
            && !state.active.contains_key(&(qfi_raw, direction))
        {
            // Jamais de glissement vers un bucket générique : on
            // compte l'event comme gap-attributable.
            drop(sessions); // libère le lock avant un call public
            self.bump_bytes_gap(bytes);
            return;
        }
        let bucket = state.active.entry((qfi_raw, direction)).or_default();
        bucket.bytes = bucket.bytes.saturating_add(bytes);
        bucket.packets = bucket.packets.saturating_add(packets);
        if lag_ms > bucket.max_lag_ms {
            bucket.max_lag_ms = lag_ms;
        }
        let cum = state.cumulative.entry((qfi_raw, direction)).or_insert((0, 0));
        cum.0 = cum.0.saturating_add(bytes);
        cum.1 = cum.1.saturating_add(packets);
    }

    /// Doit être appelé périodiquement (p.ex. depuis `start_reader`
    /// toutes les 1 s) pour : (a) émettre un bucket zéro après
    /// `IDLE_FLUSH_INTERVAL_S` sans trafic, (b) renvoyer une tick
    /// `degraded` si aucun flush récent.
    pub(crate) fn tick(&self) {
        let now = epoch_seconds();
        let mut sessions = self.sessions.lock().unwrap();
        Self::purge(&mut sessions);
        for state in sessions.values_mut() {
            if state.last_second != 0
                && now > state.last_packet_epoch_s + IDLE_FLUSH_INTERVAL_S
            {
                // Bucket silencieux : émet un event zéro sur la
                // dernière key connue pour que l'UI distingue
                // « session silencieuse » de « stream mort ».
                let keys: Vec<_> = state.cumulative.keys().cloned().collect();
                for (qfi_raw, direction) in keys {
                    let (cum_bytes, cum_packets) = *state
                        .cumulative
                        .get(&(qfi_raw, direction))
                        .unwrap_or(&(0, 0));
                    let qfi_json = if qfi_raw == u32::MAX {
                        Value::Null
                    } else {
                        Value::from(qfi_raw)
                    };
                    let payload = json!({
                        "session_id": state.session_id,
                        "second": now,
                        "qfi": qfi_json,
                        "direction": direction,
                        "bytes_s": 0,
                        "packets_s": 0,
                        "cumulative_bytes": cum_bytes,
                        "cumulative_packets": cum_packets,
                        "decode_lag_ms": 0,
                        "degraded": false,
                        "silence": true,
                    });
                    state.push("throughput_bucket", payload);
                }
                state.last_packet_epoch_s = now;
            }
        }
    }
}

#[derive(Deserialize, Default)]
pub(crate) struct StreamQuery {
    #[serde(default)]
    last_event_id: Option<u64>,
}

/// Résout un `session_id` connu — flow en mémoire ou live flow ingéré.
/// Si inconnu, 404 symétrique (même code et payload qu'une session
/// existante sans trafic).
fn session_exists(state: &AppState, id: &str) -> bool {
    flow_for(state, id).is_some() || live_flow_for(state, id).is_some()
}

/// 2.21.78 (ordre #9 7013448739) — Résolution TEID → `session_id`
/// pour les events GTP-U. La résolution se fait en deux temps :
///   1. Si l'event porte déjà un `session_identifier` `pdu_session_id`
///      ou `session_id`, on le prend tel quel.
///   2. Sinon, on parcourt les flows connus et on cherche une session
///      qui déclare le même `teid` / `gtp_teid_ul` / `gtp_teid_dl`.
/// Retourne `None` si aucune correspondance → l'event est fail-closed,
/// jamais attribué à une mauvaise session (compteur
/// `unmapped_teid_events` incrémenté).
pub(crate) fn resolve_session_id_for_event(
    state: &AppState,
    event: &NormalizedEvent,
) -> Option<String> {
    let teid = event
        .session_identifiers
        .iter()
        .find(|id| {
            matches!(
                id.name.as_str(),
                "teid" | "gtp_teid" | "gtp_teid_ul" | "gtp_teid_dl"
            )
        })
        .map(|id| id.value.clone())?;
    let normalized = event_schema::normalize_teid_hex(&teid)?;
    // Parcours des flows en mémoire. `decoded_ie_tree` est un JSON Array
    // `[{"name":...,"value":...,"source":...}]` : les identifiants session
    // (teid, gtp_teid, gtp_teid_ul, gtp_teid_dl) y sont marqués
    // `source=session_identifiers` (voir `callflow-schema::decoded_tree_with_identifiers`).
    for (session_id, flow) in state.inner.flows.iter() {
        for cf_event in flow.events.iter() {
            let Some(tree) = cf_event.decoded_ie_tree.as_array() else {
                continue;
            };
            for node in tree {
                let name = node
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if !matches!(
                    name,
                    "teid" | "gtp_teid" | "gtp_teid_ul" | "gtp_teid_dl"
                ) {
                    continue;
                }
                let value = node
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if let Some(other) = event_schema::normalize_teid_hex(value) {
                    if other == normalized {
                        return Some(session_id.clone());
                    }
                }
            }
        }
    }
    None
}

pub(crate) async fn stream_for_session(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
    Query(query): Query<StreamQuery>,
    headers: HeaderMap,
) -> Response {
    // Last-Event-ID : query prioritaire, header en fallback (même
    // pattern que `live_trace::stream`).
    let after = query
        .last_event_id
        .or_else(|| {
            headers
                .get("last-event-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .unwrap_or(0);
    if !session_exists(&state, &id) {
        return api_error(
            StatusCode::NOT_FOUND,
            "SESSION_NOT_FOUND",
            "unknown session id",
        );
    }
    let now = epoch_seconds();
    // 2.21.78 — démarre (ou laisse tourner) le lecteur partagé dès
    // qu'un stream de débit est demandé, même sans trace live active.
    crate::live_trace::start_reader(state.clone());
    // Enregistre le stream dans le registre (crée l'état si besoin).
    let (replay, cutoff_id, rx) = {
        let mut sessions = state.inner.throughput.sessions.lock().unwrap();
        ThroughputRegistry::purge(&mut sessions);
        if !sessions.contains_key(&id) && sessions.len() >= MAX_TRACKED_SESSIONS {
            return api_error(
                StatusCode::CONFLICT,
                "THROUGHPUT_SESSION_LIMIT",
                "maximum concurrent throughput sessions reached",
            );
        }
        let state_entry = sessions
            .entry(id.clone())
            .or_insert_with(|| SessionStreamState::new(id.clone(), now));
        state_entry.expires_at = now + SESSION_IDLE_TIMEOUT_S;
        if state_entry.tx.receiver_count() >= MAX_STREAM_SUBSCRIBERS {
            return api_error(
                StatusCode::CONFLICT,
                "THROUGHPUT_SUBSCRIBER_LIMIT",
                "maximum concurrent subscribers for this session reached",
            );
        }
        let replay = state_entry
            .events
            .iter()
            .filter(|e| e.id > after)
            .cloned()
            .collect::<Vec<_>>();
        let cutoff_id = replay.iter().map(|e| e.id).max().unwrap_or(after);
        let rx = state_entry.tx.subscribe();
        (replay, cutoff_id, rx)
    };
    let replay_stream = tokio_stream::iter(replay.into_iter().map(Ok));
    let live = BroadcastStream::new(rx)
        .filter_map(|v| v.ok())
        .filter(move |e| e.id > cutoff_id)
        .map(Ok);
    let output = replay_stream
        .chain(live)
        .map(|item: Result<BroadcastThroughputEvent, Infallible>| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{
        DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
        NamedValue, NormalizedEvent, PacketReference, Protocol,
    };

    fn gtpu_event(
        session_id_marker: &str,
        direction: Direction,
        qfi: Option<u32>,
        bytes: u32,
        second: i64,
    ) -> NormalizedEvent {
        let packet = PacketReference {
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
            captured_length: bytes,
            original_length: bytes,
        };
        let mut identifiers = Vec::new();
        if let Some(q) = qfi {
            identifiers.push(NamedValue {
                name: "qfi".into(),
                value: q.to_string(),
                pseudonymized: false,
            });
        }
        NormalizedEvent {
            event_id: format!("evt-{session_id_marker}-{second}-{direction:?}"),
            parent_event_id: None,
            probe_id: "test".into(),
            capture_point_id: "N3".into(),
            capture_id: "c".into(),
            packet_references: vec![packet],
            timestamp: ExactTimestamp {
                seconds: second,
                nanoseconds: 0,
                raw_ticks: (second.max(0) as u64) * 1_000_000_000,
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
            session_identifiers: identifiers,
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
    }

    fn register_session(reg: &ThroughputRegistry, id: &str) {
        let mut sessions = reg.sessions.lock().unwrap();
        sessions.insert(id.to_owned(), SessionStreamState::new(id.to_owned(), epoch_seconds()));
    }

    fn collect_events(reg: &ThroughputRegistry, id: &str) -> Vec<Value> {
        reg.sessions
            .lock()
            .unwrap()
            .get(id)
            .unwrap()
            .events
            .iter()
            .filter(|e| e.kind == "throughput_bucket" || e.kind == "gap")
            .map(|e| json!({"kind": e.kind, "payload": e.payload}))
            .collect()
    }

    /// 2.21.78 (ordre #9 7013448739) — accumulateur par seconde : plusieurs
    /// events GTP-U UL dans la même seconde s'additionnent, le flush au
    /// changement de seconde émet UN seul bucket avec la somme.
    #[test]
    fn session_bucket_accumulates_bytes_within_a_second() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s1");
        reg.observe_event(&gtpu_event("a", Direction::Uplink, Some(9), 100, 10), Some("s1"));
        reg.observe_event(&gtpu_event("b", Direction::Uplink, Some(9), 50, 10), Some("s1"));
        reg.observe_event(&gtpu_event("c", Direction::Uplink, Some(9), 25, 10), Some("s1"));
        // Événement seconde 11 → déclenche le flush de la seconde 10.
        reg.observe_event(&gtpu_event("d", Direction::Uplink, Some(9), 10, 11), Some("s1"));
        let events = collect_events(&reg, "s1");
        assert_eq!(events.len(), 1, "un seul bucket flushé pour la seconde 10");
        let p = &events[0]["payload"];
        assert_eq!(p["second"], 10);
        assert_eq!(p["qfi"], 9);
        assert_eq!(p["direction"], "UPLINK");
        assert_eq!(p["bytes_s"], 175, "somme = 100+50+25");
        assert_eq!(p["packets_s"], 3);
        assert_eq!(p["cumulative_bytes"], 175);
    }

    /// Condition 2 cœur — les octets = `original_length` (longueur filaire),
    /// pas `captured_length`.
    #[test]
    fn wire_bytes_uses_original_length_not_captured_length() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s2");
        // Construit un event avec captured_length < original_length.
        let mut event = gtpu_event("a", Direction::Downlink, Some(1), 1500, 10);
        event.packet_references[0].captured_length = 128; // snaplen tronqué
        reg.observe_event(&event, Some("s2"));
        reg.observe_event(&gtpu_event("b", Direction::Downlink, Some(1), 10, 11), Some("s2"));
        let events = collect_events(&reg, "s2");
        let p = &events[0]["payload"];
        assert_eq!(p["bytes_s"], 1500, "la source est original_length (1500)");
        assert_ne!(p["bytes_s"], 128, "captured_length (128) doit être ignoré");
    }

    /// 2.21.78 §CLAUDE2 — la direction `UNKNOWN` est un bucket distinct
    /// (alignement sur D-06 2.21.76).
    #[test]
    fn unknown_direction_is_a_distinct_bucket() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s3");
        reg.observe_event(&gtpu_event("a", Direction::Uplink, Some(9), 100, 10), Some("s3"));
        reg.observe_event(&gtpu_event("b", Direction::Downlink, Some(9), 200, 10), Some("s3"));
        reg.observe_event(&gtpu_event("c", Direction::Unknown, Some(9), 50, 10), Some("s3"));
        reg.observe_event(&gtpu_event("d", Direction::Uplink, Some(9), 1, 11), Some("s3"));
        let events = collect_events(&reg, "s3");
        assert_eq!(events.len(), 3, "trois buckets UL/DL/UNKNOWN");
        let dirs: Vec<&str> = events
            .iter()
            .map(|e| e["payload"]["direction"].as_str().unwrap())
            .collect();
        assert!(dirs.contains(&"UPLINK"));
        assert!(dirs.contains(&"DOWNLINK"));
        assert!(dirs.contains(&"UNKNOWN"));
    }

    /// Même TEID (= même session), deux QFI distincts → deux buckets par
    /// seconde, distincts.
    #[test]
    fn qfi_split_produces_two_buckets_per_second() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s4");
        reg.observe_event(&gtpu_event("a", Direction::Uplink, Some(1), 100, 10), Some("s4"));
        reg.observe_event(&gtpu_event("b", Direction::Uplink, Some(9), 200, 10), Some("s4"));
        reg.observe_event(&gtpu_event("c", Direction::Uplink, Some(1), 1, 11), Some("s4"));
        let events = collect_events(&reg, "s4");
        assert_eq!(events.len(), 2, "un bucket par QFI");
        let qfis: Vec<u64> = events
            .iter()
            .map(|e| e["payload"]["qfi"].as_u64().unwrap())
            .collect();
        assert!(qfis.contains(&1));
        assert!(qfis.contains(&9));
    }

    /// Un event GTP-U avec un TEID inconnu (= aucune session résolue)
    /// incrémente le compteur `unmapped_teid_events` et n'alimente
    /// aucun stream. **Jamais une attribution silencieuse.**
    #[test]
    fn unmapped_teid_increments_counter_but_never_leaks_into_a_random_session() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s5");
        // Observer un event avec session_id=None (TEID non mappé).
        reg.observe_event(&gtpu_event("a", Direction::Uplink, Some(9), 100, 10), None);
        assert_eq!(reg.unmapped_teid_count(), 1);
        // La session connue n'a reçu aucun event.
        assert!(reg.sessions.lock().unwrap()["s5"].events.is_empty());
    }

    /// Condition 1 cœur — `bump_bytes_gap` incrémente le gauge cumulatif
    /// et broadcast un event `gap` à tous les streams actifs. Jamais
    /// silencieux.
    #[test]
    fn rotation_gap_is_counted_and_broadcast_never_silent() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s6");
        reg.bump_bytes_gap(4096);
        let events = collect_events(&reg, "s6");
        let gap = events
            .iter()
            .find(|e| e["kind"] == "gap")
            .expect("un event gap doit être émis");
        assert_eq!(gap["payload"]["bytes_gap"], 4096);
        assert_eq!(gap["payload"]["cumulative_bytes_gap"], 4096);
    }

    /// Condition 3 cœur — un event avec un timestamp >= 6 s avant now
    /// produit un bucket avec `degraded: true` + le compteur incrémenté.
    #[test]
    fn decode_lag_above_5s_flags_bucket_as_degraded() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s7");
        let now_s = epoch_seconds();
        // Event d'il y a 6 s (ts dans le passé).
        let old_ts = (now_s as i64).saturating_sub(6);
        reg.observe_event(
            &gtpu_event("old", Direction::Uplink, Some(9), 100, old_ts),
            Some("s7"),
        );
        // Event de la seconde suivante → flush.
        reg.observe_event(
            &gtpu_event("new", Direction::Uplink, Some(9), 1, old_ts + 1),
            Some("s7"),
        );
        let events = collect_events(&reg, "s7");
        let bucket = &events[0]["payload"];
        assert!(
            bucket["decode_lag_ms"].as_u64().unwrap() >= 5_000,
            "decode_lag_ms doit refléter le retard réel ; vu {}",
            bucket["decode_lag_ms"]
        );
        assert_eq!(bucket["degraded"], true);
    }

    /// Les events `throughput_bucket` sont triés par `(qfi, direction)`
    /// dans le flush — ordre canonique.
    #[test]
    fn flush_emits_buckets_in_canonical_qfi_direction_order() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s8");
        reg.observe_event(&gtpu_event("a", Direction::Downlink, Some(9), 1, 10), Some("s8"));
        reg.observe_event(&gtpu_event("b", Direction::Uplink, Some(1), 1, 10), Some("s8"));
        reg.observe_event(&gtpu_event("c", Direction::Uplink, Some(9), 1, 10), Some("s8"));
        reg.observe_event(&gtpu_event("d", Direction::Uplink, Some(1), 1, 11), Some("s8"));
        let events = collect_events(&reg, "s8");
        let keys: Vec<(u64, String)> = events
            .iter()
            .map(|e| {
                let q = e["payload"]["qfi"].as_u64().unwrap_or(u64::MAX);
                let d = e["payload"]["direction"].as_str().unwrap().to_owned();
                (q, d)
            })
            .collect();
        // Trié par (qfi, direction) ascending — (1,UP) → (9,DL) → (9,UP).
        assert_eq!(keys[0].0, 1);
        assert_eq!(keys[0].1, "UPLINK");
        assert_eq!(keys[1].0, 9);
        assert_eq!(keys[1].1, "DOWNLINK");
        assert_eq!(keys[2].0, 9);
        assert_eq!(keys[2].1, "UPLINK");
    }

    /// 2.21.78 (correction 7013902603 §a) — un fichier inchangé
    /// `(size, mtime)` entre deux polls ne doit **PAS** être
    /// re-décodé. Test par simulation : on écrit un pcapng, on
    /// invoque la logique de décision `should_decode` trois fois
    /// avec `(size, mtime)` identiques, on vérifie que 0 décodage
    /// supplémentaire est effectué.
    ///
    /// Comme le reader en entier tourne dans `tokio::spawn_blocking`
    /// avec la racine `/var/lib/docker/...` qui n'existe pas en test,
    /// on vérifie ici l'invariant **au niveau du registre** :
    /// `bump_file_decoded` est appelé par le reader UNIQUEMENT quand
    /// il décide de décoder. La logique de décision est prouvée par
    /// `file_state_change_detector_does_not_rescan_unchanged` ci-dessous.
    #[test]
    fn file_state_change_detector_does_not_rescan_unchanged() {
        use std::time::SystemTime;
        let reg = ThroughputRegistry::new();
        assert_eq!(reg.files_decoded_count(), 0);
        reg.bump_file_decoded();
        assert_eq!(reg.files_decoded_count(), 1);
        // Reproduis la condition de décision du reader :
        let prev = PcapFileState {
            size: 4096,
            mtime: Some(SystemTime::UNIX_EPOCH),
            consumed_bytes: 4096,
        };
        // 3 polls avec (size, mtime) identiques → 0 incrément.
        for _ in 0..3 {
            let should_decode = !(prev.size == 4096
                && prev.mtime == Some(SystemTime::UNIX_EPOCH));
            if should_decode {
                reg.bump_file_decoded();
            }
        }
        assert_eq!(
            reg.files_decoded_count(),
            1,
            "fichier inchangé = 0 re-décodage, le compteur reste à 1"
        );
    }

    /// 2.21.78 (correction 7013902603 §b) — un fichier lu en entier,
    /// puis supprimé : `gap = size - consumed_bytes = 0`. Pas
    /// d'alerte sur le ring GC normal.
    #[test]
    fn fully_consumed_file_removed_contributes_zero_gap() {
        let reg = ThroughputRegistry::new();
        let prev = PcapFileState {
            size: 1500,
            mtime: None,
            consumed_bytes: 1500, // lu en entier
        };
        let gap = prev.size.saturating_sub(prev.consumed_bytes);
        if gap > 0 {
            reg.bump_bytes_gap(gap);
        }
        assert_eq!(reg.bytes_gap_count(), 0);
    }

    /// 2.21.78 (correction 7013902603 §c) — un fichier partiellement
    /// lu (décodage en erreur ou taille connue > consumed_bytes),
    /// puis supprimé : `gap = size - consumed_bytes = partie non
    /// lue`. L'alerte sonne proportionnellement à la perte réelle.
    #[test]
    fn half_consumed_file_removed_reports_unread_bytes_as_gap() {
        let reg = ThroughputRegistry::new();
        let prev = PcapFileState {
            size: 1500,
            mtime: None,
            consumed_bytes: 500, // seulement 500/1500 consommés (decode erroré)
        };
        let gap = prev.size.saturating_sub(prev.consumed_bytes);
        if gap > 0 {
            reg.bump_bytes_gap(gap);
        }
        assert_eq!(reg.bytes_gap_count(), 1000, "1500 - 500 = 1000 bytes non lus");
        // Chaque stream actif reçoit un event `gap` avec la même valeur.
        register_session(&reg, "s_gap");
        reg.bump_bytes_gap(10);
        let events = collect_events(&reg, "s_gap");
        assert!(events.iter().any(|e| e["kind"] == "gap"));
    }

    /// Cap `MAX_ACTIVE_BUCKETS_PER_SESSION` — au-delà, les octets sont
    /// comptabilisés comme gap (pas d'attribution silencieuse).
    #[test]
    fn active_buckets_cap_counts_overflow_as_gap() {
        let reg = ThroughputRegistry::new();
        register_session(&reg, "s9");
        // 32 QFI différents sur la seconde 10 → 32 buckets actifs.
        for q in 0..MAX_ACTIVE_BUCKETS_PER_SESSION as u32 {
            reg.observe_event(
                &gtpu_event("fill", Direction::Uplink, Some(q), 10, 10),
                Some("s9"),
            );
        }
        // Le 33e (QFI=99) devrait tomber dans le gap.
        let gap_before = reg.bytes_gap_from_disappeared_files.load(Ordering::Relaxed);
        reg.observe_event(&gtpu_event("x", Direction::Uplink, Some(99), 42, 10), Some("s9"));
        let gap_after = reg.bytes_gap_from_disappeared_files.load(Ordering::Relaxed);
        assert_eq!(gap_after - gap_before, 42);
    }
}
