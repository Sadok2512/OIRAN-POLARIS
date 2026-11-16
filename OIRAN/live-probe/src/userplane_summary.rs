//! 2.22.3 — agrégateur `UserPlaneSummary` : 1 record par PDU session, fermé
//! sur événement (PFCP Session Deletion / NGAP PDU Session Resource Release
//! / inactivité), avec éviction LRU bornée par la mémoire (correction C2
//! #9 6927882355).
//!
//! # Fermeture sur événement — pas en fin de fichier
//!
//! Le `N3FlowAggregator` existant émet au `finish()` — sémantique « fin de
//! capture ». En flux continu PRO 400G, cette sémantique ne passe pas à
//! l'échelle. L'agrégateur `UserPlaneSummaryAggregator` ferme un record
//! sur l'un des 3 événements suivants :
//!
//! 1. **PFCP Session Deletion Request / Response** (plan de contrôle N4) ;
//! 2. **NGAP PDU Session Resource Release Command / Response** (N2) ;
//! 3. **Inactivité** : plus de G-PDU observée depuis `inactivity_timeout_ns`
//!    nanosecondes (défaut 300 s, configurable `polaris.toml [userplane]`).
//!
//! # Éviction LRU
//!
//! Si le nombre d'entrées actives dépasse `max_summaries`, l'entrée **la
//! plus ancienne** (par `last_seen_ns`) est évincée. L'event émis porte
//! `message_name = "UserPlane Summary (evicted)"` avec IE
//! `evicted_reason = "memory_pressure"`. **Jamais** d'erreur bloquante.
//!
//! # Identification
//!
//! Clé interne : `(subscriber_pseudonym, pdu_session_id)`. Si l'index ne
//! résout aucun des deux, fallback sur `(teid_ul, teid_dl)` — un record est
//! quand même émis mais sans pseudonym (observable sur ANR2 lab si le SBI
//! n'est pas capturé).

use std::collections::BTreeMap;

use event_schema::{
    sha256_hex, DecodeStatus, Direction, EvidenceReference, EvidenceState, InformationElement,
    NamedValue, NormalizedEvent, PacketReference, Protocol,
};

use crate::userplane_index::{SourceKind, UserplaneIndex, UserplaneIndexEntry};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Configuration de l'agrégateur ; alimentée depuis `polaris.toml
/// [userplane]` au câblage 2.22.4.
#[derive(Clone, Copy, Debug)]
pub struct UserPlaneSummaryConfig {
    /// Timeout d'inactivité en nanosecondes. Défaut 300 s.
    pub inactivity_timeout_ns: i128,
    /// Nombre maximum d'entrées actives simultanément. Au-delà, LRU
    /// éviction. Défaut 4096.
    pub max_summaries: usize,
}

impl Default for UserPlaneSummaryConfig {
    fn default() -> Self {
        Self {
            inactivity_timeout_ns: 300_000_000_000, // 300 s
            max_summaries: 4096,
        }
    }
}

/// Clé interne : `subscriber_pseudonym` ou fallback TEID canonique.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SummaryKey {
    /// Résolu via `UserplaneIndex` → identifiant stable PDU session.
    Resolved {
        subscriber_pseudonym: String,
        pdu_session_id: u8,
    },
    /// Fallback : TEID canonique (UL en premier si connu, sinon DL).
    /// Évite de perdre un record quand l'index n'a pas encore vu le SBI.
    TeidFallback { teid_hex: String },
}

/// État interne d'un record en cours d'agrégation.
#[derive(Clone, Debug)]
struct Summary {
    key: SummaryKey,
    subscriber_pseudonym: Option<String>,
    subscriber_pseudonym_source: Option<SourceKind>,
    pdu_session_id: Option<u8>,
    teid_ul: Option<u32>,
    teid_dl: Option<u32>,
    seid_smf: Option<u64>,
    seid_upf: Option<u64>,
    qfi: Option<u8>,
    five_qi: Option<u16>,
    ue_ipv4: Option<String>,
    ue_ipv6: Option<String>,
    capture_id: String,
    ul_bytes: u64,
    ul_packets: u64,
    dl_bytes: u64,
    dl_packets: u64,
    first_seen_ns: i128,
    last_seen_ns: i128,
    first_packet_ul: Option<PacketReference>,
    last_packet_ul: Option<PacketReference>,
    first_packet_dl: Option<PacketReference>,
    last_packet_dl: Option<PacketReference>,
}

/// Raison de clôture d'un record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    PfcpSessionDeletion,
    NgapPduSessionResourceRelease,
    Inactivity,
    EvictedMemoryPressure,
    /// Fin de pipeline — équivalent à l'ancien `finish()`. Utile
    /// uniquement en tests ou en arrêt propre de la sonde.
    EndOfStream,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::PfcpSessionDeletion => "pfcp_session_deletion",
            CloseReason::NgapPduSessionResourceRelease => "ngap_pdu_session_resource_release",
            CloseReason::Inactivity => "inactivity_timeout",
            CloseReason::EvictedMemoryPressure => "memory_pressure",
            CloseReason::EndOfStream => "end_of_stream",
        }
    }
}

/// Agrégateur UserPlaneSummary.
pub struct UserPlaneSummaryAggregator {
    config: UserPlaneSummaryConfig,
    summaries: BTreeMap<SummaryKey, Summary>,
    pending: Vec<NormalizedEvent>,
}

impl UserPlaneSummaryAggregator {
    pub fn new(config: UserPlaneSummaryConfig) -> Self {
        Self {
            config,
            summaries: BTreeMap::new(),
            pending: Vec::new(),
        }
    }

    /// Consomme un `NormalizedEvent` émis par `N3FlowAggregator::finish()`
    /// (1 aggregate par `(message_type, teid, direction)`). Met à jour la
    /// session PDU correspondante via `UserplaneIndex`.
    pub fn observe_n3_aggregate(
        &mut self,
        aggregate: &NormalizedEvent,
        index: &UserplaneIndex,
    ) {
        if aggregate.protocol != Protocol::Gtpu || aggregate.message_type != 255 {
            return;
        }
        let teid_hex = aggregate
            .session_identifiers
            .iter()
            .find(|identifier| identifier.name == "teid")
            .map(|identifier| identifier.value.clone());
        let teid_hex = match teid_hex {
            Some(value) => value,
            None => return,
        };
        let index_entry = index.lookup(&teid_hex).cloned();
        let key = resolve_key(&teid_hex, index_entry.as_ref());
        let direction_is_ul = matches!(
            aggregate.direction,
            Direction::Uplink | Direction::RanToCore
        );
        let direction_is_dl = matches!(
            aggregate.direction,
            Direction::Downlink | Direction::CoreToRan
        );
        let packet_count = parse_u64_ie(aggregate, "aggregate_packet_count").unwrap_or(0);
        let wire_bytes = parse_u64_ie(aggregate, "aggregate_wire_bytes").unwrap_or(0);
        let first_seen_ns = parse_i128_ie(aggregate, "aggregate_first_seen_ns").unwrap_or(0);
        let last_seen_ns = parse_i128_ie(aggregate, "aggregate_last_seen_ns").unwrap_or(0);
        let first_packet = aggregate.packet_references.first().cloned();
        let last_packet = aggregate.packet_references.last().cloned().or_else(|| first_packet.clone());
        let qfi = aggregate
            .session_identifiers
            .iter()
            .find(|identifier| identifier.name == "qfi")
            .and_then(|identifier| identifier.value.parse::<u8>().ok());
        let teid_num = u32::from_str_radix(
            teid_hex
                .strip_prefix("0x")
                .or_else(|| teid_hex.strip_prefix("0X"))
                .unwrap_or(&teid_hex),
            16,
        )
        .ok();

        // Évince AVANT l'insertion si on dépasse la borne (comportement LRU).
        if !self.summaries.contains_key(&key) && self.summaries.len() >= self.config.max_summaries {
            self.evict_lru();
        }

        let summary = self.summaries.entry(key.clone()).or_insert_with(|| Summary {
            key: key.clone(),
            subscriber_pseudonym: index_entry
                .as_ref()
                .and_then(|entry| entry.subscriber_pseudonym.clone()),
            subscriber_pseudonym_source: index_entry
                .as_ref()
                .and_then(|entry| entry.subscriber_pseudonym_source),
            pdu_session_id: index_entry
                .as_ref()
                .and_then(|entry| entry.pdu_session_id),
            teid_ul: index_entry.as_ref().and_then(|entry| entry.teid_ul),
            teid_dl: index_entry.as_ref().and_then(|entry| entry.teid_dl),
            seid_smf: index_entry.as_ref().and_then(|entry| entry.seid_smf),
            seid_upf: index_entry.as_ref().and_then(|entry| entry.seid_upf),
            qfi: index_entry.as_ref().and_then(|entry| entry.qfi),
            five_qi: index_entry.as_ref().and_then(|entry| entry.five_qi),
            ue_ipv4: index_entry.as_ref().and_then(|entry| entry.ue_ipv4.clone()),
            ue_ipv6: index_entry.as_ref().and_then(|entry| entry.ue_ipv6.clone()),
            capture_id: aggregate.capture_id.clone(),
            ul_bytes: 0,
            ul_packets: 0,
            dl_bytes: 0,
            dl_packets: 0,
            first_seen_ns,
            last_seen_ns,
            first_packet_ul: None,
            last_packet_ul: None,
            first_packet_dl: None,
            last_packet_dl: None,
        });
        if summary.qfi.is_none() {
            summary.qfi = qfi;
        }
        if first_seen_ns != 0 && (summary.first_seen_ns == 0 || first_seen_ns < summary.first_seen_ns) {
            summary.first_seen_ns = first_seen_ns;
        }
        if last_seen_ns > summary.last_seen_ns {
            summary.last_seen_ns = last_seen_ns;
        }
        if direction_is_ul {
            summary.ul_bytes = summary.ul_bytes.saturating_add(wire_bytes);
            summary.ul_packets = summary.ul_packets.saturating_add(packet_count);
            if summary.first_packet_ul.is_none() {
                summary.first_packet_ul = first_packet.clone();
            }
            summary.last_packet_ul = last_packet.clone().or(summary.last_packet_ul.take());
            if summary.teid_ul.is_none() {
                summary.teid_ul = teid_num;
            }
        } else if direction_is_dl {
            summary.dl_bytes = summary.dl_bytes.saturating_add(wire_bytes);
            summary.dl_packets = summary.dl_packets.saturating_add(packet_count);
            if summary.first_packet_dl.is_none() {
                summary.first_packet_dl = first_packet.clone();
            }
            summary.last_packet_dl = last_packet.clone().or(summary.last_packet_dl.take());
            if summary.teid_dl.is_none() {
                summary.teid_dl = teid_num;
            }
        }
    }

    /// Détecte un event de contrôle qui ferme une session (PFCP Session
    /// Deletion ou NGAP PDU Session Resource Release). Renvoie `true` si
    /// l'event a déclenché une fermeture.
    pub fn observe_close_event(
        &mut self,
        event: &NormalizedEvent,
        index: &UserplaneIndex,
    ) -> bool {
        let reason = classify_close(event);
        let Some(reason) = reason else {
            return false;
        };
        // Les events de contrôle portent typiquement un `teid` (PFCP F-TEID,
        // NGAP GTP-U TEID). On ferme toutes les entrées qui matchent ce TEID
        // ou pdu_session_id.
        let mut matched = Vec::new();
        let teid_hex = event
            .session_identifiers
            .iter()
            .find(|identifier| identifier.name == "teid" || identifier.name == "gtp_teid")
            .map(|identifier| identifier.value.clone())
            .map(|value| canonical_teid(&value));
        let pdu_session_id = event
            .session_identifiers
            .iter()
            .find(|identifier| identifier.name == "pdu_session_id")
            .and_then(|identifier| identifier.value.parse::<u8>().ok());

        for (key, summary) in self.summaries.iter() {
            let mut hit = false;
            if let Some(teid) = &teid_hex {
                let teid_ul = summary.teid_ul.map(|t| format!("0x{t:08x}"));
                let teid_dl = summary.teid_dl.map(|t| format!("0x{t:08x}"));
                if teid_ul.as_deref() == Some(teid.as_str())
                    || teid_dl.as_deref() == Some(teid.as_str())
                {
                    hit = true;
                }
                if let SummaryKey::TeidFallback { teid_hex: stored } = &summary.key {
                    if stored == teid {
                        hit = true;
                    }
                }
            }
            if let (Some(wanted), Some(stored)) = (pdu_session_id, summary.pdu_session_id) {
                if wanted == stored {
                    hit = true;
                }
            }
            if hit {
                matched.push(key.clone());
            }
        }
        let fired = !matched.is_empty();
        for key in matched {
            if let Some(summary) = self.summaries.remove(&key) {
                self.pending.push(render_summary(summary, reason));
            }
        }
        let _ = index; // réservé pour résolution future (SUPI depuis NAS release)
        fired
    }

    /// Ferme toutes les entrées inactives depuis `now_ns -
    /// inactivity_timeout_ns`. Retourne le nombre d'entrées fermées.
    pub fn tick_inactivity(&mut self, now_ns: i128) -> usize {
        let timeout = self.config.inactivity_timeout_ns;
        let to_close: Vec<SummaryKey> = self
            .summaries
            .iter()
            .filter(|(_, summary)| {
                summary.last_seen_ns != 0 && (now_ns - summary.last_seen_ns) >= timeout
            })
            .map(|(key, _)| key.clone())
            .collect();
        let count = to_close.len();
        for key in to_close {
            if let Some(summary) = self.summaries.remove(&key) {
                self.pending.push(render_summary(summary, CloseReason::Inactivity));
            }
        }
        count
    }

    /// Ferme la session la plus ancienne (plus petit `last_seen_ns`)
    /// avec raison `EvictedMemoryPressure`.
    fn evict_lru(&mut self) {
        let victim = self
            .summaries
            .iter()
            .min_by_key(|(_, summary)| summary.last_seen_ns)
            .map(|(key, _)| key.clone());
        if let Some(key) = victim {
            if let Some(summary) = self.summaries.remove(&key) {
                self.pending
                    .push(render_summary(summary, CloseReason::EvictedMemoryPressure));
            }
        }
    }

    /// Ferme toutes les entrées encore ouvertes avec `EndOfStream` (utile
    /// à l'arrêt propre d'un `process_capture_into_selected` en tests).
    pub fn finish(&mut self) {
        let keys: Vec<SummaryKey> = self.summaries.keys().cloned().collect();
        for key in keys {
            if let Some(summary) = self.summaries.remove(&key) {
                self.pending
                    .push(render_summary(summary, CloseReason::EndOfStream));
            }
        }
    }

    /// Vide la file d'events prêts à être écrits sur le spool.
    pub fn drain(&mut self) -> Vec<NormalizedEvent> {
        std::mem::take(&mut self.pending)
    }

    pub fn active_count(&self) -> usize {
        self.summaries.len()
    }
}

fn resolve_key(teid_hex: &str, index_entry: Option<&UserplaneIndexEntry>) -> SummaryKey {
    if let Some(entry) = index_entry {
        if let (Some(pseudonym), Some(pdu_session_id)) =
            (entry.subscriber_pseudonym.as_ref(), entry.pdu_session_id)
        {
            return SummaryKey::Resolved {
                subscriber_pseudonym: pseudonym.clone(),
                pdu_session_id,
            };
        }
    }
    SummaryKey::TeidFallback {
        teid_hex: canonical_teid(teid_hex),
    }
}

fn canonical_teid(value: &str) -> String {
    let trimmed = value.trim();
    if let Some(stripped) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        if let Ok(n) = u64::from_str_radix(stripped, 16) {
            return format!("0x{:08x}", n & 0xffff_ffff);
        }
    }
    if let Ok(n) = trimmed.parse::<u64>() {
        return format!("0x{:08x}", n & 0xffff_ffff);
    }
    trimmed.to_ascii_lowercase()
}

fn classify_close(event: &NormalizedEvent) -> Option<CloseReason> {
    let name = event.message_name.as_str();
    match event.protocol {
        Protocol::Pfcp => {
            if name.contains("Session Deletion") {
                Some(CloseReason::PfcpSessionDeletion)
            } else {
                None
            }
        }
        Protocol::Ngap => {
            if name.contains("PDUSessionResourceRelease")
                || name.contains("PDU Session Resource Release")
            {
                Some(CloseReason::NgapPduSessionResourceRelease)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn parse_u64_ie(event: &NormalizedEvent, name: &str) -> Option<u64> {
    event
        .information_elements
        .iter()
        .find(|element| element.name == name)
        .and_then(|element| element.value.as_deref())
        .and_then(|value| value.parse().ok())
}

fn parse_i128_ie(event: &NormalizedEvent, name: &str) -> Option<i128> {
    event
        .information_elements
        .iter()
        .find(|element| element.name == name)
        .and_then(|element| element.value.as_deref())
        .and_then(|value| value.parse().ok())
}

fn render_summary(summary: Summary, reason: CloseReason) -> NormalizedEvent {
    let mut identifiers = Vec::new();
    let mut push_id = |name: &str, value: String, pseudonymized: bool| {
        identifiers.push(NamedValue {
            name: name.into(),
            value,
            pseudonymized,
        });
    };
    if let Some(pseudonym) = &summary.subscriber_pseudonym {
        push_id("subscriber_pseudonym", pseudonym.clone(), true);
    }
    if let Some(source) = summary.subscriber_pseudonym_source {
        push_id("subscriber_pseudonym_source", source.as_str().into(), false);
    }
    if let Some(pdu_session_id) = summary.pdu_session_id {
        push_id("pdu_session_id", pdu_session_id.to_string(), false);
    }
    if let Some(teid_ul) = summary.teid_ul {
        push_id("teid_ul", format!("0x{teid_ul:08x}"), false);
    }
    if let Some(teid_dl) = summary.teid_dl {
        push_id("teid_dl", format!("0x{teid_dl:08x}"), false);
    }
    if let Some(seid) = summary.seid_smf {
        push_id("seid_smf", format!("0x{seid:016x}"), false);
    }
    if let Some(seid) = summary.seid_upf {
        push_id("seid_upf", format!("0x{seid:016x}"), false);
    }
    if let Some(qfi) = summary.qfi {
        push_id("qfi", qfi.to_string(), false);
    }
    if let Some(five_qi) = summary.five_qi {
        push_id("five_qi", five_qi.to_string(), false);
    }
    if let Some(ip) = summary.ue_ipv4 {
        push_id("ue_ipv4", ip, true);
    }
    if let Some(ip) = summary.ue_ipv6 {
        push_id("ue_ipv6", ip, true);
    }
    let duration_ns = if summary.last_seen_ns >= summary.first_seen_ns {
        summary.last_seen_ns - summary.first_seen_ns
    } else {
        0
    };
    let information_elements = vec![
        ie("ul_bytes", summary.ul_bytes.to_string()),
        ie("ul_packets", summary.ul_packets.to_string()),
        ie("dl_bytes", summary.dl_bytes.to_string()),
        ie("dl_packets", summary.dl_packets.to_string()),
        ie("first_seen_ns", summary.first_seen_ns.to_string()),
        ie("last_seen_ns", summary.last_seen_ns.to_string()),
        ie("duration_ns", duration_ns.to_string()),
        ie("closed_reason", reason.as_str().into()),
    ];
    let mut packet_references = Vec::new();
    for packet in [
        summary.first_packet_ul,
        summary.last_packet_ul,
        summary.first_packet_dl,
        summary.last_packet_dl,
    ]
    .into_iter()
    .flatten()
    {
        if !packet_references
            .iter()
            .any(|existing: &PacketReference| existing.packet_number == packet.packet_number)
        {
            packet_references.push(packet);
        }
    }
    let evidence_references = packet_references
        .iter()
        .map(|packet| EvidenceReference {
            state: EvidenceState::Exact,
            kind: "packet-provenance".into(),
            reference: format!("{}#packet-{}", packet.source_file, packet.packet_number),
        })
        .collect();
    let timestamp = event_schema::ExactTimestamp {
        seconds: (summary.last_seen_ns / 1_000_000_000) as i64,
        nanoseconds: (summary.last_seen_ns % 1_000_000_000).unsigned_abs() as u32,
        raw_ticks: summary.last_seen_ns.unsigned_abs() as u64,
        resolution_base: 10,
        resolution_exponent: 9,
    };
    let (teid_for_ref, first_pn, last_pn) = (
        summary
            .teid_ul
            .or(summary.teid_dl)
            .map(|t| format!("0x{t:08x}"))
            .unwrap_or_else(|| "unknown".into()),
        packet_references
            .first()
            .map(|packet| packet.packet_number)
            .unwrap_or(0),
        packet_references
            .last()
            .map(|packet| packet.packet_number)
            .unwrap_or(0),
    );
    let raw_payload_reference = format!(
        "userplane-summary:{}:{}:{}-{}",
        summary.capture_id, teid_for_ref, first_pn, last_pn
    );
    let message_name = match reason {
        CloseReason::EvictedMemoryPressure => "UserPlane Summary (evicted)",
        _ => "UserPlane Summary (aggregated)",
    };
    let mut event = NormalizedEvent {
        event_id: String::new(),
        parent_event_id: None,
        probe_id: "oiran-vprobe-local-01".into(),
        capture_point_id: "N3".into(),
        capture_id: summary.capture_id,
        packet_references,
        timestamp,
        interface: "N3".into(),
        protocol: Protocol::Gtpu,
        message_name: message_name.into(),
        message_type: 255,
        procedure_code: None,
        procedure: None,
        security_state: None,
        source_byte_offset: None,
        source_endpoint: event_schema::Endpoint {
            address: String::new(),
            port: None,
            network_function: None,
        },
        destination_endpoint: event_schema::Endpoint {
            address: String::new(),
            port: None,
            network_function: None,
        },
        direction: Direction::Unknown,
        session_identifiers: identifiers,
        information_elements,
        decoder_name: "live-probe-userplane-summary-aggregator".into(),
        decoder_version: VERSION.into(),
        schema_version: NormalizedEvent::SCHEMA_VERSION,
        decoding_status: DecodeStatus::Decoded,
        errors: Vec::new(),
        raw_payload_reference: raw_payload_reference.clone(),
        evidence_references,
        sbi: None,
    };
    let _ = sha256_hex; // réservé pour le lot 2.22.4 bucket hashing
    event.assign_deterministic_id();
    event
}

fn ie(name: &str, value: String) -> InformationElement {
    InformationElement {
        id: None,
        name: name.into(),
        length: 0,
        value: Some(value),
        raw_sha256: None,
        status: DecodeStatus::Decoded,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{DecodeStatus, Direction, Endpoint, ExactTimestamp, PacketReference};

    fn n3_aggregate(
        teid_hex: &str,
        direction: Direction,
        packet_count: u64,
        wire_bytes: u64,
        first_ns: i128,
        last_ns: i128,
        packet_numbers: (u64, u64),
    ) -> NormalizedEvent {
        NormalizedEvent {
            event_id: format!("agg-{teid_hex}-{}", direction.as_str()),
            parent_event_id: None,
            probe_id: "oiran-vprobe-local-01".into(),
            capture_point_id: "N3".into(),
            capture_id: "sha256:lab-ue201".into(),
            packet_references: vec![
                PacketReference {
                    source_file: "n3.pcapng".into(),
                    source_sha256: None,
                    packet_number: packet_numbers.0,
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
                    captured_length: 128,
                    original_length: 1500,
                },
                PacketReference {
                    source_file: "n3.pcapng".into(),
                    source_sha256: None,
                    packet_number: packet_numbers.1,
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
                    captured_length: 128,
                    original_length: 1500,
                },
            ],
            timestamp: ExactTimestamp {
                seconds: 1,
                nanoseconds: 0,
                raw_ticks: 1,
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
                address: "10.77.14.13".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.77.14.15".into(),
                port: None,
                network_function: None,
            },
            direction,
            session_identifiers: vec![NamedValue {
                name: "teid".into(),
                value: teid_hex.into(),
                pseudonymized: false,
            }],
            information_elements: vec![
                ie("aggregate_packet_count", packet_count.to_string()),
                ie("aggregate_wire_bytes", wire_bytes.to_string()),
                ie("aggregate_first_seen_ns", first_ns.to_string()),
                ie("aggregate_last_seen_ns", last_ns.to_string()),
            ],
            decoder_name: "live-probe-n3-flow-aggregator".into(),
            decoder_version: "0.6.6".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:agg".into(),
            evidence_references: vec![],
            sbi: None,
        }
    }

    fn seed_index_for_ue201() -> UserplaneIndex {
        use crate::userplane_index::UserplaneIndex;
        let mut index = UserplaneIndex::new();
        let sbi = NormalizedEvent {
            event_id: "sbi".into(),
            parent_event_id: None,
            probe_id: "p".into(),
            capture_point_id: "SBI".into(),
            capture_id: "sha256:sbi".into(),
            packet_references: vec![],
            timestamp: ExactTimestamp {
                seconds: 1,
                nanoseconds: 0,
                raw_ticks: 1,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "SBI".into(),
            protocol: Protocol::SbiHttp2,
            message_name: "Nsmf_PDUSession CreateSMContext".into(),
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
            direction: Direction::Unknown,
            session_identifiers: vec![
                NamedValue {
                    name: "teid".into(),
                    value: "0x000096a8".into(),
                    pseudonymized: false,
                },
                NamedValue {
                    name: "subscriber_pseudonym".into(),
                    value: "sha256:pseudo-ue201".into(),
                    pseudonymized: true,
                },
                NamedValue {
                    name: "pdu_session_id".into(),
                    value: "1".into(),
                    pseudonymized: false,
                },
            ],
            information_elements: vec![],
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:sbi".into(),
            evidence_references: vec![],
            sbi: None,
        };
        index.observe(&sbi);
        index
    }

    #[test]
    fn ue201_scenario_5_ul_5_dl_collapsed_into_one_user_plane_summary_650_650() {
        let index = seed_index_for_ue201();
        let mut aggregator = UserPlaneSummaryAggregator::new(UserPlaneSummaryConfig::default());
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000096a8", Direction::Uplink, 5, 7500, 1_000, 5_000, (1, 5)),
            &index,
        );
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000096a8", Direction::Downlink, 5, 7500, 1_200, 5_200, (6, 10)),
            &index,
        );
        assert_eq!(aggregator.active_count(), 1, "1 record par PDU session");
        aggregator.finish();
        let events = aggregator.drain();
        assert_eq!(events.len(), 1);
        let summary = &events[0];
        let ie_value = |name: &str| -> Option<String> {
            summary
                .information_elements
                .iter()
                .find(|element| element.name == name)
                .and_then(|element| element.value.clone())
        };
        assert_eq!(ie_value("ul_bytes").as_deref(), Some("7500"));
        assert_eq!(ie_value("ul_packets").as_deref(), Some("5"));
        assert_eq!(ie_value("dl_bytes").as_deref(), Some("7500"));
        assert_eq!(ie_value("dl_packets").as_deref(), Some("5"));
        let id_value = |name: &str| -> Option<String> {
            summary
                .session_identifiers
                .iter()
                .find(|identifier| identifier.name == name)
                .map(|identifier| identifier.value.clone())
        };
        assert_eq!(
            id_value("subscriber_pseudonym").as_deref(),
            Some("sha256:pseudo-ue201")
        );
        assert_eq!(id_value("pdu_session_id").as_deref(), Some("1"));
    }

    #[test]
    fn pfcp_session_deletion_closes_summary_and_emits_closed_reason() {
        let index = seed_index_for_ue201();
        let mut aggregator = UserPlaneSummaryAggregator::new(UserPlaneSummaryConfig::default());
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000096a8", Direction::Uplink, 5, 7500, 1_000, 5_000, (1, 5)),
            &index,
        );
        let delete = NormalizedEvent {
            event_id: "del".into(),
            parent_event_id: None,
            probe_id: "p".into(),
            capture_point_id: "N4".into(),
            capture_id: "sha256:n4".into(),
            packet_references: vec![],
            timestamp: ExactTimestamp {
                seconds: 2,
                nanoseconds: 0,
                raw_ticks: 2,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N4".into(),
            protocol: Protocol::Pfcp,
            message_name: "PFCP Session Deletion Request".into(),
            message_type: 54,
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
            session_identifiers: vec![NamedValue {
                name: "pdu_session_id".into(),
                value: "1".into(),
                pseudonymized: false,
            }],
            information_elements: vec![],
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:del".into(),
            evidence_references: vec![],
            sbi: None,
        };
        let fired = aggregator.observe_close_event(&delete, &index);
        assert!(fired, "la session doit être trouvée et fermée");
        assert_eq!(aggregator.active_count(), 0);
        let events = aggregator.drain();
        assert_eq!(events.len(), 1);
        let closed_reason = events[0]
            .information_elements
            .iter()
            .find(|element| element.name == "closed_reason")
            .and_then(|element| element.value.as_deref());
        assert_eq!(closed_reason, Some("pfcp_session_deletion"));
    }

    #[test]
    fn inactivity_tick_closes_stale_summaries() {
        let index = seed_index_for_ue201();
        let config = UserPlaneSummaryConfig {
            inactivity_timeout_ns: 100,
            max_summaries: 4096,
        };
        let mut aggregator = UserPlaneSummaryAggregator::new(config);
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000096a8", Direction::Uplink, 1, 1500, 10, 20, (1, 1)),
            &index,
        );
        assert_eq!(aggregator.tick_inactivity(50), 0, "pas encore expiré");
        assert_eq!(aggregator.tick_inactivity(200), 1, "expiré → fermeture");
        let events = aggregator.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .information_elements
                .iter()
                .find(|element| element.name == "closed_reason")
                .and_then(|element| element.value.as_deref()),
            Some("inactivity_timeout")
        );
    }

    #[test]
    fn lru_eviction_closes_oldest_summary_as_memory_pressure_never_panics() {
        let index = seed_index_for_ue201();
        let config = UserPlaneSummaryConfig {
            inactivity_timeout_ns: 3_600_000_000_000,
            max_summaries: 2,
        };
        let mut aggregator = UserPlaneSummaryAggregator::new(config);
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000096a8", Direction::Uplink, 1, 1500, 100, 200, (1, 1)),
            &index,
        );
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x00000003", Direction::Downlink, 1, 1500, 300, 400, (2, 2)),
            &index,
        );
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000000ff", Direction::Uplink, 1, 1500, 500, 600, (3, 3)),
            &index,
        );
        // 3 sessions mais limit = 2 : la 1ʳᵉ (last_seen=200) est évincée.
        assert_eq!(aggregator.active_count(), 2);
        let events = aggregator.drain();
        assert_eq!(events.len(), 1, "exactement 1 éviction");
        let reason = events[0]
            .information_elements
            .iter()
            .find(|element| element.name == "closed_reason")
            .and_then(|element| element.value.as_deref());
        assert_eq!(reason, Some("memory_pressure"));
        assert_eq!(events[0].message_name, "UserPlane Summary (evicted)");
    }

    #[test]
    fn ngap_pdu_session_resource_release_also_closes_summary() {
        let index = seed_index_for_ue201();
        let mut aggregator = UserPlaneSummaryAggregator::new(UserPlaneSummaryConfig::default());
        aggregator.observe_n3_aggregate(
            &n3_aggregate("0x000096a8", Direction::Uplink, 5, 7500, 1_000, 5_000, (1, 5)),
            &index,
        );
        let release = NormalizedEvent {
            event_id: "rel".into(),
            parent_event_id: None,
            probe_id: "p".into(),
            capture_point_id: "N2".into(),
            capture_id: "sha256:n2".into(),
            packet_references: vec![],
            timestamp: ExactTimestamp {
                seconds: 2,
                nanoseconds: 0,
                raw_ticks: 2,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N2".into(),
            protocol: Protocol::Ngap,
            message_name: "PDUSessionResourceReleaseCommand".into(),
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
            direction: Direction::Unknown,
            session_identifiers: vec![NamedValue {
                name: "pdu_session_id".into(),
                value: "1".into(),
                pseudonymized: false,
            }],
            information_elements: vec![],
            decoder_name: "test".into(),
            decoder_version: "0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:rel".into(),
            evidence_references: vec![],
            sbi: None,
        };
        assert!(aggregator.observe_close_event(&release, &index));
        let events = aggregator.drain();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]
                .information_elements
                .iter()
                .find(|element| element.name == "closed_reason")
                .and_then(|element| element.value.as_deref()),
            Some("ngap_pdu_session_resource_release")
        );
    }
}
