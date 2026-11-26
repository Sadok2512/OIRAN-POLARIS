//! RTP / RTCP decoder (RFC 3550) as a **flow aggregator**.
//!
//! # Contract — jamais un event par paquet
//!
//! Le brief 2.11.0 l'écrit explicitement : « agrégation par flux
//! (SSRC, nb paquets, pertes, jitter), **jamais 1 événement par
//! paquet** ». Ce crate N'IMPLÉMENTE PAS `ProtocolDecoder` (qui
//! retournerait 1 event par appel) — il expose un
//! `RtpFlowAggregator` stateful, nourri par `observe_rtp(...)` ou
//! `observe_rtcp(...)` à chaque paquet observé, et qui produit UN
//! event par `(ssrc, direction)` au `finish()`.
//!
//! # Détection des flux
//!
//! L'agrégateur tient une table `(ip, port) → Call-ID` nourrie par
//! l'observation des SDP SIP (voir `register_sdp_flow`). Un
//! paquet UDP dont `source_endpoint` OU `destination_endpoint`
//! correspond à un `(ip, port)` enregistré est accepté comme RTP
//! du flux ; sinon il est ignoré silencieusement (pas un event
//! MALFORMED — un paquet UDP arbitraire sur le plan IMS ou N3 n'est
//! pas RTP par défaut).
//!
//! # Métriques par flux (RFC 3550 §A.3, §A.8)
//!
//! * `packets` — nombre de paquets RTP observés.
//! * `loss` — `(seq_max - seq_min + 1) - packets` (bornée ≥ 0 pour
//!   gérer les wraparounds u16).
//! * `jitter_ns` — estimé via `J(i) = J(i-1) + (|D(i-1, i)| -
//!   J(i-1)) / 16` avec `D(i-1, i) = (R(i) - R(i-1)) - (S(i) -
//!   S(i-1))` (RFC 3550 §6.4.1) ; `R` horloge d'arrivée en
//!   nanosecondes, `S` timestamp RTP.
//! * `codec_payload_type` — PT du premier paquet observé.

use event_schema::{
    DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState, ExactTimestamp,
    InformationElement, NamedValue, NormalizedEvent, PacketReference, Protocol,
};
use std::collections::BTreeMap;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: &str = "IETF RFC 3550 + RFC 4566";

/// Clé canonique d'un flux RTP. Un flux = une direction `(src, dst)` +
/// SSRC. Les deux directions d'un même appel ont deux SSRC distincts
/// (RFC 3550 §3) → deux events agrégés.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct FlowKey {
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub ssrc: u32,
}

#[derive(Clone, Debug, Default)]
struct FlowState {
    packets: u64,
    rtcp_packets: u64,
    rtcp_sr_count: u64,
    rtcp_rr_count: u64,
    first_seq: Option<u16>,
    last_seq: Option<u16>,
    seq_wraps: u32,
    first_timestamp: Option<u32>,
    last_timestamp: Option<u32>,
    last_arrival_ns: Option<u64>,
    /// 2.21.79 — accumulateur de jitter EN TICKS RTP (unité
    /// de l'horloge d'échantillonnage, pas des ns locaux). `None` tant
    /// qu'aucun `clock_rate_hz` n'est connu (PT dynamique sans
    /// `a=rtpmap`), auquel cas on ne calcule pas de jitter.
    jitter_rtp_ticks: Option<u64>,
    /// 2.21.79 — horloge d'échantillonnage du flux, soit lue dans la
    /// table statique PT (RFC 3551 §6) pour PT 0..=34, soit transmise
    /// par le SDP `a=rtpmap` pour les PT dynamiques (96..=127).
    clock_rate_hz: Option<u32>,
    /// 2.21.79 — raison pour laquelle `jitter_ns` sortira `null` quand
    /// `clock_rate_hz` est inconnu, émise en IE pour que l'opérateur
    /// voie pourquoi le flux n'a pas de jitter chiffré.
    jitter_unknown_reason: Option<String>,
    payload_type: Option<u8>,
    call_id: Option<String>,
    first_packet_reference: Option<PacketReference>,
    first_seen: Option<ExactTimestamp>,
    last_seen: Option<ExactTimestamp>,
}

/// Association flux → Call-ID observée depuis un SDP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdpFlowRegistration {
    pub ip: String,
    pub port: u16,
    pub call_id: String,
    pub payload_type: Option<u8>,
    /// 2.21.79 — horloge d'échantillonnage lue dans
    /// `a=rtpmap:<pt> <encoding>/<clock_rate>` pour les PT dynamiques
    /// (96..=127). `None` pour les PT statiques (RFC 3551 §6) : le
    /// aggregator résoudra via `static_rtp_clock_rate_hz`.
    pub clock_rate_hz: Option<u32>,
}

/// 0.3.0 (oiran-api 2.21.131, lot B2) — `Clone` : un instantané des flux
/// en cours se calcule sur une copie, l'agrégateur continue.
#[derive(Clone)]
pub struct RtpFlowAggregator {
    flows: BTreeMap<FlowKey, FlowState>,
    /// `(ip, port) → Call-ID` — populé par `register_sdp_flow` dès qu'un
    /// `INVITE`/`200 OK` apporte un SDP.
    endpoint_to_call_id: BTreeMap<(String, u16), String>,
    endpoint_pt: BTreeMap<(String, u16), u8>,
    /// 2.21.79 — `(ip, port) → clock_rate_hz` apporté par SDP `a=rtpmap`.
    /// Ne remplace pas la table statique PT ; les deux sources peuvent
    /// coexister, et `clock_rate_for_pt` préfère le SDP quand présent.
    endpoint_clock_rate: BTreeMap<(String, u16), u32>,
}

/// 0.3.1 — écrit une ligne dans le journal du service (sortie d'erreur).
/// En test, la ligne est aussi gardée, pour vérifier ce que le journal
/// porte.
fn journal(line: &str) {
    #[cfg(test)]
    JOURNAL.with(|lines| lines.borrow_mut().push(line.to_owned()));
    eprintln!("{line}");
}

#[cfg(test)]
thread_local! {
    static JOURNAL: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl Default for RtpFlowAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpFlowAggregator {
    pub fn new() -> Self {
        Self {
            flows: BTreeMap::new(),
            endpoint_to_call_id: BTreeMap::new(),
            endpoint_pt: BTreeMap::new(),
            endpoint_clock_rate: BTreeMap::new(),
        }
    }

    /// Enregistre un (ip, port) comme flux RTP attendu pour un Call-ID.
    /// Idempotent ; si le flux change de Call-ID, le nouveau remplace.
    pub fn register_sdp_flow(&mut self, registration: SdpFlowRegistration) {
        let SdpFlowRegistration {
            ip,
            port,
            call_id,
            payload_type,
            clock_rate_hz,
        } = registration;
        self.endpoint_to_call_id
            .insert((ip.clone(), port), call_id);
        if let Some(pt) = payload_type {
            self.endpoint_pt.insert((ip.clone(), port), pt);
        }
        if let Some(rate) = clock_rate_hz {
            self.endpoint_clock_rate.insert((ip, port), rate);
        }
    }

    /// 2.21.79 — Horloge d'échantillonnage statique RFC 3551 §6 pour les
    /// PT 0..=34. Retourne `None` pour tout PT dynamique (96..=127) et
    /// pour les PT réservés : l'appelant doit s'en remettre à
    /// `endpoint_clock_rate` (apporté par SDP `a=rtpmap`). Les valeurs
    /// sont figées par l'IANA ; ne pas les patcher à la main sans mise
    /// à jour explicite du registre.
    fn static_rtp_clock_rate_hz(payload_type: u8) -> Option<u32> {
        match payload_type {
            0 => Some(8000),     // PCMU
            3 => Some(8000),     // GSM
            4 => Some(8000),     // G723
            5 => Some(8000),     // DVI4 8 kHz
            6 => Some(16_000),   // DVI4 16 kHz
            7 => Some(8000),     // LPC
            8 => Some(8000),     // PCMA
            9 => Some(8000),     // G722 (special : sampling 16 kHz mais RTP ts à 8 kHz, RFC 3551 §4.5.2)
            10 => Some(44_100),  // L16 stereo
            11 => Some(44_100),  // L16 mono
            12 => Some(8000),    // QCELP
            13 => Some(8000),    // CN
            14 => Some(90_000),  // MPA
            15 => Some(8000),    // G728
            16 => Some(11_025),  // DVI4 11.025 kHz
            17 => Some(22_050),  // DVI4 22.05 kHz
            18 => Some(8000),    // G729
            25..=34 => Some(90_000), // CelB, JPEG, nv, H261, MPV, MP2T, H263 — vidéo 90 kHz
            _ => None,
        }
    }

    /// 2.21.79 — Résout `clock_rate_hz` pour un flux : d'abord `a=rtpmap`
    /// via SDP (fiable pour PT dynamiques), sinon table statique PT. Les
    /// deux endpoints du flux sont essayés pour trouver un rtpmap, car
    /// seul l'offerer SIP inclut le `a=rtpmap` complet dans son SDP.
    fn clock_rate_for_flow(
        &self,
        source_ip: &str,
        source_port: u16,
        destination_ip: &str,
        destination_port: u16,
        payload_type: u8,
    ) -> Option<u32> {
        self.endpoint_clock_rate
            .get(&(source_ip.to_string(), source_port))
            .copied()
            .or_else(|| {
                self.endpoint_clock_rate
                    .get(&(destination_ip.to_string(), destination_port))
                    .copied()
            })
            .or_else(|| Self::static_rtp_clock_rate_hz(payload_type))
    }

    pub fn registered_flows(&self) -> usize {
        self.endpoint_to_call_id.len()
    }

    /// Observe un paquet RTP. Retourne `true` si le paquet appartient à
    /// un flux enregistré (il a été agrégé), `false` sinon.
    ///
    /// `payload` : UDP payload entier (RTP header + payload).
    /// `arrival_ns` : horloge de capture en nanosecondes (pour le
    /// calcul de jitter).
    pub fn observe_rtp(
        &mut self,
        source_ip: &str,
        source_port: u16,
        destination_ip: &str,
        destination_port: u16,
        payload: &[u8],
        arrival_ns: u64,
        packet_reference: &PacketReference,
        timestamp: &ExactTimestamp,
    ) -> bool {
        let Some(header) = parse_rtp_header(payload) else {
            return false;
        };
        // Un paquet RTP compte comme appartenant à un flux dès qu'un de
        // ses deux endpoints est enregistré via SDP.
        let call_id = self
            .endpoint_to_call_id
            .get(&(source_ip.to_string(), source_port))
            .or_else(|| {
                self.endpoint_to_call_id
                    .get(&(destination_ip.to_string(), destination_port))
            })
            .cloned();
        if call_id.is_none() {
            return false;
        }
        let key = FlowKey {
            source_ip: source_ip.to_string(),
            source_port,
            destination_ip: destination_ip.to_string(),
            destination_port,
            ssrc: header.ssrc,
        };
        // 2.21.79 — résolution d'horloge RTP AVANT d'insérer dans l'entrée
        // flux : si aucune horloge n'est connue (PT dynamique sans
        // `a=rtpmap`), on marque le flux comme « jitter non chiffré ».
        let resolved_clock_rate = self.clock_rate_for_flow(
            source_ip,
            source_port,
            destination_ip,
            destination_port,
            header.payload_type,
        );
        let state = self.flows.entry(key).or_default();
        state.packets = state.packets.saturating_add(1);
        state.call_id = call_id;
        if state.payload_type.is_none() {
            state.payload_type = Some(header.payload_type);
        }
        if state.clock_rate_hz.is_none() {
            state.clock_rate_hz = resolved_clock_rate;
            if resolved_clock_rate.is_none() && state.jitter_unknown_reason.is_none() {
                state.jitter_unknown_reason = Some(format!(
                    "RTP clock rate inconnue pour PT {} : ni dans la table statique RFC 3551 §6 (PT 0..=34), ni dans un SDP a=rtpmap pour ce flux",
                    header.payload_type
                ));
            }
        }
        if state.first_seq.is_none() {
            state.first_seq = Some(header.sequence_number);
            state.first_timestamp = Some(header.timestamp);
            state.first_packet_reference = Some(packet_reference.clone());
            state.first_seen = Some(timestamp.clone());
        } else if let (Some(prev_seq), Some(prev_ts), Some(prev_arr)) = (
            state.last_seq,
            state.last_timestamp,
            state.last_arrival_ns,
        ) {
            // Wraparound bookkeeping.
            if header.sequence_number < prev_seq {
                state.seq_wraps = state.seq_wraps.saturating_add(1);
            }
            // 2.21.79 (CLAUDE1, ordre #9 7012275179 §1) — Jitter RFC 3550
            // §6.4.1 CALCULÉ EN TICKS RTP. `R_i - R_{i-1}` (arrivée locale,
            // en ns) est converti en ticks d'horloge RTP via
            // `r_ticks = r_delta_ns * clock_rate_hz / 1e9`. `S_i - S_{i-1}`
            // (timestamp RTP) est déjà en ticks. `D` est donc en ticks, la
            // moyenne glissante reste en ticks, et `jitter_ns` final sort
            // via `J_ticks * 1e9 / clock_rate_hz`. Si `clock_rate_hz` est
            // None : on NE CALCULE PAS, et `jitter_rtp_ticks` reste None.
            if let Some(clock_rate_hz) = state.clock_rate_hz {
                let r_delta_ns = arrival_ns.saturating_sub(prev_arr);
                // ticks = ns × clock / 1e9. Multiplication en u128 pour
                // éviter l'overflow sur r_delta_ns × clock_rate_hz quand
                // les deux sont grands (ex. gap réseau 1 s × 90 kHz).
                let r_ticks =
                    (r_delta_ns as u128).saturating_mul(clock_rate_hz as u128) / 1_000_000_000u128;
                let s_delta_ticks = header.timestamp.wrapping_sub(prev_ts) as i64;
                let r_ticks_i64 = r_ticks.min(i64::MAX as u128) as i64;
                let d_ticks = (r_ticks_i64 - s_delta_ticks).unsigned_abs();
                // Moyenne glissante en ticks : J <- J + (D - J) / 16.
                let prev_j = state.jitter_rtp_ticks.unwrap_or(0) as i64;
                let step = (d_ticks as i64 - prev_j) / 16;
                let new_j = (prev_j + step).max(0) as u64;
                state.jitter_rtp_ticks = Some(new_j);
            }
        }
        state.last_seq = Some(header.sequence_number);
        state.last_timestamp = Some(header.timestamp);
        state.last_arrival_ns = Some(arrival_ns);
        state.last_seen = Some(timestamp.clone());
        true
    }

    /// Observe un paquet RTCP (SR/RR). Agrégé par SSRC comme RTP —
    /// mais sous une sous-catégorie séparée (rtcp_sr_count / rr_count).
    pub fn observe_rtcp(
        &mut self,
        source_ip: &str,
        source_port: u16,
        destination_ip: &str,
        destination_port: u16,
        payload: &[u8],
    ) -> bool {
        let Some(header) = parse_rtcp_header(payload) else {
            return false;
        };
        let call_id = self
            .endpoint_to_call_id
            .get(&(source_ip.to_string(), source_port))
            .or_else(|| {
                self.endpoint_to_call_id
                    .get(&(destination_ip.to_string(), destination_port))
            })
            .cloned();
        if call_id.is_none() {
            return false;
        }
        let key = FlowKey {
            source_ip: source_ip.to_string(),
            source_port,
            destination_ip: destination_ip.to_string(),
            destination_port,
            ssrc: header.ssrc,
        };
        let state = self.flows.entry(key).or_default();
        state.rtcp_packets = state.rtcp_packets.saturating_add(1);
        state.call_id = call_id;
        match header.packet_type {
            200 => state.rtcp_sr_count = state.rtcp_sr_count.saturating_add(1),
            201 => state.rtcp_rr_count = state.rtcp_rr_count.saturating_add(1),
            _ => {}
        }
        true
    }

    /// Finalise l'agrégation et émet UN event par flux. Ne jamais
    /// appeler en cours d'import — strictement à la fin d'un segment
    /// ou d'une capture.
    pub fn finish(self, capture_id: &str, interface: &str) -> Vec<NormalizedEvent> {
        let mut out = Vec::with_capacity(self.flows.len());
        for (key, state) in self.flows {
            let FlowKey {
                source_ip,
                source_port,
                destination_ip,
                destination_port,
                ssrc,
            } = key;
            let expected_packets = match (state.first_seq, state.last_seq) {
                (Some(f), Some(l)) => {
                    let base = if l >= f {
                        (l - f) as u64 + 1
                    } else {
                        (u16::MAX as u64 - f as u64) + l as u64 + 2
                    };
                    base + (state.seq_wraps as u64) * (u16::MAX as u64 + 1)
                }
                _ => state.packets,
            };
            let loss = expected_packets.saturating_sub(state.packets);
            // 2.21.100 (ordre #9 7046402022 décision b) — `loss_apparent`
            // conserve le signe. `loss` (ex-`loss_count`) reste borné ≥ 0
            // pour l'opérateur ; `loss_apparent` = `expected - observed`
            // signé rend visible une collision de SSRC ou un double
            // comptage (strictement < 0). Jamais masqué, toujours signalé.
            let expected_i128 = expected_packets as i128;
            let observed_i128 = state.packets as i128;
            let loss_apparent_i64: i64 = (expected_i128 - observed_i128)
                .clamp(i64::MIN as i128, i64::MAX as i128) as i64;
            if loss_apparent_i64 < 0 {
                // 2.21.100 (ordre #9 7046402022 décision b) — journal JSON
                // manuel pour éviter une dépendance transitoire à
                // `serde_json` depuis decoder-rtp. Tous les champs sont
                // numériques ou ASCII déjà échappés par les décodeurs amont
                // (ssrc hex, IPv4 dotted-quad, u16 ports).
// 0.3.1 (oiran-api 2.21.132, ordre #9 7059947810) — le
                // journal ne porte AUCUNE adresse : ni IP, ni port. Il
                // désigne le flux par son SSRC, dans sa capture et sur son
                // interface. Avant, les adresses source et destination
                // (l'IP de l'UE) y étaient écrites en clair, et l'instantané
                // de 2.21.131 aurait répété la ligne toutes les 5 s.
                journal(&format!(
                    "{{\"event\":\"RTP_LOSS_NEGATIVE_APPARENT\",\"capture_id\":\"{}\",\"interface\":\"{}\",\"ssrc\":\"0x{:08x}\",\"expected_packets\":{},\"observed_packets\":{},\"loss_apparent\":{},\"reason\":\"candidate_collision_or_double_count\"}}",
                    capture_id, interface, ssrc, expected_packets, state.packets, loss_apparent_i64
                ));
            }
            // 2.21.79 — conversion ticks RTP → ns pour l'émission. Si
            // l'horloge est inconnue, `jitter_ns` sort en `null` + une
            // raison `jitter_null_reason` dans l'IE suivant.
            let jitter_ns_value: Option<u64> = match (state.jitter_rtp_ticks, state.clock_rate_hz) {
                (Some(ticks), Some(rate)) if rate > 0 => {
                    Some(((ticks as u128).saturating_mul(1_000_000_000u128) / rate as u128).min(u64::MAX as u128) as u64)
                }
                _ => None,
            };
            let packet_refs = state
                .first_packet_reference
                .map(|r| vec![r])
                .unwrap_or_default();
            let timestamp = state.first_seen.unwrap_or_else(|| ExactTimestamp {
                seconds: 0,
                nanoseconds: 0,
                raw_ticks: 0,
                resolution_base: 10,
                resolution_exponent: 9,
            });
            let payload_type = state.payload_type.unwrap_or(0);
            let call_id = state.call_id.unwrap_or_default();
            let mut ies = vec![
                InformationElement {
                    id: None,
                    name: "ssrc".into(),
                    length: 4,
                    value: Some(format!("0x{:08x}", ssrc)),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "aggregate_packet_count".into(),
                    length: 8,
                    value: Some(state.packets.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "loss_count".into(),
                    length: 8,
                    value: Some(loss.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                // 2.21.100 (ordre #9 7046402022 décision b) — `loss_apparent`
                // signé en plus de `loss_count` borné. Strictement < 0 ⇒
                // collision SSRC / double comptage ; event JSON
                // `RTP_LOSS_NEGATIVE_APPARENT` journalisé.
                InformationElement {
                    id: None,
                    name: "loss_apparent".into(),
                    length: 8,
                    value: Some(loss_apparent_i64.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                // 2.21.79 — `jitter_ns` ne sort une valeur que si
                // `clock_rate_hz` est connue (table statique RFC 3551 §6
                // ou `a=rtpmap`). Sinon `value=null` + une IE
                // `jitter_null_reason` dit pourquoi. Jamais un chiffre
                // sans sens physique.
                InformationElement {
                    id: None,
                    name: "jitter_ns".into(),
                    length: 8,
                    value: jitter_ns_value.map(|v| v.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "jitter_clock_rate_hz".into(),
                    length: 4,
                    value: state.clock_rate_hz.map(|v| v.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "payload_type".into(),
                    length: 1,
                    value: Some(payload_type.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "rtcp_packets".into(),
                    length: 8,
                    value: Some(state.rtcp_packets.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "rtcp_sr_count".into(),
                    length: 8,
                    value: Some(state.rtcp_sr_count.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
                InformationElement {
                    id: None,
                    name: "rtcp_rr_count".into(),
                    length: 8,
                    value: Some(state.rtcp_rr_count.to_string()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                },
            ];
            if !call_id.is_empty() {
                ies.push(InformationElement {
                    id: None,
                    name: "sip_call_id".into(),
                    length: call_id.len() as u32,
                    value: Some(call_id.clone()),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                });
            }
            if jitter_ns_value.is_none() {
                let reason = state.jitter_unknown_reason.clone().unwrap_or_else(|| {
                    format!(
                        "jitter non chiffré : clock_rate inconnue pour PT {payload_type}"
                    )
                });
                ies.push(InformationElement {
                    id: None,
                    name: "jitter_null_reason".into(),
                    length: reason.len() as u32,
                    value: Some(reason),
                    raw_sha256: None,
                    status: DecodeStatus::Decoded,
                });
            }
            let session_identifiers: Vec<NamedValue> = if !call_id.is_empty() {
                vec![NamedValue {
                    name: "sip_call_id".into(),
                    value: call_id.clone(),
                    pseudonymized: false,
                }]
            } else {
                Vec::new()
            };
            let raw_reference = format!(
                "rtp-flow-aggregate:ssrc={:08x},src={}:{},dst={}:{},packets={}",
                ssrc, source_ip, source_port, destination_ip, destination_port, state.packets
            );
            let mut event = NormalizedEvent {
                event_id: String::new(),
                stable_event_key: String::new(),
                parent_event_id: None,
                probe_id: "oiran-vprobe-01".into(),
                capture_point_id: interface.into(),
                capture_id: capture_id.into(),
                packet_references: packet_refs,
                timestamp,
                interface: interface.into(),
                protocol: Protocol::Rtp,
                message_name: "RTP Flow".into(),
                message_type: payload_type as u32,
                procedure_code: None,
                procedure: Some("VoNR/VoLTE Media".into()),
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: source_ip,
                    port: Some(source_port),
                    network_function: Some("UE".into()),
                },
                destination_endpoint: Endpoint {
                    address: destination_ip,
                    port: Some(destination_port),
                    network_function: Some("P-CSCF".into()),
                },
                direction: Direction::Unknown,
                session_identifiers,
                information_elements: ies,
                decoder_name: "decoder-rtp".into(),
                decoder_version: VERSION.into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: Vec::new(),
                raw_payload_reference: raw_reference.clone(),
                evidence_references: vec![EvidenceReference {
                    state: EvidenceState::Exact,
                    kind: "rtp-flow-aggregate".into(),
                    reference: raw_reference,
                }],
                sbi: None,
            };
            event.assign_deterministic_id();
            out.push(event);
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpHeader {
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

/// Parse best-effort du header RTP (RFC 3550 §5.1). Retourne `None` si
/// le payload ne ressemble pas à du RTP (< 12 octets ou version ≠ 2).
pub fn parse_rtp_header(payload: &[u8]) -> Option<RtpHeader> {
    if payload.len() < 12 {
        return None;
    }
    let first = payload[0];
    let version = first >> 6;
    if version != 2 {
        return None;
    }
    let payload_type = payload[1] & 0x7f;
    // RTCP occupies 200..=204. Reject them here — handled by observe_rtcp.
    if (200..=204).contains(&payload_type) {
        return None;
    }
    let sequence_number = u16::from_be_bytes([payload[2], payload[3]]);
    let timestamp = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ssrc = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some(RtpHeader {
        payload_type,
        sequence_number,
        timestamp,
        ssrc,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtcpHeader {
    pub packet_type: u8,
    pub ssrc: u32,
}

/// Parse best-effort du header RTCP (RFC 3550 §6). Retourne `None` si
/// le payload ne ressemble pas à RTCP.
pub fn parse_rtcp_header(payload: &[u8]) -> Option<RtcpHeader> {
    if payload.len() < 8 {
        return None;
    }
    let first = payload[0];
    let version = first >> 6;
    if version != 2 {
        return None;
    }
    let packet_type = payload[1];
    if !(200..=204).contains(&packet_type) {
        return None;
    }
    let ssrc = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Some(RtcpHeader { packet_type, ssrc })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(pn: u64) -> PacketReference {
        PacketReference {
            source_file: "x.pcapng".into(),
            sctp_association: None,
            source_sha256: None,
            packet_number: pn,
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
            captured_length: 200,
            original_length: 200,
        }
    }

    fn ts(ns: u64) -> ExactTimestamp {
        ExactTimestamp {
            seconds: 0,
            nanoseconds: ns as u32,
            raw_ticks: ns,
            resolution_base: 10,
            resolution_exponent: 9,
        }
    }

    fn rtp_packet(pt: u8, seq: u16, timestamp: u32, ssrc: u32, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(12 + body.len());
        v.push(0x80);
        v.push(pt);
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&timestamp.to_be_bytes());
        v.extend_from_slice(&ssrc.to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    fn rtcp_packet(packet_type: u8, ssrc: u32) -> Vec<u8> {
        let mut v = vec![0x80, packet_type, 0, 1];
        v.extend_from_slice(&ssrc.to_be_bytes());
        v
    }

    #[test]
    fn parses_rtp_header_and_rejects_non_rtp() {
        let pkt = rtp_packet(0, 42, 100, 0xcafebabe, &[0xaa; 160]);
        let header = parse_rtp_header(&pkt).unwrap();
        assert_eq!(header.payload_type, 0);
        assert_eq!(header.sequence_number, 42);
        assert_eq!(header.timestamp, 100);
        assert_eq!(header.ssrc, 0xcafebabe);
        assert!(parse_rtp_header(&[]).is_none());
        assert!(parse_rtp_header(&[0; 11]).is_none());
        // RTCP shouldn't pass as RTP.
        let sr = rtcp_packet(200, 0xcafebabe);
        assert!(parse_rtp_header(&sr).is_none());
    }

    #[test]
    fn aggregator_never_emits_per_packet_only_per_flow() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-vonr-9f8e7d6c5b4a3210".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        for (idx, seq) in (0u16..200u16).enumerate() {
            let pkt = rtp_packet(0, seq, 100 + seq as u32 * 160, 0xdeadbeef, &[0xaa; 160]);
            let accepted = agg.observe_rtp(
                "10.0.0.1",
                40000,
                "10.0.0.2",
                49170,
                &pkt,
                1_000_000 * idx as u64,
                &pr(1 + idx as u64),
                &ts(1_000_000 * idx as u64),
            );
            assert!(accepted, "flow must be recognized (dst matches SDP)");
        }
        let events = agg.finish("sha256:cap", "IMS");
        assert_eq!(events.len(), 1, "exactly one event per flow");
        let ev = &events[0];
        assert_eq!(ev.protocol, Protocol::Rtp);
        assert!(ev.information_elements.iter().any(|ie| {
            ie.name == "aggregate_packet_count" && ie.value.as_deref() == Some("200")
        }));
        // loss = 0 since contiguous seq.
        assert!(ev.information_elements.iter().any(|ie| {
            ie.name == "loss_count" && ie.value.as_deref() == Some("0")
        }));
    }

    #[test]
    fn aggregator_detects_sequence_gaps_as_loss() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-vonr-9f8e7d6c5b4a3210".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        // Send seq 0, 1, 2, SKIP 3-4, 5, 6 → expected=7, got=5, loss=2.
        let pattern = [0u16, 1, 2, 5, 6];
        for (idx, seq) in pattern.iter().enumerate() {
            let pkt = rtp_packet(0, *seq, 100 + *seq as u32 * 160, 0xdeadbeef, &[0xaa; 160]);
            agg.observe_rtp(
                "10.0.0.1",
                40000,
                "10.0.0.2",
                49170,
                &pkt,
                1_000_000 * idx as u64,
                &pr(1 + idx as u64),
                &ts(1_000_000 * idx as u64),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        let loss_ie = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "loss_count")
            .unwrap();
        assert_eq!(loss_ie.value.as_deref(), Some("2"));
    }

    #[test]
    fn rtcp_sr_rr_counted_separately() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-vonr-9f8e7d6c5b4a3210".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        let rtp = rtp_packet(0, 0, 100, 0xdeadbeef, &[0xaa; 160]);
        agg.observe_rtp("10.0.0.1", 40000, "10.0.0.2", 49170, &rtp, 0, &pr(1), &ts(0));
        // SR for same SSRC on port 49171 (RTCP conv : port+1).
        let sr = rtcp_packet(200, 0xdeadbeef);
        let rr = rtcp_packet(201, 0xdeadbeef);
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49171,
            call_id: "cid-vonr-9f8e7d6c5b4a3210".into(),
            payload_type: None,
            clock_rate_hz: None,
        });
        agg.observe_rtcp("10.0.0.1", 40001, "10.0.0.2", 49171, &sr);
        agg.observe_rtcp("10.0.0.1", 40001, "10.0.0.2", 49171, &rr);
        let events = agg.finish("sha256:cap", "IMS");
        // Two flows (différents ports) : un RTP (port 49170), un RTCP (port 49171).
        assert_eq!(events.len(), 2, "expected RTP flow + RTCP-only flow");
        let rtcp_flow = events
            .iter()
            .find(|ev| {
                ev.information_elements
                    .iter()
                    .any(|ie| ie.name == "rtcp_sr_count" && ie.value.as_deref() == Some("1"))
            })
            .expect("rtcp sr counted");
        assert!(rtcp_flow
            .information_elements
            .iter()
            .any(|ie| ie.name == "rtcp_rr_count" && ie.value.as_deref() == Some("1")));
    }

    #[test]
    fn rejects_rtp_packets_outside_registered_flows() {
        let mut agg = RtpFlowAggregator::new();
        let pkt = rtp_packet(0, 0, 100, 0xdeadbeef, &[0xaa; 160]);
        let accepted = agg.observe_rtp(
            "10.0.0.1",
            40000,
            "10.0.0.2",
            49170,
            &pkt,
            0,
            &pr(1),
            &ts(0),
        );
        assert!(!accepted, "unregistered flows must not be aggregated");
        let events = agg.finish("sha256:cap", "IMS");
        assert!(events.is_empty());
    }

    /// 2.21.79 (CLAUDE1, ordre #9 7012275179 §1) — PT 0 (PCMU statique
    /// 8 kHz) : paquets envoyés à intervalle régulier, timestamp RTP en
    /// phase avec l'arrivée réelle → le jitter doit rester petit, pas
    /// infini comme avant 2.21.79.
    #[test]
    fn jitter_stays_small_when_rtp_and_arrival_clocks_match_pt0_pcmu() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-pt0".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        // PCMU = 8000 Hz. 1 trame audio = 20 ms = 20_000_000 ns = 160 ticks RTP.
        let frame_ns: u64 = 20_000_000;
        let frame_ticks: u32 = 160;
        for i in 0..100u16 {
            let pkt = rtp_packet(0, i, 1000 + i as u32 * frame_ticks, 0xdead, &[0xaa; 160]);
            agg.observe_rtp(
                "10.0.0.1",
                40000,
                "10.0.0.2",
                49170,
                &pkt,
                frame_ns.saturating_mul(i as u64),
                &pr(1 + i as u64),
                &ts(frame_ns.saturating_mul(i as u64)),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        let jitter_ns = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_ns")
            .unwrap()
            .value
            .as_deref()
            .expect("jitter_ns doit avoir une valeur (clock_rate connue)");
        let j: u64 = jitter_ns.parse().unwrap();
        // Horloge d'arrivée en phase parfaite avec RTP → jitter devrait
        // approcher 0. 1 ms = 1_000_000 ns de marge est généreux pour
        // couvrir le bootstrap du filtre I/16 (RFC 3550).
        assert!(j < 1_000_000, "jitter attendu ~0, obtenu {j} ns");
        let rate_ie = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_clock_rate_hz")
            .unwrap();
        assert_eq!(rate_ie.value.as_deref(), Some("8000"));
    }

    /// 2.21.79 — PT 0 (PCMU) : si on injecte un retard réseau de 10 ms
    /// toutes les 10 trames, le jitter sort de 0 et devient mesurable,
    /// EN NANOSECONDES RÉELLES (pas en unité mixte).
    #[test]
    fn jitter_rises_when_arrival_delays_despite_pcmu_pt0() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-pt0-jitter".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        let frame_ns: u64 = 20_000_000;
        let frame_ticks: u32 = 160;
        for i in 0..200u16 {
            let arrival_ns = frame_ns.saturating_mul(i as u64)
                + if i % 10 == 0 { 10_000_000 } else { 0 };
            let pkt = rtp_packet(0, i, 1000 + i as u32 * frame_ticks, 0xdead, &[0xaa; 160]);
            agg.observe_rtp(
                "10.0.0.1",
                40000,
                "10.0.0.2",
                49170,
                &pkt,
                arrival_ns,
                &pr(1 + i as u64),
                &ts(arrival_ns),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        let j: u64 = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_ns")
            .unwrap()
            .value
            .as_deref()
            .unwrap()
            .parse()
            .unwrap();
        // Retard injecté de 10 ms régulier → jitter moyen attendu de
        // l'ordre du ms. La valeur exacte dépend du filtre I/16 ;
        // on se contente d'un plancher strict > 0 et < 10 ms.
        assert!(j > 0, "jitter doit être > 0 avec gigue injectée");
        assert!(j < 10_000_000, "jitter ne doit pas exploser ({j} ns)");
    }

    /// 2.21.79 — PT dynamique 96 sans `a=rtpmap` : horloge inconnue →
    /// `jitter_ns` sort en `null` + une IE `jitter_null_reason` explique
    /// pourquoi. **Jamais une valeur fausse.**
    #[test]
    fn jitter_is_null_with_reason_when_dynamic_pt_lacks_rtpmap() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-dyn".into(),
            payload_type: Some(96),
            clock_rate_hz: None, // SDP sans a=rtpmap
        });
        for i in 0..20u16 {
            let pkt = rtp_packet(96, i, 1000 + i as u32 * 160, 0xcafe, &[0xaa; 160]);
            agg.observe_rtp(
                "10.0.0.1",
                40000,
                "10.0.0.2",
                49170,
                &pkt,
                20_000_000u64 * i as u64,
                &pr(1 + i as u64),
                &ts(20_000_000u64 * i as u64),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        let jitter_ie = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_ns")
            .unwrap();
        assert!(
            jitter_ie.value.is_none(),
            "jitter_ns doit sortir `null` sans horloge ; obtenu {:?}",
            jitter_ie.value
        );
        let reason_ie = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_null_reason")
            .expect("jitter_null_reason doit expliquer pourquoi");
        let reason = reason_ie.value.as_deref().unwrap();
        assert!(
            reason.contains("PT 96") || reason.contains("rtpmap"),
            "raison doit mentionner le PT ou rtpmap : {reason}"
        );
        let rate_ie = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_clock_rate_hz")
            .unwrap();
        assert!(rate_ie.value.is_none());
    }

    /// 2.21.79 — PT dynamique 96 avec `a=rtpmap` apportant 16 000 Hz :
    /// horloge connue → jitter calculé en ticks et converti en ns.
    #[test]
    fn jitter_computes_with_dynamic_pt_when_rtpmap_provides_clock_rate() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-dyn-rtpmap".into(),
            payload_type: Some(96),
            clock_rate_hz: Some(16_000),
        });
        // 16 kHz : 1 trame audio AMR-WB = 20 ms = 320 ticks RTP.
        let frame_ns: u64 = 20_000_000;
        let frame_ticks: u32 = 320;
        for i in 0..100u16 {
            let pkt = rtp_packet(96, i, 1000 + i as u32 * frame_ticks, 0xfeed, &[0xaa; 160]);
            agg.observe_rtp(
                "10.0.0.1",
                40000,
                "10.0.0.2",
                49170,
                &pkt,
                frame_ns.saturating_mul(i as u64),
                &pr(1 + i as u64),
                &ts(frame_ns.saturating_mul(i as u64)),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        let jitter_ie = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_ns")
            .unwrap();
        let j: u64 = jitter_ie.value.as_deref().unwrap().parse().unwrap();
        assert!(j < 1_000_000, "jitter attendu ~0, obtenu {j} ns");
        let rate_ie = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "jitter_clock_rate_hz")
            .unwrap();
        assert_eq!(rate_ie.value.as_deref(), Some("16000"));
    }

    /// 2.21.100 (défaut ANR1 V2b #10 7045290646, ordre #9 7046402022
    /// décision b) — deux flux de même SSRC mais 5-tuples distincts
    /// produisent **deux `FlowKey` séparés** (= deux events, deux pertes
    /// indépendantes). Le problème V2b observé par `tshark rtp,streams`
    /// (agrégation unique sur le SSRC seul) ne se reproduit pas côté
    /// OIRAN : la FlowKey inclut (source_ip, source_port, destination_ip,
    /// destination_port, ssrc).
    #[test]
    fn two_flows_same_ssrc_different_5tuples_are_distinct_flowkeys_2_21_100() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-ue-A".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.3".into(),
            port: 49172,
            call_id: "cid-ue-B".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        // Flux A : SSRC=0xdeadbeef, 3 paquets contigus (0,1,2), aucune perte.
        for (idx, seq) in [0u16, 1, 2].iter().enumerate() {
            let pkt = rtp_packet(0, *seq, 100 + *seq as u32 * 160, 0xdeadbeef, &[0xaa; 160]);
            agg.observe_rtp(
                "10.0.0.1", 40000, "10.0.0.2", 49170,
                &pkt, 1_000_000 * idx as u64,
                &pr(1 + idx as u64), &ts(1_000_000 * idx as u64),
            );
        }
        // Flux B : MÊME SSRC=0xdeadbeef mais 5-tuple différent, 5 paquets
        // contigus (0..4) — pas de collision, 2 FlowKey distincts.
        for (idx, seq) in [0u16, 1, 2, 3, 4].iter().enumerate() {
            let pkt = rtp_packet(0, *seq, 200 + *seq as u32 * 160, 0xdeadbeef, &[0xbb; 160]);
            agg.observe_rtp(
                "10.0.0.4", 40002, "10.0.0.3", 49172,
                &pkt, 2_000_000 * idx as u64,
                &pr(10 + idx as u64), &ts(2_000_000 * idx as u64),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        assert_eq!(events.len(), 2, "2 flux (même SSRC, 5-tuple différents) ⇒ 2 events");
        for ev in &events {
            let loss_count: i64 = ev
                .information_elements
                .iter()
                .find(|ie| ie.name == "loss_count")
                .and_then(|ie| ie.value.as_deref())
                .and_then(|s| s.parse().ok())
                .unwrap_or(-1);
            let loss_apparent: i64 = ev
                .information_elements
                .iter()
                .find(|ie| ie.name == "loss_apparent")
                .and_then(|ie| ie.value.as_deref())
                .and_then(|s| s.parse().ok())
                .unwrap_or(-9999);
            assert_eq!(loss_count, 0, "flux contigu ⇒ loss_count=0");
            assert_eq!(loss_apparent, 0, "flux contigu ⇒ loss_apparent=0");
        }
    }

    /// 0.3.1 (oiran-api 2.21.132, ordre #9 7059947810) — le journal d'une
    /// perte apparente négative (ici : un paquet RTP reçu deux fois) ne
    /// porte aucune adresse IP ni aucun port ; il garde le SSRC,
    /// l'interface et les comptes. Avant : `source_ip` et `destination_ip`
    /// en clair, soit l'adresse de l'UE.
    #[test]
    fn negative_apparent_loss_is_journaled_without_any_address_2_21_132() {
        JOURNAL.with(|lines| lines.borrow_mut().clear());
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.45.0.7".into(),
            port: 49170,
            call_id: "cid-test".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        // Séquences 0, 1, 1, 2 : quatre paquets observés pour trois attendus.
        for (idx, seq) in [0u16, 1, 1, 2].iter().enumerate() {
            let pkt = rtp_packet(0, *seq, 100 + *seq as u32 * 160, 0xcafebabe, &[0xcc; 160]);
            agg.observe_rtp(
                "10.46.0.9", 40000, "10.45.0.7", 49170,
                &pkt, 1_000_000 * idx as u64,
                &pr(1 + idx as u64), &ts(1_000_000 * idx as u64),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        assert_eq!(events.len(), 1);
        let apparent = events[0]
            .information_elements
            .iter()
            .find(|ie| ie.name == "loss_apparent")
            .and_then(|ie| ie.value.clone())
            .unwrap();
        assert_eq!(apparent, "-1");
        let lines = JOURNAL.with(|lines| lines.borrow().clone());
        assert_eq!(lines.len(), 1, "une ligne de journal : {lines:?}");
        let line = &lines[0];
        assert!(line.contains("\"event\":\"RTP_LOSS_NEGATIVE_APPARENT\""));
        assert!(line.contains("\"ssrc\":\"0xcafebabe\""));
        assert!(line.contains("\"interface\":\"IMS\""));
        assert!(line.contains("\"expected_packets\":3") && line.contains("\"observed_packets\":4"));
        assert!(line.contains("\"loss_apparent\":-1"));
        for forbidden in ["10.45.0.7", "10.46.0.9", "49170", "40000", "_ip", "_port", "cid-test"] {
            assert!(!line.contains(forbidden), "le journal porte {forbidden} : {line}");
        }
        // Le journal est du JSON sur une ligne.
        assert!(line.starts_with('{') && line.ends_with('}') && !line.contains('\n'));
    }

    /// 2.21.100 — `loss_apparent` est signé et exposé en IE à côté de
    /// `loss_count`. Les gaps réels donnent les deux positifs égaux ; une
    /// collision hypothétique (expected < observed) donnerait
    /// `loss_apparent < 0` + event JSON `RTP_LOSS_NEGATIVE_APPARENT`. Ce
    /// test prouve la présence de l'IE et la cohérence loss_count vs
    /// loss_apparent sur un cas normal.
    #[test]
    fn loss_apparent_ie_mirrors_loss_count_on_contiguous_flow_2_21_100() {
        let mut agg = RtpFlowAggregator::new();
        agg.register_sdp_flow(SdpFlowRegistration {
            ip: "10.0.0.2".into(),
            port: 49170,
            call_id: "cid-test".into(),
            payload_type: Some(0),
            clock_rate_hz: None,
        });
        // Send seq 0..4 (5 packets contigus) = 0 loss.
        for (idx, seq) in [0u16, 1, 2, 3, 4].iter().enumerate() {
            let pkt = rtp_packet(0, *seq, 100 + *seq as u32 * 160, 0xcafebabe, &[0xcc; 160]);
            agg.observe_rtp(
                "10.0.0.1", 40000, "10.0.0.2", 49170,
                &pkt, 1_000_000 * idx as u64,
                &pr(1 + idx as u64), &ts(1_000_000 * idx as u64),
            );
        }
        let events = agg.finish("sha256:cap", "IMS");
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        let loss_count_ie = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "loss_count")
            .expect("loss_count doit exister");
        let loss_apparent_ie = ev
            .information_elements
            .iter()
            .find(|ie| ie.name == "loss_apparent")
            .expect("loss_apparent doit exister (nouvelle IE 2.21.100)");
        assert_eq!(loss_count_ie.value.as_deref(), Some("0"));
        assert_eq!(loss_apparent_ie.value.as_deref(), Some("0"));
    }
}
