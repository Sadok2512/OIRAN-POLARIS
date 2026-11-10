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
    jitter_fixed: u64, // Q16.16 or similar — kept as integer accumulator
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
}

pub struct RtpFlowAggregator {
    flows: BTreeMap<FlowKey, FlowState>,
    /// `(ip, port) → Call-ID` — populé par `register_sdp_flow` dès qu'un
    /// `INVITE`/`200 OK` apporte un SDP.
    endpoint_to_call_id: BTreeMap<(String, u16), String>,
    endpoint_pt: BTreeMap<(String, u16), u8>,
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
        }
    }

    /// Enregistre un (ip, port) comme flux RTP attendu pour un Call-ID.
    /// Idempotent ; si le flux change de Call-ID, le nouveau remplace.
    pub fn register_sdp_flow(&mut self, registration: SdpFlowRegistration) {
        self.endpoint_to_call_id
            .insert((registration.ip.clone(), registration.port), registration.call_id);
        if let Some(pt) = registration.payload_type {
            self.endpoint_pt.insert((registration.ip, registration.port), pt);
        }
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
        let state = self.flows.entry(key).or_default();
        state.packets = state.packets.saturating_add(1);
        state.call_id = call_id;
        if state.payload_type.is_none() {
            state.payload_type = Some(header.payload_type);
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
            // Jitter update per RFC 3550 §6.4.1 — `D(i-1,i) = (R_i -
            // R_{i-1}) - (S_i - S_{i-1})`, où R est l'horloge locale
            // et S le timestamp RTP. Converti en unités "90 kHz" si
            // PT audio dynamique — ici on garde l'unité ns (locale)
            // et on exprime jitter_ns en delta absolu puis moyenné.
            let r_delta = arrival_ns.saturating_sub(prev_arr) as i64;
            let s_delta = header.timestamp.wrapping_sub(prev_ts) as i64;
            let d = (r_delta - s_delta).unsigned_abs();
            // Moyenne glissante : J <- J + (D - J) / 16.
            let prev_j = state.jitter_fixed as i64;
            let step = (d as i64 - prev_j) / 16;
            state.jitter_fixed = (prev_j + step).max(0) as u64;
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
            let jitter_ns = state.jitter_fixed;
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
                InformationElement {
                    id: None,
                    name: "jitter_ns".into(),
                    length: 8,
                    value: Some(jitter_ns.to_string()),
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
}
