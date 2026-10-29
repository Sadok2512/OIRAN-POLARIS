//! Versioned, provenance-complete normalized protocol events.

use std::fmt::Write;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeStatus {
    Decoded,
    Partial,
    Unsupported,
    Malformed,
    EncryptedOrProtected,
}
impl DecodeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Decoded => "DECODED",
            Self::Partial => "PARTIAL",
            Self::Unsupported => "UNSUPPORTED",
            Self::Malformed => "MALFORMED",
            Self::EncryptedOrProtected => "ENCRYPTED_OR_PROTECTED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Protocol {
    Ngap,
    S1ap,
    Nas5gs,
    Nas5gmm,
    Nas5gsm,
    NasEpsMm,
    NasEpsSm,
    Gtpv2c,
    Diameter,
    Pfcp,
    Gtpu,
    Sctp,
    SbiHttp2,
    Unknown,
}
impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ngap => "NGAP",
            Self::S1ap => "S1AP",
            Self::Nas5gs => "NAS-5GS",
            Self::Nas5gmm => "NAS-5GMM",
            Self::Nas5gsm => "NAS-5GSM",
            Self::NasEpsMm => "NAS-EPS-MM",
            Self::NasEpsSm => "NAS-EPS-SM",
            Self::Gtpv2c => "GTPv2-C",
            Self::Diameter => "DIAMETER",
            Self::Pfcp => "PFCP",
            Self::Gtpu => "GTP-U",
            Self::Sctp => "SCTP",
            Self::SbiHttp2 => "SBI-HTTP2",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactTimestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
    pub raw_ticks: u64,
    pub resolution_base: u8,
    pub resolution_exponent: u8,
}
impl ExactTimestamp {
    pub fn unix_nanoseconds(&self) -> Option<i128> {
        Some(
            i128::from(self.seconds)
                .checked_mul(1_000_000_000)?
                .checked_add(i128::from(self.nanoseconds))?,
        )
    }
    pub fn display(&self) -> String {
        format!("{}.{:09}Z", self.seconds, self.nanoseconds)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketReference {
    pub source_file: String,
    pub source_sha256: Option<String>,
    pub packet_number: u64,
    pub byte_offset: u64,
    pub interface_id: u32,
    pub link_type: Option<u32>,
    pub sll2_protocol_type: Option<u16>,
    pub sll2_reserved: Option<u16>,
    pub sll2_interface_index: Option<u32>,
    pub sll2_arphrd_type: Option<u16>,
    pub sll2_packet_type: Option<u8>,
    pub sll2_address_length: Option<u8>,
    pub sll2_address: Option<String>,
    pub captured_length: u32,
    pub original_length: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub address: String,
    pub port: Option<u16>,
    pub network_function: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Direction {
    RanToCore,
    CoreToRan,
    SmfToUpf,
    UpfToSmf,
    Uplink,
    Downlink,
    Unknown,
    SbiRequest,
    SbiResponse,
}
impl Direction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RanToCore => "RAN_TO_CORE",
            Self::CoreToRan => "CORE_TO_RAN",
            Self::SmfToUpf => "SMF_TO_UPF",
            Self::UpfToSmf => "UPF_TO_SMF",
            Self::Uplink => "UPLINK",
            Self::Downlink => "DOWNLINK",
            Self::Unknown => "UNKNOWN",
            Self::SbiRequest => "SBI_REQUEST",
            Self::SbiResponse => "SBI_RESPONSE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedValue {
    pub name: String,
    pub value: String,
    pub pseudonymized: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceState {
    Exact,
    Strong,
    Possible,
    Unknown,
}
impl EvidenceState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exact => "EXACT",
            Self::Strong => "STRONG",
            Self::Possible => "POSSIBLE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceReference {
    pub state: EvidenceState,
    pub kind: String,
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InformationElement {
    pub id: Option<u16>,
    pub name: String,
    pub length: u32,
    pub value: Option<String>,
    pub raw_sha256: Option<String>,
    pub status: DecodeStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SbiMetadata {
    pub tcp_connection_id: String,
    pub http2_stream_id: u32,
    pub service: Option<String>,
    pub operation: Option<String>,
    pub http_method: Option<String>,
    pub request_uri: Option<String>,
    pub http_status: Option<u16>,
    pub consumer_nf: Option<String>,
    pub producer_nf: Option<String>,
    pub scp_transit: bool,
    pub transaction_duration_ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedEvent {
    pub event_id: String,
    pub parent_event_id: Option<String>,
    pub probe_id: String,
    pub capture_point_id: String,
    pub capture_id: String,
    pub packet_references: Vec<PacketReference>,
    pub timestamp: ExactTimestamp,
    pub interface: String,
    pub protocol: Protocol,
    pub message_name: String,
    pub message_type: u32,
    pub procedure_code: Option<u32>,
    pub procedure: Option<String>,
    pub security_state: Option<String>,
    pub source_byte_offset: Option<u32>,
    pub source_endpoint: Endpoint,
    pub destination_endpoint: Endpoint,
    pub direction: Direction,
    pub session_identifiers: Vec<NamedValue>,
    pub information_elements: Vec<InformationElement>,
    pub decoder_name: String,
    pub decoder_version: String,
    pub schema_version: &'static str,
    pub decoding_status: DecodeStatus,
    pub errors: Vec<String>,
    pub raw_payload_reference: String,
    pub evidence_references: Vec<EvidenceReference>,
    pub sbi: Option<SbiMetadata>,
}

impl NormalizedEvent {
    pub const SCHEMA_VERSION: &'static str = "1.5.0";
    pub fn assign_deterministic_id(&mut self) {
        let mut material = format!(
            "{}|{}|{}|{}|{}",
            self.capture_id,
            self.protocol.as_str(),
            self.message_type,
            self.timestamp.raw_ticks,
            self.raw_payload_reference
        );
        for packet in &self.packet_references {
            let _ = write!(
                material,
                "|{}:{}:{}",
                packet.packet_number, packet.byte_offset, packet.interface_id
            );
        }
        self.event_id = format!("evt-{:016x}", stable_hash(material.as_bytes()));
    }
    pub fn has_complete_provenance(&self) -> bool {
        !self.capture_id.is_empty()
            && !self.packet_references.is_empty()
            && self
                .packet_references
                .iter()
                .all(|p| !p.source_file.is_empty() && p.packet_number > 0)
            && !self.raw_payload_reference.is_empty()
    }
    pub fn to_json(&self) -> String {
        let packets=self.packet_references.iter().map(|p|format!("{{\"source_file\":\"{}\",\"source_sha256\":{},\"packet_number\":{},\"byte_offset\":{},\"interface_id\":{},\"link_type\":{},\"sll2_protocol_type\":{},\"sll2_reserved\":{},\"sll2_interface_index\":{},\"sll2_arphrd_type\":{},\"sll2_packet_type\":{},\"sll2_address_length\":{},\"sll2_address\":{},\"captured_length\":{},\"original_length\":{}}}",escape(&p.source_file),option_string(p.source_sha256.as_deref()),p.packet_number,p.byte_offset,p.interface_id,option_num(p.link_type),option_num(p.sll2_protocol_type),option_num(p.sll2_reserved),option_num(p.sll2_interface_index),option_num(p.sll2_arphrd_type),option_num(p.sll2_packet_type),option_num(p.sll2_address_length),option_string(p.sll2_address.as_deref()),p.captured_length,p.original_length)).collect::<Vec<_>>().join(",");
        let identifiers = self
            .session_identifiers
            .iter()
            .map(|v| {
                format!(
                    "{{\"name\":\"{}\",\"value\":\"{}\",\"pseudonymized\":{}}}",
                    escape(&v.name),
                    escape(&v.value),
                    v.pseudonymized
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let ies=self.information_elements.iter().map(|ie|format!("{{\"id\":{},\"name\":\"{}\",\"length\":{},\"value\":{},\"raw_sha256\":{},\"status\":\"{}\"}}",option_num(ie.id),escape(&ie.name),ie.length,option_string(ie.value.as_deref()),option_string(ie.raw_sha256.as_deref()),ie.status.as_str())).collect::<Vec<_>>().join(",");
        let errors = self
            .errors
            .iter()
            .map(|e| format!("\"{}\"", escape(e)))
            .collect::<Vec<_>>()
            .join(",");
        let evidence = self
            .evidence_references
            .iter()
            .map(|e| {
                format!(
                    "{{\"state\":\"{}\",\"kind\":\"{}\",\"reference\":\"{}\"}}",
                    e.state.as_str(),
                    escape(&e.kind),
                    escape(&e.reference)
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!("{{\"event_id\":\"{}\",\"parent_event_id\":{},\"probe_id\":\"{}\",\"capture_point_id\":\"{}\",\"capture_id\":\"{}\",\"packet_references\":[{}],\"timestamp\":{{\"seconds\":{},\"nanoseconds\":{},\"raw_ticks\":{},\"resolution_base\":{},\"resolution_exponent\":{},\"display\":\"{}\"}},\"interface\":\"{}\",\"protocol\":\"{}\",\"message_name\":\"{}\",\"message_type\":{},\"procedure_code\":{},\"procedure\":{},\"security_state\":{},\"source_byte_offset\":{},\"source_endpoint\":{},\"destination_endpoint\":{},\"direction\":\"{}\",\"session_identifiers\":[{}],\"information_elements\":[{}],\"decoder_name\":\"{}\",\"decoder_version\":\"{}\",\"schema_version\":\"{}\",\"decoding_status\":\"{}\",\"errors\":[{}],\"raw_payload_reference\":\"{}\",\"evidence_references\":[{}],\"sbi\":{}}}",
            escape(&self.event_id),option_string(self.parent_event_id.as_deref()),escape(&self.probe_id),escape(&self.capture_point_id),escape(&self.capture_id),packets,self.timestamp.seconds,self.timestamp.nanoseconds,self.timestamp.raw_ticks,self.timestamp.resolution_base,self.timestamp.resolution_exponent,escape(&self.timestamp.display()),escape(&self.interface),self.protocol.as_str(),escape(&self.message_name),self.message_type,option_num(self.procedure_code),option_string(self.procedure.as_deref()),option_string(self.security_state.as_deref()),option_num(self.source_byte_offset),endpoint_json(&self.source_endpoint),endpoint_json(&self.destination_endpoint),self.direction.as_str(),identifiers,ies,escape(&self.decoder_name),escape(&self.decoder_version),self.schema_version,self.decoding_status.as_str(),errors,escape(&self.raw_payload_reference),evidence,sbi_json(self.sbi.as_ref()))
    }
}

fn sbi_json(value: Option<&SbiMetadata>) -> String {
    let Some(v) = value else { return "null".into() };
    format!("{{\"tcp_connection_id\":\"{}\",\"http2_stream_id\":{},\"service\":{},\"operation\":{},\"http_method\":{},\"request_uri\":{},\"http_status\":{},\"consumer_nf\":{},\"producer_nf\":{},\"scp_transit\":{},\"transaction_duration_ns\":{}}}", escape(&v.tcp_connection_id), v.http2_stream_id, option_string(v.service.as_deref()), option_string(v.operation.as_deref()), option_string(v.http_method.as_deref()), option_string(v.request_uri.as_deref()), option_num(v.http_status), option_string(v.consumer_nf.as_deref()), option_string(v.producer_nf.as_deref()), v.scp_transit, option_num(v.transaction_duration_ns))
}

pub fn stable_hash(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
/// Streaming SHA-256 hasher. Memory is bounded to a 64-byte block buffer and
/// the 8-word running state (72 bytes total) regardless of input size — the
/// convenience `sha256_hex(bytes)` is kept for backward compatibility and is
/// now implemented on top of it.
pub struct Sha256Hasher {
    h: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    total_len: u64,
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; 64],
            buffered: 0,
            total_len: 0,
        }
    }
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut data = data;
        if self.buffered > 0 {
            let needed = 64 - self.buffered;
            let take = data.len().min(needed);
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
        while data.len() >= 64 {
            let (chunk, rest) = data.split_at(64);
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            self.compress(&block);
            data = rest;
        }
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    pub fn finish_hex(mut self) -> String {
        let bit_len = self.total_len.wrapping_mul(8);
        // Append 0x80, pad zeros so remaining length (mod 64) == 56, append
        // 8-byte big-endian bit length.
        let mut tail = [0u8; 72]; // worst case: 0x80 + 63 zeros + 8 length bytes
        tail[0] = 0x80;
        let pad = (56 - ((self.buffered as isize + 1) % 64) + 64) as usize % 64;
        let bit_len_bytes = bit_len.to_be_bytes();
        tail[1 + pad..1 + pad + 8].copy_from_slice(&bit_len_bytes);
        self.update(&tail[..1 + pad + 8]);
        debug_assert_eq!(self.buffered, 0);
        self.h.iter().map(|v| format!("{v:08x}")).collect()
    }

    fn compress(&mut self, chunk: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().expect("word"));
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) = (
            self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7],
        );
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            self.h[i] = self.h[i].wrapping_add(*v);
        }
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(bytes);
    hasher.finish_hex()
}
pub fn pseudonym(label: &str, bytes: &[u8]) -> String {
    let mut material = label.as_bytes().to_vec();
    material.push(0);
    material.extend_from_slice(bytes);
    format!("psn-{:016x}", stable_hash(&material))
}
fn endpoint_json(e: &Endpoint) -> String {
    format!(
        "{{\"address\":\"{}\",\"port\":{},\"network_function\":{}}}",
        escape(&e.address),
        option_num(e.port),
        option_string(e.network_function.as_deref())
    )
}
fn option_num<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map(|x| x.to_string()).unwrap_or_else(|| "null".into())
}
fn option_string(v: Option<&str>) -> String {
    v.map(|x| format!("\"{}\"", escape(x)))
        .unwrap_or_else(|| "null".into())
}
fn escape(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> NormalizedEvent {
        NormalizedEvent {
            event_id: String::new(),
            parent_event_id: None,
            probe_id: "probe-1".into(),
            capture_point_id: "n2-bridge".into(),
            capture_id: "sha256:abc".into(),
            packet_references: vec![PacketReference {
                source_file: "x.pcapng".into(),
                source_sha256: Some("abc".into()),
                packet_number: 7,
                byte_offset: 40,
                interface_id: 2,
                link_type: Some(1),
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: 64,
                original_length: 64,
            }],
            timestamp: ExactTimestamp {
                seconds: 10,
                nanoseconds: 5,
                raw_ticks: 10_000_000_005,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "N2".into(),
            protocol: Protocol::Ngap,
            message_name: "InitialUEMessage".into(),
            message_type: 15,
            procedure_code: Some(15),
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.0.0.1".into(),
                port: Some(38412),
                network_function: Some("gNB".into()),
            },
            destination_endpoint: Endpoint {
                address: "10.0.0.2".into(),
                port: Some(38412),
                network_function: Some("AMF".into()),
            },
            direction: Direction::RanToCore,
            session_identifiers: vec![],
            information_elements: vec![],
            decoder_name: "decoder-ngap".into(),
            decoder_version: "0.1.0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:payload".into(),
            evidence_references: vec![EvidenceReference {
                state: EvidenceState::Exact,
                kind: "packet-provenance".into(),
                reference: "sha256:payload".into(),
            }],
            sbi: None,
        }
    }
    #[test]
    fn deterministic_ids_and_provenance() {
        let mut a = event();
        let mut b = event();
        a.assign_deterministic_id();
        b.assign_deterministic_id();
        assert_eq!(a.event_id, b.event_id);
        assert!(a.has_complete_provenance());
        assert!(a.to_json().contains("\"packet_number\":7"));
        assert!(a.to_json().contains("\"state\":\"EXACT\""));
    }
    #[test]
    fn exact_timestamp_is_preserved() {
        let e = event();
        assert_eq!(e.timestamp.unix_nanoseconds(), Some(10_000_000_005));
        assert_eq!(e.timestamp.raw_ticks, 10_000_000_005);
    }
    #[test]
    fn sha256_matches_standard_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
