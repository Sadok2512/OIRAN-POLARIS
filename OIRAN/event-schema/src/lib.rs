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
    /// 2.11.0 (devmat) — Session Initiation Protocol (RFC 3261) for IMS
    /// voice signalling. Carried over UDP/TCP 5060 on the IMS plane,
    /// and inner to GTP-U on N3 / S1-U once observed in SDP offers.
    Sip,
    /// 2.11.0 (devmat) — Real-time Transport Protocol (RFC 3550). Flow
    /// detection is driven by the SIP SDP `c=` + `m=audio` observations ;
    /// events are AGGREGATED per SSRC (one event per flow at finish),
    /// never one event per RTP packet.
    Rtp,
    /// 2.11.0 (devmat) — RTCP Sender/Receiver Reports (RFC 3550 §6).
    /// Also aggregated per SSRC.
    Rtcp,
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
            Self::Sip => "SIP",
            Self::Rtp => "RTP",
            Self::Rtcp => "RTCP",
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SctpAssociationProvenance {
    pub association_id: String,
    pub association_generation: u64,
    pub verification_tag: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_tsn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_tsn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_segment_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_index: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketReference {
    pub source_file: String,
    pub source_sha256: Option<String>,
    pub sctp_association: Option<std::sync::Arc<SctpAssociationProvenance>>,
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

/// 2.7.11: canonical identity of IEs whose payload is pure key material
/// (SecurityKey carrying KeNB*/KgNB*, Next-Hop key NH, NextHopChainingCount,
/// NAS keys). Decoders MUST emit such IEs via [`InformationElement::withheld`]
/// — the length is preserved, the body bytes and any hash of the body never
/// reach the normalised event. Callers wanting to know whether an
/// upstream `(decoder, ie_id)` falls in this bucket consult
/// [`is_withheld_key_material`] below so the list stays identical between
/// S1AP and NGAP.
pub const KEY_MATERIAL_WITHHELD_IE_NAME: &str = "key_material_withheld";
pub const KEY_MATERIAL_WITHHELD_IE_VALUE: &str = "WITHHELD";

/// Is this `(decoder, protocol-IE-id)` bearing raw key material that must
/// be withheld at decode time? The list is explicit and identical between
/// S1AP (TS 36.413) and NGAP (TS 38.413).
///
/// S1AP: IE 73 (SecurityKey).
/// NGAP: IE 94 (SecurityKey).
///
/// Next-Hop (NH) / NextHopChainingCount material is embedded inside the
/// SecurityKey octet-string in both specifications, so withholding the
/// SecurityKey IE withholds the entire key chain at once. Adding an IE to
/// this allowlist is an explicit code change; there is no catch-all.
pub fn is_withheld_key_material(decoder: &str, ie_id: u16) -> bool {
    match (decoder, ie_id) {
        ("decoder-s1ap", 73) => true,
        ("decoder-ngap", 94) => true,
        _ => false,
    }
}

impl InformationElement {
    /// Emit an IE whose raw bytes must stay inside the decoder: length is
    /// preserved for provenance, the body is collapsed to the sentinel
    /// `WITHHELD`, the raw SHA-256 is cleared. This is the only path a
    /// decoder is allowed to take for key material; raw bytes escaping to
    /// the normalised event would trip `LTE_IDENTITY_DISCLOSURE_REJECTED`
    /// at the POLARIS finalizer.
    pub fn withheld(id: Option<u16>, length: u32) -> Self {
        Self {
            id,
            name: KEY_MATERIAL_WITHHELD_IE_NAME.into(),
            length,
            value: Some(KEY_MATERIAL_WITHHELD_IE_VALUE.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        }
    }
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

/// 1.8.0 (POLARIS 2.21.0) — identité de la sonde source apposée à la
/// sérialisation (`probe_id`, `probe_type` vprobe|phy|vtap, …).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProbeStamp {
    pub probe_id: Option<String>,
    pub probe_type: Option<String>,
    pub physical_link: Option<String>,
    pub timestamp_source: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedEvent {
    pub event_id: String,
    /// 1.6.0 (POLARIS 2.21.91, ordre #9 7033006772 défaut 3) — clé de
    /// corrélation live↔publié **indépendante** de `capture_id`. Live
    /// hashe `sha256(path)`, publi hashe `sha256(contenu)` → `event_id`
    /// divergent par construction sur le même pcapng. `stable_event_key`
    /// est dérivé par [`derive_stable_event_key`] dans event-schema,
    /// utilisée par les DEUX chemins (apps/api live_trace +
    /// live-probe publication), à partir de
    /// `(basename du fichier dumpcap ORIGINAL, interface_id,
    /// packet_number, byte_offset)`. `event_id` reste inchangé
    /// (zéro migration).
    pub stable_event_key: String,
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
    // 1.5.1 (2.9.4 — devmat #9 T2) : la sérialisation omet désormais les
    // champs optionnels à `null` (packet_references.sll2_*, source_sha256,
    // link_type, parent_event_id, procedure_code, procedure,
    // security_state, source_byte_offset) et les tableaux vides
    // (errors, evidence_references). `information_elements.id`,
    // `.value` et `.raw_sha256` nuls sont omis au niveau IE.
    // Réduction mesurée ~45-60 % sur événements Sxab/SBI, format reste
    // backward-compatible (session-engine `parse_event` via serde
    // ignore_unknown_fields + unwrap_or tolère toutes les omissions).
    pub const SCHEMA_VERSION: &'static str = "1.6.0";
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

    /// 1.6.0 (POLARIS 2.21.91, défaut #9 7033006772 + raffinement #9
    /// 7034553419) — stamp `stable_event_key` à partir de la première
    /// `packet_reference` du caller, en ajoutant `(protocol, ordinal)`
    /// pour garantir l'**unicité par event**. `ordinal` = rang (0-based)
    /// de l'event parmi ceux produits pour un même paquet dans l'ordre
    /// d'émission d'`oiran-decode::emit_events`. Le même décodeur
    /// produit la même séquence en live et en publication → mêmes
    /// ordinaux, mêmes clés. Si le caller ne fournit pas le chemin
    /// dumpcap (`dumpcap_file_path` vide) ou si l'event n'a pas de
    /// `packet_references`, le champ reste vide — invariant non
    /// régressé pour les tests synthétiques.
    pub fn assign_stable_event_key(
        &mut self,
        dumpcap_file_path: &str,
        ordinal: u32,
    ) {
        if dumpcap_file_path.is_empty() {
            return;
        }
        let Some(packet) = self.packet_references.first() else {
            return;
        };
        self.stable_event_key = derive_stable_event_key(
            dumpcap_file_path,
            packet.interface_id,
            packet.packet_number,
            packet.byte_offset,
            self.protocol.as_str(),
            ordinal,
        );
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
        self.to_json_with_probe(&ProbeStamp::default())
    }

    /// 1.8.0 (POLARIS 2.21.0) — sérialise en ajoutant, juste après
    /// `probe_id`, les champs multi-sonde lus par `session-engine`
    /// (`probe_type`, `timestamp_source`, `physical_link`). Un stamp vide
    /// produit une sortie bit-identique à `to_json()` ; `probe_id` n'est
    /// remplacé que s'il est fourni.
    pub fn to_json_with_probe(&self, stamp: &ProbeStamp) -> String {
        // 1.5.1 — serialisation compacte : omet les champs optionnels à null
        // et les tableaux [] vides sans perte d'information. Voir SCHEMA_VERSION.
        let packets = self
            .packet_references
            .iter()
            .map(packet_reference_json)
            .collect::<Vec<_>>()
            .join(",");
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
        let ies = self
            .information_elements
            .iter()
            .map(information_element_json)
            .collect::<Vec<_>>()
            .join(",");
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
        let mut parts: Vec<String> = Vec::with_capacity(29);
        parts.push(format!("\"event_id\":\"{}\"", escape(&self.event_id)));
        // 1.6.0 (POLARIS 2.21.91) — toujours émis, même vide, pour
        // préserver la contrat de présence côté consommateurs SSE +
        // callflow. Le champ sert de clé de corrélation live↔publié.
        parts.push(format!(
            "\"stable_event_key\":\"{}\"",
            escape(&self.stable_event_key)
        ));
        if let Some(parent) = self.parent_event_id.as_deref() {
            parts.push(format!("\"parent_event_id\":\"{}\"", escape(parent)));
        }
        parts.push(format!(
            "\"probe_id\":\"{}\"",
            escape(stamp.probe_id.as_deref().unwrap_or(&self.probe_id))
        ));
        if let Some(v) = stamp.probe_type.as_deref() {
            parts.push(format!("\"probe_type\":\"{}\"", escape(v)));
        }
        if let Some(v) = stamp.physical_link.as_deref() {
            parts.push(format!("\"physical_link\":\"{}\"", escape(v)));
        }
        if let Some(v) = stamp.timestamp_source.as_deref() {
            parts.push(format!("\"timestamp_source\":\"{}\"", escape(v)));
        }
        parts.push(format!("\"capture_point_id\":\"{}\"", escape(&self.capture_point_id)));
        parts.push(format!("\"capture_id\":\"{}\"", escape(&self.capture_id)));
        parts.push(format!("\"packet_references\":[{}]", packets));
        parts.push(format!(
            "\"timestamp\":{{\"seconds\":{},\"nanoseconds\":{},\"raw_ticks\":{},\"resolution_base\":{},\"resolution_exponent\":{},\"display\":\"{}\"}}",
            self.timestamp.seconds,
            self.timestamp.nanoseconds,
            self.timestamp.raw_ticks,
            self.timestamp.resolution_base,
            self.timestamp.resolution_exponent,
            escape(&self.timestamp.display()),
        ));
        parts.push(format!("\"interface\":\"{}\"", escape(&self.interface)));
        parts.push(format!("\"protocol\":\"{}\"", self.protocol.as_str()));
        parts.push(format!("\"message_name\":\"{}\"", escape(&self.message_name)));
        parts.push(format!("\"message_type\":{}", self.message_type));
        if let Some(pc) = self.procedure_code {
            parts.push(format!("\"procedure_code\":{}", pc));
        }
        if let Some(p) = self.procedure.as_deref() {
            parts.push(format!("\"procedure\":\"{}\"", escape(p)));
        }
        if let Some(s) = self.security_state.as_deref() {
            parts.push(format!("\"security_state\":\"{}\"", escape(s)));
        }
        if let Some(o) = self.source_byte_offset {
            parts.push(format!("\"source_byte_offset\":{}", o));
        }
        parts.push(format!("\"source_endpoint\":{}", endpoint_json(&self.source_endpoint)));
        parts.push(format!("\"destination_endpoint\":{}", endpoint_json(&self.destination_endpoint)));
        parts.push(format!("\"direction\":\"{}\"", self.direction.as_str()));
        // session_identifiers et information_elements : toujours émis même
        // si vides — plusieurs consommateurs (correlation-engine
        // `tunnel_keys`, session-engine `parse_event`) attendent la présence
        // de la clé.
        parts.push(format!("\"session_identifiers\":[{}]", identifiers));
        parts.push(format!("\"information_elements\":[{}]", ies));
        parts.push(format!("\"decoder_name\":\"{}\"", escape(&self.decoder_name)));
        parts.push(format!("\"decoder_version\":\"{}\"", escape(&self.decoder_version)));
        parts.push(format!("\"schema_version\":\"{}\"", self.schema_version));
        parts.push(format!("\"decoding_status\":\"{}\"", self.decoding_status.as_str()));
        if !self.errors.is_empty() {
            parts.push(format!("\"errors\":[{}]", errors));
        }
        parts.push(format!("\"raw_payload_reference\":\"{}\"", escape(&self.raw_payload_reference)));
        if !self.evidence_references.is_empty() {
            parts.push(format!("\"evidence_references\":[{}]", evidence));
        }
        if let Some(sbi) = self.sbi.as_ref() {
            parts.push(format!("\"sbi\":{}", sbi_json(Some(sbi))));
        }
        format!("{{{}}}", parts.join(","))
    }
}

fn packet_reference_json(p: &PacketReference) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(15);
    parts.push(format!("\"source_file\":\"{}\"", escape(&p.source_file)));
    if let Some(s) = p.source_sha256.as_deref() {
        parts.push(format!("\"source_sha256\":\"{}\"", escape(s)));
    }
    parts.push(format!("\"packet_number\":{}", p.packet_number));
    parts.push(format!("\"byte_offset\":{}", p.byte_offset));
    parts.push(format!("\"interface_id\":{}", p.interface_id));
    if let Some(n) = p.link_type {
        parts.push(format!("\"link_type\":{}", n));
    }
    if let Some(n) = p.sll2_protocol_type {
        parts.push(format!("\"sll2_protocol_type\":{}", n));
    }
    if let Some(n) = p.sll2_reserved {
        parts.push(format!("\"sll2_reserved\":{}", n));
    }
    if let Some(n) = p.sll2_interface_index {
        parts.push(format!("\"sll2_interface_index\":{}", n));
    }
    if let Some(n) = p.sll2_arphrd_type {
        parts.push(format!("\"sll2_arphrd_type\":{}", n));
    }
    if let Some(n) = p.sll2_packet_type {
        parts.push(format!("\"sll2_packet_type\":{}", n));
    }
    if let Some(n) = p.sll2_address_length {
        parts.push(format!("\"sll2_address_length\":{}", n));
    }
    if let Some(s) = p.sll2_address.as_deref() {
        parts.push(format!("\"sll2_address\":\"{}\"", escape(s)));
    }
    if let Some(sctp) = &p.sctp_association {
        let mut association = format!(
            "\"sctp_association\":{{\"association_id\":\"{}\",\"association_generation\":{},\"verification_tag\":{}",
            escape(&sctp.association_id), sctp.association_generation, sctp.verification_tag,
        );
        if let Some(tsn) = sctp.first_tsn {
            association.push_str(&format!(",\"first_tsn\":{tsn}"));
        }
        if let Some(tsn) = sctp.last_tsn {
            association.push_str(&format!(",\"last_tsn\":{tsn}"));
        }
        if let Some(name) = &sctp.original_segment_name {
            association.push_str(&format!(",\"original_segment_name\":\"{}\"", escape(name)));
        }
        if let Some(index) = sctp.rotation_index {
            association.push_str(&format!(",\"rotation_index\":{index}"));
        }
        association.push('}');
        parts.push(association);
    }
    parts.push(format!("\"captured_length\":{}", p.captured_length));
    parts.push(format!("\"original_length\":{}", p.original_length));
    format!("{{{}}}", parts.join(","))
}

fn information_element_json(ie: &InformationElement) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(6);
    if let Some(id) = ie.id {
        parts.push(format!("\"id\":{}", id));
    }
    parts.push(format!("\"name\":\"{}\"", escape(&ie.name)));
    parts.push(format!("\"length\":{}", ie.length));
    if let Some(v) = ie.value.as_deref() {
        parts.push(format!("\"value\":\"{}\"", escape(v)));
    }
    if let Some(s) = ie.raw_sha256.as_deref() {
        parts.push(format!("\"raw_sha256\":\"{}\"", escape(s)));
    }
    parts.push(format!("\"status\":\"{}\"", ie.status.as_str()));
    format!("{{{}}}", parts.join(","))
}

fn sbi_json(value: Option<&SbiMetadata>) -> String {
    let Some(v) = value else { return "null".into() };
    format!("{{\"tcp_connection_id\":\"{}\",\"http2_stream_id\":{},\"service\":{},\"operation\":{},\"http_method\":{},\"request_uri\":{},\"http_status\":{},\"consumer_nf\":{},\"producer_nf\":{},\"scp_transit\":{},\"transaction_duration_ns\":{}}}", escape(&v.tcp_connection_id), v.http2_stream_id, option_string(v.service.as_deref()), option_string(v.operation.as_deref()), option_string(v.http_method.as_deref()), option_string(v.request_uri.as_deref()), option_num(v.http_status), option_string(v.consumer_nf.as_deref()), option_string(v.producer_nf.as_deref()), v.scp_transit, option_num(v.transaction_duration_ns))
}

/// 1.6.0 (POLARIS 2.21.91, défaut #9 7033006772 + raffinement #9
/// 7034553419) — dérive la clé UNIQUE par event pour la corrélation
/// live↔publié.
///
/// Fonction UNIQUE appelée par les deux chemins :
///   * `apps/api::live_trace` (décodage du ring en live) ;
///   * `live-probe` (décodage à la publication, qui travaille sur une
///     COPIE renommée du pcapng mais reçoit le basename original via
///     `DecodeConfig::stable_source_file`).
///
/// Encodage stable, unique par event :
///   `"{basename}|{interface_id}|{packet_number}|{byte_offset}|{protocol}|{ordinal}"`.
///
/// `ordinal` discrimine les events qui partagent un même paquet
/// (ex. NGAP parent + NAS enfant). Rang 0-based dans l'ordre
/// d'émission d'`oiran-decode::emit_events` — déterministe et
/// identique entre les deux chemins pour un même pcapng. Voir aussi
/// [`packet_lookup_key`] pour le prefix servant à compter les events
/// par paquet côté caller.
pub fn derive_stable_event_key(
    dumpcap_file_path: &str,
    interface_id: u32,
    packet_number: u64,
    byte_offset: u64,
    protocol: &str,
    ordinal: u32,
) -> String {
    format!(
        "{}|{}|{}",
        packet_lookup_key(dumpcap_file_path, interface_id, packet_number, byte_offset),
        protocol,
        ordinal,
    )
}

/// 1.6.0 (POLARIS 2.21.91, #9 7034553419) — prefix de `stable_event_key`
/// tronqué à `(basename, iid, pkt, off)`. Utilisé par
/// `oiran-decode::emit_events` comme clé d'index du compteur
/// d'ordinaux : tous les events qui partagent ce prefix reçoivent des
/// ordinaux 0, 1, 2, … dans leur ordre d'émission.
pub fn packet_lookup_key(
    dumpcap_file_path: &str,
    interface_id: u32,
    packet_number: u64,
    byte_offset: u64,
) -> String {
    // basename = dernier segment après `/` ou `\\` ; si vide (ex. chemin
    // se terminant par un slash), on retombe sur la chaîne originale.
    let basename = dumpcap_file_path
        .rsplit(|c: char| c == '/' || c == '\\')
        .find(|segment| !segment.is_empty())
        .unwrap_or(dumpcap_file_path);
    format!(
        "{}|{}|{}|{}",
        basename, interface_id, packet_number, byte_offset
    )
}

/// 2.21.102 (défaut ANR1 #9 7044712668, ordre #9 7045732954) — patche
/// un objet callflow (serde_json `Value`) **en place** pour renseigner
/// `stable_event_key` sur chaque event `events[*]` qui ne le porte
/// pas. Respecte strictement la formule de [`derive_stable_event_key`]
/// (`{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}`) avec l'ordinal
/// 0-based dans l'ordre d'apparition des events dans l'array `events`
/// (= ordre d'émission, si le producteur n'a pas re-trié).
///
/// Événement sans `packet_references` : skippé (écart déclaré OUVERT
/// côté caller si besoin). Événement avec `stable_event_key` déjà
/// non vide : laissé intact.
///
/// Retourne `(patched, skipped_no_packet_references)`.
pub fn backfill_stable_event_keys_in_callflow(
    value: &mut serde_json::Value,
) -> (usize, usize) {
    let Some(events) = value.get_mut("events").and_then(|v| v.as_array_mut()) else {
        return (0, 0);
    };
    // 1.12.0 (POLARIS 2.21.133) — numérotation dans l'ordre d'émission
    // reconstitué (parent, puis ses enfants), plus dans l'ordre de l'array :
    // un callflow stocké est trié pour l'affichage, et un enfant y précède
    // son parent une fois sur deux.
    let packet_of = |event: &serde_json::Value| -> Option<(String, u32, u64, u64)> {
        let p = event
            .get("packet_references")
            .and_then(serde_json::Value::as_array)
            .and_then(|a| a.first())
            .and_then(|p| p.as_object())?;
        Some((
            p.get("source_file")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned(),
            p.get("interface_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32,
            p.get("packet_number")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            p.get("byte_offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
        ))
    };
    let has_key = |event: &serde_json::Value| {
        event
            .get("stable_event_key")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| !s.is_empty())
    };
    let mut skipped = 0usize;
    let mut by_packet = std::collections::BTreeMap::<String, Vec<usize>>::new();
    for (index, event) in events.iter().enumerate() {
        if !event.is_object() {
            continue;
        }
        match packet_of(event) {
            Some((source_file, interface_id, packet_number, byte_offset)) => by_packet
                .entry(packet_lookup_key(&source_file, interface_id, packet_number, byte_offset))
                .or_default()
                .push(index),
            None => {
                if !has_key(event) {
                    skipped += 1;
                }
            }
        }
    }
    let mut assignments: Vec<(usize, String)> = Vec::new();
    for members in by_packet.values() {
        let order = emission_order(members.len(), |position| {
            let event = &events[members[position]];
            (
                event.get("event_id").and_then(serde_json::Value::as_str).unwrap_or(""),
                event.get("parent_event_id").and_then(serde_json::Value::as_str),
            )
        });
        for (ordinal, position) in order.into_iter().enumerate() {
            let index = members[position];
            let event = &events[index];
            if has_key(event) {
                continue;
            }
            let Some((source_file, interface_id, packet_number, byte_offset)) = packet_of(event)
            else {
                continue;
            };
            let protocol = event
                .get("protocol")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            assignments.push((
                index,
                derive_stable_event_key(
                    &source_file,
                    interface_id,
                    packet_number,
                    byte_offset,
                    protocol,
                    ordinal as u32,
                ),
            ));
        }
    }
    let patched = assignments.len();
    for (index, key) in assignments {
        if let Some(obj) = events[index].as_object_mut() {
            obj.insert("stable_event_key".into(), serde_json::Value::String(key));
        }
    }
    (patched, skipped)
}

/// 1.12.0 (POLARIS 2.21.133) — ordre d'émission reconstitué des events
/// d'un MÊME paquet, donnés dans leur ordre de lecture. `describe(i)`
/// rend `(event_id, parent_event_id)` de l'event de rang `i`.
///
/// Le décodeur émet un message, puis les messages qu'il porte (NGAP ou
/// S1AP, puis son NAS). Un stockage trié peut avoir inversé les deux. On
/// rend : chaque event sans parent dans le paquet, dans l'ordre de
/// lecture, suivi de ses descendants (ordre de lecture entre frères).
/// Deux events sans lien de parenté gardent leur ordre de lecture : il
/// ne peut pas être reconstitué.
///
/// Retourne une permutation de `0..len`.
pub fn emission_order<'a, F>(len: usize, describe: F) -> Vec<usize>
where
    F: Fn(usize) -> (&'a str, Option<&'a str>),
{
    let described: Vec<(&str, Option<&str>)> = (0..len).map(&describe).collect();
    let position_of = |id: &str| described.iter().position(|(own, _)| !own.is_empty() && *own == id);
    let parent_position: Vec<Option<usize>> = described
        .iter()
        .enumerate()
        .map(|(index, (_, parent))| {
            parent
                .and_then(position_of)
                .filter(|parent_index| *parent_index != index)
        })
        .collect();
    let mut order = Vec::with_capacity(len);
    let mut placed = vec![false; len];
    fn place(
        index: usize,
        parent_position: &[Option<usize>],
        placed: &mut [bool],
        order: &mut Vec<usize>,
    ) {
        if placed[index] {
            return;
        }
        placed[index] = true;
        order.push(index);
        for child in 0..parent_position.len() {
            if parent_position[child] == Some(index) {
                place(child, parent_position, placed, order);
            }
        }
    }
    for index in 0..len {
        if parent_position[index].is_none() {
            place(index, &parent_position, &mut placed, &mut order);
        }
    }
    // Cycle de parenté (donnée corrompue) : les events restants gardent
    // leur ordre de lecture.
    for index in 0..len {
        if !placed[index] {
            placed[index] = true;
            order.push(index);
        }
    }
    order
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
#[derive(Clone)]
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

    /// 2.9.17 (#9 comment 6739207609) — Variante bornée mémoire :
    /// renvoie le digest brut 32 octets sans passer par l'hex
    /// (deux fois plus compact qu'un `String` hex). Utilisé par
    /// `repair_partial_imports` pour la dédup wire sur 1,5 M
    /// événements (budget RSS < 512 MiB).
    pub fn finish_bytes(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        let mut tail = [0u8; 72];
        tail[0] = 0x80;
        let pad = (56 - ((self.buffered as isize + 1) % 64) + 64) as usize % 64;
        let bit_len_bytes = bit_len.to_be_bytes();
        tail[1 + pad..1 + pad + 8].copy_from_slice(&bit_len_bytes);
        self.update(&tail[..1 + pad + 8]);
        debug_assert_eq!(self.buffered, 0);
        let mut out = [0u8; 32];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
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

/// 32-byte random secret bound to a single import. The key never leaves
/// process memory: `Debug`, `Display`, serde and `to_string` are deliberately
/// not implemented, and `Drop` zeroises the bytes.
///
/// Correlation within an import works because every call to
/// [`pseudonym`] with the same key and raw identity produces the same string;
/// correlation across imports is infeasible because each import carries a
/// fresh random key.
pub struct PseudonymKey([u8; 32]);

impl std::fmt::Debug for PseudonymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately redacted — raw bytes must never leak through log,
        // tracing, nor panic output.
        f.write_str("PseudonymKey(<redacted>)")
    }
}

impl PseudonymKey {
    /// Reads 32 bytes from `/dev/urandom`. Fails closed when the OS entropy
    /// source is unavailable — callers must surface
    /// `OIRAN_PSEUDONYM_KEY_UNAVAILABLE`, never fall back to an unkeyed hash.
    pub fn generate() -> Result<Self, &'static str> {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")
            .map_err(|_| "OIRAN_PSEUDONYM_KEY_UNAVAILABLE")?;
        let mut key = [0u8; 32];
        file.read_exact(&mut key)
            .map_err(|_| "OIRAN_PSEUDONYM_KEY_UNAVAILABLE")?;
        if key.iter().all(|b| *b == 0) {
            return Err("OIRAN_PSEUDONYM_KEY_UNAVAILABLE");
        }
        Ok(Self(key))
    }

    /// Default OS path for the deployment-wide pseudonym key. Operators may
    /// override it with the `OIRAN_PSEUDONYM_KEY_PATH` environment variable
    /// (or by calling [`load_or_generate`] with an explicit path).
    pub const DEFAULT_KEY_PATH: &'static str = "/var/lib/oiran/pseudonym.key";

    /// Reads the per-deployment key from `path`. Behaviour:
    /// - File exists with mode `0o600` owner-only → load its 32 bytes.
    /// - File exists with wider permissions → fail `OIRAN_PSEUDONYM_KEY_INSECURE`.
    /// - File exists and is unreadable or malformed → fail
    ///   `OIRAN_PSEUDONYM_KEY_UNAVAILABLE`.
    /// - File is absent → generate a fresh key via [`generate`], create the
    ///   parent directory (mode `0o700`), write the key atomically with mode
    ///   `0o600`, and return it. Any write-side failure maps to
    ///   `OIRAN_PSEUDONYM_KEY_UNAVAILABLE`.
    ///
    /// The key bytes are never logged, never exported via the API, never
    /// persisted in any dataset bundle. They only leave this struct through
    /// [`pseudonym`] as an HMAC output.
    pub fn load_or_generate(path: &std::path::Path) -> Result<Self, &'static str> {
        use std::io::Read;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        match std::fs::metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err("OIRAN_PSEUDONYM_KEY_INSECURE");
                }
                let mut file = std::fs::File::open(path)
                    .map_err(|_| "OIRAN_PSEUDONYM_KEY_UNAVAILABLE")?;
                let mut key = [0u8; 32];
                file.read_exact(&mut key)
                    .map_err(|_| "OIRAN_PSEUDONYM_KEY_UNAVAILABLE")?;
                let mut tail = [0u8; 1];
                if file.read(&mut tail).map_err(|_| "OIRAN_PSEUDONYM_KEY_UNAVAILABLE")? != 0 {
                    // File longer than 32 bytes — refuse rather than guess.
                    for byte in &mut key {
                        unsafe { std::ptr::write_volatile(byte, 0) };
                    }
                    return Err("OIRAN_PSEUDONYM_KEY_UNAVAILABLE");
                }
                if key.iter().all(|b| *b == 0) {
                    return Err("OIRAN_PSEUDONYM_KEY_UNAVAILABLE");
                }
                Ok(Self(key))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|_| "OIRAN_PSEUDONYM_KEY_UNAVAILABLE")?;
                    let _ = std::fs::set_permissions(
                        parent,
                        std::fs::Permissions::from_mode(0o700),
                    );
                }
                let tmp = path.with_extension("key.tmp");
                let write_result = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)
                    .and_then(|mut file| {
                        use std::io::Write;
                        file.write_all(&key.0)?;
                        file.sync_all()
                    });
                if write_result.is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    return Err("OIRAN_PSEUDONYM_KEY_UNAVAILABLE");
                }
                if std::fs::rename(&tmp, path).is_err() {
                    let _ = std::fs::remove_file(&tmp);
                    return Err("OIRAN_PSEUDONYM_KEY_UNAVAILABLE");
                }
                Ok(key)
            }
            Err(_) => Err("OIRAN_PSEUDONYM_KEY_UNAVAILABLE"),
        }
    }

    /// Resolves the effective key path: the `OIRAN_PSEUDONYM_KEY_PATH`
    /// environment variable if set, otherwise [`DEFAULT_KEY_PATH`].
    pub fn resolve_default_path() -> std::path::PathBuf {
        std::env::var_os("OIRAN_PSEUDONYM_KEY_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(Self::DEFAULT_KEY_PATH))
    }

    /// Constructor reserved for fixtures. Production imports MUST call
    /// [`load_or_generate`] so the key is a fresh random secret; `from_bytes`
    /// only exists to let tests pin a deterministic value and assert
    /// invariants (same key → same pseudonym, different key → different
    /// pseudonym).
    #[doc(hidden)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PseudonymKey {
    fn drop(&mut self) {
        // Best-effort zeroisation. Protects against swap/crash dumps, not
        // against a compiler that proves the memory unused — but since the
        // key is read back by `as_slice()`, the writes cannot be dropped
        // without a volatile hint.
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

/// HMAC-SHA256 implemented on top of the hand-rolled [`Sha256Hasher`]. No
/// external dependency is pulled in, and the key never flows into logs: the
/// struct carries only derived blocks.
struct HmacSha256 {
    inner: Sha256Hasher,
    outer: Sha256Hasher,
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut normalised = [0u8; 64];
        if key.len() > 64 {
            let digest_hex = sha256_hex(key);
            for i in 0..32 {
                let byte = u8::from_str_radix(&digest_hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
                normalised[i] = byte;
            }
        } else {
            normalised[..key.len()].copy_from_slice(key);
        }
        let mut i_pad = [0u8; 64];
        let mut o_pad = [0u8; 64];
        for i in 0..64 {
            i_pad[i] = normalised[i] ^ 0x36;
            o_pad[i] = normalised[i] ^ 0x5c;
        }
        let mut inner = Sha256Hasher::new();
        inner.update(&i_pad);
        let mut outer = Sha256Hasher::new();
        outer.update(&o_pad);
        // Scrub pad buffers; the key is still in `normalised`, so scrub that
        // too before the stack frame returns.
        for byte in &mut i_pad {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        for byte in &mut o_pad {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        for byte in &mut normalised {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        Self { inner, outer }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish_hex(mut self) -> String {
        let inner_hex = self.inner.finish_hex();
        // Convert 64-char hex digest back to 32 raw bytes to feed the outer
        // block, exactly as RFC 2104 requires.
        let mut inner_bytes = [0u8; 32];
        for i in 0..32 {
            inner_bytes[i] = u8::from_str_radix(&inner_hex[i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        self.outer.update(&inner_bytes);
        self.outer.finish_hex()
    }
}

/// Keyed pseudonym for subscriber-level identity bytes (IMSI, MEI, MSISDN,
/// user IDs). Uses HMAC-SHA256(key, label || 0x00 || bytes) and returns the
/// first 128 bits as `psn-<32 hex>`. Enumerating raw identities without the
/// key does not reveal the pseudonym, so the output is safe to export.
pub fn pseudonym(key: &PseudonymKey, label: &str, bytes: &[u8]) -> String {
    let mut mac = HmacSha256::new(key.as_slice());
    mac.update(label.as_bytes());
    mac.update(&[0u8]);
    mac.update(bytes);
    let hex = mac.finish_hex();
    format!("psn-{}", &hex[..32])
}

/// 2.9.9 (#9 comment 6725858177) : domaine unique de
/// pseudonymisation d'abonné partagé par SBI / N2 / N4. ANR2 a
/// prouvé que `decoder-sbi::sanitize_uri` utilisait le label `supi`
/// alors que `decoder-sbi::collect_json` utilisait `subscriber`,
/// rendant impossible l'égalité URI ↔ body au sein du SBI. Tous les
/// décodeurs qui veulent surfacer l'identité d'abonné DOIVENT
/// utiliser ce label — ne jamais le passer en dur.
pub const SUBSCRIBER_PSEUDO_DOMAIN: &str = "subscriber";
/// Shared domain for temporary radio identities. Assignment and later
/// presentation hash the canonical temporary component with this label.
pub const TEMPORARY_IDENTITY_PSEUDO_DOMAIN: &str = "temporary-mobile-identity";

/// 2.21.125 — domaine du pseudonyme d'une adresse IP d'UE. Une seule forme
/// d'entrée pour tous les décodeurs et pour la trace live : les OCTETS de
/// l'adresse (4 pour IPv4, 16 pour IPv6). Avant 2.21.125 le PFCP hachait
/// la valeur entière de l'IE (drapeaux compris), le SIP le texte de
/// l'adresse, la trace live les octets : trois pseudonymes différents
/// pour une même adresse, donc aucune égalité possible.
pub const UE_IP_PSEUDO_DOMAIN: &str = "pfcp-ue-ip";

/// Pseudonyme d'une adresse IP donnée par ses octets (4 ou 16). `None`
/// pour toute autre longueur.
pub fn pseudonym_ip_octets(key: &PseudonymKey, octets: &[u8]) -> Option<String> {
    match octets.len() {
        4 | 16 => Some(pseudonym(key, UE_IP_PSEUDO_DOMAIN, octets)),
        _ => None,
    }
}

/// Pseudonyme d'une adresse IP donnée en texte. L'adresse est normalisée
/// (`normalize_ip` : IPv4 projetée en IPv6, identifiant de zone) puis
/// réduite à ses octets. `None` si le texte n'est pas une adresse.
pub fn pseudonym_ip_text(key: &PseudonymKey, text: &str) -> Option<String> {
    match normalize_ip(text).parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(v4) => pseudonym_ip_octets(key, &v4.octets()),
        std::net::IpAddr::V6(v6) => pseudonym_ip_octets(key, &v6.octets()),
    }
}

/// Converts one canonical decimal subscriber identity to the shared domain.
/// Callers must decode transport-specific representations before invoking it.
pub fn pseudonym_subscriber_digits(key: &PseudonymKey, digits: &[u8]) -> String {
    debug_assert!(!digits.is_empty());
    debug_assert!(digits.iter().all(u8::is_ascii_digit));
    pseudonym(key, SUBSCRIBER_PSEUDO_DOMAIN, digits)
}

/// Decodes telephony BCD to its canonical decimal digit string. Filler
/// nibbles are ignored; any other non-decimal nibble rejects the input.
pub fn subscriber_digits_tbcd(bytes: &[u8], first_high_nibble: bool) -> Option<Vec<u8>> {
    let mut digits = Vec::with_capacity(bytes.len().saturating_mul(2));
    for (index, byte) in bytes.iter().copied().enumerate() {
        let nibbles = if index == 0 && first_high_nibble {
            [byte >> 4, 0x0f]
        } else {
            [byte & 0x0f, byte >> 4]
        };
        for nibble in nibbles {
            match nibble {
                0..=9 => digits.push(b'0' + nibble),
                0x0f => {}
                _ => return None,
            }
        }
    }
    (!digits.is_empty()).then_some(digits)
}

/// Produces one cross-protocol subscriber pseudonym from digit nibbles.
/// The returned value is opaque; the canonical digits never leave the
/// decoder. `first_high_nibble` covers EPS mobile identity octet 3, while
/// ordinary GTPv2-C TBCD starts with the low nibble.
pub fn pseudonym_subscriber_tbcd(
    key: &PseudonymKey,
    bytes: &[u8],
    first_high_nibble: bool,
) -> String {
    subscriber_digits_tbcd(bytes, first_high_nibble)
        .map(|digits| pseudonym_subscriber_digits(key, &digits))
        .unwrap_or_else(|| pseudonym(key, SUBSCRIBER_PSEUDO_DOMAIN, bytes))
}

/// Diameter User-Name is textual. Only its leading decimal identity is fed
/// to the common subscriber domain; realm/decoration is deliberately ignored.
pub fn pseudonym_subscriber_text(key: &PseudonymKey, value: &[u8]) -> String {
    let canonical = value
        .strip_prefix(b"imsi-")
        .or_else(|| value.strip_prefix(b"IMSI-"))
        .unwrap_or(value);
    let digits = canonical
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect::<Vec<_>>();
    if digits.is_empty() {
        pseudonym(key, SUBSCRIBER_PSEUDO_DOMAIN, value)
    } else {
        pseudonym_subscriber_digits(key, &digits)
    }
}

/// 2.9.9 (#9 comment 6725858177) : normalisation TEID partagée par
/// SBI / N2 / N4. ANR2 a prouvé des formats divergents sur le même
/// TEID numérique : SBI/N2 `0xd4a6`, N4 `0x0000d4a6`. La fonction
/// accepte `"d4a6"`, `"D4A6"`, `"0xd4a6"`, `"0x0000D4A6"`, et
/// `"0d54438"` (décimal explicite). Elle produit systématiquement un
/// `u32` ; la forme canonique lisible est `format!("0x{teid:x}")`.
/// Jamais de zero-padding dans la sortie — la comparaison égale deux
/// chaînes quelle que soit la largeur d'origine.
///
/// Règle de désambiguïsation décimal / hexa, strictement explicite
/// (la convention télécom par défaut est l'hexadécimal) :
///   * préfixe `0x` ou `0X` → hex.
///   * préfixe `0d` ou `0D` → décimal explicite.
///   * sinon → hex.
///
/// Note : une chaîne purement numérique sans préfixe (par exemple
/// `"11223344"`) est lue en **hex** (0x11223344), pas en décimal.
/// C'est le choix qu'imposent les traces réelles : SBI/N2/N4
/// publient toujours des TEIDs hex, parfois sans le préfixe `0x`.
/// Un producteur qui veut injecter du décimal doit préfixer `0d`.
pub fn normalize_teid_u32(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (body, radix) = if let Some(stripped) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        (stripped, 16)
    } else if let Some(stripped) = trimmed
        .strip_prefix("0d")
        .or_else(|| trimmed.strip_prefix("0D"))
    {
        (stripped, 10)
    } else {
        (trimmed, 16)
    };
    u32::from_str_radix(body, radix).ok()
}

/// 2.9.9 : même règle que `normalize_teid_u32` mais rend la forme
/// canonique `"0x{teid:x}"`. Pratique quand on compare des clés
/// dérivées de IEs sérialisées sous forme chaîne.
pub fn normalize_teid_hex(value: &str) -> Option<String> {
    normalize_teid_u32(value).map(|teid| format!("0x{teid:x}"))
}

/// 2.9.9 (#9 comment 6725858177) : normalisation IP partagée.
/// `::ffff:a.b.c.d` → `a.b.c.d`. `::1` reste `::1`. Un host-spec
/// `[2001:db8::1]:8080` est renvoyé entre crochets sans port
/// (callers trimment le port avant de normaliser). Trim complet des
/// zones scope `%eth0` au-delà de la lettre `%`.
pub fn normalize_ip(value: &str) -> String {
    let trimmed = value.trim();
    // Drop scope-id (RFC 4007 "%<zone>").
    let stripped = trimmed.split('%').next().unwrap_or(trimmed);
    // IPv4-mapped IPv6 → IPv4.
    if let Some(suffix) = stripped
        .strip_prefix("::ffff:")
        .or_else(|| stripped.strip_prefix("::FFFF:"))
    {
        if suffix
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.')
            && suffix.split('.').count() == 4
        {
            return suffix.to_string();
        }
    }
    stripped.to_string()
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
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "probe-1".into(),
            capture_point_id: "n2-bridge".into(),
            capture_id: "sha256:abc".into(),
            packet_references: vec![PacketReference {
                source_file: "x.pcapng".into(),
                sctp_association: None,
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

    /// 1.5.1 (2.9.4 — devmat #9 T2) : la sortie JSONL omet les champs
    /// `null` et les tableaux `[]` non essentiels. ANR2 a mesuré 2.6 GB /
    /// 1.23 M événements (p99 packet_references=1423 B sur SBI, dont
    /// ~9 sll2_* `null` par ref). On vérifie ici que :
    ///   * les 9 `sll2_*` à `null` ne figurent PAS dans la sortie ;
    ///   * `source_sha256`, `link_type` à `null` ne figurent PAS ;
    ///   * `parent_event_id`, `procedure`, `security_state`,
    ///     `source_byte_offset`, `sbi` à `null` ne figurent PAS ;
    ///   * `errors: []`, `evidence_references: []` vides ne figurent PAS ;
    ///   * `session_identifiers: []` et `information_elements: []` restent
    ///     émis (contrat de présence pour correlation-engine
    ///     `tunnel_keys`) ;
    ///   * les champs REQUIS (event_id, capture_id, timestamp,
    ///     packet_references.{source_file,packet_number,byte_offset,
    ///     interface_id,captured_length,original_length}, interface,
    ///     protocol, message_name, direction, source/destination_endpoint,
    ///     decoding_status, decoder_name, decoder_version,
    ///     raw_payload_reference) sont tous présents.
    #[test]
    fn to_json_omits_null_fields_and_empty_arrays_without_losing_required_keys() {
        let e = NormalizedEvent {
            event_id: "evt-abc".into(),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "probe-1".into(),
            capture_point_id: "n2-bridge".into(),
            capture_id: "sha256:cap".into(),
            packet_references: vec![PacketReference {
                source_file: "x.pcapng".into(),
                sctp_association: None,
                source_sha256: None,
                packet_number: 42,
                byte_offset: 100,
                interface_id: 0,
                link_type: None,
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
                seconds: 1,
                nanoseconds: 2,
                raw_ticks: 3,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "SBI".into(),
            protocol: Protocol::SbiHttp2,
            message_name: "N1N2MessageTransfer".into(),
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
            direction: Direction::RanToCore,
            session_identifiers: vec![],
            information_elements: vec![],
            decoder_name: "decoder-sbi".into(),
            decoder_version: "0.4.0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:payload".into(),
            evidence_references: vec![],
            sbi: None,
        };
        let out = e.to_json();
        // Omissions attendues :
        for omitted in [
            "sll2_protocol_type",
            "sll2_reserved",
            "sll2_interface_index",
            "sll2_arphrd_type",
            "sll2_packet_type",
            "sll2_address_length",
            "sll2_address",
            "source_sha256",
            "link_type",
            "parent_event_id",
            "procedure_code",
            "procedure",
            "security_state",
            "source_byte_offset",
            "\"errors\"",
            "evidence_references",
            "\"sbi\"",
        ] {
            assert!(
                !out.contains(omitted),
                "champ `{omitted}` doit être omis quand null/vide, got: {out}"
            );
        }
        // Présences requises :
        for required in [
            "\"event_id\":\"evt-abc\"",
            "\"capture_id\":\"sha256:cap\"",
            "\"packet_number\":42",
            "\"byte_offset\":100",
            "\"captured_length\":64",
            "\"source_file\":\"x.pcapng\"",
            "\"interface\":\"SBI\"",
            "\"protocol\":\"SBI-HTTP2\"",
            "\"message_name\":\"N1N2MessageTransfer\"",
            "\"direction\":\"RAN_TO_CORE\"",
            "\"decoding_status\":\"DECODED\"",
            "\"schema_version\":\"1.6.0\"",
            // présence même vide
            "\"session_identifiers\":[]",
            "\"information_elements\":[]",
        ] {
            assert!(
                out.contains(required),
                "champ requis `{required}` manquant, got: {out}"
            );
        }
        // JSON parsable sans ambiguïté (validation structurelle).
        let _: serde_json::Value =
            serde_json::from_str(&out).expect("output must parse as valid JSON");
    }

    /// 1.5.1 : mesure avant/après — sur un événement représentatif SBI
    /// (10 packet_references, tous sll2_* null), la compaction doit
    /// réduire la taille de ≥ 30 % sans perte d'information.
    #[test]
    fn to_json_reduces_size_by_at_least_30_percent_on_sbi_shape_with_10_refs() {
        // Événement SBI stylisé : 10 refs (SBI = HTTP/2 stream segmenté),
        // tous sll2_* = None ; 3 IEs avec id / value / raw_sha256 à null
        // sauf name/length/status. Mesure la taille produite par
        // `to_json` vs un modèle fidèle de la forme pré-1.5.1 (nulls émis).
        let ref_template = PacketReference {
            source_file: "/captures/5g-session-abcdef/pcap/sbi/sbi.pcapng-00001.pcapng".into(),
            sctp_association: None,
            source_sha256: None,
            packet_number: 0,
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
            captured_length: 1500,
            original_length: 1500,
        };
        let mut refs = Vec::with_capacity(10);
        for i in 0..10u64 {
            let mut r = ref_template.clone();
            r.packet_number = 100 + i;
            r.byte_offset = i * 1500;
            refs.push(r);
        }
        let ies = (0..3)
            .map(|i| InformationElement {
                id: None,
                name: format!("IE-{i}"),
                length: 8,
                value: None,
                raw_sha256: None,
                status: DecodeStatus::Decoded,
            })
            .collect::<Vec<_>>();
        let e = NormalizedEvent {
            event_id: "evt-sbi".into(),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "oiran-vprobe-local-01".into(),
            capture_point_id: "sbi".into(),
            capture_id: "sha256:87d45e4b08dcb82ccb811f978c4072c7bb04eaf9acd56650667752202fb72e24".into(),
            packet_references: refs,
            timestamp: ExactTimestamp {
                seconds: 1_794_000_000,
                nanoseconds: 123_456_000,
                raw_ticks: 1_794_000_000_123_456_000,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "SBI".into(),
            protocol: Protocol::SbiHttp2,
            message_name: "N1N2MessageTransfer".into(),
            message_type: 0,
            procedure_code: None,
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: Endpoint {
                address: "10.77.22.10".into(),
                port: None,
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.77.22.13".into(),
                port: None,
                network_function: None,
            },
            direction: Direction::RanToCore,
            session_identifiers: vec![],
            information_elements: ies,
            decoder_name: "decoder-sbi".into(),
            decoder_version: "0.4.0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:x".into(),
            evidence_references: vec![],
            sbi: None,
        };
        let after = e.to_json();
        // Reconstruit la forme pré-1.5.1 : mêmes 10 refs avec les 9
        // sll2_* / source_sha256 / link_type émis comme `null`, 3 IEs
        // avec id/value/raw_sha256 émis comme `null`, plus les
        // top-level options `parent_event_id`, `procedure_code`,
        // `procedure`, `security_state`, `source_byte_offset`, `sbi`
        // à `null`, et `errors: []`, `evidence_references: []`.
        let legacy_packet = |p: &PacketReference| -> String {
            format!(
                "{{\"source_file\":\"{}\",\"source_sha256\":null,\"packet_number\":{},\"byte_offset\":{},\"interface_id\":{},\"link_type\":null,\"sll2_protocol_type\":null,\"sll2_reserved\":null,\"sll2_interface_index\":null,\"sll2_arphrd_type\":null,\"sll2_packet_type\":null,\"sll2_address_length\":null,\"sll2_address\":null,\"captured_length\":{},\"original_length\":{}}}",
                escape(&p.source_file),
                p.packet_number,
                p.byte_offset,
                p.interface_id,
                p.captured_length,
                p.original_length,
            )
        };
        let legacy_ie = |ie: &InformationElement| -> String {
            format!(
                "{{\"id\":null,\"name\":\"{}\",\"length\":{},\"value\":null,\"raw_sha256\":null,\"status\":\"{}\"}}",
                escape(&ie.name),
                ie.length,
                ie.status.as_str(),
            )
        };
        let legacy_packets = e
            .packet_references
            .iter()
            .map(legacy_packet)
            .collect::<Vec<_>>()
            .join(",");
        let legacy_ies = e
            .information_elements
            .iter()
            .map(legacy_ie)
            .collect::<Vec<_>>()
            .join(",");
        let before = format!(
            "{{\"event_id\":\"{}\",\"stable_event_key\":\"{}\",\"parent_event_id\":null,\"probe_id\":\"{}\",\"capture_point_id\":\"{}\",\"capture_id\":\"{}\",\"packet_references\":[{}],\"timestamp\":{{\"seconds\":{},\"nanoseconds\":{},\"raw_ticks\":{},\"resolution_base\":{},\"resolution_exponent\":{},\"display\":\"{}\"}},\"interface\":\"{}\",\"protocol\":\"{}\",\"message_name\":\"{}\",\"message_type\":{},\"procedure_code\":null,\"procedure\":null,\"security_state\":null,\"source_byte_offset\":null,\"source_endpoint\":{},\"destination_endpoint\":{},\"direction\":\"{}\",\"session_identifiers\":[],\"information_elements\":[{}],\"decoder_name\":\"{}\",\"decoder_version\":\"{}\",\"schema_version\":\"{}\",\"decoding_status\":\"{}\",\"errors\":[],\"raw_payload_reference\":\"{}\",\"evidence_references\":[],\"sbi\":null}}",
            escape(&e.event_id),
            escape(&e.stable_event_key),
            escape(&e.probe_id),
            escape(&e.capture_point_id),
            escape(&e.capture_id),
            legacy_packets,
            e.timestamp.seconds,
            e.timestamp.nanoseconds,
            e.timestamp.raw_ticks,
            e.timestamp.resolution_base,
            e.timestamp.resolution_exponent,
            escape(&e.timestamp.display()),
            escape(&e.interface),
            e.protocol.as_str(),
            escape(&e.message_name),
            e.message_type,
            endpoint_json(&e.source_endpoint),
            endpoint_json(&e.destination_endpoint),
            e.direction.as_str(),
            legacy_ies,
            escape(&e.decoder_name),
            escape(&e.decoder_version),
            e.schema_version,
            e.decoding_status.as_str(),
            escape(&e.raw_payload_reference),
        );
        let before_b = before.len();
        let after_b = after.len();
        let reduction = 1.0 - (after_b as f64 / before_b as f64);
        // Toujours émettre la mesure (eprintln survit sous --nocapture
        // et fournit la preuve du gain pour le rapport #9).
        eprintln!(
            "[T2 to_json SBI shape 10 refs] before={before_b} B after={after_b} B reduction={:.3}%",
            reduction * 100.0
        );
        assert!(
            reduction >= 0.30,
            "attendu ≥ 30% de réduction ; before={before_b} after={after_b} reduction={reduction:.3}"
        );
        // Les deux JSON doivent rester strictement valides.
        let _: serde_json::Value =
            serde_json::from_str(&before).expect("legacy JSON must parse");
        let _: serde_json::Value =
            serde_json::from_str(&after).expect("compact JSON must parse");
    }
    // 1.6.0 (POLARIS 2.21.91, défaut #9 7033006772 + raffinement #9 7034553419)
    // — `derive_stable_event_key` est la fonction UNIQUE utilisée par les deux
    // chemins (live + publication). Ces tests valident :
    //   * basename extrait du chemin, indifférent au répertoire parent
    //     (live = ring dir, publi = staging dir ; même fichier → même clé) ;
    //   * encodage stable `{basename}|{iid}|{pkt}|{off}|{protocol}|{ordinal}` ;
    //   * assign_stable_event_key no-op si chemin vide ou pas de ref ;
    //   * `packet_lookup_key` est le préfixe qui regroupe les events d'un
    //     même paquet (utilisé comme clé du compteur d'ordinaux côté
    //     `oiran-decode::emit_events`).
    #[test]
    fn derive_stable_event_key_strips_parent_directory() {
        let live_path = "/var/lib/oiran/ring/n3/n3_live_00032_20261120.pcapng";
        let publish_path = "/tmp/base/staging/n3_live_00032_20261120.pcapng";
        let a = derive_stable_event_key(live_path, 2, 42, 100, "NGAP", 0);
        let b = derive_stable_event_key(publish_path, 2, 42, 100, "NGAP", 0);
        assert_eq!(a, b, "basename identique → clé identique (live↔publi)");
        assert_eq!(a, "n3_live_00032_20261120.pcapng|2|42|100|NGAP|0");
    }

    #[test]
    fn derive_stable_event_key_bare_basename() {
        // Caller qui fournit uniquement le basename (sans répertoire).
        let key = derive_stable_event_key("ngap_00001.pcapng", 0, 1, 24, "NGAP", 0);
        assert_eq!(key, "ngap_00001.pcapng|0|1|24|NGAP|0");
    }

    #[test]
    fn derive_stable_event_key_different_packets_diverge() {
        let base = "/x/f.pcapng";
        assert_ne!(
            derive_stable_event_key(base, 0, 1, 24, "NGAP", 0),
            derive_stable_event_key(base, 0, 2, 24, "NGAP", 0)
        );
        assert_ne!(
            derive_stable_event_key(base, 0, 1, 24, "NGAP", 0),
            derive_stable_event_key(base, 0, 1, 48, "NGAP", 0)
        );
        assert_ne!(
            derive_stable_event_key(base, 0, 1, 24, "NGAP", 0),
            derive_stable_event_key(base, 1, 1, 24, "NGAP", 0)
        );
    }

    #[test]
    fn derive_stable_event_key_discriminates_siblings_via_protocol_and_ordinal() {
        // NGAP parent et NAS enfant au même paquet : même prefix, mais
        // la clé complète diffère grâce à `(protocol, ordinal)`.
        let base = "/x/f.pcapng";
        let parent = derive_stable_event_key(base, 0, 7, 40, "NGAP", 0);
        let child = derive_stable_event_key(base, 0, 7, 40, "NAS-5GMM", 1);
        assert_ne!(
            parent, child,
            "clé doit discriminer parent (NGAP|0) et enfant (NAS|1)"
        );
        assert!(parent.ends_with("|NGAP|0"));
        assert!(child.ends_with("|NAS-5GMM|1"));
    }

    #[test]
    fn packet_lookup_key_is_prefix_shared_by_same_packet_events() {
        // Le prefix sert au compteur d'ordinaux côté oiran-decode : tous
        // les events qui partagent ce prefix sont numérotés 0, 1, 2, …
        let lookup = packet_lookup_key("/x/f.pcapng", 0, 7, 40);
        let parent = derive_stable_event_key("/x/f.pcapng", 0, 7, 40, "NGAP", 0);
        let child = derive_stable_event_key("/x/f.pcapng", 0, 7, 40, "NAS-5GMM", 1);
        assert_eq!(lookup, "f.pcapng|0|7|40");
        assert!(parent.starts_with(&lookup));
        assert!(child.starts_with(&lookup));
    }

    #[test]
    fn assign_stable_event_key_is_noop_on_empty_path() {
        let mut e = event();
        e.assign_stable_event_key("", 0);
        assert!(e.stable_event_key.is_empty());
    }

    #[test]
    fn assign_stable_event_key_populates_from_first_packet_reference() {
        let mut e = event();
        e.assign_stable_event_key("/ring/n2/n2_live_00007.pcapng", 0);
        // event() fournit iid=2, pkt=7, off=40, protocol=NGAP.
        assert_eq!(e.stable_event_key, "n2_live_00007.pcapng|2|7|40|NGAP|0");
    }

    #[test]
    fn assign_stable_event_key_honours_ordinal() {
        // Même paquet, deux events — 2e event stampé avec ordinal=1.
        let mut a = event();
        let mut b = event();
        a.assign_stable_event_key("/ring/n2/f.pcapng", 0);
        b.assign_stable_event_key("/ring/n2/f.pcapng", 1);
        assert_ne!(a.stable_event_key, b.stable_event_key);
        assert!(a.stable_event_key.ends_with("|0"));
        assert!(b.stable_event_key.ends_with("|1"));
    }

    /// 2.21.102 (défaut ANR1 #9 7044712668, ordre #9 7045732954) —
    /// `backfill_stable_event_keys_in_callflow` patche en place les
    /// events d'un callflow stocké SANS `stable_event_key`. La formule
    /// est strictement celle de `derive_stable_event_key`, et l'ordinal
    /// est 0-based dans l'ordre d'apparition des events.
    #[test]
    fn backfill_stable_event_keys_in_callflow_fills_missing_keys_in_order() {
        let mut flow = serde_json::json!({
            "session_id": "s1",
            "events": [
                {
                    "event_id": "evt-ngap",
                    "protocol": "NGAP",
                    "packet_references": [{
                        "source_file": "/ring/n2/N2.pcapng",
                        "packet_number": 7u64,
                        "byte_offset": 40u64,
                        "interface_id": 0u32
                    }]
                },
                // Même paquet → ordinal 1 (NAS enfant).
                {
                    "event_id": "evt-nas",
                    "protocol": "NAS-5GS-MM",
                    "packet_references": [{
                        "source_file": "/ring/n2/N2.pcapng",
                        "packet_number": 7u64,
                        "byte_offset": 40u64,
                        "interface_id": 0u32
                    }]
                },
                // Paquet différent → ordinal 0.
                {
                    "event_id": "evt-ngap-release",
                    "protocol": "NGAP",
                    "packet_references": [{
                        "source_file": "/ring/n2/N2.pcapng",
                        "packet_number": 42u64,
                        "byte_offset": 1024u64,
                        "interface_id": 0u32
                    }]
                }
            ]
        });
        let (patched, skipped) = backfill_stable_event_keys_in_callflow(&mut flow);
        assert_eq!(patched, 3);
        assert_eq!(skipped, 0);
        let events = flow["events"].as_array().unwrap();
        assert_eq!(events[0]["stable_event_key"], "N2.pcapng|0|7|40|NGAP|0");
        assert_eq!(events[1]["stable_event_key"], "N2.pcapng|0|7|40|NAS-5GS-MM|1");
        assert_eq!(events[2]["stable_event_key"], "N2.pcapng|0|42|1024|NGAP|0");
    }

    /// 2.21.102 — un event déjà porteur d'un `stable_event_key` non
    /// vide est laissé intact (idempotent).
    #[test]
    fn backfill_stable_event_keys_in_callflow_preserves_existing_keys() {
        let mut flow = serde_json::json!({
            "events": [
                {
                    "event_id": "already-has-key",
                    "stable_event_key": "explicit|0|1|0|NGAP|0",
                    "protocol": "NGAP",
                    "packet_references": [{
                        "source_file": "x",
                        "packet_number": 1u64,
                        "byte_offset": 0u64,
                        "interface_id": 0u32
                    }]
                }
            ]
        });
        let (patched, skipped) = backfill_stable_event_keys_in_callflow(&mut flow);
        assert_eq!(patched, 0);
        assert_eq!(skipped, 0);
        assert_eq!(
            flow["events"][0]["stable_event_key"],
            "explicit|0|1|0|NGAP|0"
        );
    }

    /// 2.21.102 — un event sans `packet_references` est skippé
    /// (compté dans `skipped`) et son champ reste absent — écart
    /// à déclarer OUVERT côté caller si des events sans provenance
    /// existent dans un dataset.
    #[test]
    fn backfill_stable_event_keys_in_callflow_skips_events_without_packet_references() {
        let mut flow = serde_json::json!({
            "events": [
                {"event_id": "orphan", "protocol": "NGAP"},
                {
                    "event_id": "ok",
                    "protocol": "NGAP",
                    "packet_references": [{
                        "source_file": "x",
                        "packet_number": 1u64,
                        "byte_offset": 0u64,
                        "interface_id": 0u32
                    }]
                }
            ]
        });
        let (patched, skipped) = backfill_stable_event_keys_in_callflow(&mut flow);
        assert_eq!(patched, 1);
        assert_eq!(skipped, 1);
        assert!(flow["events"][0].get("stable_event_key").is_none());
        assert_eq!(flow["events"][1]["stable_event_key"], "x|0|1|0|NGAP|0");
    }

    #[test]
    fn stable_event_key_is_emitted_in_json_even_when_empty() {
        let mut e = event();
        e.assign_deterministic_id();
        let out = e.to_json();
        assert!(
            out.contains("\"stable_event_key\":\"\""),
            "champ présent même vide ; got: {out}"
        );
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

    #[test]
    fn hmac_sha256_matches_rfc4231_test_vectors() {
        // RFC 4231 §4.2 test case 1: key = 0x0b repeated 20 bytes, data = b"Hi There".
        let mut mac = HmacSha256::new(&[0x0b; 20]);
        mac.update(b"Hi There");
        assert_eq!(
            mac.finish_hex(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // RFC 4231 §4.3 test case 2: key = "Jefe", data = "what do ya want for nothing?"
        let mut mac = HmacSha256::new(b"Jefe");
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            mac.finish_hex(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn same_identity_and_same_key_produces_identical_pseudonym() {
        // Correlation within one import: the same IMSI bytes must always
        // yield the same pseudonym under the same key, otherwise the S1-MME /
        // S11 / S1-U events cannot be stitched back to the same subscriber.
        let key = PseudonymKey::from_bytes([0x24; 32]);
        let imsi = b"\x00\x10\x00\x00\x00\x00\x00\x12";
        assert_eq!(
            pseudonym(&key, "subscriber", imsi),
            pseudonym(&key, "subscriber", imsi)
        );
        // 128-bit output: `psn-` prefix + 32 hex chars.
        let output = pseudonym(&key, "subscriber", imsi);
        assert!(output.starts_with("psn-"));
        assert_eq!(output.len(), 4 + 32);
        assert!(output[4..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_keys_produce_different_pseudonyms_for_the_same_identity() {
        // Impossible correlation across imports: two imports of the same raw
        // IMSI must emit disjoint pseudonyms, so no third party can join
        // exports back to a single subscriber by enumerating identities.
        let left = PseudonymKey::from_bytes([0x01; 32]);
        let right = PseudonymKey::from_bytes([0x02; 32]);
        let imsi = b"\x00\x10\x00\x00\x00\x00\x00\x12";
        assert_ne!(
            pseudonym(&left, "subscriber", imsi),
            pseudonym(&right, "subscriber", imsi)
        );
    }

    #[test]
    fn labels_separate_identities_of_the_same_type_bytes() {
        // Different labels are domain-separated — the same bytes under
        // `subscriber` and under `mei` must yield different pseudonyms so
        // operators cannot infer an IMSI from an IMEI (or vice-versa).
        let key = PseudonymKey::from_bytes([0x33; 32]);
        let bytes = b"\x01\x02\x03\x04";
        assert_ne!(
            pseudonym(&key, "subscriber", bytes),
            pseudonym(&key, "mei", bytes)
        );
    }

    #[test]
    fn pseudonym_is_not_recoverable_from_identity_alone() {
        // Without the per-import secret, enumerating raw IMSIs cannot reveal
        // the exported pseudonym. We assert that two independent key draws
        // produce different outputs for the full published IMSI space mocked
        // here, so a brute-force attacker would need the key to match.
        let imsi = b"\x00\x10\x00\x00\x00\x00\x00\x12";
        // Approximation of "the attacker has every IMSI but no key": any
        // plausible unkeyed hash of the IMSI is unrelated to the keyed
        // pseudonym under a random key.
        let key = PseudonymKey::generate().expect("urandom available");
        assert_ne!(
            pseudonym(&key, "subscriber", imsi),
            format!("psn-{:032x}", stable_hash(imsi))
        );
    }

    #[test]
    fn pseudonym_key_debug_does_not_leak_bytes() {
        // Guard against accidental log/panic disclosures.
        let key = PseudonymKey::from_bytes([0xde; 32]);
        let dbg = format!("{key:?}");
        assert_eq!(dbg, "PseudonymKey(<redacted>)");
        assert!(!dbg.contains("de"));
        assert!(!dbg.contains("222"));
    }

    #[test]
    fn pseudonym_key_generate_is_random_and_nonzero() {
        // Smoke check: two consecutive generates almost always differ, and
        // neither is all-zeros (which would mean the entropy source misfed).
        let a = PseudonymKey::generate().expect("urandom available");
        let b = PseudonymKey::generate().expect("urandom available");
        assert_ne!(a.as_slice(), b.as_slice());
        assert!(a.as_slice().iter().any(|byte| *byte != 0));
        assert!(b.as_slice().iter().any(|byte| *byte != 0));
    }

    /// 2.9.9 (#9 comment 6725858177) : ANR2 a prouvé que le même TEID
    /// numérique apparaît sous `0xd4a6` (SBI, N2) et `0x0000d4a6` (N4).
    /// La normalisation partagée doit égaler les deux écritures.
    #[test]
    fn normalize_teid_accepts_every_format_anr2_observed_plus_decimal() {
        // ANR2 production shapes: SBI / N2 `0xd4a6`, N4 `0x0000d4a6`.
        assert_eq!(normalize_teid_u32("0xd4a6"), Some(0xd4a6));
        assert_eq!(normalize_teid_u32("0x0000d4a6"), Some(0xd4a6));
        assert_eq!(normalize_teid_u32("0xD4A6"), Some(0xd4a6));
        assert_eq!(normalize_teid_u32("0X0000D4A6"), Some(0xd4a6));
        // Without 0x prefix : hex by default (télécom convention).
        assert_eq!(normalize_teid_u32("d4a6"), Some(0xd4a6));
        assert_eq!(normalize_teid_u32("D4A6"), Some(0xd4a6));
        // 2.9.9 : une chaîne sans préfixe est hex, même quand elle
        // ne contient que des chiffres — sinon `0x11223344` round-
        // trip sur `format!("{teid:x}")` serait relu en décimal
        // (= 0xab4130). Convention : hex partout, décimal
        // explicite via `0d`.
        assert_eq!(normalize_teid_u32("11223344"), Some(0x11223344));
        assert_eq!(normalize_teid_u32("0d54438"), Some(54438));
        assert_eq!(normalize_teid_u32("0D54438"), Some(54438));
        // Canonical hex form: never zero-padded, lower-case.
        assert_eq!(normalize_teid_hex("0x0000d4a6"), Some("0xd4a6".into()));
        assert_eq!(normalize_teid_hex("0xd4a6"), Some("0xd4a6".into()));
        assert_eq!(normalize_teid_hex("d4a6"), Some("0xd4a6".into()));
        assert_eq!(normalize_teid_hex("D4A6"), Some("0xd4a6".into()));
        assert_eq!(normalize_teid_hex("0d54438"), Some("0xd4a6".into()));
        // Garbage → None.
        assert_eq!(normalize_teid_u32(""), None);
        assert_eq!(normalize_teid_u32("not-a-teid"), None);
        assert_eq!(normalize_teid_u32("0xGGG"), None);
    }

    /// 2.9.9 (#9 comment 6725858177) : SBI porte des endpoints en
    /// IPv4-mapped IPv6 (`::ffff:10.77.22.13`) sur certaines
    /// implémentations ; la clé commune cross-plane doit égaler la
    /// forme IPv4 pure utilisée par N2 et N4.
    #[test]
    fn normalize_ip_strips_ipv4_mapped_prefix_and_scope_id() {
        assert_eq!(normalize_ip("10.77.22.13"), "10.77.22.13");
        assert_eq!(normalize_ip("::ffff:10.77.22.13"), "10.77.22.13");
        assert_eq!(normalize_ip("::FFFF:10.77.22.13"), "10.77.22.13");
        // Pure IPv6 unchanged.
        assert_eq!(normalize_ip("2001:db8::1"), "2001:db8::1");
        assert_eq!(normalize_ip("::1"), "::1");
        // Scope id dropped.
        assert_eq!(normalize_ip("fe80::1%eth0"), "fe80::1");
    }

    /// 2.9.9 (#9 comment 6725858177) : `sanitize_uri` utilisait
    /// `"supi"` et `collect_json` `"subscriber"`. Même SUPI, deux
    /// pseudos différents — rattachement abonné impossible. Le
    /// nouveau `SUBSCRIBER_PSEUDO_DOMAIN` est la seule constante
    /// autorisée côté SBI (URI + body).
    #[test]
    fn subscriber_pseudo_domain_is_the_single_shared_label() {
        assert_eq!(SUBSCRIBER_PSEUDO_DOMAIN, "subscriber");
        let key = PseudonymKey::from_bytes([0x24; 32]);
        let supi = b"imsi-208934000000001";
        // Two calls with the shared domain must produce the same
        // pseudonym — prouvant qu'un URI pseudonymisé et un body
        // pseudonymisé se comparent à l'identique.
        let uri_side = pseudonym(&key, SUBSCRIBER_PSEUDO_DOMAIN, supi);
        let body_side = pseudonym(&key, SUBSCRIBER_PSEUDO_DOMAIN, supi);
        assert_eq!(uri_side, body_side);
        // Appeler l'ancien domaine `"supi"` doit diverger — c'est
        // exactement le défaut 2.9.8 qu'ANR2 a mis en évidence.
        let legacy_uri = pseudonym(&key, "supi", supi);
        assert_ne!(legacy_uri, body_side);
    }

    #[test]
    fn subscriber_pseudonym_matches_gtpv2_eps_nas_and_diameter_encodings() {
        let key = PseudonymKey::from_bytes([0x5a; 32]);
        let gtpv2_tbcd = [0x21, 0x43, 0xf5];
        let eps_mobile_identity = [0x19, 0x32, 0x54];
        let diameter_user_name = b"12345@epc.invalid";
        let sbi_supi = [105, 109, 115, 105, 45, 49, 50, 51, 52, 53];
        let expected = pseudonym_subscriber_tbcd(&key, &gtpv2_tbcd, false);
        assert_eq!(
            expected,
            pseudonym_subscriber_tbcd(&key, &eps_mobile_identity, true)
        );
        assert_eq!(expected, pseudonym_subscriber_text(&key, diameter_user_name));
        assert_eq!(expected, pseudonym_subscriber_text(&key, &sbi_supi));
    }

    fn deployment_key_path(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oiran-pseudonym-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("pseudonym.key")
    }

    #[test]
    fn load_or_generate_creates_the_key_on_first_call_and_reloads_it_on_second() {
        // 2.7.6 adjusted: per-deployment key generated once, re-read on
        // subsequent calls. Two consecutive calls from different "processes"
        // (two separate load_or_generate invocations against the same path)
        // must yield the exact same key — that is what makes continuous
        // import dedup survive a probe restart.
        let path = deployment_key_path("first-then-reload");
        let a = PseudonymKey::load_or_generate(&path).expect("first call generates");
        let b = PseudonymKey::load_or_generate(&path).expect("second call reloads");
        assert_eq!(a.as_slice(), b.as_slice());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_or_generate_writes_the_key_file_with_mode_0600_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = deployment_key_path("mode-check");
        let _ = PseudonymKey::load_or_generate(&path).expect("generates");
        let metadata = std::fs::metadata(&path).expect("file was created");
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_or_generate_rejects_a_wider_permission_set_fail_closed() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = deployment_key_path("insecure-perms");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .unwrap();
        file.write_all(&[0x11; 32]).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert_eq!(
            PseudonymKey::load_or_generate(&path).err(),
            Some("OIRAN_PSEUDONYM_KEY_INSECURE"),
            "a world-readable key file must not be accepted"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn load_or_generate_rejects_a_truncated_or_oversized_key_file() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let short = deployment_key_path("short-key");
        std::fs::create_dir_all(short.parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&short)
            .unwrap();
        file.write_all(&[0x11; 16]).unwrap();
        drop(file);
        assert_eq!(
            PseudonymKey::load_or_generate(&short).err(),
            Some("OIRAN_PSEUDONYM_KEY_UNAVAILABLE")
        );
        let _ = std::fs::remove_dir_all(short.parent().unwrap());

        let long = deployment_key_path("long-key");
        std::fs::create_dir_all(long.parent().unwrap()).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&long)
            .unwrap();
        file.write_all(&[0x22; 48]).unwrap();
        drop(file);
        assert_eq!(
            PseudonymKey::load_or_generate(&long).err(),
            Some("OIRAN_PSEUDONYM_KEY_UNAVAILABLE")
        );
        let _ = std::fs::remove_dir_all(long.parent().unwrap());
    }

    #[test]
    fn resolve_default_path_honours_the_environment_variable_and_falls_back_otherwise() {
        // We cannot flip the global env safely under cargo test's threaded
        // harness, so we test the pure helper in both branches via a single
        // observation per process state.
        let resolved = PseudonymKey::resolve_default_path();
        if let Some(explicit) = std::env::var_os("OIRAN_PSEUDONYM_KEY_PATH") {
            assert_eq!(resolved, std::path::PathBuf::from(explicit));
        } else {
            assert_eq!(resolved, std::path::PathBuf::from(PseudonymKey::DEFAULT_KEY_PATH));
        }
    }

    /// 1.8.0 — stamp vide : bit-identique à `to_json()` ; stamp vtap :
    /// `probe_type`/`timestamp_source` présents, `probe_id` remplacé.
    #[test]
    fn to_json_with_probe_is_identical_when_empty_and_stamps_vtap() {
        let event = event();
        assert_eq!(event.to_json(), event.to_json_with_probe(&ProbeStamp::default()));
        let stamped = event.to_json_with_probe(&ProbeStamp {
            probe_id: Some("lab-vtap".into()),
            probe_type: Some("vtap".into()),
            physical_link: None,
            timestamp_source: Some("ebpf_monotonic".into()),
        });
        assert!(stamped.contains("\"probe_id\":\"lab-vtap\",\"probe_type\":\"vtap\",\"timestamp_source\":\"ebpf_monotonic\""), "{stamped}");
        assert!(!stamped.contains("physical_link"));
    }

}

#[cfg(test)]
mod ue_ip_pseudonym_tests {
    use super::*;

    /// 2.21.125 — une adresse donne le même pseudonyme quelle que soit sa
    /// présentation (octets, texte, IPv4 projetée en IPv6), et deux
    /// adresses différentes donnent deux pseudonymes.
    #[test]
    fn one_address_one_pseudonym_whatever_its_presentation_2_21_125() {
        let key = PseudonymKey::from_bytes([7; 32]);
        let octets = pseudonym_ip_octets(&key, &[10, 45, 0, 2]).unwrap();
        assert_eq!(pseudonym_ip_text(&key, "10.45.0.2").as_deref(), Some(octets.as_str()));
        assert_eq!(pseudonym_ip_text(&key, " 10.45.0.2 ").as_deref(), Some(octets.as_str()));
        assert_eq!(pseudonym_ip_text(&key, "::ffff:10.45.0.2").as_deref(), Some(octets.as_str()));
        assert_eq!(octets, pseudonym(&key, UE_IP_PSEUDO_DOMAIN, &[10, 45, 0, 2]));
        assert_ne!(pseudonym_ip_text(&key, "10.45.0.3").unwrap(), octets);
        let v6 = pseudonym_ip_text(&key, "2001:db8::1").unwrap();
        let mut v6_octets = [0u8; 16];
        v6_octets[0] = 0x20;
        v6_octets[1] = 0x01;
        v6_octets[2] = 0x0d;
        v6_octets[3] = 0xb8;
        v6_octets[15] = 1;
        assert_eq!(pseudonym_ip_octets(&key, &v6_octets).as_deref(), Some(v6.as_str()));
        assert_eq!(pseudonym_ip_text(&key, "sip.example.invalid"), None);
        assert_eq!(pseudonym_ip_octets(&key, &[0x02, 10, 45, 0, 2]), None);
    }
}

#[cfg(test)]
mod in_packet_order_tests {
    use super::*;

    fn order(events: &[(&'static str, Option<&'static str>)]) -> Vec<&'static str> {
        emission_order(events.len(), |i| events[i])
            .into_iter()
            .map(|i| events[i].0)
            .collect()
    }

    /// 1.12.0 (POLARIS 2.21.133) — l'ordre d'émission reconstitué met le
    /// parent avant ses enfants quel que soit l'ordre de lecture, garde
    /// l'ordre de lecture entre events sans parenté, suit la profondeur,
    /// et rend une permutation même sur une parenté cyclique ou un parent
    /// hors du paquet.
    #[test]
    fn emission_order_puts_each_parent_before_its_children_2_21_133() {
        assert_eq!(order(&[("nas", Some("ngap")), ("ngap", None)]), vec!["ngap", "nas"]);
        assert_eq!(order(&[("ngap", None), ("nas", Some("ngap"))]), vec!["ngap", "nas"]);
        // Deux messages sans parenté : ordre de lecture gardé.
        assert_eq!(order(&[("b", None), ("a", None)]), vec!["b", "a"]);
        // Deux NGAP groupés dans un paquet, chacun avec son NAS, lus triés
        // par identifiant : chaque parent suivi de son enfant.
        assert_eq!(
            order(&[("c1", Some("p1")), ("c2", Some("p2")), ("p1", None), ("p2", None)]),
            vec!["p1", "c1", "p2", "c2"]
        );
        // Petit-enfant.
        assert_eq!(
            order(&[("g", Some("c")), ("c", Some("p")), ("p", None)]),
            vec!["p", "c", "g"]
        );
        // Parent hors du paquet : traité comme sans parent.
        assert_eq!(order(&[("c", Some("absent")), ("p", None)]), vec!["c", "p"]);
        // Cycle (donnée corrompue) : permutation complète, ordre de lecture.
        assert_eq!(order(&[("x", Some("y")), ("y", Some("x"))]), vec!["x", "y"]);
        // Auto-référence.
        assert_eq!(order(&[("x", Some("x"))]), vec!["x"]);
    }

    /// 1.12.0 — `backfill_stable_event_keys_in_callflow` numérote un
    /// callflow stocké dans l'ordre d'affichage (enfant avant parent) comme
    /// le décodeur : parent 0, enfant 1. Avant : enfant 0, parent 1.
    #[test]
    fn callflow_backfill_numbers_the_parent_first_2_21_133() {
        let reference = serde_json::json!([{
            "source_file": "/ring/n2/n2_00001.pcapng",
            "interface_id": 0,
            "packet_number": 7,
            "byte_offset": 0
        }]);
        let mut callflow = serde_json::json!({"events": [
            {"event_id": "evt-0001", "parent_event_id": "evt-ffff", "protocol": "NAS-5GMM", "packet_references": reference},
            {"event_id": "evt-ffff", "protocol": "NGAP", "packet_references": reference},
        ]});
        assert_eq!(backfill_stable_event_keys_in_callflow(&mut callflow), (2, 0));
        let key = |i: usize| callflow["events"][i]["stable_event_key"].as_str().unwrap().to_owned();
        assert_eq!(key(1), "n2_00001.pcapng|0|7|0|NGAP|0");
        assert_eq!(key(0), "n2_00001.pcapng|0|7|0|NAS-5GMM|1");
    }
}

