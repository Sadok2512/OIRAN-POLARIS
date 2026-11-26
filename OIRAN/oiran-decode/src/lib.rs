//! Reusable native decoder pipeline used by both the CLI and live capture service.

pub mod lte_fixture;

use capture_pcap::{
    transport_view, visit_capture, visit_capture_from, CapturePacket, TransportProtocol, TransportView,
};
use decoder_diameter::DiameterDecoder;
use decoder_gtpu::GtpuDecoder;
use decoder_gtpv2c::Gtpv2cDecoder;
use decoder_ngap::NgapDecoder;
use decoder_pfcp::PfcpDecoder;
use decoder_rtp::RtpFlowAggregator;
use decoder_s1ap::S1apDecoder;
use decoder_sbi::{decode_connections, decode_connections_with_carry, SbiDecodeReport};
pub use decoder_sbi::{SbiCarryContext, SbiCarryMetrics, DEFAULT_HPACK_CARRY_MAX_CONNECTIONS};
use decoder_sip::{SipDecoder, SIP_DEFAULT_PORT};
use event_schema::{sha256_hex, Endpoint, NormalizedEvent, PacketReference, PseudonymKey};
use plugin_runtime::{DecoderInput, ProtocolDecoder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use transport_sctp::SctpReassembler;
use transport_tcp::TcpReassembler;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn installed_decoder_versions() -> BTreeMap<String, String> {
    [
        ("GTP-U", decoder_gtpu::VERSION),
        ("GTPv2-C", decoder_gtpv2c::VERSION),
        ("NAS-5GMM", decoder_nas::VERSION),
        ("NAS-5GSM", decoder_nas::VERSION),
        ("NAS-EPS-MM", decoder_nas::VERSION),
        ("NAS-EPS-SM", decoder_nas::VERSION),
        ("NGAP", decoder_ngap::VERSION),
        ("PFCP", decoder_pfcp::VERSION),
        ("S1AP", decoder_s1ap::VERSION),
        ("Diameter", decoder_diameter::VERSION),
        ("SBI-HTTP2", decoder_sbi::VERSION),
        ("SIP", decoder_sip::VERSION),
        ("RTP", decoder_rtp::VERSION),
    ]
    .into_iter()
    .map(|(name, version)| (name.to_owned(), version.to_owned()))
    .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpRoute {
    N3Gtpu,
    N4Pfcp,
    S1uGtpu,
    S11Gtpv2c,
    // 2.9.1 (#9): new LTE planes routed by port on their own interface.
    S5uGtpu,
    S5cGtpv2c,
    SxabPfcp,
    /// 2.11.0 (devmat) : IMS plane — UDP/TCP 5060 porte le SIP ;
    /// les ports négociés dans les SDP portent le RTP/RTCP et
    /// sont routés via la table de flux RTP tenue par
    /// `RtpFlowAggregator`.
    ImsSip,
}

/// 2.21.107 — plans de capture dont l'UDP hors SIP est présenté à
/// l'agrégateur RTP/RTCP : le plan IMS et le plan N6.
fn carries_ims_media(interface: &str) -> bool {
    matches!(interface, "IMS" | "N6")
}

/// 2.21.107 — interface logique des events SIP/RTP d'un plan de
/// capture. Un message IMS capturé sur N6 est publié `interface="IMS"`,
/// la seule que `correlation-engine` compte pour la voix. Les events
/// `N3-IMS` (SIP extrait du tunnel GTP-U, 2.21.100) gardent leur
/// marqueur propre et ne sont pas comptés : pas de double comptage
/// entre N3 et N6. Le plan d'origine reste lisible dans
/// `packet_references[].source_file` (`N6.pcap-…`).
///
/// 2.21.110 (ordre #9 7049845272) — sur un plan tunnel (`N3`, `S1-U`,
/// `S5-U`) l'agrégateur RTP n'est nourri que par
/// `route_inner_udp_after_gtpu` : ses flux sont du média extrait du
/// tunnel, publiés `N3-IMS` comme le SIP du même tunnel (même preuve,
/// même marqueur). Avant 2.21.110 ils sortaient `interface="N3"`. Les
/// events GTP-U eux-mêmes ne passent pas par cette fonction et gardent
/// l'interface du plan.
fn ims_event_interface(interface: &str) -> &str {
    match interface {
        "N6" => "IMS",
        "N3" | "S1-U" | "S5-U" => TUNNEL_IMS_INTERFACE,
        other => other,
    }
}

/// Marqueur des events SIP et RTP extraits d'un tunnel GTP-U (2.21.100,
/// 2.21.110) : preuve de la voix portée en tunnel, non comptée par
/// `correlation-engine`.
const TUNNEL_IMS_INTERFACE: &str = "N3-IMS";

fn udp_route(interface: &str, source_port: u16, destination_port: u16) -> Option<UdpRoute> {
    let has_port = |port| source_port == port || destination_port == port;
    match interface {
        "N3" if has_port(2152) => Some(UdpRoute::N3Gtpu),
        "N4" if has_port(8805) => Some(UdpRoute::N4Pfcp),
        "S1-U" if has_port(2152) => Some(UdpRoute::S1uGtpu),
        "S11" if has_port(2123) => Some(UdpRoute::S11Gtpv2c),
        // 2.9.1: LTE core planes — same wire protocols, different
        // interface tag so downstream session/correlation engines keep
        // them separated per plane.
        "S5-U" if has_port(2152) => Some(UdpRoute::S5uGtpu),
        "S5-C" if has_port(2123) => Some(UdpRoute::S5cGtpv2c),
        "Sxab" if has_port(8805) => Some(UdpRoute::SxabPfcp),
        // 2.11.0 : IMS SIP.
        "IMS" if has_port(SIP_DEFAULT_PORT) => Some(UdpRoute::ImsSip),
        // 2.21.107 (ordre #9 7049222982) — le plan N6 (IP UE en clair
        // côté DN) porte la signalisation IMS quand le P-CSCF est joint
        // par N6 : même route que le plan IMS.
        "N6" if has_port(SIP_DEFAULT_PORT) => Some(UdpRoute::ImsSip),
        _ => None,
    }
}

fn sctp_route(interface: &str, ppid: u32) -> Option<&'static str> {
    match (interface, ppid) {
        ("N2", 60) => Some("N2"),
        // 2.10.4 (devmat, revue 2.10.3 ANR2 #10 comment 2026-11-10 16:48Z,
        // cas S6a `_00064`/`_00065` à 490+492 trames Diameter et
        // 0 events) : certains EPC (srsEPC inclus) émettent les
        // chunks SCTP DATA S6a avec **PPID 0** (= unspecified) et
        // non la valeur IANA 46. Wireshark décode quand même via le
        // port 3868 ; côté OIRAN la contrainte `("S6a", 46)` strict
        // droppait TOUS les chunks → 0 events. L'interface tag est
        // suffisante : les captures sur `br-oiran-s6a` ne portent
        // que du Diameter.
        //
        // S1-MME garde la contrainte stricte PPID 18 (S1AP IANA) car
        // le bridge S1-MME ne porte que du S1AP et le décodeur ngap
        // tomberait sur un payload invalide si on relâchait le gate.
        // Idem N2 (PPID 60 strict NGAP).
        ("S1-MME", 18) => Some("S1-MME"),
        ("S6a", _) => Some("S6a"),
        _ => None,
    }
}

fn is_s6a_diameter_tcp(interface: &str, source_port: u16, destination_port: u16) -> bool {
    interface == "S6a" && (source_port == 3868 || destination_port == 3868)
}

#[derive(Clone, Debug)]
pub struct DecodeConfig {
    pub input: std::path::PathBuf,
    pub capture_id: String,
    pub interface: String,
    pub endpoints: HashMap<String, String>,
    /// 2.21.91 (ordre #9 7033006772 défaut 3) — chemin dumpcap ORIGINAL
    /// (celui produit par dumpcap dans le ring, avec son run_id et son
    /// numéro de segment). Reste **identique** en live et en publication
    /// même quand `input` diverge (le chemin de publication décode une
    /// copie renommée pour des raisons opérationnelles, mais le basename
    /// original reste la seule clé stable d'identité du pcapng).
    ///
    /// Utilisé par `oiran-decode::emit_events` pour stamper
    /// `stable_event_key` via
    /// [`event_schema::derive_stable_event_key`]. Vide → stamping
    /// désactivé (tests synthétiques, examples historiques).
    pub stable_source_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodeReport {
    pub capture_format: String,
    pub packets: usize,
    pub events: usize,
    pub warnings: usize,
    pub transport_errors: usize,
    pub sctp_errors: usize,
    pub incomplete_sctp: usize,
    #[serde(default)]
    pub tcp_connections: usize,
    #[serde(default)]
    pub tcp_errors: usize,
    #[serde(default)]
    pub http2_frames: usize,
    #[serde(default)]
    pub http2_streams: usize,
    #[serde(default)]
    pub sbi_transactions: usize,
}

pub struct DecodeOutput {
    pub events: Vec<NormalizedEvent>,
    pub report: DecodeReport,
}

pub fn decode_capture(config: &DecodeConfig) -> Result<DecodeOutput, String> {
    // Single-shot decode: generate one key, used only for this call. No way
    // to correlate against another decode_capture() invocation — exactly what
    // the mission mandates for a fresh import.
    let pseudonym_key = PseudonymKey::generate()?;
    let mut events = Vec::new();
    let report = decode_capture_streaming_with_sbi_carry(
        config,
        &pseudonym_key,
        None,
        |event| {
            events.push(event);
            Ok(())
        },
    )?;
    // 2.7.13: canonical processing order is (capture_id, seq, event_id).
    // The timestamp never participates in a processing sort — it may only
    // be used as presentation when rendering the call-flow ladder in
    // `callflow-schema`. Within one `decode_capture()` call every event
    // carries the same `capture_id`, so the effective key becomes
    // `(packet_number, event_id)`, which maps to the order events are
    // emitted by the per-packet decoder (parent S1AP before NAS child).
    let sort_key = |event: &NormalizedEvent| {
        (
            event.capture_id.clone(),
            event
                .packet_references
                .first()
                .map(|packet| packet.packet_number)
                .unwrap_or(0),
            event.event_id.clone(),
        )
    };
    events.sort_by(|left, right| sort_key(left).cmp(&sort_key(right)));
    Ok(DecodeOutput { events, report })
}

/// Decode a capture while transferring ownership of every normalized event to
/// the caller as soon as its protocol context permits. UDP and SCTP events are
/// emitted during packet visitation. Idle TCP connections are finalized and
/// decoded during visitation, rather than being retained until capture EOF.
/// The sink is therefore the only component deciding whether events are kept
/// in memory, written to disk, or processed incrementally.
pub fn decode_capture_streaming<F>(
    config: &DecodeConfig,
    pseudonym_key: &PseudonymKey,
    sink: F,
) -> Result<DecodeReport, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    decode_capture_streaming_with_sbi_carry(config, pseudonym_key, None, sink)
}

/// 2.21.46 (ordre #9 6977819264) — variante qui accepte un carry
/// HPACK persistant entre segments pcap consécutifs. Si
/// `sbi_carry.is_some()` et que `config.interface == "SBI"`, la
/// table dynamique HPACK est préservée pour chaque connexion TCP
/// déjà vue dans un segment précédent.
pub fn decode_capture_streaming_with_sbi_carry<F>(
    config: &DecodeConfig,
    pseudonym_key: &PseudonymKey,
    sbi_carry: Option<&mut SbiCarryContext>,
    sink: F,
) -> Result<DecodeReport, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    let mut state = DecodeState::new();
    decode_core(config, pseudonym_key, sbi_carry, &mut state, None, sink)
}

/// 0.10.0 (oiran-api 2.21.109) — état qu'un décodage crée et que la
/// reprise à l'offset doit garder d'un appel à l'autre.
struct DecodeState {
    key_ordinals: HashMap<String, u32>,
    rtp_aggregator: RtpFlowAggregator,
    sctp: SctpReassembler,
    tcp: TcpReassembler,
    /// Reprise seulement — ordinaux des paquets qui ouvrent un flux RTP
    /// du tunnel : l'event du flux, émis à la clôture, continue leur
    /// numérotation. Les ordinaux des autres paquets sont oubliés dès
    /// le paquet suivant, sinon la table grossirait avec le segment.
    retained_ordinals: HashMap<String, u32>,
    /// Reprise seulement — flux RTP du tunnel déjà vus.
    rtp_flows_seen: std::collections::HashSet<(String, u16, String, u16, u32)>,
    /// Reprise seulement — le paquet en cours ouvre un flux RTP.
    retain_current_packet: bool,
}

impl DecodeState {
    fn new() -> Self {
        Self {
            key_ordinals: HashMap::new(),
            rtp_aggregator: RtpFlowAggregator::new(),
            sctp: SctpReassembler::new(),
            tcp: TcpReassembler::new(),
            retained_ordinals: HashMap::new(),
            rtp_flows_seen: std::collections::HashSet::new(),
            retain_current_packet: false,
        }
    }

    /// Reprise : clôt le paquet précédent. Ses ordinaux sont gardés
    /// s'il a ouvert un flux RTP, oubliés sinon.
    fn close_packet(&mut self) {
        if self.retain_current_packet {
            self.retained_ordinals.extend(self.key_ordinals.drain());
        } else {
            self.key_ordinals.clear();
        }
        self.retain_current_packet = false;
    }
}

/// 0.10.0 (oiran-api 2.21.109, ordre #9 7049845272) — session de
/// décodage incrémental d'UN fichier de capture qui grossit. Gardée en
/// mémoire par l'appelant entre deux appels de
/// [`decode_capture_incremental`].
pub struct DecodeSession {
    resume: capture_pcap::ResumePoint,
    state: DecodeState,
}

impl Default for DecodeSession {
    fn default() -> Self {
        Self::new()
    }
}

impl DecodeSession {
    pub fn new() -> Self {
        Self {
            resume: capture_pcap::ResumePoint::default(),
            state: DecodeState::new(),
        }
    }
    /// Octets du fichier déjà décodés (blocs complets seulement).
    pub fn consumed_bytes(&self) -> u64 {
        self.resume.offset()
    }
    /// Paquets déjà lus depuis le début du fichier.
    pub fn packets(&self) -> u64 {
        self.resume.packets()
    }
}

/// 0.10.0 — plans décodables par reprise à l'offset.
///   * lot A (0.10.0) : un datagramme UDP y porte un message entier,
///     sans état entre paquets ;
///   * lot B1 (0.11.0) : plans SCTP N2 et S1-MME — le réassemblage est
///     gardé dans la session, un message sort à son dernier fragment.
/// Gardent le décodage intégral : SBI et S6a (TCP), IMS et N6 (SIP/RTP
/// par SDP).
pub fn supports_incremental(interface: &str) -> bool {
    matches!(
        interface,
        "N3" | "S1-U" | "S5-U" | "N4" | "Sxab" | "S11" | "S5-C"
    ) || is_incremental_sctp_plane(interface)
        // 0.12.0 (oiran-api 2.21.131, lot B2) — IMS et N6 : SIP sur UDP
        // (un datagramme, un message) et RTP agrégé en session. Le TCP
        // n'est pas décodé sur ces plans.
        || carries_ims_media(interface)
}

/// 0.11.0 (oiran-api 2.21.120, lot B1) — plans SCTP admis en reprise.
/// S6a n'en est pas : il peut aussi porter Diameter sur TCP.
fn is_incremental_sctp_plane(interface: &str) -> bool {
    matches!(interface, "N2" | "S1-MME")
}

/// 0.10.0 — décode les octets ajoutés au fichier depuis le dernier
/// appel. Un bloc incomplet en fin de fichier n'est pas consommé. Les
/// events émis (ordre, `event_id`, `stable_event_key`, numéro de
/// paquet, offset) sont ceux qu'un décodage intégral émet pour les
/// mêmes paquets. Les events de flux RTP du tunnel ne sont PAS émis
/// ici : ils le sont par [`finish_incremental`], à la clôture du
/// fichier. `DecodeReport::packets` et `events` comptent cet appel.
pub fn decode_capture_incremental<F>(
    config: &DecodeConfig,
    pseudonym_key: &PseudonymKey,
    session: &mut DecodeSession,
    sink: F,
) -> Result<DecodeReport, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    if !supports_incremental(&config.interface) {
        return Err(format!(
            "incremental decode is not supported on interface {}",
            config.interface
        ));
    }
    decode_core(
        config,
        pseudonym_key,
        None,
        &mut session.state,
        Some(&mut session.resume),
        sink,
    )
}

/// 0.10.0 — clôt une session incrémentale : émet les events de flux
/// RTP agrégés (un par flux), comme la fin d'un décodage intégral.
/// La session ne doit plus être utilisée ensuite. Retourne le nombre
/// d'events émis.
pub fn finish_incremental<F>(
    config: &DecodeConfig,
    session: &mut DecodeSession,
    mut sink: F,
) -> Result<usize, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    let state = &mut session.state;
    state.close_packet();
    std::mem::swap(&mut state.key_ordinals, &mut state.retained_ordinals);
    let mut event_count = 0usize;
    emit_rtp_flows(config, state, &mut sink, &mut event_count)?;
    Ok(event_count)
}

/// 0.12.0 (oiran-api 2.21.131, lot B2, GO #9 7050925249) — instantané
/// des flux RTP en cours d'une session incrémentale : un event par flux,
/// tel que la clôture l'émettrait si le fichier s'arrêtait ici. La
/// session n'est pas modifiée : ni l'agrégateur, ni les ordinaux. Un
/// instantané pris quand tout le fichier est lu est identique, event
/// pour event, à ce que [`finish_incremental`] émet.
/// Retourne le nombre d'events émis.
pub fn snapshot_rtp_flows<F>(
    config: &DecodeConfig,
    session: &DecodeSession,
    mut sink: F,
) -> Result<usize, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    let state = &session.state;
    // Les ordinaux que la clôture verrait : ceux des paquets qui ont
    // ouvert un flux, plus ceux du paquet en cours s'il en ouvre un.
    let mut ordinals = state.retained_ordinals.clone();
    if state.retain_current_packet {
        ordinals.extend(state.key_ordinals.iter().map(|(key, value)| (key.clone(), *value)));
    }
    let mut event_count = 0usize;
    emit_rtp_flow_events(
        config,
        state.rtp_aggregator.clone(),
        &mut ordinals,
        &mut sink,
        &mut event_count,
    )?;
    Ok(event_count)
}

/// Émet un event par flux RTP agrégé et vide l'agrégateur.
fn emit_rtp_flows<F>(
    config: &DecodeConfig,
    state: &mut DecodeState,
    sink: &mut F,
    event_count: &mut usize,
) -> Result<(), String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    let aggregator = std::mem::replace(&mut state.rtp_aggregator, RtpFlowAggregator::new());
    emit_rtp_flow_events(config, aggregator, &mut state.key_ordinals, sink, event_count)
}

fn emit_rtp_flow_events<F>(
    config: &DecodeConfig,
    aggregator: RtpFlowAggregator,
    key_ordinals: &mut HashMap<String, u32>,
    sink: &mut F,
    event_count: &mut usize,
) -> Result<(), String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    let rtp_events = aggregator.finish(&config.capture_id, ims_event_interface(&config.interface));
    for mut event in rtp_events {
        // 2.21.91 (défaut #9 7033006772 raffiné #9 7034553419) — stamper
        // `stable_event_key` unique par event (RTP agrégé partage le
        // compteur par-paquet avec `emit_events`).
        if !config.stable_source_file.is_empty() {
            if let Some(packet) = event.packet_references.first() {
                let lookup = event_schema::packet_lookup_key(
                    &config.stable_source_file,
                    packet.interface_id,
                    packet.packet_number,
                    packet.byte_offset,
                );
                let ordinal = *key_ordinals
                    .entry(lookup)
                    .and_modify(|v| *v = v.saturating_add(1))
                    .or_insert(0);
                event.assign_stable_event_key(&config.stable_source_file, ordinal);
            }
        }
        sink(event)?;
        *event_count = event_count.saturating_add(1);
    }
    Ok(())
}

fn decode_core<F>(
    config: &DecodeConfig,
    pseudonym_key: &PseudonymKey,
    mut sbi_carry: Option<&mut SbiCarryContext>,
    state: &mut DecodeState,
    mut resume: Option<&mut capture_pcap::ResumePoint>,
    mut sink: F,
) -> Result<DecodeReport, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    validate_config(config)?;
    let incremental = resume.is_some();
    let incremental_sctp = incremental && is_incremental_sctp_plane(&config.interface);
    // 2.21.91 (défaut #9 7033006772 raffiné #9 7034553419) — compteur
    // des events par paquet (clé = `packet_lookup_key`). Partagé entre
    // toutes les invocations de `emit_events` (SCTP, UDP, SBI/TCP,
    // Diameter/TCP) + l'émission RTP finale. L'incrément est 0-based,
    // déterministe, identique en live et en publication car la
    // séquence d'émission du décodeur est elle-même déterministe pour
    // un même pcapng.
    // 2.7.6: the caller owns the pseudonym key. One key per logical import —
    // standalone decode_capture() generates its own; live-probe continuous
    // imports hold a job-scoped key and reuse it across every segment so
    // overlapping snapshots dedupe by identical event_id. The key never
    // leaves the owning stack frame; this borrow carries only a reference.
    let ngap = NgapDecoder;
    let s1ap = S1apDecoder;
    let pfcp = PfcpDecoder;
    let gtpu = GtpuDecoder;
    let gtpv2c = Gtpv2cDecoder;
    let diameter = DiameterDecoder;
    let sip = SipDecoder;
    let mut event_count = 0usize;
    let mut transport_errors = 0usize;
    let mut sink_error = None;
    let mut sbi_report = SbiDecodeReport::default();
    let mut diameter_tcp_connections = 0usize;

    let mut on_packet = |packet: CapturePacket| {
        if sink_error.is_some() {
            return;
        }
        // Les ordinaux d'un paquet ne sont oubliés au paquet suivant que
        // sur les plans sans état. Sur un plan SCTP, un message
        // fragmenté sort plus tard avec la référence de son PREMIER
        // fragment : son ordinal continue ceux des messages déjà sortis
        // de ce paquet, qu'il faut donc garder. Ces plans sont de la
        // signalisation, la table reste petite.
        if incremental && !incremental_sctp {
            state.close_packet();
        }
        if packet.metadata.truncated {
            transport_errors += 1;
            return;
        }
        let view = match transport_view(&packet) {
            Ok(view) => view,
            Err(_) => {
                transport_errors += 1;
                return;
            }
        };
        // Reprise : sur un plan UDP sans état (lot A), SCTP et TCP ne
        // produisent aucun event et leur réassemblage ne doit pas
        // accumuler d'état. Sur un plan SCTP (lot B1), seul le SCTP est
        // traité ; son réassemblage vit dans la session.
        if incremental {
            let admitted = if incremental_sctp {
                matches!(view.protocol, TransportProtocol::Sctp)
            } else {
                matches!(view.protocol, TransportProtocol::Udp)
            };
            if !admitted {
                return;
            }
        }
        match view.protocol {
            TransportProtocol::Udp => {
                let ports = (
                    view.source_port.unwrap_or(0),
                    view.destination_port.unwrap_or(0),
                );
                if let Some(route) = udp_route(&config.interface, ports.0, ports.1) {
                    let (decoder, interface): (&dyn ProtocolDecoder, &str) = match route {
                        UdpRoute::N3Gtpu => (&gtpu, "N3"),
                        UdpRoute::N4Pfcp => (&pfcp, "N4"),
                        UdpRoute::S1uGtpu => (&gtpu, "S1-U"),
                        UdpRoute::S11Gtpv2c => (&gtpv2c, "S11"),
                        UdpRoute::S5uGtpu => (&gtpu, "S5-U"),
                        UdpRoute::S5cGtpv2c => (&gtpv2c, "S5-C"),
                        UdpRoute::SxabPfcp => (&pfcp, "Sxab"),
                        UdpRoute::ImsSip => (&sip, "IMS"),
                    };
                    let mut decoded = Vec::new();
                    decode_udp(
                        decoder,
                        &packet,
                        &view,
                        config,
                        interface,
                        &pseudonym_key,
                        &mut decoded,
                    );
                    // 2.11.0 (devmat) : chaque SIP décodé peut porter un SDP ;
                    // extraire `(ip, port)` + Call-ID + payload type et nourrir
                    // l'agrégateur RTP qui tourne pour la même capture.
                    if matches!(route, UdpRoute::ImsSip) {
                        register_sdp_flows_from_sip(&decoded, &mut state.rtp_aggregator);
                    }
                    // 2.21.100 (ordre #9 7046402022 décision a, design CLAUDE1
                    // #9 7012805654) — pour chaque G-PDU GTP-U (N3/S1-U/S5-U),
                    // extraire l'inner IPv4+UDP et router SIP (port 5060) ou
                    // RTP (autres ports, agrégateur) avec `interface="N3-IMS"`.
                    // Permet de voir la voix VoNR portée en tunnel quand la
                    // capture N6 directe est absente (défaut ANR1 #10 7045290646).
                    // Marqueur `N3-IMS` distinct de `IMS` (plan P-CSCF externe)
                    // pour que la publication puisse dédupliquer si les deux
                    // captures voient le même message (priorité à la source,
                    // voir CHANGELOG).
                    if matches!(
                        route,
                        UdpRoute::N3Gtpu | UdpRoute::S1uGtpu | UdpRoute::S5uGtpu
                    ) {
                        let rtp_flow = route_inner_udp_after_gtpu(
                            &packet,
                            &view,
                            config,
                            &pseudonym_key,
                            &sip,
                            &mut state.rtp_aggregator,
                            &mut decoded,
                        );
                        if incremental {
                            if let Some(flow) = rtp_flow {
                                if state.rtp_flows_seen.insert(flow) {
                                    state.retain_current_packet = true;
                                }
                            }
                        }
                    }
                    emit_events(decoded, config, &mut state.key_ordinals, &mut sink, &mut event_count, &mut sink_error);
                } else if carries_ims_media(&config.interface) {
                    // 2.11.0 : paquet UDP IMS en dehors du port SIP 5060 → tenter
                    // RTP/RTCP sur un flux déjà enregistré par un SDP.
                    let src_ip = view.source_ip.as_str();
                    let dst_ip = view.destination_ip.as_str();
                    let payload = packet_payload_slice(&packet, &view);
                    let arrival_ns = packet_arrival_ns(&packet);
                    let packet_ref = build_packet_reference(&packet, config);
                    let ts = build_timestamp(&packet);
                    let _ = state.rtp_aggregator.observe_rtp(
                        src_ip,
                        ports.0,
                        dst_ip,
                        ports.1,
                        payload,
                        arrival_ns,
                        &packet_ref,
                        &ts,
                    );
                    let _ = state.rtp_aggregator.observe_rtcp(src_ip, ports.0, dst_ip, ports.1, payload);
                }
            }
            TransportProtocol::Sctp => {
                for mut message in state.sctp.consume(&packet, &view) {
                    let Some(interface) = sctp_route(&config.interface, message.ppid) else {
                        continue;
                    };
                    let mut source = endpoint(
                        &message.source_ip,
                        Some(message.source_port),
                        &config.endpoints,
                    );
                    let mut destination = endpoint(
                        &message.destination_ip,
                        Some(message.destination_port),
                        &config.endpoints,
                    );
                    // 2.14.4 (ANR2 ladder écart 1) : si la map `config.endpoints`
                    // (clé = IP) n'a pas connaissance du couple SCTP vu dans la
                    // capture, on résout le `network_function` depuis le port
                    // SCTP seul. Côté S1-MME : port 36412 == MME, pair == eNB ;
                    // côté N2/NGAP : port 38412 == AMF, pair == gNB. Un transport
                    // qui ne se résout toujours pas garde `None` — le libellé
                    // « Unknown endpoint » affiché par l'UI reste explicite.
                    infer_sctp_network_function(
                        interface,
                        &mut source,
                        &mut destination,
                        message.source_port,
                        message.destination_port,
                    );
                    let association = std::sync::Arc::new(event_schema::SctpAssociationProvenance {
                        association_id: message.association_id,
                        association_generation: message.association_generation,
                        verification_tag: message.verification_tag,
                        first_tsn: Some(message.first_tsn),
                        last_tsn: Some(message.last_tsn),
                        original_segment_name: None,
                        rotation_index: None,
                    });
                    for reference in &mut message.packet_references {
                        reference.sctp_association = Some(association.clone());
                    }
                    let raw = format!("sha256:{}", sha256_hex(&message.payload));
                    let input = DecoderInput {
                        capture_id: &config.capture_id,
                        packet_references: &message.packet_references,
                        timestamp: &message.timestamp,
                        interface,
                        source_endpoint: source,
                        destination_endpoint: destination,
                        payload: &message.payload,
                        raw_payload_reference: &raw,
                        pseudonym_key: &pseudonym_key,
                    };
                    let decoded = match interface {
                        "S1-MME" => s1ap.decode(&input).events,
                        "S6a" => diameter.decode(&input).events,
                        _ => ngap.decode(&input).events,
                    };
                    emit_events(decoded, config, &mut state.key_ordinals, &mut sink, &mut event_count, &mut sink_error,
                    );
                }
            }
            TransportProtocol::Tcp if config.interface == "SBI" => {
                state.tcp.consume(&packet, &view);
                let finalized = state.tcp.take_finalized();
                emit_sbi_connections(
                    finalized,
                    config,
                    &pseudonym_key,
                    sbi_carry.as_deref_mut(),
                    &mut state.key_ordinals,
                    &mut sink,
                    &mut event_count,
                    &mut sink_error,
                    &mut sbi_report,
                );
            }
            TransportProtocol::Tcp
                if is_s6a_diameter_tcp(
                    &config.interface,
                    view.source_port.unwrap_or(0),
                    view.destination_port.unwrap_or(0),
                ) =>
            {
                state.tcp.consume(&packet, &view);
                let finalized = state.tcp.take_finalized();
                diameter_tcp_connections += emit_diameter_connections(
                    finalized,
                    config,
                    &diameter,
                    &pseudonym_key,
                    &mut state.key_ordinals,
                    &mut sink,
                    &mut event_count,
                    &mut sink_error,
                );
            }
            TransportProtocol::Tcp | TransportProtocol::Other(_) => {}
        }
    };
    let capture = match resume.as_deref_mut() {
        Some(point) => {
            visit_capture_from(&config.input, &config.capture_id, point, &mut on_packet)
        }
        None => visit_capture(&config.input, &config.capture_id, &mut on_packet),
    };
    drop(on_packet);
    if let Some(error) = sink_error.take() {
        return Err(error);
    }
    let capture = capture.map_err(|error| error.to_string())?;
    if incremental {
        // Reprise : pas de clôture ici. Les flux RTP du tunnel sont
        // émis par `finish_incremental`.
        return Ok(DecodeReport {
            capture_format: format!("{:?}", capture.format),
            packets: capture.packets,
            events: event_count,
            warnings: capture.warnings.len(),
            transport_errors,
            sctp_errors: 0,
            incomplete_sctp: 0,
            tcp_connections: 0,
            tcp_errors: 0,
            http2_frames: 0,
            http2_streams: 0,
            sbi_transactions: 0,
        });
    }
    let (sctp_errors, incomplete_sctp) =
        std::mem::replace(&mut state.sctp, SctpReassembler::new()).finish();
    let (connections, tcp_errors) =
        std::mem::replace(&mut state.tcp, TcpReassembler::new()).finish();
    if config.interface == "S6a" {
        diameter_tcp_connections += emit_diameter_connections(
            connections,
            config,
            &diameter,
            &pseudonym_key,
            &mut state.key_ordinals,
            &mut sink,
            &mut event_count,
            &mut sink_error,
        );
    } else {
        emit_sbi_connections(
            connections,
            config,
            &pseudonym_key,
            sbi_carry.as_deref_mut(),
            &mut state.key_ordinals,
            &mut sink,
            &mut event_count,
            &mut sink_error,
            &mut sbi_report,
        );
    }
    if let Some(error) = sink_error {
        return Err(error);
    }
    // 2.11.0 : émet UN event par flux RTP agrégé — jamais un event
    // par paquet. L'agrégateur peut être vide si le dataset n'a vu
    // aucune SDP + RTP ; c'est le cas habituel hors IMS.
    emit_rtp_flows(config, state, &mut sink, &mut event_count)?;
    Ok(DecodeReport {
        capture_format: format!("{:?}", capture.format),
        packets: capture.packets,
        events: event_count,
        warnings: capture.warnings.len(),
        transport_errors,
        sctp_errors: sctp_errors.len(),
        incomplete_sctp,
        tcp_connections: sbi_report.tcp_connections + diameter_tcp_connections,
        tcp_errors: tcp_errors.len(),
        http2_frames: sbi_report.http2_frames,
        http2_streams: sbi_report.http2_streams,
        sbi_transactions: sbi_report.sbi_transactions,
    })
}

fn emit_events<F>(
    events: impl IntoIterator<Item = NormalizedEvent>,
    config: &DecodeConfig,
    key_ordinals: &mut HashMap<String, u32>,
    sink: &mut F,
    event_count: &mut usize,
    sink_error: &mut Option<String>,
) where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    if sink_error.is_some() {
        return;
    }
    for mut event in events {
        if !event.has_complete_provenance() {
            *sink_error =
                Some("decoder emitted an event without complete packet provenance".into());
            return;
        }
        // 2.21.91 (défaut #9 7033006772 raffiné #9 7034553419) — stamp
        // `stable_event_key` UNIQUE par event. Ordinal = rang 0-based
        // dans l'ordre d'émission parmi les events partageant le même
        // (basename, iid, pkt, off). Live et publi décodent le MÊME
        // pcapng dans le MÊME ordre → mêmes ordinaux → mêmes clés.
        // `config.stable_source_file` vide → stamping sauté.
        if !config.stable_source_file.is_empty() {
            if let Some(packet) = event.packet_references.first() {
                let lookup = event_schema::packet_lookup_key(
                    &config.stable_source_file,
                    packet.interface_id,
                    packet.packet_number,
                    packet.byte_offset,
                );
                let ordinal = *key_ordinals
                    .entry(lookup)
                    .and_modify(|v| *v = v.saturating_add(1))
                    .or_insert(0);
                event.assign_stable_event_key(&config.stable_source_file, ordinal);
            }
        }
        if let Err(error) = sink(event) {
            *sink_error = Some(error);
            return;
        }
        *event_count += 1;
    }
}

fn emit_sbi_connections<F>(
    connections: Vec<transport_tcp::ReassembledConnection>,
    config: &DecodeConfig,
    pseudonym_key: &PseudonymKey,
    mut sbi_carry: Option<&mut SbiCarryContext>,
    key_ordinals: &mut HashMap<String, u32>,
    sink: &mut F,
    event_count: &mut usize,
    sink_error: &mut Option<String>,
    aggregate: &mut SbiDecodeReport,
) where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    for connection in connections {
        if sink_error.is_some() {
            return;
        }
        let (events, report) = match sbi_carry.as_deref_mut() {
            Some(carry) => decode_connections_with_carry(
                std::slice::from_ref(&connection),
                &config.capture_id,
                &config.interface,
                &config.endpoints,
                pseudonym_key,
                carry,
            ),
            None => decode_connections(
                std::slice::from_ref(&connection),
                &config.capture_id,
                &config.interface,
                &config.endpoints,
                pseudonym_key,
            ),
        };
        aggregate.tcp_connections += report.tcp_connections;
        aggregate.http2_frames += report.http2_frames;
        aggregate.http2_streams += report.http2_streams;
        aggregate.sbi_transactions += report.sbi_transactions;
        aggregate.operations_decoded += report.operations_decoded;
        aggregate.incomplete_streams += report.incomplete_streams;
        aggregate.encrypted_connections += report.encrypted_connections;
        aggregate.errors.extend(report.errors);
        emit_events(events, config, key_ordinals, sink, event_count, sink_error);
    }
}

fn emit_diameter_connections<F>(
    connections: Vec<transport_tcp::ReassembledConnection>,
    config: &DecodeConfig,
    decoder: &DiameterDecoder,
    pseudonym_key: &PseudonymKey,
    key_ordinals: &mut HashMap<String, u32>,
    sink: &mut F,
    event_count: &mut usize,
    sink_error: &mut Option<String>,
) -> usize
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    let connection_count = connections.len();
    for connection in connections {
        for direction in connection.directions {
            if sink_error.is_some() || direction.bytes.is_empty() || direction.spans.is_empty() {
                continue;
            }
            let source = endpoint(
                &direction.source.address,
                Some(direction.source.port),
                &config.endpoints,
            );
            let destination = endpoint(
                &direction.destination.address,
                Some(direction.destination.port),
                &config.endpoints,
            );
            for range in diameter_frame_ranges(&direction.bytes) {
                let frame = &direction.bytes[range.clone()];
                let mut packet_references = direction
                    .spans
                    .iter()
                    .filter(|span| span.start < range.end && span.end > range.start)
                    .map(|span| {
                        let mut packet = span.packet.clone();
                        if span.start <= range.start && range.start < span.end {
                            packet.byte_offset = packet
                                .byte_offset
                                .saturating_add((range.start - span.start) as u64);
                        }
                        packet
                    })
                    .collect::<Vec<_>>();
                packet_references.sort_by_key(|packet| packet.packet_number);
                packet_references.dedup_by_key(|packet| packet.packet_number);
                let Some(timestamp) = direction
                    .spans
                    .iter()
                    .filter(|span| span.start < range.end && span.end > range.start)
                    .min_by_key(|span| span.packet.packet_number)
                    .map(|span| span.timestamp.clone())
                else {
                    continue;
                };
                let raw = format!("sha256:{}", sha256_hex(frame));
                let input = DecoderInput {
                    capture_id: &config.capture_id,
                    packet_references: &packet_references,
                    timestamp: &timestamp,
                    interface: "S6a",
                    source_endpoint: source.clone(),
                    destination_endpoint: destination.clone(),
                    payload: frame,
                    raw_payload_reference: &raw,
                    pseudonym_key,
                };
                emit_events(decoder.decode(&input).events, config, key_ordinals, sink, event_count, sink_error,
                );
            }
        }
    }
    connection_count
}

fn diameter_frame_ranges(bytes: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let remaining = &bytes[cursor..];
        if remaining.len() < 20 || remaining[0] != 1 {
            ranges.push(cursor..bytes.len());
            break;
        }
        let length = ((remaining[1] as usize) << 16)
            | ((remaining[2] as usize) << 8)
            | remaining[3] as usize;
        if length < 20 || length > remaining.len() {
            ranges.push(cursor..bytes.len());
            break;
        }
        ranges.push(cursor..cursor + length);
        cursor += length;
    }
    ranges
}

pub fn write_jsonl(path: &Path, events: &[NormalizedEvent], append: bool) -> Result<(), String> {
    write_jsonl_stamped(path, events, append, &event_schema::ProbeStamp::default())
}

/// 0.8.0 (POLARIS 2.21.0) — comme `write_jsonl`, avec l'identité de sonde
/// apposée sur CHAQUE event (ex. `probe_type = "vtap"` pour les pcap de
/// l'agent `polaris-vtap`). Stamp vide → sortie identique à `write_jsonl`.
pub fn write_jsonl_stamped(
    path: &Path,
    events: &[NormalizedEvent],
    append: bool,
    stamp: &event_schema::ProbeStamp,
) -> Result<(), String> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    for event in events {
        writeln!(writer, "{}", event.to_json_with_probe(stamp)).map_err(|error| error.to_string())?;
    }
    writer.flush().map_err(|error| error.to_string())
}

/// Write a complete normalized-event stream without ever exposing a partial
/// destination file. The caller must create and authorize the parent dataset
/// directory before invoking this function.
///
/// 0.4.5 — accepts any `IntoIterator<Item = &NormalizedEvent>` so a caller
/// that produces events lazily does not have to materialise the full `Vec`
/// before writing. The function still writes line-by-line through a bounded
/// `BufWriter`; the public API change lifts the "collect first, write next"
/// restriction that previously forced live-probe to hold the entire decoded
/// stream in memory on top of the pcap bytes.
pub fn write_jsonl_atomic<'a, I>(path: &Path, events: I) -> Result<(), String>
where
    I: IntoIterator<Item = &'a NormalizedEvent>,
{
    let parent = path
        .parent()
        .ok_or_else(|| format!("dataset output has no parent: {}", path.display()))?;
    if !parent.is_dir() {
        return Err(format!(
            "dataset output directory is unavailable: {}",
            parent.display()
        ));
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("events.jsonl");
    let temporary = parent.join(format!(".{name}.{nonce}.tmp"));
    let result = (|| {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("create {}: {error}", temporary.display()))?;
        let mut writer = std::io::BufWriter::new(file);
        for event in events {
            writeln!(writer, "{}", event.to_json()).map_err(|error| error.to_string())?;
        }
        writer.flush().map_err(|error| error.to_string())?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| error.to_string())?;
        fs::rename(&temporary, path).map_err(|error| format!("rename {}: {error}", path.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_config(config: &DecodeConfig) -> Result<(), String> {
    if !config.capture_id.starts_with("sha256:") || config.capture_id.len() != 71 {
        return Err("capture ID must be sha256: followed by 64 hex digits".into());
    }
    if !matches!(
        config.interface.as_str(),
        // 2.9.1 (#9): the LTE core planes join the 5G-SA allowlist so
        // `decode_capture_streaming` routes them to the existing
        // decoders (GTP-U, GTPv2-C, PFCP, Diameter). N6 est resté
        // exclu jusqu'à 2.21.106 ; accepté depuis 2.21.107 (route IMS).
        "N2" | "N3" | "N4" | "SBI" | "S1-MME" | "S1-U" | "S11"
            | "S5-C" | "S5-U" | "S6a" | "Sxab"
            // 2.11.0 : plane IMS (SIP/RTP) ajoutée en 13ᵉ interface.
            | "IMS"
            // 2.21.107 : plan N6, décodé par la route IMS (SIP/RTP).
            | "N6"
    ) {
        return Err(
            "interface must be N2, N3, N4, N6, SBI, S1-MME, S1-U, S11, S5-C, S5-U, S6a, Sxab or IMS"
                .into(),
        );
    }
    Ok(())
}

/// 2.21.100 (ordre #9 7046402022 décision a, design CLAUDE1 #9 7012805654) —
/// pour un paquet G-PDU GTP-U, inspecte l'inner IPv4+UDP via
/// [`decoder_gtpu::extract_inner_udp`] et route :
///   * `source_port == 5060 || destination_port == 5060` ⇒ `SipDecoder::decode`
///     sur le payload UDP inner avec `interface="N3-IMS"` ; les flux SDP
///     éventuels sont enregistrés dans `rtp_aggregator`.
///   * sinon ⇒ `rtp_aggregator.observe_rtp` + `observe_rtcp` sur les IP/ports
///     inner (le flux doit déjà être annoncé par un SDP vu plus tôt, soit
///     côté IMS externe, soit côté N3-IMS).
///
/// Les events SIP produits sont ajoutés à `decoded` pour `emit_events`.
/// L'event GTP-U d'origine n'est pas touché (invariant « 1 event par paquet
/// GTP-U »).
#[allow(clippy::too_many_arguments)]
fn route_inner_udp_after_gtpu(
    packet: &CapturePacket,
    view: &TransportView,
    config: &DecodeConfig,
    pseudonym_key: &PseudonymKey,
    sip: &decoder_sip::SipDecoder,
    rtp_aggregator: &mut decoder_rtp::RtpFlowAggregator,
    decoded: &mut Vec<NormalizedEvent>,
) -> Option<(String, u16, String, u16, u32)> {
    let gtpu_payload = packet_payload_slice(packet, view);
    let Some(inner) = decoder_gtpu::extract_inner_udp(gtpu_payload) else {
        return None;
    };
    let inner_start = inner.udp_payload_offset;
    let inner_end = inner_start + inner.udp_payload_length;
    if inner_end > gtpu_payload.len() {
        return None;
    }
    let inner_payload = &gtpu_payload[inner_start..inner_end];
    let ts = &packet.metadata.timestamp;
    let packet_ref = packet_reference(packet);
    let arrival_ns = packet_arrival_ns(packet);
    if inner.source_port == 5060 || inner.destination_port == 5060 {
        let inner_references = [packet_ref];
        let inner_raw = format!("sha256:{}", sha256_hex(inner_payload));
        let inner_input = DecoderInput {
            capture_id: &config.capture_id,
            packet_references: &inner_references,
            timestamp: ts,
            interface: TUNNEL_IMS_INTERFACE,
            source_endpoint: Endpoint {
                address: inner.source_ip.clone(),
                port: Some(inner.source_port),
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: inner.destination_ip.clone(),
                port: Some(inner.destination_port),
                network_function: None,
            },
            payload: inner_payload,
            raw_payload_reference: &inner_raw,
            pseudonym_key,
        };
        let sip_output = sip.decode(&inner_input);
        if !sip_output.events.is_empty() {
            register_sdp_flows_from_sip(&sip_output.events, rtp_aggregator);
        }
        decoded.extend(sip_output.events);
        None
    } else {
        let accepted = rtp_aggregator.observe_rtp(
            &inner.source_ip,
            inner.source_port,
            &inner.destination_ip,
            inner.destination_port,
            inner_payload,
            arrival_ns,
            &packet_ref,
            ts,
        );
        let _ = rtp_aggregator.observe_rtcp(
            &inner.source_ip,
            inner.source_port,
            &inner.destination_ip,
            inner.destination_port,
            inner_payload,
        );
        // 0.10.0 — flux RTP auquel ce paquet a été agrégé : la reprise
        // à l'offset garde l'ordinal du paquet qui ouvre le flux.
        if accepted {
            decoder_rtp::parse_rtp_header(inner_payload).map(|header| {
                (
                    inner.source_ip.clone(),
                    inner.source_port,
                    inner.destination_ip.clone(),
                    inner.destination_port,
                    header.ssrc,
                )
            })
        } else {
            None
        }
    }
}

fn decode_udp(
    decoder: &dyn ProtocolDecoder,
    packet: &CapturePacket,
    view: &TransportView,
    config: &DecodeConfig,
    interface: &str,
    pseudonym_key: &PseudonymKey,
    events: &mut Vec<NormalizedEvent>,
) {
    let payload = &packet.data[view.payload_offset..view.payload_offset + view.payload_length];
    let references = [packet_reference(packet)];
    let raw = format!("sha256:{}", sha256_hex(payload));
    let input = DecoderInput {
        capture_id: &config.capture_id,
        packet_references: &references,
        timestamp: &packet.metadata.timestamp,
        interface,
        source_endpoint: endpoint(&view.source_ip, view.source_port, &config.endpoints),
        destination_endpoint: endpoint(
            &view.destination_ip,
            view.destination_port,
            &config.endpoints,
        ),
        payload,
        raw_payload_reference: &raw,
        pseudonym_key,
    };
    events.extend(decoder.decode(&input).events);
}

fn endpoint(ip: &str, port: Option<u16>, map: &HashMap<String, String>) -> Endpoint {
    Endpoint {
        address: ip.into(),
        port,
        network_function: map.get(ip).cloned(),
    }
}

/// 2.14.4 — résolution « port SCTP seul » des `network_function` S1-MME /
/// N2 quand la map `config.endpoints` ignore les IP du couple.
///
/// S1-MME (TS 36.413) : port serveur 36412 côté MME ; le pair est l'eNB.
/// N2 / NGAP (TS 38.413) : port serveur 38412 côté AMF ; le pair est le gNB.
///
/// On n'écrase pas un `network_function` déjà résolu par la map : le
/// paramétrage d'une plateforme reste prioritaire. Si aucun des deux ports
/// SCTP n'est connu, on laisse le champ à `None` (`Unknown endpoint` côté
/// UI, ouvert et comptable, pas silencieux).
pub fn infer_sctp_network_function(
    interface: &str,
    source: &mut Endpoint,
    destination: &mut Endpoint,
    source_port: u16,
    destination_port: u16,
) {
    let (server_port, server_nf, peer_nf): (u16, &str, &str) = match interface {
        "S1-MME" => (36412, "MME", "eNB"),
        "N2" => (38412, "AMF", "gNB"),
        _ => return,
    };
    if source_port == server_port {
        if source.network_function.is_none() {
            source.network_function = Some(server_nf.into());
        }
        if destination.network_function.is_none() {
            destination.network_function = Some(peer_nf.into());
        }
    } else if destination_port == server_port {
        if source.network_function.is_none() {
            source.network_function = Some(peer_nf.into());
        }
        if destination.network_function.is_none() {
            destination.network_function = Some(server_nf.into());
        }
    }
}

/// 2.11.0 : helper pour l'IMS branch RTP — même shape que
/// `packet_reference` ci-dessous, lié au config courant.
fn build_packet_reference(packet: &CapturePacket, _config: &DecodeConfig) -> PacketReference {
    packet_reference(packet)
}

fn build_timestamp(packet: &CapturePacket) -> event_schema::ExactTimestamp {
    packet.metadata.timestamp.clone()
}

fn packet_payload_slice<'a>(packet: &'a CapturePacket, view: &TransportView) -> &'a [u8] {
    let start = view.payload_offset;
    let end = start.saturating_add(view.payload_length);
    if end <= packet.data.len() {
        &packet.data[start..end]
    } else {
        &[]
    }
}

fn packet_arrival_ns(packet: &CapturePacket) -> u64 {
    let ts = &packet.metadata.timestamp;
    let seconds = ts.seconds.max(0) as u64;
    seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.nanoseconds as u64)
}

/// 2.11.0 : balaie les events SIP fraîchement décodés, extrait leur
/// `sdp.c` + `sdp.m.audio.port` + Call-ID, et enregistre le flux
/// correspondant auprès de l'agrégateur RTP. L'appel est idempotent.
fn register_sdp_flows_from_sip(
    events: &[NormalizedEvent],
    aggregator: &mut RtpFlowAggregator,
) {
    for event in events {
        let mut call_id: Option<String> = None;
        let mut sdp_c: Option<String> = None;
        let mut sdp_port: Option<u16> = None;
        let mut sdp_pt: Option<u8> = None;
        let mut sdp_clock_rate_hz: Option<u32> = None;
        for id in &event.session_identifiers {
            if id.name == "sip_call_id" {
                call_id = Some(id.value.clone());
            }
        }
        for ie in &event.information_elements {
            match ie.name.as_str() {
                "sdp.c" => sdp_c = ie.value.clone(),
                "sdp.m.audio.port" => {
                    sdp_port = ie.value.as_deref().and_then(|v| v.parse::<u16>().ok());
                }
                "sdp.m.audio.pt" => {
                    sdp_pt = ie
                        .value
                        .as_deref()
                        .and_then(|v| v.split(',').next())
                        .and_then(|first| first.parse::<u8>().ok());
                }
                // 2.21.79 (CLAUDE1, ordre #9 7012275179 §1) — propage le
                // `clock_rate` SDP vers l'agrégateur RTP pour le calcul
                // de jitter sur PT dynamique.
                "sdp.m.audio.rtpmap_clock_rate_hz" => {
                    sdp_clock_rate_hz =
                        ie.value.as_deref().and_then(|v| v.parse::<u32>().ok());
                }
                _ => {}
            }
        }
        if let (Some(ip), Some(port), Some(cid)) = (sdp_c, sdp_port, call_id) {
            aggregator.register_sdp_flow(decoder_rtp::SdpFlowRegistration {
                ip,
                port,
                call_id: cid,
                payload_type: sdp_pt,
                clock_rate_hz: sdp_clock_rate_hz,
            });
        }
    }
}

fn packet_reference(packet: &CapturePacket) -> PacketReference {
    let sll2 = packet.metadata.sll2.as_ref();
    PacketReference {
        source_file: packet.metadata.source_file.clone(),
        sctp_association: None,
        source_sha256: packet
            .metadata
            .capture_id
            .strip_prefix("sha256:")
            .map(str::to_owned),
        packet_number: packet.metadata.packet_number,
        byte_offset: packet.metadata.byte_offset,
        interface_id: packet.metadata.interface_id,
        link_type: Some(packet.metadata.link_type),
        sll2_protocol_type: sll2.map(|header| header.protocol_type),
        sll2_reserved: sll2.map(|header| header.reserved),
        sll2_interface_index: sll2.map(|header| header.interface_index),
        sll2_arphrd_type: sll2.map(|header| header.arphrd_type),
        sll2_packet_type: sll2.map(|header| header.packet_type),
        sll2_address_length: sll2.map(|header| header.address_length),
        sll2_address: sll2.map(|header| {
            header.address[..usize::from(header.address_length)]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":")
        }),
        captured_length: packet.metadata.captured_length,
        original_length: packet.metadata.original_length,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2.21.107 — pcap classique (Ethernet) d'un seul datagramme UDP.
    fn single_udp_pcap(path: &std::path::Path, src_port: u16, dst_port: u16, payload: &[u8]) {
        let udp_len = (8 + payload.len()) as u16;
        let ip_len = 20 + udp_len;
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&ip_len.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        frame.extend_from_slice(&[10, 47, 0, 2]);
        frame.extend_from_slice(&[10, 77, 24, 20]);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(payload);
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&[0u8; 8]);
        file.extend_from_slice(&65_535u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend_from_slice(&1_795_200_000u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&frame);
        std::fs::write(path, file).unwrap();
    }

    /// 2.21.107 (ordre #9 7049222982) — un REGISTER SIP capturé sur le
    /// plan N6 est décodé et publié `interface="IMS"`, à l'identique du
    /// même datagramme capturé sur le plan IMS (même nom de message,
    /// même référence de payload). Avant 2.21.107 : `N6` refusé par
    /// `validate_config`.
    #[test]
    fn n6_plane_decodes_sip_as_ims_interface_2_21_107() {
        let register: &[u8] = b"REGISTER sip:ims.example.invalid SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.47.0.2:5060;branch=z9hG4bKn6\r\n\
Max-Forwards: 70\r\n\
From: <sip:user@example.invalid>;tag=n6\r\n\
To: <sip:user@example.invalid>\r\n\
Call-ID: synthetic-2-21-107@oiran\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\
\r\n";
        let path = std::env::temp_dir().join(format!(
            "oiran-n6-sip-{}-{:?}.pcap",
            std::process::id(),
            std::thread::current().id()
        ));
        single_udp_pcap(&path, 5060, 5060, register);
        let key = PseudonymKey::from_bytes([9; 32]);
        let decode = |interface: &str| {
            let config = DecodeConfig {
                input: path.clone(),
                capture_id: format!("sha256:{}", "d".repeat(64)),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: String::new(),
            };
            let mut events = Vec::new();
            decode_capture_streaming(&config, &key, |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
            events
        };
        let from_n6 = decode("N6");
        let from_ims = decode("IMS");
        let _ = std::fs::remove_file(&path);
        assert_eq!(from_n6.len(), 1, "un event SIP depuis N6");
        assert_eq!(from_ims.len(), 1);
        assert_eq!(from_n6[0].interface, "IMS");
        assert_eq!(from_n6[0].protocol.as_str(), "SIP");
        assert_eq!(from_n6[0].message_name, from_ims[0].message_name);
        assert_eq!(
            from_n6[0].raw_payload_reference,
            from_ims[0].raw_payload_reference
        );
        // Le reste du trafic N6 (données UE hors SIP) n'émet rien.
        single_udp_pcap(&path, 40_000, 443, b"not sip, not rtp");
        assert!(decode("N6").is_empty());
        let _ = std::fs::remove_file(&path);
        assert_eq!(ims_event_interface("N6"), "IMS");
        // 2.21.110 : le média d'un plan tunnel est publié `N3-IMS`.
        assert_eq!(ims_event_interface("N3"), "N3-IMS");
        assert!(carries_ims_media("N6") && carries_ims_media("IMS") && !carries_ims_media("N3"));
    }

    /// Trame Ethernet/IPv4/UDP 2152 portant un G-PDU dont le paquet
    /// interne est un datagramme UDP `src:sport → dst:dport`.
    fn gtpu_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let inner_udp = (8 + payload.len()) as u16;
        let inner_ip = 20 + inner_udp;
        let outer_udp = 8 + 8 + inner_ip;
        let outer_ip = 20 + outer_udp;
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
        f.extend_from_slice(&outer_ip.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 10, 77, 11, 13, 10, 77, 22, 13]);
        f.extend_from_slice(&2152u16.to_be_bytes());
        f.extend_from_slice(&2152u16.to_be_bytes());
        f.extend_from_slice(&outer_udp.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0x30, 0xff]);
        f.extend_from_slice(&inner_ip.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x00, 0x00, 0x2a, 0x45, 0x00]);
        f.extend_from_slice(&inner_ip.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&inner_udp.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn classic_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&[0u8; 8]);
        file.extend_from_slice(&65_535u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        for (index, frame) in frames.iter().enumerate() {
            file.extend_from_slice(&(1_795_200_000u32 + index as u32 / 50).to_le_bytes());
            file.extend_from_slice(&((index as u32 % 50) * 20_000).to_le_bytes());
            file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            file.extend_from_slice(frame);
        }
        file
    }

    /// Capture N3 synthétique : G-PDU de données, un INVITE SIP avec
    /// SDP dans le tunnel, puis deux flux RTP négociés par ce SDP.
    fn synthetic_n3_voice_capture() -> Vec<u8> {
        let ue = [10, 47, 0, 2];
        let peer = [10, 77, 24, 30];
        let sdp = "v=0\r\no=- 1 1 IN IP4 10.47.0.2\r\ns=-\r\nc=IN IP4 10.47.0.2\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let invite = format!(
            "INVITE sip:callee@example.invalid SIP/2.0\r\nVia: SIP/2.0/UDP 10.47.0.2:5060;branch=z9hG4bKres\r\nMax-Forwards: 70\r\nFrom: <sip:caller@example.invalid>;tag=a\r\nTo: <sip:callee@example.invalid>\r\nCall-ID: synthetic-2-21-109@oiran\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{}",
            sdp.len(),
            sdp
        );
        let rtp = |ssrc: u32, seq: u16| {
            let mut p = vec![0x80, 0x00];
            p.extend_from_slice(&seq.to_be_bytes());
            p.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
            p.extend_from_slice(&ssrc.to_be_bytes());
            p.extend_from_slice(&[0x55; 20]);
            p
        };
        let mut frames = Vec::new();
        for i in 0..5u8 {
            frames.push(gtpu_frame(ue, 33_000, [10, 77, 24, 40], 443, &[i; 60]));
        }
        frames.push(gtpu_frame(ue, 5060, [10, 77, 24, 20], 5060, invite.as_bytes()));
        for seq in 0..40u16 {
            frames.push(gtpu_frame(ue, 40_000, peer, 50_000, &rtp(0x1111, seq)));
            frames.push(gtpu_frame(peer, 50_000, ue, 40_000, &rtp(0x2222, seq)));
            frames.push(gtpu_frame(ue, 33_000, [10, 77, 24, 40], 443, &[seq as u8; 30]));
        }
        classic_pcap(&frames)
    }

    /// Trame Ethernet/IPv4/UDP, sans tunnel.
    fn udp_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) -> Vec<u8> {
        let udp = (8 + payload.len()) as u16;
        let ip = 20 + udp;
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
        f.extend_from_slice(&ip.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&udp.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    /// Capture IMS / N6 synthétique, sans tunnel : REGISTER (sans SDP),
    /// INVITE avec SDP, 200 OK avec SDP, deux flux RTP négociés, BYE.
    fn synthetic_ims_voice_capture() -> Vec<u8> {
        let ue = [10, 47, 0, 2];
        let pcscf = [10, 77, 24, 20];
        let peer = [10, 77, 24, 30];
        let sip = |start: &str, cseq: &str, sdp: Option<&str>| {
            let body = sdp.unwrap_or("");
            let content_type = if sdp.is_some() { "Content-Type: application/sdp\r\n" } else { "" };
            format!(
                "{start}\r\nVia: SIP/2.0/UDP 10.47.0.2:5060;branch=z9hG4bKb2\r\nMax-Forwards: 70\r\nFrom: <sip:caller@example.invalid>;tag=a\r\nTo: <sip:callee@example.invalid>\r\nCall-ID: synthetic-2-21-131@oiran\r\nCSeq: {cseq}\r\n{content_type}Content-Length: {}\r\n\r\n{body}",
                body.len()
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
        let mut frames = Vec::new();
        frames.push(udp_frame(ue, 5060, pcscf, 5060, sip("REGISTER sip:example.invalid SIP/2.0", "1 REGISTER", None).as_bytes()));
        frames.push(udp_frame(ue, 5060, pcscf, 5060, sip("INVITE sip:callee@example.invalid SIP/2.0", "2 INVITE", Some(offer)).as_bytes()));
        frames.push(udp_frame(pcscf, 5060, ue, 5060, sip("SIP/2.0 200 OK", "2 INVITE", Some(answer)).as_bytes()));
        for seq in 0..40u16 {
            frames.push(udp_frame(ue, 40_000, peer, 50_000, &rtp(0x1111, seq)));
            frames.push(udp_frame(peer, 50_000, ue, 40_000, &rtp(0x2222, seq)));
        }
        frames.push(udp_frame(ue, 5060, pcscf, 5060, sip("BYE sip:callee@example.invalid SIP/2.0", "3 BYE", None).as_bytes()));
        classic_pcap(&frames)
    }

    fn seeded_cuts(len: usize, seed: u64, max_step: usize) -> Vec<usize> {
        let mut state = seed;
        let mut cuts = Vec::new();
        let mut at = 0usize;
        while at < len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            at = (at + 1 + ((state >> 33) as usize % max_step)).min(len);
            cuts.push(at);
        }
        cuts
    }

    /// 0.10.0 (oiran-api 2.21.109, ordre #9 7049845272) — gate du lot A :
    /// pour tout découpage du fichier, y compris au milieu d'un bloc,
    /// décodage incrémental + clôture = décodage intégral, event pour
    /// event (JSON complet : ordre, `event_id`, `stable_event_key`,
    /// numéro de paquet, offset). Jeux N3 et N4 du dépôt et capture N3
    /// synthétique avec SIP et RTP dans le tunnel ; 12 graines, pas
    /// fins (≤ 61 octets) et larges (≤ 3000).
    #[test]
    fn incremental_decode_matches_full_decode_for_any_split_2_21_109() {
        let datasets = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let inputs: Vec<(&str, &str, Vec<u8>)> = vec![
            ("N3", "pcapng", std::fs::read(datasets.join("N3.pcapng")).unwrap()),
            ("N4", "pcapng", std::fs::read(datasets.join("N4.pcapng")).unwrap()),
            ("N3", "pcap", synthetic_n3_voice_capture()),
            // 0.12.0 (oiran-api 2.21.131, lot B2) — plans IMS et N6.
            ("IMS", "pcap", synthetic_ims_voice_capture()),
            ("N6", "pcap", synthetic_ims_voice_capture()),
        ];
        let key = PseudonymKey::from_bytes([3; 32]);
        for (interface, extension, bytes) in &inputs {
            let path = std::env::temp_dir().join(format!(
                "oiran-incr-{}-{}-{:?}.{}",
                interface,
                std::process::id(),
                std::thread::current().id(),
                extension
            ));
            let config = DecodeConfig {
                input: path.clone(),
                capture_id: format!("sha256:{}", "e".repeat(64)),
                interface: (*interface).into(),
                endpoints: HashMap::new(),
                stable_source_file: "n3_00001_20261120.pcapng".into(),
            };
            std::fs::write(&path, bytes).unwrap();
            let mut full = Vec::new();
            decode_capture_streaming(&config, &key, |event| {
                full.push(event.to_json());
                Ok(())
            })
            .unwrap();
            assert!(!full.is_empty(), "{interface}.{extension} : des events");
            if *extension == "pcap" {
                let count = |needle: &str| full.iter().filter(|e| e.contains(needle)).count();
                assert_eq!(count("\"protocol\":\"RTP\""), 2, "{interface} : deux flux RTP");
                if *interface == "N3" {
                    assert!(count("\"interface\":\"N3-IMS\"") >= 1, "le SIP du tunnel");
                } else {
                    assert_eq!(count("\"protocol\":\"SIP\""), 4, "{interface} : REGISTER, INVITE, 200, BYE");
                    assert_eq!(count("\"interface\":\"IMS\""), 6, "{interface} publié IMS");
                }
            }
            for seed in 0..12u64 {
                for max_step in [61usize, 3000] {
                    let mut session = DecodeSession::new();
                    let mut incremental = Vec::new();
                    for cut in seeded_cuts(bytes.len(), seed, max_step) {
                        std::fs::write(&path, &bytes[..cut]).unwrap();
                        decode_capture_incremental(&config, &key, &mut session, |event| {
                            incremental.push(event.to_json());
                            Ok(())
                        })
                        .unwrap();
                        assert!(session.consumed_bytes() <= cut as u64);
                        assert!(
                            session.state.key_ordinals.len() <= 1,
                            "les ordinaux d'un paquet clos sont oubliés"
                        );
                        // 0.12.0 (lot B2) — un instantané pris à chaque
                        // découpage ne change rien à la suite.
                        snapshot_rtp_flows(&config, &session, |_| Ok(())).unwrap();
                    }
                    assert_eq!(session.consumed_bytes(), bytes.len() as u64);
                    // 0.12.0 (lot B2) — l'instantané pris quand tout le
                    // fichier est lu est la révision finale : identique à
                    // ce que la clôture émet.
                    let mut last_snapshot = Vec::new();
                    snapshot_rtp_flows(&config, &session, |event| {
                        last_snapshot.push(event.to_json());
                        Ok(())
                    })
                    .unwrap();
                    let already = incremental.len();
                    assert!(
                        session.state.retained_ordinals.len() <= 2,
                        "au plus un ordinal gardé par flux RTP"
                    );
                    finish_incremental(&config, &mut session, |event| {
                        incremental.push(event.to_json());
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(
                        &incremental[already..],
                        &last_snapshot[..],
                        "{interface}.{extension} graine {seed} pas {max_step} : instantané final = clôture"
                    );
                    assert_eq!(
                        incremental, full,
                        "{interface}.{extension} graine {seed} pas {max_step}"
                    );
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    /// 0.12.0 (oiran-api 2.21.131, lot B2, GO #9 7050925249) — l'instantané
    /// suit le flux qui grossit : mêmes flux, même `stable_event_key` d'un
    /// instantané à l'autre, compte de paquets croissant ; et la session
    /// n'est pas modifiée (la clôture reste identique au décodage
    /// intégral, vérifié par le gate de parité).
    #[test]
    fn rtp_snapshot_follows_a_growing_flow_with_a_constant_stable_key_2_21_131() {
        let bytes = synthetic_ims_voice_capture();
        let path = std::env::temp_dir().join(format!(
            "oiran-snap-{}-{:?}.pcap",
            std::process::id(),
            std::thread::current().id()
        ));
        let config = DecodeConfig {
            input: path.clone(),
            capture_id: format!("sha256:{}", "e".repeat(64)),
            interface: "IMS".into(),
            endpoints: HashMap::new(),
            stable_source_file: "ims_00001_20261121.pcapng".into(),
        };
        let key = PseudonymKey::from_bytes([3; 32]);
        let mut session = DecodeSession::new();
        let mut history: Vec<Vec<NormalizedEvent>> = Vec::new();
        for fraction in [3usize, 2, 1] {
            std::fs::write(&path, &bytes[..bytes.len() / fraction]).unwrap();
            decode_capture_incremental(&config, &key, &mut session, |_| Ok(())).unwrap();
            let mut snapshot = Vec::new();
            snapshot_rtp_flows(&config, &session, |event| {
                snapshot.push(event);
                Ok(())
            })
            .unwrap();
            // Deux instantanés de suite sans octet nouveau sont identiques.
            let mut again = Vec::new();
            snapshot_rtp_flows(&config, &session, |event| {
                again.push(event);
                Ok(())
            })
            .unwrap();
            assert_eq!(snapshot, again);
            history.push(snapshot);
        }
        let _ = std::fs::remove_file(&path);
        assert!(history.iter().all(|snapshot| snapshot.len() == 2), "deux flux à chaque instantané");
        let keys = |snapshot: &[NormalizedEvent]| -> Vec<String> {
            snapshot.iter().map(|e| e.stable_event_key.clone()).collect()
        };
        assert!(keys(&history[0]).iter().all(|key| !key.is_empty()));
        assert_eq!(keys(&history[0]), keys(&history[1]));
        assert_eq!(keys(&history[1]), keys(&history[2]));
        // Le flux grossit : l'`event_id` change (il porte le nombre de
        // paquets), la clé stable non.
        assert_ne!(history[0][0].event_id, history[2][0].event_id);
        assert_ne!(history[0][0].raw_payload_reference, history[2][0].raw_payload_reference);
        assert!(history[2][0].raw_payload_reference.ends_with("packets=40"));
    }

    /// Trame Ethernet/IPv4/SCTP portant les chunks donnés.
    fn sctp_frame(chunks: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = chunks.iter().flatten().copied().collect();
        let ip_len = (20 + 12 + body.len()) as u16;
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
        f.extend_from_slice(&ip_len.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 64, 132, 0, 0, 10, 77, 11, 13, 10, 77, 21, 20]);
        f.extend_from_slice(&33_492u16.to_be_bytes());
        f.extend_from_slice(&38_412u16.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]);
        f.extend_from_slice(&body);
        f
    }

    /// Chunk SCTP DATA (`flags` : 2 = début, 1 = fin, 3 = entier).
    fn sctp_data(flags: u8, tsn: u32, ssn: u16, payload: &[u8]) -> Vec<u8> {
        let length = (16 + payload.len()) as u16;
        let mut c = vec![0u8, flags];
        c.extend_from_slice(&length.to_be_bytes());
        c.extend_from_slice(&tsn.to_be_bytes());
        c.extend_from_slice(&0u16.to_be_bytes());
        c.extend_from_slice(&ssn.to_be_bytes());
        c.extend_from_slice(&60u32.to_be_bytes());
        c.extend_from_slice(payload);
        while c.len() % 4 != 0 {
            c.push(0);
        }
        c
    }

    /// Messages NGAP réels du jeu N2 du dépôt, tels que réassemblés.
    fn real_ngap_payloads(count: usize) -> Vec<Vec<u8>> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N2.pcapng");
        let mut reassembler = SctpReassembler::new();
        let mut payloads = Vec::new();
        visit_capture(&path, "sha256:x", |packet| {
            if let Ok(view) = transport_view(&packet) {
                if matches!(view.protocol, TransportProtocol::Sctp) {
                    for message in reassembler.consume(&packet, &view) {
                        if message.ppid == 60 {
                            payloads.push(message.payload.to_vec());
                        }
                    }
                }
            }
        })
        .unwrap();
        assert!(payloads.len() >= count, "le jeu N2 porte au moins {count} messages NGAP");
        payloads.truncate(count);
        payloads
    }

    /// Capture N2 synthétique faite de vrais messages NGAP :
    ///   paquet 1 — un message entier ET le premier fragment d'un second ;
    ///   paquet 2 — fragment du milieu ;
    ///   paquet 3 — dernier fragment ET un troisième message entier ;
    ///   paquet 4 — deux messages entiers dans le même paquet.
    /// Le message fragmenté sort au paquet 3 avec la référence du
    /// paquet 1, qui a déjà émis un message : son ordinal doit continuer.
    fn synthetic_n2_fragmented_capture() -> Vec<u8> {
        let p = real_ngap_payloads(5);
        let third = p[1].len() / 3;
        let frames = vec![
            sctp_frame(&[sctp_data(3, 1, 0, &p[0]), sctp_data(2, 2, 1, &p[1][..third])]),
            sctp_frame(&[sctp_data(0, 3, 1, &p[1][third..2 * third])]),
            sctp_frame(&[sctp_data(1, 4, 1, &p[1][2 * third..]), sctp_data(3, 5, 2, &p[2])]),
            sctp_frame(&[sctp_data(3, 6, 3, &p[3]), sctp_data(3, 7, 4, &p[4])]),
        ];
        classic_pcap(&frames)
    }

    #[test]
    fn decoded_ngap_packets_preserve_sctp_association_provenance() {
        let path = std::env::temp_dir().join(format!("oiran-sctp-provenance-{}.pcap", std::process::id()));
        std::fs::write(&path, synthetic_n2_fragmented_capture()).unwrap();
        let config = DecodeConfig {
            input: path.clone(),
            capture_id: format!("sha256:{}", "f".repeat(64)),
            interface: "N2".into(),
            endpoints: HashMap::new(),
            stable_source_file: "n2-sctp-provenance.pcap".into(),
        };
        let mut events = Vec::new();
        decode_capture_streaming(&config, &PseudonymKey::from_bytes([3; 32]), |event| {
            if matches!(event.protocol, event_schema::Protocol::Ngap) {
                events.push(serde_json::from_str::<serde_json::Value>(&event.to_json()).unwrap());
            }
            Ok(())
        }).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(events.len(), 5);
        let expected = &events[0]["packet_references"][0]["sctp_association"];
        assert_eq!(expected["verification_tag"], 1);
        assert_eq!(expected["association_generation"], 0);
        assert!(expected["association_id"].as_str().unwrap().starts_with("sctp-"));
        let bounds = [(1, 1), (2, 4), (5, 5), (6, 6), (7, 7)];
        for (event, (first, last)) in events.iter().zip(bounds) {
            for packet in event["packet_references"].as_array().unwrap() {
                let association = &packet["sctp_association"];
                for field in ["association_id", "association_generation", "verification_tag"] {
                    assert_eq!(association[field], expected[field]);
                }
                assert_eq!(association["first_tsn"], first, "first wire TSN");
                assert_eq!(association["last_tsn"], last, "last wire TSN");
            }
        }
    }

    /// 0.11.0 (oiran-api 2.21.120, lot B1, ordre #9 7050925249) — gate :
    /// sur les plans SCTP, décodage incrémental = décodage intégral pour
    /// tout découpage, y compris entre deux fragments d'un message et au
    /// milieu d'un bloc. Jeu N2 réel du dépôt et capture synthétique
    /// fragmentée + groupée faite de vrais messages NGAP ; 12 graines,
    /// pas fins (≤ 61 octets) et larges (≤ 3000). Le même fichier décodé
    /// comme S1-MME (PPID NGAP, donc aucun event) vérifie que le plan
    /// est admis et ne produit rien de plus que l'intégral.
    #[test]
    fn incremental_sctp_decode_matches_full_decode_for_any_split_2_21_120() {
        let datasets = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
        let inputs: Vec<(&str, &str, Vec<u8>, usize)> = vec![
            ("N2", "pcapng", std::fs::read(datasets.join("N2.pcapng")).unwrap(), 1),
            ("N2", "pcap", synthetic_n2_fragmented_capture(), 5),
            ("S1-MME", "pcap", synthetic_n2_fragmented_capture(), 0),
        ];
        let key = PseudonymKey::from_bytes([3; 32]);
        for (interface, extension, bytes, minimum_events) in &inputs {
            let path = std::env::temp_dir().join(format!(
                "oiran-incr-sctp-{}-{}-{:?}.{}",
                interface,
                std::process::id(),
                std::thread::current().id(),
                extension
            ));
            let config = DecodeConfig {
                input: path.clone(),
                capture_id: format!("sha256:{}", "f".repeat(64)),
                interface: (*interface).into(),
                endpoints: HashMap::new(),
                stable_source_file: "n2_00001_20261120.pcapng".into(),
            };
            std::fs::write(&path, bytes).unwrap();
            let mut full = Vec::new();
            decode_capture_streaming(&config, &key, |event| {
                full.push(event.to_json());
                Ok(())
            })
            .unwrap();
            assert!(
                full.len() >= *minimum_events,
                "{interface}.{extension} : {} events, au moins {minimum_events} attendus",
                full.len()
            );
            for seed in 0..12u64 {
                for max_step in [61usize, 3000] {
                    let mut session = DecodeSession::new();
                    let mut incremental = Vec::new();
                    for cut in seeded_cuts(bytes.len(), seed, max_step) {
                        std::fs::write(&path, &bytes[..cut]).unwrap();
                        decode_capture_incremental(&config, &key, &mut session, |event| {
                            incremental.push(event.to_json());
                            Ok(())
                        })
                        .unwrap();
                    }
                    assert_eq!(session.consumed_bytes(), bytes.len() as u64);
                    finish_incremental(&config, &mut session, |event| {
                        incremental.push(event.to_json());
                        Ok(())
                    })
                    .unwrap();
                    assert_eq!(
                        incremental, full,
                        "{interface}.{extension} graine {seed} pas {max_step}"
                    );
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    /// 0.10.0 — les plans à état non livrés refusent la reprise. Depuis
    /// 0.11.0 (lot B1), N2 et S1-MME l'acceptent.
    #[test]
    fn incremental_decode_is_refused_on_stateful_planes_2_21_109() {
        for interface in ["SBI", "S6a"] {
            assert!(!supports_incremental(interface));
            let config = DecodeConfig {
                input: "unused.pcap".into(),
                capture_id: format!("sha256:{}", "0".repeat(64)),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: String::new(),
            };
            let key = PseudonymKey::from_bytes([3; 32]);
            let mut session = DecodeSession::new();
            assert!(decode_capture_incremental(&config, &key, &mut session, |_| Ok(())).is_err());
        }
        for interface in ["N3", "S1-U", "S5-U", "N4", "Sxab", "S11", "S5-C", "N2", "S1-MME", "IMS", "N6"] {
            assert!(supports_incremental(interface));
        }
    }

    #[test]
    fn rejects_non_allowlisted_interface() {
        let config = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: format!("sha256:{}", "0".repeat(64)),
            interface: "eth0".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn routes_lte_without_aliasing_five_g_planes() {
        assert_eq!(sctp_route("S1-MME", 18), Some("S1-MME"));
        assert_eq!(sctp_route("N2", 60), Some("N2"));
        assert_eq!(sctp_route("S1-MME", 60), None);
        assert_eq!(sctp_route("N2", 18), None);
        assert_eq!(udp_route("S1-U", 2152, 9999), Some(UdpRoute::S1uGtpu));
        assert_eq!(udp_route("N3", 2152, 9999), Some(UdpRoute::N3Gtpu));
        assert_eq!(udp_route("S11", 2123, 9999), Some(UdpRoute::S11Gtpv2c));
        assert_eq!(udp_route("N4", 8805, 9999), Some(UdpRoute::N4Pfcp));
        assert_eq!(udp_route("S11", 2152, 9999), None);
    }

    /// 2.10.4 (devmat, revue 2.10.3 ANR2 cas S6a `_00064`/`_00065`) :
    /// S6a doit router quel que soit le PPID — certains EPC
    /// (srsEPC) émettent du Diameter avec PPID 0 au lieu de 46.
    /// Pré-2.10.4, `("S6a", 46)` strict droppait tous les chunks.
    #[test]
    fn routes_s6a_regardless_of_ppid_2_10_4() {
        assert_eq!(sctp_route("S6a", 46), Some("S6a"));
        assert_eq!(sctp_route("S6a", 0), Some("S6a"));
        assert_eq!(sctp_route("S6a", 7), Some("S6a"));
        assert_eq!(sctp_route("S6a", 255), Some("S6a"));
    }

    #[test]
    fn routes_only_tcp_3868_to_s6a_diameter_2_11_5() {
        assert!(is_s6a_diameter_tcp("S6a", 3868, 39200));
        assert!(is_s6a_diameter_tcp("S6a", 59770, 3868));
        assert!(!is_s6a_diameter_tcp("S6a", 39200, 59770));
        assert!(!is_s6a_diameter_tcp("SBI", 3868, 39200));
    }

    #[test]
    fn reassembled_s6a_tcp_emits_diameter_request_and_answer() {
        fn diameter(command: u32, request: bool) -> Vec<u8> {
            let mut bytes = vec![1, 0, 0, 20, if request { 0x80 } else { 0 }];
            bytes.extend_from_slice(&command.to_be_bytes()[1..]);
            bytes.extend_from_slice(&16_777_251u32.to_be_bytes());
            bytes.extend_from_slice(&1u32.to_be_bytes());
            bytes.extend_from_slice(&2u32.to_be_bytes());
            bytes
        }
        fn direction(
            source: transport_tcp::TcpEndpoint,
            destination: transport_tcp::TcpEndpoint,
            bytes: Vec<u8>,
            packet_number: u64,
        ) -> transport_tcp::ReassembledDirection {
            let timestamp = event_schema::ExactTimestamp {
                seconds: 1,
                nanoseconds: packet_number as u32,
                raw_ticks: packet_number,
                resolution_base: 10,
                resolution_exponent: 9,
            };
            let packet = event_schema::PacketReference {
                source_file: "synthetic-s6a.pcap".into(),
                sctp_association: None,
                source_sha256: Some("0".repeat(64)),
                packet_number,
                byte_offset: packet_number * 64,
                interface_id: 0,
                link_type: Some(1),
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: bytes.len() as u32,
                original_length: bytes.len() as u32,
            };
            transport_tcp::ReassembledDirection {
                source,
                destination,
                spans: vec![transport_tcp::ProvenanceSpan {
                    start: 0,
                    end: bytes.len(),
                    timestamp,
                    packet,
                }],
                bytes,
                incomplete: false,
                retransmissions: 0,
                duplicate_segments: 0,
            }
        }

        let client = transport_tcp::TcpEndpoint {
            address: "192.0.2.10".into(),
            port: 39200,
        };
        let server = transport_tcp::TcpEndpoint {
            address: "192.0.2.20".into(),
            port: 3868,
        };
        let (key, _) = transport_tcp::TcpConnectionKey::new(client.clone(), server.clone());
        let connection = transport_tcp::ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), diameter(318, true), 1),
                direction(server, client, diameter(318, false), 2),
            ],
        };
        let config = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: format!("sha256:{}", "0".repeat(64)),
            interface: "S6a".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = PseudonymKey::from_bytes([0x33; 32]);
        let mut events = Vec::new();
        let mut count = 0;
        let mut error = None;
        let mut key_ordinals: HashMap<String, u32> = HashMap::new();
        assert_eq!(
            emit_diameter_connections(
                vec![connection],
                &config,
                &DiameterDecoder,
                &key,
                &mut key_ordinals,
                &mut |event| {
                    events.push(event);
                    Ok(())
                },
                &mut count,
                &mut error,
            ),
            1
        );
        assert_eq!(error, None);
        assert_eq!(count, 2);
        assert_eq!(events[0].message_name, "Authentication-Information-Request");
        assert_eq!(events[1].message_name, "Authentication-Information-Answer");
    }

    #[test]
    fn diameter_tcp_framing_handles_two_messages_in_one_segment_and_one_in_two_2_11_6() {
        fn message(command: u32, request: bool) -> Vec<u8> {
            let mut bytes = vec![1, 0, 0, 20, if request { 0x80 } else { 0 }];
            bytes.extend_from_slice(&command.to_be_bytes()[1..]);
            bytes.extend_from_slice(&16_777_251u32.to_be_bytes());
            bytes.extend_from_slice(&command.to_be_bytes());
            bytes.extend_from_slice(&(command + 1).to_be_bytes());
            bytes
        }
        fn packet(number: u64, length: usize) -> event_schema::PacketReference {
            event_schema::PacketReference {
                source_file: "synthetic-s6a.pcap".into(),
                sctp_association: None,
                source_sha256: Some("0".repeat(64)),
                packet_number: number,
                byte_offset: number * 64,
                interface_id: 0,
                link_type: Some(1),
                sll2_protocol_type: None,
                sll2_reserved: None,
                sll2_interface_index: None,
                sll2_arphrd_type: None,
                sll2_packet_type: None,
                sll2_address_length: None,
                sll2_address: None,
                captured_length: length as u32,
                original_length: length as u32,
            }
        }
        fn timestamp(number: u64) -> event_schema::ExactTimestamp {
            event_schema::ExactTimestamp {
                seconds: 1,
                nanoseconds: number as u32,
                raw_ticks: number,
                resolution_base: 10,
                resolution_exponent: 9,
            }
        }

        let client = transport_tcp::TcpEndpoint {
            address: "192.0.2.10".into(),
            port: 39200,
        };
        let server = transport_tcp::TcpEndpoint {
            address: "192.0.2.20".into(),
            port: 3868,
        };
        let mut requests = message(318, true);
        requests.extend_from_slice(&message(316, true));
        let answer = message(318, false);
        let request_direction = transport_tcp::ReassembledDirection {
            source: client.clone(),
            destination: server.clone(),
            spans: vec![transport_tcp::ProvenanceSpan {
                start: 0,
                end: requests.len(),
                timestamp: timestamp(1),
                packet: packet(1, requests.len()),
            }],
            bytes: requests,
            incomplete: false,
            retransmissions: 0,
            duplicate_segments: 0,
        };
        let answer_direction = transport_tcp::ReassembledDirection {
            source: server.clone(),
            destination: client.clone(),
            spans: vec![
                transport_tcp::ProvenanceSpan {
                    start: 0,
                    end: 10,
                    timestamp: timestamp(2),
                    packet: packet(2, 10),
                },
                transport_tcp::ProvenanceSpan {
                    start: 10,
                    end: answer.len(),
                    timestamp: timestamp(3),
                    packet: packet(3, answer.len() - 10),
                },
            ],
            bytes: answer,
            incomplete: false,
            retransmissions: 0,
            duplicate_segments: 0,
        };
        let (connection_key, _) =
            transport_tcp::TcpConnectionKey::new(client, server);
        let connection = transport_tcp::ReassembledConnection {
            key: connection_key,
            directions: [request_direction, answer_direction],
        };
        let config = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: format!("sha256:{}", "0".repeat(64)),
            interface: "S6a".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = PseudonymKey::from_bytes([0x44; 32]);
        let mut events = Vec::new();
        let mut count = 0;
        let mut error = None;
        let mut key_ordinals: HashMap<String, u32> = HashMap::new();
        emit_diameter_connections(
            vec![connection],
            &config,
            &DiameterDecoder,
            &key,
            &mut key_ordinals,
            &mut |event| {
                events.push(event);
                Ok(())
            },
            &mut count,
            &mut error,
        );
        assert_eq!(error, None);
        assert_eq!(count, 3);
        assert_eq!(
            events
                .iter()
                .map(|event| event.message_name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Authentication-Information-Request",
                "Update-Location-Request",
                "Authentication-Information-Answer",
            ]
        );
        assert!(events
            .iter()
            .all(|event| event.decoding_status == event_schema::DecodeStatus::Decoded));
        assert_eq!(
            events[2]
                .packet_references
                .iter()
                .map(|packet| packet.packet_number)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
    }

    #[test]
    fn accepts_explicit_lte_interfaces() {
        for interface in ["S1-MME", "S1-U", "S11"] {
            let config = DecodeConfig {
                input: "unused.pcap".into(),
                capture_id: format!("sha256:{}", "0".repeat(64)),
                interface: interface.into(),
                endpoints: HashMap::new(),
                stable_source_file: String::new(),
            };
            assert!(validate_config(&config).is_ok(), "{interface}");
        }
    }

    #[test]
    fn atomic_empty_event_output_is_finalized_without_temporary_files() {
        let root = std::env::temp_dir().join(format!(
            "oiran-decode-atomic-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("oiran_events.jsonl");

        write_jsonl_atomic(&destination, &[]).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), Vec::<u8>::new());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
    }

    /// 2.11.1 (devmat, revue ANR1 #10 comment 6778895992 rollback 2.10.4) :
    /// non-régression — l'ajout des routes IMS/SIP/RTP en 2.11.0 ne
    /// doit PAS changer les events produits sur les interfaces hors
    /// IMS. On décode le pcap N3 de référence deux fois (via deux
    /// instances indépendantes de `decode_capture_streaming`) et on
    /// vérifie que la deuxième passe produit EXACTEMENT les mêmes
    /// event_ids déterministes. Idem S1-U/S5-U si fixtures
    /// disponibles. L'invariant est : les event_ids sont une
    /// fonction pure (pcap_bytes × capture_id × pseudonym_key) ; ils
    /// ne dépendent ni de la liste des décodeurs enregistrés, ni du
    /// nouveau routage IMS SIP. La régression `Changed des events`
    /// serait une régression wire-identity → session-engine ne
    /// retrouverait plus ses correspondances N3 ↔ N4.
    #[test]
    fn non_regression_n3_decode_stable_after_2_11_0() {
        use std::path::PathBuf;
        let n3 = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N3.pcapng");
        if !n3.is_file() {
            eprintln!(
                "SKIP non_regression_n3_decode_stable_after_2_11_0: fixture {} absent",
                n3.display()
            );
            return;
        }
        let key_bytes = [0x11; 32];
        let key = PseudonymKey::from_bytes(key_bytes);
        let config = DecodeConfig {
            input: n3.clone(),
            capture_id: format!("sha256:{}", "0".repeat(64)),
            interface: "N3".into(),
            endpoints: Default::default(),
            stable_source_file: String::new(),
        };
        let mut events_a = Vec::new();
        let _ = decode_capture_streaming(&config, &key, |event| {
            events_a.push(event);
            Ok(())
        })
        .unwrap();
        let mut events_b = Vec::new();
        let _ = decode_capture_streaming(&config, &key, |event| {
            events_b.push(event);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            events_a.len(),
            events_b.len(),
            "N3 decode produces a stable event count across runs"
        );
        let ids_a: Vec<&str> = events_a.iter().map(|e| e.event_id.as_str()).collect();
        let ids_b: Vec<&str> = events_b.iter().map(|e| e.event_id.as_str()).collect();
        assert_eq!(
            ids_a, ids_b,
            "2.11.0 IMS routing must not change N3 event_ids"
        );
        // Sanity: at least one event emitted (else the fixture is empty).
        assert!(!events_a.is_empty(), "N3 fixture produced zero events");
        // Interface tag must still be N3 — no silent drift into IMS.
        for event in &events_a {
            assert_eq!(event.interface, "N3", "N3 event interface drifted");
            assert!(
                matches!(
                    event.protocol,
                    event_schema::Protocol::Gtpu | event_schema::Protocol::Unknown
                ),
                "N3 event protocol unexpected: {:?}",
                event.protocol
            );
        }
    }

    /// 2.11.1 (devmat) : identique pour S1-U — on utilise le fixture
    /// N3 pcapng avec l'interface S1-U (même wire format GTP-U, le
    /// routing côté oiran-decode fait l'adressage par interface tag).
    /// Les event_ids seront différents de ceux du test N3 (le
    /// `capture_point_id` / `interface` entre dans la clé
    /// deterministic), mais stables entre deux passes.
    #[test]
    fn non_regression_s1u_decode_stable_after_2_11_0() {
        use std::path::PathBuf;
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("datasets/OIRAN_5G_PDU_SESSION_DATA_V1/N3.pcapng");
        if !fixture.is_file() {
            eprintln!("SKIP non_regression_s1u_decode_stable_after_2_11_0: fixture absent");
            return;
        }
        let key = PseudonymKey::from_bytes([0x22; 32]);
        let config = DecodeConfig {
            input: fixture.clone(),
            capture_id: format!("sha256:{}", "a".repeat(64)),
            interface: "S1-U".into(),
            endpoints: Default::default(),
            stable_source_file: String::new(),
        };
        let mut events_a = Vec::new();
        let _ = decode_capture_streaming(&config, &key, |e| {
            events_a.push(e);
            Ok(())
        })
        .unwrap();
        let mut events_b = Vec::new();
        let _ = decode_capture_streaming(&config, &key, |e| {
            events_b.push(e);
            Ok(())
        })
        .unwrap();
        assert_eq!(events_a.len(), events_b.len());
        let ids_a: Vec<&str> = events_a.iter().map(|e| e.event_id.as_str()).collect();
        let ids_b: Vec<&str> = events_b.iter().map(|e| e.event_id.as_str()).collect();
        assert_eq!(ids_a, ids_b, "2.11.0 IMS routing must not change S1-U event_ids");
        for event in &events_a {
            assert_eq!(event.interface, "S1-U", "S1-U event interface drifted");
        }
    }

    #[test]
    fn pre_sbi_decode_reports_remain_compatible() {
        let report: DecodeReport = serde_json::from_value(serde_json::json!({
            "capture_format":"Pcap","packets":26,"events":20,"warnings":0,
            "transport_errors":0,"sctp_errors":0,"incomplete_sctp":0
        }))
        .unwrap();
        assert_eq!(report.events, 20);
        assert_eq!(report.tcp_connections, 0);
        assert_eq!(report.http2_frames, 0);
        assert_eq!(report.sbi_transactions, 0);
    }

    fn fixture_event(
        capture_id: &str,
        seconds: i64,
        nanoseconds: u32,
        packet_number: u64,
        event_id: &str,
    ) -> NormalizedEvent {
        NormalizedEvent {
            event_id: event_id.into(),
            stable_event_key: String::new(),
            parent_event_id: None,
            probe_id: "probe".into(),
            capture_point_id: "cp".into(),
            capture_id: capture_id.into(),
            packet_references: vec![PacketReference {
                source_file: "capture.pcap".into(),
                sctp_association: None,
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
                captured_length: 64,
                original_length: 64,
            }],
            timestamp: event_schema::ExactTimestamp {
                seconds,
                nanoseconds,
                raw_ticks: ((seconds as u64) * 1_000_000_000) + (nanoseconds as u64),
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "S1-MME".into(),
            protocol: event_schema::Protocol::S1ap,
            message_name: "InitialContextSetupRequest".into(),
            message_type: 9,
            procedure_code: Some(9),
            procedure: None,
            security_state: None,
            source_byte_offset: None,
            source_endpoint: event_schema::Endpoint {
                address: "10.0.0.1".into(),
                port: Some(36412),
                network_function: Some("eNB".into()),
            },
            destination_endpoint: event_schema::Endpoint {
                address: "10.0.0.2".into(),
                port: Some(36412),
                network_function: Some("MME".into()),
            },
            direction: event_schema::Direction::RanToCore,
            session_identifiers: vec![],
            information_elements: vec![],
            decoder_name: "decoder-s1ap".into(),
            decoder_version: "0.2.0".into(),
            schema_version: NormalizedEvent::SCHEMA_VERSION,
            decoding_status: event_schema::DecodeStatus::Decoded,
            errors: vec![],
            raw_payload_reference: "sha256:payload".into(),
            evidence_references: vec![],
            sbi: None,
        }
    }

    #[test]
    fn sort_by_timestamp_tie_breaks_on_capture_id_then_sequence_then_event_id() {
        // 2.7.12: fully deterministic merge order for events that share
        // exactly the same packet timestamp. The sort tuple is
        // (ts.s, ts.ns, capture_id, packet_number, event_id). This test
        // runs the sort on a shuffled input and asserts the exact
        // ordering, so a future refactor cannot silently reorder events
        // that correlation and callflow reconstruction depend on.
        let s1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let s2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let shared_s = 100;
        let shared_ns = 500;
        let mut events = vec![
            fixture_event(s2, shared_s, shared_ns, 3, "evt-z"),
            fixture_event(s1, shared_s, shared_ns, 5, "evt-a"),
            fixture_event(s1, shared_s, shared_ns, 5, "evt-b"),
            fixture_event(s1, shared_s, shared_ns, 1, "evt-c"),
            fixture_event(s1, shared_s, shared_ns + 1, 0, "evt-d"),
            fixture_event(s1, shared_s - 1, 999_999_999, 0, "evt-e"),
        ];
        events.sort_by(|left, right| {
            let left_key = (
                left.timestamp.seconds,
                left.timestamp.nanoseconds,
                left.capture_id.as_str(),
                left.packet_references
                    .first()
                    .map(|packet| packet.packet_number)
                    .unwrap_or(0),
                left.event_id.as_str(),
            );
            let right_key = (
                right.timestamp.seconds,
                right.timestamp.nanoseconds,
                right.capture_id.as_str(),
                right.packet_references
                    .first()
                    .map(|packet| packet.packet_number)
                    .unwrap_or(0),
                right.event_id.as_str(),
            );
            left_key.cmp(&right_key)
        });
        let ordered: Vec<&str> = events.iter().map(|event| event.event_id.as_str()).collect();
        assert_eq!(
            ordered,
            vec!["evt-e", "evt-c", "evt-a", "evt-b", "evt-z", "evt-d"]
        );
    }

    /// 2.21.100 (défaut ANR1 #10 7045290646 point a, ordre #9 7046402022
    /// décision a, design CLAUDE1 #9 7012805654) — fixture synthétique
    /// SIP INVITE encapsulé en GTP-U(UDP 5060). `route_inner_udp_after_gtpu`
    /// doit extraire l'inner UDP, invoquer `SipDecoder::decode`, et ajouter
    /// un event SIP à `decoded` avec `interface == "N3-IMS"`.
    #[test]
    fn route_inner_udp_after_gtpu_emits_sip_event_from_tunnel_2_21_100() {
        use capture_pcap::{CapturePacket, PacketMetadata, TransportView, TransportProtocol};
        use decoder_sip::SipDecoder;
        use decoder_rtp::RtpFlowAggregator;
        use event_schema::ExactTimestamp;

        // Payload SIP minimal (INVITE sans body, headers obligatoires).
        let sip_invite: &[u8] = b"INVITE sip:callee@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.45.0.7:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=A\r\n\
To: <sip:callee@example.com>\r\n\
Call-ID: synthetic-2-21-100@oiran\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        // GTP-U header 8 bytes (version=1, pt=1, no flags, msg=0xff G-PDU, TEID=42).
        let udp_length = (8 + sip_invite.len()) as u16;
        let ip_total_len = (20 + udp_length as usize) as u16;
        let gtpu_payload_len = ip_total_len as u16;
        let mut pkt = vec![
            0x30, 0xff,
            (gtpu_payload_len >> 8) as u8, gtpu_payload_len as u8,
            0x00, 0x00, 0x00, 0x2a,
        ];
        // Inner IPv4 header (20 bytes), protocol=17 UDP, src=10.45.0.7 (UE), dst=10.0.0.1.
        pkt.extend_from_slice(&[
            0x45, 0x00,
            (ip_total_len >> 8) as u8, ip_total_len as u8,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x11,
            0x00, 0x00,
            10, 45, 0, 7,
            10, 0, 0, 1,
        ]);
        // Inner UDP header + SIP payload.
        pkt.extend_from_slice(&[
            0x13, 0xc4, // src port 5060
            0x30, 0x39, // dst port 12345
            (udp_length >> 8) as u8, udp_length as u8,
            0x00, 0x00, // checksum
        ]);
        pkt.extend_from_slice(sip_invite);

        let packet = CapturePacket {
            metadata: PacketMetadata {
                capture_id: "sha256:synthetic".into(),
                source_file: "synthetic.pcapng".into(),
                packet_number: 1,
                byte_offset: 0,
                timestamp: ExactTimestamp {
                    seconds: 10,
                    nanoseconds: 0,
                    raw_ticks: 10_000_000_000,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                captured_length: pkt.len() as u32,
                original_length: pkt.len() as u32,
                interface_id: 0,
                link_type: 1,
                sll2: None,
                truncated: false,
            },
            data: pkt.clone(),
        };
        // La TransportView couvre tout `pkt` comme UDP payload.
        let view = TransportView {
            source_ip: "172.16.0.10".into(),
            destination_ip: "172.16.0.20".into(),
            protocol: TransportProtocol::Udp,
            source_port: Some(2152),
            destination_port: Some(2152),
            payload_offset: 0,
            payload_length: pkt.len(),
        };
        let config = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: "sha256:synthetic".into(),
            interface: "N3".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let sip = SipDecoder;
        let mut rtp = RtpFlowAggregator::new();
        let mut decoded = Vec::new();
        route_inner_udp_after_gtpu(&packet, &view, &config, &key, &sip, &mut rtp, &mut decoded);
        assert!(
            !decoded.is_empty(),
            "l'inner SIP INVITE doit produire au moins un event"
        );
        let has_n3_ims_sip = decoded.iter().any(|ev| {
            ev.interface == "N3-IMS" && ev.protocol.as_str() == "SIP"
        });
        assert!(
            has_n3_ims_sip,
            "un event SIP avec interface N3-IMS doit apparaître ; decoded={:?}",
            decoded.iter().map(|e| (&e.interface, e.protocol.as_str(), &e.message_name)).collect::<Vec<_>>()
        );
    }

    /// 2.21.100 — un paquet N3 GTP-U avec inner UDP non-SIP (ex. port
    /// aléatoire sans SDP enregistré préalablement) ne produit AUCUN event
    /// SIP (ni RTP, faute de flux annoncé). `decoded` reste vide.
    #[test]
    fn route_inner_udp_after_gtpu_without_sdp_flow_emits_nothing_2_21_100() {
        use capture_pcap::{CapturePacket, PacketMetadata, TransportView, TransportProtocol};
        use decoder_sip::SipDecoder;
        use decoder_rtp::RtpFlowAggregator;
        use event_schema::ExactTimestamp;
        let payload: &[u8] = &[0u8; 160]; // payload RTP-like mais pas de SDP enregistré.
        let udp_length = (8 + payload.len()) as u16;
        let ip_total_len = (20 + udp_length as usize) as u16;
        let gtpu_len = ip_total_len as u16;
        let mut pkt = vec![
            0x30, 0xff,
            (gtpu_len >> 8) as u8, gtpu_len as u8,
            0x00, 0x00, 0x00, 0x2a,
        ];
        pkt.extend_from_slice(&[
            0x45, 0x00,
            (ip_total_len >> 8) as u8, ip_total_len as u8,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x11,
            0x00, 0x00,
            10, 45, 0, 7,
            10, 0, 0, 2,
        ]);
        pkt.extend_from_slice(&[
            0x9c, 0x44, // src port 40004
            0xc0, 0x12, // dst port 49170
            (udp_length >> 8) as u8, udp_length as u8,
            0x00, 0x00,
        ]);
        pkt.extend_from_slice(payload);

        let packet = CapturePacket {
            metadata: PacketMetadata {
                capture_id: "sha256:synthetic".into(),
                source_file: "synthetic.pcapng".into(),
                packet_number: 2,
                byte_offset: 0,
                timestamp: ExactTimestamp {
                    seconds: 10,
                    nanoseconds: 0,
                    raw_ticks: 10_000_000_000,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                captured_length: pkt.len() as u32,
                original_length: pkt.len() as u32,
                interface_id: 0,
                link_type: 1,
                sll2: None,
                truncated: false,
            },
            data: pkt.clone(),
        };
        let view = TransportView {
            source_ip: "172.16.0.10".into(),
            destination_ip: "172.16.0.20".into(),
            protocol: TransportProtocol::Udp,
            source_port: Some(2152),
            destination_port: Some(2152),
            payload_offset: 0,
            payload_length: pkt.len(),
        };
        let config = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: "sha256:synthetic".into(),
            interface: "N3".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let sip = SipDecoder;
        let mut rtp = RtpFlowAggregator::new();
        let mut decoded = Vec::new();
        route_inner_udp_after_gtpu(&packet, &view, &config, &key, &sip, &mut rtp, &mut decoded);
        assert!(
            decoded.is_empty(),
            "aucun event ne doit sortir sans SDP enregistré ni SIP sur 5060 ; got {:?}",
            decoded
        );
    }

    /// 2.21.108 contre-vérification (ordre #9 7049622543) — test croisé :
    /// un même INVITE (même Call-ID) apparaît dans deux plans :
    ///   * paquet N3 GTP-U encapsulant SIP ⇒ event `interface="N3-IMS"`
    ///     (route `route_inner_udp_after_gtpu`, décision 2.21.100 (a)).
    ///   * paquet N6 UDP 5060 SIP ⇒ event `interface="IMS"`
    ///     (route `ImsSip`, décision 2.21.107 CLAUDE1).
    /// Les 2 events coexistent en données brutes avec le MÊME `Call-ID`
    /// (clé de dédup documentée dans CHANGELOG 2.21.100 §règle de dédup) ;
    /// la dédup est à graver côté `correlation-engine` dans un lot futur.
    /// Comptage voix logique = 1 call (prouvé par call_id identique).
    #[test]
    fn cross_plane_n3_and_n6_invite_same_call_id_coexist_2_21_108() {
        use capture_pcap::{CapturePacket, PacketMetadata, TransportView, TransportProtocol};
        use decoder_sip::SipDecoder;
        use decoder_rtp::RtpFlowAggregator;
        use event_schema::ExactTimestamp;

        let call_id = "cross-n3-n6-2-21-108@oiran";
        let sip_invite = format!(
            "INVITE sip:callee@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.45.0.7:5060;branch=z9hG4bK1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@example.com>;tag=A\r\n\
To: <sip:callee@example.com>\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n"
        );
        let sip_bytes = sip_invite.as_bytes();

        // === Plan N3 (tunnel GTP-U) ===
        let udp_length = (8 + sip_bytes.len()) as u16;
        let ip_total_len = (20 + udp_length as usize) as u16;
        let gtpu_payload_len = ip_total_len as u16;
        let mut n3_pkt = vec![
            0x30, 0xff,
            (gtpu_payload_len >> 8) as u8, gtpu_payload_len as u8,
            0x00, 0x00, 0x00, 0x2a,
        ];
        n3_pkt.extend_from_slice(&[
            0x45, 0x00,
            (ip_total_len >> 8) as u8, ip_total_len as u8,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x11,
            0x00, 0x00,
            10, 45, 0, 7,
            10, 0, 0, 1,
        ]);
        n3_pkt.extend_from_slice(&[
            0x13, 0xc4,
            0x30, 0x39,
            (udp_length >> 8) as u8, udp_length as u8,
            0x00, 0x00,
        ]);
        n3_pkt.extend_from_slice(sip_bytes);

        let n3_packet = CapturePacket {
            metadata: PacketMetadata {
                capture_id: "sha256:synthetic-n3".into(),
                source_file: "N3.pcapng".into(),
                packet_number: 1,
                byte_offset: 0,
                timestamp: ExactTimestamp {
                    seconds: 10,
                    nanoseconds: 0,
                    raw_ticks: 10_000_000_000,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                captured_length: n3_pkt.len() as u32,
                original_length: n3_pkt.len() as u32,
                interface_id: 0,
                link_type: 1,
                sll2: None,
                truncated: false,
            },
            data: n3_pkt.clone(),
        };
        let n3_view = TransportView {
            source_ip: "172.16.0.10".into(),
            destination_ip: "172.16.0.20".into(),
            protocol: TransportProtocol::Udp,
            source_port: Some(2152),
            destination_port: Some(2152),
            payload_offset: 0,
            payload_length: n3_pkt.len(),
        };
        let config_n3 = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: "sha256:synthetic-n3".into(),
            interface: "N3".into(),
            endpoints: HashMap::new(),
            stable_source_file: String::new(),
        };
        let key = event_schema::PseudonymKey::from_bytes([7; 32]);
        let sip = SipDecoder;
        let mut rtp = RtpFlowAggregator::new();
        let mut decoded_n3 = Vec::new();
        route_inner_udp_after_gtpu(&n3_packet, &n3_view, &config_n3, &key, &sip, &mut rtp, &mut decoded_n3);
        let n3_ims_event = decoded_n3
            .iter()
            .find(|ev| ev.interface == "N3-IMS" && ev.protocol.as_str() == "SIP")
            .expect("event SIP N3-IMS doit exister depuis le tunnel");

        // === Plan N6 (SIP direct sur UDP 5060) ===
        // Même SIP payload, directement en DecoderInput interface "IMS"
        // (c'est ce que fait `oiran-decode` sur une route `UdpRoute::ImsSip`
        // depuis `N6` ou `IMS` en 2.21.107).
        let n6_raw = format!("sha256:{}", sha256_hex(sip_bytes));
        let n6_refs = [PacketReference {
            source_file: "N6.pcap-synthetic".into(),
            sctp_association: None,
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
            captured_length: sip_bytes.len() as u32,
            original_length: sip_bytes.len() as u32,
        }];
        let n6_input = DecoderInput {
            capture_id: "sha256:synthetic-n6",
            packet_references: &n6_refs,
            timestamp: &ExactTimestamp {
                seconds: 10,
                nanoseconds: 100,
                raw_ticks: 10_000_000_100,
                resolution_base: 10,
                resolution_exponent: 9,
            },
            interface: "IMS",
            source_endpoint: Endpoint {
                address: "10.47.0.7".into(),
                port: Some(5060),
                network_function: None,
            },
            destination_endpoint: Endpoint {
                address: "10.47.0.1".into(),
                port: Some(5060),
                network_function: None,
            },
            payload: sip_bytes,
            raw_payload_reference: &n6_raw,
            pseudonym_key: &key,
        };
        let n6_output = sip.decode(&n6_input);
        let n6_ims_event = n6_output
            .events
            .iter()
            .find(|ev| ev.interface == "IMS" && ev.protocol.as_str() == "SIP")
            .expect("event SIP IMS doit exister depuis N6");

        // Coexistence : 2 events, 2 plans distincts.
        assert_eq!(n3_ims_event.interface, "N3-IMS");
        assert_eq!(n6_ims_event.interface, "IMS");

        // Clé de dédup documentée : call_id identique sur les 2 events.
        // (Côté correlation-engine, la dédup graverait la priorité ; ici
        // on prouve que la clé est **extractible** et identique des 2 côtés.)
        let extract_call_id = |ev: &NormalizedEvent| -> Option<String> {
            ev.information_elements
                .iter()
                .find(|ie| ie.name.eq_ignore_ascii_case("call-id"))
                .and_then(|ie| ie.value.clone())
                .or_else(|| {
                    ev.session_identifiers
                        .iter()
                        .find(|id| id.name.eq_ignore_ascii_case("sip_call_id"))
                        .map(|id| id.value.clone())
                })
        };
        let n3_call_id = extract_call_id(n3_ims_event)
            .expect("call_id doit être extractible depuis l'event N3-IMS");
        let n6_call_id = extract_call_id(n6_ims_event)
            .expect("call_id doit être extractible depuis l'event IMS");
        assert_eq!(
            n3_call_id, n6_call_id,
            "clé de dédup (call_id) doit être identique sur les 2 plans (preuve pour correlation-engine)"
        );

        // Comptage voix logique (= 1 call unique, dédoublonnée hors
        // décodeur par la règle correlation-engine à graver) :
        let unique_call_ids: std::collections::HashSet<String> =
            [n3_call_id, n6_call_id].into_iter().collect();
        assert_eq!(
            unique_call_ids.len(),
            1,
            "comptage voix logique = 1 call (même call_id, 2 plans)"
        );
    }

    /// 2.21.110 — pcap classique (Ethernet) de G-PDU : IP/UDP 2152 externe,
    /// en-tête GTP-U de 8 octets (TEID 0x2a), IPv4/UDP interne.
    /// `inner` = (ip source, port source, ip destination, port destination,
    /// payload UDP interne).
    fn gpdu_pcap(path: &std::path::Path, inner: &[([u8; 4], u16, [u8; 4], u16, Vec<u8>)]) {
        let mut file = Vec::new();
        file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        file.extend_from_slice(&2u16.to_le_bytes());
        file.extend_from_slice(&4u16.to_le_bytes());
        file.extend_from_slice(&[0u8; 8]);
        file.extend_from_slice(&65_535u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        for (index, (src, sport, dst, dport, payload)) in inner.iter().enumerate() {
            let inner_udp_len = (8 + payload.len()) as u16;
            let inner_ip_len = 20 + inner_udp_len;
            let outer_udp_len = 8 + 8 + inner_ip_len;
            let outer_ip_len = 20 + outer_udp_len;
            let mut frame = vec![0u8; 12];
            frame.extend_from_slice(&[0x08, 0x00]);
            frame.extend_from_slice(&[0x45, 0x00]);
            frame.extend_from_slice(&outer_ip_len.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
            frame.extend_from_slice(&[172, 16, 0, 10]);
            frame.extend_from_slice(&[172, 16, 0, 20]);
            frame.extend_from_slice(&2152u16.to_be_bytes());
            frame.extend_from_slice(&2152u16.to_be_bytes());
            frame.extend_from_slice(&outer_udp_len.to_be_bytes());
            frame.extend_from_slice(&[0, 0]);
            frame.extend_from_slice(&[0x30, 0xff]);
            frame.extend_from_slice(&inner_ip_len.to_be_bytes());
            frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x2a]);
            frame.extend_from_slice(&[0x45, 0x00]);
            frame.extend_from_slice(&inner_ip_len.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]);
            frame.extend_from_slice(src);
            frame.extend_from_slice(dst);
            frame.extend_from_slice(&sport.to_be_bytes());
            frame.extend_from_slice(&dport.to_be_bytes());
            frame.extend_from_slice(&inner_udp_len.to_be_bytes());
            frame.extend_from_slice(&[0, 0]);
            frame.extend_from_slice(payload);
            file.extend_from_slice(&(1_795_200_000u32 + index as u32).to_le_bytes());
            file.extend_from_slice(&0u32.to_le_bytes());
            file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            file.extend_from_slice(&frame);
        }
        std::fs::write(path, file).unwrap();
    }

    /// 2.21.110 (ordre #9 7049845272) — un appel porté dans le tunnel
    /// GTP-U : INVITE + SDP puis RTP du flux annoncé. Décodage de bout en
    /// bout (`decode_capture_streaming`) sur les trois plans tunnel :
    ///   * le SIP sort `N3-IMS` (2.21.100) ;
    ///   * le flux RTP sort `N3-IMS` aussi, avec le même Call-ID — avant
    ///     2.21.110 il sortait avec l'interface du plan (`N3`) ;
    ///   * aucun event SIP ou RTP ne porte l'interface du plan ;
    ///   * les events GTP-U gardent l'interface du plan.
    #[test]
    fn tunnel_rtp_flow_is_published_n3_ims_like_tunnel_sip_2_21_110() {
        let call_id = "tunnel-rtp-2-21-110@oiran";
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 10.45.0.7\r\n\
s=-\r\n\
c=IN IP4 10.45.0.7\r\n\
t=0 0\r\n\
m=audio 40004 RTP/AVP 0\r\n\
a=rtpmap:0 PCMU/8000\r\n";
        let invite = format!(
            "INVITE sip:callee@example.invalid SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.45.0.7:5060;branch=z9hG4bK110\r\n\
Max-Forwards: 70\r\n\
From: <sip:caller@example.invalid>;tag=A\r\n\
To: <sip:callee@example.invalid>\r\n\
Call-ID: {call_id}\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\
\r\n{sdp}",
            sdp.len()
        );
        let ue = [10, 45, 0, 7];
        let peer = [10, 0, 0, 2];
        let mut inner = vec![(ue, 5060u16, [10, 0, 0, 1], 5060u16, invite.into_bytes())];
        for seq in 0u16..4 {
            let mut rtp = vec![0x80, 0x00];
            rtp.extend_from_slice(&(100 + seq).to_be_bytes());
            rtp.extend_from_slice(&(160 * seq as u32).to_be_bytes());
            rtp.extend_from_slice(&0x1122_3344u32.to_be_bytes());
            rtp.extend_from_slice(&[0xd5; 160]);
            inner.push((ue, 40_004, peer, 49_170, rtp));
        }
        let path = std::env::temp_dir().join(format!(
            "oiran-tunnel-rtp-{}-{:?}.pcap",
            std::process::id(),
            std::thread::current().id()
        ));
        gpdu_pcap(&path, &inner);
        let key = PseudonymKey::from_bytes([9; 32]);
        for plane in ["N3", "S1-U", "S5-U"] {
            let config = DecodeConfig {
                input: path.clone(),
                capture_id: format!("sha256:{}", "e".repeat(64)),
                interface: plane.into(),
                endpoints: HashMap::new(),
                stable_source_file: String::new(),
            };
            let mut events = Vec::new();
            decode_capture_streaming(&config, &key, |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
            let call_id_of = |event: &NormalizedEvent| {
                event
                    .session_identifiers
                    .iter()
                    .find(|id| id.name == "sip_call_id")
                    .map(|id| id.value.clone())
            };
            let sip: Vec<_> = events.iter().filter(|e| e.protocol.as_str() == "SIP").collect();
            let rtp: Vec<_> = events.iter().filter(|e| e.protocol.as_str() == "RTP").collect();
            let gtpu: Vec<_> = events.iter().filter(|e| e.protocol.as_str() == "GTP-U").collect();
            assert_eq!(sip.len(), 1, "{plane} : un event SIP ; events={events:?}");
            assert_eq!(rtp.len(), 1, "{plane} : un event de flux RTP ; events={events:?}");
            assert_eq!(sip[0].interface, "N3-IMS", "{plane}");
            assert_eq!(rtp[0].interface, "N3-IMS", "{plane} : RTP du tunnel = même marqueur que le SIP");
            assert_eq!(rtp[0].capture_point_id, "N3-IMS", "{plane}");
            assert_eq!(rtp[0].message_name, "RTP Flow");
            assert_eq!(call_id_of(rtp[0]).as_deref(), Some(call_id), "{plane}");
            assert_eq!(call_id_of(sip[0]), call_id_of(rtp[0]), "{plane}");
            assert!(
                events
                    .iter()
                    .filter(|e| matches!(e.protocol.as_str(), "SIP" | "RTP"))
                    .all(|e| e.interface != plane),
                "{plane} : aucun event voix ne porte l'interface du plan"
            );
            assert_eq!(gtpu.len(), inner.len(), "{plane} : un event GTP-U par G-PDU");
            assert!(gtpu.iter().all(|e| e.interface == plane), "{plane} : GTP-U inchangé");

            // Chemin incrémental du lecteur live (2.21.109 lot A) : le flux
            // RTP n'est émis qu'à la clôture, avec le même marqueur.
            let mut session = DecodeSession::new();
            let mut live = Vec::new();
            decode_capture_incremental(&config, &key, &mut session, |event| {
                live.push(event);
                Ok(())
            })
            .unwrap();
            assert!(
                live.iter().all(|e| e.protocol.as_str() != "RTP"),
                "{plane} : pas de flux RTP avant la clôture"
            );
            let mut closing = Vec::new();
            finish_incremental(&config, &mut session, |event| {
                closing.push(event);
                Ok(())
            })
            .unwrap();
            assert_eq!(closing.len(), 1, "{plane} : un flux RTP à la clôture");
            assert_eq!(closing[0].protocol.as_str(), "RTP");
            assert_eq!(closing[0].interface, "N3-IMS", "{plane} : chemin incrémental");
            assert_eq!(closing[0].event_id, rtp[0].event_id, "{plane} : parité avec le décodage intégral");
        }
        let _ = std::fs::remove_file(&path);
    }
}
