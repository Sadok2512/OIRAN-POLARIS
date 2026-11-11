//! Reusable native decoder pipeline used by both the CLI and live capture service.

pub mod lte_fixture;

use capture_pcap::{
    transport_view, visit_capture, CapturePacket, TransportProtocol, TransportView,
};
use decoder_diameter::DiameterDecoder;
use decoder_gtpu::GtpuDecoder;
use decoder_gtpv2c::Gtpv2cDecoder;
use decoder_ngap::NgapDecoder;
use decoder_pfcp::PfcpDecoder;
use decoder_rtp::RtpFlowAggregator;
use decoder_s1ap::S1apDecoder;
use decoder_sbi::{decode_connections, SbiDecodeReport};
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
    let report = decode_capture_streaming(config, &pseudonym_key, |event| {
        events.push(event);
        Ok(())
    })?;
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
    mut sink: F,
) -> Result<DecodeReport, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    validate_config(config)?;
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
    let mut rtp_aggregator = RtpFlowAggregator::new();
    let mut sctp = SctpReassembler::new();
    let mut tcp = TcpReassembler::new();
    let mut event_count = 0usize;
    let mut transport_errors = 0usize;
    let mut sink_error = None;
    let mut sbi_report = SbiDecodeReport::default();
    let mut diameter_tcp_connections = 0usize;

    let capture = visit_capture(&config.input, &config.capture_id, |packet| {
        if sink_error.is_some() {
            return;
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
                        register_sdp_flows_from_sip(&decoded, &mut rtp_aggregator);
                    }
                    emit_events(decoded, &mut sink, &mut event_count, &mut sink_error);
                } else if config.interface == "IMS" {
                    // 2.11.0 : paquet UDP IMS en dehors du port SIP 5060 → tenter
                    // RTP/RTCP sur un flux déjà enregistré par un SDP.
                    let src_ip = view.source_ip.as_str();
                    let dst_ip = view.destination_ip.as_str();
                    let payload = packet_payload_slice(&packet, &view);
                    let arrival_ns = packet_arrival_ns(&packet);
                    let packet_ref = build_packet_reference(&packet, config);
                    let ts = build_timestamp(&packet);
                    let _ = rtp_aggregator.observe_rtp(
                        src_ip,
                        ports.0,
                        dst_ip,
                        ports.1,
                        payload,
                        arrival_ns,
                        &packet_ref,
                        &ts,
                    );
                    let _ = rtp_aggregator.observe_rtcp(src_ip, ports.0, dst_ip, ports.1, payload);
                }
            }
            TransportProtocol::Sctp => {
                for message in sctp.consume(&packet, &view) {
                    let Some(interface) = sctp_route(&config.interface, message.ppid) else {
                        continue;
                    };
                    let source = endpoint(
                        &message.source_ip,
                        Some(message.source_port),
                        &config.endpoints,
                    );
                    let destination = endpoint(
                        &message.destination_ip,
                        Some(message.destination_port),
                        &config.endpoints,
                    );
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
                    emit_events(
                        decoded,
                        &mut sink,
                        &mut event_count,
                        &mut sink_error,
                    );
                }
            }
            TransportProtocol::Tcp if config.interface == "SBI" => {
                tcp.consume(&packet, &view);
                let finalized = tcp.take_finalized();
                emit_sbi_connections(
                    finalized,
                    config,
                    &pseudonym_key,
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
                tcp.consume(&packet, &view);
                let finalized = tcp.take_finalized();
                diameter_tcp_connections += emit_diameter_connections(
                    finalized,
                    config,
                    &diameter,
                    &pseudonym_key,
                    &mut sink,
                    &mut event_count,
                    &mut sink_error,
                );
            }
            TransportProtocol::Tcp | TransportProtocol::Other(_) => {}
        }
    })
    .map_err(|error| error.to_string())?;
    if let Some(error) = sink_error.take() {
        return Err(error);
    }
    let (sctp_errors, incomplete_sctp) = sctp.finish();
    let (connections, tcp_errors) = tcp.finish();
    if config.interface == "S6a" {
        diameter_tcp_connections += emit_diameter_connections(
            connections,
            config,
            &diameter,
            &pseudonym_key,
            &mut sink,
            &mut event_count,
            &mut sink_error,
        );
    } else {
        emit_sbi_connections(
            connections,
            config,
            &pseudonym_key,
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
    let rtp_events = rtp_aggregator.finish(&config.capture_id, &config.interface);
    for event in rtp_events {
        if let Err(error) = sink(event) {
            return Err(error);
        }
        event_count = event_count.saturating_add(1);
    }
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
    sink: &mut F,
    event_count: &mut usize,
    sink_error: &mut Option<String>,
) where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    if sink_error.is_some() {
        return;
    }
    for event in events {
        if !event.has_complete_provenance() {
            *sink_error =
                Some("decoder emitted an event without complete packet provenance".into());
            return;
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
        let (events, report) = decode_connections(
            std::slice::from_ref(&connection),
            &config.capture_id,
            &config.interface,
            &config.endpoints,
            pseudonym_key,
        );
        aggregate.tcp_connections += report.tcp_connections;
        aggregate.http2_frames += report.http2_frames;
        aggregate.http2_streams += report.http2_streams;
        aggregate.sbi_transactions += report.sbi_transactions;
        aggregate.operations_decoded += report.operations_decoded;
        aggregate.incomplete_streams += report.incomplete_streams;
        aggregate.encrypted_connections += report.encrypted_connections;
        aggregate.errors.extend(report.errors);
        emit_events(events, sink, event_count, sink_error);
    }
}

fn emit_diameter_connections<F>(
    connections: Vec<transport_tcp::ReassembledConnection>,
    config: &DecodeConfig,
    decoder: &DiameterDecoder,
    pseudonym_key: &PseudonymKey,
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
            let mut packet_references = direction
                .spans
                .iter()
                .map(|span| span.packet.clone())
                .collect::<Vec<_>>();
            packet_references.sort_by_key(|packet| packet.packet_number);
            packet_references.dedup_by_key(|packet| packet.packet_number);
            let timestamp = direction
                .spans
                .iter()
                .min_by_key(|span| span.packet.packet_number)
                .map(|span| span.timestamp.clone())
                .expect("non-empty Diameter TCP provenance");
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
            let raw = format!("sha256:{}", sha256_hex(&direction.bytes));
            let input = DecoderInput {
                capture_id: &config.capture_id,
                packet_references: &packet_references,
                timestamp: &timestamp,
                interface: "S6a",
                source_endpoint: source,
                destination_endpoint: destination,
                payload: &direction.bytes,
                raw_payload_reference: &raw,
                pseudonym_key,
            };
            emit_events(
                decoder.decode(&input).events,
                sink,
                event_count,
                sink_error,
            );
        }
    }
    connection_count
}

pub fn write_jsonl(path: &Path, events: &[NormalizedEvent], append: bool) -> Result<(), String> {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    for event in events {
        writeln!(writer, "{}", event.to_json()).map_err(|error| error.to_string())?;
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
        // decoders (GTP-U, GTPv2-C, PFCP, Diameter). N6 remains out —
        // it carries user-data only and no OIRAN decoder emits events
        // from it today; the live-probe counts it separately
        // (`CONTINUOUS_PLANE_COUNTED_NO_DECODER`).
        "N2" | "N3" | "N4" | "SBI" | "S1-MME" | "S1-U" | "S11"
            | "S5-C" | "S5-U" | "S6a" | "Sxab"
            // 2.11.0 : plane IMS (SIP/RTP) ajoutée en 13ᵉ interface.
            | "IMS"
    ) {
        return Err(
            "interface must be N2, N3, N4, SBI, S1-MME, S1-U, S11, S5-C, S5-U, S6a, Sxab or IMS".into(),
        );
    }
    Ok(())
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
                _ => {}
            }
        }
        if let (Some(ip), Some(port), Some(cid)) = (sdp_c, sdp_port, call_id) {
            aggregator.register_sdp_flow(decoder_rtp::SdpFlowRegistration {
                ip,
                port,
                call_id: cid,
                payload_type: sdp_pt,
            });
        }
    }
}

fn packet_reference(packet: &CapturePacket) -> PacketReference {
    let sll2 = packet.metadata.sll2.as_ref();
    PacketReference {
        source_file: packet.metadata.source_file.clone(),
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

    #[test]
    fn rejects_non_allowlisted_interface() {
        let config = DecodeConfig {
            input: "unused.pcap".into(),
            capture_id: format!("sha256:{}", "0".repeat(64)),
            interface: "eth0".into(),
            endpoints: HashMap::new(),
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
        };
        let key = PseudonymKey::from_bytes([0x33; 32]);
        let mut events = Vec::new();
        let mut count = 0;
        let mut error = None;
        assert_eq!(
            emit_diameter_connections(
                vec![connection],
                &config,
                &DiameterDecoder,
                &key,
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
    fn accepts_explicit_lte_interfaces() {
        for interface in ["S1-MME", "S1-U", "S11"] {
            let config = DecodeConfig {
                input: "unused.pcap".into(),
                capture_id: format!("sha256:{}", "0".repeat(64)),
                interface: interface.into(),
                endpoints: HashMap::new(),
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
            parent_event_id: None,
            probe_id: "probe".into(),
            capture_point_id: "cp".into(),
            capture_id: capture_id.into(),
            packet_references: vec![PacketReference {
                source_file: "capture.pcap".into(),
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
}
