//! Reusable native decoder pipeline used by both the CLI and live capture service.

use capture_pcap::{
    transport_view, visit_capture, CapturePacket, TransportProtocol, TransportView,
};
use decoder_gtpu::GtpuDecoder;
use decoder_gtpv2c::Gtpv2cDecoder;
use decoder_ngap::NgapDecoder;
use decoder_pfcp::PfcpDecoder;
use decoder_s1ap::S1apDecoder;
use decoder_sbi::{decode_connections, SbiDecodeReport};
use event_schema::{sha256_hex, Endpoint, NormalizedEvent, PacketReference};
use plugin_runtime::{DecoderInput, ProtocolDecoder};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use transport_sctp::SctpReassembler;
use transport_tcp::TcpReassembler;

pub const VERSION: &str = "0.5.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpRoute {
    N3Gtpu,
    N4Pfcp,
    S1uGtpu,
    S11Gtpv2c,
}

fn udp_route(interface: &str, source_port: u16, destination_port: u16) -> Option<UdpRoute> {
    let has_port = |port| source_port == port || destination_port == port;
    match interface {
        "N3" if has_port(2152) => Some(UdpRoute::N3Gtpu),
        "N4" if has_port(8805) => Some(UdpRoute::N4Pfcp),
        "S1-U" if has_port(2152) => Some(UdpRoute::S1uGtpu),
        "S11" if has_port(2123) => Some(UdpRoute::S11Gtpv2c),
        _ => None,
    }
}

fn sctp_route(interface: &str, ppid: u32) -> Option<&'static str> {
    match (interface, ppid) {
        ("N2", 60) => Some("N2"),
        ("S1-MME", 18) => Some("S1-MME"),
        _ => None,
    }
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
    let mut events = Vec::new();
    let report = decode_capture_streaming(config, |event| {
        events.push(event);
        Ok(())
    })?;
    events.sort_by_key(|event| {
        (
            event.timestamp.seconds,
            event.timestamp.nanoseconds,
            event
                .packet_references
                .first()
                .map(|packet| packet.packet_number)
                .unwrap_or(0),
        )
    });
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
    mut sink: F,
) -> Result<DecodeReport, String>
where
    F: FnMut(NormalizedEvent) -> Result<(), String>,
{
    validate_config(config)?;
    let ngap = NgapDecoder;
    let s1ap = S1apDecoder;
    let pfcp = PfcpDecoder;
    let gtpu = GtpuDecoder;
    let gtpv2c = Gtpv2cDecoder;
    let mut sctp = SctpReassembler::new();
    let mut tcp = TcpReassembler::new();
    let mut event_count = 0usize;
    let mut transport_errors = 0usize;
    let mut sink_error = None;
    let mut sbi_report = SbiDecodeReport::default();

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
                    };
                    let mut decoded = Vec::new();
                    decode_udp(decoder, &packet, &view, config, interface, &mut decoded);
                    emit_events(decoded, &mut sink, &mut event_count, &mut sink_error);
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
                    };
                    let decoded = if interface == "S1-MME" {
                        s1ap.decode(&input).events
                    } else {
                        ngap.decode(&input).events
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
                    &mut sink,
                    &mut event_count,
                    &mut sink_error,
                    &mut sbi_report,
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
    emit_sbi_connections(
        connections,
        config,
        &mut sink,
        &mut event_count,
        &mut sink_error,
        &mut sbi_report,
    );
    if let Some(error) = sink_error {
        return Err(error);
    }
    Ok(DecodeReport {
        capture_format: format!("{:?}", capture.format),
        packets: capture.packets,
        events: event_count,
        warnings: capture.warnings.len(),
        transport_errors,
        sctp_errors: sctp_errors.len(),
        incomplete_sctp,
        tcp_connections: sbi_report.tcp_connections,
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
        "N2" | "N3" | "N4" | "SBI" | "S1-MME" | "S1-U" | "S11"
    ) {
        return Err("interface must be N2, N3, N4, SBI, S1-MME, S1-U or S11".into());
    }
    Ok(())
}

fn decode_udp(
    decoder: &dyn ProtocolDecoder,
    packet: &CapturePacket,
    view: &TransportView,
    config: &DecodeConfig,
    interface: &str,
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
}
