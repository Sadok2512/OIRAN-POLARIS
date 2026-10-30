//! Reusable native decoder pipeline used by both the CLI and live capture service.

use capture_pcap::{
    transport_view, visit_capture, CapturePacket, TransportProtocol, TransportView,
};
use decoder_gtpu::GtpuDecoder;
use decoder_ngap::NgapDecoder;
use decoder_pfcp::PfcpDecoder;
use decoder_sbi::decode_connections;
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

pub const VERSION: &str = "0.4.5";

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
    validate_config(config)?;
    let ngap = NgapDecoder;
    let pfcp = PfcpDecoder;
    let gtpu = GtpuDecoder;
    let mut sctp = SctpReassembler::new();
    let mut tcp = TcpReassembler::new();
    let mut events = Vec::new();
    let mut transport_errors = 0usize;

    let capture = visit_capture(&config.input, &config.capture_id, |packet| {
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
                if ports.0 == 8805 || ports.1 == 8805 {
                    decode_udp(&pfcp, &packet, &view, config, "N4", &mut events);
                } else if ports.0 == 2152 || ports.1 == 2152 {
                    decode_udp(&gtpu, &packet, &view, config, "N3", &mut events);
                }
            }
            TransportProtocol::Sctp => {
                for message in sctp.consume(&packet, &view) {
                    if message.ppid != 60 {
                        continue;
                    }
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
                        interface: "N2",
                        source_endpoint: source,
                        destination_endpoint: destination,
                        payload: &message.payload,
                        raw_payload_reference: &raw,
                    };
                    events.extend(ngap.decode(&input).events);
                }
            }
            TransportProtocol::Tcp => tcp.consume(&packet, &view),
            TransportProtocol::Other(_) => {}
        }
    })
    .map_err(|error| error.to_string())?;
    let (sctp_errors, incomplete_sctp) = sctp.finish();
    let (connections, tcp_errors) = tcp.finish();
    let (sbi_events, sbi_report) = decode_connections(
        &connections,
        &config.capture_id,
        &config.interface,
        &config.endpoints,
    );
    events.extend(sbi_events);
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
    if events.iter().any(|event| !event.has_complete_provenance()) {
        return Err("decoder emitted an event without complete packet provenance".into());
    }
    Ok(DecodeOutput {
        report: DecodeReport {
            capture_format: format!("{:?}", capture.format),
            packets: capture.packets,
            events: events.len(),
            warnings: capture.warnings.len(),
            transport_errors,
            sctp_errors: sctp_errors.len(),
            incomplete_sctp,
            tcp_connections: sbi_report.tcp_connections,
            tcp_errors: tcp_errors.len(),
            http2_frames: sbi_report.http2_frames,
            http2_streams: sbi_report.http2_streams,
            sbi_transactions: sbi_report.sbi_transactions,
        },
        events,
    })
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
    if !matches!(config.interface.as_str(), "N2" | "N3" | "N4" | "SBI") {
        return Err("interface must be N2, N3, N4 or SBI".into());
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
