//! Native bounded HTTP/2 and 5G SBI transaction decoder.

use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol, SbiMetadata,
};
use hpack::Decoder;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use transport_tcp::{ProvenanceSpan, ReassembledConnection, ReassembledDirection, TcpEndpoint};

pub const VERSION: &str = "0.1.0";
const MAX_FRAME_SIZE: usize = 1_048_576;
const MAX_HEADER_BLOCK: usize = 256 * 1024;
const MAX_BODY: usize = 4 * 1024 * 1024;
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SbiDecodeReport {
    pub tcp_connections: usize,
    pub http2_frames: usize,
    pub http2_streams: usize,
    pub sbi_transactions: usize,
    pub operations_decoded: usize,
    pub incomplete_streams: usize,
    pub encrypted_connections: usize,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug)]
struct Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
    offset: usize,
    timestamp_ns: i128,
    provenance: Vec<event_schema::PacketReference>,
    source: TcpEndpoint,
    destination: TcpEndpoint,
    direction_index: usize,
}

#[derive(Clone, Debug, Default)]
struct MessagePart {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    timestamp_ns: Option<i128>,
    timestamp: Option<event_schema::ExactTimestamp>,
    provenance: Vec<event_schema::PacketReference>,
    source: Option<TcpEndpoint>,
    destination: Option<TcpEndpoint>,
    partial: bool,
}

#[derive(Clone, Debug, Default)]
struct StreamState {
    request: MessagePart,
    response: MessagePart,
    reset: bool,
}

pub fn decode_connections(
    connections: &[ReassembledConnection],
    capture_id: &str,
    interface: &str,
    endpoint_names: &HashMap<String, String>,
) -> (Vec<NormalizedEvent>, SbiDecodeReport) {
    let mut events = Vec::new();
    let mut report = SbiDecodeReport {
        tcp_connections: connections.len(),
        ..Default::default()
    };
    for connection in connections {
        if !is_sbi_candidate(connection) {
            continue;
        }
        if looks_like_tls(&connection.directions[0].bytes)
            || looks_like_tls(&connection.directions[1].bytes)
        {
            report.encrypted_connections += 1;
            continue;
        }
        let mut frames = Vec::new();
        for (index, direction) in connection.directions.iter().enumerate() {
            let (mut decoded, mut errors) = parse_direction(direction, index);
            report.http2_frames += decoded.len();
            frames.append(&mut decoded);
            report.errors.append(&mut errors);
        }
        frames.sort_by_key(|frame| (frame.timestamp_ns, frame.direction_index, frame.offset));
        let (decoded, streams, incomplete, errors) =
            transactions(connection, frames, capture_id, interface, endpoint_names);
        report.http2_streams += streams;
        report.incomplete_streams += incomplete;
        report.sbi_transactions += decoded.len();
        report.operations_decoded += decoded
            .iter()
            .filter(|event| {
                event
                    .sbi
                    .as_ref()
                    .and_then(|sbi| sbi.operation.as_ref())
                    .is_some()
            })
            .count();
        report.errors.extend(errors);
        events.extend(decoded);
    }
    events.sort_by_key(|event| {
        (
            event.timestamp.seconds,
            event.timestamp.nanoseconds,
            event.event_id.clone(),
        )
    });
    (events, report)
}

fn is_sbi_candidate(connection: &ReassembledConnection) -> bool {
    connection.key.low.port == 7777
        || connection.key.high.port == 7777
        || connection
            .directions
            .iter()
            .any(|direction| direction.bytes.starts_with(PREFACE))
}

fn looks_like_tls(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes[0] == 0x16 && bytes[1] == 0x03 && bytes[2] <= 0x04
}

fn parse_direction(
    direction: &ReassembledDirection,
    direction_index: usize,
) -> (Vec<Frame>, Vec<String>) {
    let mut offset = if direction.bytes.starts_with(PREFACE) {
        PREFACE.len()
    } else {
        0
    };
    let mut frames = Vec::new();
    let mut errors = Vec::new();
    while offset + 9 <= direction.bytes.len() {
        let length = ((direction.bytes[offset] as usize) << 16)
            | ((direction.bytes[offset + 1] as usize) << 8)
            | direction.bytes[offset + 2] as usize;
        let frame_type = direction.bytes[offset + 3];
        let flags = direction.bytes[offset + 4];
        let stream_id = u32::from_be_bytes(
            direction.bytes[offset + 5..offset + 9]
                .try_into()
                .expect("four bytes"),
        ) & 0x7fff_ffff;
        if length > MAX_FRAME_SIZE || frame_type > 9 || offset + 9 + length > direction.bytes.len()
        {
            errors.push(format!(
                "HTTP/2 framing stopped at byte {offset}: invalid or truncated frame"
            ));
            break;
        }
        let end = offset + 9 + length;
        let spans = overlapping(&direction.spans, offset, end);
        let timestamp = spans.first().map(|span| span.timestamp.clone());
        frames.push(Frame {
            frame_type,
            flags,
            stream_id,
            payload: direction.bytes[offset + 9..end].to_vec(),
            offset,
            timestamp_ns: timestamp
                .as_ref()
                .and_then(|value| value.unix_nanoseconds())
                .unwrap_or(0),
            provenance: spans.iter().map(|span| span.packet.clone()).collect(),
            source: direction.source.clone(),
            destination: direction.destination.clone(),
            direction_index,
        });
        offset = end;
    }
    (frames, errors)
}

fn overlapping(spans: &[ProvenanceSpan], start: usize, end: usize) -> Vec<&ProvenanceSpan> {
    spans
        .iter()
        .filter(|span| span.end > start && span.start < end)
        .collect()
}

fn transactions(
    connection: &ReassembledConnection,
    frames: Vec<Frame>,
    capture_id: &str,
    interface: &str,
    endpoint_names: &HashMap<String, String>,
) -> (Vec<NormalizedEvent>, usize, usize, Vec<String>) {
    let mut decoders = [Decoder::new(), Decoder::new()];
    let mut continuations: HashMap<(usize, u32), (Vec<u8>, Frame)> = HashMap::new();
    let mut streams: BTreeMap<u32, StreamState> = BTreeMap::new();
    let mut errors = Vec::new();
    for frame in frames {
        let state = streams.entry(frame.stream_id).or_default();
        match frame.frame_type {
            0 => {
                if frame.stream_id == 0 {
                    errors.push("DATA frame on stream 0".into());
                    continue;
                }
                let data = data_payload(&frame.payload, frame.flags).unwrap_or(&[]);
                let part = choose_part(state, frame.direction_index);
                append_part(part, &frame, data);
            }
            1 => {
                if frame.stream_id == 0 {
                    errors.push("HEADERS frame on stream 0".into());
                    continue;
                }
                let block = match headers_payload(&frame.payload, frame.flags) {
                    Ok(block) => block,
                    Err(error) => {
                        errors.push(error);
                        continue;
                    }
                };
                if frame.flags & 0x04 != 0 {
                    apply_headers(
                        state,
                        &frame,
                        &mut decoders[frame.direction_index],
                        block,
                        &mut errors,
                    );
                } else if block.len() <= MAX_HEADER_BLOCK {
                    continuations.insert(
                        (frame.direction_index, frame.stream_id),
                        (block.to_vec(), frame),
                    );
                }
            }
            9 => {
                let key = (frame.direction_index, frame.stream_id);
                let Some((mut block, first)) = continuations.remove(&key) else {
                    errors.push(format!("orphan CONTINUATION stream {}", frame.stream_id));
                    continue;
                };
                if block.len() + frame.payload.len() > MAX_HEADER_BLOCK {
                    errors.push("header block limit exceeded".into());
                    continue;
                }
                block.extend_from_slice(&frame.payload);
                if frame.flags & 0x04 != 0 {
                    apply_headers(
                        state,
                        &first,
                        &mut decoders[frame.direction_index],
                        &block,
                        &mut errors,
                    );
                } else {
                    continuations.insert(key, (block, first));
                }
            }
            3 => state.reset = true,
            4 | 6 | 7 | 8 => {}
            other => errors.push(format!("unsupported HTTP/2 frame type {other}")),
        }
    }
    for ((_, stream), _) in continuations {
        streams.entry(stream).or_default().request.partial = true;
    }
    let stream_count = streams.len();
    let mut incomplete = 0;
    let mut events = Vec::new();
    for (stream_id, state) in streams {
        if state.request.headers.is_empty() {
            incomplete += 1;
            continue;
        }
        if state.response.headers.is_empty() {
            incomplete += 1;
        }
        events.push(build_event(
            connection,
            stream_id,
            state,
            capture_id,
            interface,
            endpoint_names,
        ));
    }
    (events, stream_count, incomplete, errors)
}

fn choose_part(state: &mut StreamState, direction: usize) -> &mut MessagePart {
    if state
        .request
        .source
        .as_ref()
        .map(|source| direction_for(source, &state.request.destination))
        .unwrap_or(direction)
        == direction
        && !state.request.headers.is_empty()
    {
        &mut state.request
    } else {
        &mut state.response
    }
}

fn direction_for(source: &TcpEndpoint, destination: &Option<TcpEndpoint>) -> usize {
    destination
        .as_ref()
        .map(|dest| usize::from(source > dest))
        .unwrap_or(0)
}

fn append_part(part: &mut MessagePart, frame: &Frame, bytes: &[u8]) {
    if part.body.len() + bytes.len() <= MAX_BODY {
        part.body.extend_from_slice(bytes);
    } else {
        part.partial = true;
    }
    merge_provenance(&mut part.provenance, &frame.provenance);
}

fn apply_headers(
    state: &mut StreamState,
    frame: &Frame,
    decoder: &mut Decoder<'_>,
    block: &[u8],
    errors: &mut Vec<String>,
) {
    let decoded = decoder.decode(block);
    let (mut headers, partial) = match decoded {
        Ok(headers) => (
            headers
                .into_iter()
                .map(|(name, value)| {
                    (
                        String::from_utf8_lossy(&name).into_owned(),
                        String::from_utf8_lossy(&value).into_owned(),
                    )
                })
                .collect::<Vec<_>>(),
            false,
        ),
        Err(error) => {
            errors.push(format!("HPACK stream {}: {error:?}", frame.stream_id));
            (tolerant_literals(block), true)
        }
    };
    headers.retain(|(name, value)| {
        if name == ":method" {
            matches!(
                value.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
            )
        } else if name == ":path" {
            value.starts_with('/')
        } else {
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte == b':')
                && value.chars().all(|ch| !ch.is_control() || ch == '\t')
        }
    });
    let response = headers.iter().any(|(name, _)| name == ":status");
    let part = if response {
        &mut state.response
    } else {
        &mut state.request
    };
    part.headers.extend(headers);
    part.partial |= partial;
    part.timestamp_ns.get_or_insert(frame.timestamp_ns);
    if part.timestamp.is_none() {
        part.timestamp = frame
            .provenance
            .first()
            .and_then(|packet| frame_timestamp(frame, packet.packet_number));
    }
    part.source.get_or_insert_with(|| frame.source.clone());
    part.destination
        .get_or_insert_with(|| frame.destination.clone());
    merge_provenance(&mut part.provenance, &frame.provenance);
}

fn frame_timestamp(frame: &Frame, _packet_number: u64) -> Option<event_schema::ExactTimestamp> {
    let seconds = frame.timestamp_ns.div_euclid(1_000_000_000) as i64;
    let nanos = frame.timestamp_ns.rem_euclid(1_000_000_000) as u32;
    Some(event_schema::ExactTimestamp {
        seconds,
        nanoseconds: nanos,
        raw_ticks: frame.timestamp_ns.max(0) as u64,
        resolution_base: 10,
        resolution_exponent: 9,
    })
}

fn merge_provenance(
    target: &mut Vec<event_schema::PacketReference>,
    incoming: &[event_schema::PacketReference],
) {
    for packet in incoming {
        if !target.iter().any(|existing| {
            existing.source_file == packet.source_file
                && existing.packet_number == packet.packet_number
        }) {
            target.push(packet.clone());
        }
    }
}

fn headers_payload(payload: &[u8], flags: u8) -> Result<&[u8], String> {
    let mut start = 0usize;
    let mut padding = 0usize;
    if flags & 0x08 != 0 {
        padding = usize::from(*payload.first().ok_or("padded HEADERS missing pad length")?);
        start += 1;
    }
    if flags & 0x20 != 0 {
        start += 5;
    }
    if start + padding > payload.len() {
        return Err("invalid HEADERS padding/priority".into());
    }
    Ok(&payload[start..payload.len() - padding])
}

fn data_payload(payload: &[u8], flags: u8) -> Result<&[u8], String> {
    if flags & 0x08 == 0 {
        return Ok(payload);
    }
    let padding = usize::from(*payload.first().ok_or("padded DATA missing pad length")?);
    if 1 + padding > payload.len() {
        return Err("invalid DATA padding".into());
    }
    Ok(&payload[1..payload.len() - padding])
}

fn tolerant_literals(block: &[u8]) -> Vec<(String, String)> {
    // Recovery is deliberately conservative: the mature HPACK decoder remains authoritative.
    // Only literal fields with an indexed/static name and a plain (non-Huffman) value are retained.
    let static_names = [
        "",
        ":authority",
        ":method",
        ":method",
        ":path",
        ":path",
        ":scheme",
        ":scheme",
        ":status",
        ":status",
        ":status",
        ":status",
        ":status",
        ":status",
        ":status",
    ];
    let mut output = Vec::new();
    let mut i = 0;
    while i < block.len() {
        let byte = block[i];
        if byte & 0x80 != 0 {
            i += 1;
            continue;
        }
        let prefix = if byte & 0x40 != 0 { 6 } else { 4 };
        let Ok((name_index, consumed)) = decode_integer(&block[i..], prefix) else {
            break;
        };
        i += consumed;
        let name = if name_index == 0 {
            let Ok((value, used)) = plain_string(&block[i..]) else {
                break;
            };
            i += used;
            value
        } else if name_index < static_names.len() {
            static_names[name_index].to_string()
        } else {
            continue;
        };
        let Ok((value, used)) = plain_string(&block[i..]) else {
            break;
        };
        i += used;
        if !name.is_empty() {
            output.push((name, value));
        }
    }
    output
}

fn decode_integer(bytes: &[u8], prefix: u8) -> Result<(usize, usize), ()> {
    let first = *bytes.first().ok_or(())?;
    let mask = (1u16 << prefix) as u8 - 1;
    let mut value = usize::from(first & mask);
    if value < usize::from(mask) {
        return Ok((value, 1));
    }
    let mut shift = 0;
    let mut used = 1;
    for byte in &bytes[1..] {
        value = value
            .checked_add(usize::from(byte & 0x7f).checked_shl(shift).ok_or(())?)
            .ok_or(())?;
        used += 1;
        if byte & 0x80 == 0 {
            return Ok((value, used));
        }
        shift += 7;
        if used > 5 {
            return Err(());
        }
    }
    Err(())
}

fn plain_string(bytes: &[u8]) -> Result<(String, usize), ()> {
    if bytes.first().copied().ok_or(())? & 0x80 != 0 {
        return Err(());
    }
    let (length, used) = decode_integer(bytes, 7)?;
    let end = used.checked_add(length).ok_or(())?;
    if end > bytes.len() {
        return Err(());
    }
    Ok((String::from_utf8_lossy(&bytes[used..end]).into_owned(), end))
}

fn build_event(
    connection: &ReassembledConnection,
    stream_id: u32,
    state: StreamState,
    capture_id: &str,
    interface: &str,
    endpoint_names: &HashMap<String, String>,
) -> NormalizedEvent {
    let method = header(&state.request.headers, ":method");
    let raw_path = header(&state.request.headers, ":path");
    let path = raw_path.as_deref().map(sanitize_uri);
    let status: Option<u16> =
        header(&state.response.headers, ":status").and_then(|value| value.parse().ok());
    let (service, operation) = classify(path.as_deref(), method.as_deref());
    let consumer = header(&state.request.headers, "user-agent").or_else(|| {
        state
            .request
            .source
            .as_ref()
            .and_then(|ep| endpoint_names.get(&ep.address).cloned())
    });
    let target = header(&state.request.headers, "3gpp-sbi-target-apiroot");
    let producer = header(&state.request.headers, "3gpp-sbi-discovery-target-nf-type")
        .or_else(|| target.as_deref().and_then(nf_from_target))
        .or_else(|| {
            state
                .request
                .destination
                .as_ref()
                .and_then(|ep| endpoint_names.get(&ep.address).cloned())
        });
    let scp_transit = target.is_some()
        && state
            .request
            .destination
            .as_ref()
            .and_then(|ep| endpoint_names.get(&ep.address))
            .map(|name| name == "SCP")
            .unwrap_or(false);
    let mut identifiers = Vec::new();
    if let Some(path) = path.as_deref() {
        if let Some(context) = sm_context(path) {
            identifiers.push(NamedValue {
                name: "sm_context_reference".into(),
                value: context,
                pseudonymized: false,
            });
        }
    }
    let mut ies = Vec::new();
    if let Some(value) = method.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "HTTP method".into(),
            length: value.len() as u32,
            value: Some(value.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(value) = path.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "Request URI (sanitized)".into(),
            length: value.len() as u32,
            value: Some(value.into()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(value) = status {
        ies.push(InformationElement {
            id: None,
            name: "HTTP status".into(),
            length: 2,
            value: Some(value.to_string()),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    ies.push(InformationElement {
        id: None,
        name: "HTTP/2 stream ID".into(),
        length: 4,
        value: Some(stream_id.to_string()),
        raw_sha256: None,
        status: DecodeStatus::Decoded,
    });
    for (name, value) in json_fields(&state.request.body) {
        if name == "pdu_session_id" || name == "subscriber_pseudonym" {
            identifiers.push(NamedValue {
                name: name.clone(),
                value: value.clone(),
                pseudonymized: name == "subscriber_pseudonym",
            });
        }
        ies.push(InformationElement {
            id: None,
            name,
            length: value.len() as u32,
            value: Some(value),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    if let Some(value) = target.as_deref() {
        ies.push(InformationElement {
            id: None,
            name: "3gpp-sbi-target-apiroot".into(),
            length: value.len() as u32,
            value: Some(sanitize_uri(value)),
            raw_sha256: None,
            status: DecodeStatus::Decoded,
        });
    }
    let timestamp = state
        .request
        .timestamp
        .unwrap_or(event_schema::ExactTimestamp {
            seconds: 0,
            nanoseconds: 0,
            raw_ticks: 0,
            resolution_base: 10,
            resolution_exponent: 9,
        });
    let mut provenance = state.request.provenance;
    merge_provenance(&mut provenance, &state.response.provenance);
    let duration = match (state.request.timestamp_ns, state.response.timestamp_ns) {
        (Some(start), Some(end)) if end >= start => u64::try_from(end - start).ok(),
        _ => None,
    };
    let partial = state.request.partial
        || state.response.partial
        || state.response.headers.is_empty()
        || state.reset;
    let mut event = NormalizedEvent {
        event_id: String::new(),
        parent_event_id: None,
        probe_id: "local-vprobe".into(),
        capture_point_id: interface.into(),
        capture_id: capture_id.into(),
        packet_references: provenance,
        timestamp,
        interface: "SBI".into(),
        protocol: Protocol::SbiHttp2,
        message_name: operation
            .clone()
            .unwrap_or_else(|| "UnsupportedSbiOperation".into()),
        message_type: status.map(u32::from).unwrap_or(0),
        procedure_code: None,
        procedure: service.clone(),
        security_state: Some("PLAINTEXT_LAB_CAPTURE".into()),
        source_byte_offset: None,
        source_endpoint: endpoint(state.request.source.as_ref(), endpoint_names),
        destination_endpoint: endpoint(state.request.destination.as_ref(), endpoint_names),
        direction: Direction::SbiRequest,
        session_identifiers: identifiers,
        information_elements: ies,
        decoder_name: "decoder-sbi".into(),
        decoder_version: VERSION.into(),
        schema_version: NormalizedEvent::SCHEMA_VERSION,
        decoding_status: if partial {
            DecodeStatus::Partial
        } else {
            DecodeStatus::Decoded
        },
        errors: if partial {
            vec!["HTTP/2 transaction is incomplete or partially decoded".into()]
        } else {
            vec![]
        },
        raw_payload_reference: format!("sha256:{}", sha256_hex(&state.request.body)),
        evidence_references: vec![EvidenceReference {
            state: EvidenceState::Exact,
            kind: "http2-stream".into(),
            reference: format!("{}:{stream_id}", connection.key.id()),
        }],
        sbi: Some(SbiMetadata {
            tcp_connection_id: connection.key.id(),
            http2_stream_id: stream_id,
            service,
            operation,
            http_method: method,
            request_uri: path,
            http_status: status,
            consumer_nf: consumer,
            producer_nf: producer,
            scp_transit,
            transaction_duration_ns: duration,
        }),
    };
    event.assign_deterministic_id();
    event
}

fn endpoint(value: Option<&TcpEndpoint>, names: &HashMap<String, String>) -> Endpoint {
    match value {
        Some(value) => Endpoint {
            address: value.address.clone(),
            port: Some(value.port),
            network_function: names.get(&value.address).cloned(),
        },
        None => Endpoint {
            address: "unknown".into(),
            port: None,
            network_function: None,
        },
    }
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}

fn classify(path: Option<&str>, method: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(path) = path else {
        return (None, None);
    };
    if path.contains("/nsmf-pdusession/") && path.contains("/sm-contexts") {
        let operation = if path.ends_with("/modify") {
            "UpdateSMContext"
        } else if path.ends_with("/release") {
            "ReleaseSMContext"
        } else if method == Some("POST") {
            "CreateSMContext"
        } else {
            "SMContextOperation"
        };
        return (Some("Nsmf_PDUSession".into()), Some(operation.into()));
    }
    if path.contains("/namf-comm/") && path.contains("/n1-n2-messages") {
        return (
            Some("Namf_Communication".into()),
            Some("N1N2MessageTransfer".into()),
        );
    }
    if path.contains("/namf-comm/") && path.contains("ue-context") {
        return (
            Some("Namf_Communication".into()),
            Some("UEContextTransfer".into()),
        );
    }
    (service_from_path(path), None)
}

fn service_from_path(path: &str) -> Option<String> {
    path.split('/')
        .find(|part| part.starts_with('n') && part.contains('-'))
        .map(str::to_owned)
}
fn sm_context(path: &str) -> Option<String> {
    let marker = "/sm-contexts/";
    let rest = path.split_once(marker)?.1;
    let value = rest.split(['/', '?']).next()?;
    (!value.is_empty()).then(|| value.to_string())
}
fn nf_from_target(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    if lower.contains("smf") || lower.contains("172.22.0.7") {
        Some("SMF".into())
    } else if lower.contains("amf") || lower.contains("172.22.0.10") {
        Some("AMF".into())
    } else {
        None
    }
}

fn sanitize_uri(value: &str) -> String {
    value
        .split('/')
        .map(|part| {
            let (identity, suffix) = part
                .split_once('?')
                .map(|(head, tail)| (head, format!("?{tail}")))
                .unwrap_or((part, String::new()));
            if identity.starts_with("imsi-")
                || identity.starts_with("suci-")
                || identity.starts_with("nai-")
            {
                format!(
                    "subscriber-{}{}",
                    pseudonym("supi", identity.as_bytes()),
                    suffix
                )
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn json_fields(body: &[u8]) -> Vec<(String, String)> {
    let Some(json) = extract_json(body) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_slice::<Value>(json) else {
        return Vec::new();
    };
    let mut fields = Vec::new();
    collect_json(&value, &mut fields);
    fields
}

fn extract_json(body: &[u8]) -> Option<&[u8]> {
    let start = body.iter().position(|byte| *byte == b'{')?;
    for end in (start + 1..=body.len()).rev() {
        if body.get(end - 1) == Some(&b'}')
            && serde_json::from_slice::<Value>(&body[start..end]).is_ok()
        {
            return Some(&body[start..end]);
        }
    }
    None
}

fn collect_json(value: &Value, fields: &mut Vec<(String, String)>) {
    let Value::Object(map) = value else { return };
    for (key, value) in map {
        if matches!(key.as_str(), "supi" | "suci" | "pei") {
            if let Some(text) = scalar(value) {
                fields.push((
                    "subscriber_pseudonym".into(),
                    pseudonym("subscriber", text.as_bytes()),
                ));
            }
        } else {
            let normalized = match key.as_str() {
                "pduSessionId" => Some("pdu_session_id"),
                "dnn" => Some("dnn"),
                "accessType" => Some("access_type"),
                "cause" => Some("cause"),
                "smContextRef" => Some("sm_context_reference"),
                "sst" => Some("s_nssai_sst"),
                "sd" => Some("s_nssai_sd"),
                _ => None,
            };
            if let Some(name) = normalized {
                if let Some(text) = scalar(value) {
                    fields.push((name.into(), text));
                }
            }
        }
        collect_json(value, fields);
    }
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_schema::{ExactTimestamp, PacketReference};
    use hpack::Encoder;
    use transport_tcp::{ProvenanceSpan, TcpConnectionKey};

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut output = vec![
            ((payload.len() >> 16) & 0xff) as u8,
            ((payload.len() >> 8) & 0xff) as u8,
            (payload.len() & 0xff) as u8,
            kind,
            flags,
        ];
        output.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
        output.extend_from_slice(payload);
        output
    }
    fn packet(number: u64) -> PacketReference {
        PacketReference {
            source_file: "fixture.pcap".into(),
            source_sha256: None,
            packet_number: number,
            byte_offset: number,
            interface_id: 0,
            link_type: Some(1),
            sll2_protocol_type: None,
            sll2_reserved: None,
            sll2_interface_index: None,
            sll2_arphrd_type: None,
            sll2_packet_type: None,
            sll2_address_length: None,
            sll2_address: None,
            captured_length: 100,
            original_length: 100,
        }
    }
    fn direction(
        source: TcpEndpoint,
        destination: TcpEndpoint,
        bytes: Vec<u8>,
        number: u64,
    ) -> ReassembledDirection {
        let end = bytes.len();
        ReassembledDirection {
            source,
            destination,
            bytes,
            spans: vec![ProvenanceSpan {
                start: 0,
                end,
                timestamp: ExactTimestamp {
                    seconds: 1,
                    nanoseconds: number as u32,
                    raw_ticks: number,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                packet: packet(number),
            }],
            incomplete: false,
            retransmissions: 0,
            duplicate_segments: 0,
        }
    }
    #[test]
    fn classifies_context_operations() {
        assert_eq!(
            classify(
                Some("/nsmf-pdusession/v1/sm-contexts/4/modify"),
                Some("POST")
            )
            .1
            .as_deref(),
            Some("UpdateSMContext")
        );
        assert_eq!(
            classify(Some("/nsmf-pdusession/v1/sm-contexts"), Some("POST"))
                .1
                .as_deref(),
            Some("CreateSMContext")
        );
    }
    #[test]
    fn redacts_subscriber_paths() {
        let value = sanitize_uri("/ue-contexts/imsi-001011234567895/n1-n2-messages");
        assert!(!value.contains("001011234567895"));
        assert!(value.contains("subscriber-psn-"));
    }
    #[test]
    fn extracts_supported_json_without_secrets() {
        let fields = json_fields(br#"{"pduSessionId":3,"dnn":"internet","supi":"imsi-secret"}"#);
        assert!(fields.contains(&("pdu_session_id".into(), "3".into())));
        assert!(!fields
            .iter()
            .any(|(_, value)| value.contains("imsi-secret")));
    }
    #[test]
    fn rejects_invalid_frame_lengths() {
        let direction = ReassembledDirection {
            source: TcpEndpoint {
                address: "a".into(),
                port: 1,
            },
            destination: TcpEndpoint {
                address: "b".into(),
                port: 7777,
            },
            bytes: vec![0xff, 0xff, 0xff, 1, 0, 0, 0, 0, 1],
            spans: vec![],
            incomplete: false,
            retransmissions: 0,
            duplicate_segments: 0,
        };
        let (frames, errors) = parse_direction(&direction, 0);
        assert!(frames.is_empty());
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn multiplexed_continuation_streams_pair_independently() {
        let client = TcpEndpoint {
            address: "10.0.0.1".into(),
            port: 40000,
        };
        let server = TcpEndpoint {
            address: "10.0.0.2".into(),
            port: 7777,
        };
        let mut enc = Encoder::new();
        let one = enc.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (
                b":path".as_slice(),
                b"/nsmf-pdusession/v1/sm-contexts".as_slice(),
            ),
        ]);
        let three = enc.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (
                b":path".as_slice(),
                b"/nsmf-pdusession/v1/sm-contexts/4/modify".as_slice(),
            ),
        ]);
        let mut c = PREFACE.to_vec();
        let split = one.len() / 2;
        c.extend(frame(1, 0, 1, &one[..split]));
        c.extend(frame(9, 4, 1, &one[split..]));
        c.extend(frame(1, 5, 3, &three));
        let mut resp_enc = Encoder::new();
        let ok = resp_enc.encode([(b":status".as_slice(), b"201".as_slice())]);
        let mut s = Vec::new();
        s.extend(frame(1, 5, 1, &ok));
        let ok2 = resp_enc.encode([(b":status".as_slice(), b"200".as_slice())]);
        s.extend(frame(1, 5, 3, &ok2));
        let key = TcpConnectionKey::new(client.clone(), server.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), c, 1),
                direction(server, client, s, 2),
            ],
        };
        let (events, report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        assert_eq!(events.len(), 2);
        assert_eq!(report.http2_streams, 2);
        assert!(events
            .iter()
            .any(|event| event.message_name == "CreateSMContext"));
        assert!(events
            .iter()
            .any(|event| event.message_name == "UpdateSMContext"));
    }

    #[test]
    fn encrypted_connection_is_classified_not_decoded() {
        let a = TcpEndpoint {
            address: "a".into(),
            port: 1,
        };
        let b = TcpEndpoint {
            address: "b".into(),
            port: 7777,
        };
        let key = TcpConnectionKey::new(a.clone(), b.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(a.clone(), b.clone(), vec![0x16, 0x03, 0x03, 0, 1, 0], 1),
                direction(b, a, vec![], 2),
            ],
        };
        let (events, report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        assert!(events.is_empty());
        assert_eq!(report.encrypted_connections, 1);
    }
}
