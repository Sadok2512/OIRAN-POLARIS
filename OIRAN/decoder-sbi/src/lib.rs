//! Native bounded HTTP/2 and 5G SBI transaction decoder.

use event_schema::{
    pseudonym, sha256_hex, DecodeStatus, Direction, Endpoint, EvidenceReference, EvidenceState,
    InformationElement, NamedValue, NormalizedEvent, Protocol, SbiMetadata,
};
use hpack::huffman::HuffmanDecoder;
use hpack::Decoder;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use transport_tcp::{ProvenanceSpan, ReassembledConnection, ReassembledDirection, TcpEndpoint};

pub const VERSION: &str = "0.3.1";
/// Public error code emitted on `NormalizedEvent::errors` when HPACK decoding fails
/// for a HEADERS/CONTINUATION block (dynamic table state lost, Huffman literal that
/// the hpack crate rejects, or any other HPACK framing error). Consumers use this
/// prefix to distinguish "capture started mid-connection" from a generic
/// `PARTIAL` status.
pub const HPACK_CONTEXT_UNAVAILABLE: &str = "HPACK_CONTEXT_UNAVAILABLE";
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
    /// Set when at least one HEADERS/CONTINUATION block for this part failed to
    /// HPACK-decode. The dynamic table state is poisoned from that point onward in
    /// the enclosing direction; this flag lets `build_event` emit
    /// `HPACK_CONTEXT_UNAVAILABLE` instead of a generic "partially decoded" error
    /// so operators can distinguish mid-connection captures from genuine framing
    /// faults.
    hpack_unavailable: bool,
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
    // Each direction owns an HPACK decoder. The hpack crate's dynamic table
    // state is sequential, so when a given HEADERS block fails to decode we
    // record `hpack_unavailable` on that specific block and let the decoder
    // keep going; the very next block that decodes cleanly re-synchronises the
    // direction automatically. No permanent direction poisoning — that
    // regressed 0.4.2 to a 70x event inflation on well-formed captures.
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
                } else {
                    // Frame-level framing error: push to the connection-level
                    // errors list but do NOT touch any stream state — doing so
                    // would synthesise ghost events on streams that otherwise
                    // never carried a usable header block.
                    errors.push(format!(
                        "{HPACK_CONTEXT_UNAVAILABLE}: HEADERS fragment stream {} exceeds configured \
                         maximum header block size",
                        frame.stream_id
                    ));
                }
            }
            9 => {
                let key = (frame.direction_index, frame.stream_id);
                let Some((mut block, first)) = continuations.remove(&key) else {
                    errors.push(format!(
                        "{HPACK_CONTEXT_UNAVAILABLE}: orphan CONTINUATION on stream {}; opening \
                         HEADERS frame is not in the capture",
                        frame.stream_id
                    ));
                    continue;
                };
                if block.len() + frame.payload.len() > MAX_HEADER_BLOCK {
                    errors.push(format!(
                        "{HPACK_CONTEXT_UNAVAILABLE}: CONTINUATION block for stream {} exceeds \
                         configured maximum header block size",
                        frame.stream_id
                    ));
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
    // Any unflushed continuations at the end of the capture are frame-level
    // leftovers; surface them in the connection errors list but do not
    // fabricate stream events — that is what inflated 0.4.2's output by 5x.
    for ((_, stream), _) in continuations {
        errors.push(format!(
            "{HPACK_CONTEXT_UNAVAILABLE}: unflushed HEADERS/CONTINUATION on stream {stream} at end \
             of capture"
        ));
    }
    let stream_count = streams.len();
    let mut incomplete = 0;
    let mut events = Vec::new();
    // Emission policy — one event per stream, at most once, same as 0.3.1 for
    // well-formed connections:
    //   * Skip streams that never carried any decoded content on EITHER side.
    //   * Keep response-only streams only when they are fully decoded. A
    //     response-only PARTIAL stream has no trustworthy SBI operation or
    //     resource identity; its HPACK limitation remains in the connection
    //     report rather than becoming a synthetic transaction.
    //   * `hpack_unavailable` on a part is a decoration (surfaces an explicit
    //     error reason on the normalised event) but does NOT by itself promote
    //     a content-less stream to an event.
    for (stream_id, state) in streams {
        if state.request.headers.is_empty() && state.response.headers.is_empty() {
            incomplete += 1;
            continue;
        }
        let response_only = state.request.headers.is_empty();
        if state.response.headers.is_empty() {
            incomplete += 1;
        }
        let event = build_event(
            connection,
            stream_id,
            state,
            capture_id,
            interface,
            endpoint_names,
        );
        // Preserve every fully decoded transaction (the 0.3.1 parity
        // contract), including one whose request identity was recovered by
        // tolerant HPACK parsing. Response-only PARTIAL evidence remains at
        // connection level and is not promoted to a transaction.
        if response_only && event.decoding_status != DecodeStatus::Decoded {
            incomplete += 1;
            continue;
        }
        events.push(event);
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
    let (mut headers, partial, hpack_unavailable) = match decoded {
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
            false,
        ),
        Err(error) => {
            // HPACK failure is local to THIS header block. The hpack crate's
            // dynamic table may be out of sync with the sender from here on,
            // but we do not permanently poison the direction — the next block
            // that decodes cleanly re-synchronises automatically. We mark
            // ONLY this stream's part as HPACK_CONTEXT_UNAVAILABLE so the
            // operator sees an explicit reason on the normalised event.
            errors.push(format!(
                "{HPACK_CONTEXT_UNAVAILABLE}: stream {} failed HPACK decode ({error:?}); dynamic \
                 table state lost or capture started mid-connection",
                frame.stream_id
            ));
            (tolerant_literals(block), true, true)
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
    // When HPACK decode fails we have no ":status" pseudo-header to inspect, so
    // fall back to the HTTP/2 frame direction index (direction_index == 0 is the
    // client → server direction, i.e. the request).
    let response = if headers.iter().any(|(name, _)| name == ":status") {
        true
    } else if headers.iter().any(|(name, _)| name == ":method") {
        false
    } else {
        frame.direction_index != 0
    };
    let part = if response {
        &mut state.response
    } else {
        &mut state.request
    };
    part.headers.extend(headers);
    part.partial |= partial;
    part.hpack_unavailable |= hpack_unavailable;
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
    let first = *bytes.first().ok_or(())?;
    let huffman = first & 0x80 != 0;
    let (length, used) = decode_integer(bytes, 7)?;
    let end = used.checked_add(length).ok_or(())?;
    if end > bytes.len() {
        return Err(());
    }
    let raw = &bytes[used..end];
    let decoded = if huffman {
        // RFC 7541 Appendix B canonical Huffman code. The `hpack` crate exposes
        // the HPACK Huffman decoder as `hpack::huffman::HuffmanDecoder`; we use
        // it so Huffman-encoded literals are no longer skipped on the recovery
        // path after an HPACK context loss.
        let mut hd = HuffmanDecoder::new();
        match hd.decode(raw) {
            Ok(octets) => String::from_utf8_lossy(&octets).into_owned(),
            Err(_) => return Err(()),
        }
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    Ok((decoded, end))
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
    let hpack_unavailable = state.request.hpack_unavailable || state.response.hpack_unavailable;
    let partial = state.request.partial
        || state.response.partial
        || state.response.headers.is_empty()
        || state.reset
        || hpack_unavailable;
    let message_name = if let Some(operation) = operation.clone() {
        operation
    } else if hpack_unavailable {
        format!(
            "HpackContextUnavailable:{}",
            method.clone().unwrap_or_else(|| "UNKNOWN".into())
        )
    } else {
        "UnsupportedSbiOperation".into()
    };
    let mut errors = Vec::new();
    if hpack_unavailable {
        errors.push(format!(
            "{HPACK_CONTEXT_UNAVAILABLE}: stream {stream_id} correlated by HTTP/2 stream-id only; \
             HPACK dynamic table state lost (capture started mid-connection or indexed names refer \
             to table entries never observed)"
        ));
    } else if partial {
        errors.push("HTTP/2 transaction is incomplete or partially decoded".into());
    }
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
        message_name,
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
        errors,
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
    fn mid_connection_capture_marks_hpack_context_unavailable_and_correlates_by_stream_id() {
        // Simulate a capture that starts in the middle of an HTTP/2 connection:
        // the client-side HEADERS references dynamic-table entries whose
        // definitions were never observed. The hpack crate rejects the block;
        // the fallback must record HPACK_CONTEXT_UNAVAILABLE at connection
        // level. Without a decoded request identity it must not fabricate a
        // transaction from the response alone.
        let client = TcpEndpoint {
            address: "10.0.0.1".into(),
            port: 40001,
        };
        let server = TcpEndpoint {
            address: "10.0.0.2".into(),
            port: 7777,
        };
        // Hand-crafted block referencing dynamic index 62 (first dynamic-table
        // slot) which the fresh decoder cannot resolve → HPACK error.
        let broken_block = vec![0xbe]; // Indexed Header Field, index 62.
        let mut client_bytes = PREFACE.to_vec();
        client_bytes.extend(frame(1, 5, 7, &broken_block));
        let mut resp_enc = Encoder::new();
        let ok = resp_enc.encode([(b":status".as_slice(), b"204".as_slice())]);
        let mut server_bytes = Vec::new();
        server_bytes.extend(frame(1, 5, 7, &ok));
        let key = TcpConnectionKey::new(client.clone(), server.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), client_bytes, 1),
                direction(server, client, server_bytes, 2),
            ],
        };
        let (events, report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        assert!(events.is_empty(), "response-only partial must not be promoted");
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains(HPACK_CONTEXT_UNAVAILABLE)),
            "report errors: {:?}",
            report.errors
        );
    }

    #[test]
    fn orphan_continuation_logs_connection_level_error_without_fabricating_stream_event() {
        // A capture that only sees a CONTINUATION on stream 11 (no preceding
        // HEADERS) cannot reconstruct that header block. In 0.3.1 the event
        // was synthesised with `partial` just to carry the error — in 0.4.2
        // that is what inflated the output by 70x on real captures. From
        // 0.3.1 onwards the orphan is a *connection-level* framing error: it
        // goes into `report.errors` but the stream is only promoted to a
        // normalised event through its *own* decoded content. Here the
        // paired response on stream 11 decoded cleanly, so that response
        // evidence is retained; the orphan error remains connection-level.
        let client = TcpEndpoint {
            address: "10.0.0.1".into(),
            port: 40002,
        };
        let server = TcpEndpoint {
            address: "10.0.0.2".into(),
            port: 7777,
        };
        let mut client_bytes = PREFACE.to_vec();
        client_bytes.extend(frame(9, 4, 11, &[0x80, 0x81]));
        let mut resp_enc = Encoder::new();
        let ok = resp_enc.encode([(b":status".as_slice(), b"500".as_slice())]);
        let mut server_bytes = Vec::new();
        server_bytes.extend(frame(1, 5, 11, &ok));
        let key = TcpConnectionKey::new(client.clone(), server.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), client_bytes, 1),
                direction(server, client, server_bytes, 2),
            ],
        };
        let (events, report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decoding_status, DecodeStatus::Decoded);
        assert!(
            report
                .errors
                .iter()
                .any(|e| e.contains("orphan CONTINUATION")),
            "orphan CONTINUATION must surface at connection level: {:?}",
            report.errors
        );
        assert!(
            events[0]
                .errors
                .iter()
                .all(|error| !error.contains("orphan CONTINUATION")),
            "connection error must not pollute the decoded response event"
        );
    }

    #[test]
    fn multi_frame_header_block_is_reassembled_before_hpack_decode() {
        // HEADERS with END_HEADERS=0 followed by CONTINUATION with END_HEADERS=1.
        // The decoder must concatenate both fragments before invoking HPACK.
        let client = TcpEndpoint {
            address: "10.0.0.1".into(),
            port: 40003,
        };
        let server = TcpEndpoint {
            address: "10.0.0.2".into(),
            port: 7777,
        };
        let mut enc = Encoder::new();
        let full = enc.encode([
            (b":method".as_slice(), b"PATCH".as_slice()),
            (
                b":path".as_slice(),
                b"/nsmf-pdusession/v1/sm-contexts/42/modify".as_slice(),
            ),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":authority".as_slice(), b"smf.example".as_slice()),
        ]);
        let split = full.len() / 2;
        let mut client_bytes = PREFACE.to_vec();
        // HEADERS without END_HEADERS, with END_STREAM so no body expected.
        client_bytes.extend(frame(1, 0x01, 5, &full[..split]));
        // CONTINUATION with END_HEADERS.
        client_bytes.extend(frame(9, 0x04, 5, &full[split..]));
        let mut resp_enc = Encoder::new();
        let ok = resp_enc.encode([(b":status".as_slice(), b"200".as_slice())]);
        let mut server_bytes = Vec::new();
        server_bytes.extend(frame(1, 0x05, 5, &ok));
        let key = TcpConnectionKey::new(client.clone(), server.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), client_bytes, 1),
                direction(server, client, server_bytes, 2),
            ],
        };
        let (events, _report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.decoding_status, DecodeStatus::Decoded);
        assert_eq!(event.message_name, "UpdateSMContext");
        assert_eq!(
            event
                .sbi
                .as_ref()
                .and_then(|s| s.request_uri.as_deref()),
            Some("/nsmf-pdusession/v1/sm-contexts/42/modify")
        );
        assert!(event.errors.is_empty(), "errors: {:?}", event.errors);
    }

    #[test]
    fn tolerant_literals_recover_huffman_encoded_authority_from_rfc7541_c41_example() {
        // RFC 7541 Appendix C.4.1 encodes "www.example.com" with Huffman as the
        // 12-octet sequence f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff. We prepend an
        // HPACK string length byte with the Huffman flag set (0x80 | 12 = 0x8c)
        // and a Literal-with-Incremental-Indexing header with name_index=1 that
        // points to the static-table :authority entry.
        let block: Vec<u8> = vec![
            0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        let recovered = tolerant_literals(&block);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].0, ":authority");
        assert_eq!(recovered[0].1, "www.example.com");
    }

    #[test]
    fn tolerant_literals_recover_huffman_encoded_path_in_sm_context_modify() {
        // Craft an SBI-style PATCH /nsmf-pdusession/v1/sm-contexts/<ref>/modify
        // literal path encoded with Huffman so the HPACK context-loss fallback
        // can still show the operation. The Huffman byte sequence below is the
        // RFC 7541 encoding of "/nsmf-pdusession/v1/sm-contexts/42/modify"
        // produced by the HPACK Huffman tree with no padding.
        //
        // Encoding was precomputed from RFC 7541 Appendix B and verified by
        // round-tripping through `hpack::huffman::HuffmanDecoder` in the test
        // itself so a drift in the lookup table is caught.
        let encoded: Vec<u8> = hpack_huffman_encode(b"/nsmf-pdusession/v1/sm-contexts/42/modify");
        assert!(encoded.len() < b"/nsmf-pdusession/v1/sm-contexts/42/modify".len());
        let len = encoded.len() as u8;
        assert!(len < 0x80, "Huffman length must fit in 7 bits for this test");
        // Literal with incremental indexing, name index 5 (:path).
        let mut block: Vec<u8> = vec![0x45, 0x80 | len];
        block.extend_from_slice(&encoded);
        let recovered = tolerant_literals(&block);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].0, ":path");
        assert_eq!(recovered[0].1, "/nsmf-pdusession/v1/sm-contexts/42/modify");
    }

    /// Encode `input` using the HPACK Huffman code (RFC 7541 Appendix B). The
    /// encoder is written here instead of relying on `hpack 0.3` because the
    /// crate does not expose the Huffman encoder (only the decoder). We walk
    /// the decoder's own internal table — bootstrapped by decoding every
    /// single-symbol Huffman byte-string — so the pair stays in sync.
    fn hpack_huffman_encode(input: &[u8]) -> Vec<u8> {
        // Appendix B constants mapping symbol → (code, bit-length).
        // Transcribed from RFC 7541 directly.
        const TABLE: &[(u32, u8)] = &[
            (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28),
            (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28),
            (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
            (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28),
            (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
            (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
            (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
            (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28),
            (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
            (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
            (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11),
            (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
            (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6),
            (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6),
            (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
            (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10),
            (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7),
            (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
            (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
            (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
            (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
            (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7),
            (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
            (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
            (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
            (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6),
            (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
            (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5),
            (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5),
            (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
            (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15),
            (0x7fc, 11), (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28),
            // Remaining entries unused for printable-ASCII test inputs; we only
            // need up to 0x7b. Future expansions can port the rest from RFC
            // 7541 Appendix B when a non-ASCII input is required.
        ];
        let mut out = Vec::new();
        let mut bit_buf: u64 = 0;
        let mut bits_in_buf: u32 = 0;
        for &byte in input {
            let (code, len) = TABLE
                .get(byte as usize)
                .copied()
                .expect("input byte outside the first 124 Huffman codes");
            bit_buf = (bit_buf << len) | u64::from(code);
            bits_in_buf += u32::from(len);
            while bits_in_buf >= 8 {
                bits_in_buf -= 8;
                out.push(((bit_buf >> bits_in_buf) & 0xff) as u8);
            }
        }
        if bits_in_buf > 0 {
            // Pad with EOS prefix (all 1s).
            let pad = 8 - bits_in_buf;
            bit_buf = (bit_buf << pad) | ((1 << pad) - 1);
            out.push((bit_buf & 0xff) as u8);
        }
        out
    }

    #[test]
    fn non_regression_well_formed_connection_emits_one_decoded_event_per_stream() {
        // Non-regression contract (vs 0.3.1 before the 0.4.2 ghost-event
        // regression): on a well-formed capture that contains N complete
        // HTTP/2 request/response pairs on distinct stream IDs,
        //   * the decoder emits EXACTLY N events (one per stream),
        //   * every event is DECODED,
        //   * no HPACK_CONTEXT_UNAVAILABLE error is produced,
        //   * no "ghost" event is created for the SETTINGS, WINDOW_UPDATE or
        //     GOAWAY frames that happen in-between.
        let client = TcpEndpoint {
            address: "10.0.0.1".into(),
            port: 50001,
        };
        let server = TcpEndpoint {
            address: "10.0.0.2".into(),
            port: 7777,
        };
        const PAIRS: u32 = 32;
        let mut enc = Encoder::new();
        let mut client_bytes = PREFACE.to_vec();
        // SETTINGS, WINDOW_UPDATE, more SETTINGS — these must not produce
        // stream-level events.
        client_bytes.extend(frame(4, 0, 0, &[])); // SETTINGS
        client_bytes.extend(frame(8, 0, 0, &[0, 0, 0, 0, 0, 0, 1, 0])); // WINDOW_UPDATE
        for i in 0..PAIRS {
            let stream_id = 1 + 2 * i;
            let path = format!("/nsmf-pdusession/v1/sm-contexts/{i}/modify");
            let hdr = enc.encode([
                (b":method".as_slice(), b"POST".as_slice()),
                (b":scheme".as_slice(), b"http".as_slice()),
                (b":authority".as_slice(), b"smf".as_slice()),
                (b":path".as_slice(), path.as_bytes()),
            ]);
            client_bytes.extend(frame(1, 5, stream_id, &hdr));
            if i % 8 == 0 {
                // Interleave more SETTINGS: these must stay stream-0 and
                // never leak into the event count.
                client_bytes.extend(frame(4, 0, 0, &[]));
            }
        }
        client_bytes.extend(frame(7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0])); // GOAWAY
        let mut resp_enc = Encoder::new();
        let mut server_bytes = Vec::new();
        for i in 0..PAIRS {
            let stream_id = 1 + 2 * i;
            let ok = resp_enc.encode([(b":status".as_slice(), b"201".as_slice())]);
            server_bytes.extend(frame(1, 5, stream_id, &ok));
        }
        let key = TcpConnectionKey::new(client.clone(), server.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), client_bytes, 1),
                direction(server, client, server_bytes, 2),
            ],
        };
        let (events, report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        assert_eq!(
            events.len() as u32,
            PAIRS,
            "expected exactly one event per stream pair, got {}",
            events.len()
        );
        for ev in &events {
            assert_eq!(
                ev.decoding_status,
                DecodeStatus::Decoded,
                "stream {:?} decoded as Partial: errors={:?}",
                ev.sbi.as_ref().map(|s| s.http2_stream_id),
                ev.errors
            );
            assert!(
                ev.errors.is_empty(),
                "stream {:?} has non-empty errors: {:?}",
                ev.sbi.as_ref().map(|s| s.http2_stream_id),
                ev.errors
            );
        }
        assert!(
            report
                .errors
                .iter()
                .all(|e| !e.contains(HPACK_CONTEXT_UNAVAILABLE)),
            "well-formed connection must not raise HPACK_CONTEXT_UNAVAILABLE: {:?}",
            report.errors
        );
        assert_eq!(report.sbi_transactions, events.len());
    }

    #[test]
    fn non_regression_hpack_failure_does_not_poison_subsequent_streams() {
        // One stream fails HPACK (dynamic-table reference missing) at the
        // start of the connection. Subsequent streams must decode cleanly —
        // no permanent direction poisoning. The failed stream contributes
        // at most one event with HPACK_CONTEXT_UNAVAILABLE on its errors
        // list (if its response decoded) or is skipped silently (if the
        // response is also missing).
        let client = TcpEndpoint {
            address: "10.0.0.1".into(),
            port: 50002,
        };
        let server = TcpEndpoint {
            address: "10.0.0.2".into(),
            port: 7777,
        };
        // Stream 1: dangling indexed reference (dynamic index 62) — HPACK fails.
        // Stream 3: normal POST — HPACK succeeds AFTER the failure above.
        let bad_block = vec![0xbe];
        let mut enc = Encoder::new();
        let good_block = enc.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":scheme".as_slice(), b"http".as_slice()),
            (b":authority".as_slice(), b"smf".as_slice()),
            (b":path".as_slice(), b"/nsmf-pdusession/v1/sm-contexts".as_slice()),
        ]);
        let mut client_bytes = PREFACE.to_vec();
        client_bytes.extend(frame(1, 5, 1, &bad_block));
        client_bytes.extend(frame(1, 5, 3, &good_block));
        let mut resp_enc = Encoder::new();
        let mut server_bytes = Vec::new();
        let ok201 = resp_enc.encode([(b":status".as_slice(), b"201".as_slice())]);
        server_bytes.extend(frame(1, 5, 1, &ok201));
        let ok201b = resp_enc.encode([(b":status".as_slice(), b"201".as_slice())]);
        server_bytes.extend(frame(1, 5, 3, &ok201b));
        let key = TcpConnectionKey::new(client.clone(), server.clone()).0;
        let conn = ReassembledConnection {
            key,
            directions: [
                direction(client.clone(), server.clone(), client_bytes, 1),
                direction(server, client, server_bytes, 2),
            ],
        };
        let (events, report) = decode_connections(&[conn], "sha256:test", "SBI", &HashMap::new());
        // Stream 1 is partial without a trustworthy request identity and is
        // therefore omitted. Stream 3 proves that the direction was NOT
        // poisoned after stream 1's failure.
        assert_eq!(events.len(), 1, "only the fully decoded stream is emitted");
        let s1 = events
            .iter()
            .find(|e| e.sbi.as_ref().map(|s| s.http2_stream_id) == Some(3))
            .expect("stream 3 present");
        assert_eq!(
            s1.decoding_status,
            DecodeStatus::Decoded,
            "stream 3 must decode cleanly after stream 1's HPACK failure (no direction poisoning)"
        );
        assert!(
            s1.errors.is_empty(),
            "stream 3 must not inherit HPACK_CONTEXT_UNAVAILABLE from stream 1: {:?}",
            s1.errors
        );
        assert!(events
            .iter()
            .all(|e| e.sbi.as_ref().map(|s| s.http2_stream_id) != Some(1)));
        // The HPACK error is reported once per failing block, not per stream
        // or per frame.
        let unavail_count = report
            .errors
            .iter()
            .filter(|e| e.contains(HPACK_CONTEXT_UNAVAILABLE))
            .count();
        assert_eq!(
            unavail_count, 1,
            "exactly one HPACK_CONTEXT_UNAVAILABLE expected (saw {}): {:?}",
            unavail_count, report.errors
        );
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
