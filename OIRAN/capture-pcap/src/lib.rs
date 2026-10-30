//! Bounded native PCAP/PCAPNG reader with exact timestamp provenance.

use event_schema::ExactTimestamp;
use std::{
    fs::File,
    io::{BufReader, ErrorKind, Read},
    path::Path,
};

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;
const MAX_CAPTURE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureFormat {
    Pcap,
    PcapNg,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Udp,
    Tcp,
    Sctp,
    Other(u8),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    pub id: u32,
    pub link_type: u32,
    pub snaplen: u32,
    pub ts_base: u8,
    pub ts_exponent: u8,
    pub ts_offset_seconds: i64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketMetadata {
    pub capture_id: String,
    pub source_file: String,
    pub packet_number: u64,
    pub byte_offset: u64,
    pub timestamp: ExactTimestamp,
    pub captured_length: u32,
    pub original_length: u32,
    pub interface_id: u32,
    pub link_type: u32,
    pub sll2: Option<Sll2Metadata>,
    pub truncated: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Sll2Metadata {
    pub protocol_type: u16,
    pub reserved: u16,
    pub interface_index: u32,
    pub arphrd_type: u16,
    pub packet_type: u8,
    pub address_length: u8,
    pub address: [u8; 8],
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturePacket {
    pub metadata: PacketMetadata,
    pub data: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureFile {
    pub format: CaptureFormat,
    pub interfaces: Vec<Interface>,
    pub packets: Vec<CapturePacket>,
    pub warnings: Vec<CaptureError>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureSummary {
    pub format: CaptureFormat,
    pub interfaces: Vec<Interface>,
    pub packets: usize,
    pub warnings: Vec<CaptureError>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportView {
    pub source_ip: String,
    pub destination_ip: String,
    pub protocol: TransportProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub payload_offset: usize,
    pub payload_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureErrorKind {
    Io,
    InvalidHeader,
    InvalidBlock,
    Truncated,
    UnsupportedLinkType,
    UnsupportedPacket,
    InvalidTimestamp,
    InvalidNetwork,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureError {
    pub kind: CaptureErrorKind,
    pub offset: u64,
    pub message: String,
}
impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} at byte {}: {}",
            self.kind, self.offset, self.message
        )
    }
}
impl std::error::Error for CaptureError {}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}
impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes([b[0], b[1]]),
            Self::Big => u16::from_be_bytes([b[0], b[1]]),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            Self::Big => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        }
    }
    fn i64(self, b: &[u8]) -> i64 {
        let a: [u8; 8] = b.try_into().expect("eight bytes");
        match self {
            Self::Little => i64::from_le_bytes(a),
            Self::Big => i64::from_be_bytes(a),
        }
    }
}

pub fn read_capture(path: impl AsRef<Path>, capture_id: &str) -> Result<CaptureFile, CaptureError> {
    let path = path.as_ref();
    let metadata = path
        .metadata()
        .map_err(|e| err(CaptureErrorKind::Io, 0, e.to_string()))?;
    if metadata.len() > MAX_CAPTURE_BYTES {
        return Err(err(
            CaptureErrorKind::InvalidHeader,
            0,
            "capture exceeds 256 MiB safety limit",
        ));
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut f| f.read_to_end(&mut data))
        .map_err(|e| err(CaptureErrorKind::Io, 0, e.to_string()))?;
    let source = path.to_string_lossy().into_owned();
    read_capture_bytes(&data, &source, capture_id)
}

/// Visit one packet at a time without materialising the capture file or its
/// packet vector. The largest allocation is bounded by `MAX_PACKET_BYTES`.
pub fn visit_capture(
    path: impl AsRef<Path>,
    capture_id: &str,
    mut visitor: impl FnMut(CapturePacket),
) -> Result<CaptureSummary, CaptureError> {
    let path = path.as_ref();
    let source = path.to_string_lossy().into_owned();
    let mut reader = BufReader::new(
        File::open(path).map_err(|error| err(CaptureErrorKind::Io, 0, error.to_string()))?,
    );
    let mut magic = [0u8; 4];
    reader
        .read_exact(&mut magic)
        .map_err(|error| err(CaptureErrorKind::InvalidHeader, 0, error.to_string()))?;
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        visit_pcapng_stream(reader, magic, &source, capture_id, &mut visitor)
    } else {
        visit_pcap_stream(reader, magic, &source, capture_id, &mut visitor)
    }
}

fn visit_pcap_stream(
    mut reader: BufReader<File>,
    magic: [u8; 4],
    source: &str,
    capture_id: &str,
    visitor: &mut impl FnMut(CapturePacket),
) -> Result<CaptureSummary, CaptureError> {
    let (endian, nano) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => {
            return Err(err(
                CaptureErrorKind::InvalidHeader,
                0,
                "unknown PCAP magic",
            ))
        }
    };
    let mut header = [0u8; 20];
    reader
        .read_exact(&mut header)
        .map_err(|error| err(CaptureErrorKind::Truncated, 4, error.to_string()))?;
    if endian.u16(&header[0..2]) != 2 {
        return Err(err(
            CaptureErrorKind::InvalidHeader,
            4,
            "unsupported PCAP major version",
        ));
    }
    let snaplen = endian.u32(&header[12..16]);
    let link = endian.u32(&header[16..20]);
    let interface = Interface {
        id: 0,
        link_type: link,
        snaplen,
        ts_base: 10,
        ts_exponent: if nano { 9 } else { 6 },
        ts_offset_seconds: 0,
    };
    let mut offset = 24u64;
    let mut number = 0u64;
    loop {
        let mut record = [0u8; 16];
        if !read_exact_or_eof(&mut reader, &mut record, offset)? {
            break;
        }
        let sec = endian.u32(&record[0..4]) as i64;
        let fraction = endian.u32(&record[4..8]) as u64;
        let cap = endian.u32(&record[8..12]);
        let orig = endian.u32(&record[12..16]);
        if orig < cap || (snaplen != 0 && cap > snaplen) {
            return Err(err(
                CaptureErrorKind::InvalidBlock,
                offset,
                "PCAP captured/original/snap lengths are inconsistent",
            ));
        }
        if cap as usize > MAX_PACKET_BYTES {
            return Err(err(
                CaptureErrorKind::InvalidBlock,
                offset,
                "packet exceeds safety limit",
            ));
        }
        let mut packet_data = vec![0u8; cap as usize];
        reader.read_exact(&mut packet_data).map_err(|_| {
            err(
                CaptureErrorKind::Truncated,
                offset,
                "PCAP packet bytes truncated",
            )
        })?;
        let units = if nano { 1_000_000_000 } else { 1_000_000 };
        if fraction >= units {
            return Err(err(
                CaptureErrorKind::InvalidTimestamp,
                offset,
                "PCAP fractional timestamp out of range",
            ));
        }
        number += 1;
        visitor(CapturePacket {
            metadata: PacketMetadata {
                capture_id: capture_id.into(),
                source_file: source.into(),
                packet_number: number,
                byte_offset: offset,
                timestamp: ExactTimestamp {
                    seconds: sec,
                    nanoseconds: if nano {
                        fraction as u32
                    } else {
                        (fraction * 1000) as u32
                    },
                    raw_ticks: (sec as u64).saturating_mul(units) + fraction,
                    resolution_base: 10,
                    resolution_exponent: if nano { 9 } else { 6 },
                },
                captured_length: cap,
                original_length: orig,
                interface_id: 0,
                link_type: link,
                sll2: sll2_metadata_if_valid(link, &packet_data),
                truncated: cap < orig,
            },
            data: packet_data,
        });
        offset = offset.saturating_add(16 + u64::from(cap));
    }
    Ok(CaptureSummary {
        format: CaptureFormat::Pcap,
        interfaces: vec![interface],
        packets: number as usize,
        warnings: Vec::new(),
    })
}

fn visit_pcapng_stream(
    mut reader: BufReader<File>,
    first_type: [u8; 4],
    source: &str,
    capture_id: &str,
    visitor: &mut impl FnMut(CapturePacket),
) -> Result<CaptureSummary, CaptureError> {
    let mut next_type = Some(first_type);
    let mut offset = 0u64;
    let mut endian = None;
    let mut interfaces = Vec::<Interface>::new();
    let mut warnings = Vec::new();
    let mut number = 0u64;
    let mut section_seen = false;
    loop {
        let block_type_raw = if let Some(value) = next_type.take() {
            value
        } else {
            let mut value = [0u8; 4];
            if !read_exact_or_eof(&mut reader, &mut value, offset)? {
                break;
            }
            value
        };
        let mut length_raw = [0u8; 4];
        reader.read_exact(&mut length_raw).map_err(|_| {
            err(
                CaptureErrorKind::Truncated,
                offset,
                "PCAPNG block header truncated",
            )
        })?;
        if block_type_raw == [0x0a, 0x0d, 0x0d, 0x0a] {
            let mut bom = [0u8; 4];
            reader.read_exact(&mut bom).map_err(|_| {
                err(
                    CaptureErrorKind::Truncated,
                    offset,
                    "section header truncated",
                )
            })?;
            let e = match bom {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                _ => {
                    return Err(err(
                        CaptureErrorKind::InvalidHeader,
                        offset + 8,
                        "invalid PCAPNG byte-order magic",
                    ))
                }
            };
            let len = e.u32(&length_raw) as usize;
            validate_stream_block_length(len, offset)?;
            if len < 28 {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    offset,
                    "section header truncated",
                ));
            }
            let mut remainder = vec![0u8; len - 12];
            reader.read_exact(&mut remainder).map_err(|_| {
                err(
                    CaptureErrorKind::Truncated,
                    offset,
                    "section header truncated",
                )
            })?;
            validate_stream_trailer(&remainder, len, e, offset)?;
            if e.u16(&remainder[0..2]) != 1 {
                return Err(err(
                    CaptureErrorKind::InvalidHeader,
                    offset + 12,
                    "unsupported PCAPNG major version",
                ));
            }
            endian = Some(e);
            interfaces.clear();
            section_seen = true;
            offset = offset.saturating_add(len as u64);
            continue;
        }
        let e = endian.ok_or_else(|| {
            err(
                CaptureErrorKind::InvalidHeader,
                offset,
                "block before section header",
            )
        })?;
        let len = e.u32(&length_raw) as usize;
        validate_stream_block_length(len, offset)?;
        let mut remainder = vec![0u8; len - 8];
        reader.read_exact(&mut remainder).map_err(|_| {
            err(
                CaptureErrorKind::Truncated,
                offset,
                "PCAPNG block exceeds file",
            )
        })?;
        validate_stream_trailer(&remainder, len, e, offset)?;
        let body = &remainder[..remainder.len() - 4];
        match e.u32(&block_type_raw) {
            1 => {
                if body.len() < 8 {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset,
                        "interface description truncated",
                    ));
                }
                let mut iface = Interface {
                    id: interfaces.len() as u32,
                    link_type: e.u16(&body[0..2]) as u32,
                    snaplen: e.u32(&body[4..8]),
                    ts_base: 10,
                    ts_exponent: 6,
                    ts_offset_seconds: 0,
                };
                parse_idb_options(&body[8..], e, &mut iface, offset as usize + 16)?;
                interfaces.push(iface);
            }
            6 | 2 => {
                if body.len() < 20 {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset,
                        "packet block truncated",
                    ));
                }
                let iface_id = if e.u32(&block_type_raw) == 6 {
                    e.u32(&body[0..4])
                } else {
                    e.u16(&body[0..2]) as u32
                };
                let iface = interfaces.get(iface_id as usize).ok_or_else(|| {
                    err(
                        CaptureErrorKind::InvalidBlock,
                        offset,
                        "packet references unknown interface",
                    )
                })?;
                let ticks = ((e.u32(&body[4..8]) as u64) << 32) | e.u32(&body[8..12]) as u64;
                let cap = e.u32(&body[12..16]);
                let orig = e.u32(&body[16..20]);
                if orig < cap || (iface.snaplen != 0 && cap > iface.snaplen) {
                    return Err(err(
                        CaptureErrorKind::InvalidBlock,
                        offset,
                        "packet lengths exceed original length or snaplen",
                    ));
                }
                if cap as usize > MAX_PACKET_BYTES || 20 + align4(cap as usize) > body.len() {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset,
                        "packet data truncated",
                    ));
                }
                number += 1;
                let packet_data = body[20..20 + cap as usize].to_vec();
                let mut packet_metadata =
                    metadata(capture_id, source, number, offset, ticks, cap, orig, iface)?;
                packet_metadata.sll2 = sll2_metadata_if_valid(iface.link_type, &packet_data);
                visitor(CapturePacket {
                    metadata: packet_metadata,
                    data: packet_data,
                });
            }
            3 => warnings.push(err(
                CaptureErrorKind::UnsupportedPacket,
                offset,
                "simple packet block has no source timestamp and was not emitted",
            )),
            _ => {}
        }
        offset = offset.saturating_add(len as u64);
    }
    if !section_seen {
        return Err(err(CaptureErrorKind::InvalidHeader, 0, "no PCAPNG section"));
    }
    Ok(CaptureSummary {
        format: CaptureFormat::PcapNg,
        interfaces,
        packets: number as usize,
        warnings,
    })
}

fn read_exact_or_eof(
    reader: &mut BufReader<File>,
    bytes: &mut [u8],
    offset: u64,
) -> Result<bool, CaptureError> {
    match reader.read(&mut bytes[..1]) {
        Ok(0) => Ok(false),
        Ok(1) => {
            reader.read_exact(&mut bytes[1..]).map_err(|_| {
                err(
                    CaptureErrorKind::Truncated,
                    offset,
                    "capture record truncated",
                )
            })?;
            Ok(true)
        }
        Ok(_) => unreachable!(),
        Err(error) if error.kind() == ErrorKind::Interrupted => {
            read_exact_or_eof(reader, bytes, offset)
        }
        Err(error) => Err(err(CaptureErrorKind::Io, offset, error.to_string())),
    }
}

fn validate_stream_block_length(len: usize, offset: u64) -> Result<(), CaptureError> {
    if len < 12 || len % 4 != 0 || len > MAX_PACKET_BYTES + 1024 * 1024 {
        return Err(err(
            CaptureErrorKind::InvalidBlock,
            offset,
            "invalid PCAPNG block length",
        ));
    }
    Ok(())
}

fn validate_stream_trailer(
    remainder: &[u8],
    len: usize,
    endian: Endian,
    offset: u64,
) -> Result<(), CaptureError> {
    if remainder.len() < 4 || endian.u32(&remainder[remainder.len() - 4..]) as usize != len {
        return Err(err(
            CaptureErrorKind::InvalidBlock,
            offset,
            "PCAPNG trailing block length mismatch",
        ));
    }
    Ok(())
}
pub fn read_capture_bytes(
    data: &[u8],
    source: &str,
    capture_id: &str,
) -> Result<CaptureFile, CaptureError> {
    if data.len() < 4 {
        return Err(err(
            CaptureErrorKind::InvalidHeader,
            0,
            "file shorter than magic",
        ));
    }
    match &data[..4] {
        [0x0a, 0x0d, 0x0d, 0x0a] => read_pcapng(data, source, capture_id),
        _ => read_pcap(data, source, capture_id),
    }
}

fn read_pcap(data: &[u8], source: &str, capture_id: &str) -> Result<CaptureFile, CaptureError> {
    if data.len() < 24 {
        return Err(err(
            CaptureErrorKind::InvalidHeader,
            0,
            "PCAP global header truncated",
        ));
    }
    let (endian, nano) = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => {
            return Err(err(
                CaptureErrorKind::InvalidHeader,
                0,
                "unknown PCAP magic",
            ))
        }
    };
    if endian.u16(&data[4..6]) != 2 {
        return Err(err(
            CaptureErrorKind::InvalidHeader,
            4,
            "unsupported PCAP major version",
        ));
    }
    let snaplen = endian.u32(&data[16..20]);
    let link = endian.u32(&data[20..24]);
    let interface = Interface {
        id: 0,
        link_type: link,
        snaplen,
        ts_base: 10,
        ts_exponent: if nano { 9 } else { 6 },
        ts_offset_seconds: 0,
    };
    let mut offset = 24usize;
    let mut number = 0;
    let mut packets = Vec::new();
    while offset < data.len() {
        if data.len() - offset < 16 {
            return Err(err(
                CaptureErrorKind::Truncated,
                offset as u64,
                "PCAP record header truncated",
            ));
        }
        let start = offset;
        let sec = endian.u32(&data[offset..offset + 4]) as i64;
        let fraction = endian.u32(&data[offset + 4..offset + 8]) as u64;
        let cap = endian.u32(&data[offset + 8..offset + 12]);
        let orig = endian.u32(&data[offset + 12..offset + 16]);
        if orig < cap || (snaplen != 0 && cap > snaplen) {
            return Err(err(
                CaptureErrorKind::InvalidBlock,
                start as u64,
                "PCAP captured/original/snap lengths are inconsistent",
            ));
        }
        offset += 16;
        if cap as usize > MAX_PACKET_BYTES {
            return Err(err(
                CaptureErrorKind::InvalidBlock,
                start as u64,
                "packet exceeds safety limit",
            ));
        }
        if offset
            .checked_add(cap as usize)
            .filter(|end| *end <= data.len())
            .is_none()
        {
            return Err(err(
                CaptureErrorKind::Truncated,
                start as u64,
                "PCAP packet bytes truncated",
            ));
        }
        number += 1;
        let units = if nano { 1_000_000_000 } else { 1_000_000 };
        if fraction >= units {
            return Err(err(
                CaptureErrorKind::InvalidTimestamp,
                start as u64,
                "PCAP fractional timestamp out of range",
            ));
        }
        let nanos = if nano {
            fraction as u32
        } else {
            (fraction * 1000) as u32
        };
        let packet_data = data[offset..offset + cap as usize].to_vec();
        packets.push(CapturePacket {
            metadata: PacketMetadata {
                capture_id: capture_id.into(),
                source_file: source.into(),
                packet_number: number,
                byte_offset: start as u64,
                timestamp: ExactTimestamp {
                    seconds: sec,
                    nanoseconds: nanos,
                    raw_ticks: (sec as u64).saturating_mul(units) + fraction,
                    resolution_base: 10,
                    resolution_exponent: if nano { 9 } else { 6 },
                },
                captured_length: cap,
                original_length: orig,
                interface_id: 0,
                link_type: link,
                sll2: sll2_metadata_if_valid(link, &packet_data),
                truncated: cap < orig,
            },
            data: packet_data,
        });
        offset += cap as usize;
    }
    Ok(CaptureFile {
        format: CaptureFormat::Pcap,
        interfaces: vec![interface],
        packets,
        warnings: Vec::new(),
    })
}

fn read_pcapng(data: &[u8], source: &str, capture_id: &str) -> Result<CaptureFile, CaptureError> {
    let mut offset = 0usize;
    let mut endian = None;
    let mut interfaces = Vec::<Interface>::new();
    let mut packets = Vec::new();
    let mut warnings = Vec::new();
    let mut number = 0u64;
    let mut section_seen = false;
    while offset < data.len() {
        if data.len() - offset < 12 {
            return Err(err(
                CaptureErrorKind::Truncated,
                offset as u64,
                "PCAPNG block header truncated",
            ));
        }
        let block_type_raw = &data[offset..offset + 4];
        if block_type_raw == [0x0a, 0x0d, 0x0d, 0x0a] {
            if data.len() - offset < 28 {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    offset as u64,
                    "section header truncated",
                ));
            }
            let e = match &data[offset + 8..offset + 12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
                [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
                _ => {
                    return Err(err(
                        CaptureErrorKind::InvalidHeader,
                        (offset + 8) as u64,
                        "invalid PCAPNG byte-order magic",
                    ))
                }
            };
            let len = e.u32(&data[offset + 4..offset + 8]) as usize;
            validate_block(data, offset, len, e)?;
            if e.u16(&data[offset + 12..offset + 14]) != 1 {
                return Err(err(
                    CaptureErrorKind::InvalidHeader,
                    (offset + 12) as u64,
                    "unsupported PCAPNG major version",
                ));
            }
            endian = Some(e);
            interfaces.clear();
            section_seen = true;
            offset += len;
            continue;
        }
        let e = endian.ok_or_else(|| {
            err(
                CaptureErrorKind::InvalidHeader,
                offset as u64,
                "block before section header",
            )
        })?;
        let block_type = e.u32(block_type_raw);
        let len = e.u32(&data[offset + 4..offset + 8]) as usize;
        validate_block(data, offset, len, e)?;
        let body = &data[offset + 8..offset + len - 4];
        match block_type {
            1 => {
                if body.len() < 8 {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset as u64,
                        "interface description truncated",
                    ));
                }
                let id = interfaces.len() as u32;
                let mut iface = Interface {
                    id,
                    link_type: e.u16(&body[0..2]) as u32,
                    snaplen: e.u32(&body[4..8]),
                    ts_base: 10,
                    ts_exponent: 6,
                    ts_offset_seconds: 0,
                };
                parse_idb_options(&body[8..], e, &mut iface, offset + 16)?;
                interfaces.push(iface);
            }
            6 => {
                if body.len() < 20 {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset as u64,
                        "enhanced packet block truncated",
                    ));
                }
                let iface_id = e.u32(&body[0..4]);
                let iface = interfaces.get(iface_id as usize).ok_or_else(|| {
                    err(
                        CaptureErrorKind::InvalidBlock,
                        offset as u64,
                        "packet references unknown interface",
                    )
                })?;
                let ticks = ((e.u32(&body[4..8]) as u64) << 32) | e.u32(&body[8..12]) as u64;
                let cap = e.u32(&body[12..16]);
                let orig = e.u32(&body[16..20]);
                if orig < cap || (iface.snaplen != 0 && cap > iface.snaplen) {
                    return Err(err(
                        CaptureErrorKind::InvalidBlock,
                        offset as u64,
                        "enhanced packet lengths exceed original length or snaplen",
                    ));
                }
                let padded = align4(cap as usize);
                if cap as usize > MAX_PACKET_BYTES || 20 + padded > body.len() {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset as u64,
                        "enhanced packet data truncated",
                    ));
                }
                number += 1;
                let packet_data = body[20..20 + cap as usize].to_vec();
                let mut packet_metadata = metadata(
                    capture_id,
                    source,
                    number,
                    offset as u64,
                    ticks,
                    cap,
                    orig,
                    iface,
                )?;
                packet_metadata.sll2 = sll2_metadata_if_valid(iface.link_type, &packet_data);
                packets.push(CapturePacket {
                    metadata: packet_metadata,
                    data: packet_data,
                });
            }
            2 => {
                if body.len() < 20 {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset as u64,
                        "obsolete packet block truncated",
                    ));
                }
                let iface_id = e.u16(&body[0..2]) as u32;
                let iface = interfaces.get(iface_id as usize).ok_or_else(|| {
                    err(
                        CaptureErrorKind::InvalidBlock,
                        offset as u64,
                        "packet references unknown interface",
                    )
                })?;
                let ticks = ((e.u32(&body[4..8]) as u64) << 32) | e.u32(&body[8..12]) as u64;
                let cap = e.u32(&body[12..16]);
                let orig = e.u32(&body[16..20]);
                if orig < cap || (iface.snaplen != 0 && cap > iface.snaplen) {
                    return Err(err(
                        CaptureErrorKind::InvalidBlock,
                        offset as u64,
                        "packet lengths exceed original length or snaplen",
                    ));
                }
                if 20 + align4(cap as usize) > body.len() {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        offset as u64,
                        "packet block data truncated",
                    ));
                }
                number += 1;
                let packet_data = body[20..20 + cap as usize].to_vec();
                let mut packet_metadata = metadata(
                    capture_id,
                    source,
                    number,
                    offset as u64,
                    ticks,
                    cap,
                    orig,
                    iface,
                )?;
                packet_metadata.sll2 = sll2_metadata_if_valid(iface.link_type, &packet_data);
                packets.push(CapturePacket {
                    metadata: packet_metadata,
                    data: packet_data,
                });
            }
            3 => warnings.push(err(
                CaptureErrorKind::UnsupportedPacket,
                offset as u64,
                "simple packet block has no source timestamp and was not emitted",
            )),
            _ => {}
        }
        offset += len;
    }
    if !section_seen {
        return Err(err(CaptureErrorKind::InvalidHeader, 0, "no PCAPNG section"));
    }
    Ok(CaptureFile {
        format: CaptureFormat::PcapNg,
        interfaces,
        packets,
        warnings,
    })
}
fn validate_block(data: &[u8], offset: usize, len: usize, e: Endian) -> Result<(), CaptureError> {
    if len < 12 || len % 4 != 0 {
        return Err(err(
            CaptureErrorKind::InvalidBlock,
            offset as u64,
            "invalid PCAPNG block length",
        ));
    }
    let end = offset
        .checked_add(len)
        .filter(|v| *v <= data.len())
        .ok_or_else(|| {
            err(
                CaptureErrorKind::Truncated,
                offset as u64,
                "PCAPNG block exceeds file",
            )
        })?;
    if e.u32(&data[end - 4..end]) as usize != len {
        return Err(err(
            CaptureErrorKind::InvalidBlock,
            offset as u64,
            "PCAPNG trailing block length mismatch",
        ));
    }
    Ok(())
}
fn parse_idb_options(
    mut bytes: &[u8],
    e: Endian,
    iface: &mut Interface,
    base: usize,
) -> Result<(), CaptureError> {
    let mut consumed = 0;
    while bytes.len() >= 4 {
        let code = e.u16(&bytes[..2]);
        let len = e.u16(&bytes[2..4]) as usize;
        if code == 0 {
            return Ok(());
        }
        let padded = align4(len);
        if 4 + padded > bytes.len() {
            return Err(err(
                CaptureErrorKind::Truncated,
                (base + consumed) as u64,
                "interface option truncated",
            ));
        }
        let value = &bytes[4..4 + len];
        match code {
            9 if len == 1 => {
                let raw = value[0];
                iface.ts_base = if raw & 0x80 == 0 { 10 } else { 2 };
                iface.ts_exponent = raw & 0x7f;
                if iface.ts_exponent > 63 {
                    return Err(err(
                        CaptureErrorKind::InvalidTimestamp,
                        (base + consumed) as u64,
                        "timestamp resolution exponent too large",
                    ));
                }
            }
            14 if len == 8 => iface.ts_offset_seconds = e.i64(value),
            _ => {}
        }
        consumed += 4 + padded;
        bytes = &bytes[4 + padded..];
    }
    Ok(())
}
fn metadata(
    capture_id: &str,
    source: &str,
    number: u64,
    offset: u64,
    ticks: u64,
    cap: u32,
    orig: u32,
    iface: &Interface,
) -> Result<PacketMetadata, CaptureError> {
    let units = if iface.ts_base == 10 {
        10u128.checked_pow(iface.ts_exponent as u32)
    } else {
        2u128.checked_pow(iface.ts_exponent as u32)
    }
    .ok_or_else(|| {
        err(
            CaptureErrorKind::InvalidTimestamp,
            offset,
            "timestamp resolution overflow",
        )
    })?;
    let seconds = (ticks as u128 / units) as i64 + iface.ts_offset_seconds;
    let remainder = ticks as u128 % units;
    let nanoseconds = ((remainder * 1_000_000_000) / units) as u32;
    Ok(PacketMetadata {
        capture_id: capture_id.into(),
        source_file: source.into(),
        packet_number: number,
        byte_offset: offset,
        timestamp: ExactTimestamp {
            seconds,
            nanoseconds,
            raw_ticks: ticks,
            resolution_base: iface.ts_base,
            resolution_exponent: iface.ts_exponent,
        },
        captured_length: cap,
        original_length: orig,
        interface_id: iface.id,
        link_type: iface.link_type,
        sll2: None,
        truncated: cap < orig,
    })
}
fn align4(v: usize) -> usize {
    (v + 3) & !3
}
fn err(kind: CaptureErrorKind, offset: u64, message: impl Into<String>) -> CaptureError {
    CaptureError {
        kind,
        offset,
        message: message.into(),
    }
}

pub fn transport_view(packet: &CapturePacket) -> Result<TransportView, CaptureError> {
    let frame = &packet.data;
    let (mut l3, mut ether) = match packet.metadata.link_type {
        LINKTYPE_ETHERNET => {
            if frame.len() < 14 {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    packet.metadata.byte_offset,
                    "Ethernet header truncated",
                ));
            }
            (14, u16::from_be_bytes([frame[12], frame[13]]))
        }
        LINKTYPE_LINUX_SLL => {
            if frame.len() < 16 {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    packet.metadata.byte_offset,
                    "Linux cooked header truncated",
                ));
            }
            (16, u16::from_be_bytes([frame[14], frame[15]]))
        }
        LINKTYPE_LINUX_SLL2 => {
            let header = parse_sll2(frame, packet.metadata.byte_offset)?;
            (20, header.protocol_type)
        }
        other => {
            return Err(err(
                CaptureErrorKind::UnsupportedLinkType,
                packet.metadata.byte_offset,
                format!("link type {other}"),
            ))
        }
    };
    for _ in 0..2 {
        if ether == 0x8100 || ether == 0x88a8 {
            if frame.len() < l3 + 4 {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    packet.metadata.byte_offset,
                    "VLAN header truncated",
                ));
            }
            ether = u16::from_be_bytes([frame[l3 + 2], frame[l3 + 3]]);
            l3 += 4;
        }
    }
    let (source, destination, proto, l4, end) = match ether {
        0x0800 => parse_v4(frame, l3, packet.metadata.byte_offset)?,
        0x86dd => parse_v6(frame, l3, packet.metadata.byte_offset)?,
        _ => {
            return Err(err(
                CaptureErrorKind::InvalidNetwork,
                packet.metadata.byte_offset,
                format!("unsupported EtherType 0x{ether:04x}"),
            ))
        }
    };
    match proto {
        6 => {
            if l4 + 20 > end {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    packet.metadata.byte_offset,
                    "TCP header truncated",
                ));
            }
            let data_offset = usize::from(frame[l4 + 12] >> 4) * 4;
            if data_offset < 20 || l4 + data_offset > end {
                return Err(err(
                    CaptureErrorKind::InvalidNetwork,
                    packet.metadata.byte_offset,
                    "invalid TCP data offset",
                ));
            }
            Ok(TransportView {
                source_ip: source,
                destination_ip: destination,
                protocol: TransportProtocol::Tcp,
                source_port: Some(u16::from_be_bytes([frame[l4], frame[l4 + 1]])),
                destination_port: Some(u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]])),
                payload_offset: l4,
                payload_length: end - l4,
            })
        }
        17 => {
            if l4 + 8 > end {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    packet.metadata.byte_offset,
                    "UDP header truncated",
                ));
            }
            let src = u16::from_be_bytes([frame[l4], frame[l4 + 1]]);
            let dst = u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]);
            let len = u16::from_be_bytes([frame[l4 + 4], frame[l4 + 5]]) as usize;
            if len < 8 || l4 + len > end {
                return Err(err(
                    CaptureErrorKind::InvalidNetwork,
                    packet.metadata.byte_offset,
                    "invalid UDP length",
                ));
            }
            Ok(TransportView {
                source_ip: source,
                destination_ip: destination,
                protocol: TransportProtocol::Udp,
                source_port: Some(src),
                destination_port: Some(dst),
                payload_offset: l4 + 8,
                payload_length: len - 8,
            })
        }
        132 => {
            if l4 + 12 > end {
                return Err(err(
                    CaptureErrorKind::Truncated,
                    packet.metadata.byte_offset,
                    "SCTP common header truncated",
                ));
            }
            Ok(TransportView {
                source_ip: source,
                destination_ip: destination,
                protocol: TransportProtocol::Sctp,
                source_port: Some(u16::from_be_bytes([frame[l4], frame[l4 + 1]])),
                destination_port: Some(u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]])),
                payload_offset: l4,
                payload_length: end - l4,
            })
        }
        other => Ok(TransportView {
            source_ip: source,
            destination_ip: destination,
            protocol: TransportProtocol::Other(other),
            source_port: None,
            destination_port: None,
            payload_offset: l4,
            payload_length: end - l4,
        }),
    }
}

fn sll2_metadata_if_valid(link_type: u32, frame: &[u8]) -> Option<Sll2Metadata> {
    if link_type == LINKTYPE_LINUX_SLL2 {
        parse_sll2(frame, 0).ok()
    } else {
        None
    }
}

fn parse_sll2(frame: &[u8], at: u64) -> Result<Sll2Metadata, CaptureError> {
    if frame.len() < 20 {
        return Err(err(
            CaptureErrorKind::Truncated,
            at,
            "Linux cooked v2 header truncated",
        ));
    }
    let address_length = frame[11];
    if address_length > 8 {
        return Err(err(
            CaptureErrorKind::InvalidNetwork,
            at,
            format!("invalid Linux cooked v2 address length {address_length}"),
        ));
    }
    let mut address = [0_u8; 8];
    address.copy_from_slice(&frame[12..20]);
    Ok(Sll2Metadata {
        protocol_type: u16::from_be_bytes([frame[0], frame[1]]),
        reserved: u16::from_be_bytes([frame[2], frame[3]]),
        interface_index: u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]),
        arphrd_type: u16::from_be_bytes([frame[8], frame[9]]),
        packet_type: frame[10],
        address_length,
        address,
    })
}
fn parse_v4(
    f: &[u8],
    o: usize,
    at: u64,
) -> Result<(String, String, u8, usize, usize), CaptureError> {
    if f.len() < o + 20 {
        return Err(err(
            CaptureErrorKind::Truncated,
            at,
            "IPv4 header truncated",
        ));
    }
    let h = (f[o] & 15) as usize * 4;
    if f[o] >> 4 != 4 || h < 20 || f.len() < o + h {
        return Err(err(
            CaptureErrorKind::InvalidNetwork,
            at,
            "invalid IPv4 header",
        ));
    }
    let total = u16::from_be_bytes([f[o + 2], f[o + 3]]) as usize;
    if total < h || f.len() < o + total {
        return Err(err(
            CaptureErrorKind::Truncated,
            at,
            "IPv4 payload truncated",
        ));
    }
    let frag = u16::from_be_bytes([f[o + 6], f[o + 7]]);
    if frag & 0x3fff != 0 {
        return Err(err(
            CaptureErrorKind::UnsupportedPacket,
            at,
            "fragmented IPv4 requires IP reassembly",
        ));
    }
    Ok((
        format!("{}.{}.{}.{}", f[o + 12], f[o + 13], f[o + 14], f[o + 15]),
        format!("{}.{}.{}.{}", f[o + 16], f[o + 17], f[o + 18], f[o + 19]),
        f[o + 9],
        o + h,
        o + total,
    ))
}
fn parse_v6(
    f: &[u8],
    o: usize,
    at: u64,
) -> Result<(String, String, u8, usize, usize), CaptureError> {
    if f.len() < o + 40 {
        return Err(err(
            CaptureErrorKind::Truncated,
            at,
            "IPv6 header truncated",
        ));
    }
    if f[o] >> 4 != 6 {
        return Err(err(
            CaptureErrorKind::InvalidNetwork,
            at,
            "invalid IPv6 version",
        ));
    }
    let end = o + 40 + u16::from_be_bytes([f[o + 4], f[o + 5]]) as usize;
    if end > f.len() {
        return Err(err(
            CaptureErrorKind::Truncated,
            at,
            "IPv6 payload truncated",
        ));
    }
    let ip = |b: &[u8]| {
        (0..8)
            .map(|i| format!("{:x}", u16::from_be_bytes([b[i * 2], b[i * 2 + 1]])))
            .collect::<Vec<_>>()
            .join(":")
    };
    let mut next = f[o + 6];
    let mut cursor = o + 40;
    for _ in 0..8 {
        let extension_length = match next {
            0 | 43 | 60 => {
                if cursor + 2 > end {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        at,
                        "IPv6 extension header truncated",
                    ));
                }
                let length = (usize::from(f[cursor + 1]) + 1) * 8;
                let following = f[cursor];
                next = following;
                length
            }
            51 => {
                if cursor + 2 > end {
                    return Err(err(
                        CaptureErrorKind::Truncated,
                        at,
                        "IPv6 AH header truncated",
                    ));
                }
                let length = (usize::from(f[cursor + 1]) + 2) * 4;
                let following = f[cursor];
                next = following;
                length
            }
            44 => {
                return Err(err(
                    CaptureErrorKind::UnsupportedPacket,
                    at,
                    "fragmented IPv6 requires IP reassembly",
                ))
            }
            50 => {
                return Err(err(
                    CaptureErrorKind::UnsupportedPacket,
                    at,
                    "IPv6 ESP payload is encrypted and unsupported",
                ))
            }
            _ => break,
        };
        cursor = cursor.checked_add(extension_length).ok_or_else(|| {
            err(
                CaptureErrorKind::InvalidNetwork,
                at,
                "IPv6 extension offset overflow",
            )
        })?;
        if cursor > end {
            return Err(err(
                CaptureErrorKind::Truncated,
                at,
                "IPv6 extension header exceeds payload",
            ));
        }
    }
    if matches!(next, 0 | 43 | 44 | 50 | 51 | 60) {
        return Err(err(
            CaptureErrorKind::UnsupportedPacket,
            at,
            "IPv6 extension-header chain exceeds bounded traversal",
        ));
    }
    Ok((
        ip(&f[o + 8..o + 24]),
        ip(&f[o + 24..o + 40]),
        next,
        cursor,
        end,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_capture(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "capture-pcap-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }
    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }
    fn pcap() -> Vec<u8> {
        let mut v = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&le32(65535));
        v.extend_from_slice(&le32(1));
        v.extend_from_slice(&le32(1));
        v.extend_from_slice(&le32(2));
        v.extend_from_slice(&le32(4));
        v.extend_from_slice(&le32(6));
        v.extend_from_slice(&[1, 2, 3, 4]);
        v
    }
    fn pcap_with(link_type: u32, packet: &[u8], seconds: u32, micros: u32) -> Vec<u8> {
        let mut v = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        v.extend_from_slice(&[0; 8]);
        v.extend_from_slice(&le32(65535));
        v.extend_from_slice(&le32(link_type));
        v.extend_from_slice(&le32(seconds));
        v.extend_from_slice(&le32(micros));
        v.extend_from_slice(&le32(packet.len() as u32));
        v.extend_from_slice(&le32(packet.len() as u32));
        v.extend_from_slice(packet);
        v
    }
    fn ipv4_udp() -> Vec<u8> {
        let mut packet = vec![0_u8; 30];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&30_u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
        packet[20..22].copy_from_slice(&8805_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&8805_u16.to_be_bytes());
        packet[24..26].copy_from_slice(&10_u16.to_be_bytes());
        packet[28..30].copy_from_slice(&[0xaa, 0xbb]);
        packet
    }
    fn ipv6_udp() -> Vec<u8> {
        let mut packet = vec![0_u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8_u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40..42].copy_from_slice(&2152_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&2152_u16.to_be_bytes());
        packet[44..46].copy_from_slice(&8_u16.to_be_bytes());
        packet
    }
    fn sll2(protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20 + payload.len());
        packet.extend_from_slice(&protocol.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&42_u32.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.push(4);
        packet.push(6);
        packet.extend_from_slice(&[0x02, 0, 0, 0, 0, 1, 0, 0]);
        packet.extend_from_slice(payload);
        packet
    }
    fn ethernet(payload: &[u8], ether_type: u16) -> Vec<u8> {
        let mut packet = vec![0_u8; 12];
        packet.extend_from_slice(&ether_type.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }
    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let len = (12 + align4(body.len())) as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(body);
        v.resize((len - 4) as usize, 0);
        v.extend_from_slice(&len.to_le_bytes());
        v
    }
    fn pcapng() -> Vec<u8> {
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b3c4d_u32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        let mut idb1 = Vec::new();
        idb1.extend_from_slice(&1u16.to_le_bytes());
        idb1.extend_from_slice(&0u16.to_le_bytes());
        idb1.extend_from_slice(&65535u32.to_le_bytes());
        idb1.extend_from_slice(&9u16.to_le_bytes());
        idb1.extend_from_slice(&1u16.to_le_bytes());
        idb1.push(9);
        idb1.extend_from_slice(&[0; 3]);
        idb1.extend_from_slice(&[0; 4]);
        let mut idb2 = idb1.clone();
        idb2[12] = 0x8a;
        let mut epb = Vec::new();
        epb.extend_from_slice(&1u32.to_le_bytes());
        epb.extend_from_slice(&0u32.to_le_bytes());
        epb.extend_from_slice(&1024u32.to_le_bytes());
        epb.extend_from_slice(&4u32.to_le_bytes());
        epb.extend_from_slice(&4u32.to_le_bytes());
        epb.extend_from_slice(&[1, 2, 3, 4]);
        [
            block(0x0a0d0d0a, &shb),
            block(1, &idb1),
            block(1, &idb2),
            block(6, &epb),
        ]
        .concat()
    }
    #[test]
    fn reads_valid_pcap() {
        let f = read_capture_bytes(&pcap(), "a.pcap", "id").unwrap();
        assert_eq!(f.format, CaptureFormat::Pcap);
        assert_eq!(f.packets.len(), 1);
        assert!(f.packets[0].metadata.truncated);
        assert_eq!(f.packets[0].metadata.timestamp.nanoseconds, 2000);
    }

    #[test]
    fn streaming_pcap_matches_in_memory_metadata_and_packets() {
        let bytes = pcap();
        let path = temporary_capture("stream.pcap", &bytes);
        let expected = read_capture_bytes(&bytes, &path.to_string_lossy(), "id").unwrap();
        let mut packets = Vec::new();
        let summary = visit_capture(&path, "id", |packet| packets.push(packet)).unwrap();
        assert_eq!(summary.format, expected.format);
        assert_eq!(summary.interfaces, expected.interfaces);
        assert_eq!(summary.warnings, expected.warnings);
        assert_eq!(summary.packets, expected.packets.len());
        assert_eq!(packets, expected.packets);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn reads_pcapng_interfaces_and_resolution() {
        let f = read_capture_bytes(&pcapng(), "a.pcapng", "id").unwrap();
        assert_eq!(f.interfaces.len(), 2);
        assert_eq!(f.packets[0].metadata.interface_id, 1);
        assert_eq!(f.interfaces[0].ts_exponent, 9);
        assert_eq!(f.interfaces[1].ts_base, 2);
        assert_eq!(f.packets[0].metadata.timestamp.seconds, 1);
        assert_eq!(f.packets[0].metadata.timestamp.nanoseconds, 0);
        assert_eq!(f.packets[0].metadata.timestamp.raw_ticks, 1024);
    }

    #[test]
    fn streaming_pcapng_matches_in_memory_metadata_and_packets() {
        let bytes = pcapng();
        let path = temporary_capture("stream.pcapng", &bytes);
        let expected = read_capture_bytes(&bytes, &path.to_string_lossy(), "id").unwrap();
        let mut packets = Vec::new();
        let summary = visit_capture(&path, "id", |packet| packets.push(packet)).unwrap();
        assert_eq!(summary.format, expected.format);
        assert_eq!(summary.interfaces, expected.interfaces);
        assert_eq!(summary.warnings, expected.warnings);
        assert_eq!(summary.packets, expected.packets.len());
        assert_eq!(packets, expected.packets);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn rejects_malformed_and_truncated() {
        assert!(read_capture_bytes(&[1, 2, 3], "x", "id").is_err());
        let mut v = pcap();
        v.pop();
        assert_eq!(
            read_capture_bytes(&v, "x", "id").unwrap_err().kind,
            CaptureErrorKind::Truncated
        );
    }
    #[test]
    fn reads_pcap_linktype_276_and_preserves_sll2_ipv4_metadata() {
        let bytes = pcap_with(LINKTYPE_LINUX_SLL2, &sll2(0x0800, &ipv4_udp()), 7, 123_456);
        let capture = read_capture_bytes(&bytes, "sll2.pcap", "sha256:abc").unwrap();
        let packet = &capture.packets[0];
        assert_eq!(packet.metadata.link_type, LINKTYPE_LINUX_SLL2);
        assert_eq!(packet.metadata.timestamp.seconds, 7);
        assert_eq!(packet.metadata.timestamp.nanoseconds, 123_456_000);
        let metadata = packet.metadata.sll2.as_ref().unwrap();
        assert_eq!(metadata.protocol_type, 0x0800);
        assert_eq!(metadata.interface_index, 42);
        assert_eq!(metadata.arphrd_type, 1);
        assert_eq!(metadata.packet_type, 4);
        assert_eq!(metadata.address_length, 6);
        assert_eq!(&metadata.address[..6], &[0x02, 0, 0, 0, 0, 1]);
        let view = transport_view(packet).unwrap();
        assert_eq!(view.source_ip, "10.0.0.1");
        assert_eq!(view.destination_ip, "10.0.0.2");
        assert_eq!(view.protocol, TransportProtocol::Udp);
        assert_eq!(view.source_port, Some(8805));
    }
    #[test]
    fn parses_sll2_ipv6() {
        let bytes = pcap_with(LINKTYPE_LINUX_SLL2, &sll2(0x86dd, &ipv6_udp()), 1, 0);
        let capture = read_capture_bytes(&bytes, "sll2-v6.pcap", "sha256:abc").unwrap();
        let view = transport_view(&capture.packets[0]).unwrap();
        assert_eq!(view.source_ip, "2001:db08:0:0:0:0:0:1");
        assert_eq!(view.destination_port, Some(2152));
    }
    #[test]
    fn preserves_defined_sll2_packet_type_values() {
        for packet_type in 0..=7 {
            let mut frame = sll2(0x0800, &ipv4_udp());
            frame[10] = packet_type;
            let bytes = pcap_with(LINKTYPE_LINUX_SLL2, &frame, 1, 0);
            let capture = read_capture_bytes(&bytes, "packet-type.pcap", "sha256:abc").unwrap();
            assert_eq!(
                capture.packets[0]
                    .metadata
                    .sll2
                    .as_ref()
                    .unwrap()
                    .packet_type,
                packet_type
            );
            assert!(transport_view(&capture.packets[0]).is_ok());
        }
    }
    #[test]
    fn rejects_truncated_invalid_address_and_unsupported_protocol() {
        let packet = |data: Vec<u8>| CapturePacket {
            metadata: PacketMetadata {
                capture_id: "sha256:abc".into(),
                source_file: "test".into(),
                packet_number: 1,
                byte_offset: 24,
                timestamp: ExactTimestamp {
                    seconds: 0,
                    nanoseconds: 0,
                    raw_ticks: 0,
                    resolution_base: 10,
                    resolution_exponent: 6,
                },
                captured_length: data.len() as u32,
                original_length: data.len() as u32,
                interface_id: 0,
                link_type: LINKTYPE_LINUX_SLL2,
                sll2: None,
                truncated: false,
            },
            data,
        };
        assert_eq!(
            transport_view(&packet(vec![0; 19])).unwrap_err().kind,
            CaptureErrorKind::Truncated
        );
        let mut invalid = sll2(0x0800, &ipv4_udp());
        invalid[11] = 9;
        assert_eq!(
            transport_view(&packet(invalid)).unwrap_err().kind,
            CaptureErrorKind::InvalidNetwork
        );
        let unsupported = sll2(0x0806, &[0; 28]);
        let error = transport_view(&packet(unsupported)).unwrap_err();
        assert_eq!(error.kind, CaptureErrorKind::InvalidNetwork);
        assert!(error.message.contains("0806"));
    }
    #[test]
    fn mixed_pcapng_interfaces_dispatch_by_interface_link_type() {
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b3c4d_u32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        let idb = |link: u16| {
            let mut body = Vec::new();
            body.extend_from_slice(&link.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&65535u32.to_le_bytes());
            body
        };
        let epb = |interface: u32, packet: &[u8]| {
            let mut body = Vec::new();
            body.extend_from_slice(&interface.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&(interface + 1).to_le_bytes());
            body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            body.extend_from_slice(packet);
            body
        };
        let eth = ethernet(&ipv4_udp(), 0x0800);
        let cooked = sll2(0x0800, &ipv4_udp());
        let bytes = [
            block(0x0a0d0d0a, &shb),
            block(1, &idb(LINKTYPE_ETHERNET as u16)),
            block(1, &idb(LINKTYPE_LINUX_SLL2 as u16)),
            block(6, &epb(0, &eth)),
            block(6, &epb(1, &cooked)),
        ]
        .concat();
        let capture = read_capture_bytes(&bytes, "mixed.pcapng", "sha256:abc").unwrap();
        assert_eq!(capture.packets.len(), 2);
        assert_eq!(capture.packets[0].metadata.link_type, LINKTYPE_ETHERNET);
        assert_eq!(capture.packets[1].metadata.link_type, LINKTYPE_LINUX_SLL2);
        assert!(capture.packets[0].metadata.sll2.is_none());
        assert_eq!(
            capture.packets[1]
                .metadata
                .sll2
                .as_ref()
                .unwrap()
                .interface_index,
            42
        );
        assert_eq!(
            transport_view(&capture.packets[0]).unwrap().source_port,
            Some(8805)
        );
        assert_eq!(
            transport_view(&capture.packets[1]).unwrap().source_port,
            Some(8805)
        );
    }
    #[test]
    fn short_sll2_inputs_never_panic() {
        for length in 0..20 {
            let packet = CapturePacket {
                metadata: PacketMetadata {
                    capture_id: "sha256:abc".into(),
                    source_file: "fuzz".into(),
                    packet_number: 1,
                    byte_offset: 0,
                    timestamp: ExactTimestamp {
                        seconds: 0,
                        nanoseconds: 0,
                        raw_ticks: 0,
                        resolution_base: 10,
                        resolution_exponent: 6,
                    },
                    captured_length: length,
                    original_length: length,
                    interface_id: 0,
                    link_type: LINKTYPE_LINUX_SLL2,
                    sll2: None,
                    truncated: false,
                },
                data: vec![0; length as usize],
            };
            assert_eq!(
                transport_view(&packet).unwrap_err().kind,
                CaptureErrorKind::Truncated
            );
        }
    }
}
