//! Allocation-free Ethernet/IP/UDP classifier and strict GTP-U header parser.

pub const GTPU_PORT: u16 = 2152;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpFlow {
    pub source: IpAddress,
    pub destination: IpAddress,
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GtpuHeader {
    pub message_type: u8,
    pub teid: u32,
    pub payload_offset: usize,
    pub payload_length: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassifiedPacket {
    pub udp: UdpFlow,
    pub gtpu: Option<GtpuHeader>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    TruncatedEthernet,
    UnsupportedEtherType,
    TruncatedIp,
    InvalidIp,
    NotUdp,
    TruncatedUdp,
    InvalidUdpLength,
    MalformedGtpu,
}

fn u16be(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}
fn u32be(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub fn classify(frame: &[u8]) -> Result<ClassifiedPacket, ParseError> {
    if frame.len() < 14 {
        return Err(ParseError::TruncatedEthernet);
    }
    let mut offset = 14;
    let mut ether_type = u16be(&frame[12..14]);
    for _ in 0..2 {
        if ether_type == 0x8100 || ether_type == 0x88a8 {
            if frame.len() < offset + 4 {
                return Err(ParseError::TruncatedEthernet);
            }
            ether_type = u16be(&frame[offset + 2..offset + 4]);
            offset += 4;
        }
    }

    let (source, destination, udp_offset, ip_end) = match ether_type {
        0x0800 => parse_ipv4(frame, offset)?,
        0x86dd => parse_ipv6(frame, offset)?,
        _ => return Err(ParseError::UnsupportedEtherType),
    };
    if udp_offset + 8 > ip_end {
        return Err(ParseError::TruncatedUdp);
    }
    let source_port = u16be(&frame[udp_offset..udp_offset + 2]);
    let destination_port = u16be(&frame[udp_offset + 2..udp_offset + 4]);
    let udp_length = usize::from(u16be(&frame[udp_offset + 4..udp_offset + 6]));
    if udp_length < 8 || udp_offset + udp_length > ip_end {
        return Err(ParseError::InvalidUdpLength);
    }
    let payload_offset = udp_offset + 8;
    let payload = &frame[payload_offset..udp_offset + udp_length];
    let gtpu = if source_port == GTPU_PORT || destination_port == GTPU_PORT {
        Some(parse_gtpu(payload, payload_offset)?)
    } else {
        None
    };
    Ok(ClassifiedPacket {
        udp: UdpFlow {
            source,
            destination,
            source_port,
            destination_port,
        },
        gtpu,
    })
}

fn parse_ipv4(
    frame: &[u8],
    offset: usize,
) -> Result<(IpAddress, IpAddress, usize, usize), ParseError> {
    if frame.len() < offset + 20 {
        return Err(ParseError::TruncatedIp);
    }
    if frame[offset] >> 4 != 4 {
        return Err(ParseError::InvalidIp);
    }
    let header_len = usize::from(frame[offset] & 0x0f) * 4;
    if header_len < 20 || frame.len() < offset + header_len {
        return Err(ParseError::InvalidIp);
    }
    let total_len = usize::from(u16be(&frame[offset + 2..offset + 4]));
    if total_len < header_len || frame.len() < offset + total_len {
        return Err(ParseError::TruncatedIp);
    }
    if frame[offset + 9] != 17 {
        return Err(ParseError::NotUdp);
    }
    let mut src = [0_u8; 4];
    src.copy_from_slice(&frame[offset + 12..offset + 16]);
    let mut dst = [0_u8; 4];
    dst.copy_from_slice(&frame[offset + 16..offset + 20]);
    Ok((
        IpAddress::V4(src),
        IpAddress::V4(dst),
        offset + header_len,
        offset + total_len,
    ))
}

fn parse_ipv6(
    frame: &[u8],
    offset: usize,
) -> Result<(IpAddress, IpAddress, usize, usize), ParseError> {
    if frame.len() < offset + 40 {
        return Err(ParseError::TruncatedIp);
    }
    if frame[offset] >> 4 != 6 {
        return Err(ParseError::InvalidIp);
    }
    let payload_len = usize::from(u16be(&frame[offset + 4..offset + 6]));
    let end = offset + 40 + payload_len;
    if frame.len() < end {
        return Err(ParseError::TruncatedIp);
    }
    // Extension-header traversal is intentionally deferred; non-direct UDP is explicit, not guessed.
    if frame[offset + 6] != 17 {
        return Err(ParseError::NotUdp);
    }
    let mut src = [0_u8; 16];
    src.copy_from_slice(&frame[offset + 8..offset + 24]);
    let mut dst = [0_u8; 16];
    dst.copy_from_slice(&frame[offset + 24..offset + 40]);
    Ok((IpAddress::V6(src), IpAddress::V6(dst), offset + 40, end))
}

fn parse_gtpu(payload: &[u8], absolute_offset: usize) -> Result<GtpuHeader, ParseError> {
    if payload.len() < 8 {
        return Err(ParseError::MalformedGtpu);
    }
    let flags = payload[0];
    if flags >> 5 != 1 || flags & 0x10 == 0 {
        return Err(ParseError::MalformedGtpu);
    }
    let declared = usize::from(u16be(&payload[2..4])) + 8;
    if declared > payload.len() || declared < 8 {
        return Err(ParseError::MalformedGtpu);
    }
    let mut header_len = 8;
    if flags & 0x07 != 0 {
        if declared < 12 {
            return Err(ParseError::MalformedGtpu);
        }
        header_len = 12;
        if flags & 0x04 != 0 {
            let mut next_type = payload[11];
            while next_type != 0 {
                if header_len >= declared {
                    return Err(ParseError::MalformedGtpu);
                }
                let units = usize::from(payload[header_len]);
                if units == 0 {
                    return Err(ParseError::MalformedGtpu);
                }
                let extension_len = units * 4;
                if header_len + extension_len > declared {
                    return Err(ParseError::MalformedGtpu);
                }
                next_type = payload[header_len + extension_len - 1];
                header_len += extension_len;
            }
        }
    }
    if header_len > declared {
        return Err(ParseError::MalformedGtpu);
    }
    Ok(GtpuHeader {
        message_type: payload[1],
        teid: u32be(&payload[4..8]),
        payload_offset: absolute_offset + header_len,
        payload_length: declared - header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gtpu_frame(size: usize) -> Vec<u8> {
        let size = size.max(50);
        let mut f = vec![0_u8; size];
        f[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        f[14] = 0x45;
        f[16..18].copy_from_slice(&((size - 14) as u16).to_be_bytes());
        f[23] = 17;
        f[26..30].copy_from_slice(&[10, 0, 0, 1]);
        f[30..34].copy_from_slice(&[10, 0, 0, 2]);
        f[34..36].copy_from_slice(&2152_u16.to_be_bytes());
        f[36..38].copy_from_slice(&2152_u16.to_be_bytes());
        f[38..40].copy_from_slice(&((size - 34) as u16).to_be_bytes());
        f[42] = 0x30;
        f[43] = 0xff;
        f[44..46].copy_from_slice(&((size - 50) as u16).to_be_bytes());
        f[46..50].copy_from_slice(&0x12345678_u32.to_be_bytes());
        f
    }

    #[test]
    fn parses_gtpu_without_allocation() {
        let parsed = classify(&gtpu_frame(128)).unwrap();
        let gtpu = parsed.gtpu.unwrap();
        assert_eq!(gtpu.teid, 0x12345678);
        assert_eq!(gtpu.message_type, 0xff);
        assert_eq!(gtpu.payload_length, 78);
    }

    #[test]
    fn rejects_truncated_and_bad_length() {
        assert_eq!(classify(&[0_u8; 4]), Err(ParseError::TruncatedEthernet));
        let mut frame = gtpu_frame(64);
        frame[44..46].copy_from_slice(&1000_u16.to_be_bytes());
        assert_eq!(classify(&frame), Err(ParseError::MalformedGtpu));
    }

    #[test]
    fn parses_vlan() {
        let base = gtpu_frame(64);
        let mut tagged = Vec::with_capacity(68);
        tagged.extend_from_slice(&base[..12]);
        tagged.extend_from_slice(&0x8100_u16.to_be_bytes());
        tagged.extend_from_slice(&1_u16.to_be_bytes());
        tagged.extend_from_slice(&base[12..]);
        let ipv4_length = (tagged.len() - 18) as u16;
        tagged[20..22].copy_from_slice(&ipv4_length.to_be_bytes());
        assert_eq!(classify(&tagged).unwrap().gtpu.unwrap().teid, 0x12345678);
    }
}
