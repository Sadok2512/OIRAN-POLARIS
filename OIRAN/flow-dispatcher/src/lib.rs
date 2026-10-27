//! Stable software flow affinity. Hardware RSS is treated only as an input hint.

use packet_classifier::{ClassifiedPacket, IpAddress};

pub fn stable_hash(bytes: &[u8]) -> u64 {
    hash_update(0xcbf29ce484222325_u64, bytes)
}

fn hash_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub fn worker_for_hash(hash: u64, workers: usize) -> usize {
    assert!(workers > 0, "at least one worker is required");
    (hash as usize) % workers
}

pub fn affinity_hash(packet: &ClassifiedPacket) -> u64 {
    // Canonicalize endpoints so both directions remain on the same worker.
    let source = (packet.udp.source, packet.udp.source_port);
    let destination = (packet.udp.destination, packet.udp.destination_port);
    let (left, right) = if source <= destination {
        (source, destination)
    } else {
        (destination, source)
    };
    let mut hash = hash_endpoint(0xcbf29ce484222325_u64, left.0, left.1);
    hash = hash_endpoint(hash, right.0, right.1);
    if let Some(gtpu) = packet.gtpu {
        hash = hash_update(hash, &gtpu.teid.to_be_bytes());
    }
    hash
}

/// Hash an explicit cross-interface correlation key supplied by a control-plane mapper.
/// This is the mechanism for N2/N3/N4 affinity; RSS/five-tuples alone are insufficient.
pub fn correlation_affinity(key_type: u8, canonical_key: &[u8]) -> u64 {
    hash_update(
        hash_update(0xcbf29ce484222325_u64, &[key_type]),
        canonical_key,
    )
}

fn hash_endpoint(mut hash: u64, ip: IpAddress, port: u16) -> u64 {
    match ip {
        IpAddress::V4(v) => {
            hash = hash_update(hash, &[4]);
            hash = hash_update(hash, &v);
        }
        IpAddress::V6(v) => {
            hash = hash_update(hash, &[6]);
            hash = hash_update(hash, &v);
        }
    }
    hash_update(hash, &port.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_classifier::{GtpuHeader, UdpFlow};

    #[test]
    fn reverse_direction_has_same_affinity() {
        let a = IpAddress::V4([10, 0, 0, 1]);
        let b = IpAddress::V4([10, 0, 0, 2]);
        let p1 = ClassifiedPacket {
            udp: UdpFlow {
                source: a,
                destination: b,
                source_port: 1,
                destination_port: 2,
            },
            gtpu: Some(GtpuHeader {
                message_type: 255,
                teid: 7,
                payload_offset: 8,
                payload_length: 0,
            }),
        };
        let p2 = ClassifiedPacket {
            udp: UdpFlow {
                source: b,
                destination: a,
                source_port: 2,
                destination_port: 1,
            },
            gtpu: p1.gtpu,
        };
        assert_eq!(affinity_hash(&p1), affinity_hash(&p2));
    }

    #[test]
    fn explicit_session_key_is_deterministic() {
        assert_eq!(
            correlation_affinity(1, b"session-a"),
            correlation_affinity(1, b"session-a")
        );
        assert_ne!(
            correlation_affinity(1, b"session-a"),
            correlation_affinity(2, b"session-a")
        );
    }
}
