//! Immutable packet envelopes and provenance shared by capture front ends.

use std::{ops::Deref, sync::Arc};

/// Uniquely owned on live/generated paths; shared only for immutable replay fixtures.
#[derive(Clone, Debug)]
pub enum PacketBuffer {
    Owned(Box<[u8]>),
    Shared(Arc<[u8]>),
}

impl PacketBuffer {
    pub fn owned(bytes: Vec<u8>) -> Self {
        Self::Owned(bytes.into_boxed_slice())
    }

    pub fn shared(bytes: Arc<[u8]>) -> Self {
        Self::Shared(bytes)
    }
}

impl Deref for PacketBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Shared(bytes) => bytes,
        }
    }
}

impl AsRef<[u8]> for PacketBuffer {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketProvenance {
    pub capture_id: Arc<str>,
    pub packet_number: u64,
    pub timestamp_ns: u64,
    pub captured_len: u32,
    pub original_len: u32,
    pub ingress_interface: u16,
}

#[derive(Clone, Debug)]
pub struct PacketRecord {
    pub provenance: PacketProvenance,
    pub bytes: PacketBuffer,
    /// Optional expected FNV-1a fingerprint used by synthetic integrity tests.
    pub expected_fingerprint: Option<u64>,
}

impl PacketRecord {
    pub fn new(provenance: PacketProvenance, bytes: Arc<[u8]>) -> Self {
        Self {
            provenance,
            bytes: PacketBuffer::shared(bytes),
            expected_fingerprint: None,
        }
    }

    pub fn from_owned(provenance: PacketProvenance, bytes: Vec<u8>) -> Self {
        Self {
            provenance,
            bytes: PacketBuffer::owned(bytes),
            expected_fingerprint: None,
        }
    }

    pub fn with_integrity_tag(mut self) -> Self {
        self.expected_fingerprint = Some(fingerprint(self.bytes.as_ref()));
        self
    }

    pub fn with_expected_fingerprint(mut self, expected: u64) -> Self {
        self.expected_fingerprint = Some(expected);
        self
    }

    pub fn verify_integrity(&self) -> bool {
        self.expected_fingerprint
            .map(|expected| expected == fingerprint(self.bytes.as_ref()))
            .unwrap_or(true)
    }
}

#[derive(Clone, Debug, Default)]
pub struct PacketBatch {
    packets: Vec<PacketRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceKind {
    Synthetic,
    Pcap,
    AfXdp,
    Dpdk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceCapabilities {
    pub queue_count: usize,
    pub zero_copy: bool,
    pub live: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    InvalidQueue,
    MalformedInput,
    TemporarilyUnavailable,
    EndOfInput,
}

/// Production-oriented ingress boundary. Future PCAP, AF_XDP, and DPDK adapters
/// provide batches per source queue without changing worker processing.
pub trait PacketBatchSource {
    fn kind(&self) -> SourceKind;
    fn capabilities(&self) -> SourceCapabilities;
    fn poll_batch(
        &mut self,
        queue_id: usize,
        max_packets: usize,
    ) -> Result<Option<PacketBatch>, SourceError>;
}

/// Immutable packet bytes generated before a processing-only timed section.
#[derive(Clone, Debug)]
pub struct PreloadedPacket {
    pub bytes: Arc<[u8]>,
    pub expected_fingerprint: u64,
    pub captured_len: u32,
    pub original_len: u32,
    pub template_ordinal: u64,
}

impl PreloadedPacket {
    pub fn new(bytes: Arc<[u8]>, original_len: u32, template_ordinal: u64) -> Self {
        let captured_len = bytes.len() as u32;
        let expected_fingerprint = fingerprint(&bytes);
        Self {
            bytes,
            expected_fingerprint,
            captured_len,
            original_len,
            template_ordinal,
        }
    }

    pub fn verify_integrity(&self) -> bool {
        self.expected_fingerprint == fingerprint(&self.bytes)
    }
}

#[derive(Clone, Debug)]
pub struct PreloadedBatch {
    pub flow_hash: u64,
    pub packets: Arc<[PreloadedPacket]>,
}

impl PreloadedBatch {
    pub fn packet_count(&self) -> usize {
        self.packets.len()
    }

    pub fn byte_count(&self) -> u64 {
        self.packets
            .iter()
            .map(|packet| packet.bytes.len() as u64)
            .sum()
    }
}

impl PacketBatch {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, packet: PacketRecord) {
        self.packets.push(packet);
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn packets(&self) -> &[PacketRecord] {
        &self.packets
    }

    pub fn into_packets(self) -> Vec<PacketRecord> {
        self.packets
    }
}

pub fn fingerprint(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_tag_detects_change() {
        let provenance = PacketProvenance {
            capture_id: Arc::from("test"),
            packet_number: 1,
            timestamp_ns: 2,
            captured_len: 3,
            original_len: 3,
            ingress_interface: 0,
        };
        let packet = PacketRecord::new(provenance, Arc::from([1_u8, 2, 3])).with_integrity_tag();
        assert!(packet.verify_integrity());
        assert_ne!(packet.expected_fingerprint, Some(fingerprint(&[1, 2, 4])));
    }

    #[test]
    fn preloaded_packet_integrity_and_lengths_are_stable() {
        let packet = PreloadedPacket::new(Arc::from([1_u8, 2, 3, 4]), 4, 7);
        assert!(packet.verify_integrity());
        assert_eq!(packet.captured_len, 4);
        assert_eq!(packet.original_len, 4);
        assert_eq!(packet.template_ordinal, 7);
    }
}
