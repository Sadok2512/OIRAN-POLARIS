//! Record TLS en clair remonté par l'eBPF (ringbuf) — layout binaire
//! partagé avec `bpf/vtap.bpf.c` (`struct vtap_event`).

use serde::{Deserialize, Serialize};

/// Taille max d'un chunk de données par event ringbuf (= `VTAP_CHUNK` C).
pub const CHUNK: usize = 16384;
/// Nombre max de chunks par appel SSL_* (= `VTAP_MAX_CHUNKS` C).
pub const MAX_CHUNKS: usize = 8;
/// Taille de l'en-tête fixe avant `data` (= `offsetof(struct vtap_event, data)`).
pub const HEADER_LEN: usize = 56;

pub const FLAG_TRUNCATED: u8 = 0x01;
pub const FLAG_FD_UNKNOWN: u8 = 0x02;

/// Sens du flux vu depuis le processus instrumenté.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SslOp {
    /// `SSL_write`/`SSL_write_ex` : octets local → distant.
    Write,
    /// `SSL_read`/`SSL_read_ex` : octets distant → local.
    Read,
}

impl SslOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "ssl_write",
            Self::Read => "ssl_read",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsRecord {
    /// Horodatage monotonic noyau (`bpf_ktime_get_ns`).
    pub mono_ns: u64,
    pub tgid: u32,
    pub tid: u32,
    /// fd du socket (-1 si non attribué par l'eBPF).
    pub fd: i32,
    pub op: SslOp,
    pub flags: u8,
    pub chunk_index: u16,
    pub total_len: u32,
    pub ssl: u64,
    pub comm: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum RecordError {
    Short(usize),
    BadOp(u8),
    BadLen { data_len: u32, available: usize },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Short(n) => write!(f, "vtap event too short: {n} bytes"),
            Self::BadOp(op) => write!(f, "vtap event unknown op {op}"),
            Self::BadLen {
                data_len,
                available,
            } => write!(f, "vtap event data_len {data_len} > available {available}"),
        }
    }
}

impl TlsRecord {
    /// Décode un event ringbuf (little-endian, layout C).
    pub fn parse(raw: &[u8]) -> Result<Self, RecordError> {
        if raw.len() < HEADER_LEN {
            return Err(RecordError::Short(raw.len()));
        }
        let u32_at = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().expect("4"));
        let op = match raw[20] {
            0 => SslOp::Write,
            1 => SslOp::Read,
            other => return Err(RecordError::BadOp(other)),
        };
        let data_len = u32_at(28);
        let available = raw.len() - HEADER_LEN;
        if data_len as usize > available.min(CHUNK) {
            return Err(RecordError::BadLen {
                data_len,
                available,
            });
        }
        let comm_raw = &raw[40..56];
        let comm_end = comm_raw.iter().position(|b| *b == 0).unwrap_or(16);
        Ok(Self {
            mono_ns: u64::from_le_bytes(raw[0..8].try_into().expect("8")),
            tgid: u32_at(8),
            tid: u32_at(12),
            fd: u32_at(16) as i32,
            op,
            flags: raw[21],
            chunk_index: u16::from_le_bytes(raw[22..24].try_into().expect("2")),
            total_len: u32_at(24),
            ssl: u64::from_le_bytes(raw[32..40].try_into().expect("8")),
            comm: String::from_utf8_lossy(&comm_raw[..comm_end]).into_owned(),
            data: raw[HEADER_LEN..HEADER_LEN + data_len as usize].to_vec(),
        })
    }

    pub fn truncated(&self) -> bool {
        self.flags & FLAG_TRUNCATED != 0
    }

    /// Sérialise au layout C (tests + outils de rejeu).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; HEADER_LEN];
        out[0..8].copy_from_slice(&self.mono_ns.to_le_bytes());
        out[8..12].copy_from_slice(&self.tgid.to_le_bytes());
        out[12..16].copy_from_slice(&self.tid.to_le_bytes());
        out[16..20].copy_from_slice(&self.fd.to_le_bytes());
        out[20] = match self.op {
            SslOp::Write => 0,
            SslOp::Read => 1,
        };
        out[21] = self.flags;
        out[22..24].copy_from_slice(&self.chunk_index.to_le_bytes());
        out[24..28].copy_from_slice(&self.total_len.to_le_bytes());
        out[28..32].copy_from_slice(&(self.data.len() as u32).to_le_bytes());
        out[32..40].copy_from_slice(&self.ssl.to_le_bytes());
        let comm = self.comm.as_bytes();
        let n = comm.len().min(15);
        out[40..40 + n].copy_from_slice(&comm[..n]);
        out.extend_from_slice(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips_through_c_layout() {
        let record = TlsRecord {
            mono_ns: 123_456_789,
            tgid: 4242,
            tid: 4243,
            fd: 17,
            op: SslOp::Read,
            flags: FLAG_TRUNCATED,
            chunk_index: 2,
            total_len: 40_000,
            ssl: 0xdead_beef_0000_1000,
            comm: "open5gs-amfd".into(),
            data: b"hello".to_vec(),
        };
        let raw = record.encode();
        assert_eq!(raw.len(), HEADER_LEN + 5);
        let parsed = TlsRecord::parse(&raw).unwrap();
        assert_eq!(parsed, record);
        assert!(parsed.truncated());
    }

    #[test]
    fn short_or_inconsistent_events_are_rejected_not_skipped() {
        assert_eq!(TlsRecord::parse(&[0u8; 10]), Err(RecordError::Short(10)));
        let mut raw = vec![0u8; HEADER_LEN + 2];
        raw[28..32].copy_from_slice(&10u32.to_le_bytes());
        assert!(matches!(
            TlsRecord::parse(&raw),
            Err(RecordError::BadLen { .. })
        ));
        raw[20] = 9;
        assert_eq!(TlsRecord::parse(&raw), Err(RecordError::BadOp(9)));
    }
}
