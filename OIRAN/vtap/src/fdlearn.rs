//! 2.21.6 — apprentissage du fd « à la demande » (essai 4 ANR2 : les 8
//! tracepoints syscalls attachés en permanence coûtaient +2,9 points de PSI
//! system.slice, même sans TLS). Les records dont le fd est inconnu sont mis
//! en attente par (tgid, SSL*) ; dès qu'un record de la même clé arrive avec
//! un fd appris par l'eBPF, l'attente est vidée dans l'ordre d'arrivée.
//! Le chargeur n'attache les tracepoints que tant que `needs_tracepoints()`.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use crate::record::TlsRecord;

/// Durée max d'attente d'un record sans fd avant d'être compté `fd_unknown`.
pub const PENDING_MAX_AGE: Duration = Duration::from_secs(10);
/// Mémoire max des records en attente (au-delà : les plus anciens sortent
/// comme `fd_unknown`, jamais en silence).
pub const PENDING_MAX_BYTES: usize = 64 * 1024 * 1024;

#[derive(Default)]
pub struct FdLearner {
    pending: HashMap<(u32, u64), Vec<(Instant, u64, TlsRecord)>>,
    order: BTreeMap<u64, (u32, u64)>,
    seq: u64,
    bytes: usize,
}

impl FdLearner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingère un record. Renvoie les records prêts (fd connu), dans l'ordre.
    pub fn on_record(&mut self, mut record: TlsRecord, now: Instant) -> Vec<TlsRecord> {
        let key = (record.tgid, record.ssl);
        if record.fd < 0 {
            self.seq += 1;
            self.bytes += record.data.len();
            self.order.insert(self.seq, key);
            self.pending.entry(key).or_default().push((now, self.seq, record));
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(waiting) = self.pending.remove(&key) {
            for (_, seq, mut r) in waiting {
                self.order.remove(&seq);
                self.bytes = self.bytes.saturating_sub(r.data.len());
                r.fd = record.fd;
                r.flags &= !crate::record::FLAG_FD_UNKNOWN;
                out.push(r);
            }
        }
        record.flags &= !crate::record::FLAG_FD_UNKNOWN;
        out.push(record);
        out
    }

    /// Records expirés (âge > `max_age`) ou en dépassement mémoire : rendus
    /// avec fd = -1 pour être comptés `fd_unknown` par l'appelant.
    pub fn expire(&mut self, now: Instant, max_age: Duration, max_bytes: usize) -> Vec<TlsRecord> {
        let mut out = Vec::new();
        while let Some((&seq, &key)) = self.order.iter().next() {
            let Some(list) = self.pending.get_mut(&key) else {
                self.order.remove(&seq);
                continue;
            };
            let Some(pos) = list.iter().position(|(_, s, _)| *s == seq) else {
                self.order.remove(&seq);
                continue;
            };
            let too_old = now.duration_since(list[pos].0) > max_age;
            if !too_old && self.bytes <= max_bytes {
                break;
            }
            let (_, _, r) = list.remove(pos);
            if list.is_empty() {
                self.pending.remove(&key);
            }
            self.order.remove(&seq);
            self.bytes = self.bytes.saturating_sub(r.data.len());
            out.push(r);
        }
        out
    }

    pub fn needs_tracepoints(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn pending_records(&self) -> usize {
        self.order.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{SslOp, FLAG_FD_UNKNOWN};

    fn rec(ssl: u64, fd: i32, data: &[u8]) -> TlsRecord {
        TlsRecord {
            mono_ns: 1,
            tgid: 7,
            tid: 7,
            fd,
            op: SslOp::Write,
            flags: if fd < 0 { FLAG_FD_UNKNOWN } else { 0 },
            chunk_index: 0,
            total_len: data.len() as u32,
            ssl,
            comm: "open5gs-amfd".into(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn unknown_fd_records_wait_then_flush_in_order_with_learned_fd() {
        let mut l = FdLearner::new();
        let t = Instant::now();
        assert!(l.on_record(rec(1, -1, b"a"), t).is_empty());
        assert!(l.on_record(rec(1, -1, b"b"), t).is_empty());
        assert!(l.needs_tracepoints());
        let out = l.on_record(rec(1, 9, b"c"), t);
        assert_eq!(out.iter().map(|r| r.data[0]).collect::<Vec<_>>(), b"abc");
        assert!(out.iter().all(|r| r.fd == 9 && r.flags & FLAG_FD_UNKNOWN == 0));
        assert!(!l.needs_tracepoints());
    }

    #[test]
    fn other_ssl_objects_are_not_flushed_by_a_different_key() {
        let mut l = FdLearner::new();
        let t = Instant::now();
        l.on_record(rec(1, -1, b"a"), t);
        let out = l.on_record(rec(2, 5, b"z"), t);
        assert_eq!(out.len(), 1);
        assert_eq!(l.pending_records(), 1);
    }

    #[test]
    fn expiry_returns_old_records_as_fd_unknown_never_silently() {
        let mut l = FdLearner::new();
        let t0 = Instant::now();
        l.on_record(rec(1, -1, b"a"), t0);
        assert!(l.expire(t0, PENDING_MAX_AGE, PENDING_MAX_BYTES).is_empty());
        let later = t0 + PENDING_MAX_AGE + Duration::from_secs(1);
        let gone = l.expire(later, PENDING_MAX_AGE, PENDING_MAX_BYTES);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].fd, -1);
        assert!(!l.needs_tracepoints());
    }

    #[test]
    fn memory_cap_evicts_oldest_first() {
        let mut l = FdLearner::new();
        let t = Instant::now();
        l.on_record(rec(1, -1, &[0u8; 10]), t);
        l.on_record(rec(2, -1, &[1u8; 10]), t);
        let gone = l.expire(t, PENDING_MAX_AGE, 10);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].ssl, 1);
    }
}
