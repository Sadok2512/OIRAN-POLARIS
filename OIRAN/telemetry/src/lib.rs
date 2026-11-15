//! Cache-line-aligned per-worker counters for the packet fast path.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CounterSnapshot {
    pub packets: u64,
    pub bytes: u64,
    pub gtpu_packets: u64,
    pub malformed: u64,
    pub integrity_errors: u64,
    pub length_errors: u64,
    pub dropped: u64,
    pub backpressure_events: u64,
    pub queue_occupancy: usize,
    pub queue_high_watermark: usize,
    pub work_accumulator: u64,
    pub packet_number_sum: u64,
    pub packet_number_xor: u64,
}

#[repr(align(64))]
pub struct WorkerCounters {
    packets: AtomicU64,
    bytes: AtomicU64,
    gtpu_packets: AtomicU64,
    malformed: AtomicU64,
    integrity_errors: AtomicU64,
    length_errors: AtomicU64,
    dropped: AtomicU64,
    backpressure_events: AtomicU64,
    queue_occupancy: AtomicUsize,
    queue_high_watermark: AtomicUsize,
    work_accumulator: AtomicU64,
    packet_number_sum: AtomicU64,
    packet_number_xor: AtomicU64,
}

impl Default for WorkerCounters {
    fn default() -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            gtpu_packets: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            integrity_errors: AtomicU64::new(0),
            length_errors: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            backpressure_events: AtomicU64::new(0),
            queue_occupancy: AtomicUsize::new(0),
            queue_high_watermark: AtomicUsize::new(0),
            work_accumulator: AtomicU64::new(0),
            packet_number_sum: AtomicU64::new(0),
            packet_number_xor: AtomicU64::new(0),
        }
    }
}

impl WorkerCounters {
    pub fn record_packet(&self, bytes: usize, gtpu: bool, malformed: bool, integrity_error: bool) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        if gtpu {
            self.gtpu_packets.fetch_add(1, Ordering::Relaxed);
        }
        if malformed {
            self.malformed.fetch_add(1, Ordering::Relaxed);
        }
        if integrity_error {
            self.integrity_errors.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Commit worker-local values once per batch, reducing fast-path atomic traffic.
    pub fn record_batch(
        &self,
        packets: u64,
        bytes: u64,
        gtpu_packets: u64,
        malformed: u64,
        integrity_errors: u64,
        length_errors: u64,
        ordered_work_accumulator: u64,
        packet_number_sum: u64,
        packet_number_xor: u64,
    ) {
        self.packets.fetch_add(packets, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.gtpu_packets.fetch_add(gtpu_packets, Ordering::Relaxed);
        self.malformed.fetch_add(malformed, Ordering::Relaxed);
        self.integrity_errors
            .fetch_add(integrity_errors, Ordering::Relaxed);
        self.length_errors
            .fetch_add(length_errors, Ordering::Relaxed);
        self.work_accumulator
            .store(ordered_work_accumulator, Ordering::Relaxed);
        self.packet_number_sum
            .fetch_add(packet_number_sum, Ordering::Relaxed);
        self.packet_number_xor
            .fetch_xor(packet_number_xor, Ordering::Relaxed);
    }

    pub fn work_accumulator(&self) -> u64 {
        self.work_accumulator.load(Ordering::Relaxed)
    }

    /// 2.18.3 (ANR1 #10 6898944250) — CAS saturant à `usize::MAX` au
    /// lieu de `fetch_add(1) + 1`. L'ancienne version pouvait
    /// déborder si un `dequeue()` survenait avant tout `enqueue()`
    /// (cas worker-runtime observé par intermittence sur les tests
    /// `four_worker_accounting_has_no_silent_loss` et
    /// `queue_saturation_is_bounded_and_accounted`) : le compteur
    /// passait de 0 à `usize::MAX` via le `fetch_sub(1)` de
    /// `dequeue`, et le prochain `fetch_add(1) + 1` paniquait avec
    /// « attempt to add with overflow » en debug. Le CAS garantit
    /// que la valeur reste ≤ `usize::MAX` sans wrap.
    pub fn enqueue(&self) {
        let now = loop {
            let current = self.queue_occupancy.load(Ordering::Relaxed);
            let next = current.saturating_add(1);
            if next == current {
                // Déjà saturé — cas pathologique, on n'incrémente
                // plus et on ne touche pas au high watermark.
                return;
            }
            match self.queue_occupancy.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break next,
                Err(_) => continue,
            }
        };
        let mut high = self.queue_high_watermark.load(Ordering::Relaxed);
        while now > high {
            match self.queue_high_watermark.compare_exchange_weak(
                high,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => high = observed,
            }
        }
    }

    /// 2.18.3 — CAS saturant à 0. L'ancienne version `fetch_sub(1)`
    /// pouvait sous-déborder quand un `dequeue()` survenait avant
    /// `enqueue()` (ordonnancement non-strict dans worker-runtime).
    /// Le compteur sous-débordait alors à `usize::MAX`, et
    /// l'`enqueue()` suivant paniquait sur `fetch_add(1) + 1`. Le
    /// CAS empêche le passage sous 0.
    pub fn dequeue(&self) {
        let mut current = self.queue_occupancy.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                // Rien à décrémenter — invariant anti-underflow.
                return;
            }
            match self.queue_occupancy.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }
    pub fn drop_packets(&self, count: u64) {
        self.dropped.fetch_add(count, Ordering::Relaxed);
    }
    pub fn backpressure(&self) {
        self.backpressure_events.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            packets: self.packets.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            gtpu_packets: self.gtpu_packets.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            integrity_errors: self.integrity_errors.load(Ordering::Relaxed),
            length_errors: self.length_errors.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            backpressure_events: self.backpressure_events.load(Ordering::Relaxed),
            queue_occupancy: self.queue_occupancy.load(Ordering::Relaxed),
            queue_high_watermark: self.queue_high_watermark.load(Ordering::Relaxed),
            work_accumulator: self.work_accumulator.load(Ordering::Relaxed),
            packet_number_sum: self.packet_number_sum.load(Ordering::Relaxed),
            packet_number_xor: self.packet_number_xor.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2.18.3 (ANR1 #10 6898944250) — invariant anti-underflow :
    /// `dequeue()` sur un compteur vide doit rester à 0, jamais
    /// sous-déborder à `usize::MAX`. L'ancienne version
    /// `fetch_sub(1)` paniquait au prochain `enqueue()`
    /// (« attempt to add with overflow ») en debug.
    #[test]
    fn dequeue_on_empty_queue_stays_at_zero_no_underflow() {
        let c = WorkerCounters::default();
        assert_eq!(c.snapshot().queue_occupancy, 0);
        c.dequeue();
        c.dequeue();
        c.dequeue();
        assert_eq!(
            c.snapshot().queue_occupancy,
            0,
            "dequeue sur queue vide doit rester à 0 (saturant)"
        );
        // Un enqueue ultérieur doit toujours fonctionner.
        c.enqueue();
        assert_eq!(c.snapshot().queue_occupancy, 1);
        assert_eq!(c.snapshot().queue_high_watermark, 1);
    }

    /// 2.18.3 — enqueue puis dequeue retombe à 0 proprement et met
    /// à jour le high watermark correctement.
    #[test]
    fn enqueue_dequeue_updates_occupancy_and_high_watermark() {
        let c = WorkerCounters::default();
        c.enqueue();
        c.enqueue();
        c.enqueue();
        assert_eq!(c.snapshot().queue_occupancy, 3);
        assert_eq!(c.snapshot().queue_high_watermark, 3);
        c.dequeue();
        c.dequeue();
        assert_eq!(c.snapshot().queue_occupancy, 1);
        // High watermark reste à 3 (c'est une valeur de pic).
        assert_eq!(c.snapshot().queue_high_watermark, 3);
    }

    /// 2.18.3 — alternance dequeue/enqueue sous concurrence réelle
    /// (worker-runtime) : aucun panic d'overflow. Reproduit la
    /// situation où `dequeue` peut précéder `enqueue` par
    /// ordonnancement entre threads.
    #[test]
    fn interleaved_dequeue_and_enqueue_never_panics() {
        use std::sync::Arc;
        use std::thread;
        let counters = Arc::new(WorkerCounters::default());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&counters);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.dequeue();
                    c.enqueue();
                }
            }));
        }
        for _ in 0..8 {
            let c = Arc::clone(&counters);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.enqueue();
                    c.dequeue();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Occupancy final doit être un nombre raisonnable
        // (ni panic ni valeur énorme > 16 workers × 1000).
        let occ = counters.snapshot().queue_occupancy;
        assert!(occ <= 16 * 1000, "occupancy sauté: {occ}");
    }
}

pub fn sum(snapshots: &[CounterSnapshot]) -> CounterSnapshot {
    snapshots
        .iter()
        .fold(CounterSnapshot::default(), |mut a, b| {
            a.packets += b.packets;
            a.bytes += b.bytes;
            a.gtpu_packets += b.gtpu_packets;
            a.malformed += b.malformed;
            a.integrity_errors += b.integrity_errors;
            a.length_errors += b.length_errors;
            a.dropped += b.dropped;
            a.backpressure_events += b.backpressure_events;
            a.queue_occupancy += b.queue_occupancy;
            a.queue_high_watermark += b.queue_high_watermark;
            a.work_accumulator ^= b.work_accumulator;
            a.packet_number_sum = a.packet_number_sum.wrapping_add(b.packet_number_sum);
            a.packet_number_xor ^= b.packet_number_xor;
            a
        })
}
