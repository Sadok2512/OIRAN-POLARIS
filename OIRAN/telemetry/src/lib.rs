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

    pub fn enqueue(&self) {
        let now = self.queue_occupancy.fetch_add(1, Ordering::Relaxed) + 1;
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

    pub fn dequeue(&self) {
        self.queue_occupancy.fetch_sub(1, Ordering::Relaxed);
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
