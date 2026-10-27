//! Bounded per-worker queues, flow-affine dispatch, deterministic replay and shutdown.

use capture_core::{fingerprint, PacketBatch, PacketRecord, PreloadedBatch};
use std::collections::BTreeSet;
use std::sync::{
    mpsc::{self, SyncSender, TrySendError},
    Arc,
};
use std::thread::{self, JoinHandle};
use telemetry::{CounterSnapshot, WorkerCounters};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub workers: usize,
    pub queue_capacity_batches: usize,
    pub pin_cpus: bool,
    /// Explicit worker CPU IDs. When set, this supersedes legacy `pin_cpus` mapping.
    pub worker_cpus: Option<Vec<usize>>,
    pub deterministic_replay: bool,
}

impl RuntimeConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.workers == 0 {
            return Err("worker count must be positive");
        }
        if self.workers > 256 {
            return Err("worker count exceeds safety limit");
        }
        if self.queue_capacity_batches == 0 {
            return Err("queue capacity must be positive");
        }
        if let Some(cpus) = &self.worker_cpus {
            if cpus.len() != self.workers {
                return Err("worker CPU list length must equal worker count");
            }
            if cpus.iter().copied().collect::<BTreeSet<_>>().len() != cpus.len() {
                return Err("worker CPU IDs must be unique");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AffinityRequest {
    Disabled,
    Automatic,
    Explicit {
        producer_cpu: usize,
        worker_cpus: Vec<usize>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAffinity {
    pub allowed_cpus: Vec<usize>,
    pub producer_cpu: Option<usize>,
    pub worker_cpus: Vec<Option<usize>>,
}

pub fn resolve_affinity(
    request: &AffinityRequest,
    workers: usize,
) -> Result<ResolvedAffinity, &'static str> {
    resolve_affinity_for_allowed(request, workers, &effective_cpu_affinity()?)
}

pub fn resolve_affinity_for_allowed(
    request: &AffinityRequest,
    workers: usize,
    allowed_cpus: &[usize],
) -> Result<ResolvedAffinity, &'static str> {
    if workers == 0 {
        return Err("worker count must be positive");
    }
    if allowed_cpus.is_empty() {
        return Err("effective CPU set is empty");
    }
    let allowed: BTreeSet<_> = allowed_cpus.iter().copied().collect();
    match request {
        AffinityRequest::Disabled => Ok(ResolvedAffinity {
            allowed_cpus: allowed_cpus.to_vec(),
            producer_cpu: None,
            worker_cpus: vec![None; workers],
        }),
        AffinityRequest::Automatic => {
            if allowed_cpus.len() < workers + 1 {
                return Err("automatic affinity requires one producer CPU plus all worker CPUs");
            }
            Ok(ResolvedAffinity {
                allowed_cpus: allowed_cpus.to_vec(),
                producer_cpu: Some(allowed_cpus[0]),
                worker_cpus: allowed_cpus[1..=workers]
                    .iter()
                    .copied()
                    .map(Some)
                    .collect(),
            })
        }
        AffinityRequest::Explicit {
            producer_cpu,
            worker_cpus,
        } => {
            if worker_cpus.len() != workers {
                return Err("explicit worker CPU count does not match worker count");
            }
            let mut requested = worker_cpus.iter().copied().collect::<BTreeSet<_>>();
            requested.insert(*producer_cpu);
            if requested.len() != workers + 1 {
                return Err("producer and worker CPU IDs must be distinct");
            }
            if !requested.iter().all(|cpu| allowed.contains(cpu)) {
                return Err("requested CPU is outside the effective cpuset");
            }
            Ok(ResolvedAffinity {
                allowed_cpus: allowed_cpus.to_vec(),
                producer_cpu: Some(*producer_cpu),
                worker_cpus: worker_cpus.iter().copied().map(Some).collect(),
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeReport {
    pub workers: Vec<CounterSnapshot>,
    pub affinity_failures: usize,
    pub worker_effective_cpus: Vec<Vec<usize>>,
}

#[derive(Debug)]
struct WorkerExit {
    affinity_ok: bool,
    effective_cpus: Vec<usize>,
}

pub struct WorkerRuntime {
    config: RuntimeConfig,
    senders: Vec<SyncSender<PacketBatch>>,
    handles: Vec<JoinHandle<WorkerExit>>,
    counters: Vec<Arc<WorkerCounters>>,
}

impl WorkerRuntime {
    pub fn start(config: RuntimeConfig) -> Result<Self, &'static str> {
        config.validate()?;
        let allowed = effective_cpu_affinity()?;
        let requested_cpus: Vec<Option<usize>> = if let Some(cpus) = &config.worker_cpus {
            if !cpus.iter().all(|cpu| allowed.contains(cpu)) {
                return Err("worker CPU is outside the effective cpuset");
            }
            cpus.iter().copied().map(Some).collect()
        } else if config.pin_cpus {
            let legacy: Vec<_> = (0..config.workers).collect();
            if !legacy.iter().all(|cpu| allowed.contains(cpu)) {
                return Err("legacy worker CPU is outside the effective cpuset");
            }
            legacy.into_iter().map(Some).collect()
        } else {
            vec![None; config.workers]
        };
        let mut senders = Vec::with_capacity(config.workers);
        let mut handles = Vec::with_capacity(config.workers);
        let mut counters = Vec::with_capacity(config.workers);
        if config.deterministic_replay {
            for _ in 0..config.workers {
                counters.push(Arc::new(WorkerCounters::default()));
            }
            return Ok(Self {
                config,
                senders,
                handles,
                counters,
            });
        }
        for worker_id in 0..config.workers {
            let (sender, receiver) =
                mpsc::sync_channel::<PacketBatch>(config.queue_capacity_batches);
            let counter = Arc::new(WorkerCounters::default());
            let worker_counter = Arc::clone(&counter);
            let requested_cpu = requested_cpus[worker_id];
            handles.push(
                thread::Builder::new()
                    .name(format!("oiran-worker-{worker_id}"))
                    .spawn(move || {
                        let affinity_ok = requested_cpu
                            .map(set_current_thread_affinity)
                            .unwrap_or(true);
                        let effective_cpus = effective_cpu_affinity().unwrap_or_default();
                        while let Ok(batch) = receiver.recv() {
                            worker_counter.dequeue();
                            process_batch(batch, &worker_counter);
                        }
                        WorkerExit {
                            affinity_ok,
                            effective_cpus,
                        }
                    })
                    .map_err(|_| "worker thread spawn failed")?,
            );
            senders.push(sender);
            counters.push(counter);
        }
        Ok(Self {
            config,
            senders,
            handles,
            counters,
        })
    }

    pub fn submit(&self, batch: PacketBatch, affinity_hash: u64) -> Result<(), &'static str> {
        if batch.is_empty() {
            return Ok(());
        }
        let worker = flow_dispatcher::worker_for_hash(affinity_hash, self.config.workers);
        if self.config.deterministic_replay {
            process_batch(batch, &self.counters[worker]);
            return Ok(());
        }
        let count = batch.len() as u64;
        self.counters[worker].enqueue();
        match self.senders[worker].try_send(batch) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.counters[worker].dequeue();
                self.counters[worker].backpressure();
                self.counters[worker].drop_packets(count);
                Err("queue full")
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters[worker].dequeue();
                self.counters[worker].drop_packets(count);
                Err("worker disconnected")
            }
        }
    }

    pub fn snapshots(&self) -> Vec<CounterSnapshot> {
        self.counters
            .iter()
            .map(|counter| counter.snapshot())
            .collect()
    }

    pub fn shutdown(mut self) -> RuntimeReport {
        self.senders.clear();
        let exits: Vec<_> = self
            .handles
            .drain(..)
            .map(|handle| {
                handle.join().unwrap_or(WorkerExit {
                    affinity_ok: false,
                    effective_cpus: Vec::new(),
                })
            })
            .collect();
        let affinity_failures = exits.iter().filter(|exit| !exit.affinity_ok).count();
        RuntimeReport {
            workers: self.snapshots(),
            affinity_failures,
            worker_effective_cpus: exits.into_iter().map(|exit| exit.effective_cpus).collect(),
        }
    }
}

fn process_batch(batch: PacketBatch, counter: &WorkerCounters) {
    let mut stats = CounterSnapshot {
        work_accumulator: counter.work_accumulator(),
        ..CounterSnapshot::default()
    };
    for packet in batch.into_packets() {
        account_packet(
            packet.bytes.as_ref(),
            packet.expected_fingerprint,
            packet.provenance.captured_len,
            packet.provenance.original_len,
            packet.provenance.packet_number,
            &mut stats,
        );
    }
    counter.record_batch(
        stats.packets,
        stats.bytes,
        stats.gtpu_packets,
        stats.malformed,
        stats.integrity_errors,
        stats.length_errors,
        stats.work_accumulator,
        stats.packet_number_sum,
        stats.packet_number_xor,
    );
}

/// Process immutable preloaded bytes using only worker-local counters. No queue,
/// allocation, or shared atomic is touched in the packet loop.
pub fn process_preloaded_batch(
    batch: &PreloadedBatch,
    next_logical_packet: &mut u64,
    stats: &mut CounterSnapshot,
) {
    process_preloaded_batch_strided(batch, next_logical_packet, 1, stats)
}

/// Strided logical numbering lets independent workers produce globally unique
/// provenance numbers without coordination.
pub fn process_preloaded_batch_strided(
    batch: &PreloadedBatch,
    next_logical_packet: &mut u64,
    logical_stride: u64,
    stats: &mut CounterSnapshot,
) {
    process_preloaded_batch_inner(batch, next_logical_packet, logical_stride, true, stats)
}

/// Processing-only benchmark path. Immutable buffers must be fingerprint-checked
/// before timing; the observable TEID accumulator prevents dead-code removal.
pub fn process_preloaded_fast_batch_strided(
    batch: &PreloadedBatch,
    next_logical_packet: &mut u64,
    logical_stride: u64,
    stats: &mut CounterSnapshot,
) {
    process_preloaded_batch_inner(batch, next_logical_packet, logical_stride, false, stats)
}

fn process_preloaded_batch_inner(
    batch: &PreloadedBatch,
    next_logical_packet: &mut u64,
    logical_stride: u64,
    verify_fingerprint: bool,
    stats: &mut CounterSnapshot,
) {
    debug_assert!(logical_stride > 0);
    for packet in batch.packets.iter() {
        let packet_number = *next_logical_packet;
        *next_logical_packet = next_logical_packet.wrapping_add(logical_stride);
        account_packet(
            &packet.bytes,
            verify_fingerprint.then_some(packet.expected_fingerprint),
            packet.captured_len,
            packet.original_len,
            packet_number,
            stats,
        );
    }
}

fn account_packet(
    bytes: &[u8],
    expected_fingerprint: Option<u64>,
    captured_len: u32,
    original_len: u32,
    packet_number: u64,
    stats: &mut CounterSnapshot,
) {
    stats.packets += 1;
    stats.bytes += bytes.len() as u64;
    stats.packet_number_sum = stats.packet_number_sum.wrapping_add(packet_number);
    stats.packet_number_xor ^= packet_number;
    if captured_len as usize != bytes.len() || original_len < captured_len {
        stats.length_errors += 1;
    }
    if expected_fingerprint
        .map(|expected| expected != fingerprint(bytes))
        .unwrap_or(false)
    {
        stats.integrity_errors += 1;
    }
    match packet_classifier::classify(bytes) {
        Ok(parsed) => {
            if let Some(gtpu) = parsed.gtpu {
                stats.gtpu_packets += 1;
                stats.work_accumulator = stats.work_accumulator.rotate_left(5)
                    ^ u64::from(gtpu.teid)
                    ^ packet_number.wrapping_mul(0x9e3779b97f4a7c15);
            }
        }
        Err(_) => stats.malformed += 1,
    }
}

pub fn deterministic_replay(
    mut packets: Vec<PacketRecord>,
    workers: usize,
) -> Result<RuntimeReport, &'static str> {
    packets.sort_by_key(|packet| {
        (
            packet.provenance.timestamp_ns,
            packet.provenance.packet_number,
        )
    });
    let runtime = WorkerRuntime::start(RuntimeConfig {
        workers,
        queue_capacity_batches: 1,
        pin_cpus: false,
        worker_cpus: None,
        deterministic_replay: true,
    })?;
    for packet in packets {
        let hash = packet_classifier::classify(packet.bytes.as_ref())
            .map(|classified| flow_dispatcher::affinity_hash(&classified))
            .unwrap_or(packet.provenance.packet_number);
        let mut batch = PacketBatch::with_capacity(1);
        batch.push(packet);
        runtime.submit(batch, hash)?;
    }
    Ok(runtime.shutdown())
}

#[cfg(target_os = "linux")]
const CPU_MASK_WORDS: usize = 16;

#[cfg(target_os = "linux")]
type CpuMask = [u64; CPU_MASK_WORDS];

#[cfg(target_os = "linux")]
extern "C" {
    fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u64) -> i32;
    fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u64) -> i32;
}

#[cfg(target_os = "linux")]
pub fn effective_cpu_affinity() -> Result<Vec<usize>, &'static str> {
    let mut mask: CpuMask = [0; CPU_MASK_WORDS];
    let result = unsafe { sched_getaffinity(0, std::mem::size_of_val(&mask), mask.as_mut_ptr()) };
    if result != 0 {
        return Err("sched_getaffinity failed");
    }
    Ok((0..CPU_MASK_WORDS * 64)
        .filter(|cpu| mask[cpu / 64] & (1_u64 << (cpu % 64)) != 0)
        .collect())
}

#[cfg(not(target_os = "linux"))]
pub fn effective_cpu_affinity() -> Result<Vec<usize>, &'static str> {
    let count = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    Ok((0..count).collect())
}

#[cfg(target_os = "linux")]
pub fn set_current_thread_affinity(cpu: usize) -> bool {
    const WORDS: usize = 16;
    if cpu >= WORDS * 64 {
        return false;
    }
    let mut mask = [0_u64; WORDS];
    mask[cpu / 64] |= 1_u64 << (cpu % 64);
    unsafe { sched_setaffinity(0, std::mem::size_of_val(&mask), mask.as_ptr()) == 0 }
}

#[cfg(not(target_os = "linux"))]
pub fn set_current_thread_affinity(_cpu: usize) -> bool {
    false
}

pub struct AffinityGuard {
    #[cfg(target_os = "linux")]
    original: CpuMask,
}

impl AffinityGuard {
    pub fn pin(cpu: usize) -> Result<Self, &'static str> {
        #[cfg(target_os = "linux")]
        {
            let mut original: CpuMask = [0; CPU_MASK_WORDS];
            let result = unsafe {
                sched_getaffinity(0, std::mem::size_of_val(&original), original.as_mut_ptr())
            };
            if result != 0 {
                return Err("unable to read producer affinity");
            }
            if !set_current_thread_affinity(cpu) {
                return Err("unable to set producer affinity");
            }
            Ok(Self { original })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cpu;
            Err("CPU affinity is unsupported on this platform")
        }
    }
}

impl Drop for AffinityGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe {
            let _ = sched_setaffinity(
                0,
                std::mem::size_of_val(&self.original),
                self.original.as_ptr(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use capture_core::PacketProvenance;

    fn packet(number: u64, size: usize) -> PacketRecord {
        PacketRecord::new(
            PacketProvenance {
                capture_id: Arc::from("test"),
                packet_number: number,
                timestamp_ns: number,
                captured_len: size as u32,
                original_len: size as u32,
                ingress_interface: 0,
            },
            Arc::from(vec![0_u8; size]),
        )
        .with_integrity_tag()
    }

    fn gtpu_packet(number: u64) -> PacketRecord {
        let size = 64_usize;
        let mut frame = vec![0_u8; size];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((size - 14) as u16).to_be_bytes());
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[10, 0, 0, 1]);
        frame[30..34].copy_from_slice(&[10, 0, 0, 2]);
        frame[34..36].copy_from_slice(&2152_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&2152_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&((size - 34) as u16).to_be_bytes());
        frame[42] = 0x30;
        frame[43] = 0xff;
        frame[44..46].copy_from_slice(&((size - 50) as u16).to_be_bytes());
        frame[46..50].copy_from_slice(&7_u32.to_be_bytes());
        PacketRecord::from_owned(
            PacketProvenance {
                capture_id: Arc::from("ordered-flow"),
                packet_number: number,
                timestamp_ns: number,
                captured_len: size as u32,
                original_len: size as u32,
                ingress_interface: 0,
            },
            frame,
        )
        .with_integrity_tag()
    }

    #[test]
    fn deterministic_replay_is_stable() {
        let input = vec![packet(3, 64), packet(1, 64), packet(2, 64)];
        let a = deterministic_replay(input.clone(), 2).unwrap();
        let b = deterministic_replay(input, 2).unwrap();
        assert_eq!(a.workers, b.workers);
        assert_eq!(telemetry::sum(&a.workers).packets, 3);
    }

    #[test]
    fn graceful_shutdown_drains_accepted_batches() {
        let runtime = WorkerRuntime::start(RuntimeConfig {
            workers: 2,
            queue_capacity_batches: 8,
            pin_cpus: false,
            worker_cpus: None,
            deterministic_replay: false,
        })
        .unwrap();
        let mut accepted = 0;
        for n in 0..8 {
            let mut batch = PacketBatch::with_capacity(1);
            batch.push(packet(n, 64));
            if runtime.submit(batch, n).is_ok() {
                accepted += 1;
            }
        }
        let report = runtime.shutdown();
        assert_eq!(telemetry::sum(&report.workers).packets, accepted);
    }

    #[test]
    fn queue_saturation_is_bounded_and_accounted() {
        let runtime = WorkerRuntime::start(RuntimeConfig {
            workers: 1,
            queue_capacity_batches: 1,
            pin_cpus: false,
            worker_cpus: None,
            deterministic_replay: false,
        })
        .unwrap();
        let mut large = PacketBatch::with_capacity(100_000);
        for n in 0..100_000 {
            large.push(packet(n, 64));
        }
        let _ = runtime.submit(large, 0);
        let mut rejected = 0;
        for n in 0..32 {
            let mut batch = PacketBatch::with_capacity(1);
            batch.push(packet(n, 64));
            if runtime.submit(batch, 0).is_err() {
                rejected += 1;
            }
        }
        let report = runtime.shutdown();
        let total = telemetry::sum(&report.workers);
        assert!(rejected > 0);
        assert!(total.backpressure_events > 0);
        assert!(total.dropped > 0);
        // The counter includes the one batch handed to the worker plus channel capacity.
        assert!(total.queue_high_watermark <= 2);
    }

    #[test]
    fn four_worker_accounting_has_no_silent_loss() {
        let runtime = WorkerRuntime::start(RuntimeConfig {
            workers: 4,
            queue_capacity_batches: 1024,
            pin_cpus: false,
            worker_cpus: None,
            deterministic_replay: false,
        })
        .unwrap();
        let mut generated = 0_u64;
        for batch_number in 0..100_u64 {
            let mut batch = PacketBatch::with_capacity(10);
            for _ in 0..10 {
                generated += 1;
                batch.push(packet(generated, 64));
            }
            runtime.submit(batch, batch_number).unwrap();
        }
        let total = telemetry::sum(&runtime.shutdown().workers);
        assert_eq!(generated, total.packets + total.dropped);
        assert_eq!(total.packets, 1_000);
        assert_eq!(total.bytes, 64_000);
        assert_eq!(total.dropped, 0);
    }

    #[test]
    fn same_flow_preserves_submission_order() {
        let packets: Vec<_> = (1..=16).map(gtpu_packet).collect();
        let expected = deterministic_replay(packets.clone(), 1).unwrap();
        let runtime = WorkerRuntime::start(RuntimeConfig {
            workers: 1,
            queue_capacity_batches: 32,
            pin_cpus: false,
            worker_cpus: None,
            deterministic_replay: false,
        })
        .unwrap();
        for packet in packets {
            let mut batch = PacketBatch::with_capacity(1);
            batch.push(packet);
            runtime.submit(batch, 7).unwrap();
        }
        let actual = runtime.shutdown();
        assert_eq!(
            actual.workers[0].work_accumulator,
            expected.workers[0].work_accumulator
        );
    }

    #[test]
    fn provenance_length_mismatch_is_explicit() {
        let mut packet = gtpu_packet(1);
        packet.provenance.captured_len -= 1;
        let report = deterministic_replay(vec![packet], 1).unwrap();
        assert_eq!(report.workers[0].length_errors, 1);
    }

    #[test]
    fn affinity_plan_separates_producer_and_workers() {
        let automatic =
            resolve_affinity_for_allowed(&AffinityRequest::Automatic, 2, &[3, 5, 7, 9]).unwrap();
        assert_eq!(automatic.producer_cpu, Some(3));
        assert_eq!(automatic.worker_cpus, vec![Some(5), Some(7)]);

        let explicit = resolve_affinity_for_allowed(
            &AffinityRequest::Explicit {
                producer_cpu: 9,
                worker_cpus: vec![3, 7],
            },
            2,
            &[3, 5, 7, 9],
        )
        .unwrap();
        assert_eq!(explicit.producer_cpu, Some(9));
        assert!(resolve_affinity_for_allowed(
            &AffinityRequest::Explicit {
                producer_cpu: 3,
                worker_cpus: vec![3, 7],
            },
            2,
            &[3, 5, 7, 9],
        )
        .is_err());
        assert!(resolve_affinity_for_allowed(
            &AffinityRequest::Explicit {
                producer_cpu: 1,
                worker_cpus: vec![3, 7],
            },
            2,
            &[3, 5, 7, 9],
        )
        .is_err());
    }

    #[test]
    fn preloaded_processing_has_exact_accounting() {
        use capture_core::{PreloadedBatch, PreloadedPacket};
        let frames: Vec<_> = (1..=4)
            .map(|number| {
                let packet = gtpu_packet(number);
                PreloadedPacket::new(
                    Arc::from(packet.bytes.as_ref()),
                    packet.provenance.original_len,
                    number,
                )
            })
            .collect();
        let batch = PreloadedBatch {
            flow_hash: 7,
            packets: frames.into(),
        };
        let mut logical = 1;
        let mut stats = CounterSnapshot::default();
        process_preloaded_batch(&batch, &mut logical, &mut stats);
        assert_eq!(logical, 5);
        assert_eq!(stats.packets, 4);
        assert_eq!(stats.gtpu_packets, 4);
        assert_eq!(stats.bytes, 256);
        assert_eq!(stats.integrity_errors, 0);
        assert_eq!(stats.malformed, 0);
    }
}
