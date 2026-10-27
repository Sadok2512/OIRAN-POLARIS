//! Safety-gated synthetic GTP-U benchmark modes.

use capture_core::{
    fingerprint, PacketBatch, PacketProvenance, PacketRecord, PreloadedBatch, PreloadedPacket,
};
use std::{
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, OnceLock,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use telemetry::{sum, CounterSnapshot};
use worker_runtime::{
    resolve_affinity, AffinityGuard, AffinityRequest, ResolvedAffinity, RuntimeConfig,
    WorkerRuntime,
};

pub const SUPPORTED_FRAME_SIZES: [usize; 4] = [64, 128, 512, 1500];
pub const MINIMUM_SAFETY_WINDOW_SECS: u64 = 900;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BenchmarkMode {
    GeneratorOnly,
    ProcessingOnly,
    FullPipeline,
}
impl BenchmarkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GeneratorOnly => "generator",
            Self::ProcessingOnly => "processing",
            Self::FullPipeline => "full",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BenchmarkConfig {
    pub mode: BenchmarkMode,
    pub workers: usize,
    pub duration: Duration,
    pub frame_size: usize,
    pub batch_size: usize,
    pub queue_capacity_batches: usize,
    pub flow_count: usize,
    pub affinity: AffinityRequest,
}
impl BenchmarkConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=4).contains(&self.workers) {
            return Err("workers must be in 1..=4 for S2.1".into());
        }
        if !SUPPORTED_FRAME_SIZES.contains(&self.frame_size) {
            return Err("frame size must be 64, 128, 512, or 1500".into());
        }
        if ![32, 64, 128, 256].contains(&self.batch_size) {
            return Err("batch size must be 32, 64, 128, or 256".into());
        }
        if !(1..=65536).contains(&self.queue_capacity_batches) {
            return Err("queue capacity must be in 1..=65536".into());
        }
        if !(1..=4096).contains(&self.flow_count) {
            return Err("flow count must be in 1..=4096".into());
        }
        if self.duration < Duration::from_millis(10) || self.duration > Duration::from_secs(10) {
            return Err("duration must be between 10 ms and 10 s".into());
        }
        resolve_affinity(&self.affinity, self.workers).map_err(str::to_string)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyGateReceipt {
    observed_seconds: u64,
    issued_epoch_seconds: u64,
    expires_epoch_seconds: u64,
}
impl SafetyGateReceipt {
    pub fn parse(text: &str, now: u64) -> Result<Self, String> {
        let value = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(&format!("{key}=")))
                .map(str::trim)
        };
        if value("STATUS") != Some("PASS") {
            return Err("resource safety receipt does not report PASS".into());
        }
        let parse = |key: &str| {
            value(key)
                .ok_or_else(|| format!("missing {key}"))?
                .parse::<u64>()
                .map_err(|_| format!("invalid {key}"))
        };
        let receipt = Self {
            observed_seconds: parse("OBSERVED_SECONDS")?,
            issued_epoch_seconds: parse("ISSUED_EPOCH_SECONDS")?,
            expires_epoch_seconds: parse("EXPIRES_EPOCH_SECONDS")?,
        };
        if receipt.observed_seconds < MINIMUM_SAFETY_WINDOW_SECS {
            return Err("safety observation was shorter than 15 minutes".into());
        }
        if now < receipt.issued_epoch_seconds || now > receipt.expires_epoch_seconds {
            return Err("resource safety receipt is not currently valid".into());
        }
        Ok(receipt)
    }
    pub fn read(path: &str) -> Result<Self, String> {
        let text =
            fs::read_to_string(path).map_err(|e| format!("cannot read safety receipt: {e}"))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system time precedes Unix epoch")?
            .as_secs();
        Self::parse(&text, now)
    }
}

#[derive(Clone, Debug)]
pub struct BenchmarkResult {
    pub mode: BenchmarkMode,
    pub elapsed: Duration,
    pub preloaded_packets: u64,
    pub generated_packets: u64,
    pub enqueued_packets: u64,
    pub accounted_in_flight: u64,
    pub processed: CounterSnapshot,
    pub per_worker: Vec<CounterSnapshot>,
    pub packets_per_second: f64,
    pub mpps: f64,
    pub captured_gbps: f64,
    pub gtpu_payload_gbps: f64,
    pub ethernet_wire_gbps_equivalent: f64,
    pub cpu_percent: f64,
    pub rss_bytes: u64,
    pub packet_loss_percent: f64,
    pub affinity_failures: usize,
    pub affinity: ResolvedAffinity,
    pub worker_effective_cpus: Vec<Vec<usize>>,
}

pub fn run(
    config: &BenchmarkConfig,
    _receipt: &SafetyGateReceipt,
) -> Result<BenchmarkResult, String> {
    config.validate()?;
    resource_guard()?;
    let affinity = resolve_affinity(&config.affinity, config.workers).map_err(str::to_string)?;
    match config.mode {
        BenchmarkMode::GeneratorOnly => run_generator(config, affinity),
        BenchmarkMode::ProcessingOnly => run_preloaded(config, affinity),
        BenchmarkMode::FullPipeline => run_pipeline(config, affinity),
    }
}

#[derive(Clone, Debug)]
pub struct PreloadedWorkload {
    pub partitions: Vec<Vec<PreloadedBatch>>,
    pub packets: u64,
    pub bytes: u64,
}
pub fn build_preloaded_workload(config: &BenchmarkConfig) -> PreloadedWorkload {
    let mut partitions = vec![Vec::new(); config.workers];
    let mut packets = 0;
    let mut bytes = 0;
    let mut ordinal = 0;
    for flow in 0..config.flow_count {
        let teid = teid_for_flow(flow);
        let flow_hash = flow_dispatcher::correlation_affinity(3, &teid.to_be_bytes());
        let worker = flow_dispatcher::worker_for_hash(flow_hash, config.workers);
        let batch: Vec<_> = (0..config.batch_size)
            .map(|_| {
                ordinal += 1;
                let data: Arc<[u8]> = make_gtpu_frame(config.frame_size, teid, ordinal).into();
                bytes += data.len() as u64;
                packets += 1;
                PreloadedPacket::new(data, config.frame_size as u32, ordinal)
            })
            .collect();
        partitions[worker].push(PreloadedBatch {
            flow_hash,
            packets: batch.into(),
        });
    }
    PreloadedWorkload {
        partitions,
        packets,
        bytes,
    }
}

fn run_preloaded(
    config: &BenchmarkConfig,
    affinity: ResolvedAffinity,
) -> Result<BenchmarkResult, String> {
    let workload = build_preloaded_workload(config);
    if !workload
        .partitions
        .iter()
        .flatten()
        .all(|batch| batch.packets.iter().all(PreloadedPacket::verify_integrity))
    {
        return Err("preloaded packet fingerprint mismatch before timing".into());
    }
    if workload.partitions.iter().any(Vec::is_empty) {
        return Err(
            "flow distribution left a worker without a partition; increase flow count".into(),
        );
    }
    let barrier = Arc::new(Barrier::new(config.workers + 1));
    let start = Arc::new(OnceLock::<Instant>::new());
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for (worker_id, partition) in workload.partitions.into_iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let start = Arc::clone(&start);
        let stop = Arc::clone(&stop);
        let duration = config.duration;
        let cpu = affinity.worker_cpus[worker_id];
        let workers = config.workers as u64;
        handles.push(
            thread::Builder::new()
                .name(format!("oiran-preloaded-{worker_id}"))
                .spawn(move || {
                    let affinity_ok = cpu
                        .map(worker_runtime::set_current_thread_affinity)
                        .unwrap_or(true);
                    let effective = worker_runtime::effective_cpu_affinity().unwrap_or_default();
                    let mut stats = CounterSnapshot::default();
                    let mut logical = worker_id as u64 + 1;
                    barrier.wait();
                    let deadline =
                        *start.get().expect("start published before barrier release") + duration;
                    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                        for batch in &partition {
                            worker_runtime::process_preloaded_fast_batch_strided(
                                batch,
                                &mut logical,
                                workers,
                                &mut stats,
                            );
                        }
                    }
                    (stats, affinity_ok, effective)
                })
                .map_err(|e| format!("processing worker spawn failed: {e}"))?,
        );
    }
    let start_cpu = process_cpu_seconds();
    let started = Instant::now();
    start
        .set(started)
        .map_err(|_| "benchmark start was already set")?;
    barrier.wait();
    let deadline = started + config.duration;
    let mut pressure_abort = None;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
        if let Err(error) = resource_guard() {
            pressure_abort = Some(error);
            stop.store(true, Ordering::Relaxed);
            break;
        }
    }
    let mut per_worker = Vec::new();
    let mut affinity_failures = 0;
    let mut effective = Vec::new();
    for handle in handles {
        let (stats, ok, cpus) = handle.join().map_err(|_| "processing worker panicked")?;
        if !ok {
            affinity_failures += 1;
        }
        per_worker.push(stats);
        effective.push(cpus);
    }
    if let Some(error) = pressure_abort {
        return Err(error);
    }
    let elapsed = started.elapsed();
    let cpu_seconds = (process_cpu_seconds() - start_cpu).max(0.0);
    let processed = sum(&per_worker);
    validate_integrity(processed)?;
    make_result(
        config,
        affinity,
        elapsed,
        cpu_seconds,
        workload.packets,
        processed.packets,
        processed.packets,
        0,
        processed,
        per_worker,
        affinity_failures,
        effective,
    )
}

fn run_pipeline(
    config: &BenchmarkConfig,
    affinity: ResolvedAffinity,
) -> Result<BenchmarkResult, String> {
    let _producer_guard = match affinity.producer_cpu {
        Some(cpu) => Some(AffinityGuard::pin(cpu).map_err(str::to_string)?),
        None => None,
    };
    let worker_cpus = if affinity.worker_cpus.iter().all(Option::is_some) {
        Some(
            affinity
                .worker_cpus
                .iter()
                .map(|cpu| cpu.unwrap())
                .collect(),
        )
    } else {
        None
    };
    let runtime = WorkerRuntime::start(RuntimeConfig {
        workers: config.workers,
        queue_capacity_batches: config.queue_capacity_batches,
        pin_cpus: false,
        worker_cpus,
        deterministic_replay: false,
    })
    .map_err(str::to_string)?;
    let start_cpu = process_cpu_seconds();
    let started = Instant::now();
    let deadline = started + config.duration;
    let mut sequence = 0;
    let mut generated = 0;
    let mut enqueued = 0;
    let mut batch_number = 0;
    let mut pressure_abort = None;
    while Instant::now() < deadline {
        let flow = batch_number % config.flow_count;
        let teid = teid_for_flow(flow);
        let mut batch = PacketBatch::with_capacity(config.batch_size);
        for _ in 0..config.batch_size {
            sequence += 1;
            batch.push(
                PacketRecord::from_owned(
                    provenance(config.frame_size, sequence),
                    make_gtpu_frame(config.frame_size, teid, sequence),
                )
                .with_integrity_tag(),
            );
        }
        let count = batch.len() as u64;
        generated += count;
        let hash = flow_dispatcher::correlation_affinity(3, &teid.to_be_bytes());
        if runtime.submit(batch, hash).is_ok() {
            enqueued += count;
        } else {
            thread::yield_now();
        }
        batch_number += 1;
        if batch_number % 1024 == 0 {
            if let Err(error) = resource_guard() {
                pressure_abort = Some(error);
                break;
            }
        }
    }
    let report = runtime.shutdown();
    if let Some(error) = pressure_abort {
        return Err(error);
    }
    let elapsed = started.elapsed();
    let cpu_seconds = (process_cpu_seconds() - start_cpu).max(0.0);
    let processed = sum(&report.workers);
    if generated != processed.packets.saturating_add(processed.dropped) {
        return Err(format!(
            "silent packet accounting mismatch: generated={generated} processed={} dropped={}",
            processed.packets, processed.dropped
        ));
    }
    if enqueued != processed.packets {
        return Err(format!(
            "drain mismatch: enqueued={enqueued} processed={}",
            processed.packets
        ));
    }
    validate_integrity(processed)?;
    make_result(
        config,
        affinity,
        elapsed,
        cpu_seconds,
        0,
        generated,
        enqueued,
        0,
        processed,
        report.workers,
        report.affinity_failures,
        report.worker_effective_cpus,
    )
}

fn run_generator(
    config: &BenchmarkConfig,
    affinity: ResolvedAffinity,
) -> Result<BenchmarkResult, String> {
    let _producer_guard = match affinity.producer_cpu {
        Some(cpu) => Some(AffinityGuard::pin(cpu).map_err(str::to_string)?),
        None => None,
    };
    let start_cpu = process_cpu_seconds();
    let started = Instant::now();
    let deadline = started + config.duration;
    let mut generated = 0;
    let mut generated_bytes = 0;
    let mut accumulator = 0_u64;
    while Instant::now() < deadline {
        let flow = (generated as usize / config.batch_size) % config.flow_count;
        let teid = teid_for_flow(flow);
        for _ in 0..config.batch_size {
            generated += 1;
            let frame = make_gtpu_frame(config.frame_size, teid, generated);
            generated_bytes += frame.len() as u64;
            accumulator = accumulator.rotate_left(5)
                ^ fingerprint(&frame)
                ^ generated.wrapping_mul(0x9e3779b97f4a7c15);
        }
        if generated % (config.batch_size as u64 * 1024) == 0 {
            resource_guard()?;
        }
    }
    let elapsed = started.elapsed();
    let cpu_seconds = (process_cpu_seconds() - start_cpu).max(0.0);
    let processed = CounterSnapshot {
        packets: generated,
        bytes: generated_bytes,
        gtpu_packets: generated,
        work_accumulator: accumulator,
        packet_number_sum: sequence_sum(generated),
        packet_number_xor: sequence_xor(generated),
        ..CounterSnapshot::default()
    };
    make_result(
        config,
        affinity,
        elapsed,
        cpu_seconds,
        0,
        generated,
        generated,
        0,
        processed,
        vec![processed],
        0,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn make_result(
    config: &BenchmarkConfig,
    affinity: ResolvedAffinity,
    elapsed: Duration,
    cpu_seconds: f64,
    preloaded_packets: u64,
    generated_packets: u64,
    enqueued_packets: u64,
    accounted_in_flight: u64,
    processed: CounterSnapshot,
    per_worker: Vec<CounterSnapshot>,
    affinity_failures: usize,
    worker_effective_cpus: Vec<Vec<usize>>,
) -> Result<BenchmarkResult, String> {
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    let pps = processed.packets as f64 / seconds;
    let offered = processed.packets.saturating_add(processed.dropped);
    let loss = if offered == 0 {
        0.0
    } else {
        processed.dropped as f64 * 100.0 / offered as f64
    };
    let payload = config.frame_size.saturating_sub(50) as f64;
    Ok(BenchmarkResult {
        mode: config.mode,
        elapsed,
        preloaded_packets,
        generated_packets,
        enqueued_packets,
        accounted_in_flight,
        processed,
        per_worker,
        packets_per_second: pps,
        mpps: pps / 1e6,
        captured_gbps: pps * config.frame_size as f64 * 8.0 / 1e9,
        gtpu_payload_gbps: pps * payload * 8.0 / 1e9,
        ethernet_wire_gbps_equivalent: pps * (config.frame_size + 24) as f64 * 8.0 / 1e9,
        cpu_percent: cpu_seconds / seconds * 100.0,
        rss_bytes: process_rss_bytes(),
        packet_loss_percent: loss,
        affinity_failures,
        affinity,
        worker_effective_cpus,
    })
}
fn validate_integrity(stats: CounterSnapshot) -> Result<(), String> {
    if stats.integrity_errors > 0 || stats.length_errors > 0 || stats.malformed > 0 {
        Err(format!(
            "integrity failure: fingerprint={} length={} malformed={}",
            stats.integrity_errors, stats.length_errors, stats.malformed
        ))
    } else {
        Ok(())
    }
}
fn teid_for_flow(flow: usize) -> u32 {
    0x0100_0000 | (flow as u32 & 0x000f_ffff)
}
fn provenance(frame_size: usize, sequence: u64) -> PacketProvenance {
    PacketProvenance {
        capture_id: Arc::from("synthetic-gtpu"),
        packet_number: sequence,
        timestamp_ns: sequence,
        captured_len: frame_size as u32,
        original_len: frame_size as u32,
        ingress_interface: 0,
    }
}
fn sequence_sum(count: u64) -> u64 {
    if count & 1 == 0 {
        (count / 2).wrapping_mul(count + 1)
    } else {
        count.wrapping_mul((count + 1) / 2)
    }
}
fn sequence_xor(count: u64) -> u64 {
    match count & 3 {
        0 => count,
        1 => 1,
        2 => count + 1,
        _ => 0,
    }
}

pub fn make_gtpu_frame(size: usize, teid: u32, sequence: u64) -> Vec<u8> {
    assert!(size >= 64);
    let mut frame = vec![0; size];
    frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((size - 14) as u16).to_be_bytes());
    frame[18..20].copy_from_slice(&(sequence as u16).to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&[10, 77, 22, 20]);
    frame[30..34].copy_from_slice(&[10, 77, 22, 13]);
    frame[34..36].copy_from_slice(&2152_u16.to_be_bytes());
    frame[36..38].copy_from_slice(&2152_u16.to_be_bytes());
    frame[38..40].copy_from_slice(&((size - 34) as u16).to_be_bytes());
    frame[42] = 0x30;
    frame[43] = 0xff;
    frame[44..46].copy_from_slice(&((size - 50) as u16).to_be_bytes());
    frame[46..50].copy_from_slice(&teid.to_be_bytes());
    for (index, byte) in frame[50..].iter_mut().enumerate() {
        *byte = (sequence.wrapping_add(index as u64) & 0xff) as u8;
    }
    frame
}
fn resource_guard() -> Result<(), String> {
    let text =
        fs::read_to_string("/proc/meminfo").map_err(|e| format!("resource check failed: {e}"))?;
    let available = text
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    if available < 2 * 1024 * 1024 {
        return Err("benchmark stopped: less than 2 GiB memory available".into());
    }
    if let Ok(p) = fs::read_to_string("/proc/pressure/memory") {
        if p.lines()
            .find(|l| l.starts_with("full "))
            .and_then(parse_avg10)
            .unwrap_or(0.0)
            > 5.0
        {
            return Err("benchmark stopped: memory pressure full avg10 exceeds 5%".into());
        }
    }
    Ok(())
}
fn parse_avg10(line: &str) -> Option<f64> {
    line.split_whitespace()
        .find_map(|f| f.strip_prefix("avg10=")?.parse().ok())
}
fn process_rss_bytes() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
        * 1024
}
fn process_cpu_seconds() -> f64 {
    let stat = match fs::read_to_string("/proc/self/stat") {
        Ok(v) => v,
        Err(_) => return 0.0,
    };
    let rest = match stat.rsplit_once(')') {
        Some((_, v)) => v,
        None => return 0.0,
    };
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks = f.get(11).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
        + f.get(12).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    ticks as f64 / clock_ticks_per_second() as f64
}
#[cfg(target_family = "unix")]
fn clock_ticks_per_second() -> i64 {
    extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    let t = unsafe { sysconf(2) };
    if t > 0 {
        t
    } else {
        100
    }
}
#[cfg(not(target_family = "unix"))]
fn clock_ticks_per_second() -> i64 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(mode: BenchmarkMode, workers: usize) -> BenchmarkConfig {
        BenchmarkConfig {
            mode,
            workers,
            duration: Duration::from_millis(10),
            frame_size: 128,
            batch_size: 32,
            queue_capacity_batches: 8,
            flow_count: 64,
            affinity: AffinityRequest::Disabled,
        }
    }
    #[test]
    fn generated_frames_parse() {
        for size in SUPPORTED_FRAME_SIZES {
            let frame = make_gtpu_frame(size, 0x10203040, 7);
            assert_eq!(
                packet_classifier::classify(&frame)
                    .unwrap()
                    .gtpu
                    .unwrap()
                    .teid,
                0x10203040
            );
        }
    }
    #[test]
    fn limits_are_bounded() {
        let mut c = config(BenchmarkMode::FullPipeline, 1);
        c.duration = Duration::from_secs(11);
        assert!(c.validate().is_err());
        c.duration = Duration::from_millis(10);
        c.workers = 5;
        assert!(c.validate().is_err());
    }
    #[test]
    fn receipt_requires_fifteen_fresh_minutes() {
        let valid="STATUS=PASS\nOBSERVED_SECONDS=900\nISSUED_EPOCH_SECONDS=1000\nEXPIRES_EPOCH_SECONDS=1300\n";
        assert!(SafetyGateReceipt::parse(valid, 1100).is_ok());
        assert!(SafetyGateReceipt::parse(&valid.replace("900", "899"), 1100).is_err());
        assert!(SafetyGateReceipt::parse(valid, 1400).is_err());
    }
    #[test]
    fn preloaded_integrity_partition_and_uniqueness() {
        let c = config(BenchmarkMode::ProcessingOnly, 4);
        let w = build_preloaded_workload(&c);
        assert_eq!(w.packets, (c.flow_count * c.batch_size) as u64);
        let mut ordinals = Vec::new();
        for (worker, partition) in w.partitions.iter().enumerate() {
            for batch in partition {
                assert_eq!(
                    flow_dispatcher::worker_for_hash(batch.flow_hash, c.workers),
                    worker
                );
                for packet in batch.packets.iter() {
                    assert!(packet.verify_integrity());
                    ordinals.push(packet.template_ordinal);
                }
            }
        }
        ordinals.sort_unstable();
        ordinals.dedup();
        assert_eq!(ordinals.len() as u64, w.packets);
    }
    #[test]
    fn modes_are_isolated() {
        assert_ne!(BenchmarkMode::GeneratorOnly, BenchmarkMode::ProcessingOnly);
        assert_ne!(BenchmarkMode::ProcessingOnly, BenchmarkMode::FullPipeline);
        assert_eq!(
            build_preloaded_workload(&config(BenchmarkMode::ProcessingOnly, 2))
                .partitions
                .len(),
            2
        );
    }
}
