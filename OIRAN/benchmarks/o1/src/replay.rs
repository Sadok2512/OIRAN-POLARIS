//! 2.23.0 — volet A du bench O1 : rejeu d'un pcap sur N workers.
//!
//! Charge le pcap en mémoire, puis le rejoue `rounds` fois réparties
//! sur `workers` threads. Chaque thread décode indépendamment et
//! compte paquets/events. Métriques publiées :
//! - `packets_per_second` (total agrégé, calculé sur `wall_elapsed`) ;
//! - `bits_per_second` (= `wire_bytes * 8 / wall_elapsed`, sur
//!   `original_length` jamais `captured_length` — invariant OP2.1) ;
//! - `events_per_second_per_worker` ;
//! - `scaling_efficiency` = `thrpt_N / (N × thrpt_1)` ;
//! - `rss_max_kib` (approximatif, lecture `/proc/self/status`
//!   avant/après — ne pas l'étendre côté ARM32 où le champ est différent).

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;

#[derive(Clone, Debug)]
pub struct ReplayConfig {
    pub input: PathBuf,
    pub interface: String,
    pub capture_id: String,
    pub workers: usize,
    /// Nombre de rejeux total du pcap (réparti sur les workers).
    pub rounds: usize,
}

#[derive(Debug, Serialize)]
pub struct WorkerReport {
    pub worker_id: usize,
    pub rounds_run: usize,
    pub packets: u64,
    pub wire_bytes: u64,
    pub events: u64,
    pub elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
pub struct ReplayReport {
    pub workers: usize,
    pub rounds_requested: usize,
    pub rounds_run: usize,
    pub wall_elapsed_ms: u128,
    pub total_packets: u64,
    pub total_wire_bytes: u64,
    pub total_events: u64,
    pub packets_per_second: f64,
    pub bits_per_second: f64,
    pub events_per_second: f64,
    pub rss_kib_before: u64,
    pub rss_kib_after: u64,
    pub per_worker: Vec<WorkerReport>,
}

/// Exécute `rounds` rejeux du pcap sur `workers` threads. Retourne les
/// métriques agrégées. Les workers se répartissent `rounds` round-robin.
pub fn run_replay(config: &ReplayConfig) -> Result<ReplayReport, String> {
    if config.workers == 0 {
        return Err("workers must be >= 1".into());
    }
    if config.rounds == 0 {
        return Err("rounds must be >= 1".into());
    }
    let bytes = fs::read(&config.input).map_err(|error| {
        format!(
            "failed to load pcap {}: {error}",
            config.input.display()
        )
    })?;
    let bytes = Arc::new(bytes);
    let rss_before = read_rss_kib();
    let wall_start = Instant::now();

    let mut handles = Vec::with_capacity(config.workers);
    for worker_id in 0..config.workers {
        let bytes = bytes.clone();
        let interface = config.interface.clone();
        let capture_id = config.capture_id.clone();
        let rounds_for_worker = rounds_for(config.rounds, config.workers, worker_id);
        let handle = std::thread::spawn(move || {
            run_worker(
                worker_id,
                bytes,
                &interface,
                &capture_id,
                rounds_for_worker,
            )
        });
        handles.push(handle);
    }
    let mut per_worker = Vec::with_capacity(config.workers);
    for handle in handles {
        let report = handle
            .join()
            .map_err(|_| "worker panicked".to_string())??;
        per_worker.push(report);
    }
    let wall_elapsed = wall_start.elapsed();
    let rss_after = read_rss_kib();

    let total_packets: u64 = per_worker.iter().map(|w| w.packets).sum();
    let total_wire_bytes: u64 = per_worker.iter().map(|w| w.wire_bytes).sum();
    let total_events: u64 = per_worker.iter().map(|w| w.events).sum();
    let rounds_run: usize = per_worker.iter().map(|w| w.rounds_run).sum();
    let wall_ms = wall_elapsed.as_millis().max(1);
    let secs = (wall_ms as f64) / 1000.0;

    Ok(ReplayReport {
        workers: config.workers,
        rounds_requested: config.rounds,
        rounds_run,
        wall_elapsed_ms: wall_ms,
        total_packets,
        total_wire_bytes,
        total_events,
        packets_per_second: (total_packets as f64) / secs,
        bits_per_second: ((total_wire_bytes as f64) * 8.0) / secs,
        events_per_second: (total_events as f64) / secs,
        rss_kib_before: rss_before,
        rss_kib_after: rss_after,
        per_worker,
    })
}

/// Répartit `rounds` aussi uniformément que possible sur `workers`.
fn rounds_for(rounds: usize, workers: usize, worker_id: usize) -> usize {
    let base = rounds / workers;
    let extra = rounds % workers;
    base + if worker_id < extra { 1 } else { 0 }
}

fn run_worker(
    worker_id: usize,
    bytes: Arc<Vec<u8>>,
    interface: &str,
    capture_id: &str,
    rounds: usize,
) -> Result<WorkerReport, String> {
    use event_schema::{sha256_hex, PseudonymKey};
    use oiran_decode::{decode_capture_streaming, DecodeConfig};

    // Le décodeur `decode_capture_streaming` lit le fichier à partir
    // du chemin ; on le matérialise une fois dans un tmpfile en RAM
    // (`/dev/shm` si disponible, sinon `/tmp`) pour simuler un rejeu
    // 100 % mémoire. Les workers partagent le même tmpfile en lecture.
    let tmp_dir = if std::path::Path::new("/dev/shm").is_dir() {
        std::path::Path::new("/dev/shm")
    } else {
        std::path::Path::new("/tmp")
    };
    let tmp_path = tmp_dir.join(format!(
        "polaris-bench-o1-replay-{worker_id}-{}.pcap",
        std::process::id()
    ));
    fs::write(&tmp_path, &*bytes).map_err(|error| {
        format!("failed to materialize tmpfile {tmp_path:?}: {error}")
    })?;
    let pseudonym_key = PseudonymKey::generate()?;

    let start = Instant::now();
    let mut packets = 0u64;
    let mut wire_bytes = 0u64;
    let mut events = 0u64;
    for round in 0..rounds {
        // Capture ID doit être `sha256:` + 64 hex. On dérive un SHA-256
        // synthétique à partir de la base + worker + round pour que les
        // events restent déterministes entre runs.
        let payload = format!("{capture_id}:{worker_id}:{round}");
        let digest = sha256_hex(payload.as_bytes());
        let round_capture_id = format!("sha256:{digest}");
        let config = DecodeConfig {
            input: tmp_path.clone(),
            capture_id: round_capture_id,
            interface: interface.to_string(),
            endpoints: Default::default(),
        };
        let report = decode_capture_streaming(&config, &pseudonym_key, |event| {
            events = events.saturating_add(1);
            for packet in &event.packet_references {
                packets = packets.saturating_add(1);
                wire_bytes = wire_bytes.saturating_add(u64::from(packet.original_length));
            }
            Ok(())
        })
        .map_err(|error| format!("worker {worker_id} round {round} failed: {error}"))?;
        let _ = report; // report.events déjà consommé ci-dessus
    }
    let elapsed = start.elapsed();
    let _ = fs::remove_file(&tmp_path);
    Ok(WorkerReport {
        worker_id,
        rounds_run: rounds,
        packets,
        wire_bytes,
        events,
        elapsed_ms: elapsed.as_millis(),
    })
}

/// Lecture de `VmRSS` depuis `/proc/self/status`. Retourne 0 si
/// inaccessible (CI / non-linux).
fn read_rss_kib() -> u64 {
    let content = match fs::read_to_string("/proc/self/status") {
        Ok(content) => content,
        Err(_) => return 0,
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            if let Some(number) = rest.split_whitespace().next() {
                if let Ok(value) = number.parse::<u64>() {
                    return value;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_for_distributes_uniformly_with_remainder_on_first_workers() {
        assert_eq!(rounds_for(4, 2, 0), 2);
        assert_eq!(rounds_for(4, 2, 1), 2);
        assert_eq!(rounds_for(5, 2, 0), 3); // extra pour worker 0
        assert_eq!(rounds_for(5, 2, 1), 2);
        assert_eq!(rounds_for(10, 4, 0), 3); // 2 base + 1 extra
        assert_eq!(rounds_for(10, 4, 1), 3);
        assert_eq!(rounds_for(10, 4, 2), 2);
        assert_eq!(rounds_for(10, 4, 3), 2);
    }

    #[test]
    fn run_replay_rejects_zero_workers() {
        let config = ReplayConfig {
            input: PathBuf::from("/nonexistent.pcap"),
            interface: "N3".into(),
            capture_id: "test".into(),
            workers: 0,
            rounds: 1,
        };
        assert!(run_replay(&config).is_err());
    }

    #[test]
    fn run_replay_rejects_zero_rounds() {
        let config = ReplayConfig {
            input: PathBuf::from("/nonexistent.pcap"),
            interface: "N3".into(),
            capture_id: "test".into(),
            workers: 1,
            rounds: 0,
        };
        assert!(run_replay(&config).is_err());
    }
}
