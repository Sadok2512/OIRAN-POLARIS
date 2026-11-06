//! 2.8.1 (#9, ANR2 CPU proof): bench the continuous worker at rest.
//!
//! Spins up a scratch `CaptureManager`, starts the continuous import
//! loop against an empty source tree (no pcap files, no new segments),
//! samples the process CPU time over the chosen window, and reports
//! `cpu_percent = 100 * (cpu_delta_s / window_s)`. The pre-2.8.1 worker
//! re-hashed every segment every ~1 s even at `pending=0`; ANR2 observed
//! 87.6 % CPU in production. The 2.8.1 fix adds a `(size, mtime) →
//! (sha, packets)` cache so idle scans emit zero file reads.
//!
//! Usage:
//!     OIRAN_PSEUDONYM_KEY_PATH=<key> idle_cpu_bench <window_seconds>
//!     window_seconds defaults to 60.

use live_probe::{CaptureManager, ContinuousImportConfig, CONTINUOUS_CAPTURE_ID};
use std::{env, fs, thread, time::Duration};

fn cpu_time_seconds() -> f64 {
    let stat = fs::read_to_string("/proc/self/stat").expect("read /proc/self/stat");
    // Skip fields 1 and 2 (pid, comm) which may contain spaces.
    let rparen = stat.rfind(')').expect("comm end");
    let rest = &stat[rparen + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // After pid and comm, the next fields are: state ppid pgrp session tty_nr
    // tpgid flags minflt cminflt majflt cmajflt utime stime …
    // utime is field 14 overall → index 11 in `rest` after skipping pid+comm.
    let utime: u64 = fields[11].parse().expect("utime u64");
    let stime: u64 = fields[12].parse().expect("stime u64");
    let ticks_per_s = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    (utime + stime) as f64 / ticks_per_s
}

fn main() {
    let window_seconds: u64 = env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(60);
    let preload_segments: usize = env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let scratch = env::temp_dir().join(format!("oiran-idle-cpu-{}", std::process::id()));
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).unwrap();
    let source_root = scratch.join("source");
    fs::create_dir_all(&source_root.join("N2")).unwrap();
    fs::create_dir_all(&source_root.join("N3")).unwrap();
    fs::create_dir_all(&source_root.join("N4")).unwrap();
    // 2.8.1 bench contract: pre-populate N pcap segments so the idle
    // worker has something to re-scan. Before the (dev, inode, size,
    // mtime_ns) cache, every scan re-hashed all N files; the test
    // measures CPU AFTER the first scan has had a chance to populate
    // the cache. If preload_segments==0, the worker scans an empty
    // tree every tick.
    let template_body = {
        let mut v = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 1, 0, 0, 0,
            0,
        ];
        let payload = vec![0xa5u8; 64];
        while v.len() < 2 * 1024 * 1024 {
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            v.extend_from_slice(&payload);
        }
        v.truncate(2 * 1024 * 1024);
        v
    };
    // 2.8.1 bench: pre-populate N pcap segments AND pre-populate the
    // persisted `import_state.json` so the worker starts in the
    // "already ingested, nothing to do" state ANR2 observed in
    // production. Without pre-populating the state the worker would
    // (correctly) ingest the 512 files; the goal here is to measure
    // the IDLE path.
    use std::os::unix::fs::MetadataExt;
    let mut seen_checksums: Vec<String> = Vec::new();
    let mut fingerprints: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    for index in 0..preload_segments {
        let mut body = template_body.clone();
        let offset = 24 + (index % (body.len() - 24 - 4));
        body[offset] = (index & 0xff) as u8;
        body[offset + 1] = ((index >> 8) & 0xff) as u8;
        let plane = match index % 3 {
            0 => "N2",
            1 => "N3",
            _ => "N4",
        };
        let path = source_root
            .join(plane)
            .join(format!("segment-{index:04}.pcapng"));
        fs::write(&path, &body).unwrap();
        // Compute the SHA via the event_schema streaming API so the
        // state looks exactly like a normal ingestion would persist.
        let checksum = {
            let bytes = fs::read(&path).unwrap();
            event_schema::sha256_hex(&bytes)
        };
        let metadata = fs::metadata(&path).unwrap();
        let mtime_ns = i128::from(metadata.mtime()) * 1_000_000_000i128
            + i128::from(metadata.mtime_nsec());
        seen_checksums.push(checksum.clone());
        fingerprints.insert(
            path.display().to_string(),
            serde_json::json!({
                "dev": metadata.dev(),
                "inode": metadata.ino(),
                "size_bytes": metadata.size(),
                "mtime_ns": mtime_ns,
                "checksum": checksum,
                "packets": 0u64,
            }),
        );
    }
    drop(template_body);
    if preload_segments > 0 {
        let base = scratch
            .join("captures")
            .join(CONTINUOUS_CAPTURE_ID);
        fs::create_dir_all(&base).unwrap();
        let state = serde_json::json!({
            "segments": {},
            "seen_checksums": seen_checksums,
            "seen_order": seen_checksums,
            "failed_ingestions": [],
            "source_fingerprints": fingerprints,
        });
        fs::write(
            base.join("import_state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
    }
    // CaptureManager.root is the "captures" directory — distinct from
    // the source root.
    let root = scratch.join("captures");
    fs::create_dir_all(&root).unwrap();
    // Steer the pseudonym-key path under the scratch so we don't touch
    // /var/lib/oiran. load_or_generate creates a fresh 32-byte key.
    env::set_var(
        "OIRAN_PSEUDONYM_KEY_PATH",
        scratch.join("pseudonym.key").to_string_lossy().to_string(),
    );
    let manager = CaptureManager::new(root, false).expect("manager init");
    let config = ContinuousImportConfig::bounded(source_root);
    manager
        .start_continuous_import(config)
        .expect("start continuous import");

    // Settle the worker: for a preloaded tree the first scan must
    // populate the cache for every file (one SHA + packet count per
    // preload segment, ~tens of ms per 2 MiB file × preload_segments).
    // A 15 s settle window covers the cold-cache work for 512 × 2 MiB
    // PCAPs on a loaded runner. After settle, the cache is fully
    // populated and every subsequent scan must hit the cache.
    let settle = if preload_segments > 0 { 15 } else { 2 };
    thread::sleep(Duration::from_secs(settle));
    let cpu_before = cpu_time_seconds();
    let wall_before = std::time::Instant::now();
    thread::sleep(Duration::from_secs(window_seconds));
    let cpu_after = cpu_time_seconds();
    let wall = wall_before.elapsed().as_secs_f64();
    let cpu_delta = cpu_after - cpu_before;
    let cpu_percent = 100.0 * cpu_delta / wall;
    println!(
        "preload_segments={preload_segments} window_s={window_seconds} wall_s={wall:.3} cpu_delta_s={cpu_delta:.3} cpu_percent={cpu_percent:.2}"
    );
    // Hard-code the 2.8.1 contract in the bench output so operators
    // can assert the gate without a separate reader.
    let ok = cpu_percent < 2.0;
    println!("gate_cpu_percent_below_2 = {ok}");
    let _ = fs::remove_dir_all(&scratch);
    if !ok {
        std::process::exit(1);
    }
}
