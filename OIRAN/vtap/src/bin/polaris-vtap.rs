//! `polaris-vtap` — agent eBPF POLARIS vTAP 2.21.0 (P1b).
//!
//! Attache les uprobes libssl dans les processus `open5gs-*`, lit le
//! ringbuf, résout chaque fd en 4-tuple et écrit des pcap TCP rotatifs
//! (`vtap_SBI_<UTC>.pcap` + `.vtap.json`) lisibles par `oiran-decode`.
//!
//! usage: polaris-vtap [--out-dir DIR] [--rotate-seconds N] [--comm-prefix P]
//!                     [--server-port PORT]... [--libssl PATH]... [--probe-id ID]
//!                     [--proc-root DIR] [--duration-seconds N]
//!
//! Requiert root (CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE pour /proc/<pid>/fd).
//! Logs JSON sur stderr, aucune identité ni charge utile journalisée.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use aya::maps::{PerCpuArray, RingBuf};
use aya::programs::{TracePoint, UProbe};
use aya::Ebpf;
use polaris_vtap::conn::ProcResolver;
use polaris_vtap::pcap::{FileManifest, RotatingWriter};
use polaris_vtap::record::TlsRecord;
use polaris_vtap::synth::{Synthesizer, DEFAULT_SERVER_PORTS};
use serde_json::json;

static STOP: AtomicBool = AtomicBool::new(false);
static STOP_SIGNAL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

extern "C" fn on_signal(sig: libc::c_int) {
    STOP_SIGNAL.store(sig, Ordering::SeqCst);
    STOP.store(true, Ordering::SeqCst);
}

struct Args {
    out_dir: PathBuf,
    rotate: Duration,
    comm_prefix: String,
    server_ports: Vec<u16>,
    libssl: Vec<PathBuf>,
    probe_id: String,
    proc_root: PathBuf,
    duration: Option<Duration>,
}

fn log(value: serde_json::Value) {
    eprintln!("{value}");
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            log(json!({"event":"VTAP_FATAL","error":e}));
            std::process::exit(1);
        }
    }
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut a = Args {
        out_dir: PathBuf::from("/var/lib/oiran/vtap"),
        rotate: Duration::from_secs(300),
        comm_prefix: "open5gs-".into(),
        server_ports: Vec::new(),
        libssl: Vec::new(),
        probe_id: "lab-vtap".into(),
        proc_root: PathBuf::from("/proc"),
        duration: None,
    };
    let mut i = 0;
    while i < raw.len() {
        let v = raw.get(i + 1).ok_or(format!("{} requires a value", raw[i]))?;
        let num = |v: &str| v.parse::<u64>().map_err(|_| format!("{}: not a number", raw[i]));
        match raw[i].as_str() {
            "--out-dir" => a.out_dir = v.into(),
            "--rotate-seconds" => a.rotate = Duration::from_secs(num(v)?.max(10)),
            "--comm-prefix" => a.comm_prefix = v.clone(),
            "--server-port" => a.server_ports.push(num(v)? as u16),
            "--libssl" => a.libssl.push(v.into()),
            "--probe-id" => a.probe_id = v.clone(),
            "--proc-root" => a.proc_root = v.into(),
            "--duration-seconds" => a.duration = Some(Duration::from_secs(num(v)?)),
            other => return Err(format!("unknown option {other}")),
        }
        i += 2;
    }
    if a.server_ports.is_empty() {
        a.server_ports = DEFAULT_SERVER_PORTS.to_vec();
    }
    Ok(a)
}

/// libssl mappée par les processus cibles, dédupliquée par (dev, inode) :
/// une uprobe sur un inode couvre tous les processus qui le partagent.
fn discover_libssl(args: &Args) -> Vec<(PathBuf, Vec<String>)> {
    let mut seen = BTreeSet::new();
    let mut out: Vec<(PathBuf, Vec<String>)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&args.proc_root) else {
        return out;
    };
    for entry in entries.flatten() {
        let pid = entry.file_name().to_string_lossy().to_string();
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let base = args.proc_root.join(&pid);
        let comm = std::fs::read_to_string(base.join("comm")).unwrap_or_default();
        let comm = comm.trim();
        if !comm.starts_with(&args.comm_prefix) {
            continue;
        }
        let maps = std::fs::read_to_string(base.join("maps")).unwrap_or_default();
        for line in maps.lines() {
            let Some(path) = line.split_whitespace().nth(5) else { continue };
            if !path.contains("libssl.so") {
                continue;
            }
            let full = base.join("root").join(path.trim_start_matches('/'));
            let Ok(meta) = std::fs::metadata(&full) else { continue };
            if seen.insert((meta.dev(), meta.ino())) {
                out.push((full, vec![comm.to_string()]));
            } else if let Some(slot) = out.iter_mut().find(|(p, _)| {
                std::fs::metadata(p).map(|m| (m.dev(), m.ino()) == (meta.dev(), meta.ino())).unwrap_or(false)
            }) {
                if !slot.1.iter().any(|c| c == comm) {
                    slot.1.push(comm.to_string());
                }
            }
        }
    }
    out
}

fn realtime_offset_ns() -> i128 {
    let get = |clock| {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe { libc::clock_gettime(clock, &mut ts) };
        ts.tv_sec as i128 * 1_000_000_000 + ts.tv_nsec as i128
    };
    get(libc::CLOCK_REALTIME) - get(libc::CLOCK_MONOTONIC)
}

/// `YYYYMMDDTHHMMSSZ` UTC sans dépendance chrono.
fn utc_stamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

const UPROBES: &[(&str, &str, bool)] = &[
    ("vtap_ssl_write_enter", "SSL_write", true),
    ("vtap_ssl_write_exit", "SSL_write", true),
    ("vtap_ssl_read_enter", "SSL_read", true),
    ("vtap_ssl_read_exit", "SSL_read", true),
    ("vtap_ssl_write_ex_enter", "SSL_write_ex", false),
    ("vtap_ssl_write_ex_exit", "SSL_write_ex", false),
    ("vtap_ssl_read_ex_enter", "SSL_read_ex", false),
    ("vtap_ssl_read_ex_exit", "SSL_read_ex", false),
    ("vtap_ssl_set_fd", "SSL_set_fd", false),
];

const TRACEPOINTS: &[(&str, &str)] = &[
    ("vtap_sys_write", "sys_enter_write"),
    ("vtap_sys_writev", "sys_enter_writev"),
    ("vtap_sys_sendto", "sys_enter_sendto"),
    ("vtap_sys_sendmsg", "sys_enter_sendmsg"),
    ("vtap_sys_read", "sys_enter_read"),
    ("vtap_sys_readv", "sys_enter_readv"),
    ("vtap_sys_recvfrom", "sys_enter_recvfrom"),
    ("vtap_sys_recvmsg", "sys_enter_recvmsg"),
];

fn run() -> Result<(), String> {
    let args = parse_args()?;
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        // 2.21.5 — essai 3 : agent lancé en `&` depuis un shell d'outil,
        // tué au SIGHUP de fin de session sans VTAP_STOP ni pcap fermé.
        // SIGHUP/SIGQUIT déclenchent désormais l'arrêt propre (fichier
        // fermé + manifeste + VTAP_STOP avec le signal reçu).
        libc::signal(libc::SIGHUP, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGQUIT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
    log(json!({
        "event": "VTAP_START",
        "version": polaris_vtap::VERSION,
        "probe_id": args.probe_id,
        "probe_type": polaris_vtap::PROBE_TYPE,
        "out_dir": args.out_dir.display().to_string(),
        "rotate_seconds": args.rotate.as_secs(),
        "comm_prefix": args.comm_prefix,
        "server_ports": args.server_ports,
        "open_item": "HPACK: les NF Open5GS lancées AVANT l'agent doivent être redémarrées, sinon en-têtes HTTP/2 illisibles (hpack_context=mid_stream)",
    }));

    let targets: Vec<(PathBuf, Vec<String>)> = if args.libssl.is_empty() {
        discover_libssl(&args)
    } else {
        args.libssl.iter().map(|p| (p.clone(), vec!["--libssl".into()])).collect()
    };
    if targets.is_empty() {
        return Err(format!(
            "VTAP_NO_TARGET: aucun processus `{}*` ne mappe libssl (TLS SBI actif ? NF lancées ?)",
            args.comm_prefix
        ));
    }

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/vtap.bpf.o")))
        .map_err(|e| format!("bpf load: {e}"))?;
    let mut attached_core = 0usize;
    for (prog, symbol, core) in UPROBES {
        let p: &mut UProbe = bpf
            .program_mut(prog)
            .ok_or(format!("program {prog} absent"))?
            .try_into()
            .map_err(|e| format!("{prog}: {e}"))?;
        p.load().map_err(|e| format!("{prog} load: {e}"))?;
        for (lib, comms) in &targets {
            match p.attach(Some(symbol), 0, lib, None) {
                Ok(_) => {
                    if *core {
                        attached_core += 1;
                    }
                    log(json!({"event":"VTAP_UPROBE_ATTACHED","program":prog,"symbol":symbol,"libssl":lib.display().to_string(),"comms":comms}));
                }
                Err(e) => log(json!({"event":"VTAP_SYMBOL_MISSING","program":prog,"symbol":symbol,"libssl":lib.display().to_string(),"error":e.to_string(),"core":core})),
            }
        }
    }
    // SSL_write + SSL_read (entrée + sortie) sur au moins une libssl.
    if attached_core < 4 {
        return Err("VTAP_ATTACH_FAILED: SSL_write/SSL_read non attachés".into());
    }
    ensure_tracefs()?;
    for (prog, tp) in TRACEPOINTS {
        let p: &mut TracePoint = bpf
            .program_mut(prog)
            .ok_or(format!("program {prog} absent"))?
            .try_into()
            .map_err(|e| format!("{prog}: {e}"))?;
        p.load().map_err(|e| format!("{prog} load: {e}"))?;
        p.attach("syscalls", tp).map_err(|e| format!("{prog} attach {tp}: {e}"))?;
    }

    let mut ring = RingBuf::try_from(bpf.take_map("events").ok_or("map events absente")?)
        .map_err(|e| format!("ringbuf: {e}"))?;
    let stats: PerCpuArray<_, u64> =
        PerCpuArray::try_from(bpf.take_map("stats").ok_or("map stats absente")?)
            .map_err(|e| format!("stats: {e}"))?;

    let offset = realtime_offset_ns();
    let mut resolver = ProcResolver::new(&args.proc_root);
    let mut synth = Synthesizer::new(&args.server_ports);
    let mut writer = RotatingWriter::new(&args.out_dir, format!("vtap_{}", polaris_vtap::INTERFACE))
        .map_err(|e| format!("out dir: {e}"))?;
    writer.open(&utc_stamp()).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut file_started = Instant::now();
    let mut last_alive = Instant::now();
    let mut bpf_base = read_stats(&stats);

    loop {
        let mut drained = 0usize;
        while let Some(item) = ring.next() {
            drained += 1;
            let record = match TlsRecord::parse(&item) {
                Ok(r) => r,
                Err(e) => {
                    synth.note_unresolved("malformed_event");
                    log(json!({"event":"VTAP_EVENT_MALFORMED","error":e.to_string()}));
                    continue;
                }
            };
            drop(item);
            if !record.comm.starts_with(&args.comm_prefix) {
                synth.counters.filtered_records += 1;
                continue;
            }
            let tuple = match resolver.resolve(record.tgid, record.fd) {
                Ok(t) => t,
                Err(e) => {
                    synth.counters.records += 1;
                    synth.note_unresolved(e.counter());
                    continue;
                }
            };
            let ts = (record.mono_ns as i128 + offset).max(0) as u64;
            let packets = synth.push(ts, tuple, record.op, &record.comm, record.truncated(), &record.data);
            writer.write(&packets).map_err(|e| format!("pcap write: {e}"))?;
        }
        let stop = STOP.load(Ordering::SeqCst)
            || args.duration.map(|d| started.elapsed() >= d).unwrap_or(false);
        if stop || file_started.elapsed() >= args.rotate {
            let now = read_stats(&stats);
            let delta: Vec<u64> = now.iter().zip(&bpf_base).map(|(a, b)| a.saturating_sub(*b)).collect();
            bpf_base = now;
            // Pertes ringbuf : seul compteur invisible côté userspace
            // (troncature et fd inconnu arrivent déjà flaggés par event).
            if delta[0] > 0 {
                *synth.counters.unresolved.entry("bpf_ringbuf_full".into()).or_default() += delta[0];
            }
            let items = polaris_vtap::open_items(&synth);
            let closed = writer
                .close(|path| {
                    serde_json::to_string_pretty(&FileManifest {
                        schema: "polaris.vtap.manifest.v1",
                        agent_version: polaris_vtap::VERSION,
                        probe_id: &args.probe_id,
                        probe_type: polaris_vtap::PROBE_TYPE,
                        interface: polaris_vtap::INTERFACE,
                        timestamp_source: polaris_vtap::TIMESTAMP_SOURCE,
                        pcap: path.display().to_string(),
                        counters: &synth.counters,
                        connections: synth.manifest(),
                        open_items: items.clone(),
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| format!("rotate: {e}"))?;
            log(json!({
                "event": "VTAP_FILE_CLOSED",
                "pcap": closed.map(|p| p.display().to_string()),
                "counters": synth.counters,
                "open_items": items,
            }));
            synth.rotate();
            if stop {
                log(json!({"event":"VTAP_STOP","signal":STOP_SIGNAL.load(Ordering::SeqCst),"uptime_s":started.elapsed().as_secs()}));
                return Ok(());
            }
            writer.open(&utc_stamp()).map_err(|e| e.to_string())?;
            file_started = Instant::now();
        }
        if last_alive.elapsed() >= Duration::from_secs(60) {
            // 2.21.5 — battement de vie : prouve que l'agent tourne et
            // date sa mort s'il disparaît (aucun silence).
            writer.flush().map_err(|e| format!("pcap flush: {e}"))?;
            log(json!({"event":"VTAP_ALIVE","uptime_s":started.elapsed().as_secs(),"counters":synth.counters}));
            last_alive = Instant::now();
        }
        if drained == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// 2.21.1 — les tracepoints exigent tracefs. Absent (ex. après reboot) →
/// l'agent le monte lui-même et le journalise ; échec → VTAP_FATAL explicite.
fn ensure_tracefs() -> Result<(), String> {
    let present = |p: &str| std::path::Path::new(p).join("events").is_dir();
    for path in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        if present(path) {
            log(json!({"event":"VTAP_TRACEFS_PRESENT","path":path}));
            return Ok(());
        }
    }
    let rc = unsafe {
        libc::mount(
            c"nodev".as_ptr(),
            c"/sys/kernel/tracing".as_ptr(),
            c"tracefs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 || !present("/sys/kernel/tracing") {
        return Err(format!(
            "VTAP_TRACEFS_UNAVAILABLE: tracefs absent et montage impossible ({})",
            std::io::Error::last_os_error()
        ));
    }
    log(json!({"event":"VTAP_TRACEFS_MOUNTED","path":"/sys/kernel/tracing"}));
    Ok(())
}

fn read_stats(stats: &PerCpuArray<aya::maps::MapData, u64>) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, slot) in out.iter_mut().enumerate() {
        if let Ok(values) = stats.get(&(i as u32), 0) {
            *slot = values.iter().sum();
        }
    }
    out
}
