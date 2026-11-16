//! 2.23.0 — binaire `polaris-bench-o1`.
//!
//! Sous-commandes :
//! - `replay-workers --input <pcap> --workers N --rounds M [--interface N3]`
//!   rejoue `M` fois le pcap sur `N` workers et imprime le rapport JSON
//!   (paquets/s, Gbit/s sur `original_length`, events/s, efficacité).
//! - `amplify --input <pcap> --ues K --output-dir DIR` (**stub 2.23.0**) :
//!   actuellement imprime le plan d'amplification pour `K` UE (table des
//!   `SyntheticUe { ue_index, imsi, msisdn, imei, teid_offset, ... }`).
//!   La réécriture pcap effective (lecture, patch, écriture) viendra en
//!   2.23.1 (nécessite capture-pcap writer + recomputed checksums).
//!
//! Format de sortie : **toujours JSON** (une ligne par exécution, pas
//! de logs texte libres) — standard polaris-bench, consommable par
//! `jq` et un futur agrégateur.

use std::io::Write;
use std::path::PathBuf;

use polaris_bench_o1::{build_synthetic_ue, run_replay, ReplayConfig};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(String::as_str).unwrap_or("");
    let result = match command {
        "replay-workers" => cmd_replay_workers(&args[2..]),
        "amplify" => cmd_amplify(&args[2..]),
        "help" | "--help" | "-h" | "" => {
            print_help();
            Ok(())
        }
        other => Err(format!("unknown subcommand: {other}. Use --help.")),
    };
    if let Err(error) = result {
        eprintln!(
            r#"{{"event":"POLARIS_BENCH_O1_ERROR","message":"{}"}}"#,
            error.replace('"', "'")
        );
        std::process::exit(2);
    }
}

fn print_help() {
    println!(
        "polaris-bench-o1 — harnais du bench O1 (2.23.0)\n\
\n\
Sous-commandes :\n\
  replay-workers --input <pcap> --workers N --rounds M [--interface N3] [--capture-id ID]\n\
      Rejoue le pcap sur N workers. Sortie JSON (1 ligne)\n\
      sur stdout : paquets/s, Gbit/s, events/s, efficacité.\n\
\n\
  amplify --input <pcap> --ues K [--output-dir DIR]\n\
      (2.23.0 stub) Imprime le plan d'amplification JSON pour K UE.\n\
      Réécriture effective du pcap : 2.23.1.\n\
\n\
  help    Affiche cette aide.\n"
    );
}

fn cmd_replay_workers(args: &[String]) -> Result<(), String> {
    let mut input: Option<PathBuf> = None;
    let mut workers: usize = 1;
    let mut rounds: usize = 1;
    let mut interface = String::from("N3");
    let mut capture_id = String::from("polaris-bench-o1-replay");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = Some(PathBuf::from(
                    args.get(i).ok_or("missing value for --input")?,
                ));
            }
            "--workers" => {
                i += 1;
                workers = args
                    .get(i)
                    .ok_or("missing value for --workers")?
                    .parse()
                    .map_err(|_| "--workers must be a positive integer".to_string())?;
            }
            "--rounds" => {
                i += 1;
                rounds = args
                    .get(i)
                    .ok_or("missing value for --rounds")?
                    .parse()
                    .map_err(|_| "--rounds must be a positive integer".to_string())?;
            }
            "--interface" => {
                i += 1;
                interface = args
                    .get(i)
                    .ok_or("missing value for --interface")?
                    .clone();
            }
            "--capture-id" => {
                i += 1;
                capture_id = args
                    .get(i)
                    .ok_or("missing value for --capture-id")?
                    .clone();
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    let input = input.ok_or("--input is required")?;
    let config = ReplayConfig {
        input,
        interface,
        capture_id,
        workers,
        rounds,
    };
    let report = run_replay(&config)?;
    let json = serde_json::to_string(&report)
        .map_err(|error| format!("failed to serialize report: {error}"))?;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{json}").map_err(|error| format!("stdout write: {error}"))?;
    Ok(())
}

fn cmd_amplify(args: &[String]) -> Result<(), String> {
    let mut ues: u32 = 1;
    let mut input: Option<PathBuf> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = Some(PathBuf::from(
                    args.get(i).ok_or("missing value for --input")?,
                ));
            }
            "--ues" => {
                i += 1;
                ues = args
                    .get(i)
                    .ok_or("missing value for --ues")?
                    .parse()
                    .map_err(|_| "--ues must be a positive integer".to_string())?;
            }
            "--output-dir" => {
                i += 1;
                output_dir = Some(PathBuf::from(
                    args.get(i).ok_or("missing value for --output-dir")?,
                ));
            }
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 1;
    }
    let input_display = input
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let output_dir_display = output_dir
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let plan: Vec<serde_json::Value> = (0..ues)
        .map(|ue_index| {
            let ue = build_synthetic_ue(ue_index);
            serde_json::json!({
                "ue_index": ue.ue_index,
                "imsi": ue.imsi,
                "msisdn": ue.msisdn,
                "imei": ue.imei,
                "teid_offset": format!("0x{:08x}", ue.teid_offset),
                "seid_offset": format!("0x{:016x}", ue.seid_offset),
                "ran_ue_ngap_id_offset": ue.ran_ue_ngap_id_offset,
                "amf_ue_ngap_id_offset": ue.amf_ue_ngap_id_offset,
            })
        })
        .collect();
    let report = serde_json::json!({
        "event": "POLARIS_BENCH_O1_AMPLIFY_PLAN",
        "status": "STUB_2_23_0",
        "note": "pcap rewrite deferred to 2.23.1 (requires capture-pcap writer + checksum recompute). This stub emits the synthetic UE plan so operators can audit identity generation.",
        "input": input_display,
        "output_dir": output_dir_display,
        "ue_count": ues,
        "plan": plan,
    });
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", serde_json::to_string(&report).unwrap())
        .map_err(|error| format!("stdout write: {error}"))?;
    Ok(())
}
