//! 2.21.148 — banc de la passe des représentants de publication
//! (`load_paths_spilling_representatives_with_progress`).
//!
//! Deux sous-commandes :
//!
//! ```text
//! cargo run --release -p session-engine --example representatives_bench -- \
//!     generate <fixture.jsonl> <sortie.jsonl> <events> <ue>
//! cargo run --release -p session-engine --example representatives_bench -- \
//!     run <dossier de travail> <fichier.jsonl> [<fichier.jsonl> …]
//! ```
//!
//! `generate` fabrique un jeu synthétique en répétant les events d'un
//! jeu réel (`datasets/OIRAN_5G_PDU_SESSION_DATA_V1/oiran_events.jsonl`)
//! avec des identifiants décalés : `<ue>` contextes UE distincts, chacun
//! rejoué plusieurs fois, comme une capture continue qui revoit les
//! mêmes abonnés. Aucune identité réelle : le jeu de départ ne porte que
//! des pseudonymes.
//!
//! `run` exécute la passe avec le plafond mémoire de production (64 Mio)
//! et imprime : events lus, représentants, durée, pic de mémoire
//! résidente, et une **empreinte de la liste des représentants** — le
//! SHA-256 chaîné de chaque représentant sérialisé, dans l'ordre. Deux
//! exécutions rendent la même empreinte si et seulement si la liste est
//! identique event par event : c'est la preuve qu'une optimisation ne
//! change pas le résultat.

use std::{
    fs,
    io::{BufRead, BufReader, BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

use serde_json::Value;

/// Plafond des passages gardés en mémoire avant écriture sur disque :
/// la valeur de production (`live-probe`,
/// `PUBLICATION_REPRESENTATIVE_RUN_MEMORY_BYTES`).
const RUN_MEMORY_BYTES: usize = 64 * 1024 * 1024;

/// Identifiants décalés d'un contexte UE à l'autre.
const SHIFTED_IDENTIFIERS: &[&str] = &[
    "ran_ue_ngap_id",
    "amf_ue_ngap_id",
    "seid",
    "f_seid",
    "teid",
    "f_teid",
    "gtp_teid",
    "enb_ue_s1ap_id",
    "mme_ue_s1ap_id",
];

fn shift_identifier(value: &str, ue: u64) -> String {
    if let Some(hex) = value.strip_prefix("0x") {
        if let Ok(number) = u64::from_str_radix(hex, 16) {
            if number != 0 {
                return format!("0x{:0width$x}", number.wrapping_add(ue << 20), width = hex.len());
            }
        }
        return value.to_owned();
    }
    match value.parse::<u64>() {
        Ok(number) => (number + ue * 1_000).to_string(),
        Err(_) => value.to_owned(),
    }
}

/// Réécrit un event du jeu de départ pour la répétition `replica`.
fn rewrite(value: &mut Value, replica: u64, ue: u64, segment: u64, parent_key: Option<&str>) {
    match value {
        Value::String(text) => {
            if text.starts_with("evt-") {
                text.push_str(&format!("-{replica}"));
            } else if text.starts_with("sha256:") || parent_key == Some("source_sha256") {
                let prefix = if text.starts_with("sha256:") { "sha256:" } else { "" };
                *text = format!("{prefix}{:064x}", segment + 1);
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite(item, replica, ue, segment, None);
            }
        }
        Value::Object(map) => {
            let shifted = map
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| SHIFTED_IDENTIFIERS.contains(&name));
            if shifted {
                if let Some(Value::String(text)) = map.get_mut("value") {
                    *text = shift_identifier(text, ue);
                }
            }
            for (key, item) in map.iter_mut() {
                if shifted && key == "value" {
                    continue;
                }
                rewrite(item, replica, ue, segment, Some(key.as_str()));
            }
        }
        _ => {}
    }
}

fn generate(fixture: &str, output: &str, events: u64, ues: u64) -> Result<(), String> {
    let base: Vec<Value> = BufReader::new(fs::File::open(fixture).map_err(|e| e.to_string())?)
        .lines()
        .map_while(Result::ok)
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(&line).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    if base.is_empty() || ues == 0 {
        return Err("jeu de départ vide ou nombre d'UE nul".into());
    }
    let mut writer = BufWriter::with_capacity(
        8 * 1024 * 1024,
        fs::File::create(output).map_err(|e| e.to_string())?,
    );
    let mut written = 0u64;
    let mut replica = 0u64;
    while written < events {
        let ue = replica % ues;
        // Un « segment » de capture regroupe 32 répétitions.
        let segment = replica / 32;
        for event in &base {
            if written >= events {
                break;
            }
            let mut event = event.clone();
            rewrite(&mut event, replica, ue, segment, None);
            if let Some(seconds) = event.pointer_mut("/timestamp/seconds") {
                if let Some(number) = seconds.as_i64() {
                    *seconds = Value::from(number + replica as i64);
                }
            }
            serde_json::to_writer(&mut writer, &event).map_err(|e| e.to_string())?;
            writer.write_all(b"\n").map_err(|e| e.to_string())?;
            written += 1;
        }
        replica += 1;
    }
    writer.flush().map_err(|e| e.to_string())?;
    println!("generated events={written} replicas={replica} ues={ues} file={output}");
    Ok(())
}

/// Pic de mémoire résidente du processus, en kilo-octets.
fn peak_rss_kb() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| line.split_whitespace().nth(1).and_then(|kb| kb.parse().ok()))
        })
        .unwrap_or(0)
}

fn run(staging: &str, paths: &[String]) -> Result<(), String> {
    let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let input_bytes: u64 = paths
        .iter()
        .map(|path| fs::metadata(path).map(|meta| meta.len()).unwrap_or(0))
        .sum();
    let started = Instant::now();
    let index = session_engine::load_paths_spilling_representatives_with_progress(
        &paths,
        std::path::Path::new(staging),
        RUN_MEMORY_BYTES,
        |_, _| {},
    )?;
    let elapsed_ms = started.elapsed().as_millis();
    let peak_kb = peak_rss_kb();
    // Empreinte chaînée : identique si et seulement si la liste des
    // représentants est identique, event par event, dans l'ordre.
    let mut digest = String::new();
    for event in &index.events {
        let mut bytes = digest.into_bytes();
        bytes.extend_from_slice(&serde_json::to_vec(event).map_err(|e| e.to_string())?);
        digest = event_schema::sha256_hex(&bytes);
    }
    println!(
        "run input_bytes={input_bytes} source_events={} representatives={} elapsed_ms={elapsed_ms} us_per_event={} peak_rss_kb={peak_kb} representatives_sha256={digest}",
        index.source_event_count,
        index.events.len(),
        if index.source_event_count == 0 { 0 } else { elapsed_ms * 1_000 / index.source_event_count as u128 },
    );
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("generate") if args.len() == 5 => match (args[3].parse(), args[4].parse()) {
            (Ok(events), Ok(ues)) => generate(&args[1], &args[2], events, ues),
            _ => Err("<events> et <ue> sont des nombres".into()),
        },
        Some("run") if args.len() >= 3 => run(&args[1], &args[2..]),
        _ => Err(
            "usage : generate <fixture.jsonl> <sortie.jsonl> <events> <ue> | run <dossier> <fichier.jsonl>…"
                .into(),
        ),
    };
    if let Err(error) = result {
        eprintln!("representatives_bench: {error}");
        std::process::exit(2);
    }
}
