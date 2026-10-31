// Probe Agent MVP CLI.
//
// Subcommands:
//   probe-agent version                 — print the crate version
//   probe-agent validate <config.toml>  — validate a config file
//   probe-agent sha256 <path>           — compute the SHA-256 the
//                                         Probe Manager would verify
//                                         before accepting a segment
//
// The enrollment / heartbeat / upload loops will land with the mTLS
// transport PR; this binary is enough to run the smoke tests on a
// dev host without a Probe Manager up.

use probe_agent::{sha256_hex, validate_config, AgentConfig, VERSION};
use std::env;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") => {
            println!("probe-agent {VERSION}");
            ExitCode::SUCCESS
        }
        Some("validate") => match args.get(1) {
            Some(path) => match fs::read_to_string(path) {
                Ok(text) => match parse_config(&text) {
                    Ok(config) => match validate_config(&config) {
                        Ok(()) => {
                            println!("OK");
                            ExitCode::SUCCESS
                        }
                        Err(code) => {
                            eprintln!("{code}");
                            ExitCode::from(2)
                        }
                    },
                    Err(error) => {
                        eprintln!("CONFIG_PARSE_FAILED: {error}");
                        ExitCode::from(2)
                    }
                },
                Err(error) => {
                    eprintln!("CONFIG_READ_FAILED: {error}");
                    ExitCode::from(2)
                }
            },
            None => {
                eprintln!("usage: probe-agent validate <config.toml>");
                ExitCode::from(64)
            }
        },
        Some("sha256") => match args.get(1) {
            Some(path) => match fs::read(path) {
                Ok(bytes) => {
                    println!("{}", sha256_hex(&bytes));
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("READ_FAILED: {error}");
                    ExitCode::from(2)
                }
            },
            None => {
                eprintln!("usage: probe-agent sha256 <path>");
                ExitCode::from(64)
            }
        },
        _ => {
            eprintln!("usage: probe-agent [version | validate <config> | sha256 <path>]");
            ExitCode::from(64)
        }
    }
}

/// Minimal TOML-ish parser for the MVP config. The real transport PR
/// swaps this for the `toml` crate; keeping it in-tree avoids pulling
/// a dependency for a 20-line file.
fn parse_config(text: &str) -> Result<AgentConfig, String> {
    use probe_agent::{InterfaceConfig, InterfaceRole};
    let mut probe_id = String::new();
    let mut endpoint = String::new();
    let mut interfaces: Vec<InterfaceConfig> = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_role: Option<InterfaceRole> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[interfaces]]" {
            if let Some(name) = current_name.take() {
                interfaces.push(InterfaceConfig {
                    name,
                    role: current_role.take().unwrap_or(InterfaceRole::Unknown),
                });
            } else {
                current_role = None;
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let value = v.trim().trim_matches('"').to_string();
            match key {
                "probe_id" => probe_id = value,
                "probe_manager_endpoint" => endpoint = value,
                "name" => current_name = Some(value),
                "role" => current_role = Some(InterfaceRole::from_wire(&value)),
                _ => {}
            }
        }
    }
    if let Some(name) = current_name {
        interfaces.push(InterfaceConfig {
            name,
            role: current_role.unwrap_or(InterfaceRole::Unknown),
        });
    }
    Ok(AgentConfig {
        probe_id,
        probe_manager_endpoint: endpoint,
        interfaces,
    })
}
