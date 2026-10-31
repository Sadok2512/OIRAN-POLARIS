use oiran_decode::{decode_capture, write_jsonl, DecodeConfig};
use std::{collections::HashMap, env, process};

fn usage() {
    eprintln!("usage: oiran-decode --input FILE --capture-id sha256:HEX --interface N2|N3|N4|SBI|S1-MME|S1-U|S11 --output FILE [--append] [--endpoint IP=FUNCTION]...");
}
fn main() {
    if let Err(e) = execute() {
        eprintln!("decode_error={e}");
        process::exit(1)
    }
}
fn execute() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut input = None;
    let mut capture_id = None;
    let mut interface = None;
    let mut output = None;
    let mut append = false;
    let mut endpoints = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--append" {
            append = true;
            i += 1;
            continue;
        }
        if i + 1 >= args.len() {
            usage();
            return Err("missing option value".into());
        }
        match args[i].as_str() {
            "--input" => input = Some(args[i + 1].clone()),
            "--capture-id" => capture_id = Some(args[i + 1].clone()),
            "--interface" => interface = Some(args[i + 1].clone()),
            "--output" => output = Some(args[i + 1].clone()),
            "--endpoint" => {
                let (ip, nf) = args[i + 1]
                    .split_once('=')
                    .ok_or("endpoint must be IP=FUNCTION")?;
                endpoints.insert(ip.to_string(), nf.to_string());
            }
            _ => {
                usage();
                return Err(format!("unknown option {}", args[i]));
            }
        }
        i += 2;
    }
    let input = input.ok_or("--input is required")?;
    let capture_id = capture_id.ok_or("--capture-id is required")?;
    if !capture_id.starts_with("sha256:") || capture_id.len() != 71 {
        return Err("capture ID must be sha256: followed by 64 hex digits".into());
    }
    let interface = interface.ok_or("--interface is required")?;
    let output = output.ok_or("--output is required")?;
    let decoded = decode_capture(&DecodeConfig {
        input: input.into(),
        capture_id,
        interface,
        endpoints,
    })?;
    write_jsonl(std::path::Path::new(&output), &decoded.events, append)?;
    println!("capture_format={} packets={} events={} warnings={} transport_errors={} sctp_errors={} incomplete_sctp={} tcp_connections={} tcp_errors={} http2_frames={} http2_streams={} sbi_transactions={} output={}", decoded.report.capture_format, decoded.report.packets, decoded.report.events, decoded.report.warnings, decoded.report.transport_errors, decoded.report.sctp_errors, decoded.report.incomplete_sctp, decoded.report.tcp_connections, decoded.report.tcp_errors, decoded.report.http2_frames, decoded.report.http2_streams, decoded.report.sbi_transactions, output);
    Ok(())
}
