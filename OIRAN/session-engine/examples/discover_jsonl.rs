use session_engine::{discover_sessions, load_path};
use std::path::Path;

fn main() {
    let mut events = Vec::new();
    let paths = std::env::args().skip(1).collect::<Vec<_>>();
    if paths.is_empty() {
        eprintln!("usage: discover_jsonl EVENTS.jsonl [EVENTS.jsonl ...]");
        std::process::exit(2);
    }
    for path in &paths {
        match load_path(Path::new(path)) {
            Ok(mut loaded) => events.append(&mut loaded),
            Err(error) => {
                eprintln!("{path}: {error}");
                std::process::exit(1);
            }
        }
    }
    let result = discover_sessions(events);
    println!(
        "{}",
        serde_json::to_string_pretty(&result).expect("serialize discovery result")
    );
}
