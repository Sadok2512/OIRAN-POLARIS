use live_probe::CaptureManager;
use std::{env, path::PathBuf, process::ExitCode};

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(capture_id) = arguments.next() else {
        eprintln!("usage: oiran-recover <capture-id> [capture-root]");
        return ExitCode::from(2);
    };
    let root = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/oiran/captures"));
    if arguments.next().is_some() {
        eprintln!("unexpected extra arguments");
        return ExitCode::from(2);
    }
    let manager = match CaptureManager::new(root, false) {
        Ok(manager) => manager,
        Err(error) => {
            eprintln!("recovery initialization failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    match manager.recover_failed_capture(&capture_id) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("serialize recovery report")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("recovery failed: {error}");
            ExitCode::FAILURE
        }
    }
}
