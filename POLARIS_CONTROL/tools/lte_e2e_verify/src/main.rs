use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!(
            "usage: lte-e2e-verify <pending-evidence-dir>\n\
             version: {}",
            lte_e2e_verify::VERSION
        );
        return ExitCode::from(2);
    };
    let path = PathBuf::from(dir);
    match lte_e2e_verify::verify(&path) {
        Ok(report) => {
            print!("{}", report.render());
            // Exit 0 only on REAL_PASS so the tool is safe for CI gates.
            if report.final_verdict() == "REAL_PASS" {
                ExitCode::from(0)
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            eprintln!("MISSION=LTE_E2E_NORTH_STAR");
            eprintln!("ERROR={}", err);
            eprintln!("FINAL_VERDICT=NO_LTE_E2E_REAL_PASS");
            ExitCode::from(2)
        }
    }
}
