use callflow_schema::build_callflow;
use correlation_engine::{correlate, ScenarioManifest};
use session_engine::{load_path, reconstruct, ReconstructionHints};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("error={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let workspace = env::current_dir()
        .map_err(display_error)?
        .canonicalize()
        .map_err(display_error)?;
    let mut dataset = PathBuf::from("datasets/OIRAN_5G_PDU_SESSION_DATA_V1");
    let mut json_output = PathBuf::from("OIRAN_5G_E2E_CALLFLOW.json");
    let mut html_output = PathBuf::from("OIRAN_5G_E2E_CALLFLOW.html");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {arg}"))?;
        match arg.as_str() {
            "--dataset" => dataset = PathBuf::from(value),
            "--json" => json_output = PathBuf::from(value),
            "--html" => html_output = PathBuf::from(value),
            _ => return Err(format!("unknown argument {arg}")),
        }
    }
    let dataset = dataset.canonicalize().map_err(display_error)?;
    if !dataset.starts_with(&workspace) {
        return Err("dataset must remain inside the OIRAN workspace".into());
    }
    json_output = safe_output(&workspace, &json_output)?;
    html_output = safe_output(&workspace, &html_output)?;
    let manifest: ScenarioManifest = serde_json::from_slice(
        &fs::read(dataset.join("scenario_manifest.json")).map_err(display_error)?,
    )
    .map_err(|e| format!("scenario manifest: {e}"))?;
    let events = load_path(&dataset.join("oiran_events.jsonl"))?;
    if events.iter().any(|e| !e.has_provenance()) {
        return Err("source event lacks packet provenance".into());
    }
    let reconstruction = reconstruct(
        events,
        ReconstructionHints {
            ue_pseudonym: Some(manifest.test_ue.clone()),
            uplink_teid: Some(manifest.identifiers.uplink_teid.clone()),
            downlink_teid: Some(manifest.identifiers.downlink_teid.clone()),
        },
    );
    let edges = correlate(&reconstruction, &manifest);
    let flow = build_callflow(&reconstruction, edges);
    validate(&flow)?;
    let json = serde_json::to_string_pretty(&flow).map_err(|e| e.to_string())?;
    let html = callflow_renderer::render(&flow).map_err(|e| e.to_string())?;
    fs::write(&json_output, format!("{json}\n")).map_err(display_error)?;
    fs::write(&html_output, html).map_err(display_error)?;
    println!(
        "callflow={} source={} session={} background={} unmatched={} edges={} json={} html={}",
        flow.callflow_id,
        flow.accounting.source_events,
        flow.accounting.session_events,
        flow.accounting.background_events,
        flow.accounting.unmatched_events,
        flow.correlation_edges.len(),
        json_output.display(),
        html_output.display()
    );
    Ok(())
}

fn validate(flow: &callflow_schema::CallFlow) -> Result<(), String> {
    if flow.events.len() != flow.accounting.source_events {
        return Err("event accounting mismatch".into());
    }
    let accounted = flow.accounting.session_events
        + flow.accounting.background_events
        + flow.accounting.unmatched_events;
    if accounted != flow.accounting.source_events {
        return Err("source events are not exhaustively classified".into());
    }
    if flow.accounting.extra_events != 0 || flow.accounting.duplicate_events != 0 {
        return Err("extra or duplicate events present".into());
    }
    if flow.correlation_status.get("N2_N4").map(String::as_str) != Some("STRONG")
        || flow.correlation_status.get("N4_N3").map(String::as_str) != Some("EXACT")
        || flow.correlation_status.get("E2E").map(String::as_str) != Some("STRONG")
    {
        return Err("certified correlation levels not reproduced".into());
    }
    if flow.events.iter().any(|e| e.packet_references.is_empty()) {
        return Err("call flow event lacks provenance".into());
    }
    Ok(())
}

fn safe_output(workspace: &Path, path: &Path) -> Result<PathBuf, String> {
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    };
    let parent = resolved
        .parent()
        .ok_or("output path has no parent")?
        .canonicalize()
        .map_err(display_error)?;
    if !parent.starts_with(workspace) {
        return Err("output must remain inside the OIRAN workspace".into());
    }
    Ok(resolved)
}

fn display_error(error: std::io::Error) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use callflow_schema::{CallFlow, EventAccounting};
    use std::collections::BTreeMap;

    fn flow(source: usize) -> CallFlow {
        CallFlow {
            callflow_id: "c".into(),
            session_id: "s".into(),
            technology: "5G SA".into(),
            start_timestamp: "".into(),
            end_timestamp: "".into(),
            participants: vec![],
            interfaces: vec![],
            procedures: vec![],
            events: vec![],
            correlation_edges: vec![],
            correlation_status: BTreeMap::new(),
            decoder_versions: BTreeMap::new(),
            schema_version: "1".into(),
            capture_references: vec![],
            accounting: EventAccounting {
                source_events: source,
                session_events: 0,
                background_events: 0,
                unmatched_events: 0,
                duplicate_events: 0,
                extra_events: 0,
            },
            unresolved_fields: 0,
        }
    }

    #[test]
    fn fabricated_event_accounting_is_rejected() {
        assert!(validate(&flow(1)).is_err());
    }

    #[test]
    fn output_path_escape_is_rejected() {
        let root = std::env::current_dir().unwrap().canonicalize().unwrap();
        assert!(safe_output(&root, Path::new("/tmp/escape.json")).is_err());
    }
}
