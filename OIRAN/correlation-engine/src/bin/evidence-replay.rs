use callflow_schema::fold_overlapping_edges;
use correlation_engine::{correlate_cross_interface_evidence, correlate_discovered_tunnels};
use session_engine::{discover_sessions, load_path};
use std::{env, fs, path::PathBuf};

fn main() {
    if let Err(error) = run() {
        eprintln!("error={error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let input = PathBuf::from(args.next().ok_or("usage: evidence-replay EVENTS OUTPUT")?);
    let output = PathBuf::from(args.next().ok_or("usage: evidence-replay EVENTS OUTPUT")?);
    if args.next().is_some() {
        return Err("usage: evidence-replay EVENTS OUTPUT".into());
    }
    let events = load_path(&input)?;
    let discovery = discover_sessions(&mut events.clone());
    // 2.7.26: replay the full publication correlation set (discovered
    // tunnels + cross-interface evidence) and fold overlapping-rule
    // edges into one per canonical pair. This matches the live-probe
    // publication path so operators can reproduce prod call-flow
    // output by hand without the 2.7.25 double-counting.
    let mut edges = correlate_discovered_tunnels(&events, &discovery);
    edges.extend(correlate_cross_interface_evidence(&events));
    let edges = fold_overlapping_edges(edges);
    let value = serde_json::json!({
        "source_events": events.len(),
        "ue_contexts": discovery.ue_contexts.len(),
        "pdu_sessions": discovery.pdu_sessions.len(),
        "pfcp_sessions": discovery.pfcp_sessions.len(),
        "gtpu_tunnels": discovery.gtpu_tunnels.len(),
        "correlation_edges": edges,
    });
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    let parent = output.parent().ok_or("output requires parent directory")?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temporary = output.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    fs::rename(&temporary, &output).map_err(|error| error.to_string())?;
    println!(
        "events={} sessions={} edges={} output={}",
        events.len(),
        discovery.pdu_sessions.len(),
        value["correlation_edges"].as_array().map_or(0, Vec::len),
        output.display()
    );
    Ok(())
}
