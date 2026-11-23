//! 2.21.152 — comparaison AVANT / APRÈS de l'ordre d'import des captures,
//! en LECTURE SEULE sur un jeu continu.
//!
//! Usage :
//!   dataset-order-compare <manifeste> <dossier des fragments> <dossier de travail>
//!
//! * `<manifeste>` : une COPIE de `dataset_manifest.json` (pas celui du jeu
//!   en service) ;
//! * `<dossier des fragments>` : le dossier du jeu, lu seulement (les
//!   fragments d'events sont immuables) ;
//! * `<dossier de travail>` : un dossier HORS du jeu, pour un fichier
//!   temporaire (les events NGAP et NAS 5G, quelques Mo), retiré à la fin.
//!
//! Ce que l'outil calcule, sans rien publier ni modifier :
//!   1. « avant » — la découverte des sessions dans l'ordre d'avant
//!      2.21.152 (empreintes), comparée à celle que porte le manifeste ;
//!   2. « après » — la même découverte dans l'ordre d'import, avec la
//!      table des ids publiés tirée du manifeste ;
//!   3. la différence : ids gardés, ids que la découverte ne produit plus,
//!      ids nouveaux.
//!
//! Seuls des nombres et des identifiants opaques (`5g-session-…`,
//! `uectx-…`) sont affichés : aucune adresse, aucune identité d'abonné.
//! Les ids de session ne dépendent que des events NGAP et NAS 5G : le
//! reste des fragments est lu mais non retenu.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde_json::Value;
use session_engine::{
    apply_capture_ranks, canonical_capture_order, discover_sessions, discover_sessions_with,
    load_paths_spilling_representatives_with_progress, ContextIdentityPolicy, DiscoveryResult,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("dataset-order-compare: {error}");
        std::process::exit(1);
    }
}

fn ids(discovery: &DiscoveryResult) -> (BTreeSet<String>, BTreeSet<String>) {
    (
        discovery.ue_contexts.iter().map(|context| context.context_id.clone()).collect(),
        discovery.pdu_sessions.iter().map(|session| session.session_id.clone()).collect(),
    )
}

fn run() -> Result<(), String> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [manifest_path, dataset_dir, work_dir] = arguments.as_slice() else {
        return Err("usage : dataset-order-compare <manifeste> <dossier des fragments> <dossier de travail>".into());
    };
    let dataset_dir = PathBuf::from(dataset_dir);
    let work_dir = PathBuf::from(work_dir);
    let dataset_real = fs::canonicalize(&dataset_dir).map_err(|error| format!("{}: {error}", dataset_dir.display()))?;
    fs::create_dir_all(&work_dir).map_err(|error| format!("{}: {error}", work_dir.display()))?;
    let work_real = fs::canonicalize(&work_dir).map_err(|error| format!("{}: {error}", work_dir.display()))?;
    if work_real.starts_with(&dataset_real) {
        return Err("le dossier de travail doit être HORS du jeu".into());
    }
    let manifest: Value = serde_json::from_slice(&fs::read(manifest_path).map_err(|error| format!("{manifest_path}: {error}"))?)
        .map_err(|error| format!("{manifest_path}: {error}"))?;
    let shards: Vec<String> = manifest["event_shards"]
        .as_array()
        .map(|shards| shards.iter().filter_map(|shard| shard["path"].as_str().map(str::to_owned)).collect())
        .filter(|shards: &Vec<String>| !shards.is_empty())
        .unwrap_or_else(|| vec!["oiran_events.jsonl".to_owned()]);

    // Ce que le manifeste publie.
    let published: DiscoveryResult = serde_json::from_value(manifest["discovery"].clone())
        .map_err(|error| format!("manifeste sans découverte lisible : {error}"))?;
    let (published_contexts, published_sessions) = ids(&published);
    let anchors: BTreeMap<String, String> = manifest["published_context_anchors"]
        .as_object()
        .map(|table| table.iter().filter_map(|(anchor, id)| id.as_str().map(|id| (anchor.clone(), id.to_owned()))).collect())
        .unwrap_or_default();
    let mut anchors = anchors;
    for context in &published.ue_contexts {
        if let Some(anchor) = context.event_ids.first() {
            anchors.entry(anchor.clone()).or_insert_with(|| context.context_id.clone());
        }
    }

    // Les events NGAP et NAS 5G, dans l'ordre des fragments.
    let filtered = work_real.join(format!("dataset-order-compare-{}.jsonl", std::process::id()));
    let (mut lines_read, mut lines_kept) = (0u64, 0u64);
    {
        let mut writer = BufWriter::new(fs::File::create(&filtered).map_err(|error| format!("{}: {error}", filtered.display()))?);
        for shard in &shards {
            let path = dataset_dir.join(shard);
            let reader = BufReader::new(fs::File::open(&path).map_err(|error| format!("{}: {error}", path.display()))?);
            for line in reader.split(b'\n') {
                let line = line.map_err(|error| format!("{}: {error}", path.display()))?;
                lines_read += 1;
                let wanted = [&b"\"NGAP\""[..], &b"\"NAS-5GMM\""[..], &b"\"NAS-5GSM\""[..]]
                    .iter()
                    .any(|needle| line.windows(needle.len()).any(|window| window == *needle));
                if !wanted {
                    continue;
                }
                let value: Value = match serde_json::from_slice(&line) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                if !matches!(value["protocol"].as_str(), Some("NGAP" | "NAS-5GMM" | "NAS-5GSM")) {
                    continue;
                }
                writer.write_all(&line).and_then(|_| writer.write_all(b"\n")).map_err(|error| error.to_string())?;
                lines_kept += 1;
            }
        }
        writer.flush().map_err(|error| error.to_string())?;
    }
    let loaded = load_paths_spilling_representatives_with_progress(
        &[filtered.clone()],
        &work_real.join(format!("dataset-order-compare-staging-{}", std::process::id())),
        64 * 1024 * 1024,
        |_, _| {},
    );
    let _ = fs::remove_file(&filtered);
    let _ = fs::remove_dir_all(work_real.join(format!("dataset-order-compare-staging-{}", std::process::id())));
    let index = loaded?;
    // Ordre d'import : celui que porte le manifeste s'il en porte un
    // (jeu déjà publié sous 2.21.152), complété par la première apparition.
    let mut import_ids: Vec<String> = Vec::new();
    let mut import_points: Vec<String> = Vec::new();
    for entry in manifest["capture_order"].as_array().into_iter().flatten() {
        if let (Some(id), Some(point)) = (entry["capture_id"].as_str(), entry["capture_point_id"].as_str()) {
            import_ids.push(id.to_owned());
            import_points.push(point.to_owned());
        }
    }
    let persisted = import_ids.len();
    for (position, capture_id) in index.capture_order.iter().enumerate() {
        if !import_ids.contains(capture_id) {
            import_ids.push(capture_id.clone());
            import_points.push(index.capture_points.get(position).cloned().unwrap_or_default());
        }
    }
    let order = canonical_capture_order(&import_ids, &import_points);

    // Avant : ordre des empreintes, ids historiques.
    let mut events = index.events.clone();
    let before = discover_sessions(&mut events);
    let (before_contexts, before_sessions) = ids(&before);

    // Après : ordre d'import, ids publiés gardés par leur ancre.
    let mut events = index.events;
    let without_rank = apply_capture_ranks(&mut events, &order);
    let after = discover_sessions_with(
        &mut events,
        ContextIdentityPolicy { intrinsic: true, published_anchors: Some(&anchors) },
    );
    let (after_contexts, after_sessions) = ids(&after);

    let list = |set: BTreeSet<&String>| -> Vec<String> { set.into_iter().take(200).cloned().collect() };
    let report = serde_json::json!({
        "tool": "dataset-order-compare",
        "version": env!("CARGO_PKG_VERSION"),
        "fragments": shards.len(),
        "lines_read": lines_read,
        "ngap_nas_events_kept": lines_kept,
        "captures_ranked": order.len(),
        "captures_ranked_by_manifest": persisted,
        "captures_with_ngap_or_nas": index.capture_order.len(),
        "events_without_rank": without_rank,
        "published": {
            "contexts": published_contexts.len(),
            "pdu_sessions": published_sessions.len(),
            "session_ids_listed": manifest["session_ids"].as_array().map(Vec::len),
        },
        "before_recomputed": {
            "contexts": before_contexts.len(),
            "pdu_sessions": before_sessions.len(),
            // Si faux, l'outil ne reproduit pas l'état publié : ne pas conclure.
            "matches_published_contexts": before_contexts == published_contexts,
            "matches_published_pdu_sessions": before_sessions == published_sessions,
        },
        "after": {
            "contexts": after_contexts.len(),
            "pdu_sessions": after_sessions.len(),
            "contexts_keeping_published_id": after.event_accounting.get("contexts_keeping_published_id"),
            "contexts_with_intrinsic_id": after.event_accounting.get("contexts_with_intrinsic_id"),
        },
        "pdu_sessions_diff": {
            "kept": published_sessions.intersection(&after_sessions).count(),
            "not_rediscovered": published_sessions.difference(&after_sessions).count(),
            "created": after_sessions.difference(&published_sessions).count(),
            "not_rediscovered_ids": list(published_sessions.difference(&after_sessions).collect()),
            "created_ids": list(after_sessions.difference(&published_sessions).collect()),
        },
        "contexts_diff": {
            "kept": published_contexts.intersection(&after_contexts).count(),
            "not_rediscovered": published_contexts.difference(&after_contexts).count(),
            "created": after_contexts.difference(&published_contexts).count(),
        },
    });
    println!("{}", serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?);
    let _: &Path = &dataset_real;
    Ok(())
}
