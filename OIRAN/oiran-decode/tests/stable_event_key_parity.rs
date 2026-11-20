//! 2.21.91 (ordre #9 7033006772 défaut 3) — preuve que le même pcapng
//! décodé par le chemin LIVE et par le chemin PUBLICATION produit des
//! events dont le `stable_event_key` est identique à 100 %.
//!
//! Scénario modélisé :
//!   * LIVE   — `apps/api::live_trace` lit le fichier dumpcap
//!              DIRECTEMENT dans le ring (`/var/lib/oiran/ring/n2/…`).
//!              `DecodeConfig.input = /…/n2/N2.pcapng`,
//!              `stable_source_file = "N2.pcapng"` (basename original).
//!   * PUBLI  — `live-probe` COPIE le dumpcap vers
//!              `/base/pcap/N2.pcap-<hash16>.pcapng` et décode la copie.
//!              `DecodeConfig.input = /…/staging/N2.pcap-abcdef1234567890.pcapng`,
//!              `stable_source_file = "N2.pcapng"` (basename ORIGINAL,
//!              propagé par le caller — voir `live-probe::run_continuous`
//!              @ `candidate.path.file_name()`).
//!
//! Attendu :
//!   * chaque event live a un `stable_event_key` non vide ;
//!   * l'ensemble `stable_event_key` live == l'ensemble `stable_event_key`
//!     publi, **strictement** (|Δ| = 0) ;
//!   * les `event_id` live et publi, eux, divergent (preuve que la nouvelle
//!     clé stable est indépendante du `capture_id` — invariant du design).

use event_schema::{sha256_hex, NormalizedEvent};
use oiran_decode::{decode_capture, DecodeConfig};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

fn fixture() -> PathBuf {
    // `CARGO_MANIFEST_DIR` = `.../OIRAN/oiran-decode`. Les pcapng sont
    // dans `OIRAN/datasets/OIRAN_5G_PDU_SESSION_DATA_V1/`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("datasets")
        .join("OIRAN_5G_PDU_SESSION_DATA_V1")
        .join("N2.pcapng")
}

fn collect_keys(events: &[NormalizedEvent]) -> BTreeSet<String> {
    events
        .iter()
        .map(|event| event.stable_event_key.clone())
        .collect()
}

/// Multiset de `stable_event_key` — préserve les multiplicités quand
/// un même paquet produit plusieurs events (ex. NGAP parent + NAS
/// encapsulé décodé en event enfant, événements-objets SCTP
/// reassembled). L'arbitrage #9 7033006772 spécifie une clé AU NIVEAU
/// DU PAQUET, pas AU NIVEAU DE L'EVENT — collisions attendues et
/// souhaitées pour la corrélation live↔publi du même paquet.
fn multiset_keys(events: &[NormalizedEvent]) -> std::collections::BTreeMap<String, usize> {
    let mut m = std::collections::BTreeMap::new();
    for event in events {
        *m.entry(event.stable_event_key.clone()).or_insert(0usize) += 1;
    }
    m
}

#[test]
fn live_and_publish_paths_produce_identical_stable_event_keys_on_the_same_pcapng() {
    let original = fixture();
    assert!(
        original.exists(),
        "fixture must exist: {}",
        original.display()
    );

    // LIVE — lit l'original directement, `capture_id = sha256(path)`
    // (dérivation historique côté apps/api::live_trace).
    let live_capture_id = format!(
        "sha256:{}",
        sha256_hex(original.to_string_lossy().as_bytes())
    );
    let live_output = decode_capture(&DecodeConfig {
        input: original.clone(),
        capture_id: live_capture_id,
        interface: "N2".into(),
        endpoints: std::collections::HashMap::new(),
        // live_trace alimente `stable_source_file` avec le basename du
        // fichier du ring — ici, c'est `N2.pcapng`.
        stable_source_file: original
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_owned())
            .expect("basename"),
    })
    .expect("live decode succeeds");

    // PUBLI — simule la copie de staging renommée en `N2.pcap-<hash16>.pcapng`
    // dans un répertoire distinct (= comportement de
    // `live-probe::run_continuous`). `capture_id` est dérivé du CONTENU
    // (checksum) comme en vrai.
    let tmp = tempdir_simulate_publish(&original);
    let copy_path = tmp.join("N2.pcap-abcdef1234567890.pcapng");
    std::fs::copy(&original, &copy_path).expect("copy to staging");
    let content_bytes = std::fs::read(&original).expect("read original");
    let publish_capture_id = format!("sha256:{}", sha256_hex(&content_bytes));
    let publish_output = decode_capture(&DecodeConfig {
        input: copy_path.clone(),
        capture_id: publish_capture_id,
        interface: "N2".into(),
        endpoints: std::collections::HashMap::new(),
        // live-probe::run_continuous alimente `stable_source_file` avec
        // le basename du dumpcap ORIGINAL (`candidate.path.file_name()`),
        // PAS le basename de la copie — c'est la seule valeur partagée
        // avec le chemin live.
        stable_source_file: original
            .file_name()
            .and_then(|s| s.to_str())
            .map(|s| s.to_owned())
            .expect("basename"),
    })
    .expect("publish decode succeeds");
    let _ = std::fs::remove_file(&copy_path);
    let _ = std::fs::remove_dir(&tmp);

    // Preuve 1 — décodage non vide (sinon le test ne prouve rien).
    assert!(
        !live_output.events.is_empty(),
        "live decode must emit events on N2.pcapng"
    );
    assert_eq!(
        live_output.events.len(),
        publish_output.events.len(),
        "même pcapng → même nombre d'events (live={}, publi={})",
        live_output.events.len(),
        publish_output.events.len(),
    );

    // Preuve 2 — chaque event a un `stable_event_key` non vide.
    for (idx, event) in live_output.events.iter().enumerate() {
        assert!(
            !event.stable_event_key.is_empty(),
            "live event #{idx} manque stable_event_key : {event:?}"
        );
    }

    // Preuve 3a — parité stricte 100 % des `stable_event_key` (ensemble).
    let live_keys = collect_keys(&live_output.events);
    let publish_keys = collect_keys(&publish_output.events);
    let only_live: Vec<_> = live_keys.difference(&publish_keys).collect();
    let only_publish: Vec<_> = publish_keys.difference(&live_keys).collect();
    assert!(
        only_live.is_empty() && only_publish.is_empty(),
        "stable_event_key diverge (live-only={only_live:?}, publi-only={only_publish:?})"
    );
    // Preuve 3b — parité stricte MULTISET : chaque paquet produit le
    // même nombre d'events des deux côtés (NGAP parent + NAS enfant
    // partagent la même clé par construction — voir `multiset_keys`).
    let live_mset = multiset_keys(&live_output.events);
    let publish_mset = multiset_keys(&publish_output.events);
    assert_eq!(
        live_mset, publish_mset,
        "multisets stable_event_key diffèrent live={live_mset:?} publi={publish_mset:?}"
    );

    // Preuve 4 — `event_id` diverge bien (invariant du design : zero
    // migration côté event_id, la clé stable est orthogonale).
    let live_ids: BTreeSet<_> = live_output
        .events
        .iter()
        .map(|e| e.event_id.clone())
        .collect();
    let publish_ids: BTreeSet<_> = publish_output
        .events
        .iter()
        .map(|e| e.event_id.clone())
        .collect();
    let intersect = live_ids.intersection(&publish_ids).count();
    assert_eq!(
        intersect, 0,
        "event_id DOIT diverger (capture_id live=sha256(path) ≠ publi=sha256(contenu))"
    );
}

fn tempdir_simulate_publish(seed_path: &Path) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "polaris-2.21.91-parity-{}-{}",
        std::process::id(),
        sha256_hex(seed_path.to_string_lossy().as_bytes())
            .chars()
            .take(8)
            .collect::<String>(),
    ));
    std::fs::create_dir_all(&base).expect("tmp dir");
    base
}
