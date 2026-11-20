//! 2.21.6 — Intégration : vTAP out_dir → manifeste → stamp sur event.
//!
//! Réponse à la régression 2.21.5 (3 écarts Sadok) : 2.21.6 câble pour
//! de bon l'ingestion vTAP via l'`out_dir` + lit le stamp du manifeste
//! écrit par l'agent `polaris-vtap`. Ce test écrit manuellement un
//! `.vtap.json` plausible (même schéma que `polaris_vtap::pcap::FileManifest`)
//! à côté d'un `vtap_*.pcap` stub et vérifie que le pipeline
//! `read_vtap_manifest_stamp` extrait exactement les 3 champs
//! (`probe_id`, `probe_type`, `timestamp_source`) depuis le MANIFESTE,
//! et renvoie `VTAP_MANIFEST_MISSING` quand le manifeste est absent.
//!
//! Le test d'ingestion continuous complet (CaptureManager →
//! `process_continuous_capture_inner` → écriture JSONL) est couvert
//! par les tests bout-en-bout dans le lot de recette lab, pas ici.
//! Ce test prouve la boucle « chemin → manifeste → stamp » qui
//! nourrit directement le pipeline en live-probe/src/lib.rs.

use std::path::{Path, PathBuf};

use live_probe::capture_source::{
    append_vtap_manifest_suffix, read_vtap_manifest_stamp, VtapManifestError, VtapSource,
    VTAP_MANIFEST_MISSING,
};
use live_probe::vtap_out_dirs;

fn tmp_dir(prefix: &str) -> PathBuf {
    let base = PathBuf::from(format!(
        "/tmp/oiran-vtap-wiring-{}-{}",
        prefix,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn write_manifest(pcap: &Path, body: &[u8]) {
    std::fs::write(append_vtap_manifest_suffix(pcap), body).unwrap();
}

#[test]
fn ingestible_entries_pair_with_manifest_stamp_for_a_real_vtap_filename() {
    let dir = tmp_dir("pair");
    let pcap = dir.join("vtap_SBI_20261116T120000Z.pcap");
    std::fs::write(&pcap, b"stub-pcap").unwrap();
    write_manifest(
        &pcap,
        br#"{
            "schema": "polaris.vtap.manifest.v1",
            "probe_id": "oiran-vtap-lab-01",
            "probe_type": "vtap",
            "interface": "SBI",
            "timestamp_source": "ebpf_monotonic",
            "pcap": "stub",
            "counters": {},
            "connections": [],
            "open_items": []
        }"#,
    );
    // L'opérateur appelle `ingestible_entries` → liste les
    // `vtap_*.pcap` fermés, triés par nom.
    let entries = VtapSource::ingestible_entries(&dir).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], pcap);

    // Puis `read_vtap_manifest_stamp` sur chaque pcap → stamp issu
    // DU CONTENU DU MANIFESTE (jamais un défaut en dur).
    let stamp = read_vtap_manifest_stamp(&entries[0]).unwrap();
    assert_eq!(stamp.probe_id.as_deref(), Some("oiran-vtap-lab-01"));
    assert_eq!(stamp.probe_type.as_deref(), Some("vtap"));
    assert_eq!(stamp.timestamp_source.as_deref(), Some("ebpf_monotonic"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ingestion_with_missing_manifest_raises_vtap_manifest_missing_never_falls_back() {
    let dir = tmp_dir("missing");
    let pcap = dir.join("vtap_SBI_20261116T120100Z.pcap");
    std::fs::write(&pcap, b"stub-pcap").unwrap();
    // AUCUN .vtap.json à côté.
    let entries = VtapSource::ingestible_entries(&dir).unwrap();
    assert_eq!(entries.len(), 1);
    let err = read_vtap_manifest_stamp(&entries[0]).unwrap_err();
    assert!(matches!(err, VtapManifestError::Missing));
    let msg = err.to_string();
    assert!(
        msg.starts_with(VTAP_MANIFEST_MISSING),
        "msg should start with VTAP_MANIFEST_MISSING : {msg}"
    );
    // Preuve de non-régression : aucun stamp vprobe de repli n'est
    // fabriqué par la chaîne — l'appelant DOIT skip ce pcap.
    let _ = std::fs::remove_dir_all(&dir);
}

/// Validation du train 2.21.108 (ordre #9 7049622543) — les deux tests
/// ci-dessous écrivent la même variable d'environnement du processus
/// et tournent en parallèle dans ce binaire : le test « défaut » a lu
/// la valeur posée par le test « override » (1 échec sur 13 passes).
/// Ce verrou les sérialise ; un verrou empoisonné par un test en échec
/// reste utilisable.
static VTAP_OUT_DIRS_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn vtap_out_dirs_env_overrides_default_and_splits_on_comma() {
    let _env = VTAP_OUT_DIRS_ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::set_var("OIRAN_VTAP_OUT_DIRS", "/tmp/oiran-vtap-a,/tmp/oiran-vtap-b");
    let dirs = vtap_out_dirs();
    std::env::remove_var("OIRAN_VTAP_OUT_DIRS");
    assert_eq!(dirs.len(), 2);
    assert_eq!(dirs[0], PathBuf::from("/tmp/oiran-vtap-a"));
    assert_eq!(dirs[1], PathBuf::from("/tmp/oiran-vtap-b"));
}

#[test]
fn vtap_out_dirs_default_is_var_lib_oiran_vtap_when_env_absent() {
    let _env = VTAP_OUT_DIRS_ENV.lock().unwrap_or_else(|e| e.into_inner());
    std::env::remove_var("OIRAN_VTAP_OUT_DIRS");
    let dirs = vtap_out_dirs();
    assert_eq!(dirs, vec![PathBuf::from("/var/lib/oiran/vtap")]);
}

/// 2.21.7 — un `vtap_*.pcap` qui ne contient QUE l'entête pcap
/// (24 octets) est filtré **AVANT** la lecture du manifeste par
/// `ingestible_entries` ? Non — c'est `lib.rs` qui le skip. Ce test
/// prouve qu'un tel fichier est bien listé par `ingestible_entries`
/// (son filtre ne regarde que le nom), charge à l'appelant de le
/// loger comme `CONTINUOUS_VTAP_EMPTY_SKIPPED` (règle Sadok : pas
/// de garde silencieuse).
#[test]
fn ingestible_entries_lists_header_only_pcap_so_scan_can_log_empty_skipped() {
    let dir = tmp_dir("empty-visible");
    let pcap = dir.join("vtap_SBI_20261116T120000Z.pcap");
    // pcap-header-only = 24 octets exactement.
    std::fs::write(&pcap, vec![0u8; 24]).unwrap();
    let entries = VtapSource::ingestible_entries(&dir).unwrap();
    // `ingestible_entries` ne juge que le nom (contrat) —
    // c'est la boucle d'ingestion qui filtre les ≤ 24 et loge
    // `CONTINUOUS_VTAP_EMPTY_SKIPPED`. Preuve de la ligne de
    // défense : le fichier est bien vu.
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], pcap);
    let _ = std::fs::remove_dir_all(&dir);
}

/// 2.21.7 — simulation de l'écriture atomique de
/// `polaris_vtap::pcap::RotatingWriter::close` : manifeste
/// (`<pcap>.vtap.json.part` → `<pcap>.vtap.json`) écrit AVANT que
/// `<pcap>.pcap` n'apparaisse. Au moment où l'ingestion voit un
/// `vtap_*.pcap` dans l'`ingestible_entries`, le manifeste est
/// garanti présent. Test croisé : même schéma que
/// `polaris_vtap::pcap::FileManifest` (champs identiques).
#[test]
fn vtap_rotating_writer_close_schema_is_consumed_by_read_vtap_manifest_stamp() {
    let dir = tmp_dir("cross");
    let pcap = dir.join("vtap_SBI_20261116T120100Z.pcap");

    // Étape 1 — comme `RotatingWriter::close` : écrire le
    // manifeste AVANT le pcap. On utilise le même suffixe `.part`
    // + rename pour prouver la séquence.
    let manifest_path = append_vtap_manifest_suffix(&pcap);
    let manifest_part = PathBuf::from(format!("{}.part", manifest_path.display()));
    let manifest_body = serde_json::json!({
        "schema": "polaris.vtap.manifest.v1",
        "agent_version": "2.21.4-stub",
        "probe_id": "oiran-vtap-lab-01",
        "probe_type": "vtap",
        "interface": "SBI",
        "timestamp_source": "ebpf_monotonic",
        "pcap": "vtap_SBI_20261116T120100Z.pcap",
        "counters": {},
        "connections": [],
        "open_items": []
    })
    .to_string();
    std::fs::write(&manifest_part, manifest_body.as_bytes()).unwrap();
    std::fs::rename(&manifest_part, &manifest_path).unwrap();
    // Étape 2 — le pcap n'arrive qu'après : garantit que l'ordre
    // de visibilité (manifeste puis pcap) attendu par le lecteur
    // est respecté.
    std::fs::write(&pcap, vec![0u8; 100]).unwrap();

    // Au moment où la boucle d'ingestion scanne le répertoire,
    // elle voit le pcap ET le manifeste à côté.
    let entries = VtapSource::ingestible_entries(&dir).unwrap();
    assert_eq!(entries.len(), 1);
    let stamp = read_vtap_manifest_stamp(&entries[0]).unwrap();
    assert_eq!(stamp.probe_id.as_deref(), Some("oiran-vtap-lab-01"));
    assert_eq!(stamp.probe_type.as_deref(), Some("vtap"));
    assert_eq!(stamp.timestamp_source.as_deref(), Some("ebpf_monotonic"));
    assert!(stamp.physical_link.is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ingestible_entries_filters_pcap_part_so_vtap_scan_never_picks_an_open_file() {
    let dir = tmp_dir("part");
    // 2 pcaps fermés + 1 .pcap.part (en cours d'écriture) + 1
    // .vtap.json orphelin : seuls les 2 fermés sont retournés.
    std::fs::write(dir.join("vtap_SBI_20261116T120000Z.pcap"), b"ok").unwrap();
    std::fs::write(dir.join("vtap_SBI_20261116T120100Z.pcap"), b"ok").unwrap();
    std::fs::write(dir.join("vtap_SBI_20261116T120200Z.pcap.part"), b"open").unwrap();
    std::fs::write(dir.join("vtap_SBI_20261116T120200Z.vtap.json"), b"{}").unwrap();
    let entries = VtapSource::ingestible_entries(&dir).unwrap();
    assert_eq!(entries.len(), 2);
    for e in &entries {
        let name = e.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("vtap_"));
        assert!(name.ends_with(".pcap"));
        assert!(!name.ends_with(".pcap.part"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}
