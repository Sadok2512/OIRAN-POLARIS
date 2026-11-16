//! 2.20.1 — publication incrémentale avec marker `commit_seq`.
//!
//! Design : `OIRAN/docs/architecture/PHASE1-2.md` §3.2.
//!
//! Chaque dataset porte un fichier `commit_seq.txt` à côté de
//! `oiran_events.jsonl` et `dataset_manifest.json`. Le fichier
//! contient **une seule ligne** : un entier u64 décimal
//! monotoniquement croissant par publication. `publish_events_to_dataset_dir`
//! incrémente cette valeur après chaque écriture atomique réussie
//! du JSONL + du manifest. Les lecteurs (API `ListRowCache`,
//! `cached_live_list_row`, `callflow_file_signature`) incluent
//! `commit_seq` dans la clé de cache : un marker qui change force
//! l'invalidation, un marker stable permet un cache-hit O(1).
//!
//! Contrat de vie privée : le fichier NE contient JAMAIS d'identité
//! — seulement un entier. Jamais logué individuellement (apparaît
//! dans les traces structurées de publication aux côtés du
//! `dataset_id`).
//!
//! Invariant iso-comportement 2.19.x : si `commit_seq.txt` est
//! absent, `read()` retourne `0` et les lecteurs se replient sur
//! leur signature précédente (size+mtime). Aucun effet de bord sur
//! les datasets existants.

use std::path::Path;

/// Nom du fichier marker, posé dans chaque répertoire dataset à
/// côté de `oiran_events.jsonl`.
pub const COMMIT_SEQ_FILENAME: &str = "commit_seq.txt";

/// Lit `commit_seq.txt` dans `dataset_dir`. Fichier absent ou vide
/// → `0` (pas d'erreur : chemin iso-comportement 2.19.x). Lecture
/// invalide (non parsable) → `0` aussi, pour ne jamais bloquer un
/// lecteur.
pub fn read(dataset_dir: &Path) -> u64 {
    let path = dataset_dir.join(COMMIT_SEQ_FILENAME);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return 0;
    };
    text.trim().parse::<u64>().unwrap_or(0)
}

/// Écrit `seq` de manière atomique : tempfile + rename. Appel
/// typique côté `publish_events_to_dataset_dir` juste après la
/// mise à jour atomique du manifest.
pub fn write(dataset_dir: &Path, seq: u64) -> Result<(), String> {
    let path = dataset_dir.join(COMMIT_SEQ_FILENAME);
    let tmp = dataset_dir.join(format!(".{COMMIT_SEQ_FILENAME}.tmp"));
    std::fs::write(&tmp, format!("{seq}\n"))
        .map_err(|e| format!("commit_seq temp write: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("commit_seq rename: {e}"))?;
    Ok(())
}

/// Lit `seq`, l'incrémente, puis écrit la nouvelle valeur. Retourne
/// la valeur publiée. Utilisé par `publish_events_to_dataset_dir`
/// chaque fois qu'un batch d'events est publié avec succès.
pub fn bump_and_write(dataset_dir: &Path) -> Result<u64, String> {
    let next = read(dataset_dir).saturating_add(1);
    write(dataset_dir, next)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(prefix: &str) -> std::path::PathBuf {
        let base = std::path::PathBuf::from(format!(
            "/tmp/oiran-commit-seq-{prefix}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn read_returns_zero_when_commit_seq_file_absent() {
        let dir = tmp_dir("absent");
        // Cleanup first — the previous run might have left a file.
        let _ = std::fs::remove_file(dir.join(COMMIT_SEQ_FILENAME));
        assert_eq!(read(&dir), 0);
    }

    #[test]
    fn write_then_read_round_trips_the_sequence() {
        let dir = tmp_dir("rw");
        write(&dir, 42).unwrap();
        assert_eq!(read(&dir), 42);
        write(&dir, 1_000_000).unwrap();
        assert_eq!(read(&dir), 1_000_000);
    }

    #[test]
    fn bump_increments_from_zero_or_prior() {
        let dir = tmp_dir("bump");
        let _ = std::fs::remove_file(dir.join(COMMIT_SEQ_FILENAME));
        assert_eq!(bump_and_write(&dir).unwrap(), 1);
        assert_eq!(bump_and_write(&dir).unwrap(), 2);
        assert_eq!(bump_and_write(&dir).unwrap(), 3);
        assert_eq!(read(&dir), 3);
    }

    /// Un `commit_seq.txt` corrompu (ligne non-entier) ne bloque
    /// jamais un lecteur : fallback à 0, iso-comportement.
    #[test]
    fn read_returns_zero_on_corrupted_file() {
        let dir = tmp_dir("corrupt");
        std::fs::write(dir.join(COMMIT_SEQ_FILENAME), "not-a-number\n").unwrap();
        assert_eq!(read(&dir), 0);
    }
}
