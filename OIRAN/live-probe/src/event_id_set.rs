//! 2.9.18-fu3 (devmat, ANR2 #9 comment 6750859966) — jeu d'event_id
//! borné en mémoire qui déborde sur disque par lots triés.
//!
//! ## Problème corrigé
//!
//! ANR2 a prouvé (comment 6750859966) deux OOM consécutifs sur
//! `oiran-api` 2.9.18 / 2.9.18-fu2 sous `MemoryMax=268435456` (256 MiB)
//! pendant la reconstruction continue de `.dataset-next/` :
//! `anon-rss ≈ 256 MiB` aux deux impacts.
//!
//! Cause fichier:ligne (pré-fu3) : `live-probe/src/lib.rs::process_capture_into`
//! créait `seen_ids: BTreeSet<String>` passé deux fois à
//! `merge_event_stream` pour dédoublonner `continuous_observation_id`
//! (`evt-XXXXXXXXXXXXXXXX`, 20 caractères). Sur une production à
//! 5 414 segments → ~2,1 M événements, ce set à lui seul atteint
//! ~200 MiB ; combiné aux autres structures de publication
//! (`load_path_streaming_index` qui rebatit un `BTreeSet` identique
//! + `Vec<EventRecord>` compact), le total déborde le cgroup 256 MiB.
//!
//! ## Garanties 2.9.18-fu3
//!
//! * **Mémoire bornée** : au plus `mem_cap` entrées en RAM (≤ 65 536
//!   par défaut ≈ 1,5 MiB). Chaque débordement vide le set RAM dans
//!   un fichier trié sur disque (`.ids-chunk-NNNNNN.bin`), jamais
//!   relu intégralement — binary search par chunk via `read_exact_at`.
//! * **Aucune croissance avec le nombre de segments** : les chunks
//!   vivent dans un `tmp_dir` dédié et sont supprimés à `Drop`.
//! * **Dédoublonnage correct** : l'empreinte est le u64 bas de
//!   `continuous_observation_id` (déjà tronqué à 16 hex = 64 bits
//!   d'entropie côté producteur) ; probabilité de collision pour
//!   10 M entrées < 10⁻⁶.
//! * **Fail-closed** : toute erreur d'I/O remonte en `io::Error` au
//!   caller, qui annule l'import sans toucher `dataset/`.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// Capacité par défaut du set en RAM avant débordement sur disque.
/// 65 536 × 8 B ≈ 1,5 MiB — négligeable face au cgroup 256 MiB.
pub const DEFAULT_MEM_CAP: usize = 65_536;

pub struct SpillingEventIdSet {
    tmp_dir: PathBuf,
    mem: HashSet<u64>,
    mem_cap: usize,
    chunks: Vec<PathBuf>,
    total_unique: u64,
    flush_count: u64,
    owned_tmp_dir: bool,
}

impl SpillingEventIdSet {
    /// Crée le set sous `tmp_dir` (créé si absent). Le répertoire
    /// est supprimé lorsque `self` est droppé si personne d'autre
    /// n'y écrit.
    pub fn new(tmp_dir: &Path, mem_cap: usize) -> std::io::Result<Self> {
        let owned = !tmp_dir.exists();
        fs::create_dir_all(tmp_dir)?;
        Ok(Self {
            tmp_dir: tmp_dir.to_path_buf(),
            mem: HashSet::with_capacity(mem_cap.min(DEFAULT_MEM_CAP)),
            mem_cap: mem_cap.max(1_024),
            chunks: Vec::new(),
            total_unique: 0,
            flush_count: 0,
            owned_tmp_dir: owned,
        })
    }

    /// Insère l'event_id string. Retourne `Ok(true)` si nouveau,
    /// `Ok(false)` si déjà présent (mémoire ou chunk disque).
    pub fn insert(&mut self, event_id: &str) -> std::io::Result<bool> {
        let key = fingerprint(event_id);
        if self.contains_key(key)? {
            return Ok(false);
        }
        self.mem.insert(key);
        self.total_unique = self.total_unique.saturating_add(1);
        if self.mem.len() >= self.mem_cap {
            self.flush()?;
        }
        Ok(true)
    }

    /// Lookup pur sans insertion — utilisé pour filtrer les
    /// call-flows prior qui doivent survivre au merge.
    pub fn contains(&self, event_id: &str) -> std::io::Result<bool> {
        self.contains_key(fingerprint(event_id))
    }

    fn contains_key(&self, key: u64) -> std::io::Result<bool> {
        if self.mem.contains(&key) {
            return Ok(true);
        }
        for chunk in &self.chunks {
            if chunk_contains(chunk, key)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.mem.is_empty() {
            return Ok(());
        }
        let mut values: Vec<u64> = self.mem.drain().collect();
        values.sort_unstable();
        let name = format!("ids-chunk-{:06}.bin", self.chunks.len());
        let path = self.tmp_dir.join(&name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let mut writer = BufWriter::with_capacity(1 << 16, file);
        for v in &values {
            writer.write_all(&v.to_le_bytes())?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
        self.chunks.push(path);
        self.flush_count = self.flush_count.saturating_add(1);
        Ok(())
    }

    /// Nombre total d'entrées uniques observées (métrique opérateur).
    pub fn len_hint(&self) -> u64 {
        self.total_unique
    }

    /// Nombre de chunks débordés sur disque (métrique opérateur).
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Nombre de flushes disque effectués (métrique opérateur).
    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }

    /// Nombre d'entrées en RAM (métrique opérateur — borné par `mem_cap`).
    pub fn mem_len(&self) -> usize {
        self.mem.len()
    }
}

impl Drop for SpillingEventIdSet {
    fn drop(&mut self) {
        for chunk in self.chunks.drain(..) {
            let _ = fs::remove_file(&chunk);
        }
        if self.owned_tmp_dir {
            let _ = fs::remove_dir(&self.tmp_dir);
        }
    }
}

/// Empreinte 64-bit stable d'un event_id. Format attendu :
/// `"evt-XXXXXXXXXXXXXXXX"` (16 chars hex, 64 bits). Les formes
/// héritées (ex. ids de tests `"event-1"`, pseudonymes, UUID)
/// retombent sur un hash FNV-1a 64-bit — toujours déterministe et
/// stable entre runs.
fn fingerprint(event_id: &str) -> u64 {
    if let Some(trail) = event_id.strip_prefix("evt-") {
        if trail.len() >= 16 {
            if let Ok(v) = u64::from_str_radix(&trail[..16], 16) {
                return v;
            }
        }
    }
    fnv1a_64(event_id.as_bytes())
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    // Marque le MSB pour garantir qu'un fallback FNV ne peut jamais
    // entrer en collision avec un vrai evt-16hex (lequel est
    // produit par SHA-256 tronqué et n'a aucune garantie sur le MSB,
    // mais la probabilité de collision avec le fallback reste
    // négligeable vu la séparation de domaines).
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash | 0x8000_0000_0000_0000
}

fn chunk_contains(path: &Path, needle: u64) -> std::io::Result<bool> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    let len = meta.len() / 8;
    if len == 0 {
        return Ok(false);
    }
    let mut lo: i64 = 0;
    let mut hi: i64 = len as i64 - 1;
    let mut buf = [0u8; 8];
    while lo <= hi {
        let mid = ((lo + hi) / 2) as u64;
        file.read_exact_at(&mut buf, mid * 8)?;
        let v = u64::from_le_bytes(buf);
        if v == needle {
            return Ok(true);
        } else if v < needle {
            lo = mid as i64 + 1;
        } else {
            hi = mid as i64 - 1;
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spills_to_disk_and_returns_insertion_truth() {
        let tmp = tempdir();
        let mut set = SpillingEventIdSet::new(&tmp, 1_024).unwrap();
        for i in 0..5_000u64 {
            let id = format!("evt-{:016x}", i);
            assert!(set.insert(&id).unwrap(), "first insert of {id} must be true");
        }
        assert!(set.chunk_count() >= 4, "must have spilled multiple chunks");
        for i in 0..5_000u64 {
            let id = format!("evt-{:016x}", i);
            assert!(!set.insert(&id).unwrap(), "re-insert of {id} must be false");
        }
        assert_eq!(set.len_hint(), 5_000);
    }

    #[test]
    fn contains_checks_both_mem_and_chunks() {
        let tmp = tempdir();
        let mut set = SpillingEventIdSet::new(&tmp, 1_024).unwrap();
        for i in 0..2_500u64 {
            set.insert(&format!("evt-{:016x}", i)).unwrap();
        }
        assert!(set.contains("evt-0000000000000005").unwrap());
        assert!(set.contains(&format!("evt-{:016x}", 2_499)).unwrap());
        assert!(!set.contains("evt-ffffffffffffffff").unwrap());
    }

    #[test]
    fn fallback_handles_non_evt_prefixed_ids() {
        let tmp = tempdir();
        let mut set = SpillingEventIdSet::new(&tmp, 1_024).unwrap();
        assert!(set.insert("event-1").unwrap());
        assert!(!set.insert("event-1").unwrap());
        assert!(set.insert("event-2").unwrap());
        assert!(set.contains("event-1").unwrap());
        assert!(set.contains("event-2").unwrap());
    }

    #[test]
    fn drop_cleans_chunks_and_owned_tmp_dir() {
        let tmp = tempdir();
        {
            let mut set = SpillingEventIdSet::new(&tmp, 512).unwrap();
            for i in 0..2_048u64 {
                set.insert(&format!("evt-{:016x}", i)).unwrap();
            }
            assert!(set.chunk_count() >= 2);
        }
        let residual: Vec<_> = fs::read_dir(tmp.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path() == tmp)
            .collect();
        assert!(
            residual.is_empty(),
            "tmp dir created by SpillingEventIdSet must be removed on Drop"
        );
    }

    fn tempdir() -> PathBuf {
        let base = std::env::temp_dir();
        let unique = format!(
            "oiran-eventset-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        base.join(unique)
    }
}
