//! Écriture pcap (nanosecondes, LINKTYPE_ETHERNET) avec rotation atomique :
//! le fichier courant s'écrit en `.pcap.part` puis est renommé `.pcap` à
//! la fermeture — le watcher d'ingestion ne lit jamais un fichier ouvert
//! (invariant 2.19.x). Un manifeste JSON accompagne chaque fichier.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::synth::{ConnManifest, Counters, SynthPacket};

pub const PCAP_MAGIC_NS: u32 = 0xa1b2_3c4d;
pub const LINKTYPE_ETHERNET: u32 = 1;

pub fn global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&PCAP_MAGIC_NS.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    h[16..20].copy_from_slice(&262_144u32.to_le_bytes());
    h[20..24].copy_from_slice(&LINKTYPE_ETHERNET.to_le_bytes());
    h
}

pub fn record(packet: &SynthPacket) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + packet.frame.len());
    r.extend_from_slice(&((packet.ts_ns / 1_000_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&((packet.ts_ns % 1_000_000_000) as u32).to_le_bytes());
    let len = packet.frame.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&packet.frame);
    r
}

/// Manifeste écrit à côté de chaque pcap (`<nom>.vtap.json`). Ne contient
/// aucune identité ni charge utile : topologie, compteurs, points OUVERTS.
#[derive(Serialize)]
pub struct FileManifest<'a> {
    pub schema: &'static str,
    pub agent_version: &'static str,
    pub probe_id: &'a str,
    pub probe_type: &'static str,
    pub interface: &'static str,
    pub timestamp_source: &'static str,
    pub pcap: String,
    pub counters: &'a Counters,
    pub connections: Vec<ConnManifest>,
    /// Points OUVERTS détectés sur ce fichier (jamais masqués).
    pub open_items: Vec<String>,
}

pub struct RotatingWriter {
    dir: PathBuf,
    prefix: String,
    current: Option<(PathBuf, BufWriter<File>)>,
}

impl RotatingWriter {
    pub fn new(dir: impl Into<PathBuf>, prefix: impl Into<String>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            prefix: prefix.into(),
            current: None,
        })
    }

    /// Ouvre un nouveau fichier `.part` horodaté (nom fourni par l'appelant).
    pub fn open(&mut self, stamp: &str) -> std::io::Result<()> {
        let path = self.dir.join(format!("{}_{}.pcap.part", self.prefix, stamp));
        let mut w = BufWriter::new(File::create(&path)?);
        w.write_all(&global_header())?;
        self.current = Some((path, w));
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.current.is_some()
    }

    pub fn write(&mut self, packets: &[SynthPacket]) -> std::io::Result<()> {
        if let Some((_, w)) = self.current.as_mut() {
            for p in packets {
                w.write_all(&record(p))?;
            }
        }
        Ok(())
    }

    /// Ferme, renomme `.part` → `.pcap` et écrit le manifeste JSON.
    pub fn close(&mut self, manifest: impl FnOnce(&Path) -> String) -> std::io::Result<Option<PathBuf>> {
        let Some((part, mut w)) = self.current.take() else {
            return Ok(None);
        };
        w.flush()?;
        drop(w);
        let final_path = part.with_extension("");
        std::fs::rename(&part, &final_path)?;
        let json_path = final_path.with_extension("vtap.json");
        std::fs::write(&json_path, manifest(&final_path))?;
        Ok(Some(final_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_nanosecond_ethernet_pcap() {
        let h = global_header();
        assert_eq!(&h[0..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
        assert_eq!(u32::from_le_bytes(h[20..24].try_into().unwrap()), 1);
    }

    #[test]
    fn rotation_renames_part_atomically_and_writes_manifest() {
        let dir = std::env::temp_dir().join(format!("vtap-rot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut w = RotatingWriter::new(&dir, "vtap_SBI").unwrap();
        w.open("20261116T150000Z").unwrap();
        assert!(dir.join("vtap_SBI_20261116T150000Z.pcap.part").exists());
        w.write(&[SynthPacket { ts_ns: 1, frame: vec![0u8; 60] }]).unwrap();
        let out = w.close(|_| "{}".into()).unwrap().unwrap();
        assert_eq!(out, dir.join("vtap_SBI_20261116T150000Z.pcap"));
        assert!(!dir.join("vtap_SBI_20261116T150000Z.pcap.part").exists());
        assert!(dir.join("vtap_SBI_20261116T150000Z.vtap.json").exists());
        assert_eq!(std::fs::metadata(&out).unwrap().len(), 24 + 16 + 60);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
