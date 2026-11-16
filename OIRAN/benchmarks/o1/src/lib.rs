//! 2.23.0 — harnais du bench O1.
//!
//! Deux fonctions publiques :
//!
//! * [`amplify`] — primitives de réécriture de champs d'identité
//!   (IMSI, MSISDN, IMEI, TEID, SEID, NGAP IDs) dans un buffer à
//!   partir d'un index UE source → UE cible. Sans parse pcap complet
//!   (ça viendra en 2.23.1) : ces fonctions travaillent sur des
//!   `&mut [u8]` + patterns bien localisés et sont testables unitairement.
//!
//! * [`replay`] — rejoue un pcap sur N workers en parallèle, mesure
//!   paquets/s, Gbit/s (sur `original_length`), events/s, RSS max,
//!   efficacité de montée en charge `débit_N / (N × débit_1)`.
//!
//! Invariant privacy : les fonctions `amplify` ne **créent** que des
//! identités synthétiques (MCC/MNC 001/01 + MSIN généré à partir d'un
//! `ue_index`). Elles ne lisent jamais une identité du pcap source —
//! c'est l'appelant qui fournit la paire `(source_bytes, target_bytes)`.
//! Le binaire CLI (`main.rs`) garantit cette règle en rejetant tout
//! pattern IMSI/MSISDN/IMEI qui apparaît dans la sortie et qui n'était
//! **pas** présent dans l'index synthétique.

pub mod amplify;
pub mod replay;

pub use amplify::{
    build_synthetic_ue, replace_bytes_all, synthesize_imei, synthesize_imsi, synthesize_msisdn,
    teid_offset, SyntheticUe,
};
pub use replay::{run_replay, ReplayConfig, ReplayReport, WorkerReport};
