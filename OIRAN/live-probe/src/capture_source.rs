//! 2.20.0 — trait `CaptureSource` + `PcapRotatingSource` iso-comportement.
//!
//! Design : `OIRAN/docs/architecture/PHASE1-2.md` §3.1. Ce module ne
//! change AUCUN comportement runtime : `PcapRotatingSource` enveloppe
//! simplement les chemins existants (rotation-watcher →
//! `process_continuous_capture_inner` → `publish_events_to_dataset_dir`).
//!
//! Le pipeline live `LiveInterfaceSource` (AF_PACKET TPACKET_V3 +
//! PACKET_FANOUT) et la publication incrémentale `commit_seq`
//! arriveront en **2.20.1**. Cette première release pose uniquement
//! la fondation modulaire pour que :
//!   1. Le wiring 2.20.1 soit un ajout d'implémentation, pas un
//!      changement structurel.
//!   2. Les tests d'iso-comportement 2.19.x vs 2.20.0 passent sans
//!      modification (mêmes sessions, mêmes ids, mêmes call flows).
//!   3. Le type `CaptureSourceKind` soit déjà exposé dans la config
//!      `polaris.toml` (`engine = "pcap_rotating"` par défaut).
//!
//! Un `CaptureSource` est SELF-CONTAINED : il connaît son
//! `probe_id`, le `CaptureInterface` qu'il écoute (BPF + device), et
//! le mode `timestamp_source` (`kernel` par défaut). À l'exécution
//! il émet les events normalisés vers un sink partagé avec le
//! pipeline actuel.
//!
//! Contrat de progression (conforme au design doc) :
//! - **2.20.0** (ce lot) : trait + `PcapRotatingSource` stub, non
//!   câblé dans le capture path. Les binaires `oiran-live-probe` et
//!   `oiran-api` continuent de passer par le chemin 2.19.x.
//! - **2.20.1** : `LiveInterfaceSource` (TPACKET_V3), publication
//!   incrémentale `commit_seq`, bench O1.
//! - **2.20.2** : retrait de la rotation horaire **uniquement si**
//!   R1.a (latence E2E médiane ≤ 2 s sur 24 h) prouvé.

use std::path::PathBuf;

use crate::CaptureInterface;

/// Identifie la nature de la sonde source. Reflète la clé
/// `probes[].engine` de `polaris.toml`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureSourceKind {
    /// Rotation horaire via `dumpcap -b duration:3600` + watcher
    /// (comportement 2.19.x inchangé).
    PcapRotating,
    /// AF_PACKET TPACKET_V3 + PACKET_FANOUT (livré en 2.20.1).
    LiveInterface,
    /// XDP socket (prévu, hors scope PHASE 1).
    AfXdp,
    /// DPDK UIO/VFIO 400 Gbit/s (prévu, hors scope PHASE 1).
    Dpdk,
}

impl CaptureSourceKind {
    /// Mapping texte ↔ enum pour `polaris.toml`. Insensible à la
    /// casse. Un engine inconnu → `None` (le loader renvoie une
    /// erreur avec le texte d'origine pour aider l'opérateur).
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "pcap_rotating" | "pcap" => Some(Self::PcapRotating),
            "live_pcap" | "live_interface" | "af_packet" => Some(Self::LiveInterface),
            "af_xdp" | "xdp" => Some(Self::AfXdp),
            "dpdk" => Some(Self::Dpdk),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PcapRotating => "pcap_rotating",
            Self::LiveInterface => "live_interface",
            Self::AfXdp => "af_xdp",
            Self::Dpdk => "dpdk",
        }
    }

    pub fn probe_type(self) -> &'static str {
        // 2.20.0 — PcapRotating et LiveInterface sont vProbe
        // (bridges Docker br-oiran-*) ; AF_XDP et DPDK sont les
        // modes physiques pour sondes PRO.
        match self {
            Self::PcapRotating | Self::LiveInterface => "vprobe",
            Self::AfXdp | Self::Dpdk => "phy",
        }
    }
}

/// Source d'où proviennent les paquets avant décodage. Deux rôles
/// par le type d'implémentation :
/// * `PcapRotatingSource` : lit des `.pcapng` déjà fermés par
///   dumpcap (chemin 2.19.x, ingestion batch).
/// * `LiveInterfaceSource` (à venir en 2.20.1) : attache une
///   `PACKET_RX_RING` TPACKET_V3 et émet paquet-par-paquet.
pub trait CaptureSource: Send + Sync {
    /// Identifiant stable (probe_id × interface_label).
    fn id(&self) -> &str;
    /// Spec de l'interface (device, BPF, protocole, label plane).
    fn spec(&self) -> &CaptureInterface;
    /// Type de source, sert à remplir `event.probe_type` et
    /// à auditer le pipeline.
    fn kind(&self) -> CaptureSourceKind;
    /// Source d'horodatage utilisée pour emit `event.timestamp_source`.
    /// 2.20.0 : `"kernel"` par défaut (SO_TIMESTAMPNS). 2.20.1 :
    /// exposera `"hw_ptp"` quand SO_TIMESTAMPING + PHC est actif.
    fn timestamp_source(&self) -> &str {
        "kernel"
    }
    /// Identifiant physique de la carte/port (`enp4s0f1np1`,
    /// `0000:04:00.1`, …). Rempli uniquement en `phy`.
    fn physical_link(&self) -> Option<&str> {
        None
    }
    /// `probe_id` propagé sur chaque event. Un seul `probe_id` par
    /// sonde ; plusieurs interfaces d'une même sonde partagent le
    /// même `probe_id`.
    fn probe_id(&self) -> &str;
}

/// Implémentation 2.20.0 : enveloppe iso-comportement du chemin
/// rotation-watcher 2.19.x. **Non câblée** dans le pipeline actif ;
/// uniquement présente pour poser la fondation modulaire. Le
/// pipeline 2.19.x reste opérationnel.
pub struct PcapRotatingSource {
    id: String,
    probe_id: String,
    spec: CaptureInterface,
    /// Répertoire où dumpcap rotate ses `.pcapng`. Lecture seule
    /// par le watcher ; `PcapRotatingSource` ne touche pas au
    /// fichier ouvert (dernier `.pcapng` non-fermé) — invariant
    /// 2.19.x conservé.
    rotation_dir: PathBuf,
}

impl PcapRotatingSource {
    pub fn new(
        probe_id: impl Into<String>,
        spec: CaptureInterface,
        rotation_dir: impl Into<PathBuf>,
    ) -> Self {
        let probe_id = probe_id.into();
        let id = format!("{}:{}", probe_id, spec.interface);
        Self {
            id,
            probe_id,
            spec,
            rotation_dir: rotation_dir.into(),
        }
    }

    pub fn rotation_dir(&self) -> &PathBuf {
        &self.rotation_dir
    }
}

impl CaptureSource for PcapRotatingSource {
    fn id(&self) -> &str {
        &self.id
    }
    fn spec(&self) -> &CaptureInterface {
        &self.spec
    }
    fn kind(&self) -> CaptureSourceKind {
        CaptureSourceKind::PcapRotating
    }
    fn probe_id(&self) -> &str {
        &self.probe_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CaptureInterface;

    fn spec(interface: &str, device: &str) -> CaptureInterface {
        CaptureInterface {
            interface: interface.into(),
            role: None,
            device: device.into(),
            protocol: "X".into(),
            capture_point: "test".into(),
            bpf_filter: "tcp port 7777".into(),
            available: true,
            operstate: "up".into(),
            reason: None,
        }
    }

    #[test]
    fn capture_source_kind_parses_canonical_and_aliases() {
        assert_eq!(
            CaptureSourceKind::parse("pcap_rotating"),
            Some(CaptureSourceKind::PcapRotating)
        );
        assert_eq!(
            CaptureSourceKind::parse("pcap"),
            Some(CaptureSourceKind::PcapRotating)
        );
        assert_eq!(
            CaptureSourceKind::parse("LIVE_PCAP"),
            Some(CaptureSourceKind::LiveInterface)
        );
        assert_eq!(
            CaptureSourceKind::parse("af_packet"),
            Some(CaptureSourceKind::LiveInterface)
        );
        assert_eq!(
            CaptureSourceKind::parse("af_xdp"),
            Some(CaptureSourceKind::AfXdp)
        );
        assert_eq!(
            CaptureSourceKind::parse("dpdk"),
            Some(CaptureSourceKind::Dpdk)
        );
        assert!(CaptureSourceKind::parse("unknown_engine").is_none());
    }

    #[test]
    fn capture_source_kind_round_trip_and_probe_type() {
        for kind in [
            CaptureSourceKind::PcapRotating,
            CaptureSourceKind::LiveInterface,
            CaptureSourceKind::AfXdp,
            CaptureSourceKind::Dpdk,
        ] {
            let s = kind.as_str();
            assert_eq!(CaptureSourceKind::parse(s), Some(kind), "round-trip {s}");
        }
        assert_eq!(CaptureSourceKind::PcapRotating.probe_type(), "vprobe");
        assert_eq!(CaptureSourceKind::LiveInterface.probe_type(), "vprobe");
        assert_eq!(CaptureSourceKind::AfXdp.probe_type(), "phy");
        assert_eq!(CaptureSourceKind::Dpdk.probe_type(), "phy");
    }

    #[test]
    fn pcap_rotating_source_fills_id_probe_and_defaults() {
        let src = PcapRotatingSource::new(
            "lab-vprobe",
            spec("N2", "br-oiran-n2"),
            "/tmp/pcap-rotation",
        );
        assert_eq!(src.id(), "lab-vprobe:N2");
        assert_eq!(src.probe_id(), "lab-vprobe");
        assert_eq!(src.kind(), CaptureSourceKind::PcapRotating);
        assert_eq!(src.timestamp_source(), "kernel");
        assert!(src.physical_link().is_none());
        assert_eq!(src.spec().interface, "N2");
        assert_eq!(src.spec().device, "br-oiran-n2");
    }

    /// 2.20.0 — un `Box<dyn CaptureSource>` compile et dispatche
    /// correctement : la fondation est prête pour accueillir
    /// `LiveInterfaceSource` en 2.20.1 sans toucher au trait.
    #[test]
    fn capture_source_trait_object_dispatches() {
        let src: Box<dyn CaptureSource> = Box::new(PcapRotatingSource::new(
            "lab-vprobe",
            spec("SBI", "br-oiran-sbi"),
            "/tmp",
        ));
        assert_eq!(src.id(), "lab-vprobe:SBI");
        assert_eq!(src.kind().as_str(), "pcap_rotating");
    }
}
