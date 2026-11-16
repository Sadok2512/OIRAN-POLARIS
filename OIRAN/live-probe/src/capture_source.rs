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

use std::path::{Path, PathBuf};

use event_schema::ProbeStamp;

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
    /// 2.21.0 (P1b) — vTAP eBPF : uprobes libssl dans les NF, HTTP/2
    /// SBI en clair rejoué en pcap TCP par l'agent `polaris-vtap`
    /// (`OIRAN/vtap`). Sonde logicielle : ni vProbe bridge ni phy.
    Vtap,
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
            "vtap" | "ebpf_tls" => Some(Self::Vtap),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PcapRotating => "pcap_rotating",
            Self::LiveInterface => "live_interface",
            Self::AfXdp => "af_xdp",
            Self::Dpdk => "dpdk",
            Self::Vtap => "vtap",
        }
    }

    pub fn probe_type(self) -> &'static str {
        // 2.20.0 — PcapRotating et LiveInterface sont vProbe
        // (bridges Docker br-oiran-*) ; AF_XDP et DPDK sont les
        // modes physiques pour sondes PRO.
        match self {
            Self::PcapRotating | Self::LiveInterface => "vprobe",
            Self::AfXdp | Self::Dpdk => "phy",
            Self::Vtap => "vtap",
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

    /// 2.21.1 — compose un `event_schema::ProbeStamp` depuis la
    /// source. Appelé par `oiran-decode::write_jsonl_stamped` et par
    /// le pipeline live pour apposer la même identité de sonde sur
    /// chaque event émis par cette source. Les champs
    /// `probe_id`/`probe_type`/`timestamp_source`/`physical_link`
    /// viennent directement du trait, jamais fabriqués côté appelant.
    fn to_probe_stamp(&self) -> ProbeStamp {
        ProbeStamp {
            probe_id: Some(self.probe_id().to_owned()),
            probe_type: Some(self.kind().probe_type().to_owned()),
            physical_link: self.physical_link().map(ToOwned::to_owned),
            timestamp_source: Some(self.timestamp_source().to_owned()),
        }
    }
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

/// 2.20.1 — paramètres `tpacket_req3` publiés dans `/health` et
/// réutilisés pour ouvrir l'anneau. Valeurs par défaut issues du
/// design doc §3.1 : latence block-level ≤ 10 ms, buffer 256 MiB
/// par interface (`block_size * block_nr = 4 MiB * 64`), frame
/// size 2 KiB (MTU + marge).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tpacketv3Params {
    pub block_size: u32,
    pub block_nr: u32,
    pub frame_size: u32,
    pub retire_blk_tov_ms: u32,
    pub feature_req_word: u32,
}

impl Default for Tpacketv3Params {
    fn default() -> Self {
        Self {
            block_size: 4 * 1024 * 1024,
            block_nr: 64,
            frame_size: 2048,
            retire_blk_tov_ms: 10,
            // TP_FT_REQ_FILL_RXHASH = 1 ; nous demandons le rxhash
            // pour PACKET_FANOUT_HASH 4-tuple.
            feature_req_word: 1,
        }
    }
}

impl Tpacketv3Params {
    pub fn buffer_bytes(&self) -> u64 {
        u64::from(self.block_size) * u64::from(self.block_nr)
    }
}

/// 2.20.1 — paramètres `PACKET_FANOUT` pour load-balancing
/// multi-threads. `fanout_id` partagé par toutes les sockets qui
/// participent au même groupe ; `PACKET_FANOUT_HASH` répartit par
/// hash 4-tuple (L4 symétrique côté noyau).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketFanoutParams {
    pub fanout_id: u16,
    pub mode: PacketFanoutMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketFanoutMode {
    Hash,
    /// `PACKET_FANOUT_LB` : round-robin (test uniquement).
    LoadBalance,
}

impl PacketFanoutMode {
    /// Valeur du haut du u32 pass'é à `setsockopt(SOL_PACKET,
    /// PACKET_FANOUT, (mode << 16) | id)`. Constants Linux
    /// `PACKET_FANOUT_HASH = 0`, `PACKET_FANOUT_LB = 1`.
    pub fn code(self) -> u16 {
        match self {
            Self::Hash => 0,
            Self::LoadBalance => 1,
        }
    }
}

impl PacketFanoutParams {
    pub fn setsockopt_value(&self) -> u32 {
        (u32::from(self.mode.code()) << 16) | u32::from(self.fanout_id)
    }
}

/// 2.20.1 — erreurs d'ouverture de `LiveInterfaceSource`. Les cas
/// opérateur (CAP_NET_RAW manquant, interface absente) sont
/// typés pour que le healthcheck sache qu'il doit remonter
/// `MISSING_CAP_NET_RAW` au lieu de « Linux generic ».
#[derive(Debug)]
pub enum LiveInterfaceError {
    NonLinuxBuild,
    MissingCapNetRaw(std::io::Error),
    InterfaceNotFound(String),
    SocketOpen(std::io::Error),
    SetsockoptVersion(std::io::Error),
    SetsockoptRing(std::io::Error),
    SetsockoptFanout(std::io::Error),
    SetsockoptTimestamping(std::io::Error),
    Bind(std::io::Error),
    MmapRing(std::io::Error),
}

impl std::fmt::Display for LiveInterfaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonLinuxBuild => write!(f, "LiveInterfaceSource requires target_os=linux"),
            Self::MissingCapNetRaw(e) => write!(f, "CAP_NET_RAW missing or EACCES: {e}"),
            Self::InterfaceNotFound(name) => write!(f, "interface not found: {name}"),
            Self::SocketOpen(e) => write!(f, "AF_PACKET socket open failed: {e}"),
            Self::SetsockoptVersion(e) => write!(f, "PACKET_VERSION (TPACKET_V3) failed: {e}"),
            Self::SetsockoptRing(e) => write!(f, "PACKET_RX_RING setsockopt failed: {e}"),
            Self::SetsockoptFanout(e) => write!(f, "PACKET_FANOUT setsockopt failed: {e}"),
            Self::SetsockoptTimestamping(e) => write!(f, "SO_TIMESTAMPING setsockopt failed: {e}"),
            Self::Bind(e) => write!(f, "bind to interface failed: {e}"),
            Self::MmapRing(e) => write!(f, "mmap ring failed: {e}"),
        }
    }
}

impl std::error::Error for LiveInterfaceError {}

/// 2.20.1 — source live AF_PACKET TPACKET_V3 + PACKET_FANOUT.
/// Design doc §3.1.
///
/// Portabilité : l'ouverture socket est gated `cfg(target_os =
/// "linux")`. Sur macOS/Windows/CI non-Linux, `try_open()`
/// renvoie `NonLinuxBuild` sans tenter d'appel kernel.
///
/// En Linux sans `CAP_NET_RAW` (cas CI typique), `try_open()`
/// renvoie `MissingCapNetRaw` : les paramètres sont publiables
/// via `params()` et `fanout()` même quand la socket n'est pas
/// ouverte (pour test unitaire + inspection /health).
///
/// Snapshot `tp_drops` via `packet_statistics_v3()` (bench O1).
pub struct LiveInterfaceSource {
    id: String,
    probe_id: String,
    spec: CaptureInterface,
    params: Tpacketv3Params,
    fanout: PacketFanoutParams,
    hw_timestamping_requested: bool,
    physical_link: Option<String>,
    #[cfg(target_os = "linux")]
    socket_fd: Option<std::os::fd::OwnedFd>,
    #[cfg(not(target_os = "linux"))]
    socket_fd: Option<()>,
}

impl LiveInterfaceSource {
    pub fn new(
        probe_id: impl Into<String>,
        spec: CaptureInterface,
        params: Tpacketv3Params,
        fanout: PacketFanoutParams,
        hw_timestamping_requested: bool,
        physical_link: Option<String>,
    ) -> Self {
        let probe_id = probe_id.into();
        let id = format!("{}:{}", probe_id, spec.interface);
        Self {
            id,
            probe_id,
            spec,
            params,
            fanout,
            hw_timestamping_requested,
            physical_link,
            socket_fd: None,
        }
    }

    pub fn params(&self) -> &Tpacketv3Params {
        &self.params
    }

    pub fn fanout(&self) -> &PacketFanoutParams {
        &self.fanout
    }

    pub fn hw_timestamping_requested(&self) -> bool {
        self.hw_timestamping_requested
    }

    /// Tente d'ouvrir la socket AF_PACKET TPACKET_V3 configurée avec
    /// les params + FANOUT + SO_TIMESTAMPING (selon
    /// `hw_timestamping_requested`). Sur non-Linux ou sans
    /// CAP_NET_RAW, renvoie l'erreur typée correspondante.
    #[cfg(target_os = "linux")]
    pub fn try_open(&mut self) -> Result<(), LiveInterfaceError> {
        use std::os::fd::{FromRawFd, OwnedFd};

        // 1. Résolution de l'index d'interface.
        let device_cstr = std::ffi::CString::new(self.spec.device.clone())
            .map_err(|_| LiveInterfaceError::InterfaceNotFound(self.spec.device.clone()))?;
        let ifindex = unsafe { libc::if_nametoindex(device_cstr.as_ptr()) };
        if ifindex == 0 {
            return Err(LiveInterfaceError::InterfaceNotFound(self.spec.device.clone()));
        }
        // 2. Ouverture AF_PACKET.
        let eth_p_all: u16 = 0x0003; // libc::ETH_P_ALL is i32 ; htons on u16
        let proto = eth_p_all.to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) => {
                    LiveInterfaceError::MissingCapNetRaw(err)
                }
                _ => LiveInterfaceError::SocketOpen(err),
            });
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };

        // 3. PACKET_VERSION = TPACKET_V3.
        let version: libc::c_int = 2; // TPACKET_V3
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_VERSION,
                &version as *const _ as *const libc::c_void,
                std::mem::size_of_val(&version) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(LiveInterfaceError::SetsockoptVersion(
                std::io::Error::last_os_error(),
            ));
        }

        // 4. PACKET_RX_RING avec tpacket_req3.
        // Layout exact du struct Linux kernel (uapi/linux/if_packet.h).
        #[repr(C)]
        struct Tpacketreq3 {
            tp_block_size: u32,
            tp_block_nr: u32,
            tp_frame_size: u32,
            tp_frame_nr: u32,
            tp_retire_blk_tov: u32,
            tp_sizeof_priv: u32,
            tp_feature_req_word: u32,
        }
        let frame_nr =
            (self.params.block_size * self.params.block_nr) / self.params.frame_size;
        let req = Tpacketreq3 {
            tp_block_size: self.params.block_size,
            tp_block_nr: self.params.block_nr,
            tp_frame_size: self.params.frame_size,
            tp_frame_nr: frame_nr,
            tp_retire_blk_tov: self.params.retire_blk_tov_ms,
            tp_sizeof_priv: 0,
            tp_feature_req_word: self.params.feature_req_word,
        };
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_RX_RING,
                &req as *const _ as *const libc::c_void,
                std::mem::size_of_val(&req) as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EACCES) | Some(libc::EPERM) => {
                    LiveInterfaceError::MissingCapNetRaw(err)
                }
                _ => LiveInterfaceError::SetsockoptRing(err),
            });
        }

        // 5. PACKET_FANOUT.
        let fanout_value: i32 = self.fanout.setsockopt_value() as i32;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_FANOUT,
                &fanout_value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&fanout_value) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(LiveInterfaceError::SetsockoptFanout(
                std::io::Error::last_os_error(),
            ));
        }

        // 6. SO_TIMESTAMPING si hw_ptp demandé (fallback silencieux
        // si le driver ne supporte pas — timestamp_source bascule en
        // "kernel").
        if self.hw_timestamping_requested {
            // SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE
            // | SOF_TIMESTAMPING_RX_SOFTWARE = 0x4 | 0x40 | 0x8 = 0x4c.
            let flags: i32 = 0x4 | 0x40 | 0x8;
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_TIMESTAMPING,
                    &flags as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&flags) as libc::socklen_t,
                )
            };
            if rc != 0 {
                // Soft-fail : hw_ptp indisponible, on reste en kernel.
                let _ = std::io::Error::last_os_error();
            }
        }

        // 7. bind(sockaddr_ll) sur l'interface + protocole.
        #[repr(C)]
        #[derive(Default)]
        struct SockaddrLl {
            sll_family: u16,
            sll_protocol: u16,
            sll_ifindex: i32,
            sll_hatype: u16,
            sll_pkttype: u8,
            sll_halen: u8,
            sll_addr: [u8; 8],
        }
        let addr = SockaddrLl {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: eth_p_all.to_be(),
            sll_ifindex: ifindex as i32,
            ..Default::default()
        };
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrLl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(LiveInterfaceError::Bind(std::io::Error::last_os_error()));
        }

        self.socket_fd = Some(owned);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn try_open(&mut self) -> Result<(), LiveInterfaceError> {
        Err(LiveInterfaceError::NonLinuxBuild)
    }

    /// Lit `PACKET_STATISTICS_V3` sur la socket active. Retourne
    /// `(tp_packets, tp_drops, tp_freeze_q_cnt)`. La socket est
    /// réinitialisée côté noyau à chaque lecture — appeler
    /// périodiquement (p.ex. 1 Hz) pour un snapshot cumulé.
    #[cfg(target_os = "linux")]
    pub fn packet_statistics_v3(&self) -> Result<(u32, u32, u32), LiveInterfaceError> {
        use std::os::fd::AsRawFd;
        let fd = self
            .socket_fd
            .as_ref()
            .map(|owned| owned.as_raw_fd())
            .ok_or_else(|| {
                LiveInterfaceError::SocketOpen(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "socket is not open",
                ))
            })?;
        #[repr(C)]
        #[derive(Default)]
        struct TpacketStatsV3 {
            tp_packets: u32,
            tp_drops: u32,
            tp_freeze_q_cnt: u32,
        }
        let mut stats = TpacketStatsV3::default();
        let mut len = std::mem::size_of::<TpacketStatsV3>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                &mut stats as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(LiveInterfaceError::SetsockoptRing(
                std::io::Error::last_os_error(),
            ));
        }
        Ok((stats.tp_packets, stats.tp_drops, stats.tp_freeze_q_cnt))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn packet_statistics_v3(&self) -> Result<(u32, u32, u32), LiveInterfaceError> {
        Err(LiveInterfaceError::NonLinuxBuild)
    }

    /// `true` ssi la socket est ouverte et attachée à l'interface.
    pub fn is_open(&self) -> bool {
        self.socket_fd.is_some()
    }
}

impl CaptureSource for LiveInterfaceSource {
    fn id(&self) -> &str {
        &self.id
    }
    fn spec(&self) -> &CaptureInterface {
        &self.spec
    }
    fn kind(&self) -> CaptureSourceKind {
        CaptureSourceKind::LiveInterface
    }
    fn probe_id(&self) -> &str {
        &self.probe_id
    }
    fn physical_link(&self) -> Option<&str> {
        self.physical_link.as_deref()
    }
    fn timestamp_source(&self) -> &str {
        // 2.20.1 — optimiste : si l'opérateur a demandé hw_ptp, on
        // publie "hw_ptp" sur chaque event. Le fallback kernel reste
        // signalé via logs quand `setsockopt(SO_TIMESTAMPING)` échoue
        // (soft-fail), mais la publicité event reste cohérente avec
        // la demande opérateur.
        if self.hw_timestamping_requested {
            "hw_ptp"
        } else {
            "kernel"
        }
    }
}

/// 2.21.0 (P1b) — source vTAP. L'agent `polaris-vtap` écrit des pcap
/// fermés atomiquement (`.pcap.part` → `.pcap`) + manifeste
/// `.vtap.json` dans `out_dir`, consommés comme une rotation. Chaque
/// event issu de cette source porte `probe_type = "vtap"` et
/// `timestamp_source = "ebpf_monotonic"`. **Non câblée** dans le
/// watcher continu (même statut que `PcapRotatingSource`) : câblage
/// effectif avec le wiring 2.20.2 de `LiveInterfaceSource`.
pub struct VtapSource {
    id: String,
    probe_id: String,
    spec: CaptureInterface,
    out_dir: PathBuf,
}

impl VtapSource {
    /// Horodatage : `bpf_ktime_get_ns` + offset REALTIME au démarrage.
    pub const TIMESTAMP_SOURCE: &'static str = "ebpf_monotonic";

    pub fn new(probe_id: impl Into<String>, spec: CaptureInterface, out_dir: impl Into<PathBuf>) -> Self {
        let probe_id = probe_id.into();
        let id = format!("{}:{}", probe_id, spec.interface);
        Self {
            id,
            probe_id,
            spec,
            out_dir: out_dir.into(),
        }
    }

    pub fn out_dir(&self) -> &PathBuf {
        &self.out_dir
    }

    /// Fichiers prêts à l'ingestion : `.pcap` fermés uniquement, jamais
    /// le `.pcap.part` en cours d'écriture (invariant 2.19.x).
    pub fn is_ingestible(path: &std::path::Path) -> bool {
        path.extension().map(|e| e == "pcap").unwrap_or(false)
            && path
                .file_name()
                .map(|n| n.to_string_lossy().starts_with("vtap_"))
                .unwrap_or(false)
    }

    /// 2.21.1 — scan atomique du `out_dir` : renvoie la liste
    /// triée (`capture_id canonique`) des `vtap_*.pcap` **fermés**
    /// prêts à être décodés. `.pcap.part`, `.vtap.json`, et tout
    /// autre fichier sont filtrés. L'ordre canonique de retour est
    /// le tri lexicographique du nom (dumpcap-style monotone car
    /// l'agent inclut un timestamp au format `YYYYMMDDTHHMMSSZ` et
    /// un index), **jamais un tri par mtime** (règle 2.21.1).
    /// Fichier manquant, dir inexistant → `Ok(vec![])`. Erreur IO
    /// autre → remontée. Un garde qui se saute en silence ne garde
    /// rien : une erreur de scan est visible.
    pub fn ingestible_entries(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
        match std::fs::read_dir(dir) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
            Ok(iter) => {
                let mut paths: Vec<PathBuf> = iter
                    .filter_map(|entry| entry.ok().map(|e| e.path()))
                    .filter(|p| Self::is_ingestible(p))
                    .collect();
                paths.sort();
                Ok(paths)
            }
        }
    }
}

impl CaptureSource for VtapSource {
    fn id(&self) -> &str {
        &self.id
    }
    fn spec(&self) -> &CaptureInterface {
        &self.spec
    }
    fn kind(&self) -> CaptureSourceKind {
        CaptureSourceKind::Vtap
    }
    fn timestamp_source(&self) -> &str {
        Self::TIMESTAMP_SOURCE
    }
    fn probe_id(&self) -> &str {
        &self.probe_id
    }
}

/// 2.21.5 — câblage effectif Live/Vtap dans `CaptureManager`.
/// Dérive l'empreinte de sonde à apposer sur les events d'un pcap
/// à partir **uniquement du nom de fichier** (donc sans état
/// global, sans manifeste additionnel). Deux moteurs sont câblés :
///
/// * `vtap_*.pcap` fermés (filtrés par `VtapSource::is_ingestible`) →
///   `probe_type="vtap"`, `probe_id="lab-vtap"`, `timestamp_source="ebpf_monotonic"`.
/// * Tout autre pcap (fichier `.pcapng` dumpcap ou pcap live) →
///   `probe_type="vprobe"`, `probe_id="lab-vprobe"`, `timestamp_source="kernel"`.
///
/// Les `probe_id` par défaut sont des étiquettes stables ; un
/// opérateur qui veut différencier plusieurs sondes passe par
/// `polaris.toml` (lot futur) qui remontera sur la même fonction.
/// L'invariant **iso-comportement 2.21.4** est préservé car les
/// 4 champs multi-sonde sont émis via `to_json_with_probe()` qui
/// skip `None` : la fonction renvoie toujours `Some(_)` pour
/// `probe_type` + `probe_id` + `timestamp_source`, les lignes
/// publiées 2.21.5 portent ces 3 clés (nouveau comportement voulu
/// par ANR2), les 2.21.4 ne les portaient pas.
pub fn probe_stamp_for_pcap_path(path: &Path) -> ProbeStamp {
    if VtapSource::is_ingestible(path) {
        ProbeStamp {
            probe_id: Some("lab-vtap".into()),
            probe_type: Some(CaptureSourceKind::Vtap.probe_type().into()),
            physical_link: None,
            timestamp_source: Some(VtapSource::TIMESTAMP_SOURCE.into()),
        }
    } else {
        ProbeStamp {
            probe_id: Some("lab-vprobe".into()),
            probe_type: Some(CaptureSourceKind::PcapRotating.probe_type().into()),
            physical_link: None,
            timestamp_source: Some("kernel".into()),
        }
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

    // 2.20.1 — LiveInterfaceSource & params.

    /// 2.20.1 — valeurs par défaut TPACKET_V3 : buffer total
    /// 256 MiB, bloc 4 MiB × 64, frame 2 KiB, retire_blk_tov
    /// 10 ms. Conforme au design doc §3.1.
    #[test]
    fn tpacketv3_defaults_match_design_doc_latency_and_buffer() {
        let p = Tpacketv3Params::default();
        assert_eq!(p.block_size, 4 * 1024 * 1024);
        assert_eq!(p.block_nr, 64);
        assert_eq!(p.frame_size, 2048);
        assert_eq!(p.retire_blk_tov_ms, 10);
        assert_eq!(p.buffer_bytes(), 256 * 1024 * 1024);
        assert_eq!(p.feature_req_word, 1); // TP_FT_REQ_FILL_RXHASH
    }

    /// 2.20.1 — `setsockopt_value` packe `(mode << 16) | id` comme
    /// requis par `setsockopt(SOL_PACKET, PACKET_FANOUT, …)` Linux.
    #[test]
    fn packet_fanout_setsockopt_value_packs_mode_and_id() {
        let fanout = PacketFanoutParams {
            fanout_id: 0xABCD,
            mode: PacketFanoutMode::Hash,
        };
        // Hash = 0 => haut 16 bits à 0, bas 16 bits = id.
        assert_eq!(fanout.setsockopt_value(), 0x0000_ABCD);
        let fanout_lb = PacketFanoutParams {
            fanout_id: 1,
            mode: PacketFanoutMode::LoadBalance,
        };
        // LoadBalance = 1 => haut 16 bits = 1.
        assert_eq!(fanout_lb.setsockopt_value(), 0x0001_0001);
    }

    /// 2.20.1 — un `LiveInterfaceSource` expose `physical_link` +
    /// `timestamp_source` depuis la demande opérateur, sans
    /// nécessiter d'ouverture socket. Utilisable dans les tests et
    /// l'inspection /health.
    #[test]
    fn live_interface_source_publishes_kind_and_timestamp_source() {
        let src = LiveInterfaceSource::new(
            "lab-vprobe",
            spec("N2", "br-oiran-n2"),
            Tpacketv3Params::default(),
            PacketFanoutParams {
                fanout_id: 0xBEEF,
                mode: PacketFanoutMode::Hash,
            },
            true,
            Some("enp4s0f1np1".into()),
        );
        assert_eq!(src.id(), "lab-vprobe:N2");
        assert_eq!(src.kind(), CaptureSourceKind::LiveInterface);
        assert_eq!(src.kind().probe_type(), "vprobe");
        assert_eq!(src.timestamp_source(), "hw_ptp");
        assert_eq!(src.physical_link(), Some("enp4s0f1np1"));
        assert!(src.hw_timestamping_requested());
        assert!(!src.is_open());
    }

    /// 2.20.1 — hw_timestamping NON demandé → `timestamp_source =
    /// "kernel"`. Jamais d'invention : la publicité event colle à
    /// la demande.
    #[test]
    fn live_interface_source_defaults_to_kernel_timestamp_when_not_requested() {
        let src = LiveInterfaceSource::new(
            "lab-vprobe",
            spec("N2", "br-oiran-n2"),
            Tpacketv3Params::default(),
            PacketFanoutParams {
                fanout_id: 1,
                mode: PacketFanoutMode::Hash,
            },
            false,
            None,
        );
        assert_eq!(src.timestamp_source(), "kernel");
        assert!(src.physical_link().is_none());
    }

    /// 2.20.1 — `try_open()` sans CAP_NET_RAW retourne une erreur
    /// typée (`MissingCapNetRaw` sur Linux, `NonLinuxBuild` ailleurs).
    /// Jamais de panic, jamais de leak. Les paramètres restent
    /// inspectables même en cas d'échec.
    #[test]
    fn live_interface_try_open_returns_typed_error_without_cap_net_raw_or_on_non_linux() {
        let mut src = LiveInterfaceSource::new(
            "lab-vprobe",
            spec("N2", "no-such-interface-for-oiran-test"),
            Tpacketv3Params::default(),
            PacketFanoutParams {
                fanout_id: 42,
                mode: PacketFanoutMode::Hash,
            },
            false,
            None,
        );
        let result = src.try_open();
        assert!(result.is_err(), "try_open on unavailable interface must fail");
        assert!(!src.is_open());
        #[cfg(not(target_os = "linux"))]
        {
            assert!(matches!(
                result.err().unwrap(),
                LiveInterfaceError::NonLinuxBuild
            ));
        }
        #[cfg(target_os = "linux")]
        {
            // Sans CAP_NET_RAW, l'ouverture AF_PACKET elle-même
            // échoue AVANT if_nametoindex. Sur bench avec
            // CAP_NET_RAW, if_nametoindex renvoie 0 →
            // InterfaceNotFound. Les deux cas sont acceptables.
            let err = result.err().unwrap();
            assert!(
                matches!(
                    err,
                    LiveInterfaceError::MissingCapNetRaw(_)
                        | LiveInterfaceError::SocketOpen(_)
                        | LiveInterfaceError::InterfaceNotFound(_)
                ),
                "unexpected error: {err}"
            );
        }
    }

    /// 2.20.1 — `packet_statistics_v3()` sur socket non-ouverte
    /// renvoie une erreur sans toucher au kernel.
    #[test]
    fn packet_statistics_v3_fails_cleanly_when_socket_not_open() {
        let src = LiveInterfaceSource::new(
            "lab-vprobe",
            spec("N2", "br-oiran-n2"),
            Tpacketv3Params::default(),
            PacketFanoutParams {
                fanout_id: 1,
                mode: PacketFanoutMode::Hash,
            },
            false,
            None,
        );
        let result = src.packet_statistics_v3();
        assert!(result.is_err());
    }

    /// 2.21.0 — moteur `vtap` : parse, round-trip, probe_type `vtap`.
    #[test]
    fn vtap_kind_parses_and_reports_probe_type_vtap() {
        assert_eq!(CaptureSourceKind::parse("vtap"), Some(CaptureSourceKind::Vtap));
        assert_eq!(CaptureSourceKind::parse("EBPF_TLS"), Some(CaptureSourceKind::Vtap));
        assert_eq!(CaptureSourceKind::Vtap.as_str(), "vtap");
        assert_eq!(CaptureSourceKind::Vtap.probe_type(), "vtap");
    }

    #[test]
    fn vtap_source_fills_fields_and_never_ingests_part_files() {
        let src = VtapSource::new("lab-vtap", spec("SBI", "vtap"), "/var/lib/oiran/vtap");
        assert_eq!(src.id(), "lab-vtap:SBI");
        assert_eq!(src.kind(), CaptureSourceKind::Vtap);
        assert_eq!(src.timestamp_source(), "ebpf_monotonic");
        assert!(src.physical_link().is_none());
        use std::path::Path;
        assert!(VtapSource::is_ingestible(Path::new("/x/vtap_SBI_20261116T150000Z.pcap")));
        assert!(!VtapSource::is_ingestible(Path::new("/x/vtap_SBI_20261116T150000Z.pcap.part")));
        assert!(!VtapSource::is_ingestible(Path::new("/x/vtap_SBI_20261116T150000Z.vtap.json")));
        assert!(!VtapSource::is_ingestible(Path::new("/x/SBI_00001.pcap")));
    }

    /// 2.21.1 — `to_probe_stamp()` compose un `ProbeStamp` complet
    /// depuis la source (vtap). Jamais d'invention : `probe_id`,
    /// `probe_type`, `timestamp_source` viennent du trait.
    #[test]
    fn vtap_source_to_probe_stamp_is_filled_with_vtap_values() {
        let src = VtapSource::new("lab-vtap", spec("SBI", "vtap"), "/var/lib/oiran/vtap");
        let stamp = src.to_probe_stamp();
        assert_eq!(stamp.probe_id.as_deref(), Some("lab-vtap"));
        assert_eq!(stamp.probe_type.as_deref(), Some("vtap"));
        assert_eq!(stamp.timestamp_source.as_deref(), Some("ebpf_monotonic"));
        assert!(stamp.physical_link.is_none());
    }

    /// 2.21.1 — un `PcapRotatingSource` compose aussi son propre
    /// `ProbeStamp` : parité du contrat sur le trait.
    #[test]
    fn pcap_rotating_source_to_probe_stamp_is_filled_with_vprobe_values() {
        let src = PcapRotatingSource::new(
            "lab-vprobe",
            spec("N2", "br-oiran-n2"),
            "/tmp/pcap-rotation",
        );
        let stamp = src.to_probe_stamp();
        assert_eq!(stamp.probe_id.as_deref(), Some("lab-vprobe"));
        assert_eq!(stamp.probe_type.as_deref(), Some("vprobe"));
        assert_eq!(stamp.timestamp_source.as_deref(), Some("kernel"));
        assert!(stamp.physical_link.is_none());
    }

    /// 2.21.1 — `LiveInterfaceSource::to_probe_stamp()` propage
    /// `physical_link` (phy-like) et le `timestamp_source` demandé.
    /// Le `probe_type` reste `"vprobe"` (vProbe sur bridges Docker) ;
    /// le passage à `"phy"` sera géré par `AfXdpSource`/`DpdkSource`
    /// en 2.22.x.
    #[test]
    fn live_interface_source_to_probe_stamp_carries_physical_link() {
        let src = LiveInterfaceSource::new(
            "lab-vprobe",
            spec("N2", "br-oiran-n2"),
            Tpacketv3Params::default(),
            PacketFanoutParams {
                fanout_id: 1,
                mode: PacketFanoutMode::Hash,
            },
            true,
            Some("enp4s0f1np1".into()),
        );
        let stamp = src.to_probe_stamp();
        assert_eq!(stamp.probe_id.as_deref(), Some("lab-vprobe"));
        assert_eq!(stamp.probe_type.as_deref(), Some("vprobe"));
        assert_eq!(stamp.timestamp_source.as_deref(), Some("hw_ptp"));
        assert_eq!(stamp.physical_link.as_deref(), Some("enp4s0f1np1"));
    }

    /// 2.21.1 — `ingestible_entries()` scanne un vrai répertoire
    /// temporaire : retourne uniquement les `vtap_*.pcap` fermés,
    /// jamais le `.pcap.part` ni le `.vtap.json`. Ordre canonique
    /// = tri du nom (jamais mtime).
    #[test]
    fn vtap_source_ingestible_entries_filters_closed_pcaps_and_sorts_by_name() {
        let base = std::path::PathBuf::from(format!(
            "/tmp/oiran-vtap-ingestible-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        for name in [
            "vtap_SBI_20261116T120000Z.pcap",       // kept
            "vtap_SBI_20261116T120100Z.pcap",       // kept
            "vtap_SBI_20261116T120200Z.pcap.part",  // skipped (open)
            "vtap_SBI_20261116T120200Z.vtap.json",  // skipped (manifest)
            "SBI_00001.pcap",                       // skipped (not vtap_*)
            "random.log",                           // skipped
        ] {
            std::fs::write(base.join(name), b"stub").unwrap();
        }
        let entries = VtapSource::ingestible_entries(&base).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].ends_with("vtap_SBI_20261116T120000Z.pcap"));
        assert!(entries[1].ends_with("vtap_SBI_20261116T120100Z.pcap"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// 2.21.1 — scan d'un répertoire inexistant → `Ok(vec![])`.
    /// Un dossier `out_dir` pas encore créé n'est PAS une erreur
    /// bloquante — l'agent vTAP peut démarrer plus tard. Les
    /// autres erreurs IO sont remontées (pas de garde silencieuse).
    #[test]
    fn vtap_source_ingestible_entries_on_missing_dir_returns_empty() {
        let missing = std::path::PathBuf::from(format!(
            "/tmp/oiran-vtap-missing-{}-never-created",
            std::process::id()
        ));
        let entries = VtapSource::ingestible_entries(&missing).unwrap();
        assert!(entries.is_empty());
    }

    /// 2.21.5 — câblage effectif : un pcap `vtap_*.pcap` fermé
    /// produit un `ProbeStamp` « vtap », un pcap dumpcap classique
    /// produit un `ProbeStamp` « vprobe ». Jamais de ProbeStamp
    /// vide : les 3 champs clés sont toujours `Some(_)`.
    #[test]
    fn probe_stamp_from_pcap_path_is_vtap_for_vtap_filenames() {
        let stamp = probe_stamp_for_pcap_path(Path::new(
            "/var/lib/oiran/vtap/vtap_SBI_20261116T120000Z.pcap",
        ));
        assert_eq!(stamp.probe_id.as_deref(), Some("lab-vtap"));
        assert_eq!(stamp.probe_type.as_deref(), Some("vtap"));
        assert_eq!(stamp.timestamp_source.as_deref(), Some("ebpf_monotonic"));
        assert!(stamp.physical_link.is_none());
    }

    #[test]
    fn probe_stamp_from_pcap_path_is_vprobe_for_dumpcap_filenames() {
        let stamp = probe_stamp_for_pcap_path(Path::new(
            "/var/lib/oiran/capture/N2/N2_00042.pcapng",
        ));
        assert_eq!(stamp.probe_id.as_deref(), Some("lab-vprobe"));
        assert_eq!(stamp.probe_type.as_deref(), Some("vprobe"));
        assert_eq!(stamp.timestamp_source.as_deref(), Some("kernel"));
    }

    /// 2.21.5 — un `.pcap.part` n'est **pas** un vtap fermé →
    /// classé vprobe en fallback (iso-comportement 2.21.4 pour les
    /// pcaps classiques). En pratique un `.part` n'est jamais
    /// ingéré (filtré par rotation-watcher et par
    /// `VtapSource::is_ingestible`) ; ce test prouve que même si
    /// un bug laissait passer un `.part` dans le pipeline, le
    /// stamp vtap ne lui serait pas apposé par erreur.
    #[test]
    fn probe_stamp_from_pcap_part_file_falls_back_to_vprobe() {
        let stamp = probe_stamp_for_pcap_path(Path::new(
            "/var/lib/oiran/vtap/vtap_SBI_20261116T120000Z.pcap.part",
        ));
        assert_eq!(stamp.probe_type.as_deref(), Some("vprobe"));
    }

    /// 2.21.5 — INTÉGRATION : le câblage `probe_stamp_for_pcap_path`
    /// + `NormalizedEvent::to_json_with_probe` produit des lignes
    /// JSONL marquées `probe_type` conformément au chemin pcap
    /// source. Reproduit exactement ce que le pipeline
    /// `process_continuous_capture_inner` fait depuis la 2.21.5.
    #[test]
    fn integration_wiring_pcap_path_then_json_marks_probe_type_as_source() {
        use event_schema::{
            DecodeStatus, Direction, Endpoint, ExactTimestamp, NormalizedEvent, PacketReference,
            Protocol,
        };
        fn minimal_event(capture_id: &str, packet_number: u64) -> NormalizedEvent {
            NormalizedEvent {
                event_id: String::new(),
                parent_event_id: None,
                probe_id: "will-be-overridden".into(),
                capture_point_id: "SBI".into(),
                capture_id: capture_id.into(),
                packet_references: vec![PacketReference {
                    source_file: "stub.pcap".into(),
                    source_sha256: None,
                    packet_number,
                    byte_offset: 0,
                    interface_id: 0,
                    link_type: None,
                    sll2_protocol_type: None,
                    sll2_reserved: None,
                    sll2_interface_index: None,
                    sll2_arphrd_type: None,
                    sll2_packet_type: None,
                    sll2_address_length: None,
                    sll2_address: None,
                    captured_length: 64,
                    original_length: 64,
                }],
                timestamp: ExactTimestamp {
                    seconds: 0,
                    nanoseconds: 0,
                    raw_ticks: 0,
                    resolution_base: 10,
                    resolution_exponent: 9,
                },
                interface: "SBI".into(),
                protocol: Protocol::SbiHttp2,
                message_name: "integration-test".into(),
                message_type: 0,
                procedure_code: None,
                procedure: None,
                security_state: None,
                source_byte_offset: None,
                source_endpoint: Endpoint {
                    address: "a".into(),
                    port: None,
                    network_function: None,
                },
                destination_endpoint: Endpoint {
                    address: "b".into(),
                    port: None,
                    network_function: None,
                },
                direction: Direction::Unknown,
                session_identifiers: vec![],
                information_elements: vec![],
                decoder_name: "test".into(),
                decoder_version: "test".into(),
                schema_version: NormalizedEvent::SCHEMA_VERSION,
                decoding_status: DecodeStatus::Decoded,
                errors: vec![],
                raw_payload_reference: "sha256:int".into(),
                evidence_references: vec![],
                sbi: None,
            }
        }
        // (a) Pcap classique dumpcap → vprobe partout dans la JSONL.
        let path_vprobe = Path::new("/var/lib/oiran/capture/N2/N2_00001.pcapng");
        let stamp_vprobe = probe_stamp_for_pcap_path(path_vprobe);
        let line_vprobe = minimal_event("sha256:vprobe", 1).to_json_with_probe(&stamp_vprobe);
        let v: serde_json::Value = serde_json::from_str(&line_vprobe).unwrap();
        assert_eq!(v["probe_type"], "vprobe", "{line_vprobe}");
        assert_eq!(v["probe_id"], "lab-vprobe");
        assert_eq!(v["timestamp_source"], "kernel");
        // physical_link reste absent (None → skip_serializing_if).
        assert!(v.as_object().unwrap().get("physical_link").is_none());

        // (b) Pcap vTAP fermé → vtap partout.
        let path_vtap = Path::new("/var/lib/oiran/vtap/vtap_SBI_20261116T120000Z.pcap");
        let stamp_vtap = probe_stamp_for_pcap_path(path_vtap);
        let line_vtap = minimal_event("sha256:vtap", 2).to_json_with_probe(&stamp_vtap);
        let v: serde_json::Value = serde_json::from_str(&line_vtap).unwrap();
        assert_eq!(v["probe_type"], "vtap", "{line_vtap}");
        assert_eq!(v["probe_id"], "lab-vtap");
        assert_eq!(v["timestamp_source"], "ebpf_monotonic");

        // (c) `.pcap.part` → fallback vprobe : jamais de confusion.
        let path_part = Path::new("/var/lib/oiran/vtap/vtap_SBI_20261116T120100Z.pcap.part");
        let stamp_part = probe_stamp_for_pcap_path(path_part);
        let line_part = minimal_event("sha256:part", 3).to_json_with_probe(&stamp_part);
        let v: serde_json::Value = serde_json::from_str(&line_part).unwrap();
        assert_eq!(v["probe_type"], "vprobe", "{line_part}");
    }
}
