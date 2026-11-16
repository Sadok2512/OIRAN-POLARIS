//! 2.20.0 — chargeur de `polaris.toml` (multi-sonde PRO 400G).
//!
//! Design : `OIRAN/docs/architecture/PHASE1-2.md` §3.3. Ce module
//! **ne change rien au comportement runtime 2.19.x** :
//!
//! * Si aucun fichier `polaris.toml` n'est présent (env
//!   `POLARIS_CONFIG` non défini ET fichier par défaut absent),
//!   `load_default()` renvoie `None` et l'application utilise les
//!   constantes historiques (bridges `br-oiran-*`, IPs lab,
//!   `CONTINUOUS_CAPTURE_ID`, …).
//!
//! * Si un `polaris.toml` est trouvé, il est parsé et exposé via
//!   `AppState` (câblage effectif dans les lots 2.20.1+ ; en 2.20.0
//!   on expose uniquement le parseur et les tests). La présence du
//!   fichier ne doit pas CHANGER les sessions/ids/callflows d'un
//!   dataset existant — c'est l'invariant iso-comportement.
//!
//! Format attendu :
//! ```toml
//! [[probes]]
//! id       = "lab-vprobe"
//! engine   = "pcap_rotating"          # ou live_pcap|af_xdp|dpdk
//! probe_type = "vprobe"               # ou "phy"
//! rotation_dir = "/var/lib/oiran/rotation"   # pcap_rotating only
//! interfaces = [
//!   { label = "N2",  device = "br-oiran-n2",  filter = "sctp and port 38412", decoder = "ngap" },
//!   { label = "SBI", device = "br-oiran-sbi", filter = "tcp port 7777",       decoder = "sbi"  },
//! ]
//!
//! [endpoints]
//! "172.22.0.7"  = { nf = "SMF", plmn = "00101" }
//! "172.22.0.10" = { nf = "AMF", plmn = "00101" }
//! ```
//!
//! Vie privée : le fichier NE contient JAMAIS d'identité (pas de
//! IMSI/SUPI/IMEI/…). Il décrit la topologie de capture et le
//! mapping endpoint → NF, rien d'autre. Un endpoint dupliqué ou un
//! probe_id dupliqué déclenche une erreur de parsing (pas de fusion
//! silencieuse).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Chemin par défaut recherché si `POLARIS_CONFIG` n'est pas défini.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/polaris.toml";

/// Var env qui, si présente, surclasse `DEFAULT_CONFIG_PATH`. Priorité :
/// env > chemin par défaut > `None` (iso-comportement 2.19.x).
pub const CONFIG_ENV_VAR: &str = "POLARIS_CONFIG";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolarisConfig {
    #[serde(default)]
    pub probes: Vec<ProbeConfig>,
    #[serde(default)]
    pub endpoints: BTreeMap<String, EndpointConfig>,
    /// 2.22.1 — section `[userplane]` (plan usager résumé). Absence =
    /// comportement historique inchangé ; chaque champ a un défaut
    /// documenté (voir `UserplaneConfig`).
    #[serde(default)]
    pub userplane: UserplaneConfig,
}

/// 2.22.1 — section `[userplane]` de `polaris.toml`. Configure la
/// troncature sonde (OP2.1 tranché) et préparera les clés 2.22.3
/// `inactivity_timeout_ns` + 2.22.4 `window_ns` dans les lots suivants.
///
/// Invariant OP2.1 : le snaplen sonde définit la **fenêtre capturée**
/// sur disque ; les volumes `aggregate_wire_bytes` se calculent
/// **toujours** sur `original_length` (champ pcapng), jamais sur
/// `captured_length`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserplaneConfig {
    /// 2.22.4 — bascule iso-comportement. `false` par défaut : la sonde
    /// ne publie AUCUN record `UserPlaneSummary` (iso-comportement
    /// 2.22.3). À passer à `true` pour activer la vue par PDU session.
    #[serde(default)]
    pub enabled: bool,
    /// Snaplen BPF pour les interfaces N3 (après l'entête GTP-U).
    /// Défaut : 128 octets — suffisant pour IPv4/IPv6 + TCP/UDP +
    /// options SACK/Timestamps (cf. PHASE1-2.md §4.5). La sonde
    /// capture `L2 + L3 externe + GTP-U header + snaplen_n3_bytes`.
    #[serde(default = "default_snaplen_n3_bytes")]
    pub snaplen_n3_bytes: u32,
    /// 2.22.4 — largeur du bucket de throughput, en nanosecondes.
    /// Défaut 1 s (OP2.3 tranché #9 6927882355). Recommandation prod 5 s.
    #[serde(default = "default_window_ns")]
    pub window_ns: i128,
    /// 2.22.4 — timeout d'inactivité d'une session PDU avant
    /// fermeture automatique du `UserPlaneSummary`. Défaut 300 s.
    #[serde(default = "default_inactivity_timeout_ns")]
    pub inactivity_timeout_ns: i128,
    /// 2.22.4 — nombre maximum de `UserPlaneSummary` actifs
    /// simultanément. Au-delà : éviction LRU avec event tracé.
    /// Défaut 4096.
    #[serde(default = "default_max_summaries")]
    pub max_summaries: usize,
}

impl Default for UserplaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            snaplen_n3_bytes: default_snaplen_n3_bytes(),
            window_ns: default_window_ns(),
            inactivity_timeout_ns: default_inactivity_timeout_ns(),
            max_summaries: default_max_summaries(),
        }
    }
}

fn default_snaplen_n3_bytes() -> u32 {
    128
}

fn default_window_ns() -> i128 {
    1_000_000_000
}

fn default_inactivity_timeout_ns() -> i128 {
    300_000_000_000
}

fn default_max_summaries() -> usize {
    4096
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeConfig {
    pub id: String,
    pub engine: String,
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub rotation_dir: Option<PathBuf>,
    /// 2.21.0 — `engine = "vtap"` uniquement : répertoire où l'agent
    /// `polaris-vtap` dépose `vtap_SBI_*.pcap` + `.vtap.json`.
    #[serde(default)]
    pub out_dir: Option<PathBuf>,
    #[serde(default)]
    pub interfaces: Vec<ProbeInterfaceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeInterfaceConfig {
    pub label: String,
    pub device: String,
    #[serde(default)]
    pub filter: String,
    #[serde(default)]
    pub decoder: Option<String>,
    /// 2.20.0 — champs destinés à 2.20.1 (hardware).
    #[serde(default)]
    pub physical_link: Option<String>,
    #[serde(default)]
    pub timestamp_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointConfig {
    pub nf: String,
    #[serde(default)]
    pub plmn: Option<String>,
}

#[derive(Debug)]
pub enum PolarisConfigError {
    Io(std::io::Error, PathBuf),
    Parse(toml::de::Error, PathBuf),
    DuplicateProbeId(String),
    UnknownEngine { probe_id: String, engine: String },
    /// 2.21.0 — `probe_type` déclaré incohérent avec le moteur (ex.
    /// `engine = "vtap"` + `probe_type = "phy"`) : refus, pas de
    /// correction silencieuse.
    ProbeTypeMismatch { probe_id: String, declared: String, expected: String },
    /// 2.21.0 — champ requis par le moteur absent (`out_dir` pour vtap).
    MissingField { probe_id: String, field: &'static str },
}

impl std::fmt::Display for PolarisConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e, p) => write!(f, "polaris.toml io error at {}: {e}", p.display()),
            Self::Parse(e, p) => write!(f, "polaris.toml parse error at {}: {e}", p.display()),
            Self::DuplicateProbeId(id) => {
                write!(f, "polaris.toml: duplicate probe id `{id}`")
            }
            Self::UnknownEngine { probe_id, engine } => write!(
                f,
                "polaris.toml: probe `{probe_id}` has unknown engine `{engine}` \
                 (must be pcap_rotating|live_pcap|af_xdp|dpdk|vtap)"
            ),
            Self::ProbeTypeMismatch { probe_id, declared, expected } => write!(
                f,
                "polaris.toml: probe `{probe_id}` declares probe_type `{declared}` \
                 but its engine implies `{expected}`"
            ),
            Self::MissingField { probe_id, field } => {
                write!(f, "polaris.toml: probe `{probe_id}` requires `{field}`")
            }
        }
    }
}

impl std::error::Error for PolarisConfigError {}

impl PolarisConfig {
    /// Résout le chemin de config selon la convention env > default.
    /// Renvoie `None` si aucun n'est utilisable — chemin iso-comportement.
    pub fn resolve_path(env_value: Option<&str>) -> Option<PathBuf> {
        if let Some(path) = env_value {
            if !path.is_empty() {
                // 2.21.0 (revue) : une variable explicite pointant vers un
                // fichier absent n'est PLUS remplacée en silence par
                // /etc/polaris.toml — le chemin est rendu tel quel et
                // `load_from_file` échoue en `Io` (garde visible).
                return Some(PathBuf::from(path));
            }
        }
        let default = PathBuf::from(DEFAULT_CONFIG_PATH);
        if default.exists() {
            Some(default)
        } else {
            None
        }
    }

    /// Lit la var env `POLARIS_CONFIG` puis le chemin par défaut.
    /// Aucun fichier → `Ok(None)` (iso-comportement 2.19.x).
    pub fn load_default() -> Result<Option<Self>, PolarisConfigError> {
        let env_value = std::env::var(CONFIG_ENV_VAR).ok();
        let Some(path) = Self::resolve_path(env_value.as_deref()) else {
            return Ok(None);
        };
        Self::load_from_file(&path).map(Some)
    }

    /// Charge depuis un fichier précis + validation. Renvoie
    /// `PolarisConfigError` sur IO / parsing / duplicate / engine
    /// inconnu.
    pub fn load_from_file(path: &Path) -> Result<Self, PolarisConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| PolarisConfigError::Io(e, path.to_owned()))?;
        Self::load_from_str(&text, path)
    }

    /// Charge + valide depuis une &str (utile pour les tests).
    pub fn load_from_str(text: &str, path: &Path) -> Result<Self, PolarisConfigError> {
        let config: Self = toml::from_str(text)
            .map_err(|e| PolarisConfigError::Parse(e, path.to_owned()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), PolarisConfigError> {
        let mut seen = std::collections::BTreeSet::new();
        for probe in &self.probes {
            if !seen.insert(probe.id.clone()) {
                return Err(PolarisConfigError::DuplicateProbeId(probe.id.clone()));
            }
            let Some(kind) = live_probe::capture_source::CaptureSourceKind::parse(&probe.engine)
            else {
                return Err(PolarisConfigError::UnknownEngine {
                    probe_id: probe.id.clone(),
                    engine: probe.engine.clone(),
                });
            };
            if let Some(declared) = probe.probe_type.as_deref() {
                if declared != kind.probe_type() {
                    return Err(PolarisConfigError::ProbeTypeMismatch {
                        probe_id: probe.id.clone(),
                        declared: declared.to_string(),
                        expected: kind.probe_type().to_string(),
                    });
                }
            }
            if kind == live_probe::capture_source::CaptureSourceKind::Vtap && probe.out_dir.is_none() {
                return Err(PolarisConfigError::MissingField {
                    probe_id: probe.id.clone(),
                    field: "out_dir",
                });
            }
        }
        Ok(())
    }

    /// Nombre de sondes configurées. 0 → iso-comportement.
    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// Lookup endpoint → NF. Utilisé en 2.20.1+ pour remplacer les
    /// hardcodes `172.22.0.7`/`172.22.0.10` dans `decoder-sbi`.
    pub fn nf_for_endpoint(&self, address: &str) -> Option<&EndpointConfig> {
        self.endpoints.get(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        PathBuf::from(format!("/tmp/polaris-config-test-{name}.toml"))
    }

    #[test]
    fn empty_config_is_valid_and_probe_count_zero() {
        let text = "";
        let config =
            PolarisConfig::load_from_str(text, &tmp_path("empty")).expect("empty parses");
        assert_eq!(config.probe_count(), 0);
        assert!(config.endpoints.is_empty());
    }

    #[test]
    fn parse_single_probe_with_two_interfaces_and_endpoints() {
        let text = r#"
[[probes]]
id = "lab-vprobe"
engine = "pcap_rotating"
probe_type = "vprobe"
rotation_dir = "/var/lib/oiran/rotation"
interfaces = [
  { label = "N2",  device = "br-oiran-n2",  filter = "sctp and port 38412", decoder = "ngap" },
  { label = "SBI", device = "br-oiran-sbi", filter = "tcp port 7777",       decoder = "sbi"  },
]

[endpoints]
"172.22.0.7"  = { nf = "SMF", plmn = "00101" }
"172.22.0.10" = { nf = "AMF", plmn = "00101" }
"#;
        let config =
            PolarisConfig::load_from_str(text, &tmp_path("single")).expect("parses");
        assert_eq!(config.probe_count(), 1);
        let probe = &config.probes[0];
        assert_eq!(probe.id, "lab-vprobe");
        assert_eq!(probe.engine, "pcap_rotating");
        assert_eq!(probe.probe_type.as_deref(), Some("vprobe"));
        assert_eq!(probe.interfaces.len(), 2);
        assert_eq!(probe.interfaces[0].label, "N2");
        assert_eq!(probe.interfaces[0].device, "br-oiran-n2");
        assert_eq!(probe.interfaces[1].decoder.as_deref(), Some("sbi"));
        let smf = config.nf_for_endpoint("172.22.0.7").unwrap();
        assert_eq!(smf.nf, "SMF");
        assert_eq!(smf.plmn.as_deref(), Some("00101"));
    }

    #[test]
    fn duplicate_probe_id_is_rejected() {
        let text = r#"
[[probes]]
id = "probe-a"
engine = "pcap_rotating"

[[probes]]
id = "probe-a"
engine = "live_pcap"
"#;
        let err = PolarisConfig::load_from_str(text, &tmp_path("dup")).unwrap_err();
        match err {
            PolarisConfigError::DuplicateProbeId(id) => assert_eq!(id, "probe-a"),
            other => panic!("expected DuplicateProbeId, got {other}"),
        }
    }

    #[test]
    fn unknown_engine_is_rejected_with_probe_id() {
        let text = r#"
[[probes]]
id = "probe-x"
engine = "magic_pipe"
"#;
        let err = PolarisConfig::load_from_str(text, &tmp_path("engine")).unwrap_err();
        match err {
            PolarisConfigError::UnknownEngine { probe_id, engine } => {
                assert_eq!(probe_id, "probe-x");
                assert_eq!(engine, "magic_pipe");
            }
            other => panic!("expected UnknownEngine, got {other}"),
        }
    }

    /// 2.21.0 (revue) — une variable `POLARIS_CONFIG` explicite vers un
    /// fichier absent est une ERREUR visible, jamais un repli silencieux
    /// sur `/etc/polaris.toml` ni un `Ok(None)`. (Remplace le test 2.20.0
    /// qui figeait ce repli et dépendait de l'absence de /etc/polaris.toml.)
    #[test]
    fn explicit_env_path_to_missing_file_is_an_error_not_a_silent_fallback() {
        assert_eq!(
            PolarisConfig::resolve_path(Some("/no/such/polaris/config/for/test")),
            Some(PathBuf::from("/no/such/polaris/config/for/test"))
        );
        let err = PolarisConfig::load_from_file(Path::new("/no/such/polaris/config/for/test"))
            .unwrap_err();
        assert!(matches!(err, PolarisConfigError::Io(..)), "{err}");
    }

    #[test]
    fn vtap_probe_requires_out_dir_and_coherent_probe_type() {
        let ok = r#"
[[probes]]
id = "lab-vtap"
engine = "vtap"
probe_type = "vtap"
out_dir = "/var/lib/oiran/vtap"
interfaces = [ { label = "SBI", device = "vtap", decoder = "sbi" } ]
"#;
        let config = PolarisConfig::load_from_str(ok, &tmp_path("vtap-ok")).expect("vtap ok");
        assert_eq!(config.probes[0].out_dir.as_deref(), Some(Path::new("/var/lib/oiran/vtap")));
        let missing = "[[probes]]\nid = \"v\"\nengine = \"vtap\"\n";
        assert!(matches!(
            PolarisConfig::load_from_str(missing, &tmp_path("vtap-missing")),
            Err(PolarisConfigError::MissingField { field: "out_dir", .. })
        ));
        let mismatch = "[[probes]]\nid = \"v\"\nengine = \"vtap\"\nprobe_type = \"phy\"\nout_dir = \"/x\"\n";
        assert!(matches!(
            PolarisConfig::load_from_str(mismatch, &tmp_path("vtap-mismatch")),
            Err(PolarisConfigError::ProbeTypeMismatch { .. })
        ));
        let pcap_phy = "[[probes]]\nid = \"p\"\nengine = \"pcap_rotating\"\nprobe_type = \"phy\"\n";
        assert!(matches!(
            PolarisConfig::load_from_str(pcap_phy, &tmp_path("pcap-phy")),
            Err(PolarisConfigError::ProbeTypeMismatch { .. })
        ));
    }

    /// 2.20.0 — chaque engine valide listé par `CaptureSourceKind`
    /// est accepté par le validateur (contrat partagé). Un alias
    /// (`pcap`, `af_packet`, …) est aussi accepté.
    #[test]
    fn validator_accepts_every_capture_source_kind_including_aliases() {
        for engine in [
            "pcap_rotating",
            "pcap",
            "live_pcap",
            "af_packet",
            "live_interface",
            "af_xdp",
            "xdp",
            "dpdk",
            "vtap",
        ] {
            let text = format!(
                r#"
[[probes]]
id = "p"
engine = "{engine}"
out_dir = "/tmp/vtap"
"#
            );
            PolarisConfig::load_from_str(&text, &tmp_path(&format!("engine-{engine}")))
                .expect("engine accepted");
        }
    }

    /// 2.22.1 — section `[userplane]` absente ⇒ snaplen par défaut
    /// 128 oct (OP2.1 tranché #9 6927882355).
    #[test]
    fn missing_userplane_section_yields_default_snaplen_128() {
        let text = "";
        let config =
            PolarisConfig::load_from_str(text, &tmp_path("userplane-default")).expect("parses");
        assert_eq!(config.userplane.snaplen_n3_bytes, 128);
    }

    /// 2.22.1 — `[userplane]` surchargée dans `polaris.toml`.
    #[test]
    fn userplane_section_overrides_snaplen_n3_bytes() {
        let text = r#"
[userplane]
snaplen_n3_bytes = 192
"#;
        let config =
            PolarisConfig::load_from_str(text, &tmp_path("userplane-overridden"))
                .expect("parses");
        assert_eq!(config.userplane.snaplen_n3_bytes, 192);
    }
}
