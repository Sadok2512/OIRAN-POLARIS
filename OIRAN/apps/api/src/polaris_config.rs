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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeConfig {
    pub id: String,
    pub engine: String,
    #[serde(default)]
    pub probe_type: Option<String>,
    #[serde(default)]
    pub rotation_dir: Option<PathBuf>,
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
                 (must be pcap_rotating|live_pcap|af_xdp|dpdk)"
            ),
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
                let p = PathBuf::from(path);
                if p.exists() {
                    return Some(p);
                }
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
            if live_probe::capture_source::CaptureSourceKind::parse(&probe.engine).is_none() {
                return Err(PolarisConfigError::UnknownEngine {
                    probe_id: probe.id.clone(),
                    engine: probe.engine.clone(),
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

    /// 2.20.0 — `load_default()` renvoie `Ok(None)` quand aucun
    /// fichier n'est présent : aucun crash, aucun log, chemin
    /// iso-comportement.
    #[test]
    fn load_default_returns_none_when_no_file_exists() {
        // Isole env à cette thread.
        std::env::remove_var(CONFIG_ENV_VAR);
        // Garantit l'absence : var vide pointe vers un chemin
        // volontairement improbable.
        std::env::set_var(CONFIG_ENV_VAR, "/no/such/polaris/config/for/test");
        let result = PolarisConfig::load_default();
        std::env::remove_var(CONFIG_ENV_VAR);
        assert!(matches!(result, Ok(None)));
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
        ] {
            let text = format!(
                r#"
[[probes]]
id = "p"
engine = "{engine}"
"#
            );
            PolarisConfig::load_from_str(&text, &tmp_path(&format!("engine-{engine}")))
                .expect("engine accepted");
        }
    }
}
