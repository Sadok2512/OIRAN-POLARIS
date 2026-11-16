//! POLARIS vTAP 2.21.0 (P1b) — visibilité SBI chiffré (TLS) sans clé.
//!
//! Chaîne : eBPF (uprobes `SSL_write`/`SSL_read`[`_ex`] de libssl dans les
//! conteneurs Open5GS, `bpf/vtap.bpf.c`) → ringbuf → [`record::TlsRecord`]
//! → [`conn::ProcResolver`] (fd → 4-tuple, netns du conteneur) →
//! [`synth::Synthesizer`] (TCP rejoué, seq cohérents deux sens) →
//! [`pcap::RotatingWriter`] (pcap + manifeste). Le pcap est lu SANS
//! changement par `transport-tcp` + `decoder-sbi`.
//!
//! OUVERT (déclaré, jamais masqué) :
//! * HPACK : une connexion ouverte avant l'agent n'a pas sa table
//!   dynamique → `hpack_context = mid_stream` dans le manifeste. Les NF
//!   Open5GS doivent être redémarrées APRÈS le lancement de l'agent.
//! * HPACK entre deux fichiers pcap rotatés : même limite que le chemin
//!   dumpcap (décodage par fichier).
//! * IPv6 non supporté (compté `unsupported_family`).
//! * Pas de FIN synthétique (fin de connexion = timeout d'inactivité du
//!   réassembleur).

pub mod conn;
pub mod fdlearn;
pub mod pcap;
pub mod record;
pub mod synth;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROBE_TYPE: &str = "vtap";
pub const INTERFACE: &str = "SBI";
/// `bpf_ktime_get_ns` (monotonic) + offset REALTIME mesuré au démarrage.
pub const TIMESTAMP_SOURCE: &str = "ebpf_monotonic";

/// Points OUVERTS d'un fichier, dérivés des compteurs et du manifeste.
pub fn open_items(s: &synth::Synthesizer) -> Vec<String> {
    let mut items = Vec::new();
    let mid = s.mid_stream_connections();
    if mid > 0 {
        items.push(format!(
            "HPACK_MID_STREAM: {mid} connexion(s) ouvertes avant l'agent — en-têtes potentiellement illisibles ; redémarrer les NF Open5GS après l'agent"
        ));
    }
    if s.counters.truncated_records > 0 {
        items.push(format!(
            "TRUNCATED: {} record(s) SSL > {} octets tronqués",
            s.counters.truncated_records,
            record::CHUNK * record::MAX_CHUNKS
        ));
    }
    for (cause, n) in &s.counters.unresolved {
        items.push(format!("UNRESOLVED_{}: {n} record(s) sans 4-tuple", cause.to_uppercase()));
    }
    items
}
