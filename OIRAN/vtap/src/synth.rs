//! Synthèse TCP : rejoue les octets TLS en clair comme un flux TCP/IPv4
//! normal (handshake SYN/SYN-ACK/ACK, seq/ack cohérents dans les deux
//! sens), lisible sans changement par `transport-tcp` + `decoder-sbi`.
//!
//! Déduplication : une connexion SBI entre deux NF Open5GS est vue deux
//! fois (SSL_write côté émetteur, SSL_read côté récepteur). Chaque SENS
//! d'une connexion est verrouillé sur la PREMIÈRE source observée ; les
//! octets de l'autre source pour ce sens sont comptés `dedup_dropped`,
//! jamais mélangés (sinon seq incohérents).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddrV4;

use serde::Serialize;

use crate::conn::ConnTuple;
use crate::record::SslOp;

/// Préface client HTTP/2 (RFC 9113 §3.4).
pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Charge utile max par segment synthétique (IPv4 total ≤ 65535).
pub const MAX_SEGMENT: usize = 16384;
/// Ports considérés « serveur » pour orienter le SYN synthétique.
pub const DEFAULT_SERVER_PORTS: &[u16] = &[7777, 443, 80, 8080];

/// Clé canonique d'une connexion : (bas, haut) — identique vue des deux bouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct CanonKey {
    pub low: SocketAddrV4,
    pub high: SocketAddrV4,
}

impl CanonKey {
    pub fn new(a: SocketAddrV4, b: SocketAddrV4) -> Self {
        if (a.ip().octets(), a.port()) <= (b.ip().octets(), b.port()) {
            Self { low: a, high: b }
        } else {
            Self { low: b, high: a }
        }
    }
    pub fn id(&self) -> String {
        format!("{}-{}", self.low, self.high)
    }
}

/// Contexte HPACK observé à l'ouverture de la connexion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HpackContext {
    /// Préface HTTP/2 vue : table dynamique HPACK complète.
    PrefaceSeen,
    /// Connexion déjà ouverte au lancement de l'agent : table dynamique
    /// HPACK manquante → en-têtes potentiellement illisibles. OUVERT :
    /// les NF Open5GS doivent être redémarrées APRÈS l'agent.
    MidStream,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnManifest {
    pub connection_id: String,
    pub client: String,
    pub server: String,
    pub hpack_context: HpackContext,
    /// Source verrouillée par sens : `"ssl_write@open5gs-amfd"`.
    pub source_client_to_server: Option<String>,
    pub source_server_to_client: Option<String>,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Counters {
    pub records: u64,
    pub bytes: u64,
    pub packets: u64,
    pub connections: u64,
    pub dedup_dropped_records: u64,
    pub truncated_records: u64,
    /// Records d'un processus hors cible (`comm` sans le préfixe).
    pub filtered_records: u64,
    /// Échecs de résolution par cause (`fd_unknown`, `fd_gone`, …).
    pub unresolved: BTreeMap<String, u64>,
}

/// Paquet Ethernet/IPv4/TCP prêt à écrire en pcap.
#[derive(Clone, Debug)]
pub struct SynthPacket {
    pub ts_ns: u64,
    pub frame: Vec<u8>,
}

struct ConnState {
    client: SocketAddrV4,
    server: SocketAddrV4,
    /// next_seq[0] = client→serveur, [1] = serveur→client.
    next_seq: [u32; 2],
    owner: [Option<String>; 2],
    bytes: [u64; 2],
    hpack: Option<HpackContext>,
    ip_id: u16,
}

pub struct Synthesizer {
    server_ports: Vec<u16>,
    conns: HashMap<CanonKey, ConnState>,
    /// Connexions vues depuis la dernière rotation (manifeste par fichier).
    touched: HashSet<CanonKey>,
    pub counters: Counters,
}

impl Synthesizer {
    pub fn new(server_ports: &[u16]) -> Self {
        Self {
            server_ports: server_ports.to_vec(),
            conns: HashMap::new(),
            touched: HashSet::new(),
            counters: Counters::default(),
        }
    }

    pub fn note_unresolved(&mut self, cause: &str) {
        *self.counters.unresolved.entry(cause.to_string()).or_default() += 1;
    }

    /// Ingère un record TLS déjà résolu en tuple. `ts_ns` = horodatage
    /// réel (epoch ns). Renvoie les paquets à écrire, dans l'ordre.
    pub fn push(
        &mut self,
        ts_ns: u64,
        tuple: ConnTuple,
        op: SslOp,
        comm: &str,
        truncated: bool,
        data: &[u8],
    ) -> Vec<SynthPacket> {
        self.counters.records += 1;
        if truncated {
            self.counters.truncated_records += 1;
        }
        if data.is_empty() {
            return Vec::new();
        }
        // Sens réel des octets.
        let (src, dst) = match op {
            SslOp::Write => (tuple.local, tuple.remote),
            SslOp::Read => (tuple.remote, tuple.local),
        };
        let key = CanonKey::new(src, dst);
        let mut out = Vec::new();
        if !self.conns.contains_key(&key) {
            let (client, server) = self.orient(src, dst);
            let isn_c = isn(&key, 0);
            let isn_s = isn(&key, 1);
            let state = ConnState {
                client,
                server,
                next_seq: [isn_c.wrapping_add(1), isn_s.wrapping_add(1)],
                owner: [None, None],
                bytes: [0, 0],
                hpack: None,
                ip_id: 1,
            };
            self.conns.insert(key, state);
            self.counters.connections += 1;
            let st = self.conns.get_mut(&key).expect("inserted");
            // Handshake synthétique : SYN, SYN-ACK, ACK.
            out.push(packet(st, ts_ns, 0, isn_c, 0, TCP_SYN, &[]));
            out.push(packet(st, ts_ns, 1, isn_s, isn_c.wrapping_add(1), TCP_SYN | TCP_ACK, &[]));
            let (s0, s1) = (st.next_seq[0], st.next_seq[1]);
            out.push(packet(st, ts_ns, 0, s0, s1, TCP_ACK, &[]));
        }
        self.touched.insert(key);
        let st = self.conns.get_mut(&key).expect("present");
        let dir = usize::from(src != st.client);
        let source_label = format!("{}@{}", op.as_str(), comm);
        match &st.owner[dir] {
            None => st.owner[dir] = Some(source_label),
            Some(owner) if *owner == source_label => {}
            Some(_) => {
                self.counters.dedup_dropped_records += 1;
                return out;
            }
        }
        if dir == 0 && st.hpack.is_none() {
            st.hpack = Some(if data.starts_with(H2_PREFACE) {
                HpackContext::PrefaceSeen
            } else {
                HpackContext::MidStream
            });
        }
        // Le SETTINGS serveur peut être lu AVANT que la préface client
        // soit écrite : seul le premier octet client→serveur décide.
        for chunk in data.chunks(MAX_SEGMENT) {
            let seq = st.next_seq[dir];
            let ack = st.next_seq[1 - dir];
            out.push(packet(st, ts_ns, dir, seq, ack, TCP_PSH | TCP_ACK, chunk));
            st.next_seq[dir] = seq.wrapping_add(chunk.len() as u32);
        }
        st.bytes[dir] += data.len() as u64;
        self.counters.bytes += data.len() as u64;
        self.counters.packets += out.len() as u64;
        out
    }

    fn orient(&self, src: SocketAddrV4, dst: SocketAddrV4) -> (SocketAddrV4, SocketAddrV4) {
        let src_srv = self.server_ports.contains(&src.port());
        let dst_srv = self.server_ports.contains(&dst.port());
        match (src_srv, dst_srv) {
            (false, true) => (src, dst),
            (true, false) => (dst, src),
            // Indécidable : le port le plus bas est le serveur.
            _ if src.port() > dst.port() => (src, dst),
            _ => (dst, src),
        }
    }

    pub fn manifest(&self) -> Vec<ConnManifest> {
        let mut keys: Vec<_> = self.touched.iter().copied().collect();
        keys.sort();
        keys.into_iter()
            .map(|key| {
                let st = &self.conns[&key];
                ConnManifest {
                    connection_id: key.id(),
                    client: st.client.to_string(),
                    server: st.server.to_string(),
                    hpack_context: st.hpack.unwrap_or(HpackContext::MidStream),
                    source_client_to_server: st.owner[0].clone(),
                    source_server_to_client: st.owner[1].clone(),
                    bytes_client_to_server: st.bytes[0],
                    bytes_server_to_client: st.bytes[1],
                }
            })
            .collect()
    }

    /// Rotation : les compteurs et la liste de connexions repartent à
    /// zéro pour le fichier suivant ; l'état TCP (seq) est conservé.
    pub fn rotate(&mut self) {
        self.touched.clear();
        self.counters = Counters::default();
    }

    /// Connexions dont le contexte HPACK est incomplet (OUVERT).
    pub fn mid_stream_connections(&self) -> usize {
        self.manifest()
            .iter()
            .filter(|c| c.hpack_context == HpackContext::MidStream)
            .count()
    }
}

const TCP_SYN: u8 = 0x02;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;

/// ISN déterministe par (connexion, sens) : un même trafic rejoué produit
/// un pcap bit-identique (reproductibilité des recettes).
fn isn(key: &CanonKey, dir: u8) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in key
        .low
        .ip()
        .octets()
        .iter()
        .chain(&key.low.port().to_be_bytes())
        .chain(&key.high.ip().octets())
        .chain(&key.high.port().to_be_bytes())
        .chain(&[dir])
    {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn mac(ip: &SocketAddrV4) -> [u8; 6] {
    let o = ip.ip().octets();
    [0x02, 0x00, o[0], o[1], o[2], o[3]]
}

fn packet(
    st: &mut ConnState,
    ts_ns: u64,
    dir: usize,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> SynthPacket {
    let (src, dst) = if dir == 0 {
        (st.client, st.server)
    } else {
        (st.server, st.client)
    };
    let ip_id = st.ip_id;
    st.ip_id = st.ip_id.wrapping_add(1);
    let mut f = Vec::with_capacity(54 + payload.len());
    f.extend_from_slice(&mac(&dst));
    f.extend_from_slice(&mac(&src));
    f.extend_from_slice(&[0x08, 0x00]);
    // IPv4
    let total = (20 + 20 + payload.len()) as u16;
    let ip_start = f.len();
    f.extend_from_slice(&[0x45, 0x00]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&ip_id.to_be_bytes());
    f.extend_from_slice(&[0x40, 0x00, 64, 6, 0, 0]);
    f.extend_from_slice(&src.ip().octets());
    f.extend_from_slice(&dst.ip().octets());
    let ip_csum = checksum(&f[ip_start..ip_start + 20], 0);
    f[ip_start + 10..ip_start + 12].copy_from_slice(&ip_csum.to_be_bytes());
    // TCP
    let tcp_start = f.len();
    f.extend_from_slice(&src.port().to_be_bytes());
    f.extend_from_slice(&dst.port().to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&(if flags & TCP_ACK != 0 { ack } else { 0 }).to_be_bytes());
    f.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    let mut pseudo = 0u32;
    for pair in src.ip().octets().chunks(2).chain(dst.ip().octets().chunks(2)) {
        pseudo += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    pseudo += 6 + (20 + payload.len()) as u32;
    let tcp_csum = checksum(&f[tcp_start..], pseudo);
    f[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    SynthPacket { ts_ns, frame: f }
}

fn checksum(bytes: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amf_to_udm() -> ConnTuple {
        ConnTuple {
            local: "172.22.0.10:40000".parse().unwrap(),
            remote: "172.22.0.12:7777".parse().unwrap(),
        }
    }
    fn udm_view() -> ConnTuple {
        ConnTuple {
            local: "172.22.0.12:7777".parse().unwrap(),
            remote: "172.22.0.10:40000".parse().unwrap(),
        }
    }
    fn tcp_seq(p: &SynthPacket) -> u32 {
        u32::from_be_bytes(p.frame[38..42].try_into().unwrap())
    }
    fn tcp_ack(p: &SynthPacket) -> u32 {
        u32::from_be_bytes(p.frame[42..46].try_into().unwrap())
    }

    #[test]
    fn first_record_emits_handshake_then_data_with_coherent_seq_ack() {
        let mut s = Synthesizer::new(DEFAULT_SERVER_PORTS);
        let mut data = H2_PREFACE.to_vec();
        data.extend_from_slice(b"abc");
        let p = s.push(1, amf_to_udm(), SslOp::Write, "open5gs-amfd", false, &data);
        assert_eq!(p.len(), 4);
        assert_eq!(p[0].frame[47], TCP_SYN);
        assert_eq!(p[1].frame[47], TCP_SYN | TCP_ACK);
        assert_eq!(tcp_ack(&p[1]), tcp_seq(&p[0]).wrapping_add(1));
        assert_eq!(tcp_seq(&p[3]), tcp_seq(&p[0]).wrapping_add(1));
        // Réponse serveur (vue par l'UDM en SSL_write).
        let r = s.push(2, udm_view(), SslOp::Write, "open5gs-udmd", false, b"xyz");
        assert_eq!(r.len(), 1);
        assert_eq!(tcp_seq(&r[0]), tcp_seq(&p[1]).wrapping_add(1));
        assert_eq!(tcp_ack(&r[0]), tcp_seq(&p[3]).wrapping_add(data.len() as u32));
        let m = s.manifest();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].client, "172.22.0.10:40000");
        assert_eq!(m[0].hpack_context, HpackContext::PrefaceSeen);
    }

    #[test]
    fn both_ends_probed_are_deduplicated_per_direction() {
        let mut s = Synthesizer::new(DEFAULT_SERVER_PORTS);
        s.push(1, amf_to_udm(), SslOp::Write, "open5gs-amfd", false, H2_PREFACE);
        // L'UDM lit les mêmes octets → doit être ignoré pour ce sens.
        let dup = s.push(2, udm_view(), SslOp::Read, "open5gs-udmd", false, H2_PREFACE);
        assert!(dup.is_empty());
        assert_eq!(s.counters.dedup_dropped_records, 1);
        assert_eq!(s.manifest()[0].bytes_client_to_server, H2_PREFACE.len() as u64);
    }

    #[test]
    fn connection_without_preface_is_flagged_mid_stream_not_hidden() {
        let mut s = Synthesizer::new(DEFAULT_SERVER_PORTS);
        s.push(1, amf_to_udm(), SslOp::Write, "open5gs-amfd", false, &[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        assert_eq!(s.mid_stream_connections(), 1);
    }

    #[test]
    fn server_settings_read_before_client_preface_is_not_mid_stream() {
        let mut s = Synthesizer::new(DEFAULT_SERVER_PORTS);
        s.push(1, amf_to_udm(), SslOp::Read, "c", false, &[0, 0, 0, 4, 0, 0, 0, 0, 0]);
        s.push(2, amf_to_udm(), SslOp::Write, "c", false, H2_PREFACE);
        assert_eq!(s.manifest()[0].hpack_context, HpackContext::PrefaceSeen);
    }

    #[test]
    fn large_record_is_split_and_checksums_verify() {
        let mut s = Synthesizer::new(DEFAULT_SERVER_PORTS);
        let data = vec![7u8; MAX_SEGMENT * 2 + 10];
        let p = s.push(1, amf_to_udm(), SslOp::Write, "x", false, &data);
        assert_eq!(p.len(), 3 + 3);
        assert_eq!(tcp_seq(&p[4]), tcp_seq(&p[3]).wrapping_add(MAX_SEGMENT as u32));
        // Checksum IPv4 : la somme sur l'en-tête complet doit valoir 0.
        assert_eq!(checksum(&p[3].frame[14..34], 0), 0);
    }

    #[test]
    fn replay_is_deterministic() {
        let run = || {
            let mut s = Synthesizer::new(DEFAULT_SERVER_PORTS);
            s.push(1, amf_to_udm(), SslOp::Write, "a", false, H2_PREFACE)
                .into_iter()
                .flat_map(|p| p.frame)
                .collect::<Vec<u8>>()
        };
        assert_eq!(run(), run());
    }
}
