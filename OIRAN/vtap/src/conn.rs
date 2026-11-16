//! Résolution `(tgid, fd)` → 4-tuple TCP via `/proc` (netns du processus).
//!
//! `/proc/<tgid>/fd/<fd>` → `socket:[inode]`, puis `/proc/<tgid>/net/tcp`
//! (vu depuis le netns du conteneur) → adresses locale/distante. Aucun
//! fallback silencieux : chaque échec est typé et compté au manifeste.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConnTuple {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// L'eBPF n'a pas pu attribuer de fd (aucun syscall observé).
    FdUnknown,
    /// fd fermé / processus disparu avant résolution.
    FdGone,
    /// fd qui n'est pas un socket.
    NotSocket,
    /// Socket introuvable en IPv4 (IPv6 / unix) — non supporté en 2.21.0.
    UnsupportedFamily,
}

impl ResolveError {
    pub fn counter(&self) -> &'static str {
        match self {
            Self::FdUnknown => "fd_unknown",
            Self::FdGone => "fd_gone",
            Self::NotSocket => "not_socket",
            Self::UnsupportedFamily => "unsupported_family",
        }
    }
}

/// Parse `/proc/<pid>/net/tcp` → inode → tuple. Format noyau :
/// `sl local_address rem_address st ... inode` avec adresses
/// `AABBCCDD:PPPP` (IPv4 little-endian hex, port big-endian hex).
pub fn parse_proc_net_tcp(text: &str) -> HashMap<u64, ConnTuple> {
    let mut out = HashMap::new();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_addr(cols[1]), parse_addr(cols[2])) else {
            continue;
        };
        if let Ok(inode) = cols[9].parse::<u64>() {
            if inode != 0 {
                out.insert(inode, ConnTuple { local, remote });
            }
        }
    }
    out
}

fn parse_addr(value: &str) -> Option<SocketAddrV4> {
    let (ip, port) = value.split_once(':')?;
    if ip.len() != 8 {
        return None;
    }
    let raw = u32::from_str_radix(ip, 16).ok()?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some(SocketAddrV4::new(Ipv4Addr::from(raw.swap_bytes()), port))
}

/// Résolveur avec cache `(tgid, fd, inode)`. Le cache est invalidé dès
/// que l'inode du fd change (réutilisation de fd → nouvelle connexion).
pub struct ProcResolver {
    proc_root: PathBuf,
    cache: HashMap<(u32, i32), (u64, ConnTuple)>,
}

impl ProcResolver {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            cache: HashMap::new(),
        }
    }

    pub fn resolve(&mut self, tgid: u32, fd: i32) -> Result<ConnTuple, ResolveError> {
        if fd < 0 {
            return Err(ResolveError::FdUnknown);
        }
        let link = self
            .proc_root
            .join(tgid.to_string())
            .join("fd")
            .join(fd.to_string());
        let target = match std::fs::read_link(&link) {
            Ok(t) => t,
            // fd déjà fermé : les records restants sont la fin de la
            // DERNIÈRE connexion portée par ce fd (un fd n'est réutilisé
            // qu'après close, et l'eBPF émet avant close). Le cache est
            // donc exact ; sans cache → FdGone compté.
            Err(_) => {
                return self
                    .cache
                    .get(&(tgid, fd))
                    .map(|(_, t)| *t)
                    .ok_or(ResolveError::FdGone)
            }
        };
        let target = target.to_string_lossy();
        let inode = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or(ResolveError::NotSocket)?;
        if let Some((cached_inode, tuple)) = self.cache.get(&(tgid, fd)) {
            if *cached_inode == inode {
                return Ok(*tuple);
            }
        }
        let net = self.proc_root.join(tgid.to_string()).join("net").join("tcp");
        let text = std::fs::read_to_string(net).map_err(|_| ResolveError::FdGone)?;
        let tuple = *parse_proc_net_tcp(&text)
            .get(&inode)
            .ok_or(ResolveError::UnsupportedFamily)?;
        self.cache.insert((tgid, fd), (inode, tuple));
        Ok(tuple)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0A0016AC:1E61 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0A0016AC:9C40 0C0016AC:1E61 01 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 20 4 30 10 -1
";

    #[test]
    fn parses_proc_net_tcp_ipv4_little_endian() {
        let map = parse_proc_net_tcp(NET_TCP);
        let t = map[&2222];
        assert_eq!(t.local, "172.22.0.10:40000".parse().unwrap());
        assert_eq!(t.remote, "172.22.0.12:7777".parse().unwrap());
        assert_eq!(map[&1111].local.port(), 7777);
    }

    #[test]
    fn resolves_fd_through_fake_proc_tree_and_tracks_fd_reuse() {
        let root = std::env::temp_dir().join(format!("vtap-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("42/fd")).unwrap();
        std::fs::create_dir_all(root.join("42/net")).unwrap();
        std::fs::write(root.join("42/net/tcp"), NET_TCP).unwrap();
        std::os::unix::fs::symlink("socket:[2222]", root.join("42/fd/7")).unwrap();
        std::os::unix::fs::symlink("/dev/null", root.join("42/fd/8")).unwrap();
        let mut resolver = ProcResolver::new(&root);
        let t = resolver.resolve(42, 7).unwrap();
        assert_eq!(t.remote.port(), 7777);
        assert_eq!(resolver.resolve(42, 8), Err(ResolveError::NotSocket));
        assert_eq!(resolver.resolve(42, 9), Err(ResolveError::FdGone));
        // fd 7 fermé après une première résolution → tuple du cache.
        std::fs::remove_file(root.join("42/fd/7")).unwrap();
        assert_eq!(resolver.resolve(42, 7).unwrap().remote.port(), 7777);
        assert_eq!(resolver.resolve(42, -1), Err(ResolveError::FdUnknown));
        // Réutilisation du fd 7 sur un autre socket (inode absent en IPv4).
        std::os::unix::fs::symlink("socket:[9999]", root.join("42/fd/7")).unwrap();
        assert_eq!(resolver.resolve(42, 7), Err(ResolveError::UnsupportedFamily));
        let _ = std::fs::remove_dir_all(&root);
    }
}
