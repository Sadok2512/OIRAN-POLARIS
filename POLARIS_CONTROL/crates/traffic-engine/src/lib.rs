use serde::{Deserialize, Serialize};
use std::net::IpAddr;
pub const VERSION: &str = "0.1.0";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Protocol {
    Icmp,
    Udp,
    Tcp,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub protocol: Protocol,
    pub destination: IpAddr,
    pub packet_count: u16,
    pub packet_size: u16,
    pub rate_per_second: u16,
    pub duration_seconds: u16,
}
pub fn validate(p: &Profile, allowed: &[IpAddr]) -> Result<(), String> {
    if !allowed.contains(&p.destination) {
        return Err("destination is not an approved laboratory endpoint".into());
    }
    if p.packet_count == 0
        || p.packet_count > 100
        || p.packet_size < 32
        || p.packet_size > 1400
        || p.rate_per_second == 0
        || p.rate_per_second > 10
        || p.duration_seconds == 0
        || p.duration_seconds > 60
    {
        return Err("traffic profile exceeds bounded limits".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_allowlist() {
        let ip = "10.77.22.1".parse().unwrap();
        let p = Profile {
            protocol: Protocol::Udp,
            destination: ip,
            packet_count: 5,
            packet_size: 64,
            rate_per_second: 1,
            duration_seconds: 5,
        };
        assert!(validate(&p, &[ip]).is_ok());
        assert!(validate(&p, &[]).is_err());
        let mut bad = p;
        bad.packet_count = 101;
        assert!(validate(&bad, &[ip]).is_err())
    }
}
