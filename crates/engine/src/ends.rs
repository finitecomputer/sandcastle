//! Where a connection goes, across machines: a unix socket's path or a TCP
//! address (`End`), the address ranges a listener takes (`Cidr`), and the
//! ends a node lets a start name for its computer's egress
//! (`nitro.session_egress_allow`, docs/nitro.md "Computers on other
//! parents").

use std::path::{Component, Path, PathBuf};

/// One end of a relay between machines: a unix socket's path, or a TCP
/// address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    Unix(PathBuf),
    Tcp(std::net::SocketAddr),
}

impl std::str::FromStr for End {
    type Err = String;
    fn from_str(s: &str) -> Result<End, String> {
        match s.split_once(':') {
            Some(("unix", p)) if p.starts_with('/') => Ok(End::Unix(p.into())),
            Some(("tcp", a)) => a.parse().map(End::Tcp).map_err(|e| format!("{s}: {e}")),
            _ => Err(format!("{s}: unix:/<path> or tcp:<address>:<port>")),
        }
    }
}

/// An address range a TCP relay takes connections from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: std::net::IpAddr,
    bits: u8,
}

impl std::str::FromStr for Cidr {
    type Err = String;
    fn from_str(s: &str) -> Result<Cidr, String> {
        let (addr, bits) = s.split_once('/').unwrap_or((s, ""));
        let net: std::net::IpAddr = addr.parse().map_err(|e| format!("{s}: {e}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = if bits.is_empty() { max } else { bits.parse::<u8>().ok().filter(|b| *b <= max).ok_or_else(|| format!("{s}: a prefix of 0 to {max}"))? };
        Ok(Cidr { net, bits })
    }
}

impl Cidr {
    pub fn contains(&self, ip: std::net::IpAddr) -> bool {
        let ip = match ip {
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        let (a, b, len): (u128, u128, u32) = match (self.net, ip) {
            (std::net::IpAddr::V4(n), std::net::IpAddr::V4(i)) => (u32::from(n) as u128, u32::from(i) as u128, 32),
            (std::net::IpAddr::V6(n), std::net::IpAddr::V6(i)) => (u128::from(n), u128::from(i), 128),
            _ => return false,
        };
        let shift = len - self.bits as u32;
        shift >= len || (a >> shift) == (b >> shift)
    }
}


/// One entry of a node's `nitro.session_egress_allow`: unix sockets below a
/// directory (`unix:/dir/`), or TCP addresses in a range (`tcp:<cidr>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allowed {
    UnixUnder(PathBuf),
    TcpIn(Cidr),
}

impl std::str::FromStr for Allowed {
    type Err = String;
    fn from_str(s: &str) -> Result<Allowed, String> {
        match s.split_once(':') {
            Some(("unix", d)) if d.starts_with('/') && d.ends_with('/') && normal(Path::new(d)) => Ok(Allowed::UnixUnder(d.into())),
            Some(("tcp", c)) => c.parse().map(Allowed::TcpIn),
            _ => Err(format!("{s}: unix:/<a directory>/ or tcp:<cidr>")),
        }
    }
}

/// An absolute path of plain names: no `.`, no `..`.
fn normal(p: &Path) -> bool {
    p.is_absolute() && p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// Whether `end` is one `allow` takes: a socket at a normal path below one
/// of its directories, or an address in one of its ranges.
pub fn allowed(allow: &[Allowed], end: &End) -> bool {
    allow.iter().any(|a| match (a, end) {
        (Allowed::UnixUnder(dir), End::Unix(p)) => normal(p) && p.starts_with(dir) && p != dir,
        (Allowed::TcpIn(c), End::Tcp(addr)) => c.contains(addr.ip()),
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: a start's egress end is taken only where the node allows it: a
    // socket below an allowed directory (never by `..`), an address in an
    // allowed range; and the allow list reads as written, and nothing else.
    #[test]
    fn an_egress_end_is_allowed_only_where_the_node_says() {
        let allow: Vec<Allowed> = ["unix:/run/nitro-home/", "tcp:10.0.0.0/16"].iter().map(|a| a.parse().unwrap()).collect();
        let end = |s: &str| s.parse::<End>().unwrap();
        assert!(allowed(&allow, &end("unix:/run/nitro-home/t1/egress.sock")));
        assert!(allowed(&allow, &end("tcp:10.0.7.9:5104")));
        for no in ["unix:/run/nitro-home/../lane-a/x.sock", "unix:/run/other/egress.sock", "unix:/run/nitro-home-x/e.sock", "unix:/run/nitro-home/", "tcp:10.1.0.1:5104", "tcp:[fd00::1]:5104"] {
            assert!(!allowed(&allow, &end(no)), "{no}");
        }
        assert!(!allowed(&[], &end("unix:/run/nitro-home/t1/egress.sock")), "an empty list takes none");
        for bad in ["unix:/run/nitro-home", "unix:run/", "unix:/run/../x/", "tcp:10.0.0.0/40", "udp:10.0.0.0/8", "/run/"] {
            assert!(bad.parse::<Allowed>().is_err(), "{bad}");
        }
    }
}
