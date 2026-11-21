//! The sandbox's network on the parent (docs/nitro-spike.md, acceptance 7):
//! a tap, and nftables that send every TCP connection and every DNS query
//! arriving on it to sandcastle's forwarder (`PORT_TCP`, `PORT_DNS`), and
//! nothing anywhere else: no route out, no forward, no other port. The
//! forwarder hands each to sandcastle's egress proxy, which decides; the
//! proxy refuses private addresses, the parent's instance metadata
//! (169.254.169.254) among them.
//!
//! The tap lives in the parent's own namespace (Firecracker opens it by
//! name), so the rules are what keeps the guest off the parent's network.

use std::io::Write;
use std::process::{Command, Stdio};

use sandcastle_wire::egress::{PORT_DNS, PORT_TCP};

use crate::run::Failure;

/// The parent's side of the tap, and the guest's.
pub const HOST_ADDR: &str = "10.0.2.1";
pub const GUEST_ADDR: &str = "10.0.2.2/24";
pub const MTU: u16 = 1500;

fn run(what: &str, argv: &[&str], stdin: Option<&str>) -> Result<(), Failure> {
    let mut c = Command::new(argv[0]);
    c.args(&argv[1..]).stdout(Stdio::null()).stderr(Stdio::piped());
    if stdin.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut child = c.spawn().map_err(|e| Failure(format!("{what}: {e}")))?;
    if let Some(s) = stdin {
        child.stdin.take().expect("piped").write_all(s.as_bytes()).map_err(|e| Failure(format!("{what}: {e}")))?;
    }
    let out = child.wait_with_output().map_err(|e| Failure(format!("{what}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(Failure(format!("{what}: {}", String::from_utf8_lossy(&out.stderr).trim())))
    }
}

/// The rules for one tap, as one nftables table of its own.
pub fn ruleset(tap: &str) -> String {
    assert!(!tap.is_empty() && tap.bytes().all(|b| b.is_ascii_alphanumeric()), "a plain tap name");
    format!(
        "table ip nitro_{tap} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname \"{tap}\" udp dport 53 redirect to :{PORT_DNS}
        iifname \"{tap}\" meta l4proto tcp redirect to :{PORT_TCP}
    }}
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname \"{tap}\" udp dport {PORT_DNS} accept
        iifname \"{tap}\" tcp dport {PORT_TCP} accept
        iifname \"{tap}\" ct state established,related accept
        iifname \"{tap}\" drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname \"{tap}\" drop
        oifname \"{tap}\" drop
    }}
}}
"
    )
}

/// Makes `tap` with the parent's address and loads its rules.
pub fn up(tap: &str) -> Result<(), Failure> {
    down(tap);
    run("making the tap", &["ip", "tuntap", "add", "dev", tap, "mode", "tap"], None)?;
    run("the tap's address", &["ip", "addr", "add", &format!("{HOST_ADDR}/24"), "dev", tap], None)?;
    run("the tap up", &["ip", "link", "set", tap, "up"], None)?;
    run("the tap's rules", &["nft", "-f", "-"], Some(&ruleset(tap)))
}

/// Removes `tap` and its rules, whatever is left of them.
pub fn down(tap: &str) {
    let _ = run("removing the rules", &["nft", "delete", "table", "ip", &format!("nitro_{tap}")], None);
    let _ = run("removing the tap", &["ip", "link", "delete", tap], None);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the rules send the tap's TCP and DNS to the forwarder, drop
    // everything else it sends, and route nothing through the parent.
    #[test]
    fn rules_only_reach_the_forwarder() {
        let r = ruleset("tap0");
        assert!(r.contains(&format!("iifname \"tap0\" meta l4proto tcp redirect to :{PORT_TCP}")));
        assert!(r.contains(&format!("iifname \"tap0\" udp dport 53 redirect to :{PORT_DNS}")));
        assert!(r.contains("iifname \"tap0\" drop\n"), "anything else the guest sends the parent is dropped");
        assert!(r.contains("chain forward") && r.contains("oifname \"tap0\" drop"), "no route through the parent either way");
    }
}
