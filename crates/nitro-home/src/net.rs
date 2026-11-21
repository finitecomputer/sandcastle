//! The home's network on the parent (docs/nitro-home.md, "Network"): a tap
//! whose traffic the parent NATs to the internet. The home is our own
//! measured code, so it takes no egress proxy (an agent's computer does);
//! what the rules keep it from is the parent and its networks: every
//! private, shared, link-local and loopback range (the parent's metadata
//! service at 169.254.169.254, its VPC, the tailnet's 100.64/10), and the
//! parent's own addresses, refused. Nothing from outside reaches the home
//! (no inbound port): a browser reaches it over the home's own tailnet
//! connection, which the parent carries as WireGuard.

use std::io::Write;
use std::process::{Command, Stdio};

use sandcastle_nitro_spike::run::Failure;

pub const MTU: u16 = 1500;

/// What the home may never reach through the parent.
pub const REFUSED: [&str; 9] = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"];

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

fn table(tap: &str) -> String {
    format!("nitrohome_{tap}")
}

/// The rules for one home's tap, as one nftables table of its own. `guest`
/// is the home's address.
pub fn ruleset(tap: &str, guest: &str) -> String {
    assert!(!tap.is_empty() && tap.bytes().all(|b| b.is_ascii_alphanumeric()), "a plain tap name");
    assert!(guest.parse::<std::net::Ipv4Addr>().is_ok(), "an IPv4 address");
    let refused = REFUSED.join(", ");
    let t = table(tap);
    format!(
        "table ip {t} {{
    chain input {{
        type filter hook input priority filter; policy accept;
        iifname \"{tap}\" ct state established,related accept
        iifname \"{tap}\" drop
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname \"{tap}\" ip saddr != {guest} drop
        iifname \"{tap}\" ip daddr {{ {refused} }} drop
        iifname \"{tap}\" fib daddr type local drop
        iifname \"{tap}\" accept
        oifname \"{tap}\" ct state established,related accept
        oifname \"{tap}\" drop
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr {guest} oifname != \"{tap}\" masquerade
    }}
}}
"
    )
}

fn guest_of(host: &str) -> String {
    let (net, _) = host.rsplit_once('.').expect("checked: a.b.c.1");
    format!("{net}.2")
}

/// Docker, when the parent runs it, drops forwarded traffic by default
/// (its iptables FORWARD policy): the home's tap is let through its
/// `DOCKER-USER` chain, which Docker keeps for this. No Docker, no rule.
fn docker_user(tap: &str, add: bool) {
    let has_chain = Command::new("iptables").args(["-n", "-L", "DOCKER-USER"]).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    if !has_chain {
        return;
    }
    let rules: [&[&str]; 2] = [&["-i", tap, "-j", "ACCEPT"], &["-o", tap, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]];
    for r in rules {
        let exists = Command::new("iptables").args(["-C", "DOCKER-USER"]).args(r).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
        match (add, exists) {
            (true, false) => {
                let _ = Command::new("iptables").args(["-I", "DOCKER-USER"]).args(r).status();
            }
            (false, true) => {
                let _ = Command::new("iptables").args(["-D", "DOCKER-USER"]).args(r).status();
            }
            _ => {}
        }
    }
}

/// Makes `tap` with the parent's address `host` (`a.b.c.1`, the home
/// `a.b.c.2`), turns forwarding on and loads the tap's rules.
pub fn up(tap: &str, host: &str) -> Result<(), Failure> {
    down(tap);
    run("making the tap", &["ip", "tuntap", "add", "dev", tap, "mode", "tap"], None)?;
    run("the tap's address", &["ip", "addr", "add", &format!("{host}/24"), "dev", tap], None)?;
    run("the tap up", &["ip", "link", "set", tap, "up"], None)?;
    run("forwarding", &["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"], None)?;
    run("the tap's rules", &["nft", "-f", "-"], Some(&ruleset(tap, &guest_of(host))))?;
    docker_user(tap, true);
    Ok(())
}

/// Removes `tap` and its rules, whatever is left of them.
pub fn down(tap: &str) {
    docker_user(tap, false);
    let _ = run("removing the rules", &["nft", "delete", "table", "ip", &table(tap)], None);
    let _ = run("removing the tap", &["ip", "link", "delete", tap], None);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the home's traffic goes out NATed from its own address only;
    // the parent, its metadata service and every private range are
    // refused; nothing from outside is forwarded in.
    #[test]
    fn rules_open_the_internet_and_nothing_of_the_parent() {
        let r = ruleset("nitrohome0", "10.0.9.2");
        assert!(r.contains("iifname \"nitrohome0\" ip saddr != 10.0.9.2 drop"), "no other source");
        for range in ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8"] {
            assert!(r.contains(range), "{range} refused");
        }
        assert!(r.contains("fib daddr type local drop"), "the parent's own addresses, public ones too");
        assert!(r.contains("chain input") && r.contains("iifname \"nitrohome0\" drop"), "nothing of the parent's own services");
        assert!(r.contains("oifname \"nitrohome0\" ct state established,related accept") && r.contains("oifname \"nitrohome0\" drop"), "only answers come in");
        assert!(r.contains("ip saddr 10.0.9.2 oifname != \"nitrohome0\" masquerade"));
        assert_eq!(guest_of("10.0.9.1"), "10.0.9.2");
    }
}
