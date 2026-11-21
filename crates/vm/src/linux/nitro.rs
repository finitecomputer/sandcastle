//! The runner's Nitro Sandbox (docs/nitro.md, "The runner"): Firecracker
//! as the runner's child, in the same jail, in place of libkrun in the
//! runner's own thread. The runner keeps everything else it does for
//! libkrun: the guest's lifecycle channel (Firecracker's vsock hands the
//! guest's dial to the host's port 1025 to `v.sock_1025`), the agent
//! socket (relayed into the vsock with Firecracker's `CONNECT 1024`), its
//! control socket, the boot watchdog and the network's forwarder.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::config::{Nitro, Net, VmConfig};
use crate::firecracker::{Boot, Drive, Enclave, Mode, Nic, Parent, Sandbox, Vsock};
use crate::paths;

/// How long a relay waits for Firecracker's answer to `CONNECT`.
const CONNECT_WAIT: Duration = Duration::from_secs(5);
/// The answer's longest line (`OK <port>\n`).
const ANSWER_BYTES_MAX: u64 = 64;

/// Firecracker's description of the VM `config` asks for. The parent's
/// size bounds only the vCPUs, which the engine has already admitted, so
/// the jail need not read `/sys`: a parent as large as the config's limit.
pub fn sandbox(config: &VmConfig, nitro: &Nitro) -> Sandbox {
    let drive = |i: usize, d: &crate::config::Disk| Drive { id: format!("vd{}", (b'a' + i as u8) as char), path: d.path.clone(), read_only: d.role.read_only(), dmb_mib: None };
    Sandbox {
        boot: Boot::Kernel { kernel: nitro.kernel.clone(), initrd: Some(nitro.initrd.clone()), cmdline: config.nitro_cmdline().expect("a Nitro config") },
        vcpus: u32::from(config.vcpus),
        memory_mib: config.memory_mib,
        drives: config.disks.iter().enumerate().map(|(i, d)| drive(i, d)).collect(),
        nics: match &config.net {
            Net::None => vec![],
            Net::Tap { name, mac } => vec![Nic { id: "eth0".into(), tap: name.clone(), guest_mac: Some(*mac), dmb_mib: None }],
        },
        vsock: Vsock { guest_cid: nitro.guest_cid, uds_path: config.sock(paths::NITRO_VSOCK), dmb_mib: None },
        enclave: Enclave {
            mode: if nitro.confidential { Mode::Confidential } else { Mode::Direct },
            cpu_overcommit: nitro.cpu_overcommit,
            hotplug: false,
            debug: false,
            cpu_accounting: false,
        },
    }
}

/// The parent the engine admitted the VM on, as far as `Sandbox`'s checks
/// go: its vCPUs never past the config's own limit.
pub const PARENT: Parent = Parent { vcpus: crate::config::VCPUS_MAX as u32 + 1, first_core_vcpus: 1 };

/// Writes Firecracker's configuration and starts it, its output to the
/// console log (the guest's console is Firecracker's only outside debug
/// mode, and debug mode is never asked for).
pub fn spawn(config: &VmConfig, nitro: &Nitro, console: &Path) -> std::io::Result<Child> {
    let json = sandbox(config, nitro).render(&PARENT).map_err(std::io::Error::other)?;
    let at = config.sock(paths::NITRO_CONFIG);
    std::fs::write(&at, json)?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(console)?;
    Command::new(&nitro.firecracker)
        .arg("--no-api")
        .arg("--config-file")
        .arg(&at)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
}

/// One host-side connection into the guest's agent: `CONNECT 1024` on
/// Firecracker's vsock, its `OK` read, then a plain stream.
pub fn connect_agent(vsock: &Path) -> std::io::Result<UnixStream> {
    let mut s = UnixStream::connect(vsock)?;
    s.set_read_timeout(Some(CONNECT_WAIT))?;
    s.write_all(format!("CONNECT {}\n", sandcastle_wire::PORT_AGENT).as_bytes())?;
    // A byte at a time: what follows the answer's newline is the agent's,
    // and a buffered reader would take it.
    let mut line = Vec::new();
    let mut b = [0u8; 1];
    while line.last() != Some(&b'\n') {
        if line.len() as u64 >= ANSWER_BYTES_MAX || s.read(&mut b)? == 0 {
            break;
        }
        line.push(b[0]);
    }
    if !line.starts_with(b"OK ") || line.last() != Some(&b'\n') {
        return Err(std::io::Error::other(format!("Firecracker's vsock answered {:?}", String::from_utf8_lossy(&line).trim_end())));
    }
    s.set_read_timeout(None)?;
    Ok(s)
}

/// Copies one way until EOF, then closes the other side's write half, so
/// each direction ends on its own as a socketpair would.
fn pump(mut from: UnixStream, to: UnixStream) {
    let _ = std::io::copy(&mut from, &mut &to);
    let _ = to.shutdown(std::net::Shutdown::Write);
}

/// Serves the agent socket for the VM's life: each connection a relay of
/// its own into the guest. A connection the guest refuses is dropped, as
/// libkrun drops one.
pub fn serve_agent(listener: UnixListener, vsock: std::path::PathBuf) {
    // Unbounded by design: the agent socket serves for the VM's life.
    for conn in listener.incoming() {
        let Ok(host) = conn else { continue };
        let vsock = vsock.clone();
        let _ = std::thread::Builder::new().name("agent-relay".into()).spawn(move || {
            let Ok(guest) = connect_agent(&vsock) else { return };
            let (Ok(host2), Ok(guest2)) = (host.try_clone(), guest.try_clone()) else { return };
            let back = std::thread::spawn(move || pump(guest2, host2));
            pump(host, guest);
            let _ = back.join();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::nitro_config;
    use std::io::{BufRead, BufReader};

    // Goal: the VM config becomes the sandbox the spike launched: the
    // verity table on the kernel's line, the hash tree first and every
    // shared disk read-only, the tap with the guest's MAC, the vsock in
    // the run directory. Method: render it and read the JSON back.
    #[test]
    fn a_vm_config_renders_as_its_sandbox() {
        let c = nitro_config();
        let n = c.nitro.as_ref().unwrap();
        let json: serde_json::Value = serde_json::from_str(&sandbox(&c, n).render(&PARENT).unwrap()).unwrap();
        let args = json["boot-source"]["boot_args"].as_str().unwrap();
        assert!(args.starts_with("panic=1 initcall_blacklist=i8042_init quiet dm-mod.create=\"sc-image,,,ro,0 "));
        assert!(args.contains(" verity 1 /dev/vdb /dev/vda 4096 4096 "));
        assert!(args.contains(&n.verity.as_ref().unwrap().root_hash));
        assert!(args.contains(" sandcastle.image=/dev/dm-0"));
        assert_eq!(json["boot-source"]["initrd_path"], n.initrd.to_str().unwrap());
        let drives = json["drives"].as_array().unwrap();
        assert_eq!(drives.len(), 3);
        assert_eq!((drives[0]["is_read_only"].as_bool(), drives[1]["is_read_only"].as_bool(), drives[2]["is_read_only"].as_bool()), (Some(true), Some(true), Some(false)));
        assert!(drives.iter().all(|d| d["is_root_device"] == false && d["dmb_size_mib"] == 16));
        assert_eq!(json["network-interfaces"][0]["guest_mac"], "02:53:43:00:00:07");
        assert_eq!(json["vsock"]["uds_path"], "/vm/v.sock");
        assert_eq!(json["vsock"]["guest_cid"], 10);
        assert_eq!(json["enclave"]["direct_mode"], false);
    }

    // Goal: the relay hands a stream through only after Firecracker's OK,
    // and refuses any other answer. Method: a fake vsock that answers each
    // way.
    #[test]
    fn the_agent_relay_waits_for_firecrackers_ok() {
        let dir = std::env::temp_dir().join(format!("nitro-relay-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (answer, ok) in [("OK 1073741824\n", true), ("FAILURE\n", false), ("OK", false)] {
            let path = dir.join("v.sock");
            let _ = std::fs::remove_file(&path);
            let l = UnixListener::bind(&path).unwrap();
            let fake = std::thread::spawn(move || {
                let (mut s, _) = l.accept().unwrap();
                let mut line = String::new();
                BufReader::new(&s).read_line(&mut line).unwrap();
                assert_eq!(line, "CONNECT 1024\n");
                s.write_all(answer.as_bytes()).unwrap();
                if answer.ends_with('\n') {
                    s.write_all(b"hello").unwrap();
                }
            });
            let r = connect_agent(&path);
            assert_eq!(r.is_ok(), ok, "{answer:?}");
            if let Ok(mut s) = r {
                let mut got = String::new();
                s.read_to_string(&mut got).unwrap();
                assert_eq!(got, "hello");
            }
            fake.join().unwrap();
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
