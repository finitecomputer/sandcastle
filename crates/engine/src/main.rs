//! `sandcastle-engine`: a node's microVM engine (docs/krun-engine.md).
//!
//! - `serve --config <path>`: as root, in a delegated cgroup subtree,
//!   serve the API on the state directory's `engine.sock`.
//! - `reset --config <path> --cgroup <dir> [--all]`: as root, end every VM
//!   in the engine's subtree and hand the node user's files back; with
//!   `--all`, remove the engine's whole state directory.
//! - `hold`: what the VMs' own unit runs (docs/nitro.md, "Restarts"): it
//!   moves itself into its unit's `keeper/` leaf, so the unit's cgroup can
//!   hand its controllers to the VMs' cgroups, and waits.

use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: sandcastle-engine serve --config <path> | reset --config <path> --cgroup <dir> [--all] | hold");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    if args.first().map(String::as_str) == Some("hold") {
        return hold();
    }
    let Some(config) = flag("--config") else { return usage() };
    let config: sandcastle_engine::EngineConfig = match std::fs::read(&config)
        .map_err(|e| e.to_string())
        .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sandcastle-engine: config: {e}");
            return ExitCode::FAILURE;
        }
    };
    match args.first().map(String::as_str) {
        Some("serve") => serve(config),
        Some("reset") => match flag("--cgroup") {
            Some(cg) => reset(config, PathBuf::from(cg), args.iter().any(|a| a == "--all")),
            None => usage(),
        },
        _ => usage(),
    }
}

#[cfg(target_os = "linux")]
fn serve(config: sandcastle_engine::EngineConfig) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sandcastle-engine: runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(async {
        let node = sandcastle_engine::linux::node_addrs();
        let engine = match sandcastle_engine::linux::engine::Engine::open(config, node) {
            Ok(e) => std::sync::Arc::new(e),
            Err(e) => {
                eprintln!("sandcastle-engine: {e}");
                return ExitCode::FAILURE;
            }
        };
        eprintln!("sandcastle-engine: recovered {}", engine.recover());
        let sock = engine.config().socket();
        let _ = std::fs::remove_file(&sock);
        let listener = match tokio::net::UnixListener::bind(&sock) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sandcastle-engine: {}: {e}", sock.display());
                return ExitCode::FAILURE;
            }
        };
        let ports_sock = engine.config().ports_socket();
        let _ = std::fs::remove_file(&ports_sock);
        let ports = match tokio::net::UnixListener::bind(&ports_sock) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sandcastle-engine: {}: {e}", ports_sock.display());
                return ExitCode::FAILURE;
            }
        };
        let c = engine.config();
        for s in [&sock, &ports_sock] {
            let _ = std::os::unix::fs::chown(s, Some(c.client_uid), Some(c.client_gid));
            let _ = std::fs::set_permissions(s, std::os::unix::fs::PermissionsExt::from_mode(0o600));
        }
        eprintln!("sandcastle-engine: serving on {} and {}", sock.display(), ports_sock.display());
        let sweeper = engine.clone();
        tokio::spawn(async move {
            // Unbounded by design: hourly, for the engine's life.
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                sweeper.sweep_snapshots();
            }
        });
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a signal handler");
        tokio::select! {
            _ = sandcastle_engine::linux::server::serve(engine.clone(), listener) => {}
            _ = sandcastle_engine::linux::ports::serve(engine.clone(), ports) => {}
            _ = term.recv() => {
                eprintln!("sandcastle-engine: stopping; its VMs keep running");
            }
        }
        ExitCode::SUCCESS
    })
}

/// Ends every VM under the engine's cgroup subtree, removes their run
/// directories, and hands data disks back to the node's user.
#[cfg(target_os = "linux")]
fn reset(config: sandcastle_engine::EngineConfig, cgroup: PathBuf, all: bool) -> ExitCode {
    if !cgroup.starts_with("/sys/fs/cgroup/") {
        eprintln!("sandcastle-engine reset: --cgroup is under /sys/fs/cgroup");
        return ExitCode::FAILURE;
    }
    // Each VM's cgroup (and an engine's own `engine/` leaf, which a stopped
    // engine left), never the subtree's root: a VMs' unit's keeper lives
    // in its `keeper/` leaf and stays.
    let ended: Vec<PathBuf> = std::fs::read_dir(&cgroup)
        .map(|d| d.flatten().map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("vm-") || n == "engine")).collect())
        .unwrap_or_default();
    for cg in &ended {
        let _ = std::fs::write(cg.join("cgroup.kill"), "1");
    }
    std::thread::sleep(std::time::Duration::from_millis(200));
    for cg in &ended {
        if cg.file_name().is_some_and(|n| n != "engine") {
            let _ = std::fs::remove_dir(cg);
        }
    }
    let _ = std::fs::remove_dir_all(config.vms());
    let _ = std::fs::remove_dir_all(config.tmp());
    if all {
        // Everything the engine kept: images, blobs, snapshots, data, its CA.
        let _ = std::fs::remove_dir_all(&config.state_dir);
        println!("{{\"reset\":true,\"all\":true}}");
        return ExitCode::SUCCESS;
    }
    if let Ok(d) = std::fs::read_dir(config.data()) {
        for e in d.flatten() {
            let _ = std::os::unix::fs::lchown(e.path(), Some(config.client_uid), Some(config.client_gid));
        }
    }
    println!("{{\"reset\":true}}");
    ExitCode::SUCCESS
}

/// The VMs' own unit's one process: in its `keeper/` leaf, it waits, and
/// its unit's stop (`KillMode=process`) ends it alone.
#[cfg(target_os = "linux")]
fn hold() -> ExitCode {
    match sandcastle_engine::linux::cgroup::Subtree::hold() {
        Ok(root) => eprintln!("sandcastle-engine hold: keeping {} for the VMs", root.display()),
        Err(e) => {
            eprintln!("sandcastle-engine hold: {e}");
            return ExitCode::FAILURE;
        }
    }
    loop {
        // SAFETY: pause(2) has no preconditions; a signal's default action ends the process.
        unsafe { libc::pause() };
    }
}

#[cfg(not(target_os = "linux"))]
fn hold() -> ExitCode {
    eprintln!("sandcastle-engine runs on Linux");
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn serve(_: sandcastle_engine::EngineConfig) -> ExitCode {
    eprintln!("sandcastle-engine runs on Linux");
    ExitCode::FAILURE
}

#[cfg(not(target_os = "linux"))]
fn reset(_: sandcastle_engine::EngineConfig, _: PathBuf, _: bool) -> ExitCode {
    eprintln!("sandcastle-engine runs on Linux");
    ExitCode::FAILURE
}
