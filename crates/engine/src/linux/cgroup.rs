//! The engine's cgroup subtree (cgroup v2), delegated by its service
//! manager. cgroup v2 keeps processes in leaves only, so the engine moves
//! itself into `engine/` and makes one sibling per VM, `vm-<slot>`, with
//! its memory, CPU, and process limits. A VM boots at full CPU and gets
//! its instance's share once it says ready, so a `lite` VM's boot is not
//! a sixteenth as fast.

use std::io;
use std::path::{Path, PathBuf};

use crate::api::Resources;
use crate::config::{PIDS_PER_VM_MAX, VMM_OVERHEAD_MIB};

const ROOT: &str = "/sys/fs/cgroup";
/// cpu.max's period, in microseconds: long, so a mostly idle VM's request
/// runs at full speed on its period's quota (and the burst it saved). A
/// 20 ms period, measured, spread every `lite` request out to sixteen
/// times its CPU time (a 2.6 ms handler call took 60 ms), where 100 ms
/// leaves most at 2.6 ms and stalls the rest one period.
const PERIOD_US: u64 = 100_000;

pub struct Subtree {
    root: PathBuf,
}

fn write(p: &Path, value: &str) -> io::Result<()> {
    std::fs::write(p, value).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))
}

/// The cgroup this process is in, from `/proc/self/cgroup`'s v2 line.
fn own() -> io::Result<PathBuf> {
    let s = std::fs::read_to_string("/proc/self/cgroup")?;
    let line = s.lines().find(|l| l.starts_with("0::")).ok_or_else(|| io::Error::other("no cgroup v2"))?;
    Ok(Path::new(ROOT).join(line.trim_start_matches("0::").trim_start_matches('/')))
}

impl Subtree {
    /// Takes the subtree this process was given: moves itself into
    /// `engine/` and enables the controllers its VMs need.
    pub fn take() -> io::Result<Subtree> {
        let mut root = own()?;
        // A restarted engine already sits in `engine/`.
        if root.file_name().is_some_and(|n| n == "engine") {
            root.pop();
        }
        let leaf = root.join("engine");
        match std::fs::create_dir(&leaf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        write(&leaf.join("cgroup.procs"), &std::process::id().to_string())?;
        write(&root.join("cgroup.subtree_control"), "+memory +cpu +pids")?;
        Ok(Subtree { root })
    }

    pub fn vm(&self, slot: u32) -> PathBuf {
        self.root.join(format!("vm-{slot}"))
    }

    /// The VM's cgroup, made fresh: memory and processes capped, CPU
    /// unthrottled until ready.
    pub fn make(&self, slot: u32, r: &Resources) -> io::Result<PathBuf> {
        let cg = self.vm(slot);
        if cg.exists() {
            self.remove(slot)?;
        }
        std::fs::create_dir(&cg)?;
        let bytes = (r.memory_mib as u64 + VMM_OVERHEAD_MIB) << 20;
        write(&cg.join("memory.max"), &bytes.to_string())?;
        write(&cg.join("memory.swap.max"), "0")?;
        write(&cg.join("pids.max"), &PIDS_PER_VM_MAX.to_string())?;
        write(&cg.join("cpu.max"), &format!("max {PERIOD_US}"))?;
        Ok(cg)
    }

    /// The instance's CPU share, once the VM is ready, and a burst of one
    /// period's quota saved while idle (the kernel's ceiling for it).
    pub fn throttle(&self, slot: u32, r: &Resources) -> io::Result<()> {
        let cg = self.vm(slot);
        write(&cg.join("cpu.max"), &cpu_max(r.cpu_milli))?;
        write(&cg.join("cpu.max.burst"), &quota_us(r.cpu_milli).to_string())
    }

    /// Kills whatever is left in the VM's cgroup and removes it.
    pub fn remove(&self, slot: u32) -> io::Result<()> {
        let cg = self.vm(slot);
        if !cg.exists() {
            return Ok(());
        }
        let _ = write(&cg.join("cgroup.kill"), "1");
        // Bounded: rmdir succeeds once the kill has reaped the last
        // process, a few milliseconds; 200 tries of 5 ms each.
        for _ in 0..200 {
            match std::fs::remove_dir(&cg) {
                Ok(()) => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::other(format!("{} stayed busy", cg.display())))
    }

    /// The VM's memory as charged: what it holds on the node.
    pub fn memory_current(&self, slot: u32) -> Option<u64> {
        std::fs::read_to_string(self.vm(slot).join("memory.current")).ok()?.trim().parse().ok()
    }

    /// What the VM holds that the node cannot take back: its charge less
    /// the host's page cache (`in_use`).
    pub fn memory_in_use(&self, slot: u32) -> Option<u64> {
        let cg = self.vm(slot);
        let current = std::fs::read_to_string(cg.join("memory.current")).ok()?;
        in_use(&current, &std::fs::read_to_string(cg.join("memory.stat")).ok()?)
    }

    /// Every VM cgroup present, by slot (an engine restarting finds them).
    /// The processes in a VM's cgroup.
    pub fn procs(&self, slot: u32) -> Vec<u32> {
        std::fs::read_to_string(self.vm(slot).join("cgroup.procs")).map(|s| s.lines().filter_map(|l| l.parse().ok()).collect()).unwrap_or_default()
    }

    pub fn slots(&self) -> Vec<u32> {
        let Ok(d) = std::fs::read_dir(&self.root) else { return vec![] };
        d.flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_prefix("vm-")).and_then(|s| s.parse().ok()))
            .collect()
    }
}

/// A VM's charge (`memory.current`) less its page cache (`memory.stat`'s
/// `file`), and never less than what one `memory.stat` read says it holds
/// that the host can't reclaim: anonymous, shared and kernel memory. The
/// guest's memory is the VMM's anonymous memory; the file pages are the
/// host's cache of the VM's disks (and the VMM's own libraries), which the
/// host reclaims when it needs the room and which the guest caches again
/// itself. Measured on a 6 GiB computer that wrote and read 2 GiB: a charge
/// of 4.3 GiB, 2.0 GiB of it file pages.
///
/// The bound is needed because the two files are two reads: cache the host
/// adds between them is subtracted from a charge read before it, which can
/// report a VM holding 700 MiB as 100 MiB, or as nothing.
fn in_use(current: &str, stat: &str) -> Option<u64> {
    let current: u64 = current.trim().parse().ok()?;
    let line = |key: &str| stat.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(' ')?.trim().parse::<u64>().ok());
    let file = line("file")?;
    let held = line("anon")?.saturating_add(line("shmem").unwrap_or(0)).saturating_add(line("kernel").unwrap_or(0));
    Some(current.saturating_sub(file).max(held))
}

/// A period's quota for a share of CPU in thousandths, at least the
/// kernel's 1 ms.
fn quota_us(cpu_milli: u32) -> u64 {
    (cpu_milli as u64 * PERIOD_US / 1000).max(1000)
}

/// `cpu.max` for a share of CPU in thousandths.
pub fn cpu_max(cpu_milli: u32) -> String {
    format!("{} {PERIOD_US}", quota_us(cpu_milli))
}

#[cfg(test)]
mod tests {
    #[test]
    fn cpu_shares() {
        assert_eq!(super::cpu_max(63), "6300 100000", "lite: 1/16 vCPU");
        assert_eq!(super::cpu_max(2000), "200000 100000");
        assert_eq!(super::cpu_max(1), "1000 100000", "a floor the kernel accepts");
    }

    // Goal: in use is the charge less the page cache, by memory.stat's
    // `file` line alone (not `file_mapped`, `file_dirty`, ...), and never
    // below the anonymous, shared and kernel memory of the same read.
    #[test]
    fn in_use() {
        let stat = "anon 2390753280\nfile_mapped 4096\nfile 2162163712\nfile_dirty 0\nkernel 30097408\n";
        assert_eq!(super::in_use("4582080512\n", stat), Some(2390753280 + 30097408), "a charge read a moment apart: the larger");
        assert_eq!(super::in_use("5000000000\n", stat), Some(5000000000 - 2162163712));
        assert_eq!(super::in_use("100\n", "anon 0\nfile 200\n"), Some(0), "never below zero");
        assert_eq!(super::in_use("100\n", "anon 100\n"), None, "no file line");
        assert_eq!(super::in_use("100\n", "file 100\n"), None, "no anon line");
        assert_eq!(super::in_use("100\n", "anon 50\nfile 10\nshmem 70\n"), Some(120), "shared memory is held too");
        assert_eq!(super::in_use("max\n", stat), None);
    }

    // Goal: page cache that grows between the two reads never hides the
    // guest's own memory. Invalid: the charge is read at 800 MiB, then the
    // host caches 600 MiB more of the VM's disk before memory.stat is read
    // (anon 700 MiB, file 700 MiB). The 700 MiB the guest holds throughout
    // is still counted, not 800 - 700 = 100 MiB.
    #[test]
    fn cache_grown_between_reads_hides_nothing() {
        const MIB: u64 = 1 << 20;
        let stat = format!("anon {}\nfile {}\nkernel 0\nshmem 0\n", 700 * MIB, 700 * MIB);
        let got = super::in_use(&format!("{}\n", 800 * MIB), &stat).expect("a number");
        assert!(got >= 700 * MIB, "reported {} MiB", got / MIB);
    }
}
