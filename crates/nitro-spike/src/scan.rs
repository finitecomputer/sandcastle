//! What the parent can read, searched for a canary (docs/nitro-spike.md,
//! acceptance 3). Three places, each stated exactly in the evidence:
//!
//! - **Firecracker's own memory**: every readable mapping in
//!   `/proc/<pid>/maps`, read through `/proc/<pid>/mem` as root.
//! - **The parent's physical memory**: every System RAM range of
//!   `/proc/iomem`, read through `/proc/kcore` (the kernel's view of RAM)
//!   as root. This is where a sandbox's pages live, donated or not.
//! - **A file**: a block device's backing file, or Firecracker's log (the
//!   console).
//!
//! The needle is the canary repeated [`RUN_REPEATS`] times. The guest
//! fills megabytes with it; the parent holds the text once in the command
//! it sent and once in this scanner's needle. So a count of matches far
//! above one is the guest's memory; one or two are our own copies.

use std::io::Read;
use std::os::unix::fs::FileExt;

use memchr::memmem;
use serde::Serialize;

/// How many times the canary repeats in the needle.
pub const RUN_REPEATS: usize = 64;
/// Read this much at a time.
pub const CHUNK_BYTES: usize = 4 << 20;
/// A physical scan reads at most this much (the parent's RAM).
pub const PHYSICAL_BYTES_MAX: u64 = 1 << 40;

#[derive(Debug, Default, Serialize)]
pub struct Scan {
    pub place: String,
    pub ranges: u64,
    pub bytes_read: u64,
    /// Ranges, or chunks of them, the kernel would not read.
    pub unreadable: u64,
    pub matches: u64,
    /// Bytes read that were zero: what a read returns where it returns
    /// nothing of the guest's.
    pub zero_bytes: u64,
}

pub fn needle(canary: &str) -> Vec<u8> {
    canary.as_bytes().repeat(RUN_REPEATS)
}

/// Searches `len` bytes of `file` from `start` for `needle`, chunk by
/// chunk, carrying the tail across chunks so no match is cut in two.
fn search_range(file: &std::fs::File, start: u64, len: u64, finder: &memmem::Finder<'_>, needle_len: usize, scan: &mut Scan) {
    let mut buf = vec![0u8; CHUNK_BYTES + needle_len];
    let mut carried = 0usize;
    let mut offset = 0u64;
    // Bounded by len.
    while offset < len {
        let want = (CHUNK_BYTES as u64).min(len - offset) as usize;
        match file.read_at(&mut buf[carried..carried + want], start + offset) {
            Ok(0) => break,
            Ok(n) => {
                let filled = carried + n;
                scan.matches += finder.find_iter(&buf[..filled]).count() as u64;
                scan.zero_bytes += buf[carried..filled].iter().filter(|b| **b == 0).count() as u64;
                scan.bytes_read += n as u64;
                let keep = (needle_len - 1).min(filled);
                buf.copy_within(filled - keep..filled, 0);
                carried = keep;
                offset += n as u64;
            }
            Err(_) => {
                scan.unreadable += 1;
                carried = 0;
                offset += want as u64;
            }
        }
    }
}

/// Every readable mapping of process `pid`.
pub fn process(pid: u32, canary: &str) -> std::io::Result<Scan> {
    let n = needle(canary);
    let finder = memmem::Finder::new(&n);
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    let mut scan = Scan { place: "/proc/<firecracker>/mem, every readable mapping in /proc/<firecracker>/maps".into(), ..Scan::default() };
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else { continue };
        if !perms.starts_with('r') {
            continue;
        }
        let Some((a, b)) = range.split_once('-') else { continue };
        let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else { continue };
        if b <= a {
            continue;
        }
        scan.ranges += 1;
        search_range(&mem, a, b - a, &finder, n.len(), &mut scan);
    }
    Ok(scan)
}

/// The mappings of `pid` backed by `/dev/nitro_enclaves` that grant no
/// access (`---s`: a confidential sandbox's memory), read anyway through
/// `/proc/<pid>/mem`, which as root reads past a mapping's protection
/// where the kernel can reach the pages at all.
pub fn locked(pid: u32, canary: &str) -> std::io::Result<Scan> {
    let n = needle(canary);
    let finder = memmem::Finder::new(&n);
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mem = std::fs::File::open(format!("/proc/{pid}/mem"))?;
    let mut scan = Scan { place: "/proc/<firecracker>/mem over its no-access /dev/nitro_enclaves mappings".into(), ..Scan::default() };
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else { continue };
        if perms.starts_with('r') || !line.ends_with("/dev/nitro_enclaves") {
            continue;
        }
        let Some((a, b)) = range.split_once('-') else { continue };
        let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else { continue };
        scan.ranges += 1;
        search_range(&mem, a, b - a, &finder, n.len(), &mut scan);
    }
    Ok(scan)
}

/// The mappings of process `pid` over a size, for the evidence: what
/// Firecracker has mapped (a guest's memory, if it is mapped at all).
pub fn large_mappings(pid: u32, bytes_min: u64) -> std::io::Result<Vec<String>> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut out = Vec::new();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else { continue };
        let rest: Vec<&str> = parts.skip(3).collect();
        let Some((a, b)) = range.split_once('-') else { continue };
        let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) else { continue };
        if b - a >= bytes_min {
            out.push(format!("{} MiB {perms} {}", (b - a) >> 20, rest.join(" ")));
        }
    }
    Ok(out)
}

/// System RAM's physical ranges, from `/proc/iomem` (top-level entries).
fn system_ram() -> std::io::Result<Vec<(u64, u64)>> {
    let iomem = std::fs::read_to_string("/proc/iomem")?;
    let mut out = Vec::new();
    for line in iomem.lines() {
        if line.starts_with(' ') || !line.ends_with(": System RAM") {
            continue;
        }
        let range = line.split(" : ").next().unwrap_or("");
        if let Some((a, b)) = range.split_once('-') {
            if let (Ok(a), Ok(b)) = (u64::from_str_radix(a, 16), u64::from_str_radix(b, 16)) {
                out.push((a, b + 1));
            }
        }
    }
    Ok(out)
}

/// `/proc/kcore`'s loadable segments: (file offset, physical address,
/// size), from its ELF64 program headers.
fn kcore_segments(kcore: &std::fs::File) -> std::io::Result<Vec<(u64, u64, u64)>> {
    let mut ehdr = [0u8; 64];
    kcore.read_exact_at(&mut ehdr, 0)?;
    if &ehdr[..4] != b"\x7fELF" || ehdr[4] != 2 {
        return Err(std::io::Error::other("kcore is not ELF64"));
    }
    let u64_at = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let u16_at = |b: &[u8], o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
    let phoff = u64_at(&ehdr, 32);
    let (phentsize, phnum) = (u16_at(&ehdr, 54) as usize, u16_at(&ehdr, 56) as usize);
    assert!(phentsize >= 56 && phnum < 4096);
    let mut out = Vec::new();
    for i in 0..phnum {
        let mut ph = vec![0u8; phentsize];
        kcore.read_exact_at(&mut ph, phoff + (i * phentsize) as u64)?;
        let p_type = u32::from_le_bytes(ph[..4].try_into().unwrap());
        if p_type == 1 {
            out.push((u64_at(&ph, 8), u64_at(&ph, 24), u64_at(&ph, 32)));
        }
    }
    Ok(out)
}

/// Every System RAM byte the kernel's `/proc/kcore` maps.
pub fn physical(canary: &str) -> std::io::Result<Scan> {
    let n = needle(canary);
    let finder = memmem::Finder::new(&n);
    let kcore = std::fs::File::open("/proc/kcore")?;
    let ram = system_ram()?;
    let segments = kcore_segments(&kcore)?;
    let mut scan = Scan { place: "/proc/kcore over every System RAM range of /proc/iomem".into(), ..Scan::default() };
    let mut total = 0u64;
    for (offset, paddr, size) in segments {
        for (a, b) in &ram {
            // The part of this segment inside this RAM range.
            let start = paddr.max(*a);
            let end = paddr.saturating_add(size).min(*b);
            if start >= end {
                continue;
            }
            total += end - start;
            assert!(total <= PHYSICAL_BYTES_MAX);
            scan.ranges += 1;
            search_range(&kcore, offset + (start - paddr), end - start, &finder, n.len(), &mut scan);
        }
    }
    Ok(scan)
}

pub fn file(path: &std::path::Path, canary: &str, place: &str) -> std::io::Result<Scan> {
    let n = needle(canary);
    let finder = memmem::Finder::new(&n);
    let f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let mut scan = Scan { place: place.into(), ranges: 1, ..Scan::default() };
    search_range(&f, 0, len, &finder, n.len(), &mut scan);
    Ok(scan)
}

/// A file's text, for a canary that appears once (the console's line).
pub fn file_contains(path: &std::path::Path, text: &str) -> std::io::Result<bool> {
    let mut s = Vec::new();
    std::fs::File::open(path)?.read_to_end(&mut s)?;
    Ok(memmem::find(&s, text.as_bytes()).is_some())
}
