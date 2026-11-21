//! The guest's initrd: a newc cpio archive (the kernel's
//! `Documentation/driver-api/early-userspace/buffer-format.rst`) holding
//! the probe as `/init` and the few nodes an init needs. Every inode,
//! owner, mode and time is fixed, so the same probe makes the same bytes,
//! and the same bytes make the same PCR1 and PCR0.

/// A file or a directory or a device node in the archive.
pub struct Entry<'a> {
    pub path: &'a str,
    pub mode: u32,
    /// A device node's major and minor numbers.
    pub rdev: (u32, u32),
    pub data: &'a [u8],
}

const DIR: u32 = 0o040_000;
const FILE: u32 = 0o100_000;
const CHAR: u32 = 0o020_000;
/// An archive's largest file: the probe is a few MiB.
pub const FILE_BYTES_MAX: usize = 64 << 20;

/// The probe's initrd: `/init` and the mount points it uses, and
/// `/dev/console` so the kernel can open init's console before devtmpfs.
pub fn probe(init: &[u8]) -> Vec<u8> {
    with_mke2fs(init, None)
}

/// `probe`'s archive, with a static `mke2fs` at `/mke2fs` when given: the
/// node line's guest copies it out and formats its sealed scratch disk with
/// it (sandcastle's `rootfs::initrd::guest`, the same entries).
pub fn with_mke2fs(init: &[u8], mke2fs: Option<&[u8]>) -> Vec<u8> {
    assert!(!init.is_empty() && init.len() <= FILE_BYTES_MAX);
    assert!(mke2fs.is_none_or(|m| !m.is_empty() && m.len() <= FILE_BYTES_MAX));
    let dir = |path| Entry { path, mode: DIR | 0o755, rdev: (0, 0), data: &[] };
    let mut entries = vec![
        dir("dev"),
        Entry { path: "dev/console", mode: CHAR | 0o600, rdev: (5, 1), data: &[] },
        dir("proc"),
        dir("sys"),
        dir("run"),
        dir("tmp"),
        Entry { path: "init", mode: FILE | 0o755, rdev: (0, 0), data: init },
    ];
    if let Some(m) = mke2fs {
        entries.push(Entry { path: "mke2fs", mode: FILE | 0o755, rdev: (0, 0), data: m });
    }
    newc(&entries)
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn header(out: &mut Vec<u8>, ino: u32, e: &Entry<'_>) {
    let is_dir = e.mode & 0o170_000 == DIR;
    let fields = [ino, e.mode, 0, 0, if is_dir { 2 } else { 1 }, 0, e.data.len() as u32, 0, 0, e.rdev.0, e.rdev.1, e.path.len() as u32 + 1, 0];
    out.extend_from_slice(b"070701");
    for f in fields {
        out.extend_from_slice(format!("{f:08x}").as_bytes());
    }
    out.extend_from_slice(e.path.as_bytes());
    out.push(0);
    pad4(out);
    out.extend_from_slice(e.data);
    pad4(out);
}

pub fn newc(entries: &[Entry<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        assert!(!e.path.is_empty() && !e.path.starts_with('/') && !e.path.contains('\0'), "relative paths, as the kernel unpacks them");
        assert!(e.data.len() <= FILE_BYTES_MAX);
        header(&mut out, i as u32 + 1, e);
    }
    header(&mut out, 0, &Entry { path: "TRAILER!!!", mode: 0, rdev: (0, 0), data: &[] });
    assert!(out.len().is_multiple_of(4));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: a guest's initrd carries a static mke2fs at /mke2fs only when
    // given one (the node line's guest formats its sealed scratch with it),
    // and the archive without it is the probe's, byte for byte.
    #[test]
    fn mke2fs_only_when_given() {
        let with = with_mke2fs(b"init", Some(b"mke2fs bytes"));
        let without = with_mke2fs(b"init", None);
        assert!(with.windows(7).any(|w| w == b"mke2fs\0") && with.windows(12).any(|w| w == b"mke2fs bytes"));
        assert!(!without.windows(7).any(|w| w == b"mke2fs\0"));
        assert_eq!(without, probe(b"init"));
    }

    // Goal: the header is the kernel's newc layout. Method: one file, its
    // fields read back at their offsets.
    #[test]
    fn newc_layout() {
        let a = newc(&[Entry { path: "init", mode: FILE | 0o755, rdev: (0, 0), data: b"hello" }]);
        assert_eq!(&a[..6], b"070701");
        let field = |n: usize| u32::from_str_radix(std::str::from_utf8(&a[6 + 8 * n..14 + 8 * n]).unwrap(), 16).unwrap();
        assert_eq!(field(0), 1, "ino");
        assert_eq!(field(1), FILE | 0o755, "mode");
        assert_eq!(field(6), 5, "filesize");
        assert_eq!(field(11), 5, "namesize, its zero included");
        assert_eq!(&a[110..115], b"init\0");
        assert_eq!(&a[116..121], b"hello", "the name padded to four from the header's start");
        assert!(a.windows(10).any(|w| w == b"TRAILER!!!"));
    }

    // Goal: the same probe makes the same bytes; another makes others.
    #[test]
    fn reproducible() {
        assert_eq!(probe(b"\x7fELF one"), probe(b"\x7fELF one"));
        assert_ne!(probe(b"\x7fELF one"), probe(b"\x7fELF two"));
    }
}
