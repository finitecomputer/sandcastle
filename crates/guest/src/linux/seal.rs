//! The sealed scratch disk (docs/nitro.md, "The sealed scratch disk"). On
//! a Nitro Sandbox the guest puts dm-crypt over its scratch disk with a key
//! it makes at boot, formats the mapping and mounts that. The key is never
//! written anywhere but the kernel's memory, which the parent cannot read,
//! and dies with the VM. The scratch disk does not outlive the VM either,
//! so no key is ever kept or released: the parent holds ciphertext only.

use std::io;
use std::os::fd::AsRawFd;
use std::process::Command;

use crate::dm;

/// The sealed disk's device-mapper name.
pub const NAME: &str = "sc-scratch";
/// The formatter, from the initrd (`sandcastle_rootfs::initrd::guest`).
pub const MKE2FS: &str = "/mke2fs";
/// AES-256 in XTS mode: two 256-bit keys.
const KEY_BYTES: usize = 64;
const CIPHER: &str = "aes-xts-plain64";
const CONTROL: &str = "/dev/mapper/control";
/// `_IOR(0x12, 114, size_t)`.
const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;

/// Seals `disk` under a fresh key, formats it, and returns the device to
/// mount in its place.
pub fn open(disk: &str) -> io::Result<String> {
    let sectors = sectors(disk)?;
    let mut key = [0u8; KEY_BYTES];
    getrandom(&mut key)?;
    let device = map(disk, sectors, &mut key);
    dm::wipe(&mut key);
    let device = device?;
    format(&device)?;
    Ok(device)
}

/// The crypt mapping, its key wiped from every buffer of ours.
fn map(disk: &str, sectors: u64, key: &mut [u8]) -> io::Result<String> {
    let control = std::fs::OpenOptions::new().read(true).write(true).open(CONTROL)?;
    let fd = control.as_raw_fd();
    let mut created = dm::header(NAME, 0).map_err(io::Error::other)?;
    // SAFETY: a dm_ioctl of the size the ioctl number names, ours.
    super::sys::check(unsafe { libc::ioctl(fd, dm::IOCTL_DEV_CREATE as _, &mut created as *mut dm::Header) })?;
    let mut params = dm::crypt_params(CIPHER, key, disk);
    let table = dm::table(NAME, sectors, "crypt", &params);
    dm::wipe(&mut params);
    let mut table = table.map_err(io::Error::other)?;
    // SAFETY: the buffer is a dm_ioctl followed by its data, `data_size`
    // bytes in all, as `dm::table` lays it out.
    let loaded = super::sys::check(unsafe { libc::ioctl(fd, dm::IOCTL_TABLE_LOAD as _, table.as_mut_ptr()) });
    dm::wipe(&mut table);
    loaded?;
    let mut resumed = dm::header(NAME, 0).map_err(io::Error::other)?;
    // SAFETY: as for the create.
    super::sys::check(unsafe { libc::ioctl(fd, dm::IOCTL_DEV_SUSPEND as _, &mut resumed as *mut dm::Header) })?;
    let (major, minor) = dm::major_minor(created.dev);
    let path = format!("/dev/dm-{minor}");
    if !std::path::Path::new(&path).exists() {
        // devtmpfs names it; a guest without the node makes it.
        let c = super::sys::cstr(&path)?;
        // SAFETY: mknod with a NUL-terminated path.
        super::sys::check(unsafe { libc::mknod(c.as_ptr(), libc::S_IFBLK | 0o600, libc::makedev(major, minor)) })?;
    }
    Ok(path)
}

/// A fresh ext4 with no journal (the scratch disk dies with the VM), its
/// inode tables left for the kernel to zero: through dm-crypt, a few
/// megabytes are written, not the disk.
fn format(device: &str) -> io::Result<()> {
    let out = Command::new(MKE2FS)
        .args(["-q", "-F", "-t", "ext4", "-m", "0", "-O", "^has_journal", "-E", "root_owner=0:0,lazy_itable_init=1,lazy_journal_init=1,nodiscard"])
        .arg(device)
        .output()?;
    if !out.status.success() {
        let why: String = String::from_utf8_lossy(&out.stderr).chars().take(1000).collect();
        return Err(io::Error::other(format!("mke2fs {device}: {}", why.trim_end())));
    }
    Ok(())
}

fn sectors(disk: &str) -> io::Result<u64> {
    let f = std::fs::File::open(disk)?;
    let mut bytes: u64 = 0;
    // SAFETY: BLKGETSIZE64 writes one u64.
    super::sys::check(unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64 as _, &mut bytes as *mut u64) })?;
    Ok(bytes / 512)
}

fn getrandom(buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: getrandom writes at most the rest of the buffer.
        let n = unsafe { libc::getrandom(buf[filled..].as_mut_ptr() as *mut libc::c_void, buf.len() - filled, 0) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
            continue;
        }
        filled += n as usize;
    }
    Ok(())
}
