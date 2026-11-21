//! Device-mapper's ioctl buffers (`linux/dm-ioctl.h`), the few a sealed
//! scratch disk needs (docs/nitro.md, "The sealed scratch disk"): create a
//! device, load its one target's table, resume it. Pure: the buffers and
//! the ioctl numbers, tested on any host; `linux::seal` makes the calls.

/// The ioctls' version: device-mapper refuses another major.
pub const VERSION: [u32; 3] = [4, 0, 0];
pub const NAME_BYTES_MAX: usize = 127;
const NAME_LEN: usize = 128;
const UUID_LEN: usize = 129;
const TYPE_NAME_LEN: usize = 16;
/// Ask the kernel to wipe its copies of the ioctl's buffers: a table load's
/// parameters hold the key.
pub const SECURE_DATA_FLAG: u32 = 1 << 15;
/// A parameter string's ceiling: a cipher, a 512-bit key in hex and a
/// device path fit many times.
pub const PARAMS_BYTES_MAX: usize = 1024;

const DM_IOCTL: u32 = 0xfd;
const DEV_CREATE: u32 = 3;
const DEV_SUSPEND: u32 = 6;
const TABLE_LOAD: u32 = 9;

/// `struct dm_ioctl`, as the kernel lays it out.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Header {
    pub version: [u32; 3],
    pub data_size: u32,
    pub data_start: u32,
    pub target_count: u32,
    pub open_count: i32,
    pub flags: u32,
    pub event_nr: u32,
    pub padding: u32,
    pub dev: u64,
    pub name: [u8; NAME_LEN],
    pub uuid: [u8; UUID_LEN],
    pub data: [u8; 7],
}

/// `struct dm_target_spec`; its parameter string follows it.
#[repr(C)]
#[derive(Clone, Copy)]
struct TargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; TYPE_NAME_LEN],
}

pub const HEADER_BYTES: usize = std::mem::size_of::<Header>();
const SPEC_BYTES: usize = std::mem::size_of::<TargetSpec>();
const _: () = assert!(HEADER_BYTES == 312 && SPEC_BYTES == 40);

/// `_IOWR(DM_IOCTL, nr, struct dm_ioctl)`.
const fn iowr(nr: u32) -> u64 {
    (3u64 << 30) | ((HEADER_BYTES as u64) << 16) | ((DM_IOCTL as u64) << 8) | nr as u64
}
pub const IOCTL_DEV_CREATE: u64 = iowr(DEV_CREATE);
pub const IOCTL_DEV_SUSPEND: u64 = iowr(DEV_SUSPEND);
pub const IOCTL_TABLE_LOAD: u64 = iowr(TABLE_LOAD);

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DmError {
    #[error("a device-mapper name of 1 to {NAME_BYTES_MAX} bytes, no NUL")]
    Name,
    #[error("a target's parameters past {PARAMS_BYTES_MAX} bytes, or with a NUL")]
    Params,
    #[error("a target of no sectors")]
    Empty,
}

/// A header alone (create, resume): `name`, `flags`, no data after it.
pub fn header(name: &str, flags: u32) -> Result<Header, DmError> {
    if name.is_empty() || name.len() > NAME_BYTES_MAX || name.bytes().any(|b| b == 0) {
        return Err(DmError::Name);
    }
    let mut name_bytes = [0u8; NAME_LEN];
    name_bytes[..name.len()].copy_from_slice(name.as_bytes());
    Ok(Header {
        version: VERSION,
        data_size: HEADER_BYTES as u32,
        data_start: HEADER_BYTES as u32,
        target_count: 0,
        open_count: 0,
        flags,
        event_nr: 0,
        padding: 0,
        dev: 0,
        name: name_bytes,
        uuid: [0; UUID_LEN],
        data: [0; 7],
    })
}

/// A table load's buffer: the header, one target over `sectors` from 0,
/// and its parameters, NUL-ended and padded to 8 bytes. The caller wipes
/// it after the call: the parameters may hold a key.
pub fn table(name: &str, sectors: u64, target: &str, params: &[u8]) -> Result<Vec<u8>, DmError> {
    if sectors == 0 {
        return Err(DmError::Empty);
    }
    if params.len() > PARAMS_BYTES_MAX || params.contains(&0) || target.is_empty() || target.len() >= TYPE_NAME_LEN {
        return Err(DmError::Params);
    }
    let params_bytes = (params.len() + 1).next_multiple_of(8);
    let total = HEADER_BYTES + SPEC_BYTES + params_bytes;
    let mut h = header(name, SECURE_DATA_FLAG)?;
    h.data_size = total as u32;
    h.target_count = 1;
    let mut target_type = [0u8; TYPE_NAME_LEN];
    target_type[..target.len()].copy_from_slice(target.as_bytes());
    let spec = TargetSpec { sector_start: 0, length: sectors, status: 0, next: 0, target_type };
    let mut buf = Vec::with_capacity(total);
    // SAFETY: both are plain repr(C) structs of integers and byte arrays,
    // read as the bytes they are.
    unsafe {
        buf.extend_from_slice(std::slice::from_raw_parts(&h as *const Header as *const u8, HEADER_BYTES));
        buf.extend_from_slice(std::slice::from_raw_parts(&spec as *const TargetSpec as *const u8, SPEC_BYTES));
    }
    buf.extend_from_slice(params);
    buf.resize(total, 0);
    Ok(buf)
}

/// dm-crypt's parameters over `disk`: `<cipher> <key in hex> 0 <disk> 0`.
/// The caller wipes them after the table load.
pub fn crypt_params(cipher: &str, key: &[u8], disk: &str) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut p = Vec::with_capacity(cipher.len() + key.len() * 2 + disk.len() + 8);
    p.extend_from_slice(cipher.as_bytes());
    p.push(b' ');
    for b in key {
        p.push(HEX[(b >> 4) as usize]);
        p.push(HEX[(b & 0xf) as usize]);
    }
    p.extend_from_slice(b" 0 ");
    p.extend_from_slice(disk.as_bytes());
    p.extend_from_slice(b" 0");
    p
}

/// A device number as device-mapper reports it (the kernel's
/// `huge_encode_dev`), as (major, minor).
pub fn major_minor(dev: u64) -> (u32, u32) {
    (((dev >> 8) & 0xfff) as u32, ((dev & 0xff) | ((dev >> 12) & 0xffff_ff00)) as u32)
}

/// Overwrites `buf` with zeroes the compiler cannot elide.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: a valid, aligned byte of `buf`.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: the ioctl numbers are the kernel's: _IOWR(0xfd, nr, 312 bytes).
    #[test]
    fn the_ioctls_are_the_kernels() {
        assert_eq!(IOCTL_DEV_CREATE, 0xC138_FD03);
        assert_eq!(IOCTL_DEV_SUSPEND, 0xC138_FD06);
        assert_eq!(IOCTL_TABLE_LOAD, 0xC138_FD09);
    }

    // Goal: a table load's buffer is the header, one spec and the
    // parameters, laid out as the kernel reads them: sizes and offsets
    // set, the parameters NUL-ended and padded to 8, the secure-data flag
    // on. Method: read the bytes back at the kernel's offsets.
    #[test]
    fn a_table_is_laid_out_as_the_kernel_reads_it() {
        let params = crypt_params("aes-xts-plain64", &[0xab; 64], "/dev/vdc");
        let buf = table("sc-scratch", 2048, "crypt", &params).unwrap();
        let u32_at = |o: usize| u32::from_ne_bytes(buf[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        assert_eq!((u32_at(0), u32_at(4), u32_at(8)), (4, 0, 0));
        assert_eq!(u32_at(12) as usize, buf.len());
        assert_eq!(u32_at(16) as usize, HEADER_BYTES);
        assert_eq!(u32_at(20), 1, "one target");
        assert_eq!(u32_at(28), SECURE_DATA_FLAG);
        assert_eq!(&buf[48..58], b"sc-scratch");
        assert_eq!(buf[58], 0);
        let spec = HEADER_BYTES;
        assert_eq!((u64_at(spec), u64_at(spec + 8)), (0, 2048));
        assert_eq!(&buf[spec + 24..spec + 29], b"crypt");
        let p = spec + SPEC_BYTES;
        assert_eq!(&buf[p..p + params.len()], &params[..]);
        assert!(buf[p + params.len()..].iter().all(|&b| b == 0) && buf.len().is_multiple_of(8));
        let text = std::str::from_utf8(&params).unwrap();
        assert!(text.starts_with("aes-xts-plain64 abab") && text.ends_with(" 0 /dev/vdc 0"));
        assert_eq!(text.split(' ').nth(1).unwrap().len(), 128, "a 512-bit key in hex");
    }

    // Goal: names, parameters and sizes the kernel would refuse, or cut,
    // are refused here.
    #[test]
    fn bad_tables_are_refused() {
        assert_eq!(header("", 0).err(), Some(DmError::Name));
        assert_eq!(header(&"x".repeat(128), 0).err(), Some(DmError::Name));
        assert!(header(&"x".repeat(127), 0).is_ok());
        assert_eq!(table("n", 0, "crypt", b"p").err(), Some(DmError::Empty));
        assert_eq!(table("n", 1, "crypt", &vec![b'p'; PARAMS_BYTES_MAX + 1]).err(), Some(DmError::Params));
        assert_eq!(table("n", 1, "crypt", b"a\0b").err(), Some(DmError::Params));
        assert_eq!(table("n", 1, "a-target-name-too-long", b"p").err(), Some(DmError::Params));
    }

    // Goal: a device number decodes as the kernel encodes it, small and
    // large minors alike; wipe leaves zeroes.
    #[test]
    fn devices_decode_and_buffers_wipe() {
        assert_eq!(major_minor((253 << 8) | 1), (253, 1));
        let minor: u64 = 0x1_2345;
        let dev = (minor & 0xff) | (253 << 8) | ((minor & !0xff) << 12);
        assert_eq!(major_minor(dev), (253, 0x1_2345));
        let mut key = [7u8; 64];
        wipe(&mut key);
        assert_eq!(key, [0u8; 64]);
    }
}
