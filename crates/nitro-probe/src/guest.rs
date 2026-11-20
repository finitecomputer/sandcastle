//! The probe as PID 1: mount the basics, dial the parent, say hello, then
//! do one command at a time until told to power off or the parent hangs
//! up. Nothing it is sent can end it except `PowerOff`: a command that
//! fails is answered `Refused`, since PID 1 exiting panics the kernel.

use std::ffi::CString;
use std::io::{BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Instant;

use rsa::pkcs8::EncodePublicKey;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

use crate::protocol::{read_line, write_line, Answer, Command, ProtocolError, DISK_CANARY_BYTES, PORT};
use crate::{cms, nsm};

/// The host's CID on vsock.
const CID_HOST: u32 = 2;
/// Tries at dialing the parent before giving up, 20 ms apart: the driver
/// listens before it starts the sandbox, so the first normally answers.
const DIAL_TRIES_MAX: u32 = 250;
/// The key KMS encrypts to: RSAES_OAEP_SHA_256 needs an RSA key; 2048
/// bits is KMS's smallest.
const RSA_BITS: usize = 2048;
/// `_IOWR(NSM_MAGIC = 0x0A, 0, struct nsm_raw)`, 32 bytes.
const NSM_IOCTL_RAW: libc::c_ulong = 0xC020_0A00;

#[repr(C)]
struct NsmIovec {
    addr: u64,
    len: u64,
}

#[repr(C)]
struct NsmRaw {
    request: NsmIovec,
    response: NsmIovec,
}

const _: () = assert!(std::mem::size_of::<NsmRaw>() == 32);
const _: () = assert!(NSM_IOCTL_RAW == (3 << 30) | (32 << 16) | (0x0A << 8));

fn boottime_ms() -> u64 {
    // SAFETY: clock_gettime writes the timespec it is given.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u64 * 1000 + ts.tv_nsec as u64 / 1_000_000
}

fn mount(source: &str, target: &str, fstype: &str) {
    let _ = std::fs::create_dir_all(target);
    let (s, t, f) = (CString::new(source).unwrap(), CString::new(target).unwrap(), CString::new(fstype).unwrap());
    // SAFETY: NUL-terminated strings; no data. EBUSY (already mounted, as
    // devtmpfs may be) is fine.
    unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), libc::MS_NOSUID, std::ptr::null()) };
}

fn dial(cid: u32, port: u32) -> std::io::Result<UnixStream> {
    // SAFETY: a socket call; the descriptor is owned at once.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: sockaddr_vm is plain data; zero is its empty value.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_cid = cid;
    addr.svm_port = port;
    // SAFETY: a valid sockaddr_vm and its size.
    let r = unsafe { libc::connect(fd.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, std::mem::size_of_val(&addr) as u32) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // A vsock stream behaves as a unix stream does for reads and writes.
    Ok(UnixStream::from(fd))
}

fn poweroff() -> ! {
    // SAFETY: sync and reboot(2) as PID 1.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    // Bounded: the power-off takes effect within the call above; this only
    // keeps PID 1 from returning if it did not.
    loop {
        // SAFETY: pause(2) has no preconditions.
        unsafe { libc::pause() };
    }
}

fn kernel_release() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()).unwrap_or_default()
}

pub fn main() -> ! {
    let init_ms = boottime_ms();
    if std::process::id() != 1 {
        eprintln!("nitro-probe is a guest's init and runs as PID 1");
        std::process::exit(2);
    }
    mount("proc", "/proc", "proc");
    mount("sysfs", "/sys", "sysfs");
    mount("devtmpfs", "/dev", "devtmpfs");
    let mut stream = None;
    // Bounded by DIAL_TRIES_MAX.
    for _ in 0..DIAL_TRIES_MAX {
        match dial(CID_HOST, PORT) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    let Some(stream) = stream else {
        eprintln!("nitro-probe: the parent never answered on vsock port {PORT}");
        poweroff()
    };
    let mut probe = Probe { key: None, kept: Vec::new() };
    let _ = serve(&mut probe, stream, init_ms);
    poweroff()
}

struct Probe {
    /// The key the last attestation carried, until one envelope is opened
    /// with it: one use, so a parent cannot ask the guest to open envelope
    /// after envelope with one key (a decryption oracle).
    key: Option<RsaPrivateKey>,
    /// Canaries kept for the guest's life.
    kept: Vec<&'static [u8]>,
}

fn serve(probe: &mut Probe, stream: UnixStream, init_ms: u64) -> Result<(), ProtocolError> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let hello = Answer::Hello { init_ms, hello_ms: boottime_ms(), kernel: kernel_release(), nsm: std::path::Path::new("/dev/nsm").exists() };
    write_line(&mut writer, &hello)?;
    // Bounded by the connection: it ends when the parent closes it or
    // sends PowerOff.
    loop {
        let command: Command = read_line(&mut reader)?;
        if command == Command::PowerOff {
            return Ok(());
        }
        let answer = match command.validate() {
            Ok(()) => probe.act(command),
            Err(e) => Answer::Refused { message: e.to_string() },
        };
        write_line(&mut writer, &answer)?;
    }
}

fn refused(what: &str, e: impl std::fmt::Display) -> Answer {
    Answer::Refused { message: format!("{what}: {e}") }
}

fn fill(buf: &mut [u8], text: &[u8]) {
    assert!(!text.is_empty());
    for (i, b) in buf.iter_mut().enumerate() {
        *b = text[i % text.len()];
    }
}

impl Probe {
    fn act(&mut self, command: Command) -> Answer {
        match command {
            Command::MemoryCanary { text, mib } => {
                let mut buf = vec![0u8; (mib as usize) << 20];
                fill(&mut buf, text.as_bytes());
                let kept: &'static [u8] = Box::leak(buf.into_boxed_slice());
                self.kept.push(kept);
                Answer::Done { bytes: kept.len() as u64 }
            }
            Command::ConsoleCanary { text } => {
                let line = format!("{text}\n");
                let console = std::fs::OpenOptions::new().write(true).open("/dev/console").and_then(|mut c| c.write_all(line.as_bytes()));
                let kmsg = std::fs::OpenOptions::new().write(true).open("/dev/kmsg").and_then(|mut k| k.write_all(format!("<6>{text}").as_bytes()));
                match console.and(kmsg) {
                    Ok(()) => Answer::Done { bytes: line.len() as u64 },
                    Err(e) => refused("the console", e),
                }
            }
            Command::DiskCanary { device, text } => {
                let mut buf = vec![0u8; DISK_CANARY_BYTES as usize];
                fill(&mut buf, text.as_bytes());
                let written = std::fs::OpenOptions::new().write(true).open(&device).and_then(|mut d| {
                    d.write_all(&buf)?;
                    d.sync_all()
                });
                match written {
                    Ok(()) => Answer::Done { bytes: buf.len() as u64 },
                    Err(e) => refused(&device, e),
                }
            }
            Command::Attest { nonce_hex, with_key } => self.attest(&nonce_hex, with_key),
            Command::Open { cms_hex } => {
                let Some(key) = self.key.take() else {
                    return Answer::Refused { message: "no key: attest with a key first (one envelope per key)".into() };
                };
                let ber = hex::decode(&cms_hex).expect("validated");
                match cms::open(&key, &ber) {
                    Ok(plaintext) => Answer::Opened { plaintext_sha256: hex::encode(Sha256::digest(&plaintext)), plaintext_bytes: plaintext.len() as u64 },
                    Err(e) => refused("the envelope", e),
                }
            }
            Command::PowerOff => unreachable!("handled by serve"),
        }
    }

    fn attest(&mut self, nonce_hex: &str, with_key: bool) -> Answer {
        let nonce = hex::decode(nonce_hex).expect("validated");
        let started = Instant::now();
        let public_key = if with_key {
            let key = match RsaPrivateKey::new(&mut rsa::rand_core::OsRng, RSA_BITS) {
                Ok(k) => k,
                Err(e) => return refused("making a key", e),
            };
            let der = key.to_public_key().to_public_key_der().expect("an RSA public key encodes").as_bytes().to_vec();
            self.key = Some(key);
            Some(der)
        } else {
            self.key = None;
            None
        };
        let key_ms = started.elapsed().as_millis() as u64;
        let asked = Instant::now();
        let request = nsm::attestation_request(None, Some(&nonce), public_key.as_deref());
        let mut response = vec![0u8; nsm::RESPONSE_BYTES_MAX];
        let mut raw = NsmRaw {
            request: NsmIovec { addr: request.as_ptr() as u64, len: request.len() as u64 },
            response: NsmIovec { addr: response.as_mut_ptr() as u64, len: response.len() as u64 },
        };
        let file = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/nsm") {
            Ok(f) => f,
            Err(e) => return refused("/dev/nsm", e),
        };
        // SAFETY: NSM_IOCTL_RAW with a valid nsm_raw whose buffers outlive
        // the call; the driver writes the answer's length back into it.
        let r = unsafe { libc::ioctl(file.as_raw_fd(), NSM_IOCTL_RAW as _, &mut raw as *mut NsmRaw) };
        if r != 0 {
            return refused("the NSM's ioctl", std::io::Error::last_os_error());
        }
        let len = raw.response.len as usize;
        assert!(len <= response.len(), "the driver answers within the buffer it was given");
        let nsm_ms = asked.elapsed().as_millis() as u64;
        match nsm::attestation_document(&response[..len]) {
            Ok(document) => Answer::Attested { document_hex: hex::encode(document), public_key_sha256: public_key.map(|k| hex::encode(Sha256::digest(&k))), key_ms, nsm_ms },
            Err(e) => refused("the NSM's answer", e),
        }
    }
}
