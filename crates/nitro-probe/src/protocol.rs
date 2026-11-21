//! The probe's protocol: the guest dials the parent on vsock port [`PORT`]
//! as soon as it runs, says [`Answer::Hello`], then answers one
//! [`Command`] at a time. Each message is one JSON line of at most
//! [`LINE_BYTES_MAX`]; enums are externally tagged. Both sides check every
//! limit, since the parent is untrusted to the guest and the guest to the
//! parent.

use std::io::{BufRead, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The port the guest dials on the host's CID (2). Firecracker hands that
/// connection to the unix socket `<uds_path>_9000` on the parent.
pub const PORT: u32 = 9000;
/// One message. An attestation document is about 4.5 KiB (9 as hex); a
/// CMS envelope from KMS under 1 KiB.
pub const LINE_BYTES_MAX: usize = 64 * 1024;
/// A canary's text: printable ASCII, long enough to be unmistakable.
pub const CANARY_TEXT_BYTES_MIN: usize = 16;
pub const CANARY_TEXT_BYTES_MAX: usize = 128;
/// Memory a canary may fill, in MiB.
pub const CANARY_MIB_MAX: u32 = 1024;
/// What a disk canary writes from the device's start.
pub const DISK_CANARY_BYTES: u64 = 1 << 20;
/// A nonce for the NSM: the NSM takes up to 512 bytes; the verifier
/// issues 32.
pub const NONCE_BYTES_MAX: usize = 512;
/// A CMS envelope from KMS: a 256-byte RSA-wrapped key, and a plaintext of
/// at most 4096 bytes (KMS's limit) under AES-CBC.
pub const CMS_BYTES_MAX: usize = 16 * 1024;

const _: () = assert!(2 * CMS_BYTES_MAX < LINE_BYTES_MAX);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    /// Fill `mib` MiB of fresh memory with `text`, over and over, and keep
    /// it for the guest's life.
    MemoryCanary { text: String, mib: u32 },
    /// Write `text` to the console and the kernel's log.
    ConsoleCanary { text: String },
    /// Write `text`, over and over, across the first
    /// [`DISK_CANARY_BYTES`] of `device`, and sync it.
    DiskCanary { device: String, text: String },
    /// Ask the NSM for a document carrying `nonce_hex`; with `with_key`, a
    /// fresh RSA-2048 key is made first and its public half carried too.
    Attest { nonce_hex: String, with_key: bool },
    /// Open a CMS envelope with the key the last `Attest` made, once.
    Open { cms_hex: String },
    PowerOff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    Hello {
        /// The guest's boot clock (`CLOCK_BOOTTIME`) when its init began,
        /// and when it said hello.
        init_ms: u64,
        hello_ms: u64,
        kernel: String,
        /// Whether `/dev/nsm` exists: confidential mode with the driver.
        nsm: bool,
    },
    Done {
        bytes: u64,
    },
    Attested {
        document_hex: String,
        /// SHA-256 of the public key the document carries, if any.
        public_key_sha256: Option<String>,
        key_ms: u64,
        nsm_ms: u64,
    },
    /// What a CMS envelope held, by its hash only: the plaintext never
    /// leaves the guest.
    Opened {
        plaintext_sha256: String,
        plaintext_bytes: u64,
    },
    Refused {
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("the connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("a line over {LINE_BYTES_MAX} bytes")]
    LineTooLong,
    #[error("the peer closed the connection")]
    Closed,
    #[error("a malformed message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(&'static str),
}

fn canary_text(text: &str) -> Result<(), ProtocolError> {
    let printable = text.bytes().all(|b| (b' '..=b'~').contains(&b));
    if (CANARY_TEXT_BYTES_MIN..=CANARY_TEXT_BYTES_MAX).contains(&text.len()) && printable {
        Ok(())
    } else {
        Err(ProtocolError::Invalid("a canary is 16 to 128 bytes of printable ASCII"))
    }
}

fn hex_bounded(s: &str, max: usize) -> Result<Vec<u8>, ProtocolError> {
    if s.len() > 2 * max {
        return Err(ProtocolError::Invalid("hex over its limit"));
    }
    hex::decode(s).map_err(|_| ProtocolError::Invalid("not hex"))
}

impl Command {
    /// Checked by the guest before it acts, and by the driver before it
    /// sends.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Command::MemoryCanary { text, mib } => {
                canary_text(text)?;
                if *mib == 0 || *mib > CANARY_MIB_MAX {
                    return Err(ProtocolError::Invalid("a memory canary is 1 to 1024 MiB"));
                }
                Ok(())
            }
            Command::ConsoleCanary { text } => canary_text(text),
            Command::DiskCanary { device, text } => {
                canary_text(text)?;
                // Only a whole virtio disk, never a path the guest's init
                // has anything else on.
                let ok = device.len() == "/dev/vda".len() && device.starts_with("/dev/vd") && device.as_bytes()[7].is_ascii_lowercase();
                if ok {
                    Ok(())
                } else {
                    Err(ProtocolError::Invalid("a disk canary goes on /dev/vd[a-z]"))
                }
            }
            Command::Attest { nonce_hex, .. } => {
                let n = hex_bounded(nonce_hex, NONCE_BYTES_MAX)?;
                if n.is_empty() {
                    return Err(ProtocolError::Invalid("an attestation needs a nonce"));
                }
                Ok(())
            }
            Command::Open { cms_hex } => hex_bounded(cms_hex, CMS_BYTES_MAX).map(|_| ()),
            Command::PowerOff => Ok(()),
        }
    }
}

/// Writes one message as a line. Its size is asserted: every message a
/// side writes is bounded by construction.
pub fn write_line<W: Write, T: Serialize>(w: &mut W, message: &T) -> Result<(), ProtocolError> {
    let mut bytes = serde_json::to_vec(message)?;
    assert!(bytes.len() < LINE_BYTES_MAX, "a message we make is within its limit");
    assert!(!bytes.contains(&b'\n'), "JSON escapes newlines");
    bytes.push(b'\n');
    w.write_all(&bytes)?;
    w.flush()?;
    Ok(())
}

/// Reads one message: at most [`LINE_BYTES_MAX`] bytes up to its newline.
pub fn read_line<R: BufRead, T: DeserializeOwned>(r: &mut R) -> Result<T, ProtocolError> {
    let mut line = Vec::with_capacity(1024);
    let n = r.by_ref().take(LINE_BYTES_MAX as u64 + 1).read_until(b'\n', &mut line)?;
    if n == 0 {
        return Err(ProtocolError::Closed);
    }
    if line.last() != Some(&b'\n') {
        return Err(if n > LINE_BYTES_MAX { ProtocolError::LineTooLong } else { ProtocolError::Closed });
    }
    line.pop();
    Ok(serde_json::from_slice(&line)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Goal: every message survives the line codec, externally tagged.
    #[test]
    fn messages_round_trip() {
        let commands = [
            Command::MemoryCanary { text: "NITRO-SPIKE-CANARY-0123456789ab".into(), mib: 64 },
            Command::Attest { nonce_hex: "00".repeat(32), with_key: true },
            Command::Open { cms_hex: "30".into() },
            Command::PowerOff,
        ];
        let mut buf = Vec::new();
        for c in &commands {
            write_line(&mut buf, c).unwrap();
        }
        let mut r = std::io::BufReader::new(&buf[..]);
        for c in &commands {
            assert_eq!(&read_line::<_, Command>(&mut r).unwrap(), c);
        }
        assert!(matches!(read_line::<_, Command>(&mut r), Err(ProtocolError::Closed)));
        let mut out = Vec::new();
        write_line(&mut out, &Command::PowerOff).unwrap();
        assert_eq!(out, b"\"power_off\"\n");
    }

    // Goal: a line past its limit is refused, not buffered.
    #[test]
    fn long_lines_refused() {
        let mut long = vec![b'"'; LINE_BYTES_MAX + 10];
        long.push(b'\n');
        let mut r = std::io::BufReader::new(&long[..]);
        assert!(matches!(read_line::<_, Command>(&mut r), Err(ProtocolError::LineTooLong)));
        let cut = b"\"power_off\"";
        let mut r = std::io::BufReader::new(&cut[..]);
        assert!(matches!(read_line::<_, Command>(&mut r), Err(ProtocolError::Closed)), "no newline: cut short");
    }

    // Goal: every command's limits, at the edge and one past.
    #[test]
    fn commands_validated() {
        let t = |n: usize| "x".repeat(n);
        assert!(Command::ConsoleCanary { text: t(CANARY_TEXT_BYTES_MIN) }.validate().is_ok());
        assert!(Command::ConsoleCanary { text: t(CANARY_TEXT_BYTES_MIN - 1) }.validate().is_err());
        assert!(Command::ConsoleCanary { text: t(CANARY_TEXT_BYTES_MAX) }.validate().is_ok());
        assert!(Command::ConsoleCanary { text: t(CANARY_TEXT_BYTES_MAX + 1) }.validate().is_err());
        assert!(Command::ConsoleCanary { text: format!("{}\n", t(20)) }.validate().is_err());
        assert!(Command::MemoryCanary { text: t(20), mib: CANARY_MIB_MAX }.validate().is_ok());
        assert!(Command::MemoryCanary { text: t(20), mib: CANARY_MIB_MAX + 1 }.validate().is_err());
        assert!(Command::MemoryCanary { text: t(20), mib: 0 }.validate().is_err());
        assert!(Command::DiskCanary { device: "/dev/vdb".into(), text: t(20) }.validate().is_ok());
        for bad in ["/dev/vda1", "/dev/sda", "/dev/vd", "/etc/passwd", "/dev/vdA"] {
            assert!(Command::DiskCanary { device: bad.into(), text: t(20) }.validate().is_err(), "{bad}");
        }
        assert!(Command::Attest { nonce_hex: "ab".repeat(NONCE_BYTES_MAX), with_key: false }.validate().is_ok());
        assert!(Command::Attest { nonce_hex: "ab".repeat(NONCE_BYTES_MAX + 1), with_key: false }.validate().is_err());
        assert!(Command::Attest { nonce_hex: String::new(), with_key: false }.validate().is_err());
        assert!(Command::Attest { nonce_hex: "zz".into(), with_key: false }.validate().is_err());
        assert!(Command::Open { cms_hex: "ab".repeat(CMS_BYTES_MAX + 1) }.validate().is_err());
    }
}
