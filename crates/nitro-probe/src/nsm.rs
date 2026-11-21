//! The Nitro Security Module's messages, as `/dev/nsm` takes them through
//! its one ioctl (`NSM_IOCTL_RAW`, Linux's `include/uapi/linux/nsm.h`): a
//! CBOR request in, a CBOR response out. Only the attestation request and
//! its answer are here, encoded exactly as the NSM API's own serde does
//! (its `request_encoding_matches_serde_cbor` and
//! `response_encoding_matches_serde_cbor` tests are this module's).

use thiserror::Error;

/// The driver's buffers (`NSM_REQUEST_MAX_SIZE`, `NSM_RESPONSE_MAX_SIZE`).
pub const REQUEST_BYTES_MAX: usize = 0x1000;
pub const RESPONSE_BYTES_MAX: usize = 0x3000;
/// The request's optional fields, as the NSM bounds them.
pub const NONCE_BYTES_MAX: usize = 512;
pub const USER_DATA_BYTES_MAX: usize = 512;
pub const PUBLIC_KEY_BYTES_MAX: usize = 1024;

const _: () = assert!(NONCE_BYTES_MAX + USER_DATA_BYTES_MAX + PUBLIC_KEY_BYTES_MAX + 64 < REQUEST_BYTES_MAX);

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NsmError {
    #[error("the NSM answered an error: {0}")]
    Nsm(String),
    #[error("a malformed answer from the NSM at byte {0}")]
    Malformed(usize),
    #[error("an answer of {0} bytes, over {RESPONSE_BYTES_MAX}")]
    TooLarge(usize),
}

fn head(out: &mut Vec<u8>, major: u8, arg: usize) {
    let m = major << 5;
    // The NSM's fields are all under 64 KiB.
    assert!(arg <= usize::from(u16::MAX));
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg <= 0xff {
        out.extend_from_slice(&[m | 24, arg as u8]);
    } else {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    }
}

fn text(out: &mut Vec<u8>, s: &str) {
    head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn optional_bytes(out: &mut Vec<u8>, b: Option<&[u8]>) {
    match b {
        Some(b) => {
            head(out, 2, b.len());
            out.extend_from_slice(b);
        }
        None => out.push(0xf6),
    }
}

/// `{"Attestation": {"user_data": …, "nonce": …, "public_key": …}}`, each
/// null when absent.
pub fn attestation_request(user_data: Option<&[u8]>, nonce: Option<&[u8]>, public_key: Option<&[u8]>) -> Vec<u8> {
    assert!(user_data.is_none_or(|d| d.len() <= USER_DATA_BYTES_MAX));
    assert!(nonce.is_none_or(|n| n.len() <= NONCE_BYTES_MAX));
    assert!(public_key.is_none_or(|k| k.len() <= PUBLIC_KEY_BYTES_MAX));
    let mut out = Vec::with_capacity(64 + user_data.map_or(0, <[u8]>::len) + nonce.map_or(0, <[u8]>::len) + public_key.map_or(0, <[u8]>::len));
    head(&mut out, 5, 1);
    text(&mut out, "Attestation");
    head(&mut out, 5, 3);
    text(&mut out, "user_data");
    optional_bytes(&mut out, user_data);
    text(&mut out, "nonce");
    optional_bytes(&mut out, nonce);
    text(&mut out, "public_key");
    optional_bytes(&mut out, public_key);
    assert!(out.len() <= REQUEST_BYTES_MAX);
    out
}

/// Reads a head at `at`: (major type, argument, where its content starts).
fn read_head(b: &[u8], at: usize) -> Result<(u8, usize, usize), NsmError> {
    let initial = *b.get(at).ok_or(NsmError::Malformed(at))?;
    let (major, info) = (initial >> 5, initial & 0x1f);
    let (arg, next) = match info {
        0..=23 => (usize::from(info), at + 1),
        24 => (usize::from(*b.get(at + 1).ok_or(NsmError::Malformed(at))?), at + 2),
        25 => {
            let s = b.get(at + 1..at + 3).ok_or(NsmError::Malformed(at))?;
            (usize::from(u16::from_be_bytes([s[0], s[1]])), at + 3)
        }
        _ => return Err(NsmError::Malformed(at)),
    };
    Ok((major, arg, next))
}

fn read_text(b: &[u8], at: usize) -> Result<(&str, usize), NsmError> {
    let (major, len, start) = read_head(b, at)?;
    let s = b.get(start..start + len).filter(|_| major == 3).ok_or(NsmError::Malformed(at))?;
    Ok((std::str::from_utf8(s).map_err(|_| NsmError::Malformed(at))?, start + len))
}

/// The document from `{"Attestation": {"document": …}}`, or the NSM's
/// error from `{"Error": "<code>"}`. Anything else is malformed.
pub fn attestation_document(response: &[u8]) -> Result<&[u8], NsmError> {
    if response.len() > RESPONSE_BYTES_MAX {
        return Err(NsmError::TooLarge(response.len()));
    }
    let (major, entries, at) = read_head(response, 0)?;
    if major != 5 || entries != 1 {
        return Err(NsmError::Malformed(0));
    }
    let (key, at) = read_text(response, at)?;
    match key {
        "Attestation" => {
            let (major, entries, at) = read_head(response, at)?;
            if major != 5 || entries != 1 {
                return Err(NsmError::Malformed(at));
            }
            let (field, at) = read_text(response, at)?;
            let (major, len, start) = read_head(response, at)?;
            if field != "document" || major != 2 || start + len != response.len() {
                return Err(NsmError::Malformed(at));
            }
            Ok(&response[start..])
        }
        "Error" => {
            let (code, end) = read_text(response, at)?;
            if end == response.len() {
                Err(NsmError::Nsm(code.to_string()))
            } else {
                Err(NsmError::Malformed(end))
            }
        }
        _ => Err(NsmError::Malformed(at)),
    }
}

/// `_IOWR(NSM_MAGIC = 0x0A, 0, struct nsm_raw)`, 32 bytes.
#[cfg(target_os = "linux")]
const NSM_IOCTL_RAW: libc::c_ulong = 0xC020_0A00;

#[cfg(target_os = "linux")]
#[repr(C)]
struct NsmIovec {
    addr: u64,
    len: u64,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct NsmRaw {
    request: NsmIovec,
    response: NsmIovec,
}

#[cfg(target_os = "linux")]
const _: () = assert!(std::mem::size_of::<NsmRaw>() == 32);
#[cfg(target_os = "linux")]
const _: () = assert!(NSM_IOCTL_RAW == (3 << 30) | (32 << 16) | (0x0A << 8));

/// Asks `/dev/nsm` for an attestation document carrying `nonce` and
/// `public_key`: the document, or why not.
#[cfg(target_os = "linux")]
pub fn attest(nonce: Option<&[u8]>, public_key: Option<&[u8]>) -> Result<Vec<u8>, String> {
    use std::os::fd::AsRawFd;
    let request = attestation_request(None, nonce, public_key);
    let mut response = vec![0u8; RESPONSE_BYTES_MAX];
    let mut raw = NsmRaw {
        request: NsmIovec { addr: request.as_ptr() as u64, len: request.len() as u64 },
        response: NsmIovec { addr: response.as_mut_ptr() as u64, len: response.len() as u64 },
    };
    let file = std::fs::OpenOptions::new().read(true).write(true).open("/dev/nsm").map_err(|e| format!("/dev/nsm: {e}"))?;
    // SAFETY: NSM_IOCTL_RAW with a valid nsm_raw whose buffers outlive
    // the call; the driver writes the answer's length back into it.
    let r = unsafe { libc::ioctl(file.as_raw_fd(), NSM_IOCTL_RAW as _, &mut raw as *mut NsmRaw) };
    if r != 0 {
        return Err(format!("the NSM's ioctl: {}", std::io::Error::last_os_error()));
    }
    let len = raw.response.len as usize;
    assert!(len <= response.len(), "the driver answers within the buffer it was given");
    attestation_document(&response[..len]).map(<[u8]>::to_vec).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    // Goal: our request is byte for byte the NSM API's. Method: its own
    // pinned case (aws-nitro-enclaves-nsm-api, src/api/mod.rs,
    // request_encoding_matches_serde_cbor), then a document-sized nonce
    // and key, whose lengths take the longer heads.
    #[test]
    fn requests_match_the_nsm_apis() {
        let ours = attestation_request(Some(&[9, 9]), None, Some(&[7]));
        assert_eq!(ours, unhex("a16b4174746573746174696f6ea369757365725f64617461420909656e6f6e6365f66a7075626c69635f6b65794107"));
        let big = attestation_request(None, Some(&[1; 32]), Some(&[2; 294]));
        assert_eq!(&big[big.len() - 297..big.len() - 294], &[0x59, 0x01, 0x26], "a 294-byte key's head");
    }

    // Goal: the NSM's answers read as it writes them (the same file's
    // response_encoding_matches_serde_cbor), and nothing else does.
    #[test]
    fn answers_match_the_nsm_apis() {
        assert_eq!(attestation_document(&unhex("a16b4174746573746174696f6ea168646f63756d656e7442d284")), Ok(&[0xd2u8, 0x84][..]));
        assert_eq!(attestation_document(&unhex("a1654572726f726c496e76616c6964496e646578")), Err(NsmError::Nsm("InvalidIndex".into())));
        let ok = unhex("a16b4174746573746174696f6ea168646f63756d656e7442d284");
        for cut in 0..ok.len() {
            assert!(attestation_document(&ok[..cut]).is_err(), "cut at {cut}");
        }
        let mut trailing = ok.clone();
        trailing.push(0);
        assert!(attestation_document(&trailing).is_err());
        // DescribePCR's answer is not an attestation.
        assert!(attestation_document(&unhex("a16b4465736372696265504352a2646c6f636bf5646461746142aabb")).is_err());
        assert_eq!(attestation_document(&vec![0xa1; RESPONSE_BYTES_MAX + 1]), Err(NsmError::TooLarge(RESPONSE_BYTES_MAX + 1)));
    }
}
