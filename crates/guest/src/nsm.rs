//! The guest's clock on a Nitro Sandbox (docs/nitro.md, "The guest"): a
//! confidential sandbox boots at 1970, with no clock the parent sets and
//! none it could be trusted to set. Its Nitro Security Module signs the
//! time into every attestation document, so the guest asks `/dev/nsm` for
//! one and takes the time from it, before the workload starts (TLS checks
//! certificates' dates).
//!
//! The NSM takes one ioctl: a CBOR request in, a CBOR response out
//! (Linux's `include/uapi/linux/nsm.h`). Here are only the attestation
//! request, its answer, and the document's `timestamp`, read without its
//! signature: the guest reads its own NSM, which is the hypervisor's, and
//! verifying a document is the operator's job, not the guest's. Pure, so
//! tested on any host; the ioctl is in `linux::sys`.

use thiserror::Error;

/// The NSM's device, present only in a Nitro Sandbox.
pub const DEVICE: &str = "/dev/nsm";
/// The driver's buffers (`NSM_REQUEST_MAX_SIZE`, `NSM_RESPONSE_MAX_SIZE`).
pub const REQUEST_BYTES_MAX: usize = 0x1000;
pub const RESPONSE_BYTES_MAX: usize = 0x3000;
/// The nonce the guest sends: random, so each document is fresh.
pub const NONCE_BYTES: usize = 32;
/// Nesting the reader walks through before it calls a document malformed.
const DEPTH_MAX: usize = 16;
/// A clock before this (2026-01-01) is not one the NSM signed.
pub const EARLIEST_MS: u64 = 1_767_225_600_000;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NsmError {
    #[error("the NSM answered an error: {0}")]
    Nsm(String),
    #[error("a malformed NSM message at byte {0}")]
    Malformed(usize),
    #[error("an NSM answer of {0} bytes, over {RESPONSE_BYTES_MAX}")]
    TooLarge(usize),
    #[error("the document has no timestamp")]
    NoTimestamp,
    #[error("the document's time ({0} ms) is before 2026")]
    Implausible(u64),
}

fn head(out: &mut Vec<u8>, major: u8, arg: usize) {
    let m = major << 5;
    // The request's fields are all far under 64 KiB.
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

/// `{"Attestation": {"user_data": null, "nonce": <nonce>, "public_key":
/// null}}`, encoded exactly as the NSM API's own serde does.
pub fn attestation_request(nonce: &[u8; NONCE_BYTES], public_key: Option<&[u8; 32]>) -> Vec<u8> {
    let mut out = Vec::with_capacity(96 + NONCE_BYTES);
    head(&mut out, 5, 1);
    text(&mut out, "Attestation");
    head(&mut out, 5, 3);
    text(&mut out, "user_data");
    out.push(0xf6);
    text(&mut out, "nonce");
    head(&mut out, 2, NONCE_BYTES);
    out.extend_from_slice(nonce);
    text(&mut out, "public_key");
    match public_key {
        Some(k) => {
            head(&mut out, 2, k.len());
            out.extend_from_slice(k);
        }
        None => out.push(0xf6),
    }
    assert!(out.len() <= REQUEST_BYTES_MAX);
    out
}

/// A CBOR reader over one message: heads of every width, definite and
/// indefinite lengths, and a bounded skip, which is all a document needs.
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

/// A head's argument: a count or a value, or "indefinite" (`None`).
type Arg = Option<u64>;

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Reader<'a> {
        Reader { b, at: 0 }
    }

    fn byte(&mut self) -> Result<u8, NsmError> {
        let v = *self.b.get(self.at).ok_or(NsmError::Malformed(self.at))?;
        self.at += 1;
        Ok(v)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], NsmError> {
        let n = usize::try_from(n).map_err(|_| NsmError::Malformed(self.at))?;
        let end = self.at.checked_add(n).filter(|&e| e <= self.b.len()).ok_or(NsmError::Malformed(self.at))?;
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }

    /// (major type, argument); info 31 is indefinite (or a break).
    fn head(&mut self) -> Result<(u8, Arg), NsmError> {
        let at = self.at;
        let initial = self.byte()?;
        let (major, info) = (initial >> 5, initial & 0x1f);
        let arg = match info {
            0..=23 => Some(u64::from(info)),
            24 => Some(u64::from(self.byte()?)),
            25..=27 => {
                let width = 1u64 << (info - 24);
                Some(self.take(width)?.iter().fold(0u64, |v, &b| (v << 8) | u64::from(b)))
            }
            31 if matches!(major, 2..=5 | 7) => None,
            _ => return Err(NsmError::Malformed(at)),
        };
        Ok((major, arg))
    }

    fn is_break(&self) -> bool {
        self.b.get(self.at) == Some(&0xff)
    }

    /// Skips one item, whatever it is, at most `DEPTH_MAX` deep.
    fn skip(&mut self, depth: usize) -> Result<(), NsmError> {
        if depth > DEPTH_MAX {
            return Err(NsmError::Malformed(self.at));
        }
        let at = self.at;
        match self.head()? {
            (0 | 1, Some(_)) => Ok(()),
            (2 | 3, Some(n)) => self.take(n).map(|_| ()),
            (2 | 3, None) => {
                while !self.is_break() {
                    self.skip(depth + 1)?;
                }
                self.at += 1;
                Ok(())
            }
            (4, Some(n)) => (0..n).try_for_each(|_| self.skip(depth + 1)),
            (5, Some(n)) => (0..n).try_for_each(|_| self.skip(depth + 1).and_then(|_| self.skip(depth + 1))),
            (4 | 5, None) => {
                while !self.is_break() {
                    self.skip(depth + 1)?;
                }
                self.at += 1;
                Ok(())
            }
            (6, Some(_)) => self.skip(depth + 1),
            (7, Some(_)) => Ok(()),
            _ => Err(NsmError::Malformed(at)),
        }
    }

    fn text(&mut self) -> Result<&'a str, NsmError> {
        let at = self.at;
        match self.head()? {
            (3, Some(n)) => std::str::from_utf8(self.take(n)?).map_err(|_| NsmError::Malformed(at)),
            _ => Err(NsmError::Malformed(at)),
        }
    }

    fn bytes(&mut self) -> Result<&'a [u8], NsmError> {
        let at = self.at;
        match self.head()? {
            (2, Some(n)) => self.take(n),
            _ => Err(NsmError::Malformed(at)),
        }
    }

    /// A map's entry count, or `None` for an indefinite map.
    fn map(&mut self) -> Result<Arg, NsmError> {
        let at = self.at;
        match self.head()? {
            (5, n) => Ok(n),
            _ => Err(NsmError::Malformed(at)),
        }
    }
}

/// The document from `{"Attestation": {"document": …}}`, or the NSM's
/// error from `{"Error": "<code>"}`. Anything else is malformed.
pub fn attestation_document(response: &[u8]) -> Result<&[u8], NsmError> {
    if response.len() > RESPONSE_BYTES_MAX {
        return Err(NsmError::TooLarge(response.len()));
    }
    let mut r = Reader::new(response);
    if r.map()? != Some(1) {
        return Err(NsmError::Malformed(0));
    }
    let doc = match r.text()? {
        "Attestation" => {
            if r.map()? != Some(1) || r.text()? != "document" {
                return Err(NsmError::Malformed(r.at));
            }
            r.bytes()?
        }
        "Error" => {
            let code = r.text()?;
            if r.at != response.len() {
                return Err(NsmError::Malformed(r.at));
            }
            return Err(NsmError::Nsm(code.to_string()));
        }
        _ => return Err(NsmError::Malformed(r.at)),
    };
    if r.at != response.len() {
        return Err(NsmError::Malformed(r.at));
    }
    Ok(doc)
}

/// The document's `timestamp`, in ms since 1970: its COSE_Sign1 (tagged
/// 18 or bare), the payload's map (the NSM writes it indefinite), the
/// key `timestamp`. Unsigned and unchecked; see the module's comment.
pub fn timestamp_ms(document: &[u8]) -> Result<u64, NsmError> {
    if document.len() > RESPONSE_BYTES_MAX {
        return Err(NsmError::TooLarge(document.len()));
    }
    let mut r = Reader::new(document);
    let mut top = r.head()?;
    if top == (6, Some(18)) {
        top = r.head()?;
    }
    if top != (4, Some(4)) {
        return Err(NsmError::Malformed(0));
    }
    r.bytes()?; // the protected header
    r.skip(1)?; // the unprotected header
    let payload = r.bytes()?;
    r.bytes()?; // the signature
    if r.at != document.len() {
        return Err(NsmError::Malformed(r.at));
    }
    let mut p = Reader::new(payload);
    let entries = p.map()?;
    let mut seen = 0u64;
    loop {
        match entries {
            Some(n) if seen == n => break,
            None if p.is_break() => break,
            _ => {}
        }
        if p.text()? == "timestamp" {
            let at = p.at;
            return match p.head()? {
                (0, Some(ms)) if ms >= EARLIEST_MS => Ok(ms),
                (0, Some(ms)) => Err(NsmError::Implausible(ms)),
                _ => Err(NsmError::Malformed(at)),
            };
        }
        p.skip(1)?;
        seen += 1;
    }
    Err(NsmError::NoTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn bstr(out: &mut Vec<u8>, b: &[u8]) {
        head(out, 2, b.len());
        out.extend_from_slice(b);
    }

    /// A payload shaped as the real NSM writes it: an indefinite map with
    /// every field a document has, the timestamp among them.
    fn payload(timestamp: Option<u64>) -> Vec<u8> {
        let mut p = vec![0xbf];
        text(&mut p, "module_id");
        text(&mut p, "a-test-module");
        text(&mut p, "digest");
        text(&mut p, "SHA384");
        if let Some(ms) = timestamp {
            text(&mut p, "timestamp");
            p.push(0x1b);
            p.extend_from_slice(&ms.to_be_bytes());
        }
        text(&mut p, "pcrs");
        p.push(0xb0); // a definite map of 16
        for i in 0..16u8 {
            p.push(i);
            bstr(&mut p, &[i; 48]);
        }
        text(&mut p, "certificate");
        bstr(&mut p, &[0x30; 639]);
        text(&mut p, "cabundle");
        p.push(0x84);
        for n in [533usize, 300, 300, 300] {
            bstr(&mut p, &vec![0x30; n]);
        }
        text(&mut p, "public_key");
        p.push(0xf6);
        text(&mut p, "user_data");
        p.push(0xf6);
        text(&mut p, "nonce");
        bstr(&mut p, &[7; 32]);
        p.push(0xff);
        p
    }

    fn document(payload: &[u8], tagged: bool) -> Vec<u8> {
        let mut d = Vec::new();
        if tagged {
            d.push(0xd2);
        }
        d.push(0x84);
        bstr(&mut d, &[0xa1, 0x01, 0x38, 0x22]); // {1: -35}, ES384
        d.push(0xa0);
        bstr(&mut d, payload);
        bstr(&mut d, &[0x5a; 96]);
        d
    }

    const MS: u64 = 1_795_214_429_007;

    // Goal: our request is byte for byte the NSM API's. Method: its
    // pinned shape (aws-nitro-enclaves-nsm-api, src/api/mod.rs) with a
    // 32-byte nonce, and with the session's 32-byte public key or none.
    #[test]
    fn the_request_is_the_nsm_apis() {
        let r = attestation_request(&[1; NONCE_BYTES], None);
        let mut want = unhex("a16b4174746573746174696f6ea369757365725f64617461f6656e6f6e63655820");
        want.extend_from_slice(&[1; NONCE_BYTES]);
        want.extend_from_slice(&unhex("6a7075626c69635f6b6579f6"));
        assert_eq!(r, want);
        let with_key = attestation_request(&[1; NONCE_BYTES], Some(&[2; 32]));
        let mut want = want[..want.len() - 1].to_vec();
        want.extend_from_slice(&unhex("5820"));
        want.extend_from_slice(&[2; 32]);
        assert_eq!(with_key, want);
    }

    // Goal: the NSM's answers read as it writes them, and nothing else
    // does: its own pinned cases, every cut, a trailing byte, another
    // request's answer, and an oversized one.
    #[test]
    fn answers_read_as_the_nsm_writes_them() {
        let ok = unhex("a16b4174746573746174696f6ea168646f63756d656e7442d284");
        assert_eq!(attestation_document(&ok), Ok(&[0xd2u8, 0x84][..]));
        assert_eq!(attestation_document(&unhex("a1654572726f726c496e76616c6964496e646578")), Err(NsmError::Nsm("InvalidIndex".into())));
        for cut in 0..ok.len() {
            assert!(attestation_document(&ok[..cut]).is_err(), "cut at {cut}");
        }
        let mut trailing = ok.clone();
        trailing.push(0);
        assert!(attestation_document(&trailing).is_err());
        assert!(attestation_document(&unhex("a16b4465736372696265504352a2646c6f636bf5646461746142aabb")).is_err());
        assert_eq!(attestation_document(&vec![0xa1; RESPONSE_BYTES_MAX + 1]), Err(NsmError::TooLarge(RESPONSE_BYTES_MAX + 1)));
    }

    // Goal: the time comes out of a document as the NSM makes it, tagged
    // or bare, with its payload map indefinite or definite.
    #[test]
    fn a_documents_time_is_read() {
        for tagged in [false, true] {
            assert_eq!(timestamp_ms(&document(&payload(Some(MS)), tagged)), Ok(MS));
        }
        // The same fields in a definite map of 10.
        let mut definite = payload(Some(MS));
        definite[0] = 0xa9; // nine fields
        definite.pop();
        assert_eq!(timestamp_ms(&document(&definite, true)), Ok(MS));
    }

    // Goal: nothing but a whole, well-formed document with a plausible
    // time gives a time. Method: no timestamp, a 1970 one, every cut of
    // the document, a trailing byte, a non-integer time, deep nesting.
    #[test]
    fn a_bad_document_gives_no_time() {
        assert_eq!(timestamp_ms(&document(&payload(None), true)), Err(NsmError::NoTimestamp));
        assert_eq!(timestamp_ms(&document(&payload(Some(5)), true)), Err(NsmError::Implausible(5)));
        let doc = document(&payload(Some(MS)), true);
        for cut in 0..doc.len() {
            assert!(timestamp_ms(&doc[..cut]).is_err(), "cut at {cut}");
        }
        let mut trailing = doc.clone();
        trailing.push(0);
        assert!(timestamp_ms(&trailing).is_err());
        let mut textual = vec![0xa1];
        text(&mut textual, "timestamp");
        text(&mut textual, "1795214429007");
        assert!(timestamp_ms(&document(&textual, true)).is_err());
        let mut deep = vec![0xa2];
        text(&mut deep, "x");
        deep.extend(std::iter::repeat_n(0x81, DEPTH_MAX + 2));
        deep.push(0x00);
        text(&mut deep, "timestamp");
        deep.push(0x00);
        assert!(timestamp_ms(&document(&deep, true)).is_err());
    }
}
